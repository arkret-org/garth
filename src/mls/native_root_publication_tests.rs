//! Encrypted-file reopen, durable-write failures and real HTTPS client flows.
//! Test Station responses isolate client behavior, not native PG admission.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use arkret_keystore::{EncryptedFileKeyStore, KeyBytes, KeyStore};
use ed25519_dalek::{Signer, SigningKey};

use super::*;
use crate::{SecureKeyStoreBackendInfo, SecureKeyStoreError, SecureKeyStoreResult};

#[path = "native_root_publication_flow_tests.rs"]
mod flow_tests;

fn fixture() -> (
    ContentRootBackupEntry,
    KeyBackup,
    RealmActorBackupPutResponseBody,
) {
    let data = arkret_schema_conformance::spec_json_artifact(
        "fixtures/realm-actor-content-backup-fixture.json",
    )
    .unwrap();
    (
        serde_json::from_value(data["plaintext"]["items"][0].clone()).unwrap(),
        serde_json::from_value(data["native_packet"].clone()).unwrap(),
        serde_json::from_value(data["native_put_response"].clone()).unwrap(),
    )
}

fn endpoint(packet: &KeyBackup) -> MlsWelcomeRecipientEndpoint {
    MlsWelcomeRecipientEndpoint::Device {
        device_id: packet.device_id.clone().unwrap(),
    }
}

#[cfg(not(target_arch = "wasm32"))]
type StoreFuture<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

struct DurableStore {
    inner: EncryptedFileKeyStore,
    cas_lock: PathBuf,
    fail_next_cas: AtomicBool,
}

fn storage_error(error: impl std::fmt::Display) -> SecureKeyStoreError {
    SecureKeyStoreError::Backend(error.to_string())
}

impl DurableStore {
    fn open(directory: &Path) -> Self {
        Self {
            inner: EncryptedFileKeyStore::new(
                directory.join("roots.vault"),
                "garth.native-root-journal-tests",
                [91; 32],
            )
            .unwrap(),
            cas_lock: directory.join("root-journal-cas.lock"),
            fail_next_cas: AtomicBool::new(false),
        }
    }
}

impl SecureKeyStore for DurableStore {
    fn store_secret_bytes(&self, key: &str, value: &[u8]) -> SecureKeyStoreResult<()> {
        self.inner.store(key, value).map_err(storage_error)
    }
    fn get_secret_bytes(&self, key: &str) -> SecureKeyStoreResult<Option<KeyBytes>> {
        match self.inner.load(key) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) if error.is_not_found() => Ok(None),
            Err(error) => Err(storage_error(error)),
        }
    }
    fn delete_secret(&self, key: &str) -> SecureKeyStoreResult<()> {
        self.inner.delete(key).map_err(storage_error)
    }
    fn list_secret_keys(&self, prefix: Option<&str>) -> SecureKeyStoreResult<Vec<String>> {
        Ok(self
            .inner
            .list()
            .map_err(storage_error)?
            .into_iter()
            .filter(|key| prefix.is_none_or(|prefix| key.starts_with(prefix)))
            .collect())
    }
    fn backend_info(&self) -> SecureKeyStoreBackendInfo {
        SecureKeyStoreBackendInfo {
            name: "encrypted-file-test-vault",
            hardware_backed: false,
            exportable: true,
        }
    }
    fn read_secret_bytes_durable<'a>(
        &'a self,
        key: &'a str,
    ) -> StoreFuture<'a, SecureKeyStoreResult<Option<KeyBytes>>> {
        Box::pin(async move { self.get_secret_bytes(key) })
    }
    fn compare_exchange_secret_bytes_durable<'a>(
        &'a self,
        key: &'a str,
        expected: Option<&'a [u8]>,
        replacement: &'a [u8],
    ) -> StoreFuture<'a, SecureKeyStoreResult<bool>> {
        Box::pin(async move {
            if self.fail_next_cas.swap(false, Ordering::SeqCst) {
                return Err(storage_error("injected durable commit failure"));
            }
            let lock = std::fs::OpenOptions::new()
                .create(true)
                .truncate(false)
                .read(true)
                .write(true)
                .open(&self.cas_lock)
                .map_err(storage_error)?;
            lock.lock().map_err(storage_error)?;
            if self.get_secret_bytes(key)?.as_ref().map(KeyBytes::as_slice) != expected {
                return Ok(false);
            }
            self.inner.store(key, replacement).map_err(storage_error)?;
            Ok(true)
        })
    }
}

#[tokio::test]
async fn frozen_native_packet_survives_real_encrypted_file_cold_reopen_without_fake_ack() {
    let directory = tempfile::tempdir().unwrap();
    let (root, packet, _) = fixture();
    let endpoint = endpoint(&packet);
    {
        let store = DurableStore::open(directory.path());
        let vault = ContentRootVault::new(&store, &packet.actor_id, &endpoint);
        assert!(matches!(
            vault
                .native_root_publication_state("original", &root)
                .await
                .unwrap(),
            NativeRootPublicationState::Unprepared
        ));
        vault.retain_root(&root).await.unwrap();
        vault
            .freeze_native_root_publication("original", &root, &packet)
            .await
            .unwrap();
        assert!(matches!(
            vault
                .native_root_publication_state("original", &root)
                .await
                .unwrap(),
            NativeRootPublicationState::Frozen { .. }
        ));
        assert!(vault.published_backup_refs(&root).await.unwrap().is_none());
    }
    let store = DurableStore::open(directory.path());
    let vault = ContentRootVault::new(&store, &packet.actor_id, &endpoint);
    let NativeRootPublicationState::Frozen { packet: reopened } = vault
        .native_root_publication_state("original", &root)
        .await
        .unwrap()
    else {
        panic!("no ACK may be invented across a real cold reopen")
    };
    assert!(same_packet(&reopened, &packet).unwrap());
    assert!(vault.published_backup_refs(&root).await.unwrap().is_none());
    let mut fork = packet.clone();
    fork.signature_proof.signature =
        arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode([0; 64])).unwrap();
    assert!(
        vault
            .freeze_native_root_publication("original", &root, &fork)
            .await
            .is_err()
    );
    assert!(
        same_packet(
            &vault.frozen_backup("original").await.unwrap().unwrap(),
            &packet
        )
        .unwrap()
    );
    let raw = std::fs::read(directory.path().join("roots.vault")).unwrap();
    let encoded_root = Zeroizing::new(arkret_canonical::base64url_encode(
        root.root_base64url.expose(),
    ));
    assert!(!String::from_utf8_lossy(&raw).contains(encoded_root.as_str()));
}

#[tokio::test]
async fn failed_native_ack_commit_preserves_original_intent_then_retries_into_history_only_record()
{
    let directory = tempfile::tempdir().unwrap();
    let (root, packet, response) = fixture();
    let endpoint = endpoint(&packet);
    {
        let store = DurableStore::open(directory.path());
        let vault = ContentRootVault::new(&store, &packet.actor_id, &endpoint);
        vault.retain_root(&root).await.unwrap();
        vault
            .freeze_native_root_publication("original", &root, &packet)
            .await
            .unwrap();
        store.fail_next_cas.store(true, Ordering::SeqCst);
        assert!(
            vault
                .commit_native_publication_history("original", &root, &packet, &response)
                .await
                .is_err()
        );
        assert!(matches!(
            vault
                .native_root_publication_state("original", &root)
                .await
                .unwrap(),
            NativeRootPublicationState::Frozen { .. }
        ));
    }
    {
        let store = DurableStore::open(directory.path());
        let vault = ContentRootVault::new(&store, &packet.actor_id, &endpoint);
        vault
            .commit_native_publication_history("original", &root, &packet, &response)
            .await
            .unwrap();
    }
    let store = DurableStore::open(directory.path());
    let vault = ContentRootVault::new(&store, &packet.actor_id, &endpoint);
    let NativeRootPublicationState::Recorded { history } = vault
        .native_root_publication_state("original", &root)
        .await
        .unwrap()
    else {
        panic!("the actual stored reference ACK must survive reopening")
    };
    assert!(same_packet(history.packet(), &packet).unwrap());
    assert_eq!(
        history.response().admission.envelope_digest,
        response.admission.envelope_digest
    );
    let keys = store.list_secret_keys(None).unwrap();
    let mut duplicate = response.clone();
    duplicate.status = arkret_models_crypto::KeyBackupPutStatus::Duplicate;
    vault
        .commit_native_publication_history("original", &root, &packet, &duplicate)
        .await
        .unwrap();
    assert_eq!(store.list_secret_keys(None).unwrap(), keys);
    assert!(
        vault.published_backup_refs(&root).await.unwrap().is_none(),
        "native historical data does not install an old Account-style publication or SDK current capability"
    );
}

#[tokio::test]
async fn native_ack_conflicts_leave_the_frozen_intent_and_durable_key_set_unchanged() {
    let directory = tempfile::tempdir().unwrap();
    let (root, packet, response) = fixture();
    let endpoint = endpoint(&packet);
    let store = DurableStore::open(directory.path());
    let vault = ContentRootVault::new(&store, &packet.actor_id, &endpoint);
    vault.retain_root(&root).await.unwrap();
    vault
        .freeze_native_root_publication("original", &root, &packet)
        .await
        .unwrap();
    let keys = store.list_secret_keys(None).unwrap();
    for failure in [
        "envelope_digest",
        "ciphertext_digest",
        "original_public",
        "generation",
        "scope",
    ] {
        let mut wrong = response.clone();
        if failure == "envelope_digest" {
            wrong.admission.envelope_digest =
                Hash::new(arkret_canonical::sha256_digest(b"wrong")).unwrap();
        }
        if failure == "ciphertext_digest" {
            wrong.ciphertext_digest = Hash::new(arkret_canonical::sha256_digest(b"wrong")).unwrap();
        }
        if failure == "original_public" {
            wrong.admission.device_public_key_base64url =
                arkret_canonical::base64url_encode([9; 32]);
        }
        if failure == "generation" {
            wrong.admission.device_generation += 1;
        }
        if failure == "scope" {
            wrong.admission.effective_scope = ScopeRef::Realm {
                realm_id: crate::test_fixtures::realm_id(),
            };
        }
        assert!(
            vault
                .commit_native_publication_history("original", &root, &packet, &wrong)
                .await
                .is_err(),
            "{failure}"
        );
        assert_eq!(store.list_secret_keys(None).unwrap(), keys);
        assert!(matches!(
            vault
                .native_root_publication_state("original", &root)
                .await
                .unwrap(),
            NativeRootPublicationState::Frozen { .. }
        ));
    }
}

#[tokio::test]
async fn historical_ack_is_bound_to_original_endpoint_and_is_not_rebound_to_a_new_requester() {
    let directory = tempfile::tempdir().unwrap();
    let (root, packet, response) = fixture();
    let endpoint = endpoint(&packet);
    let store = DurableStore::open(directory.path());
    let vault = ContentRootVault::new(&store, &packet.actor_id, &endpoint);
    vault.retain_root(&root).await.unwrap();
    vault
        .freeze_native_root_publication("original", &root, &packet)
        .await
        .unwrap();
    vault
        .commit_native_publication_history("original", &root, &packet, &response)
        .await
        .unwrap();
    let sibling = MlsWelcomeRecipientEndpoint::Device {
        device_id: arkret_wire::DeviceId::new("ak:device:019a0000-0000-7000-8000-000000000099")
            .unwrap(),
    };
    let sibling_vault = ContentRootVault::new(&store, &packet.actor_id, &sibling);
    assert!(matches!(
        sibling_vault
            .native_root_publication_state("original", &root)
            .await
            .unwrap(),
        NativeRootPublicationState::Unprepared
    ));
    assert!(
        sibling_vault
            .freeze_native_root_publication("original", &root, &packet)
            .await
            .is_err()
    );
    assert!(
        sibling_vault
            .commit_native_publication_history("original", &root, &packet, &response)
            .await
            .is_err()
    );
}

struct NativeHttpFixture {
    client: OwnStationDeviceClient,
    source: Arc<crate::own_station_results::tests::member_genesis::NativeSource>,
    root: ContentRootBackupEntry,
    packet: KeyBackup,
    response: RealmActorBackupPutResponseBody,
}

fn native_http_fixture(base: &str) -> NativeHttpFixture {
    use crate::own_station_results::tests::member_genesis::{founding_original, native_client};
    let (genesis, _) = founding_original();
    let (client, source) = native_client(base, &genesis);
    let context = client.context().unwrap();
    let data = arkret_schema_conformance::spec_json_artifact(
        "fixtures/realm-actor-content-backup-fixture.json",
    )
    .unwrap();
    let mut root: ContentRootBackupEntry =
        serde_json::from_value(data["plaintext"]["items"][0].clone()).unwrap();
    root.root_context.effective_scope = context.effective_scope().clone();
    root.root_context.genesis_event_ref = genesis.event.event_id.clone();
    root.root_context.group_state_ref = genesis.event.event_id.clone();
    root.root_context.backup_strategy_ref = genesis.event.event_id.clone();
    root.root_ref =
        arkret_crypto::content_history::content_root_ref(&root.root_base64url, &root.root_context)
            .unwrap();
    let mut input:arkret_models_crypto::ContentBackupNextPrepareInput=serde_json::from_value(serde_json::json!({
        "auth_binding":data["native_packet"]["auth_binding"],"content_backup_recipient":data["recipient"],
        "active_series_id":data["native_packet"]["series_id"],
    })).unwrap();
    let stream = arkret_wire::CommitStreamRef::RealmControl {
        realm_id: genesis.event.realm_id.clone(),
    };
    for reference in [
        &mut input.auth_binding.manager_ref,
        &mut input.auth_binding.recovery_ref,
        &mut input.auth_binding.recipient_ref,
    ] {
        reference.stream_ref = stream.clone();
    }
    let device_key = SigningKey::from_bytes(&[123; 32]);
    let fingerprint = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
        device_key.verifying_key().as_bytes(),
    );
    let created_at =
        chrono::DateTime::from_timestamp_millis(chrono::Utc::now().timestamp_millis()).unwrap();
    let packet = arkret_crypto::content_history::RealmActorContentRootBackupDraft {
        backup_id: serde_json::from_value(data["native_packet"]["backup_id"].clone()).unwrap(),
        realm_actor_id: context.actor_id().as_realm_actor_id().unwrap().clone(),
        created_at,
        author: arkret_crypto::backup::KeyBackupAuthBinding {
            device_id: context.device_id().clone(),
            device_authorize_event_id: context.authorization_event_id().clone(),
            verification_method: arkret_wire::DidUrl::new(format!(
                "did:key:{fingerprint}#{fingerprint}"
            ))
            .unwrap(),
            signature_algorithm: arkret_models_crypto::KeyBackupSignatureAlgorithm::Ed25519,
        },
        prepare_input: input,
        domain_separation: serde_json::from_value(
            data["native_packet"]["domain_separation"].clone(),
        )
        .unwrap(),
        series_sequence: 0,
        supersedes: None,
    }
    .seal(root.clone(), |bytes| {
        Ok(device_key.sign(bytes).to_bytes().to_vec())
    })
    .unwrap();
    let mut admission: arkret_models_crypto::RealmActorContentBackupAdmission =
        serde_json::from_value(data["native_put_response"]["admission"].clone()).unwrap();
    admission.backup_id = packet.backup_id.clone();
    admission.envelope_digest =
        Hash::new(arkret_canonical::canonical_sha256(&packet).unwrap()).unwrap();
    admission.ciphertext_digest = packet.ciphertext_digest.clone();
    admission.realm_actor_id = context.actor_id().as_realm_actor_id().unwrap().clone();
    admission.effective_scope = context.effective_scope().clone();
    admission.device_id = context.device_id().clone();
    admission.device_authorize_ref.event_id = context.authorization_event_id().clone();
    admission.device_authorize_ref.stream_ref = stream;
    admission.device_public_key_base64url =
        arkret_canonical::base64url_encode(device_key.verifying_key().as_bytes());
    let auth = packet.auth_binding.as_ref().unwrap();
    admission.manager_ref = auth.manager_ref.clone();
    admission.recovery_ref = auth.recovery_ref.clone();
    admission.recipient_ref = auth.recipient_ref.clone();
    admission.device_generation = auth.device_generation;
    admission.accepted_at = created_at;
    admission.service_id = context.binding().service_id().clone();
    admission.governance_generation = 0;
    admission.authority_ref =
        arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(genesis.event.event_id);
    let admission =
        arkret_signatures::realm_actor_content_backup::sign_realm_actor_content_backup_admission(
            arkret_signatures::realm_actor_content_backup::admission_signing_input(&admission)
                .unwrap(),
            arkret_wire::DidUrl::new("did:web:station.example#signing-1").unwrap(),
            &SigningKey::from_bytes(&[43; 32]),
        )
        .unwrap();
    let response = RealmActorBackupPutResponseBody {
        status: arkret_models_crypto::KeyBackupPutStatus::Accepted,
        backup_id: packet.backup_id.clone(),
        ciphertext_digest: packet.ciphertext_digest.clone(),
        admission,
    };
    NativeHttpFixture {
        client,
        source,
        root,
        packet,
        response,
    }
}

type HttpTrace = Arc<Mutex<Vec<(String, Vec<u8>)>>>;

fn serve_native_puts(
    listener: std::net::TcpListener,
    bodies: Vec<RealmActorBackupPutResponseBody>,
    retire: Option<Arc<crate::own_station_results::tests::member_genesis::NativeSource>>,
) -> (std::thread::JoinHandle<()>, HttpTrace) {
    let tls = crate::test_fixtures::native_tls::server_config();
    let trace = Arc::new(Mutex::new(Vec::new()));
    let captured = trace.clone();
    listener.set_nonblocking(true).unwrap();
    let handle = std::thread::spawn(move || {
        for response in bodies {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
            let socket = loop {
                match listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(
                            std::time::Instant::now() < deadline,
                            "expected immutable native PUT never arrived"
                        );
                        std::thread::sleep(std::time::Duration::from_millis(5));
                    }
                    Err(error) => panic!("native TLS accept: {error}"),
                }
            };
            socket
                .set_read_timeout(Some(std::time::Duration::from_secs(10)))
                .unwrap();
            let mut stream = rustls::StreamOwned::new(
                rustls::ServerConnection::new(tls.clone()).unwrap(),
                socket,
            );
            let mut bytes = Vec::new();
            let end = loop {
                if let Some(index) = bytes.windows(4).position(|piece| piece == b"\r\n\r\n") {
                    break index + 4;
                }
                let mut buffer = [0; 4096];
                let read = stream.read(&mut buffer).unwrap();
                assert!(read > 0);
                bytes.extend_from_slice(&buffer[..read]);
            };
            let header = String::from_utf8_lossy(&bytes[..end]).to_ascii_lowercase();
            assert!(header.starts_with("put /_arkret/self/keys/backups/"));
            assert!(!header.contains("authorization:"));
            assert!(header.contains("signature-input:"));
            assert!(header.contains("content-digest:"));
            assert!(header.contains("arkret-managed-device"));
            let length: usize = header
                .lines()
                .find_map(|line| {
                    line.strip_prefix("content-length:")
                        .map(|value| value.trim().parse().unwrap())
                })
                .unwrap();
            while bytes.len() < end + length {
                let mut buffer = [0; 4096];
                let read = stream.read(&mut buffer).unwrap();
                assert!(read > 0);
                bytes.extend_from_slice(&buffer[..read]);
            }
            captured.lock().unwrap().push((
                header.lines().next().unwrap().to_owned(),
                bytes[end..end + length].to_vec(),
            ));
            if let Some(source) = &retire {
                source.active.store(false, Ordering::SeqCst);
            }
            let body = serde_json::to_vec(&response).unwrap();
            write!(stream,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len()).unwrap();
            stream.write_all(&body).unwrap();
            stream.flush().unwrap();
        }
    });
    (handle, trace)
}

#[tokio::test]
async fn native_unknown_result_cold_retries_real_https_put_before_any_new_prepare() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let fixture = native_http_fixture(&format!("https://{}/", listener.local_addr().unwrap()));
    let mut duplicate = fixture.response.clone();
    duplicate.status = arkret_models_crypto::KeyBackupPutStatus::Duplicate;
    let (server, trace) =
        serve_native_puts(listener, vec![fixture.response.clone(), duplicate], None);
    let directory = tempfile::tempdir().unwrap();
    let endpoint = endpoint(&fixture.packet);
    {
        let store = DurableStore::open(directory.path());
        let vault = ContentRootVault::new(&store, &fixture.packet.actor_id, &endpoint);
        vault.retain_root(&fixture.root).await.unwrap();
        vault
            .register_native_publication_intent("business-operation", "frozen-before-network")
            .await
            .unwrap();
        // Registration precedes the freeze. Reopening this interrupted entry
        // must retain it without inventing a PUT or suppressing older intents.
        vault
            .register_native_publication_intent("business-operation", "interrupted-before-freeze")
            .await
            .unwrap();
        vault
            .freeze_native_root_publication("frozen-before-network", &fixture.root, &fixture.packet)
            .await
            .unwrap();
    }
    {
        let store = DurableStore::open(directory.path());
        let vault = ContentRootVault::new(&store, &fixture.packet.actor_id, &endpoint);
        store.fail_next_cas.store(true, Ordering::SeqCst);
        let result = retry_native_root_publication(
            &fixture.client,
            &vault,
            "frozen-before-network",
            &fixture.root,
        )
        .await;
        let error = match result {
            Err(error) => error,
            Ok(_) => panic!("injected ACK journal write failure was hidden"),
        };
        assert!(
            error
                .to_string()
                .contains("injected durable commit failure"),
            "{error}"
        );
        assert!(matches!(
            vault
                .native_root_publication_state("frozen-before-network", &fixture.root)
                .await
                .unwrap(),
            NativeRootPublicationState::Frozen { .. }
        ));
    }
    let store = DurableStore::open(directory.path());
    let vault = ContentRootVault::new(&store, &fixture.packet.actor_id, &endpoint);
    let history =
        retry_frozen_native_root_publication(&fixture.client, &vault, "business-operation")
            .await
            .unwrap()
            .pop()
            .unwrap();
    assert!(same_packet(history.packet(), &fixture.packet).unwrap());
    assert_eq!(
        vault
            .native_publication_intents("business-operation")
            .await
            .unwrap(),
        vec![
            "frozen-before-network".to_owned(),
            "interrupted-before-freeze".to_owned()
        ]
    );
    server.join().unwrap();
    let trace = trace.lock().unwrap();
    assert_eq!(trace.len(), 2);
    assert_eq!(trace[0].1, trace[1].1);
    assert!(
        same_packet(
            &serde_json::from_slice::<KeyBackup>(&trace[0].1).unwrap(),
            &fixture.packet
        )
        .unwrap()
    );
    drop(trace);
    fixture.source.active.store(false, Ordering::SeqCst);
    // A repaired history has no current refs/capability API, and remains cold
    // readable after the live original requester is retired.
    assert!(same_packet(history.packet(), &fixture.packet).unwrap());
    assert!(matches!(
        vault
            .native_root_publication_state("frozen-before-network", &fixture.root)
            .await
            .unwrap(),
        NativeRootPublicationState::Recorded { .. }
    ));
}

#[tokio::test]
async fn native_real_https_late_context_or_signed_wrong_digest_cannot_write_ack_journal() {
    for failure in ["late_context", "wrong_digest"] {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let fixture = native_http_fixture(&format!("https://{}/", listener.local_addr().unwrap()));
        let mut response = fixture.response.clone();
        if failure == "wrong_digest" {
            response.admission.envelope_digest =
                Hash::new(arkret_canonical::sha256_digest(b"wrong original packet")).unwrap();
            response.admission=arkret_signatures::realm_actor_content_backup::sign_realm_actor_content_backup_admission(
                arkret_signatures::realm_actor_content_backup::admission_signing_input(&response.admission).unwrap(),
                arkret_wire::DidUrl::new("did:web:station.example#signing-1").unwrap(),&SigningKey::from_bytes(&[43;32]),
            ).unwrap();
        }
        let retire = if failure == "late_context" {
            Some(fixture.source.clone())
        } else {
            None
        };
        let (server, trace) = serve_native_puts(listener, vec![response], retire);
        let directory = tempfile::tempdir().unwrap();
        let store = DurableStore::open(directory.path());
        let endpoint = endpoint(&fixture.packet);
        let vault = ContentRootVault::new(&store, &fixture.packet.actor_id, &endpoint);
        vault.retain_root(&fixture.root).await.unwrap();
        vault
            .freeze_native_root_publication("original", &fixture.root, &fixture.packet)
            .await
            .unwrap();
        let keys = store.list_secret_keys(None).unwrap();
        let result =
            retry_native_root_publication(&fixture.client, &vault, "original", &fixture.root).await;
        let error = match result {
            Err(error) => error,
            Ok(_) => panic!("invalid native ACK was accepted: {failure}"),
        };
        if failure == "wrong_digest" {
            assert!(
                error
                    .to_string()
                    .contains("differs from immutable first-PUT admission"),
                "{error}"
            );
        } else {
            assert!(error.to_string().contains("retired"), "{error}");
        }
        server.join().unwrap();
        assert_eq!(trace.lock().unwrap().len(), 1);
        assert_eq!(store.list_secret_keys(None).unwrap(), keys);
        assert!(matches!(
            vault
                .native_root_publication_state("original", &fixture.root)
                .await
                .unwrap(),
            NativeRootPublicationState::Frozen { .. }
        ));
    }
}
