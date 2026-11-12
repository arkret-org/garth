//! Real HTTPS prepare/head/PUT orchestration. The test Station signs its own
//! declared reference cut; native server/PG acceptance belongs to joint tests.

use std::sync::atomic::AtomicUsize;

use arkret_models_integration::{
    RealmActorMaterial, RealmActorMaterialCurrentEntry, RealmActorMaterialPurpose,
    RealmActorMaterialRequestBody, RealmActorMaterialSignatureInput,
};
use arkret_wire::{CommitStreamHead, CurrentRevision, CurrentState, DetachedSignatureContext};

use super::*;

fn input(fixture: &NativeHttpFixture) -> arkret_models_crypto::ContentBackupNextPrepareInput {
    let data = arkret_schema_conformance::spec_json_artifact(
        "fixtures/realm-actor-content-backup-fixture.json",
    )
    .unwrap();
    let mut binding = fixture.packet.auth_binding.clone().unwrap();
    binding.recovery_ref.event_id =
        arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [201; 32]);
    binding.recovery_ref.commit_id = arkret_wire::RealmCommitId::from_digest([202; 32]);
    binding.recovery_ref.stream_position += 20;
    arkret_models_crypto::ContentBackupNextPrepareInput {
        auth_binding: binding,
        content_backup_recipient: serde_json::from_value(data["recipient"].clone()).unwrap(),
        active_series_id: fixture.packet.series_id.clone(),
    }
}

fn signed_material(
    request: RealmActorMaterialRequestBody,
    fixture: &NativeHttpFixture,
    bad_nonce: bool,
    prepared: &arkret_models_crypto::ContentBackupNextPrepareInput,
) -> serde_json::Value {
    let RealmActorMaterialRequestBody::Current {
        actor_id,
        request_nonce,
        selectors,
    } = &request
    else {
        panic!("native prepare must request exact current material")
    };
    assert_eq!(selectors.len(), 2);
    assert_eq!(actor_id, &fixture.packet.actor_id);
    let prepared = prepared.clone();
    let recovery_source = prepared.auth_binding.recovery_ref.clone();
    let data = arkret_schema_conformance::spec_json_artifact(
        "fixtures/realm-actor-content-backup-fixture.json",
    )
    .unwrap();
    let mut series_source: arkret_wire::CommittedEventRef =
        serde_json::from_value(data["native_current_entry"]["source_ref"].clone()).unwrap();
    series_source.stream_ref = recovery_source.stream_ref.clone();
    let recovery:arkret_models_integration::RealmActorRecoveryValue=serde_json::from_value(serde_json::json!({
        "kind":"manager_native","enabled":false,"pending":null,"content_backup_recipient":prepared.content_backup_recipient,
        "content_backup_recipient_ref":prepared.auth_binding.recipient_ref,
    })).unwrap();
    let series = arkret_models_collaboration::RealmActorKeyBackupActiveSeriesValue {
        active_series_id: prepared.active_series_id.clone(),
        series_pointer_version: 1,
        manager_ref: prepared.auth_binding.manager_ref.clone(),
        recovery_ref: fixture
            .packet
            .auth_binding
            .as_ref()
            .unwrap()
            .recovery_ref
            .clone(),
        recipient_ref: prepared.auth_binding.recipient_ref.clone(),
    };
    let current = |selector: arkret_wire::CurrentSelector,
                   source: &arkret_wire::CommittedEventRef,
                   value: serde_json::Value| {
        RealmActorMaterialCurrentEntry::Present {
            current_state: CurrentState::Value {
                selector,
                source_stream_ref: source.stream_ref.clone(),
                revision: CurrentRevision {
                    commit_id: source.commit_id.clone(),
                    stream_position: source.stream_position,
                },
                value,
            },
            source_ref: source.clone(),
        }
    };
    let head_source = if series_source.stream_position >= recovery_source.stream_position {
        &series_source
    } else {
        &recovery_source
    };
    let issued_at =
        chrono::DateTime::from_timestamp_millis(chrono::Utc::now().timestamp_millis()).unwrap();
    let mut nonce = request_nonce.clone();
    if bad_nonce {
        nonce.replace_range(..1, if nonce.starts_with('A') { "B" } else { "A" });
    }
    let (genesis, _) = crate::own_station_results::tests::member_genesis::founding_original();
    let unsigned = RealmActorMaterialSignatureInput {
        realm_id: genesis.event.realm_id.clone(),
        actor_id: actor_id.clone(),
        purpose: RealmActorMaterialPurpose::Current,
        request_digest: Hash::new(arkret_canonical::canonical_sha256(&request).unwrap()).unwrap(),
        request_nonce: nonce,
        requester_actor_id: actor_id.clone(),
        governance_generation: 0,
        authority_ref: arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(
            genesis.event.event_id,
        ),
        control_stream_head: Some(CommitStreamHead {
            stream_ref: head_source.stream_ref.clone(),
            stream_position: head_source.stream_position,
            commit_id: head_source.commit_id.clone(),
        }),
        issued_at,
        expires_at: issued_at + chrono::Duration::seconds(30),
        material: RealmActorMaterial::Current {
            entries: vec![
                current(
                    selectors[0].clone(),
                    &recovery_source,
                    serde_json::to_value(recovery).unwrap(),
                ),
                current(
                    selectors[1].clone(),
                    &series_source,
                    serde_json::to_value(series).unwrap(),
                ),
            ],
            next_prepare_input: Some(prepared),
        },
    };
    let signature = arkret_signatures::detached_object::sign_detached_object(
        &unsigned,
        DetachedSignatureContext::RealmActorMaterial,
        arkret_wire::DidUrl::new("did:web:station.example#signing-1").unwrap(),
        issued_at,
        &SigningKey::from_bytes(&[43; 32]),
    )
    .unwrap();
    serde_json::to_value(unsigned.into_signed(signature)).unwrap()
}

fn empty_head(
    fixture: &NativeHttpFixture,
    prepared: &arkret_models_crypto::ContentBackupNextPrepareInput,
) -> serde_json::Value {
    let prepared = prepared.clone();
    let head = arkret_models_crypto::RealmActorBackupSeriesHeadResponseBody {
        purpose: arkret_models_crypto::RealmActorBackupSeriesHeadResponseBodyPurpose::Value,
        realm_actor_id: fixture.packet.actor_id.as_realm_actor_id().unwrap().clone(),
        effective_scope: fixture.root.root_context.effective_scope.clone(),
        active_series: arkret_models_crypto::RealmActorBackupActiveSeriesState {
            realm_actor_id: fixture.packet.actor_id.as_realm_actor_id().unwrap().clone(),
            effective_scope: fixture.root.root_context.effective_scope.clone(),
            manager_ref: prepared.auth_binding.manager_ref,
            recovery_ref: fixture
                .packet
                .auth_binding
                .as_ref()
                .unwrap()
                .recovery_ref
                .clone(),
            recipient_ref: prepared.auth_binding.recipient_ref,
            authority_commit_id: fixture
                .response
                .admission
                .device_authorize_ref
                .commit_id
                .clone(),
            secret_storage: arkret_models_crypto::BackupActiveSeriesPointer::Active {
                active_series_id: prepared.active_series_id,
                series_pointer_version: 1,
            },
        },
        items: vec![],
    };
    serde_json::to_value(head).unwrap()
}

fn signed_put_reply(fixture: &NativeHttpFixture, packet: &KeyBackup) -> serde_json::Value {
    let mut admission = arkret_signatures::realm_actor_content_backup::admission_signing_input(
        &fixture.response.admission,
    )
    .unwrap();
    admission.backup_id = packet.backup_id.clone();
    admission.envelope_digest =
        Hash::new(arkret_canonical::canonical_sha256(packet).unwrap()).unwrap();
    admission.ciphertext_digest = packet.ciphertext_digest.clone();
    let auth = packet.auth_binding.as_ref().unwrap();
    admission.manager_ref = auth.manager_ref.clone();
    admission.recovery_ref = auth.recovery_ref.clone();
    admission.recipient_ref = auth.recipient_ref.clone();
    let admission =
        arkret_signatures::realm_actor_content_backup::sign_realm_actor_content_backup_admission(
            admission,
            arkret_wire::DidUrl::new("did:web:station.example#signing-1").unwrap(),
            &SigningKey::from_bytes(&[43; 32]),
        )
        .unwrap();
    arkret_signatures::realm_actor_content_backup::verify_realm_actor_backup_packet(
        packet, &admission,
    )
    .unwrap();
    serde_json::to_value(RealmActorBackupPutResponseBody {
        status: arkret_models_crypto::KeyBackupPutStatus::Accepted,
        backup_id: packet.backup_id.clone(),
        ciphertext_digest: packet.ciphertext_digest.clone(),
        admission,
    })
    .unwrap()
}

fn head_with_original(
    fixture: &NativeHttpFixture,
    prepared: &arkret_models_crypto::ContentBackupNextPrepareInput,
) -> serde_json::Value {
    let mut head = empty_head(fixture, prepared);
    let packet = serde_json::to_value(&fixture.packet).unwrap();
    let mut metadata = serde_json::Map::new();
    for field in [
        "backup_id",
        "actor_id",
        "device_id",
        "backup_kind",
        "backup_version",
        "series_id",
        "series_sequence",
        "supersedes_id",
        "supersedes_digest",
        "created_at",
        "updated_at",
        "ciphertext_digest",
        "auth_binding",
    ] {
        if let Some(value) = packet.get(field) {
            metadata.insert(field.to_owned(), value.clone());
        }
    }
    metadata.insert(
        "encryption".into(),
        serde_json::json!({
            "recipient_method":packet["encryption"]["recipient_method"],
            "recipient_key_ref":packet["encryption"]["recipient_key_ref"],
            "hpke_suite":packet["encryption"]["hpke_suite"],
        }),
    );
    let metadata: arkret_models_crypto::RealmActorBackupMetadata =
        serde_json::from_value(serde_json::Value::Object(metadata)).unwrap();
    head["items"] = serde_json::to_value(vec![arkret_models_crypto::RealmActorBackupHeadEntry {
        metadata,
        admission: fixture.response.admission.clone(),
    }])
    .unwrap();
    head
}

fn challenge_reply(
    fixture: &NativeHttpFixture,
    prepared: &arkret_models_crypto::ContentBackupNextPrepareInput,
    body: &[u8],
) -> serde_json::Value {
    let request: arkret_models_crypto::RealmActorBackupIssueUnlockChallengeRequestBody =
        serde_json::from_slice(body).unwrap();
    assert_eq!(
        request.envelope_digest,
        fixture.response.admission.envelope_digest
    );
    let now =
        chrono::DateTime::from_timestamp_millis(chrono::Utc::now().timestamp_millis()).unwrap();
    let context = fixture.client.context().unwrap();
    let challenge = arkret_models_crypto::RealmActorBackupUnlockChallenge {
        challenge_id: arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
            [21; 32],
        ))
        .unwrap(),
        challenge: arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode([22; 32]))
            .unwrap(),
        nonce: arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode([23; 32]))
            .unwrap(),
        operation: arkret_models_crypto::RealmActorBackupUnlockChallengeOperation::Value,
        backup_id: fixture.packet.backup_id.clone(),
        audience: arkret_wire::NonEmptyString::new(
            url::Url::parse(context.binding().base_url())
                .unwrap()
                .origin()
                .ascii_serialization(),
        )
        .unwrap(),
        service_id: context.binding().service_id().clone(),
        request_id: arkret_wire::NonEmptyString::new(request.request_id.as_str()).unwrap(),
        issued_at: now,
        expires_at: now + chrono::Duration::seconds(30),
        series_id: fixture.packet.series_id.clone(),
        ciphertext_digest: fixture.packet.ciphertext_digest.clone(),
        kind: request.kind,
        purpose: request.purpose,
        realm_actor_id: request.realm_actor_id,
        effective_scope: request.effective_scope,
        manager_ref: prepared.auth_binding.manager_ref.clone(),
        recovery_ref: prepared.auth_binding.recovery_ref.clone(),
        recipient_ref: prepared.auth_binding.recipient_ref.clone(),
        requesting_device_id: Some(context.device_id().clone()),
        device_authorize_event_id: Some(context.authorization_event_id().clone()),
        device_generation: Some(prepared.auth_binding.device_generation),
        envelope_digest: request.envelope_digest,
    };
    challenge.validate_at(chrono::Utc::now()).unwrap();
    serde_json::to_value(challenge).unwrap()
}

fn serve_flow(
    listener: std::net::TcpListener,
    fixture: NativeHttpFixture,
    bad_nonce: bool,
) -> (std::thread::JoinHandle<()>, HttpTrace) {
    let prepared = input(&fixture);
    serve_flow_at_cut(listener, fixture, bad_nonce, prepared, false, false)
}

fn serve_flow_at_cut(
    listener: std::net::TcpListener,
    fixture: NativeHttpFixture,
    bad_nonce: bool,
    prepared: arkret_models_crypto::ContentBackupNextPrepareInput,
    original_head: bool,
    put_after_unlock: bool,
) -> (std::thread::JoinHandle<()>, HttpTrace) {
    let tls = crate::test_fixtures::native_tls::server_config();
    let trace = Arc::new(Mutex::new(Vec::new()));
    let captured = trace.clone();
    listener.set_nonblocking(true).unwrap();
    let server = std::thread::spawn(move || {
        let steps = if bad_nonce {
            1
        } else if original_head {
            if put_after_unlock { 5 } else { 4 }
        } else {
            3
        };
        for step in 0..steps {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
            let socket = loop {
                match listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(
                            std::time::Instant::now() < deadline,
                            "native flow step {step} missing"
                        );
                        std::thread::sleep(std::time::Duration::from_millis(5));
                    }
                    Err(error) => panic!("TLS accept: {error}"),
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
                if let Some(i) = bytes.windows(4).position(|x| x == b"\r\n\r\n") {
                    break i + 4;
                }
                let mut buffer = [0; 4096];
                let read = stream.read(&mut buffer).unwrap();
                assert!(read > 0);
                bytes.extend_from_slice(&buffer[..read]);
            };
            let header = String::from_utf8_lossy(&bytes[..end]);
            let line = header.lines().next().unwrap().to_owned();
            let lower = header.to_ascii_lowercase();
            assert!(!lower.contains("authorization:"));
            assert!(lower.contains("signature-input:"));
            assert!(lower.contains("arkret-managed-device"));
            let length = lower
                .lines()
                .find_map(|x| {
                    x.strip_prefix("content-length:")
                        .map(|x| x.trim().parse::<usize>().unwrap())
                })
                .unwrap_or(0);
            while bytes.len() < end + length {
                let mut buffer = [0; 4096];
                let read = stream.read(&mut buffer).unwrap();
                assert!(read > 0);
                bytes.extend_from_slice(&buffer[..read]);
            }
            let body = &bytes[end..end + length];
            captured.lock().unwrap().push((line.clone(), body.to_vec()));
            let response = match step {
                0 => {
                    assert!(line.starts_with("POST /_arkret/self/realm-actors/material "));
                    signed_material(
                        serde_json::from_slice(body).unwrap(),
                        &fixture,
                        bad_nonce,
                        &prepared,
                    )
                }
                1 => {
                    assert!(line.starts_with("GET /_arkret/self/keys/backups?"));
                    let path = line.split_whitespace().nth(1).unwrap();
                    let url = url::Url::parse(&format!("https://station.example{path}")).unwrap();
                    let query = arkret_models_crypto::KeysBackupsListParameters::from_query_pairs(
                        url.query_pairs(),
                    )
                    .unwrap();
                    assert!(matches!(
                        query,
                        arkret_models_crypto::KeysBackupsListParameters::Device(_)
                    ));
                    if original_head {
                        head_with_original(&fixture, &prepared)
                    } else {
                        empty_head(&fixture, &prepared)
                    }
                }
                2 if original_head => {
                    assert!(line.contains("/unlock-challenge "));
                    challenge_reply(&fixture, &prepared, body)
                }
                3 if original_head => {
                    assert!(line.contains("/unlock "));
                    let request: serde_json::Value = serde_json::from_slice(body).unwrap();
                    let proof: arkret_models_crypto::RealmActorDeviceKeyBackupUnlockProof =
                        serde_json::from_value(request["proof"].clone()).unwrap();
                    let signature = arkret_canonical::base64url_decode(
                        proof.signature_proof.signature.as_str(),
                    )
                    .unwrap();
                    SigningKey::from_bytes(&[123; 32])
                        .verifying_key()
                        .verify_strict(
                            &proof.signing_payload_bytes().unwrap(),
                            &ed25519_dalek::Signature::from_slice(&signature).unwrap(),
                        )
                        .unwrap();
                    serde_json::to_value(arkret_models_crypto::RealmActorBackupUnlockResponseBody {
                        backup: fixture.packet.clone(),
                        admission: fixture.response.admission.clone(),
                    })
                    .unwrap()
                }
                _ => {
                    assert!(line.starts_with("PUT /_arkret/self/keys/backups/"));
                    signed_put_reply(&fixture, &serde_json::from_slice(body).unwrap())
                }
            };
            let response = serde_json::to_vec(&response).unwrap();
            write!(stream,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",response.len()).unwrap();
            stream.write_all(&response).unwrap();
            stream.flush().unwrap();
        }
    });
    (server, trace)
}

#[tokio::test]
async fn native_first_publication_uses_signed_current_input_real_https_and_sdk_hpke_before_journal()
{
    for bad_nonce in [false, true] {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("https://{}/", listener.local_addr().unwrap());
        let fixture = native_http_fixture(&base);
        let root = fixture.root.clone();
        let packet = fixture.packet.clone();
        let (genesis, _) = crate::own_station_results::tests::member_genesis::founding_original();
        let materials = crate::own_station_results::tests::member_genesis::native_client_materials(
            &base, &genesis,
        );
        let (server, trace) = serve_flow(listener, fixture, bad_nonce);
        let directory = tempfile::tempdir().unwrap();
        let store = DurableStore::open(directory.path());
        let endpoint = endpoint(&packet);
        let vault = ContentRootVault::new(&store, &packet.actor_id, &endpoint);
        let signatures = Arc::new(AtomicUsize::new(0));
        let signed = signatures.clone();
        let parameters = NativeRootPublicationParameters {
            operation: "first-native-root",
            root: &root,
            created_at: packet.created_at,
            author: arkret_crypto::backup::KeyBackupAuthBinding {
                device_id: packet.device_id.clone().unwrap(),
                verification_method: packet.signature_proof.verification_method.clone(),
                signature_algorithm: packet.signature_proof.signature_algorithm,
                device_authorize_event_id: packet
                    .signature_proof
                    .device_authorize_event_id
                    .clone()
                    .unwrap(),
            },
            domain_separation: packet.domain_separation.clone(),
            authority: &materials.authority,
            station_resolution: &materials.resolution,
            authority_keys: &materials.keys,
        };
        let result =
            publish_native_content_root(&materials.client, &vault, parameters, move |bytes| {
                signed.fetch_add(1, Ordering::SeqCst);
                Ok(SigningKey::from_bytes(&[123; 32])
                    .sign(bytes)
                    .to_bytes()
                    .to_vec())
            })
            .await;
        server.join().unwrap();
        if bad_nonce {
            let error = match result {
                Err(error) => error,
                Ok(_) => panic!("wrong signed nonce was accepted"),
            };
            assert!(
                error.to_string().contains("selectors, cut or bindings"),
                "{error}"
            );
            assert_eq!(signatures.load(Ordering::SeqCst), 0);
            assert_eq!(trace.lock().unwrap().len(), 1);
            assert!(matches!(
                vault
                    .native_root_publication_state("first-native-root", &root)
                    .await
                    .unwrap(),
                NativeRootPublicationState::Unprepared
            ));
        } else {
            let outcome = result.unwrap();
            assert_ne!(
                outcome.backup_refs().unwrap(),
                vec![packet.backup_id.clone()]
            );
            assert_eq!(signatures.load(Ordering::SeqCst), 1);
            let trace = trace.lock().unwrap();
            assert_eq!(trace.len(), 3);
            let sent: KeyBackup = serde_json::from_slice(&trace[2].1).unwrap();
            assert!(same_packet(outcome.original_packet().unwrap(), &sent).unwrap());
            assert_ne!(
                sent.auth_binding.as_ref().unwrap().recovery_ref,
                packet.auth_binding.as_ref().unwrap().recovery_ref
            );
            drop(trace);
            let intents = vault
                .native_publication_intents("first-native-root")
                .await
                .unwrap();
            assert_eq!(intents.len(), 1);
            assert!(matches!(
                vault
                    .native_root_publication_state(&intents[0], &root)
                    .await
                    .unwrap(),
                NativeRootPublicationState::Recorded { .. }
            ));
        }
    }
}

async fn historical_ack_requires_current_cut(change: &str) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("https://{}/", listener.local_addr().unwrap());
    let fixture = native_http_fixture(&base);
    let packet = fixture.packet.clone();
    let old_root = fixture.root.clone();
    let mut root = old_root.clone();
    let mut prepared = input(&fixture);
    match change {
        "selected_series" => {
            prepared.active_series_id = arkret_wire::BackupSeriesId::new(
                "ak:backup_series:0196419b-0000-7000-8000-000000000099",
            )
            .unwrap();
        }
        "recovery_source" => {
            // input() advances only current Recovery while the real old series
            // keeps its historical declaration. No fresh series is required.
            assert_ne!(
                prepared.auth_binding.recovery_ref,
                packet.auth_binding.as_ref().unwrap().recovery_ref
            );
        }
        "epoch" => {
            root.root_context.epoch += 1;
            root.root_context.group_state_ref =
                arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [203; 32]);
            root.root_ref = arkret_crypto::content_history::content_root_ref(
                &root.root_base64url,
                &root.root_context,
            )
            .unwrap();
        }
        _ => panic!("unknown current cut mutation"),
    }
    let expected_input = prepared.clone();
    let (genesis, _) = crate::own_station_results::tests::member_genesis::founding_original();
    let materials =
        crate::own_station_results::tests::member_genesis::native_client_materials(&base, &genesis);
    let directory = tempfile::tempdir().unwrap();
    let endpoint = endpoint(&packet);
    let operation = "stable-business-operation";
    let old_intent = "previous-selected-series-intent";
    {
        let store = DurableStore::open(directory.path());
        let vault = ContentRootVault::new(&store, &packet.actor_id, &endpoint);
        vault.retain_root(&old_root).await.unwrap();
        vault
            .register_native_publication_intent(operation, old_intent)
            .await
            .unwrap();
        vault
            .freeze_native_root_publication(old_intent, &old_root, &packet)
            .await
            .unwrap();
        vault
            .commit_native_publication_history(old_intent, &old_root, &packet, &fixture.response)
            .await
            .unwrap();
    }
    // Reopen real encrypted storage containing a genuine prior signed ACK.
    // Its existence must not suppress today's prepare and selected-head check.
    let store = DurableStore::open(directory.path());
    let vault = ContentRootVault::new(&store, &packet.actor_id, &endpoint);
    let reuse = change == "recovery_source";
    let successor = change == "epoch";
    let (server, trace) = serve_flow_at_cut(
        listener,
        fixture,
        false,
        prepared,
        reuse || successor,
        successor,
    );
    let signatures = Arc::new(AtomicUsize::new(0));
    let signed = signatures.clone();
    let outcome = publish_native_content_root(
        &materials.client,
        &vault,
        NativeRootPublicationParameters {
            operation,
            root: &root,
            created_at: packet.created_at,
            author: arkret_crypto::backup::KeyBackupAuthBinding {
                device_id: packet.device_id.clone().unwrap(),
                verification_method: packet.signature_proof.verification_method.clone(),
                signature_algorithm: packet.signature_proof.signature_algorithm,
                device_authorize_event_id: packet
                    .signature_proof
                    .device_authorize_event_id
                    .clone()
                    .unwrap(),
            },
            domain_separation: packet.domain_separation.clone(),
            authority: &materials.authority,
            station_resolution: &materials.resolution,
            authority_keys: &materials.keys,
        },
        move |bytes| {
            signed.fetch_add(1, Ordering::SeqCst);
            Ok(SigningKey::from_bytes(&[123; 32])
                .sign(bytes)
                .to_bytes()
                .to_vec())
        },
    )
    .await
    .unwrap();
    server.join().unwrap();
    if reuse {
        assert_eq!(signatures.load(Ordering::SeqCst), 0);
        {
            let requests = trace.lock().unwrap();
            assert_eq!(requests.len(), 4);
            assert!(
                requests[0]
                    .0
                    .starts_with("POST /_arkret/self/realm-actors/material ")
            );
            assert!(requests[2].0.contains("/unlock-challenge "));
            assert!(requests[3].0.contains("/unlock "));
            assert!(!requests.iter().any(|request| request.0.starts_with("PUT ")));
        }
        assert_eq!(
            outcome.backup_refs().unwrap(),
            vec![packet.backup_id.clone()]
        );
        assert!(same_packet(outcome.original_packet().unwrap(), &packet).unwrap());
        assert_eq!(
            vault.native_publication_intents(operation).await.unwrap(),
            vec![old_intent.to_owned()]
        );
        return;
    }
    let sent: KeyBackup = {
        let requests = trace.lock().unwrap();
        assert_eq!(
            requests.len(),
            if successor { 5 } else { 3 },
            "{change}: history bypassed current cut"
        );
        assert!(
            requests[0]
                .0
                .starts_with("POST /_arkret/self/realm-actors/material ")
        );
        serde_json::from_slice(&requests.last().unwrap().1).unwrap()
    };
    assert_ne!(sent.backup_id, packet.backup_id);
    assert_eq!(sent.series_id, expected_input.active_series_id);
    assert_eq!(signatures.load(Ordering::SeqCst), 1);
    if successor {
        assert_eq!(sent.series_sequence, packet.series_sequence + 1);
        assert_eq!(sent.supersedes_id.as_ref(), Some(&packet.backup_id));
    }
    assert_eq!(
        sent.auth_binding.as_ref().unwrap(),
        &expected_input.auth_binding
    );
    assert_eq!(
        sent.contents[0].root_context.as_ref(),
        Some(&root.root_context)
    );
    assert_eq!(outcome.backup_refs().unwrap(), vec![sent.backup_id.clone()]);
    let intents = vault.native_publication_intents(operation).await.unwrap();
    assert_eq!(intents.len(), 2);
    assert!(intents.iter().any(|intent| intent == old_intent));
    assert!(
        same_packet(
            &vault.frozen_backup(old_intent).await.unwrap().unwrap(),
            &packet
        )
        .unwrap()
    );
    assert!(matches!(
        vault
            .native_root_publication_state(old_intent, &old_root)
            .await
            .unwrap(),
        NativeRootPublicationState::Recorded { .. }
    ));
    let current = intents
        .iter()
        .find(|intent| intent.as_str() != old_intent)
        .unwrap();
    assert!(matches!(
        vault
            .native_root_publication_state(current, &root)
            .await
            .unwrap(),
        NativeRootPublicationState::Recorded { .. }
    ));
}

#[tokio::test]
async fn native_old_ack_after_series_replacement_requires_new_current_series_publication() {
    historical_ack_requires_current_cut("selected_series").await;
}

#[tokio::test]
async fn native_old_ack_after_benign_recovery_advance_revalidates_head_and_unlock_without_resealing()
 {
    historical_ack_requires_current_cut("recovery_source").await;
}

#[tokio::test]
async fn native_same_business_operation_after_epoch_change_retains_old_intent_and_publishes_new_root()
 {
    historical_ack_requires_current_cut("epoch").await;
}
