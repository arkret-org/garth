//! The narrow member-Genesis source uses real producer Ed25519 signatures.
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use arkret_http_client::own_station_device_results::{
    OwnStationDeviceBinding, OwnStationDeviceClient, OwnStationDeviceInstance,
    OwnStationDeviceSnapshot, OwnStationDeviceSource,
};
use arkret_models_identity::ResolvedSignerKey;
use arkret_wire::{CommittedEventFullView, DetachedSignatureContext, ScopeRef};
use ed25519_dalek::SigningKey;

use super::*;

type NativeResponse = arkret_http_client::own_station_device_results::BoundOwnStationDeviceResponse<
    EventId,
    CommittedEventView,
>;

pub(crate) struct NativeSource {
    snapshot: Mutex<OwnStationDeviceSnapshot>,
    pub(crate) active: AtomicBool,
}
impl OwnStationDeviceSource for NativeSource {
    fn snapshot(&self) -> arkret_http_client::Result<OwnStationDeviceSnapshot> {
        if !self.active.load(Ordering::SeqCst) {
            return Err(arkret_http_client::Error::Protocol("Device retired".into()));
        }
        Ok(self.snapshot.lock().unwrap().clone())
    }
}

pub(crate) fn founding_original() -> (CommittedEventFullView, ResolvedSignerKey) {
    founding_original_with_purpose(
        arkret_models_collaboration::events_payloads::realm::RealmPurpose::Collaboration,
    )
}

fn founding_original_with_purpose(
    purpose: arkret_models_collaboration::events_payloads::realm::RealmPurpose,
) -> (CommittedEventFullView, ResolvedSignerKey) {
    use arkret_models_collaboration::authority_commit::AccountDeviceHistoricalSignerFact;
    use arkret_models_collaboration::events_payloads::realm::{RealmCreatePayload, RealmGenesis};
    use arkret_signatures::{Ed25519DetachedJwsSigner, SignEventOptions, sign_event};
    let (agent, _, key) = native_self_genesis_fixture("alice");
    let account = agent.actual_signer().as_account_id().unwrap();
    let object = RealmGenesis::new(
        purpose,
        arkret_wire::GenesisSalt::new("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap(),
        arkret_wire::TrustDomainId::new("ak:trust_domain:station.example").unwrap(),
        arkret_wire::SecurityClass::Standard,
        account.station_id.clone(),
        arkret_wire::JoinRule::Invite,
        arkret_wire::HistoryAccess::SinceJoin,
        arkret_wire::Discoverability::Listed,
        None,
        None,
    )
    .unwrap();
    let mut event = crate::test_fixtures::event(
        93,
        arkret_wire::EventKind::RealmCreate,
        RealmCreatePayload::new(object).to_value().unwrap(),
    );
    event.actor_id = arkret_wire::ActorId::account(account.clone());
    event.scope_ref = ScopeRef::RealmGenesis;
    event.created_at = crate::test_fixtures::at(2);
    event.producer_proof = None;
    let mut authored = arkret_wire::AuthoredEvent::finalize_with_digest_suite(
        event,
        arkret_canonical::DigestSuite::Sha256,
    )
    .unwrap();
    sign_event(
        &mut authored,
        &Ed25519DetachedJwsSigner::new(
            SigningKey::from_bytes(&[41; 32]),
            format!(
                "did:web:alice.example#{}",
                crate::test_fixtures::device_id()
            ),
        ),
        SignEventOptions::new().with_created_at(crate::test_fixtures::at(2)),
    )
    .unwrap();
    let event = authored.into_event();
    let fact = AccountDeviceHistoricalSignerFact {
        event_id: event.event_id.clone(),
        actor: event.actor_id.clone(),
        device_id: crate::test_fixtures::device_id(),
        verification_method: event
            .producer_proof
            .as_ref()
            .unwrap()
            .verification_method
            .clone(),
        key: key.clone(),
        accepted_at: crate::test_fixtures::at(1),
    };
    let mut commit = crate::test_fixtures::commit(
        93,
        &event,
        CommitStreamRef::Realm {
            realm_id: event.realm_id.clone(),
        },
        0,
    );
    commit.authority_ref =
        arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(event.event_id.clone());
    commit.producer_signer_fact_digest = Some(fact.digest().unwrap());
    (
        CommittedEventFullView {
            event,
            commit: seal_native_fixture_commit(commit),
        },
        key,
    )
}

pub(crate) fn native_client(
    base: &str,
    original: &CommittedEventFullView,
) -> (OwnStationDeviceClient, Arc<NativeSource>) {
    let materials = native_client_materials(base, original);
    (materials.client, materials.source)
}

pub(crate) struct NativeClientMaterials {
    pub(crate) client: OwnStationDeviceClient,
    pub(crate) source: Arc<NativeSource>,
    pub(crate) authority: arkret_identity::VerifiedRealmAuthority,
    pub(crate) resolution: arkret_models_identity::AuthenticatedServiceResolution,
    pub(crate) keys: arkret_identity::RealmAuthorityKeyMap,
}

pub(crate) fn native_client_materials(
    base: &str,
    original: &CommittedEventFullView,
) -> NativeClientMaterials {
    use arkret_identity::{
        RealmAuthorityFreshness, RealmAuthorityKeyMap, verify_realm_authority_bundle,
    };
    let route = crate::service_route_material::test_fixture::current_web_route_fixture(
        "station.example",
        "station",
        43,
    );
    let now = chrono::Utc::now();
    let nonce = arkret_wire::Base64UrlString::new("AAAAAAAAAAAAAAAAAAAAAA").unwrap();
    let head = CommitStreamHead {
        stream_ref: original.commit.stream_ref.clone(),
        stream_position: 0,
        commit_id: original.commit.commit_id.clone(),
    };
    let mut assertion = arkret_wire::RealmAuthorityCurrentAssertion {
        realm_id: original.event.realm_id.clone(),
        current_generation: 0,
        current_service_id: route.service_id.clone(),
        last_handoff_ref: None,
        realm_stream_head: head.clone(),
        nonce: nonce.clone(),
        expires_at: now + chrono::Duration::minutes(5),
        signature: crate::test_fixtures::detached_signature(
            DetachedSignatureContext::RealmAuthorityCurrentAssertion,
        ),
    };
    assertion.signature = arkret_signatures::detached_object::sign_detached_object(
        &arkret_canonical::canonical::unsigned_value(&assertion, &["signature"]).unwrap(),
        DetachedSignatureContext::RealmAuthorityCurrentAssertion,
        arkret_wire::DidUrl::new("did:web:station.example#signing-1").unwrap(),
        now,
        &route.signing_key,
    )
    .unwrap();
    let bundle = arkret_wire::RealmAuthorityBundle {
        realm_id: original.event.realm_id.clone(),
        genesis_event: original.event.clone(),
        genesis_commit: original.commit.clone(),
        authority_transitions: vec![],
        current_generation: 0,
        current_service_id: route.service_id.clone(),
        current_route_record: serde_json::to_value(&route.resolution).unwrap(),
        realm_stream_head: head,
        bundle_issued_at: now,
        current_assertion: assertion,
    };
    let keys = RealmAuthorityKeyMap::new().with_key(
        &arkret_wire::DidUrl::new("did:web:station.example#notary").unwrap(),
        arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: route.signing_key.verifying_key().to_bytes().to_vec(),
        },
    );
    let authority =
        verify_realm_authority_bundle(&bundle, &RealmAuthorityFreshness::new(now, nonce), &keys)
            .unwrap();
    let mut description = route.describe;
    description.transport_bindings = vec![arkret_models_discovery::TransportBinding::HttpJson {
        base_url: base.into(),
        extension_profile_required: (),
    }];
    let base = url::Url::parse(base).unwrap();
    let binding = OwnStationDeviceBinding::from_description(&base, &description).unwrap();
    let key = SigningKey::from_bytes(&[123; 32]);
    let metadata = arkret_models_integration::AppletManagedDeviceMetadata {
        actor_id: arkret_wire::ActorId::realm(arkret_wire::RealmActorId {
            realm_id: original.event.realm_id.clone(),
            principal_id: arkret_wire::DidCoreId::new("ak:did_core:webvh:zbot").unwrap(),
        }),
        device_id: crate::test_fixtures::device_id(),
        authorization_event_id: EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [124; 32],
        ),
        applet_id: arkret_wire::AppletId::new("ak:applet:01964137-0000-7000-8000-000000000123")
            .unwrap(),
        effective_scope: ScopeRef::Realm {
            realm_id: original.event.realm_id.clone(),
        },
        nonce: arkret_canonical::base64url_encode([125; 16]),
    };
    let snapshot = OwnStationDeviceSnapshot::new(
        binding,
        &authority,
        &metadata,
        key.verifying_key().to_bytes(),
        now - chrono::Duration::minutes(1),
        now + chrono::Duration::minutes(5),
        0,
        OwnStationDeviceInstance::default(),
    )
    .unwrap();
    let source = Arc::new(NativeSource {
        snapshot: Mutex::new(snapshot),
        active: AtomicBool::new(true),
    });
    let fingerprint =
        arkret_canonical::ed25519_pubkey_to_did_key_multibase(key.verifying_key().as_bytes());
    let raw = arkret_http_client::ClientBuilder::new(base)
        .http_client(crate::test_fixtures::native_tls::client())
        .retry(arkret_http_client::RetryConfig::standard(0))
        .build()
        .unwrap()
        .with_managed_device_http_signer(
            metadata,
            route.service_id,
            arkret_http_client::HttpMessageSigner::new(
                format!("did:key:{fingerprint}#{fingerprint}"),
                key,
            ),
        )
        .unwrap();
    NativeClientMaterials {
        client: OwnStationDeviceClient::new(raw, source.clone()).unwrap(),
        source,
        authority,
        resolution: route.resolution,
        keys,
    }
}

fn native_server(
    original: &CommittedEventFullView,
    bodies: Vec<serde_json::Value>,
    retire_during_query: bool,
) -> (
    OwnStationDeviceClient,
    Arc<NativeSource>,
    std::thread::JoinHandle<()>,
    Arc<Mutex<Vec<String>>>,
) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let (client, source) = native_client(
        &format!("https://{}/", listener.local_addr().unwrap()),
        original,
    );
    let active = source.clone();
    let paths = Arc::new(Mutex::new(Vec::new()));
    let observed = paths.clone();
    let tls = crate::test_fixtures::native_tls::server_config();
    listener.set_nonblocking(true).unwrap();
    let handle = std::thread::spawn(move || {
        for body in bodies {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
            let socket = loop {
                match listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(
                            std::time::Instant::now() < deadline,
                            "expected native request did not arrive"
                        );
                        std::thread::sleep(std::time::Duration::from_millis(5));
                    }
                    Err(error) => panic!("native TLS accept failed: {error}"),
                }
            };
            socket
                .set_read_timeout(Some(std::time::Duration::from_secs(10)))
                .unwrap();
            let connection = rustls::ServerConnection::new(tls.clone()).unwrap();
            let mut stream = rustls::StreamOwned::new(connection, socket);
            let mut bytes = Vec::new();
            let header_end = loop {
                if let Some(index) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
                    break index + 4;
                }
                let mut chunk = [0; 4096];
                let count = stream.read(&mut chunk).unwrap();
                assert!(count > 0);
                bytes.extend_from_slice(&chunk[..count]);
            };
            let headers = String::from_utf8_lossy(&bytes[..header_end]).to_ascii_lowercase();
            assert!(!headers.contains("authorization:"));
            assert!(headers.contains("signature-input:"));
            assert!(headers.contains("arkret-managed-device"));
            observed
                .lock()
                .unwrap()
                .push(headers.lines().next().unwrap().to_owned());
            let size = headers
                .lines()
                .find_map(|line| {
                    line.strip_prefix("content-length:")
                        .map(|size| size.trim().parse::<usize>().unwrap())
                })
                .unwrap_or(0);
            while bytes.len() < header_end + size {
                let mut chunk = [0; 4096];
                let count = stream.read(&mut chunk).unwrap();
                assert!(count > 0);
                bytes.extend_from_slice(&chunk[..count]);
            }
            let body = if let Some(key) = body.get("__signer_key") {
                let request: SignerKeysQueryRequestBody =
                    serde_json::from_slice(&bytes[header_end..header_end + size]).unwrap();
                assert!(request.recipient_account_id.is_none());
                assert!(
                    request
                        .recipient_actor_id
                        .as_ref()
                        .unwrap()
                        .as_realm_actor_id()
                        .is_some()
                );
                let selector = request.queries[0].clone();
                let SignerKeyQuerySelector::HistoricalEvent {
                    sender:
                        HistoricalSignerKeyQuerySender::AccountDevice {
                            committed_event_ref,
                            ..
                        },
                } = &selector
                else {
                    panic!("exact historical producer required")
                };
                assert_eq!(committed_event_ref.stream_position, 0);
                let mut selector = selector;
                if body["__wrong_target"] == true {
                    if let SignerKeyQuerySelector::HistoricalEvent {
                        sender:
                            HistoricalSignerKeyQuerySender::AccountDevice {
                                committed_event_ref,
                                ..
                            },
                    } = &mut selector
                    {
                        committed_event_ref.stream_position = 1;
                    }
                }
                let resolution = if body["__unavailable"] == true {
                    SignerKeyResolution::Unavailable { selector }
                } else {
                    SignerKeyResolution::HistoricalResolved {
                        selector,
                        key: serde_json::from_value(key.clone()).unwrap(),
                        accepted_at: crate::test_fixtures::at(1),
                    }
                };
                if retire_during_query {
                    active.active.store(false, Ordering::SeqCst);
                }
                serde_json::to_value(arkret_models_identity::SignerKeyQueryResponseBody {
                    request_id: request.request_id,
                    realm_id: request.realm_id,
                    recipient_account_id: request.recipient_account_id,
                    recipient_actor_id: request.recipient_actor_id,
                    resolutions: vec![resolution],
                })
                .unwrap()
            } else {
                body
            };
            let body = serde_json::to_string(&body).unwrap();
            write!(stream,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",body.len(),body).unwrap();
            stream.flush().unwrap();
        }
    });
    (client, source, handle, paths)
}

async fn candidate(client: &OwnStationDeviceClient, realm: &RealmId) -> NativeResponse {
    client.committed_event_get(&realm.event_id()).await.unwrap()
}

#[tokio::test]
async fn native_and_account_genesis_verify_real_producer_without_scan() {
    use arkret_models_collaboration::events_payloads::realm::RealmPurpose;
    for purpose in [
        RealmPurpose::Collaboration,
        RealmPurpose::DirectConversation,
    ] {
        let (full, key) = founding_original_with_purpose(purpose);
        let realm = full.event.realm_id.clone();
        let row = serde_json::to_value(CommittedEventView::Full(full.clone())).unwrap();
        let (client, _, server, paths) = native_server(
            &full,
            vec![row.clone(), serde_json::json!({"__signer_key":key})],
            false,
        );
        let response = candidate(&client, &realm).await;
        let result = consume_own_station_device_realm_genesis(&client, &realm, response)
            .await
            .unwrap();
        assert_eq!(result.value().unwrap(), &CommittedEventView::Full(full));
        server.join().unwrap();
        {
            let paths = paths.lock().unwrap();
            assert_eq!(paths.len(), 2);
            assert!(paths[0].starts_with("get /_arkret/self/committed-events/"));
            assert!(paths[1].contains("/signer-keys/query"));
            assert!(paths.iter().all(|path| !path.contains("scan")));
        }
        let (account, server, paths) =
            observed_client(vec![row, serde_json::json!({"__signer_key":key})]);
        read_collaboration_realm_genesis(&account, &realm)
            .await
            .unwrap()
            .value()
            .unwrap();
        server.join().unwrap();
        assert_eq!(paths.lock().unwrap().len(), 2);
    }
}

#[tokio::test]
async fn ordinary_native_consumer_still_requires_the_exact_stream_original() {
    let (full, _) = founding_original();
    let realm = full.event.realm_id.clone();
    let scan = StreamScanResponseBody {
        committed_events: vec![],
        readable_floor: None,
        truncated: false,
    };
    let (client, _, server, paths) = native_server(
        &full,
        vec![
            serde_json::to_value(CommittedEventView::Full(full.clone())).unwrap(),
            serde_json::to_value(scan).unwrap(),
        ],
        false,
    );
    let response = candidate(&client, &realm).await;
    assert!(
        consume_own_station_device_event(&client, &realm.event_id(), response)
            .await
            .is_err()
    );
    server.join().unwrap();
    let paths = paths.lock().unwrap();
    assert_eq!(paths.len(), 2);
    assert!(paths[1].contains("scan"));
    assert!(paths.iter().all(|path| !path.contains("signer-keys")));
}

#[tokio::test]
async fn native_genesis_rejects_bad_key_target_unavailable_and_retirement() {
    for failure in [
        "key",
        "signature",
        "fact_digest",
        "target",
        "unavailable",
        "retired",
    ] {
        let (mut full, mut key) = founding_original();
        let realm = full.event.realm_id.clone();
        if failure == "signature" {
            let proof = full.event.producer_proof.as_mut().unwrap();
            let (header, _) = proof.jws.split_once("..").unwrap();
            proof.jws = format!("{header}..{}", arkret_canonical::base64url_encode([0; 64]));
        }
        if failure == "fact_digest" {
            full.commit.producer_signer_fact_digest = Some(
                arkret_wire::Hash::new(arkret_canonical::sha256_digest(b"different original fact"))
                    .unwrap(),
            );
            full.commit = seal_native_fixture_commit(full.commit);
        }
        if failure == "key" {
            key.public_key_base64url =
                arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
                    SigningKey::from_bytes(&[42; 32]).verifying_key().as_bytes(),
                ))
                .unwrap();
        }
        let (client, _, server, _) = native_server(
            &full,
            vec![
                serde_json::to_value(CommittedEventView::Full(full.clone())).unwrap(),
                serde_json::json!({"__signer_key":key,"__wrong_target":failure=="target","__unavailable":failure=="unavailable"}),
            ],
            failure == "retired",
        );
        assert!(
            consume_own_station_device_realm_genesis(
                &client,
                &realm,
                candidate(&client, &realm).await
            )
            .await
            .is_err(),
            "{failure}"
        );
        server.join().unwrap();
    }
}

#[tokio::test]
async fn native_genesis_rejects_sibling_reader_and_retired_cached_response() {
    for retired in [false, true] {
        let (full, _) = founding_original();
        let realm = full.event.realm_id.clone();
        let (client, source, server, paths) = native_server(
            &full,
            vec![serde_json::to_value(CommittedEventView::Full(full.clone())).unwrap()],
            false,
        );
        let response = candidate(&client, &realm).await;
        server.join().unwrap();
        if retired {
            source.active.store(false, Ordering::SeqCst);
            assert!(
                consume_own_station_device_realm_genesis(&client, &realm, response)
                    .await
                    .is_err()
            );
        } else {
            let (sibling, _) = native_client(client.context().unwrap().binding().base_url(), &full);
            assert!(
                consume_own_station_device_realm_genesis(&sibling, &realm, response)
                    .await
                    .is_err()
            );
        }
        assert_eq!(paths.lock().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn native_genesis_rejects_uncommitted_fact_and_wrong_realm_before_signer_query() {
    for failure in [
        "fact",
        "realm",
        "position",
        "predecessor",
        "generation",
        "event_ref",
        "commit_realm",
        "stream",
        "withheld",
        "kind",
        "scope",
        "proof",
    ] {
        let (valid, _) = founding_original();
        let realm = valid.event.realm_id.clone();
        let mut full = valid.clone();
        match failure {
            "fact" => {
                full.commit.producer_signer_fact_digest = None;
                full.commit = seal_native_fixture_commit(full.commit);
            }
            "position" => full.commit.stream_position = 1,
            "predecessor" => {
                full.commit.previous_commit_ref =
                    Some(arkret_wire::RealmCommitId::from_digest([22; 32]))
            }
            "generation" => full.commit.governance_generation = 1,
            "event_ref" => {
                full.commit.event_ref =
                    EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [95; 32])
            }
            "commit_realm" => {
                full.commit.realm_id = RealmId::from_event_id(&EventId::from_digest(
                    arkret_canonical::DigestSuite::Sha256,
                    [96; 32],
                ))
            }
            "stream" => {
                full.commit.stream_ref = CommitStreamRef::Realm {
                    realm_id: RealmId::from_event_id(&EventId::from_digest(
                        arkret_canonical::DigestSuite::Sha256,
                        [97; 32],
                    )),
                }
            }
            "kind" => full.event.kind = arkret_wire::EventKind::MlsGenesis,
            "scope" => {
                full.event.scope_ref = ScopeRef::Realm {
                    realm_id: realm.clone(),
                }
            }
            "proof" => full.event.producer_proof.as_mut().unwrap().jws = "invalid".into(),
            _ => {}
        }
        let body = if failure == "withheld" {
            serde_json::json!({"commit":full.commit,"event_disclosure":{"status":"withheld"}})
        } else {
            serde_json::to_value(CommittedEventView::Full(full)).unwrap()
        };
        let (client, _, server, paths) = native_server(&valid, vec![body], false);
        let response = client.committed_event_get(&realm.event_id()).await;
        let requested = if failure == "realm" {
            RealmId::from_event_id(&EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                [98; 32],
            ))
        } else {
            realm
        };
        if let Ok(response) = response {
            assert!(
                consume_own_station_device_realm_genesis(&client, &requested, response)
                    .await
                    .is_err(),
                "{failure}"
            );
        }
        server.join().unwrap();
        assert_eq!(paths.lock().unwrap().len(), 1);
    }
}

#[test]
fn member_genesis_shared_predicate_rejects_other_private_purposes() {
    let (event, commit, _) = native_self_genesis_fixture("alice");
    let realm = event.realm_id.clone();
    assert!(
        validate_member_realm_genesis(
            &CommittedEventView::Full(CommittedEventFullView { event, commit }),
            &realm
        )
        .is_err()
    );
}
