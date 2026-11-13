//! Real Root/Device/HPKE math over authenticated-result models, not Native admission.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use arkret_models_collaboration::events_payloads::{
    DeviceAuthorizationBindingKind, DeviceOrPrincipalRef, SignatureMaterial,
};
use arkret_models_crypto::{
    ContentContext, ContentRootBackupEntry, EncryptedEnvelope, EventContentMaterial,
    EventContentPreEncryptionHeader, EventContentRoutingContext, KeyBackupPlaintext,
    RecoveryPolicy, RecoveryPolicyRef, SecretStorageContentIndex, SecretStorageItemKind,
};
use arkret_models_identity::{CurrentPrincipalRequestBody, ResolvedSignerKey};
use arkret_signatures::{Ed25519PayloadSigner, SignEventOptions};
use arkret_test_kit::pcr_genesis::{HumanPcrFixtureInput, HumanPcrOriginalsFixture};
use arkret_wire::{CommittedEventFullView, CommittedEventRef, CommittedEventView, CurrentRevision};
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::{Value, json};

use super::*;
use crate::MemorySecureKeyStore;
use crate::own_station_results::pcr_genesis::tests::{founding, original, setup};
use crate::own_station_results::tests::observed_client_for_account;

struct DurabilityFaultStore {
    inner: MemorySecureKeyStore,
    fail_at: usize,
    writes: std::sync::atomic::AtomicUsize,
}

#[cfg(not(target_arch = "wasm32"))]
type StoreFuture<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;
#[cfg(target_arch = "wasm32")]
type StoreFuture<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + 'a>>;

impl SecureKeyStore for DurabilityFaultStore {
    fn store_secret_bytes(&self, key: &str, value: &[u8]) -> crate::SecureKeyStoreResult<()> {
        self.inner.store_secret_bytes(key, value)
    }
    fn get_secret_bytes(
        &self,
        key: &str,
    ) -> crate::SecureKeyStoreResult<Option<arkret_keystore::KeyBytes>> {
        self.inner.get_secret_bytes(key)
    }
    fn delete_secret(&self, key: &str) -> crate::SecureKeyStoreResult<()> {
        self.inner.delete_secret(key)
    }
    fn list_secret_keys(&self, prefix: Option<&str>) -> crate::SecureKeyStoreResult<Vec<String>> {
        self.inner.list_secret_keys(prefix)
    }
    fn backend_info(&self) -> crate::SecureKeyStoreBackendInfo {
        self.inner.backend_info()
    }
    fn read_secret_bytes_durable<'a>(
        &'a self,
        key: &'a str,
    ) -> StoreFuture<'a, crate::SecureKeyStoreResult<Option<arkret_keystore::KeyBytes>>> {
        self.inner.read_secret_bytes_durable(key)
    }
    fn compare_exchange_secret_bytes_durable<'a>(
        &'a self,
        key: &'a str,
        expected: Option<&'a [u8]>,
        replacement: &'a [u8],
    ) -> StoreFuture<'a, crate::SecureKeyStoreResult<bool>> {
        Box::pin(async move {
            if self.writes.fetch_add(1, Ordering::SeqCst) + 1 == self.fail_at {
                return Err(crate::SecureKeyStoreError::Backend(
                    "injected durable transaction failure".into(),
                ));
            }
            self.inner
                .compare_exchange_secret_bytes_durable(key, expected, replacement)
                .await
        })
    }
}
use crate::own_station_results::{PcrHistoryBackupReader, read_own_station_human_pcr_genesis};

fn at(second: u32) -> chrono::DateTime<chrono::Utc> {
    crate::test_fixtures::at(second)
}

fn signed_event(
    f: &HumanPcrOriginalsFixture,
    kind: EventKind,
    payload: Value,
) -> arkret_wire::Event {
    let mut event = crate::test_fixtures::event(84, kind, payload);
    event.actor_id = ActorId::account(f.account.clone());
    event.realm_id = f.unit.create().realm_id.clone();
    event.scope_ref = ScopeRef::Realm {
        realm_id: event.realm_id.clone(),
    };
    let created = if event.kind == EventKind::ProfileUpdate {
        at(5)
    } else {
        at(2)
    };
    event.created_at = created;
    event.producer_proof = None;
    let mut event = arkret_wire::AuthoredEvent::finalize_with_digest_suite(
        event,
        arkret_canonical::DigestSuite::Sha256,
    )
    .unwrap();
    arkret_signatures::sign_event(
        &mut event,
        &Ed25519PayloadSigner::new(
            f.device_signing_key.clone(),
            f.resolution.did.clone(),
            f.device_verification_method.clone(),
        ),
        SignEventOptions::new().with_created_at(created),
    )
    .unwrap();
    event.into_event()
}

fn append_read(
    bodies: &mut Vec<Value>,
    full: &CommittedEventFullView,
    pair: &[CommittedEventFullView; 2],
    f: &HumanPcrOriginalsFixture,
) {
    bodies.push(json!(CommittedEventView::Full(full.clone())));
    bodies.push(json!(arkret_wire::StreamScanResponseBody {
        committed_events: vec![CommittedEventView::Full(full.clone())],
        readable_floor: Some(arkret_wire::ReadableFloor {
            oldest_position: 0,
            floor_commit_id: pair[0].commit.commit_id.clone(),
            floor_reason: arkret_wire::ReadableFloorReason::StreamStart,
        }),
        truncated: true,
    }));
    bodies.push(json!({"__signer_key":ResolvedSignerKey {
        public_key_base64url:arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(f.device_signing_key.verifying_key().to_bytes())).unwrap(),
        authorization_ref:CommittedEventRef {event_id:pair[1].event.event_id.clone(),commit_id:pair[1].commit.commit_id.clone(),stream_ref:pair[1].commit.stream_ref.clone(),stream_position:1},
        revision:CurrentRevision {commit_id:pair[1].commit.commit_id.clone(),stream_position:1},governance_generation:0,
    },"__expected_native_target":CommittedEventRef {event_id:full.event.event_id.clone(),commit_id:full.commit.commit_id.clone(),stream_ref:full.commit.stream_ref.clone(),stream_position:full.commit.stream_position}}));
}

#[tokio::test]
async fn mnemonic_root_import_checks_original_signers_and_keeps_only_selected_history_roots() {
    for refusal in [
        "none",
        "expired_retry",
        "expired_response",
        "lost_challenge_response",
        "wrong_device_challenge",
        "request_flush_failure",
        "proof_flush_failure",
        "ciphertext_flush_failure",
        "selection",
        "subject",
        "words",
        "policy_ref",
        "policy_signature",
        "backup_signature",
        "authorizer_is_not_backup_signer",
        "index",
        "late_session",
    ] {
        let success = matches!(
            refusal,
            "none"
                | "expired_retry"
                | "expired_response"
                | "lost_challenge_response"
                | "ciphertext_flush_failure"
        );
        let download_case = success
            || matches!(
                refusal,
                "wrong_device_challenge" | "request_flush_failure" | "proof_flush_failure"
            );
        let vector =
            arkret_schema_conformance::spec_json_artifact("fixtures/content-history-fixture.json")
                .unwrap();
        let words = vector["hpke_grant"]["mnemonic"].as_str().unwrap();
        let material =
            arkret_crypto::identity_root::derive_identity_recovery_key_material_from_bip39(
                words, "", 0,
            )
            .unwrap();
        let f = HumanPcrOriginalsFixture::webvh(HumanPcrFixtureInput {
            station_id: &"ak:did_core:web:station.example".parse().unwrap(),
            endpoint: &url::Url::parse("https://principal.example/").unwrap(),
            root_seed: material.root_seed,
            next_root_seed: material.next_root_seed,
            device_seed: [41; 32],
            device_hpke_private_key: [51; 32],
            device_id: crate::test_fixtures::device_id(),
            genesis_salt: arkret_wire::GenesisSalt::new(arkret_canonical::base64url_encode(
                [61; 32],
            ))
            .unwrap(),
            created_at: at(0),
        })
        .unwrap();
        let pair = founding(&f);
        let mut policy: RecoveryPolicy = serde_json::from_value(json!({
            "schema":"ak.schema.recovery_policy.v1","policy_id":"ak:policy:0196419b-0000-7000-8000-000000000003","account_id":f.account,"version":1,
            "trust_domain":"ak:trust_domain:holder.example","issued_at":at(1).to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "signature_proof":{"verification_method":f.device_verification_method,"signature_algorithm":"Ed25519","signature":arkret_canonical::base64url_encode([0;64])},
            "methods":[{"kind":"recovery_unlock","keys":[{
                "verification_method":format!("did:key:{0}#{0}",material.recovery_proof_public_key_multikey),
                "public_key_multibase":material.recovery_proof_public_key_multikey,"signature_algorithm":"Ed25519","not_before":at(0).to_rfc3339_opts(chrono::SecondsFormat::Millis, true),"expires_at":"2030-01-01T00:00:00.000Z",
                "backup_hpke":{"key_agreement_ref":format!("did:key:{0}#{0}",material.backup_hpke_public_key_multikey),"key_agreement_algorithm":"X25519","public_key_multibase":material.backup_hpke_public_key_multikey,
                    "hpke_suites":["ak.hpke_x25519_aead_chacha20poly1305.v1"],"use":"backup_hpke","not_before":at(0).to_rfc3339_opts(chrono::SecondsFormat::Millis, true),"expires_at":"2030-01-01T00:00:00.000Z"}
            }]}]
        })).unwrap();
        policy.signature_proof.signature =
            arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
                f.device_signing_key
                    .sign(&recovery_policy_signature_transcript_bytes(&policy).unwrap())
                    .to_bytes(),
            ))
            .unwrap();
        if refusal == "policy_signature" {
            policy.signature_proof.signature =
                arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode([0; 64]))
                    .unwrap();
        }
        let policy_event = signed_event(
            &f,
            EventKind::PolicySet,
            json!({"policy_id":policy.policy_id,"value":policy}),
        );
        let policy_full = original(&f, policy_event, 2, Some(pair[1].commit.commit_id.clone()));
        let backup_key = SigningKey::from_bytes(&[42; 32]);
        let backup_device: DeviceId = "ak:device:0196419b-0000-7000-8000-000000000002"
            .parse()
            .unwrap();
        let mut authorize: DeviceAuthorizePayload =
            serde_json::from_value(serde_json::to_value(&pair[1].event.payload).unwrap()).unwrap();
        authorize.device_id = backup_device.clone();
        authorize.device_public_key_did = arkret_wire::NonEmptyString::new(format!(
            "did:key:{}",
            arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                backup_key.verifying_key().as_bytes()
            )
        ))
        .unwrap();
        authorize.authorized_by = DeviceOrPrincipalRef::DeviceId(f.device_id.clone());
        authorize.authorization_binding_kind = DeviceAuthorizationBindingKind::AcceptedDevice;
        authorize.pairing_challenge_transcript_digest = Some(
            arkret_wire::Hash::new(arkret_canonical::sha256_digest(
                b"authenticated pairing fixture",
            ))
            .unwrap(),
        );
        authorize.device_signature = SignatureMaterial::NonEmptyString(
            arkret_wire::NonEmptyString::new(arkret_canonical::base64url_encode(
                backup_key
                    .sign(
                        &authorize
                            .device_possession_signature_input(&f.account)
                            .unwrap(),
                    )
                    .to_bytes(),
            ))
            .unwrap(),
        );
        let authorize_full = original(
            &f,
            signed_event(
                &f,
                EventKind::DeviceAuthorize,
                serde_json::to_value(&authorize).unwrap(),
            ),
            3,
            Some(policy_full.commit.commit_id.clone()),
        );
        let mut root: ContentRootBackupEntry =
            serde_json::from_value(vector["root_backup"]["plaintext"]["items"][0].clone()).unwrap();
        root.root_context.effective_scope = ScopeRef::Realm {
            realm_id: f.unit.create().realm_id.clone(),
        };
        root.root_context.backup_strategy_ref = f.unit.create().event_id.clone();
        root.root_ref = arkret_crypto::content_history::content_root_ref(
            &root.root_base64url,
            &root.root_context,
        )
        .unwrap();
        let mut extra = root.clone();
        extra.secret_id = "extra_root".into();
        extra.root_context.epoch += 1;
        extra.root_ref = arkret_crypto::content_history::content_root_ref(
            &extra.root_base64url,
            &extra.root_context,
        )
        .unwrap();
        let mut envelope: KeyBackup =
            serde_json::from_value(vector["root_backup"]["envelope"].clone()).unwrap();
        envelope.actor_id = ActorId::account(f.account.clone());
        envelope.device_id = Some(backup_device.clone());
        envelope.created_at = at(4);
        envelope.signature_proof.device_id = Some(backup_device.clone());
        envelope.signature_proof.device_authorize_event_id =
            Some(authorize_full.event.event_id.clone());
        envelope.signature_proof.verification_method =
            arkret_wire::DidUrl::new(format!("{}#{}", f.resolution.did, backup_device)).unwrap();
        envelope.recovery_policy_ref = Some(RecoveryPolicyRef {
            policy_id: policy.policy_id.clone(),
            policy_version: 1,
        });
        envelope.encryption.recipient_key_ref = Some(format!(
            "did:key:{0}#{0}",
            material.backup_hpke_public_key_multikey
        ));
        let roots = [root.clone(), extra.clone()];
        envelope.contents = roots
            .iter()
            .map(|entry| SecretStorageContentIndex {
                item_kind: SecretStorageItemKind::ContentEpochRoot,
                secret_id: entry.secret_id.clone(),
                root_context: Some(entry.root_context.clone()),
                root_ref: Some(entry.root_ref.clone()),
            })
            .collect();
        let mut bag: KeyBackupPlaintext =
            serde_json::from_value(vector["root_backup"]["plaintext"].clone()).unwrap();
        bag.backup_id = envelope.backup_id.clone();
        bag.series_id = envelope.series_id.clone();
        bag.series_sequence = envelope.series_sequence;
        bag.items = roots
            .into_iter()
            .map(SecretStorageEntry::ContentRoot)
            .collect();
        envelope = arkret_crypto::content_history::seal_content_root_backup(
            envelope,
            &bag,
            &material.backup_hpke_public_key,
            |bytes| Ok(backup_key.sign(bytes).to_bytes().to_vec()),
        )
        .unwrap();
        let mut carrier = vector["kat"]["envelope"].clone();
        carrier["encryption_context"]["epoch"] = json!(root.root_context.epoch.to_string());
        carrier["encryption_context"]["group_state_ref"] = json!(root.root_context.group_state_ref);
        carrier["encryption_context"]["root_ref"] = json!(root.root_ref);
        carrier["encryption_context"]["protection"]["root_refs"] = json!([root.root_ref]);
        carrier["encryption_context"]["protection"]["backup_refs"] = json!([envelope.backup_id]);
        let mut context: ContentContext =
            serde_json::from_value(vector["kat"]["content_context"].clone()).unwrap();
        context.root_context = root.root_context.clone();
        context.root_ref = root.root_ref.clone();
        context.producer.actor_id = ActorId::account(f.account.clone());
        context.producer.endpoint = MlsWelcomeRecipientEndpoint::Device {
            device_id: f.device_id.clone(),
        };
        context.producer.authorization_event_ref = pair[1].event.event_id.clone();
        context.producer.signature_key_base64url =
            arkret_canonical::base64url_encode(f.device_signing_key.verifying_key().to_bytes());
        let key =
            arkret_crypto::content_history::derive_content_key(&root.root_base64url, &context)
                .unwrap();
        carrier["encryption_context"]["key_commitment"] =
            json!(arkret_crypto::content_history::content_key_commitment(&context, &key).unwrap());
        let pending = signed_event(
            &f,
            EventKind::ProfileUpdate,
            json!({"actor_profile_id":arkret_wire::ActorProfileId::from_event_id(&pair[0].event.event_id),"patch":{"encrypted_private_fields":carrier}}),
        );
        let mut outer = serde_json::to_value(&pending).unwrap();
        for field in ["event_id", "payload", "producer_proof", "unsigned"] {
            outer.as_object_mut().unwrap().remove(field);
        }
        let parsed: EncryptedEnvelope = serde_json::from_value(carrier.clone()).unwrap();
        let header = EventContentPreEncryptionHeader::reconstruct(
            "1.0",
            parsed.content_type.clone(),
            parsed.encryption_scheme,
            context.root_context.effective_scope.clone(),
            "ak.profile.update",
            context.root_context.epoch,
            context.root_context.group_state_ref.clone(),
            String::from_utf8(
                arkret_canonical::canonical_json_bytes(&context.producer.actor_id).unwrap(),
            )
            .unwrap(),
            EventContentRoutingContext::None,
            EventContentMaterial {
                content_context: context,
                outer_event: outer.clone(),
                protection: serde_json::from_value(
                    carrier["encryption_context"]["protection"].clone(),
                )
                .unwrap(),
                key_commitment: serde_json::from_value(
                    carrier["encryption_context"]["key_commitment"].clone(),
                )
                .unwrap(),
            },
        )
        .unwrap();
        let plaintext = br#"{"private_note":"original PCR private history"}"#;
        carrier["ciphertext"] = json!(
            arkret_crypto::content_history::seal_content(&root.root_base64url, &header, plaintext,)
                .unwrap()
        );
        let mut source_full = original(
            &f,
            signed_event(
                &f,
                EventKind::ProfileUpdate,
                json!({"actor_profile_id":arkret_wire::ActorProfileId::from_event_id(&pair[0].event.event_id),"patch":{"encrypted_private_fields":carrier}}),
            ),
            4,
            Some(authorize_full.commit.commit_id.clone()),
        );
        source_full.commit = crate::own_station_results::tests::seal_native_fixture_commit_at(
            source_full.commit,
            at(5),
        );
        let mut bodies = setup(&f, &pair);
        append_read(&mut bodies, &source_full, &pair, &f);
        append_read(&mut bodies, &policy_full, &pair, &f);
        let current: DeviceId = "ak:device:0196419b-0000-7000-8000-000000000009"
            .parse()
            .unwrap();
        let current_key = SigningKey::from_bytes(&[49; 32]);
        let current_public = arkret_signatures::PublicKeyMaterial::Ed25519Multibase {
            value: arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                current_key.verifying_key().as_bytes(),
            ),
        };
        let audience = "https://station.example";
        let summary = arkret_models_crypto::KeyBackupSummary {
            backup_id: envelope.backup_id.clone(),
            actor_id: envelope.actor_id.clone(),
            device_id: envelope.device_id.clone(),
            backup_kind: envelope.backup_kind,
            backup_version: arkret_wire::NonEmptyString::new(envelope.backup_version.clone())
                .unwrap(),
            series_id: envelope.series_id.clone(),
            series_sequence: envelope.series_sequence,
            supersedes_id: envelope.supersedes_id.clone().map(Some),
            supersedes_digest: envelope.supersedes_digest.clone(),
            created_at: envelope.created_at,
            updated_at: None,
            expires_at: envelope.expires_at,
            retention: envelope.retention.as_ref().map(|value| {
                serde_json::to_value(value)
                    .unwrap()
                    .as_object()
                    .unwrap()
                    .clone()
            }),
            ciphertext_digest: envelope.ciphertext_digest.clone(),
            encryption: arkret_models_crypto::KeyBackupSummaryEncryption {
                recipient_method: envelope.encryption.recipient_method,
                recipient_key_ref: envelope.encryption.recipient_key_ref.clone(),
            },
        };
        if download_case && refusal != "request_flush_failure" {
            let mut challenge = arkret_models_crypto::KeysBackupsUnlockChallenge {
                challenge_id: arkret_wire::Base64UrlString::new(
                    arkret_canonical::base64url_encode([71; 32]),
                )
                .unwrap(),
                challenge: arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
                    [72; 32],
                ))
                .unwrap(),
                nonce: arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
                    [73; 32],
                ))
                .unwrap(),
                operation: arkret_wire::ServiceOperationId::SELF_KEYS_BACKUPS_COMMAND_UNLOCK_V1
                    .into(),
                account_id: f.account.clone(),
                requesting_device_id: current.clone(),
                backup_id: envelope.backup_id.clone(),
                series_id: envelope.series_id.clone(),
                ciphertext_digest: envelope.ciphertext_digest.clone(),
                audience: arkret_wire::NonEmptyString::new(audience).unwrap(),
                service_id: f.account.station_id.clone(),
                request_id: arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
                    [74; 32],
                ))
                .unwrap(),
                issued_at: at(5),
                expires_at: at(55),
                subject_actor_id: None,
                custody_authorization_ref: None,
                content_history: Some(arkret_models_crypto::ContentHistoryBackupAccess {
                    source: CommittedEventRef {
                        event_id: source_full.event.event_id.clone(),
                        commit_id: source_full.commit.commit_id.clone(),
                        stream_ref: source_full.commit.stream_ref.clone(),
                        stream_position: 4,
                    },
                    root_refs: vec![root.root_ref.clone()],
                }),
            };
            if refusal == "wrong_device_challenge" {
                challenge.requesting_device_id = backup_device.clone();
            }
            if refusal == "expired_response" {
                challenge.expires_at = at(5) + chrono::Duration::milliseconds(1);
            }
            bodies.push(json!({"__history_challenge":challenge,"__drop_response":refusal == "lost_challenge_response"}));
            if success {
                if !matches!(refusal, "expired_response" | "lost_challenge_response") {
                    bodies.push(json!({"__history_unlock":envelope,"__history_key":current_public,"__drop_response":refusal != "ciphertext_flush_failure"}));
                }
                if matches!(
                    refusal,
                    "expired_retry" | "expired_response" | "lost_challenge_response"
                ) {
                    challenge.issued_at = if refusal == "expired_response" {
                        at(6)
                    } else {
                        at(56)
                    };
                    challenge.expires_at = challenge.issued_at + chrono::Duration::seconds(60);
                    challenge.challenge_id = arkret_wire::Base64UrlString::new(
                        arkret_canonical::base64url_encode([75; 32]),
                    )
                    .unwrap();
                    challenge.nonce = arkret_wire::Base64UrlString::new(
                        arkret_canonical::base64url_encode([76; 32]),
                    )
                    .unwrap();
                    challenge.challenge = arkret_wire::Base64UrlString::new(
                        arkret_canonical::base64url_encode([77; 32]),
                    )
                    .unwrap();
                    bodies.push(json!({"__history_challenge":challenge,"__fresh_request":refusal != "lost_challenge_response","__same_request":refusal == "lost_challenge_response"}));
                }
                bodies.push(json!({"__history_unlock":envelope,"__history_key":current_public}));
            }
        }
        let needs_authorization = matches!(
            refusal,
            "none"
                | "expired_retry"
                | "expired_response"
                | "lost_challenge_response"
                | "ciphertext_flush_failure"
                | "backup_signature"
                | "authorizer_is_not_backup_signer"
                | "index"
        );
        if needs_authorization {
            append_read(&mut bodies, &authorize_full, &pair, &f);
        }
        let active = Arc::new(AtomicBool::new(true));
        let (client, server, requests) =
            observed_client_for_account(bodies, f.account.clone(), active.clone());
        let principal = client
            .current_principal(&CurrentPrincipalRequestBody {
                request_id: "ak:request:0196419b-0000-7000-8000-000000000001"
                    .parse()
                    .unwrap(),
                account_id: f.account.clone(),
            })
            .await
            .unwrap();
        let pcr = read_own_station_human_pcr_genesis(&client, principal)
            .await
            .unwrap();
        let source = pcr
            .read_original(&source_full.event.event_id)
            .await
            .unwrap();
        let policy_original = pcr
            .read_original(&policy_full.event.event_id)
            .await
            .unwrap();
        if refusal == "subject" {
            let mut other = f.account.clone();
            other.station_id = "ak:did_core:web:other.example".parse().unwrap();
            envelope.actor_id = ActorId::account(other);
        }
        if refusal == "policy_ref" {
            envelope
                .recovery_policy_ref
                .as_mut()
                .unwrap()
                .policy_version = 2;
        }
        if refusal == "backup_signature" {
            envelope.signature_proof.signature =
                arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode([0; 64]))
                    .unwrap();
        }
        if refusal == "authorizer_is_not_backup_signer" {
            envelope.signature_proof.signature =
                arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
                    f.device_signing_key
                        .sign(&envelope.signing_payload_bytes().unwrap())
                        .to_bytes(),
                ))
                .unwrap();
        }
        if refusal == "index" {
            envelope.contents[1].root_ref = Some(root.root_ref.clone());
            envelope.signature_proof.signature =
                arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
                    backup_key
                        .sign(&envelope.signing_payload_bytes().unwrap())
                        .to_bytes(),
                ))
                .unwrap();
        }
        if refusal == "late_session" {
            active.store(false, Ordering::SeqCst);
        }
        let selected = if refusal == "selection" {
            vec![extra.root_ref.clone()]
        } else {
            vec![root.root_ref.clone()]
        };
        let wrong = [99; 32];
        let private = if refusal == "words" {
            &wrong
        } else {
            &material.backup_hpke_derived_private_key
        };
        let store = MemorySecureKeyStore::default();
        if download_case {
            let fault_store = DurabilityFaultStore {
                inner: store.clone(),
                fail_at: match refusal {
                    "request_flush_failure" => 1,
                    "proof_flush_failure" => 2,
                    "ciphertext_flush_failure" => 3,
                    _ => usize::MAX,
                },
                writes: std::sync::atomic::AtomicUsize::new(0),
            };
            let sign = |bytes: &[u8]| Ok(current_key.sign(bytes).to_bytes().to_vec());
            let resumed = AtomicBool::new(false);
            let now = || {
                if resumed.load(Ordering::SeqCst)
                    && matches!(refusal, "expired_retry" | "lost_challenge_response")
                {
                    at(56)
                } else {
                    at(6)
                }
            };
            let reader = PcrHistoryBackupReader {
                device: &current,
                audience,
                store: &fault_store,
                signing_key: &current_public,
                sign_raw: &sign,
                now: &now,
            };
            let first = source
                .download_content_root_backup(&summary, &selected, &reader)
                .await;
            if refusal == "expired_response" {
                envelope = first.unwrap();
            } else {
                assert!(first.is_err(), "{refusal}: {first:?}");
            }
            if !success {
                assert!(
                    store
                        .list_secret_keys(Some("content-root/v1/"))
                        .unwrap()
                        .is_empty()
                );
                server.join().unwrap();
                let expected = if refusal == "request_flush_failure" {
                    11
                } else {
                    12
                };
                assert_eq!(
                    requests.lock().unwrap().len(),
                    expected,
                    "{refusal}: no unlock may precede durable proof"
                );
                continue;
            }
            if refusal != "expired_response" {
                resumed.store(true, Ordering::SeqCst);
                envelope = source
                    .download_content_root_backup(&summary, &selected, &reader)
                    .await
                    .unwrap();
            }
            let cached = source
                .download_content_root_backup(&summary, &selected, &reader)
                .await
                .unwrap();
            assert_eq!(
                serde_json::to_value(&cached).unwrap(),
                serde_json::to_value(&envelope).unwrap()
            );
        }
        let result = source
            .import_content_root_backup(
                &envelope,
                &policy_original,
                private,
                &current,
                &selected,
                &store,
            )
            .await;
        assert_eq!(result.is_ok(), success, "{refusal}: {result:?}");
        let actor = ActorId::account(f.account.clone());
        let endpoint = MlsWelcomeRecipientEndpoint::Device { device_id: current };
        let vault = ContentRootVault::new(&store, &actor, &endpoint);
        if success {
            let recovered = vault.root(&root.root_ref).await.unwrap().unwrap();
            assert_eq!(
                arkret_crypto::content_history::open_content(
                    &recovered.root_base64url,
                    &header,
                    carrier["ciphertext"].as_str().unwrap(),
                )
                .unwrap(),
                plaintext
            );
            let mut accepted_outer = serde_json::to_value(&source_full.event).unwrap();
            for field in ["event_id", "payload", "producer_proof", "unsigned"] {
                accepted_outer.as_object_mut().unwrap().remove(field);
            }
            assert_eq!(accepted_outer, outer);
        }
        assert_eq!(vault.root(&root.root_ref).await.unwrap().is_some(), success);
        assert!(vault.root(&extra.root_ref).await.unwrap().is_none());
        server.join().unwrap();
    }
}
