//! Shared memory CAS and real HPKE/commitment checks, not native authority.
use arkret_test_kit::signed_event::SignedEventFixtureBuilder;
use arkret_test_kit::{keys, subjects};

use super::*;
use crate::MemorySecureKeyStore;

fn request() -> (PendingHistoryRequest, chrono::DateTime<chrono::Utc>) {
    let f = arkret_schema_conformance::spec_json_artifact("fixtures/content-history-fixture.json")
        .unwrap();
    let mut grant: HistoryGrant = serde_json::from_value(f["hpke_grant"]["grant"].clone()).unwrap();
    grant.recipient.actor_id = ActorId::account(subjects::alice_account_id());
    grant.recipient.endpoint = MlsWelcomeRecipientEndpoint::Device {
        device_id: subjects::alice_device_id(),
    };
    let hpke = arkret_crypto::hpke::generate_x25519_keypair().unwrap();
    let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let scope = ScopeRef::Realm {
        realm_id: grant.history_cut.stream_ref.realm_id().clone(),
    };
    let payload = arkret_models_crypto::HistoryRequest {
        recipient: grant.recipient,
        recipient_hpke_key_base64url: arkret_canonical::base64url_encode(hpke.public_key()),
        history_cut: grant.history_cut,
        expires_at: at + chrono::Duration::seconds(600),
    };
    let signer = keys::seeded_signer(subjects::alice_did(), subjects::alice_verification_method());
    let event = SignedEventFixtureBuilder::new(
        "ak.mls.history_request",
        scope,
        payload.recipient.actor_id.clone(),
        serde_json::to_value(payload).unwrap(),
    )
    .with_created_at(at)
    .sign_verifiable(&signer)
    .unwrap()
    .expect_verifiable();
    (
        PendingHistoryRequest::new(event, hpke.private_key()).unwrap(),
        at,
    )
}

#[tokio::test]
async fn concurrent_endpoints_keep_one_frozen_request_and_one_durable_private_key() {
    let store = MemorySecureKeyStore::default();
    let (first, at) = request();
    let (second, second_at) = request();
    let at = at.max(second_at);
    let body = first.event.as_mls_history_request().unwrap();
    let actor = body.recipient.actor_id.clone();
    let endpoint = body.recipient.endpoint.clone();
    let scope = first.event.scope_ref.clone();
    let vault = HistoryExchangeVault::new(&store, &actor, &endpoint);
    let reopened = HistoryExchangeVault::new(&store, &actor, &endpoint);
    let (left, right) = tokio::join!(
        vault.freeze_request(first, at),
        reopened.freeze_request(second, at)
    );
    let left = left.unwrap();
    let right = right.unwrap();
    assert_eq!(left.event.event_id, right.event.event_id);
    let reader = reopened.request(&scope).await.unwrap().unwrap();
    let request = reader.event.as_mls_history_request().unwrap();
    let mut grant = HistoryGrant {
        recipient: request.recipient,
        recipient_hpke_key_base64url: request.recipient_hpke_key_base64url,
        recipient_key_event_ref: reader.event.event_id.clone(),
        history_cut: request.history_cut,
        expires_at: request.expires_at,
        entries: vec![],
    };
    let selector = HistoryKeySelector::ContentKey {
        source_event_ref: grant.history_cut.event_id.clone(),
        content_path: "/payload/encrypted_content".into(),
    };
    let secret = [83u8; 16];
    let sealed =
        arkret_crypto::content_history::seal_history_key(&grant, &selector, &secret).unwrap();
    grant.entries.push(HistoryGrantEntry {
        selector,
        sealed_key_base64url: sealed,
    });
    assert_eq!(
        reader
            .open_entry(&grant, &grant.entries[0], at)
            .unwrap()
            .as_slice(),
        secret
    );
    let mut swapped = grant.clone();
    swapped.history_cut.stream_position += 1;
    assert!(
        reader
            .open_entry(&swapped, &swapped.entries[0], at)
            .is_err()
    );
    assert!(
        reader
            .open_entry(
                &grant,
                &grant.entries[0],
                at + chrono::Duration::seconds(600)
            )
            .is_err()
    );
    let other = MlsWelcomeRecipientEndpoint::Device {
        device_id: subjects::bob_device_id(),
    };
    assert!(
        HistoryExchangeVault::new(&store, &actor, &other)
            .request(&scope)
            .await
            .unwrap()
            .is_none()
    );
    vault
        .consume_request(&scope, &reader.event.event_id)
        .await
        .unwrap();
    let consumed = reopened.request(&scope).await.unwrap().unwrap();
    assert!(!consumed.has_private_key());
    assert!(consumed.open_entry(&grant, &grant.entries[0], at).is_err());
}

#[tokio::test]
async fn selected_keys_require_exact_original_context_commitment_and_endpoint_namespace() {
    let f = arkret_schema_conformance::spec_json_artifact("fixtures/content-history-fixture.json")
        .unwrap();
    let original: Event = serde_json::from_value(f["kat"]["source_event"].clone()).unwrap();
    let envelope = serde_json::from_value(f["kat"]["envelope"].clone()).unwrap();
    let material = EventContentMaterial::from_original(
        &original,
        &envelope,
        serde_json::from_value(f["kat"]["root_context"].clone()).unwrap(),
        serde_json::from_value(f["kat"]["content_context"]["producer"].clone()).unwrap(),
    )
    .unwrap();
    let mut source: CommittedEventRef =
        serde_json::from_value(f["hpke_grant"]["grant"]["history_cut"].clone()).unwrap();
    source.event_id = original.event_id.clone();
    source.stream_ref = arkret_wire::CommitStreamRef::from_scope(
        &original.scope_ref,
        Some(original.realm_id.clone()),
    )
    .unwrap();
    let commitment = material.key_commitment.clone();
    let raw = hex::decode(f["kat"]["key_hex"].as_str().unwrap()).unwrap();
    let context = RetainedHistoryKeyContext::Body { material };
    assert!(
        RetainedHistoryContentKey::new(
            source.clone(),
            "/payload/encrypted_content".into(),
            context.clone(),
            commitment.clone(),
            &[0; 16]
        )
        .is_err()
    );
    let retained = RetainedHistoryContentKey::new(
        source.clone(),
        "/payload/encrypted_content".into(),
        context,
        commitment,
        &raw,
    )
    .unwrap();
    let store = MemorySecureKeyStore::default();
    let actor = ActorId::account(subjects::alice_account_id());
    let endpoint = MlsWelcomeRecipientEndpoint::Device {
        device_id: subjects::alice_device_id(),
    };
    let vault = HistoryExchangeVault::new(&store, &actor, &endpoint);
    vault.retain_key(&retained).await.unwrap();
    let reopened = HistoryExchangeVault::new(&store, &actor, &endpoint);
    assert_eq!(
        reopened
            .read_key(&source.event_id, "/payload/encrypted_content")
            .await
            .unwrap()
            .unwrap()
            .key()
            .unwrap()
            .as_slice(),
        raw
    );
    assert_eq!(
        reopened
            .cached_key(&source.event_id, "/payload/encrypted_content")
            .unwrap()
            .unwrap()
            .key()
            .unwrap()
            .as_slice(),
        raw
    );
    assert!(
        reopened
            .cached_key(&source.event_id, "/payload/encrypted_metadata")
            .unwrap()
            .is_none()
    );
    assert!(
        HistoryExchangeVault::new(
            &store,
            &ActorId::account(subjects::bob_account_id()),
            &endpoint
        )
        .cached_key(&source.event_id, "/payload/encrypted_content")
        .unwrap()
        .is_none()
    );
}
