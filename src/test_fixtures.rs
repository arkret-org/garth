//! Deterministic fixtures shared by the behavior tests in this crate.

use arkret_canonical::DigestSuite;
use arkret_wire::{
    ActorId, Base64UrlString, CommitStreamRef, DetachedObjectSignature, DetachedSignatureAlgorithm,
    DetachedSignatureContext, DeviceId, DidCoreId, DidUrl, Event, EventId, EventKind, Hash,
    RealmCommit, RealmCommitAuthorityRef, RealmCommitId, RealmId, ScopeRef,
};
use chrono::{DateTime, TimeZone, Utc};
use serde_json::Value;

pub fn at(second: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 9, 16, 0, 0, second).unwrap()
}

pub fn realm_id() -> RealmId {
    RealmId::new("ak:realm:AfF-hFqRoMbajXkPapH-xaq0xwK-UKt2ph2zTs9JZRAO").unwrap()
}

pub fn realm_stream() -> CommitStreamRef {
    CommitStreamRef::Realm {
        realm_id: realm_id(),
    }
}

pub fn device_id() -> DeviceId {
    DeviceId::new("ak:device:0196419b-0000-7000-8000-000000000001").unwrap()
}

pub fn actor_id() -> ActorId {
    ActorId::service(DidCoreId::new("ak:did_core:web:alice.example").unwrap())
}

pub fn event(seed: u8, kind: EventKind, payload: Value) -> Event {
    let mut event = Event {
        event_id: EventId::from_digest(DigestSuite::Sha256, [seed; 32]),
        kind,
        realm_id: realm_id(),
        scope_ref: ScopeRef::Realm {
            realm_id: realm_id(),
        },
        actor_id: actor_id(),
        executed_by: None,
        authorization_ref: None,
        applet_id: None,
        external_ref: None,
        created_at: at(0),
        semantic_refs: Vec::new(),
        payload: serde_json::from_value(payload).unwrap(),
        producer_proof: None,
    };
    // Shape fixtures do not claim producer signature verification.
    let digest = Hash::new(format!("sha256:{}", "00".repeat(32))).unwrap();
    event.producer_proof = Some(arkret_wire::ProducerEventProof {
        kind: "detached_jws".into(),
        verification_method: DidUrl::new("did:web:alice.example#runtime-1").unwrap(),
        event_digest: digest.clone(),
        created_at: at(0),
        domain: Some("arkret-event-v1".into()),
        audience: None,
        proof_purpose: None,
        jws: arkret_wire::test_support::structural_only_detached_jws(&digest),
    });
    event
}

pub fn message_payload(seed: u8) -> Value {
    serde_json::json!({
        "strand_id": arkret_wire::StrandId::from_event_id(&EventId::from_digest(DigestSuite::Sha256, [2; 32])),
        "track_name": "discussion",
        "content": {"kind": "ak.content.text", "body": format!("fixture message {seed}")}
    })
}

pub fn genesis_payload(seed: u8, realm: RealmId) -> Value {
    let payload = arkret_models_collaboration::events_payloads::MlsGenesisPayload {
        cipher_suite: arkret_wire::NonEmptyString::new(
            "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
        )
        .unwrap(),
        group_info_ref: arkret_wire::BlobRef::new(format!("ak:blob:sha256:{seed:064x}")).unwrap(),
        ratchet_tree_ref: arkret_wire::BlobRef::new(format!(
            "ak:blob:sha256:{:064x}",
            seed.wrapping_add(1)
        ))
        .unwrap(),
        creator_leaf_authority:
            arkret_models_collaboration::events_payloads::MlsGenesisCreatorLeafAuthority {
                leaf_signature_key_base64url: Base64UrlString::new(
                    arkret_canonical::base64url_encode([3; 32]),
                )
                .unwrap(),
                endpoint: arkret_wire::MlsWelcomeRecipientEndpoint::Device {
                    device_id: device_id(),
                },
                authorization_event_ref: EventId::from_digest(DigestSuite::Sha256, [4; 32]),
            },
        governance_binding: arkret_models_crypto::MlsGovernanceBindingPayload::realm(
            realm, None, 0, 0, 0,
        )
        .unwrap(),
        created_at: at(0),
    };
    serde_json::to_value(payload).unwrap()
}

pub fn commit(seed: u8, event: &Event, stream_ref: CommitStreamRef, position: u64) -> RealmCommit {
    RealmCommit {
        commit_id: RealmCommitId::from_digest([seed; 32]),
        realm_id: stream_ref.realm_id().clone(),
        stream_ref,
        stream_position: position,
        previous_commit_ref: (position > 0)
            .then(|| RealmCommitId::from_digest([seed.wrapping_sub(1); 32])),
        event_ref: event.event_id.clone(),
        governance_generation: 0,
        authority_ref: RealmCommitAuthorityRef::GenesisOrChangeEvent(EventId::from_digest(
            DigestSuite::Sha256,
            [9; 32],
        )),
        committed_at: at(1),
        producer_signer_fact_digest: None,
        signature: detached_signature(DetachedSignatureContext::RealmCommit),
    }
}

pub fn detached_signature(context: DetachedSignatureContext) -> DetachedObjectSignature {
    DetachedObjectSignature {
        context,
        signature_algorithm: DetachedSignatureAlgorithm::Ed25519,
        verification_method: DidUrl::new("did:web:authority.example#key-1").unwrap(),
        signed_digest: Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
        created_at: at(1),
        signature: Base64UrlString::new("AA").unwrap(),
    }
}
