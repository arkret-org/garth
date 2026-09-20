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
    Event {
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
    }
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
        sig: Base64UrlString::new("AA").unwrap(),
    }
}
