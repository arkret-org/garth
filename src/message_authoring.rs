//! One producer-side path from finalized message bytes to authority submission.
//!
//! The host owns encryption and the signing key. Garth verifies that the
//! content-bound Event is a message, attaches exactly one producer proof, and
//! freezes the resulting authority request for durable retry.

pub use arkret_models_collaboration::message_authoring::{
    MessageAuthoringContent, MessageAuthoringIntent, MessageEncryptionContext,
    MessageSubmitRequestBody,
};
use arkret_signatures::{EventSigner, SignEventOptions, sign_event};
use arkret_wire::{AuthoredEvent, AuthoritySubmitRequest, EventCommitSubmission, EventKind};

use crate::{Error, QueuedSubmission, Result};

pub fn author_message<S: EventSigner + ?Sized>(
    mut event: AuthoredEvent,
    signer: &S,
    options: SignEventOptions,
) -> Result<MessageSubmitRequestBody> {
    if event.kind != EventKind::MessageCreate {
        return Err(Error::Protocol(
            "message authoring requires ak.message.create".to_owned(),
        ));
    }
    sign_event(&mut event, signer, options).map_err(|error| Error::Protocol(error.to_string()))?;
    let request = MessageSubmitRequestBody {
        submission: EventCommitSubmission {
            event: event.into_event(),
        },
    };
    request.validate()?;
    request.submission.event.validate_for_submit_structural()?;
    Ok(request)
}

pub fn queue_authored_message(request: MessageSubmitRequestBody) -> Result<QueuedSubmission> {
    request.validate()?;
    QueuedSubmission::new(AuthoritySubmitRequest::Event(request.submission))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use arkret_canonical::DigestSuite;
    use arkret_signatures::Ed25519DetachedJwsSigner;
    use arkret_wire::{ActorId, DidCoreId, Event, EventId, RealmId, ScopeRef};
    use chrono::TimeZone;
    use ed25519_dalek::SigningKey;
    use serde_json::json;

    use super::*;

    fn authored(kind: EventKind) -> AuthoredEvent {
        let seed_id = EventId::from_digest(DigestSuite::Sha256, [7; 32]);
        let realm_id = RealmId::from_event_id(&seed_id);
        let event = Event {
            event_id: seed_id,
            kind,
            realm_id: realm_id.clone(),
            scope_ref: ScopeRef::Realm { realm_id },
            actor_id: ActorId::service(DidCoreId::new("ak:did_core:web:alice.example").unwrap()),
            executed_by: None,
            authorization_ref: None,
            applet_id: None,
            external_ref: None,
            created_at: chrono::Utc.with_ymd_and_hms(2026, 9, 16, 0, 0, 0).unwrap(),
            refs: Vec::new(),
            payload: BTreeMap::from([("body".to_owned(), json!("hello"))]),
            proofs: Vec::new(),
        };
        AuthoredEvent::finalize_with_digest_suite(event, DigestSuite::Sha256).unwrap()
    }

    fn signer() -> Ed25519DetachedJwsSigner {
        Ed25519DetachedJwsSigner::new(
            SigningKey::from_bytes(&[9; 32]),
            "did:web:alice.example#key-1",
        )
    }

    #[test]
    fn authoring_attaches_one_producer_proof_and_freezes_submission() {
        let request = author_message(
            authored(EventKind::MessageCreate),
            &signer(),
            SignEventOptions::new(),
        )
        .unwrap();
        assert_eq!(request.submission.event.proofs.len(), 1);
        let expected_id = request.submission.event.event_id.clone();
        let queued = queue_authored_message(request).unwrap();
        assert_eq!(queued.event_id, expected_id);
    }

    #[test]
    fn authoring_rejects_non_message_events_before_signing() {
        let error = author_message(
            authored(EventKind::ReactionAdd),
            &signer(),
            SignEventOptions::new(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("ak.message.create"));
    }

    #[test]
    fn queued_message_preserves_exact_canonical_event_bytes() {
        let request = author_message(
            authored(EventKind::MessageCreate),
            &signer(),
            SignEventOptions::new(),
        )
        .unwrap();
        let expected = arkret_canonical::canonical_json_bytes(&request.submission.event).unwrap();
        let queued = queue_authored_message(request).unwrap();
        let AuthoritySubmitRequest::Event(submission) = queued.request else {
            panic!("message authoring must queue an ordinary Event submission");
        };
        assert_eq!(
            arkret_canonical::canonical_json_bytes(&submission.event).unwrap(),
            expected
        );
    }
}
