//! Proof-only Event authoring over host-owned signer and encryption adapters.

use arkret_wire::{
    AuthoredEvent, AuthoritySubmitRequestBody, Event, EventAdmissionSubmission, EventKind,
};

use crate::{Error, QueuedSubmission, Result};

/// The content and derived identity are finalized before the signer runs.
pub struct EventAuthoringSession {
    event: AuthoredEvent,
    unsigned_bytes: Vec<u8>,
}

impl EventAuthoringSession {
    pub fn new(event: AuthoredEvent) -> Result<Self> {
        if event.producer_proof.is_some() {
            return Err(Error::Protocol(
                "Event authoring requires an unsigned intent".into(),
            ));
        }
        event.verify_identity()?;
        let unsigned_bytes = arkret_canonical::canonical_json_bytes(event.event())?;
        Ok(Self {
            event,
            unsigned_bytes,
        })
    }

    pub fn sign_with(
        mut self,
        signer: impl FnOnce(&mut AuthoredEvent) -> Result<()>,
    ) -> Result<AuthoredEvent> {
        signer(&mut self.event)?;
        self.event.verify_identity()?;
        let mut unsigned = self.event.event().clone();
        unsigned.producer_proof = None;
        if arkret_canonical::canonical_json_bytes(&unsigned)? != self.unsigned_bytes {
            return Err(Error::Protocol(
                "Event signer rewrote the frozen intent".into(),
            ));
        }
        validate_signed_event(self.event.event(), self.event.digest_suite())?;
        Ok(self.event)
    }
}

pub fn validate_signed_event(event: &Event, suite: arkret_canonical::DigestSuite) -> Result<()> {
    if event.producer_proof.is_none() {
        return Err(Error::Protocol(format!(
            "submit requires exactly one producer proof (event_id={}, kind={})",
            event.event_id,
            event.kind.as_str(),
        )));
    }
    event.validate_proof_bindings_with_digest_suite(suite)?;
    arkret_event_draft::validate_event_for_submit(event)
        .map_err(|error| Error::Protocol(error.to_string()))
}

/// Freeze the exact signed request for the existing durable authority queue.
pub fn event_submission(event: &AuthoredEvent) -> Result<QueuedSubmission> {
    validate_signed_event(event.event(), event.digest_suite())?;
    let submission = EventAdmissionSubmission::new(event.event().clone());
    if event.kind == EventKind::MessageCreate {
        return crate::FrozenMessageSubmission::from_signed_request(
            crate::MessageSubmitRequestBody { submission },
        )
        .map(crate::FrozenMessageSubmission::into_queued_submission);
    }
    QueuedSubmission::new(AuthoritySubmitRequestBody::Event(submission))
}
