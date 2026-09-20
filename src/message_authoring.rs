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
        submission: EventCommitSubmission::new(event.into_event()),
    };
    request.validate()?;
    request.submission.event.validate_for_submit_structural()?;
    Ok(request)
}

pub fn queue_authored_message(request: MessageSubmitRequestBody) -> Result<QueuedSubmission> {
    request.validate()?;
    QueuedSubmission::new(AuthoritySubmitRequest::Event(request.submission))
}

/// What a host should do about one failed authoring attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageAuthoringRecovery {
    /// Retry the identical frozen submission. Nothing about it is wrong.
    RetrySameRequest,
    /// The frozen MLS binding is stale: encrypt the body again for the current
    /// epoch before authoring a new Event.
    ReEncrypt,
    /// The submit left the device but its outcome is unknown. Replay the exact
    /// same bytes so the Station's idempotency record answers instead of
    /// authoring a second message.
    ReplayExactSubmission,
    /// Fail closed. Nothing about retrying changes the answer.
    FailClosed,
}

/// Why one ordinary-message attempt did not produce a committed Event.
///
/// The variants exist so an interface can say what is actually wrong. One
/// "could not send" line hides the difference between "the Station is
/// momentarily unavailable, this clears on its own" and "your encryption
/// context is stale and this body must be encrypted again".
///
/// Deliberately exhaustive: a consumer that renders these has to say something
/// true about every one of them, and a wildcard arm is how "send failed" comes
/// back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MessageAuthoringFailure {
    /// The producer's authorization is not effective yet at the current
    /// governance Station. This clears without user action.
    AuthorizationPending { detail: String },
    /// A dependency the governance Station needs is momentarily unavailable.
    DependencyUnavailable { detail: String },
    /// The target refuses a plaintext body. The encrypted branch is required.
    PlaintextRefused { detail: String },
    /// The frozen MLS governance binding no longer matches the installed group
    /// state, so the body has to be encrypted again.
    EncryptionContextChanged { detail: String },
    /// This request identity already carries different bytes.
    DuplicateConflict { detail: String },
    /// Transport failed after the request left, so the commit outcome for this
    /// Event is unknown until the exact bytes are replayed.
    SubmissionOutcomeUnknown { detail: String },
    /// The governance Station refused the Event outright.
    Refused { code: String, detail: String },
}

impl MessageAuthoringFailure {
    pub fn recovery(&self) -> MessageAuthoringRecovery {
        match self {
            Self::AuthorizationPending { .. } | Self::DependencyUnavailable { .. } => {
                MessageAuthoringRecovery::RetrySameRequest
            }
            Self::EncryptionContextChanged { .. } => MessageAuthoringRecovery::ReEncrypt,
            Self::SubmissionOutcomeUnknown { .. } => {
                MessageAuthoringRecovery::ReplayExactSubmission
            }
            Self::PlaintextRefused { .. }
            | Self::DuplicateConflict { .. }
            | Self::Refused { .. } => MessageAuthoringRecovery::FailClosed,
        }
    }

    /// True while the send is still expected to succeed on its own.
    pub fn is_not_ready(&self) -> bool {
        matches!(
            self,
            Self::AuthorizationPending { .. } | Self::DependencyUnavailable { .. }
        )
    }

    pub fn detail(&self) -> &str {
        match self {
            Self::AuthorizationPending { detail }
            | Self::DependencyUnavailable { detail }
            | Self::PlaintextRefused { detail }
            | Self::EncryptionContextChanged { detail }
            | Self::DuplicateConflict { detail }
            | Self::SubmissionOutcomeUnknown { detail }
            | Self::Refused { detail, .. } => detail,
        }
    }
}

impl std::fmt::Display for MessageAuthoringFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AuthorizationPending { detail } => write!(
                formatter,
                "this authorization is not effective at the current governance Station yet: {detail}"
            ),
            Self::DependencyUnavailable { detail } => write!(
                formatter,
                "a dependency for this message is unavailable: {detail}"
            ),
            Self::PlaintextRefused { detail } => write!(
                formatter,
                "this target requires end-to-end encryption: {detail}"
            ),
            Self::EncryptionContextChanged { detail } => write!(
                formatter,
                "the frozen encryption context no longer applies: {detail}"
            ),
            Self::DuplicateConflict { detail } => write!(
                formatter,
                "this request identity already carries different content: {detail}"
            ),
            Self::SubmissionOutcomeUnknown { detail } => write!(
                formatter,
                "the message submission result is unknown: {detail}"
            ),
            Self::Refused { code, detail } => {
                write!(formatter, "message refused ({code}): {detail}")
            }
        }
    }
}

/// Classify a transport or contract error into its recovery class.
///
/// Anything that is not a typed API answer is reported as an unknown outcome,
/// because a submission that left the device may still have been committed.
/// Nothing here widens an error into a retry the contract does not allow.
pub fn classify_message_authoring_error(error: &Error) -> MessageAuthoringFailure {
    let Error::Api { error, .. } = error else {
        return MessageAuthoringFailure::SubmissionOutcomeUnknown {
            detail: error.to_string(),
        };
    };
    let detail = error.detail.clone();
    let reason = error
        .extensions
        .get("reason_code")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_else(|| error.code());
    classify_authoring_reason_code(reason, detail, error.code())
}

/// Classify one governance-Station rejection reason code from a submit outcome.
///
/// A rejection is an answer, not a transport fault: the Event reached the
/// Station and was refused, so nothing here ever reports an unknown outcome.
pub fn classify_authority_rejection(reason_code: &str) -> MessageAuthoringFailure {
    classify_authoring_reason_code(reason_code, reason_code.to_owned(), reason_code)
}

fn classify_authoring_reason_code(
    reason: &str,
    detail: String,
    code: &str,
) -> MessageAuthoringFailure {
    use arkret_wire::ReasonCode;
    match reason {
        ReasonCode::MLS_GOVERNANCE_BINDING_STALE => {
            MessageAuthoringFailure::EncryptionContextChanged { detail }
        }
        ReasonCode::DUPLICATE_CONFLICT => MessageAuthoringFailure::DuplicateConflict { detail },
        ReasonCode::RATE_LIMITED
        | ReasonCode::EXTERNAL_RATE_LIMITED
        | ReasonCode::BACKEND_UNAVAILABLE
        | ReasonCode::REALM_UNAVAILABLE
        | ReasonCode::SCOPE_UNAVAILABLE
        | ReasonCode::RECIPIENT_UNAVAILABLE => {
            MessageAuthoringFailure::DependencyUnavailable { detail }
        }
        ReasonCode::SIGNAL_PLAINTEXT_FORBIDDEN | ReasonCode::SERVICE_NOT_PLAINTEXT_VISIBLE => {
            MessageAuthoringFailure::PlaintextRefused { detail }
        }
        ReasonCode::POLICY_REVISION_GAP | ReasonCode::DECRYPTION_PENDING => {
            MessageAuthoringFailure::AuthorizationPending { detail }
        }
        _ => MessageAuthoringFailure::Refused {
            code: code.to_owned(),
            detail,
        },
    }
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
            producer_proof: None,
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
        assert!(request.submission.event.producer_proof.is_some());
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

    #[test]
    fn a_stale_governance_binding_asks_for_re_encryption() {
        let failure = classify_message_authoring_error(&Error::Api {
            status: 409,
            error: Box::new(problem_with_reason(
                "conflict",
                arkret_wire::ReasonCode::MLS_GOVERNANCE_BINDING_STALE,
            )),
        });
        assert_eq!(failure.recovery(), MessageAuthoringRecovery::ReEncrypt);
        assert!(!failure.is_not_ready());
    }

    #[test]
    fn a_transport_fault_leaves_the_commit_outcome_unknown() {
        let failure = classify_message_authoring_error(&Error::Http("reset".to_owned()));
        assert_eq!(
            failure.recovery(),
            MessageAuthoringRecovery::ReplayExactSubmission
        );
    }

    #[test]
    fn an_unavailable_dependency_is_retryable_but_a_refusal_is_not() {
        let pending = classify_authority_rejection(arkret_wire::ReasonCode::BACKEND_UNAVAILABLE);
        assert_eq!(
            pending.recovery(),
            MessageAuthoringRecovery::RetrySameRequest
        );
        assert!(pending.is_not_ready());

        let refused = classify_authority_rejection("authorization_denied");
        assert_eq!(refused.recovery(), MessageAuthoringRecovery::FailClosed);
        assert!(matches!(refused, MessageAuthoringFailure::Refused { .. }));
    }

    #[test]
    fn a_plaintext_refusal_never_becomes_a_retry() {
        let failure =
            classify_authority_rejection(arkret_wire::ReasonCode::SIGNAL_PLAINTEXT_FORBIDDEN);
        assert!(matches!(
            failure,
            MessageAuthoringFailure::PlaintextRefused { .. }
        ));
        assert_eq!(failure.recovery(), MessageAuthoringRecovery::FailClosed);
    }

    fn problem_with_reason(code: &str, reason: &str) -> arkret_wire::Problem {
        let mut problem = arkret_wire::Problem::new(code, 409, "stale binding");
        problem
            .extensions
            .insert("reason_code".to_owned(), json!(reason));
        problem
    }
}
