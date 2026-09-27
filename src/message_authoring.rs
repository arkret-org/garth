//! One producer-side path from finalized message bytes to authority submission.
//!
//! The host owns encryption and the signing key. Garth verifies that the
//! content-bound Event is a message, attaches exactly one producer proof, and
//! freezes the resulting authority request for durable retry.

pub use arkret_models_collaboration::message_authoring::{
    MessageAuthoringContent, MessageAuthoringIntent, MessageEncryptionContext,
    MessagePrepareOutcome, MessagePrepareRequestBody, MessageSubmitRequestBody,
};
use arkret_signatures::{EventSigner, SignEventOptions, sign_event};
use arkret_wire::{AuthoredEvent, AuthoritySubmitRequest, EventAdmissionSubmission, EventKind};

use crate::{Error, QueuedSubmission, Result};

/// Frozen optional prepare input. Retrying this stage never invokes encryption.
#[derive(Clone, Debug, serde::Serialize)]
pub struct MessageAuthoringPreparation {
    request: MessagePrepareRequestBody,
    canonical_request_bytes: Vec<u8>,
}

impl<'de> serde::Deserialize<'de> for MessageAuthoringPreparation {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        use serde::de::Error as _;
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Raw {
            request: MessagePrepareRequestBody,
            canonical_request_bytes: Vec<u8>,
        }
        let raw = Raw::deserialize(deserializer)?;
        let preparation = Self::new(raw.request).map_err(D::Error::custom)?;
        if preparation.canonical_request_bytes != raw.canonical_request_bytes {
            return Err(D::Error::custom(
                "durable prepare bytes do not bind the frozen request",
            ));
        }
        Ok(preparation)
    }
}

impl MessageAuthoringPreparation {
    pub fn new(request: MessagePrepareRequestBody) -> Result<Self> {
        request.validate()?;
        let canonical_request_bytes = arkret_canonical::canonical_json_bytes(&request)?;
        Ok(Self {
            request,
            canonical_request_bytes,
        })
    }

    pub fn request(&self) -> &MessagePrepareRequestBody {
        &self.request
    }

    pub fn canonical_request_bytes(&self) -> &[u8] {
        &self.canonical_request_bytes
    }

    pub fn resolve(self, outcome: &MessagePrepareOutcome) -> Result<MessageAuthoringSession> {
        self.resolve_at(outcome, chrono::Utc::now())
    }

    pub fn resolve_at(
        self,
        outcome: &MessagePrepareOutcome,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<MessageAuthoringSession> {
        let event = verify_prepared_message(&self.request, outcome)?;
        if now >= outcome.expires_at || now < outcome.observed_at {
            return Err(Error::Protocol(
                "message prepare draft is outside its validity window".to_owned(),
            ));
        }
        MessageAuthoringSession::from_authored_event(event)
    }
}

/// A finalized unsigned message intent, consumed by exactly one proof-only signer.
/// Encryption and MLS private state belong to the host, outside this session.
#[derive(Debug)]
pub struct MessageAuthoringSession {
    event: AuthoredEvent,
    unsigned_bytes: Vec<u8>,
}

impl MessageAuthoringSession {
    pub fn from_authored_event(event: AuthoredEvent) -> Result<Self> {
        if event.kind != EventKind::MessageCreate || event.producer_proof.is_some() {
            return Err(Error::Protocol(
                "message session requires an unsigned ak.message.create".to_owned(),
            ));
        }
        event.verify_identity()?;
        let unsigned_bytes = arkret_canonical::canonical_json_bytes(event.event())?;
        Ok(Self {
            event,
            unsigned_bytes,
        })
    }

    pub fn from_prepared(
        request: MessagePrepareRequestBody,
        outcome: &MessagePrepareOutcome,
    ) -> Result<Self> {
        MessageAuthoringPreparation::new(request)?.resolve(outcome)
    }

    pub fn event(&self) -> &AuthoredEvent {
        &self.event
    }

    pub fn sign<S: EventSigner + ?Sized>(
        self,
        signer: &S,
        options: SignEventOptions,
    ) -> Result<FrozenMessageSubmission> {
        self.sign_with(|event| {
            sign_event(event, signer, options).map_err(|error| Error::Protocol(error.to_string()))
        })
    }

    /// Let the host supply its existing signer adapter without giving it an
    /// opportunity to rewrite the already encrypted producer bytes.
    pub fn sign_with<F>(mut self, signer: F) -> Result<FrozenMessageSubmission>
    where
        F: FnOnce(&mut AuthoredEvent) -> Result<()>,
    {
        signer(&mut self.event)?;
        self.event.verify_identity()?;
        let mut unsigned = self.event.event().clone();
        unsigned.producer_proof = None;
        if arkret_canonical::canonical_json_bytes(&unsigned)? != self.unsigned_bytes {
            return Err(Error::Protocol(
                "message signer rewrote the frozen intent".to_owned(),
            ));
        }
        FrozenMessageSubmission::from_signed_request(MessageSubmitRequestBody {
            submission: EventAdmissionSubmission::new(self.event.into_event()),
        })
    }
}

/// Local delivery progress. Refusals are reported separately as typed failures;
/// they do not create an accepted state or a shared current projection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageSubmissionState {
    Queued,
    Forwarding,
    Committed,
}

/// Durable exact-byte submission, using the existing authority queue wire DTO.
#[derive(Clone, Debug, serde::Serialize)]
pub struct FrozenMessageSubmission {
    request: MessageSubmitRequestBody,
    canonical_submission_bytes: Vec<u8>,
    queued: QueuedSubmission,
    forwarding: bool,
}

impl<'de> serde::Deserialize<'de> for FrozenMessageSubmission {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        use serde::de::Error as _;
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Raw {
            request: MessageSubmitRequestBody,
            canonical_submission_bytes: Vec<u8>,
            queued: QueuedSubmission,
            forwarding: bool,
        }
        let raw = Raw::deserialize(deserializer)?;
        let mut frozen = Self::from_signed_request(raw.request).map_err(D::Error::custom)?;
        if frozen.canonical_submission_bytes != raw.canonical_submission_bytes
            || frozen.queued.request != raw.queued.request
        {
            return Err(D::Error::custom(
                "durable message bytes do not bind its frozen request",
            ));
        }
        frozen.queued = raw.queued;
        frozen.forwarding = raw.forwarding;
        Ok(frozen)
    }
}

impl FrozenMessageSubmission {
    pub fn from_signed_request(request: MessageSubmitRequestBody) -> Result<Self> {
        request.validate()?;
        if request.submission.event.producer_proof.is_none() {
            return Err(Error::Protocol(
                "frozen message requires a producer proof".to_owned(),
            ));
        }
        request.submission.event.validate_for_submit_structural()?;
        let suite = request
            .submission
            .event
            .producer_proof
            .as_ref()
            .expect("checked proof")
            .event_digest
            .digest_suite()
            .map_err(|error| Error::Protocol(error.to_string()))?;
        request
            .submission
            .event
            .verify_event_id_matches_content_with_digest_suite(suite)?;
        request
            .submission
            .event
            .validate_proof_bindings_with_digest_suite(suite)?;
        let queued =
            QueuedSubmission::new(AuthoritySubmitRequest::Event(request.submission.clone()))?;
        let canonical_submission_bytes = arkret_canonical::canonical_json_bytes(&queued.request)?;
        Ok(Self {
            request,
            canonical_submission_bytes,
            queued,
            forwarding: false,
        })
    }

    pub fn request(&self) -> &MessageSubmitRequestBody {
        &self.request
    }
    pub fn canonical_submission_bytes(&self) -> &[u8] {
        &self.canonical_submission_bytes
    }
    pub fn into_request(self) -> MessageSubmitRequestBody {
        self.request
    }
    pub fn into_queued_submission(self) -> QueuedSubmission {
        self.queued
    }

    pub fn state(&self) -> MessageSubmissionState {
        if matches!(self.queued.state, crate::SubmissionState::Committed { .. }) {
            MessageSubmissionState::Committed
        } else if self.forwarding {
            MessageSubmissionState::Forwarding
        } else {
            MessageSubmissionState::Queued
        }
    }

    pub fn mark_forwarding(&mut self) {
        self.forwarding = true;
    }

    /// Bind the authenticated authority answer to this exact Event and stream.
    /// Hosts still verify Commit authority signatures before shared projection.
    pub fn apply_outcome(
        &mut self,
        outcome: arkret_wire::AuthoritySubmitOutcome,
    ) -> Result<Option<MessageAuthoringFailure>> {
        if matches!(self.queued.state, crate::SubmissionState::Committed { .. }) {
            let mut candidate = self.queued.clone();
            candidate.apply_outcome(outcome)?;
            if !matches!((&candidate.state, &self.queued.state),
                (crate::SubmissionState::Committed { commit: next, .. },
                 crate::SubmissionState::Committed { commit: existing, .. }) if next == existing)
            {
                return Err(Error::Protocol(
                    "message already has a different terminal Commit".to_owned(),
                ));
            }
            return Ok(None);
        }
        let failure = match &outcome {
            arkret_wire::AuthoritySubmitOutcome::Rejected { reason_code, .. } => {
                Some(classify_authority_rejection(reason_code))
            }
            _ => None,
        };
        self.queued.apply_outcome(outcome)?;
        self.forwarding = false;
        Ok(failure)
    }
}

/// Accept an optional Station-prepared draft only after the SDK proves that it
/// binds the exact frozen request. The returned Event is still unsigned; the
/// host must pass it to [`author_message`] with its own signer.
pub fn verify_prepared_message(
    request: &MessagePrepareRequestBody,
    outcome: &MessagePrepareOutcome,
) -> Result<AuthoredEvent> {
    outcome.validate_against_request(request)?;
    outcome
        .draft
        .unsigned_event_for_kind(arkret_wire::event_kind_str::MESSAGE_CREATE)
        .map_err(Into::into)
}

pub fn author_message<S: EventSigner + ?Sized>(
    event: AuthoredEvent,
    signer: &S,
    options: SignEventOptions,
) -> Result<MessageSubmitRequestBody> {
    Ok(MessageAuthoringSession::from_authored_event(event)?
        .sign(signer, options)?
        .into_request())
}

pub fn queue_authored_message(request: MessageSubmitRequestBody) -> Result<QueuedSubmission> {
    Ok(FrozenMessageSubmission::from_signed_request(request)?.into_queued_submission())
}

/// What a host should do about one failed authoring attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageAuthoringRecovery {
    /// Retry the identical frozen submission. Nothing about it is wrong.
    RetrySameRequest,
    /// The frozen epoch / `group_state_ref` names a group the scope has moved
    /// past. Fetch and verify the current public group and its continuous MLS
    /// transitions, install the matching local private state, then encrypt a
    /// new body and author a new Event. The old frozen request is never
    /// replayed with a rebound ciphertext.
    RefreshGroupAndReEncrypt,
    /// Stop this attempt until a covering MLS Commit is accepted, then
    /// encrypt a new body against the resulting current epoch.
    WaitForEpochCommit,
    /// The submit left the device but its outcome is unknown. Replay the exact
    /// same bytes so the Station's idempotency record answers instead of
    /// authoring a second message.
    ReplayExactSubmission,
    /// Re-read the domain current result and prepare a new intentional write.
    PrepareAgain,
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
    RevisionConflict {
        detail: String,
    },
    PermissionRevoked {
        detail: String,
    },
    PreconditionFailed {
        detail: String,
    },
    /// The producer's authorization is not effective yet at the current
    /// governance Station. This clears without user action.
    AuthorizationPending {
        detail: String,
    },
    /// A dependency the governance Station needs is momentarily unavailable.
    DependencyUnavailable {
        detail: String,
    },
    /// The target refuses a plaintext body. The encrypted branch is required.
    PlaintextRefused {
        detail: String,
    },
    /// Top-level `epoch_mismatch`: the frozen MLS epoch / group state differs
    /// from the ready current group, so the group has to be refreshed and the
    /// body encrypted again into a new request.
    EncryptionContextChanged {
        detail: String,
    },
    /// `failed_precondition` / `epoch_update_required`: a pending MLS
    /// membership or key-access change needs a covering winning Commit before
    /// this scope accepts another encrypted application Event. There is no
    /// target epoch to encrypt for yet.
    EpochCommitPending {
        detail: String,
    },
    /// This request identity already carries different bytes.
    DuplicateConflict {
        detail: String,
    },
    /// Transport failed after the request left, so the commit outcome for this
    /// Event is unknown until the exact bytes are replayed.
    SubmissionOutcomeUnknown {
        detail: String,
    },
    /// The governance Station refused the Event outright.
    Refused {
        code: String,
        detail: String,
    },
}

impl MessageAuthoringFailure {
    pub fn recovery(&self) -> MessageAuthoringRecovery {
        match self {
            Self::RevisionConflict { .. } => MessageAuthoringRecovery::PrepareAgain,
            Self::AuthorizationPending { .. } | Self::DependencyUnavailable { .. } => {
                MessageAuthoringRecovery::RetrySameRequest
            }
            Self::EncryptionContextChanged { .. } => {
                MessageAuthoringRecovery::RefreshGroupAndReEncrypt
            }
            Self::EpochCommitPending { .. } => MessageAuthoringRecovery::WaitForEpochCommit,
            Self::SubmissionOutcomeUnknown { .. } => {
                MessageAuthoringRecovery::ReplayExactSubmission
            }
            Self::PlaintextRefused { .. }
            | Self::PermissionRevoked { .. }
            | Self::PreconditionFailed { .. }
            | Self::DuplicateConflict { .. }
            | Self::Refused { .. } => MessageAuthoringRecovery::FailClosed,
        }
    }

    /// True while the send is still expected to succeed on its own.
    pub fn is_not_ready(&self) -> bool {
        matches!(
            self,
            Self::AuthorizationPending { .. }
                | Self::DependencyUnavailable { .. }
                | Self::EpochCommitPending { .. }
        )
    }

    pub fn detail(&self) -> &str {
        match self {
            Self::RevisionConflict { detail }
            | Self::PermissionRevoked { detail }
            | Self::PreconditionFailed { detail }
            | Self::AuthorizationPending { detail }
            | Self::DependencyUnavailable { detail }
            | Self::PlaintextRefused { detail }
            | Self::EncryptionContextChanged { detail }
            | Self::EpochCommitPending { detail }
            | Self::DuplicateConflict { detail }
            | Self::SubmissionOutcomeUnknown { detail }
            | Self::Refused { detail, .. } => detail,
        }
    }
}

impl std::fmt::Display for MessageAuthoringFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RevisionConflict { detail } => write!(
                formatter,
                "the domain current revision has changed: {detail}"
            ),
            Self::PermissionRevoked { detail } => write!(
                formatter,
                "message permission is no longer effective: {detail}"
            ),
            Self::PreconditionFailed { detail } => {
                write!(formatter, "message precondition is not satisfied: {detail}")
            }
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
            Self::EpochCommitPending { detail } => write!(
                formatter,
                "this scope needs a covering MLS Commit before sending: {detail}"
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

/// The two current MLS send-gate refusals (encryption-and-audit §2.5.2,
/// decision 0100).
///
/// Every encrypted application Event path classifies a Station answer through
/// this typed view of the registered codes, never through problem detail text,
/// so the pause-for-repair and refresh-then-re-encrypt paths cannot be
/// confused with each other or with a key-access consumption refusal
/// (`mls_governance_binding_stale`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MlsSendRefusal {
    /// Top-level `epoch_mismatch` (HTTP 409): the frozen epoch or
    /// `group_state_ref` differs from the ready current group. Refresh the
    /// group, then encrypt a new request.
    EpochMismatch,
    /// `failed_precondition` + `epoch_update_required`: the scope's
    /// key-access checkpoint awaits a covering winning Commit. Pause, and wait
    /// for or drive the repair Commit.
    EpochUpdateRequired,
}

impl MlsSendRefusal {
    /// Classify one problem document by its typed registered identity.
    pub fn from_problem(problem: &arkret_wire::Problem) -> Option<Self> {
        match problem.error_code()? {
            arkret_wire::ErrorCode::EpochMismatch => Some(Self::EpochMismatch),
            arkret_wire::ErrorCode::FailedPrecondition => match problem_reason_code(problem)? {
                arkret_wire::ReasonCode::EpochUpdateRequired => Some(Self::EpochUpdateRequired),
                _ => None,
            },
            _ => None,
        }
    }

    /// Classify one `AuthoritySubmitOutcome::Rejected` reason code.
    pub fn from_rejection_reason(reason_code: &str) -> Option<Self> {
        if arkret_wire::ErrorCode::from_wire(reason_code)
            == Some(arkret_wire::ErrorCode::EpochMismatch)
        {
            return Some(Self::EpochMismatch);
        }
        match arkret_wire::ReasonCode::from_wire(reason_code) {
            arkret_wire::ReasonCode::EpochUpdateRequired => Some(Self::EpochUpdateRequired),
            _ => None,
        }
    }

    fn failure(self, detail: String) -> MessageAuthoringFailure {
        match self {
            Self::EpochMismatch => MessageAuthoringFailure::EncryptionContextChanged { detail },
            Self::EpochUpdateRequired => MessageAuthoringFailure::EpochCommitPending { detail },
        }
    }
}

/// The typed `reason_code` extension of a problem document, if present.
fn problem_reason_code(problem: &arkret_wire::Problem) -> Option<arkret_wire::ReasonCode> {
    problem
        .extensions
        .get("reason_code")
        .and_then(serde_json::Value::as_str)
        .map(arkret_wire::ReasonCode::from_wire)
}

/// Explicit domain-CAS context supplied by the operation's typed read adapter.
/// It is not inferred from Problem extension names or message detail text.
#[derive(Clone, Debug)]
pub struct DomainRevisionContext {
    expected: Option<arkret_wire::CurrentRevision>,
    current: Option<arkret_wire::CurrentRevision>,
}

impl DomainRevisionContext {
    /// `None` current means a confirmed authorized absence, not a failed read.
    /// The host authenticates the current result before constructing this context.
    pub fn from_current(
        selector: &arkret_wire::CurrentSelector,
        stream: &arkret_wire::CommitStreamRef,
        expected: Option<arkret_wire::CurrentRevision>,
        current: Option<&arkret_wire::TypedCurrentResult>,
    ) -> Result<Self> {
        let current = match current {
            Some(arkret_wire::TypedCurrentResult::Value {
                selector: actual_selector,
                source_stream_ref,
                revision,
                ..
            })
            | Some(arkret_wire::TypedCurrentResult::MessageReactions {
                selector: actual_selector,
                source_stream_ref,
                revision,
                ..
            }) => {
                if selector != actual_selector || stream != source_stream_ref {
                    return Err(Error::Protocol(
                        "domain revision context belongs to another subject or stream".to_owned(),
                    ));
                }
                Some(revision.clone())
            }
            None => None,
        };
        Ok(Self { expected, current })
    }

    pub fn revision_changed(&self) -> bool {
        self.expected != self.current
    }
}

/// A failed_precondition can name either a CAS mismatch or another gate. Only
/// an explicit operation context with a different exact current revision can
/// select re-prepare; ordinary MessageCreate has no such context.
pub fn classify_message_authoring_error_with_revision(
    error: &Error,
    context: &DomainRevisionContext,
) -> MessageAuthoringFailure {
    if let Error::Api { error: problem, .. } = error
        && problem.error_code() == Some(arkret_wire::ErrorCode::FailedPrecondition)
        && !problem.extensions.contains_key("reason_code")
        && context.revision_changed()
    {
        return MessageAuthoringFailure::RevisionConflict {
            detail: problem.detail.clone(),
        };
    }
    classify_message_authoring_error(error)
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
    if let Some(refusal) = MlsSendRefusal::from_problem(error) {
        return refusal.failure(detail);
    }
    let reason = problem_reason_code(error)
        .unwrap_or_else(|| arkret_wire::ReasonCode::from_wire(error.code()));
    let reason_failure = classify_reason(reason, detail.clone(), error.code());
    if !matches!(reason_failure, MessageAuthoringFailure::Refused { .. }) {
        return reason_failure;
    }
    if let Some(failure) = classify_registered_error(error.error_code(), detail.clone()) {
        return failure;
    }
    reason_failure
}

/// Classify one governance-Station rejection reason code from a submit outcome.
///
/// A rejection is an answer, not a transport fault: the Event reached the
/// Station and was refused, so nothing here ever reports an unknown outcome.
pub fn classify_authority_rejection(reason_code: &str) -> MessageAuthoringFailure {
    let detail = reason_code.to_owned();
    if let Some(refusal) = MlsSendRefusal::from_rejection_reason(reason_code) {
        return refusal.failure(detail);
    }
    let reason_failure = classify_reason(
        arkret_wire::ReasonCode::from_wire(reason_code),
        detail.clone(),
        reason_code,
    );
    if !matches!(reason_failure, MessageAuthoringFailure::Refused { .. }) {
        return reason_failure;
    }
    if let Some(failure) = classify_registered_error(
        arkret_wire::ErrorCode::from_wire(reason_code),
        detail.clone(),
    ) {
        return failure;
    }
    reason_failure
}

fn classify_registered_error(
    code: Option<arkret_wire::ErrorCode>,
    detail: String,
) -> Option<MessageAuthoringFailure> {
    use arkret_wire::ErrorCode;
    match code? {
        ErrorCode::TemporarilyUnavailable => {
            Some(MessageAuthoringFailure::DependencyUnavailable { detail })
        }
        ErrorCode::CasConflict => Some(MessageAuthoringFailure::RevisionConflict { detail }),
        ErrorCode::FailedPrecondition => {
            Some(MessageAuthoringFailure::PreconditionFailed { detail })
        }
        ErrorCode::DeviceRevoked
        | ErrorCode::DeviceGenerationFenced
        | ErrorCode::DeviceUnauthorized
        | ErrorCode::AppletRevoked
        | ErrorCode::PolicyDenied
        | ErrorCode::CapabilityDenied => {
            Some(MessageAuthoringFailure::PermissionRevoked { detail })
        }
        _ => None,
    }
}

fn classify_reason(
    reason: arkret_wire::ReasonCode,
    detail: String,
    code: &str,
) -> MessageAuthoringFailure {
    use arkret_wire::ReasonCode;
    match reason {
        ReasonCode::PermissionDenied | ReasonCode::PolicyRevoked | ReasonCode::ConsentRevoked => {
            MessageAuthoringFailure::PermissionRevoked { detail }
        }
        ReasonCode::DuplicateConflict => MessageAuthoringFailure::DuplicateConflict { detail },
        ReasonCode::RateLimited
        | ReasonCode::ExternalRateLimited
        | ReasonCode::BackendUnavailable => {
            MessageAuthoringFailure::DependencyUnavailable { detail }
        }
        ReasonCode::SignalPlaintextForbidden
        | ReasonCode::ServiceNotPlaintextVisible
        | ReasonCode::MlsActivationRequired => MessageAuthoringFailure::PlaintextRefused { detail },
        ReasonCode::PolicyRevisionGap | ReasonCode::DecryptionPending => {
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
            semantic_refs: Vec::new(),
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
    fn proof_only_callback_cannot_replace_the_frozen_event() {
        let session =
            MessageAuthoringSession::from_authored_event(authored(EventKind::MessageCreate))
                .unwrap();
        let error = session
            .sign_with(|event| {
                let mut changed = event.event().clone();
                changed
                    .payload
                    .insert("body".to_owned(), json!("rewritten"));
                *event = AuthoredEvent::finalize_with_digest_suite(changed, DigestSuite::Sha256)?;
                sign_event(event, &signer(), SignEventOptions::new())
                    .map_err(|error| Error::Protocol(error.to_string()))
            })
            .unwrap_err();
        assert!(error.to_string().contains("rewrote the frozen intent"));
    }

    #[test]
    fn only_an_exact_covering_commit_changes_delivery_progress() {
        let mut frozen =
            MessageAuthoringSession::from_authored_event(authored(EventKind::MessageCreate))
                .unwrap()
                .sign(&signer(), SignEventOptions::new())
                .unwrap();
        let event = &frozen.request().submission.event;
        let commit = crate::test_fixtures::commit(
            8,
            event,
            arkret_wire::CommitStreamRef::from_scope(
                &event.scope_ref,
                Some(event.realm_id.clone()),
            )
            .unwrap(),
            1,
        );
        let mut wrong = commit.clone();
        wrong.event_ref = EventId::from_digest(DigestSuite::Sha256, [77; 32]);
        assert!(
            frozen
                .apply_outcome(arkret_wire::AuthoritySubmitOutcome::Accepted {
                    status: arkret_wire::AuthorityCommitStatus::Committed,
                    commit: wrong,
                })
                .is_err()
        );
        assert_eq!(frozen.state(), MessageSubmissionState::Queued);
        frozen
            .apply_outcome(arkret_wire::AuthoritySubmitOutcome::Accepted {
                status: arkret_wire::AuthorityCommitStatus::Committed,
                commit: commit.clone(),
            })
            .unwrap();
        assert_eq!(frozen.state(), MessageSubmissionState::Committed);
        frozen
            .apply_outcome(arkret_wire::AuthoritySubmitOutcome::Accepted {
                status: arkret_wire::AuthorityCommitStatus::Duplicate,
                commit,
            })
            .unwrap();
        assert!(
            frozen
                .apply_outcome(arkret_wire::AuthoritySubmitOutcome::Rejected {
                    status: arkret_wire::AuthorityRejectionStatus::Rejected,
                    reason_code: "policy_denied".to_owned(),
                })
                .is_err()
        );
        let mut saved = serde_json::to_value(&frozen).unwrap();
        saved["queued"]["state"]["commit"]["event_ref"] =
            json!(EventId::from_digest(DigestSuite::Sha256, [77; 32]));
        assert!(serde_json::from_value::<FrozenMessageSubmission>(saved).is_err());
    }

    #[test]
    fn a_signed_or_unsigned_incomplete_session_cannot_sign_again() {
        let mut event = authored(EventKind::MessageCreate);
        sign_event(&mut event, &signer(), SignEventOptions::new()).unwrap();
        assert!(MessageAuthoringSession::from_authored_event(event).is_err());
        assert!(
            MessageAuthoringSession::from_authored_event(authored(EventKind::MessageCreate))
                .unwrap()
                .sign_with(|_| Ok(()))
                .is_err()
        );
    }

    #[test]
    fn durable_reopen_replays_the_identical_submission_without_signing() {
        let mut frozen =
            MessageAuthoringSession::from_authored_event(authored(EventKind::MessageCreate))
                .unwrap()
                .sign(&signer(), SignEventOptions::new())
                .unwrap();
        assert_eq!(frozen.state(), MessageSubmissionState::Queued);
        frozen.mark_forwarding();
        let saved = serde_json::to_vec(&frozen).unwrap();
        let mut reopened: FrozenMessageSubmission = serde_json::from_slice(&saved).unwrap();
        assert_eq!(reopened.state(), MessageSubmissionState::Forwarding);
        assert_eq!(
            frozen.canonical_submission_bytes(),
            reopened.canonical_submission_bytes()
        );
        assert_eq!(
            reopened
                .apply_outcome(arkret_wire::AuthoritySubmitOutcome::Rejected {
                    status: arkret_wire::AuthorityRejectionStatus::RetryableUnavailable,
                    reason_code: "temporarily_unavailable".to_owned(),
                })
                .unwrap()
                .unwrap()
                .recovery(),
            MessageAuthoringRecovery::RetrySameRequest
        );
        assert_eq!(reopened.state(), MessageSubmissionState::Queued);
        assert_eq!(
            frozen.canonical_submission_bytes(),
            reopened.canonical_submission_bytes()
        );
        let mut tampered = serde_json::to_value(&frozen).unwrap();
        tampered["canonical_submission_bytes"][0] = json!(0);
        assert!(serde_json::from_value::<FrozenMessageSubmission>(tampered).is_err());
        let mut request = reopened.into_request();
        request
            .submission
            .event
            .payload
            .insert("body".to_owned(), json!("changed after signing"));
        assert!(FrozenMessageSubmission::from_signed_request(request).is_err());
    }

    #[test]
    fn prepared_and_direct_sessions_share_the_exact_sign_and_queue_boundary() {
        let request: MessagePrepareRequestBody = serde_json::from_value(json!({
            "request_id": "ak:request:019b6a40-0000-7000-8000-000000000001",
            "account_id": { "principal_id": "ak:did_core:web:alice.example", "station_id": "ak:did_core:web:station.example" },
            "realm_id": authored(EventKind::MessageCreate).realm_id,
            "intent": {
                "strand_id": "ak:strand:AUOjN8M8xm-W1G1Ve9UR6sHKJh7JPG7bM8ZDnzcGJ2Vh",
                "track_name": "discussion",
                "content": { "kind": "plaintext", "content": { "kind": "ak.content.text", "body": "hello", "format": "plain" } }
            },
            "created_at": "2026-09-16T00:00:00.000Z"
        })).unwrap();
        let mut event = authored(EventKind::MessageCreate).into_event();
        event.actor_id = ActorId::account(request.account_id.clone());
        event.payload =
            serde_json::from_value(serde_json::to_value(request.intent.payload()).unwrap())
                .unwrap();
        let event = AuthoredEvent::finalize_with_digest_suite(event, DigestSuite::Sha256).unwrap();
        let outcome = MessagePrepareOutcome {
            request_digest: request.canonical_request_digest().unwrap(),
            draft: arkret_models_collaboration::prepared_event_draft::PreparedEventDraft {
                unsigned_event_bytes: arkret_wire::Base64UrlString::new(
                    arkret_canonical::base64url_encode(
                        arkret_canonical::canonical_json_bytes(&event.digest_payload().unwrap())
                            .unwrap(),
                    ),
                )
                .unwrap(),
                event_digest: arkret_wire::Hash::new(
                    event
                        .event_digest_with_digest_suite(DigestSuite::Sha256)
                        .unwrap(),
                )
                .unwrap(),
            },
            observed_at: request.created_at,
            expires_at: request.created_at + chrono::Duration::seconds(300),
        };
        let preparation = MessageAuthoringPreparation::new(request.clone()).unwrap();
        assert_eq!(
            preparation.canonical_request_bytes(),
            arkret_canonical::canonical_json_bytes(&request).unwrap()
        );
        let options = SignEventOptions::new().with_created_at(request.created_at);
        let direct = MessageAuthoringSession::from_authored_event(event)
            .unwrap()
            .sign(&signer(), options.clone())
            .unwrap();
        let durable_preparation: MessageAuthoringPreparation =
            serde_json::from_slice(&serde_json::to_vec(&preparation).unwrap()).unwrap();
        assert_eq!(
            durable_preparation.canonical_request_bytes(),
            preparation.canonical_request_bytes()
        );
        assert!(
            preparation
                .clone()
                .resolve_at(&outcome, outcome.expires_at)
                .is_err()
        );
        let prepared = preparation
            .resolve_at(&outcome, request.created_at)
            .unwrap()
            .sign(&signer(), options)
            .unwrap();
        assert_eq!(
            direct.canonical_submission_bytes(),
            prepared.canonical_submission_bytes()
        );
        let mut wrong_request = request;
        wrong_request.intent.reply_to_id = Some("other-message".to_owned());
        assert!(MessageAuthoringSession::from_prepared(wrong_request, &outcome).is_err());
    }

    #[test]
    fn registered_failures_keep_permission_revision_precondition_and_epoch_distinct() {
        for (code, recovery) in [
            ("cas_conflict", MessageAuthoringRecovery::PrepareAgain),
            ("device_revoked", MessageAuthoringRecovery::FailClosed),
            ("failed_precondition", MessageAuthoringRecovery::FailClosed),
            (
                "epoch_mismatch",
                MessageAuthoringRecovery::RefreshGroupAndReEncrypt,
            ),
        ] {
            let failure = classify_message_authoring_error(&Error::Api {
                status: 409,
                error: Box::new(arkret_wire::Problem::new(code, 409, "failure")),
            });
            assert_eq!(failure.recovery(), recovery);
            match code {
                "cas_conflict" => assert!(matches!(
                    failure,
                    MessageAuthoringFailure::RevisionConflict { .. }
                )),
                "device_revoked" => assert!(matches!(
                    failure,
                    MessageAuthoringFailure::PermissionRevoked { .. }
                )),
                "failed_precondition" => assert!(matches!(
                    failure,
                    MessageAuthoringFailure::PreconditionFailed { .. }
                )),
                _ => assert!(matches!(
                    failure,
                    MessageAuthoringFailure::EncryptionContextChanged { .. }
                )),
            }
        }
    }

    #[test]
    fn domain_failed_precondition_requires_explicit_exact_revision_context() {
        use arkret_wire::{
            CommitStreamRef, CurrentRevision, CurrentSelector, RealmCommitId, TypedCurrentResult,
        };
        let selector = CurrentSelector::DeviceGeneration;
        let stream = CommitStreamRef::Realm {
            realm_id: authored(EventKind::MessageCreate).realm_id.clone(),
        };
        let expected = CurrentRevision {
            commit_id: RealmCommitId::from_digest([1; 32]),
            stream_position: 7,
        };
        let current_revision = CurrentRevision {
            commit_id: RealmCommitId::from_digest([2; 32]),
            stream_position: 7,
        };
        let current = TypedCurrentResult::Value {
            selector: selector.clone(),
            source_stream_ref: stream.clone(),
            revision: current_revision.clone(),
            value: json!({ "current_device_generation_ref": 2 }),
        };
        let stale =
            DomainRevisionContext::from_current(&selector, &stream, Some(expected), Some(&current))
                .unwrap();
        let error = Error::Api {
            status: 409,
            error: Box::new(arkret_wire::Problem::new(
                "failed_precondition",
                409,
                "precondition failed",
            )),
        };
        assert!(matches!(
            classify_message_authoring_error_with_revision(&error, &stale),
            MessageAuthoringFailure::RevisionConflict { .. }
        ));
        assert_eq!(
            classify_message_authoring_error_with_revision(&error, &stale).recovery(),
            MessageAuthoringRecovery::PrepareAgain
        );
        // The same numeric position with another Commit is still a different revision.
        assert!(stale.revision_changed());
        let matching = DomainRevisionContext::from_current(
            &selector,
            &stream,
            Some(current_revision),
            Some(&current),
        )
        .unwrap();
        assert!(matches!(
            classify_message_authoring_error_with_revision(&error, &matching),
            MessageAuthoringFailure::PreconditionFailed { .. }
        ));
        assert_eq!(
            classify_message_authoring_error(&error).recovery(),
            MessageAuthoringRecovery::FailClosed
        );
        let epoch_pending = Error::Api {
            status: 409,
            error: Box::new(problem_with_reason(
                "failed_precondition",
                arkret_wire::ReasonCode::EPOCH_UPDATE_REQUIRED,
            )),
        };
        assert_eq!(
            classify_message_authoring_error_with_revision(&epoch_pending, &stale).recovery(),
            MessageAuthoringRecovery::WaitForEpochCommit
        );
        assert!(
            DomainRevisionContext::from_current(
                &CurrentSelector::RealmProfile,
                &stream,
                None,
                Some(&current)
            )
            .is_err()
        );
        let absent = DomainRevisionContext::from_current(&selector, &stream, None, None).unwrap();
        assert!(!absent.revision_changed());
        let first_write =
            DomainRevisionContext::from_current(&selector, &stream, None, Some(&current)).unwrap();
        assert!(first_write.revision_changed());
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
        let arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest::Event(
            submission,
        ) = queued.request
        else {
            panic!("message authoring must queue an ordinary Event submission");
        };
        assert_eq!(
            arkret_canonical::canonical_json_bytes(&submission.event).unwrap(),
            expected
        );
    }

    #[test]
    fn a_key_access_binding_refusal_does_not_reencrypt() {
        let failure = classify_message_authoring_error(&Error::Api {
            status: 409,
            error: Box::new(problem_with_reason(
                "conflict",
                arkret_wire::ReasonCode::MLS_GOVERNANCE_BINDING_STALE,
            )),
        });
        assert_eq!(failure.recovery(), MessageAuthoringRecovery::FailClosed);
    }

    #[test]
    fn a_stale_epoch_asks_for_re_encryption() {
        let failure = classify_message_authoring_error(&Error::Api {
            status: 409,
            error: Box::new(arkret_wire::Problem::new(
                "epoch_mismatch",
                409,
                "stale epoch",
            )),
        });
        assert_eq!(
            failure.recovery(),
            MessageAuthoringRecovery::RefreshGroupAndReEncrypt
        );
        assert!(!failure.is_not_ready());
    }

    #[test]
    fn an_uncovered_epoch_waits_for_commit_without_retrying_frozen_bytes() {
        let failure = classify_authority_rejection(arkret_wire::ReasonCode::EPOCH_UPDATE_REQUIRED);
        assert_eq!(
            failure.recovery(),
            MessageAuthoringRecovery::WaitForEpochCommit
        );
        assert!(failure.is_not_ready());
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

    #[test]
    fn an_uncovered_checkpoint_problem_pauses_for_the_repair_commit() {
        let problem = problem_with_reason(
            "failed_precondition",
            arkret_wire::ReasonCode::EPOCH_UPDATE_REQUIRED,
        );
        assert_eq!(
            MlsSendRefusal::from_problem(&problem),
            Some(MlsSendRefusal::EpochUpdateRequired)
        );
        let failure = classify_message_authoring_error(&Error::Api {
            status: 409,
            error: Box::new(problem),
        });
        assert!(matches!(
            failure,
            MessageAuthoringFailure::EpochCommitPending { .. }
        ));
        assert_eq!(
            failure.recovery(),
            MessageAuthoringRecovery::WaitForEpochCommit
        );
    }

    #[test]
    fn send_gate_identity_comes_from_registered_codes_not_detail_text() {
        let wording = arkret_wire::Problem::new(
            "conflict",
            409,
            "epoch_mismatch: epoch_update_required mls_governance_binding_stale",
        );
        assert_eq!(MlsSendRefusal::from_problem(&wording), None);
        let failure = classify_message_authoring_error(&Error::Api {
            status: 409,
            error: Box::new(wording),
        });
        assert_eq!(failure.recovery(), MessageAuthoringRecovery::FailClosed);

        // The pause reason only counts under its registered outer code.
        let misplaced =
            problem_with_reason("conflict", arkret_wire::ReasonCode::EPOCH_UPDATE_REQUIRED);
        assert_eq!(MlsSendRefusal::from_problem(&misplaced), None);
        assert_eq!(
            classify_message_authoring_error(&Error::Api {
                status: 409,
                error: Box::new(misplaced),
            })
            .recovery(),
            MessageAuthoringRecovery::FailClosed
        );
    }

    #[test]
    fn submit_rejection_reasons_split_refresh_from_pause() {
        assert_eq!(
            MlsSendRefusal::from_rejection_reason(arkret_wire::ErrorCode::EPOCH_MISMATCH),
            Some(MlsSendRefusal::EpochMismatch)
        );
        assert_eq!(
            classify_authority_rejection(arkret_wire::ErrorCode::EPOCH_MISMATCH).recovery(),
            MessageAuthoringRecovery::RefreshGroupAndReEncrypt
        );
        assert_eq!(
            MlsSendRefusal::from_rejection_reason(
                arkret_wire::ReasonCode::MLS_GOVERNANCE_BINDING_STALE
            ),
            None
        );
    }

    #[test]
    fn plaintext_after_activation_is_a_plaintext_refusal() {
        let failure = classify_message_authoring_error(&Error::Api {
            status: 409,
            error: Box::new(problem_with_reason(
                "failed_precondition",
                arkret_wire::ReasonCode::MLS_ACTIVATION_REQUIRED,
            )),
        });
        assert!(matches!(
            failure,
            MessageAuthoringFailure::PlaintextRefused { .. }
        ));
        assert_eq!(failure.recovery(), MessageAuthoringRecovery::FailClosed);
    }

    #[test]
    fn registered_specific_reasons_precede_the_generic_precondition_fallback() {
        for reason in [
            arkret_wire::ReasonCode::MLS_ACTIVATION_REQUIRED,
            arkret_wire::ReasonCode::SERVICE_NOT_PLAINTEXT_VISIBLE,
        ] {
            let failure = classify_message_authoring_error(&Error::Api {
                status: 409,
                error: Box::new(problem_with_reason("failed_precondition", reason)),
            });
            assert!(matches!(
                failure,
                MessageAuthoringFailure::PlaintextRefused { .. }
            ));
            assert!(matches!(
                classify_authority_rejection(reason),
                MessageAuthoringFailure::PlaintextRefused { .. }
            ));
        }
        for reason in [
            arkret_wire::ReasonCode::PERMISSION_DENIED,
            arkret_wire::ReasonCode::POLICY_REVOKED,
        ] {
            assert!(matches!(
                classify_message_authoring_error(&Error::Api {
                    status: 409,
                    error: Box::new(problem_with_reason("failed_precondition", reason)),
                }),
                MessageAuthoringFailure::PermissionRevoked { .. }
            ));
            assert!(matches!(
                classify_authority_rejection(reason),
                MessageAuthoringFailure::PermissionRevoked { .. }
            ));
        }
        let unknown = classify_message_authoring_error(&Error::Api {
            status: 409,
            error: Box::new(problem_with_reason(
                "failed_precondition",
                "unknown_plaintext_wording",
            )),
        });
        assert!(matches!(
            unknown,
            MessageAuthoringFailure::PreconditionFailed { .. }
        ));
        assert_eq!(unknown.recovery(), MessageAuthoringRecovery::FailClosed);
    }

    #[test]
    fn inactive_mls_scope_fails_closed_without_retry() {
        let problem = arkret_wire::Problem::new(
            "failed_precondition",
            409,
            "scope has no accepted MLS group",
        );
        assert_eq!(MlsSendRefusal::from_problem(&problem), None);
        let failure = classify_message_authoring_error(&Error::Api {
            status: 409,
            error: Box::new(problem),
        });
        assert!(matches!(
            failure,
            MessageAuthoringFailure::PreconditionFailed { .. }
        ));
        assert_eq!(failure.recovery(), MessageAuthoringRecovery::FailClosed);
    }

    #[test]
    fn current_mls_read_fault_retries_exact_request() {
        let problem = arkret_wire::Problem::new(
            "temporarily_unavailable",
            503,
            "current MLS group is temporarily unavailable",
        );
        let failure = classify_message_authoring_error(&Error::Api {
            status: 503,
            error: Box::new(problem),
        });
        assert!(matches!(
            failure,
            MessageAuthoringFailure::DependencyUnavailable { .. }
        ));
        assert_eq!(
            failure.recovery(),
            MessageAuthoringRecovery::RetrySameRequest
        );
    }

    fn problem_with_reason(code: &str, reason: &str) -> arkret_wire::Problem {
        let mut problem = arkret_wire::Problem::new(code, 409, "stale binding");
        problem
            .extensions
            .insert("reason_code".to_owned(), json!(reason));
        problem
    }
}
