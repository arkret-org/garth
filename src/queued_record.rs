use std::ops::Deref;

use arkret_event_draft::EventIntent;
use arkret_identifiers::ScheduledSendId;
use arkret_models_collaboration::direct_conversation_ops::{
    DirectConversationFoundingAcceptanceOutcome, DirectConversationFoundingPlan,
    DirectConversationFoundingUnitSubmission,
};
use arkret_models_collaboration::events_payloads::RealmCreatePayload;
use arkret_wire::{
    ActorId, AuthoredEvent, DidCoreId, Event, EventId, EventKind, Hash, MessageId, RealmId,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{Error, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthoringAuthorityModel {
    AcceptedDevice,
    Agent,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthoringGeneration {
    pub authority_model: AuthoringAuthorityModel,
    pub authority_principal_id: DidCoreId,
    pub generation_ref: String,
}

impl AuthoringGeneration {
    pub fn agent(
        controller: &str,
        controller_generation: &Self,
        authorization_ref: &str,
    ) -> Result<Self> {
        let authorization_ref = authorization_ref.trim();
        if authorization_ref.is_empty() {
            return Err(Error::Protocol(
                "Agent authoring requires authorization_ref".to_owned(),
            ));
        }
        let generation_ref = arkret_canonical::canonical_sha256(&serde_json::json!({
            "controller_authority_model": controller_generation.authority_model,
            "controller_generation_ref": controller_generation.generation_ref,
            "authorization_ref": authorization_ref,
        }))?;
        Ok(Self {
            authority_model: AuthoringAuthorityModel::Agent,
            authority_principal_id: DidCoreId::new(controller.to_owned())?,
            generation_ref,
        })
    }
}

/// The semantic operation a queue slot stands for, frozen before authoring.
///
/// This is the SDK's [`EventIntent`], not a normalized [`Event`]. The queue used
/// to keep an `Event` here with its authoring fields blanked and `event_id`
/// re-derived from the blanks — a durable identity that named no Event anyone
/// would ever submit, yet was shaped exactly like one, so every reader that
/// reached for it got a plausible-looking wrong answer. An `EventIntent` has no
/// identity to reach for; the only identity in this record is on the authored
/// attempt.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueuedEventIntent {
    pub digest_suite: arkret_canonical::DigestSuite,
    pub intent: EventIntent,
}

impl QueuedEventIntent {
    pub fn new(intent: EventIntent, digest_suite: arkret_canonical::DigestSuite) -> Self {
        // A CBA basis the producer did not pin is per-attempt state: each retry
        // re-reads the Seal view it authors against.
        Self {
            digest_suite,
            intent: intent.without_cba_basis(),
        }
    }

    /// Freeze an intent that pins its own CBA basis.
    ///
    /// A pre-join `ak.invite.accept` cannot re-resolve the membership-gated
    /// Realm Seal view, so the join-candidate basis its author resolved is part
    /// of the operation, not of one attempt at it.
    pub fn with_pinned_cba_basis(
        intent: EventIntent,
        digest_suite: arkret_canonical::DigestSuite,
    ) -> Self {
        Self {
            digest_suite,
            intent,
        }
    }

    pub fn digest(&self) -> Result<Hash> {
        Ok(Hash::new(arkret_canonical::canonical_sha256(self)?)?)
    }
}

impl Deref for QueuedEventIntent {
    type Target = EventIntent;

    fn deref(&self) -> &Self::Target {
        &self.intent
    }
}

/// One authoring attempt at a queue slot's intent, frozen byte-for-byte.
///
/// `envelope` is an [`AuthoredEvent`], so restoring this record re-proves that
/// the stored `event_id` is the one its own content derives. A durable record is
/// not a trusted source of identity.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueuedAuthoredEventAttempt {
    pub intent_digest: Hash,
    pub envelope: AuthoredEvent,
    pub transport_idempotency_key: String,
    pub canonical_body_bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScheduledSendSubmissionState {
    Ready,
    SubmissionUncertain,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScheduledSendDispatchRecord {
    pub scheduled_send_id: ScheduledSendId,
    pub event_id: EventId,
    pub message_id: MessageId,
    pub canonical_signed_event_bytes: Vec<u8>,
    pub submission_state: ScheduledSendSubmissionState,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueuedMlsSnapshot {
    pub realm_id: String,
    pub group_id: String,
    pub epoch: u64,
    pub admission_epoch: u64,
    pub group_state_event_id: Option<EventId>,
    pub salt_hex: String,
    pub ciphertext_hex: String,
    pub mac_hex: String,
    pub recorded_at: DateTime<Utc>,
    pub epoch_started_at: DateTime<Utc>,
    pub app_messages_observed: u64,
    pub aead_version: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MlsAdmissionStage {
    CommitPending,
    CommitAcceptedWaitingSeal,
    WelcomesAuthored,
    WelcomesAcceptedWaitingSeal,
}

/// The Welcome batch bound to an MLS admission Commit.
///
/// Exact signed Welcome Events bound to an authored MLS admission Commit.
/// They are frozen before the Commit's first network write so producer-side
/// envelope-size preflight and crash replay cover the complete admission unit.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueuedMlsWelcomes {
    pub events: Vec<AuthoredEvent>,
}

impl QueuedMlsWelcomes {
    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn authored(&self) -> &[AuthoredEvent] {
        &self.events
    }

    /// Every Realm this batch writes into, for the scope check below.
    fn realm_ids(&self) -> Vec<Option<&RealmId>> {
        self.events
            .iter()
            .map(|event| Some(&event.realm_id))
            .collect()
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum QueuedPostAcceptAction {
    MlsAdmission {
        realm_id: String,
        actor_id: String,
        device_id: String,
        /// Exact signed Add proposal Events submitted atomically with the
        /// Commit. They are durable here before the first transport attempt.
        proposal_events: Vec<AuthoredEvent>,
        /// Durable protocol phase. Ingress acceptance is not finality: both
        /// the Commit and the Welcome batch wait for a covering accepted Seal
        /// before the next phase is allowed to run.
        stage: MlsAdmissionStage,
        #[serde(default)]
        commit_ingress_receipts: Vec<arkret_wire::IngressReceipt>,
        #[serde(default)]
        commit_was_duplicate: bool,
        welcomes: QueuedMlsWelcomes,
        snapshot: QueuedMlsSnapshot,
    },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueuedSdkEvent {
    pub intent: QueuedEventIntent,
    pub intent_digest: Hash,
    pub local_operation_id: String,
    pub authoring_idempotency_key: String,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub authored_attempt: Option<QueuedAuthoredEventAttempt>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub supersedes_event_id: Option<EventId>,
    pub authoring_generation: AuthoringGeneration,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub post_accept: Option<QueuedPostAcceptAction>,
    #[serde(deserialize_with = "deserialize_required_nullable")]
    pub scheduled_dispatch: Option<ScheduledSendDispatchRecord>,
}

fn deserialize_required_nullable<'de, D, T>(
    deserializer: D,
) -> std::result::Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

impl QueuedSdkEvent {
    pub fn unauthored(
        intent: QueuedEventIntent,
        local_operation_id: String,
        authoring_idempotency_key: String,
        supersedes_event_id: Option<EventId>,
        authoring_generation: AuthoringGeneration,
        post_accept: Option<QueuedPostAcceptAction>,
    ) -> Result<Self> {
        let intent_digest = intent.digest()?;
        let queued = Self {
            intent,
            intent_digest,
            local_operation_id,
            authoring_idempotency_key,
            authored_attempt: None,
            supersedes_event_id,
            authoring_generation,
            post_accept,
            scheduled_dispatch: None,
        };
        queued.validate()?;
        Ok(queued)
    }

    /// A slot whose intent is already authored into one exact attempt.
    ///
    /// `intent` is passed in rather than reconstructed from `envelope`: the
    /// caller authored the envelope *from* that intent, and only the caller
    /// knows which CBA members the producer pinned as part of the operation
    /// versus resolved for this attempt.
    #[allow(clippy::too_many_arguments)]
    pub fn authored(
        intent: QueuedEventIntent,
        envelope: AuthoredEvent,
        local_operation_id: String,
        transport_idempotency_key: String,
        canonical_body_bytes: Vec<u8>,
        supersedes_event_id: Option<EventId>,
        authoring_generation: AuthoringGeneration,
        post_accept: Option<QueuedPostAcceptAction>,
    ) -> Result<Self> {
        let intent_digest = intent.digest()?;
        let queued = Self {
            intent,
            intent_digest: intent_digest.clone(),
            local_operation_id,
            authoring_idempotency_key: transport_idempotency_key.clone(),
            authored_attempt: Some(QueuedAuthoredEventAttempt {
                intent_digest,
                envelope,
                transport_idempotency_key,
                canonical_body_bytes,
            }),
            supersedes_event_id,
            authoring_generation,
            post_accept,
            scheduled_dispatch: None,
        };
        queued.validate()?;
        Ok(queued)
    }

    /// A scheduled send: authored, signed and frozen long before dispatch.
    ///
    /// The intent is recovered from the envelope because there is no re-author
    /// path here — the whole point is that these exact bytes ship later.
    pub fn scheduled_authored(
        scheduled_send_id: ScheduledSendId,
        envelope: AuthoredEvent,
        authoring_generation: AuthoringGeneration,
    ) -> Result<Self> {
        if envelope.kind != EventKind::MessageCreate {
            return Err(Error::Protocol(
                "scheduled dispatch must contain ak.message.create".to_owned(),
            ));
        }
        if envelope.proofs.is_empty() {
            return Err(Error::Protocol(
                "scheduled dispatch Event must already be signed".to_owned(),
            ));
        }
        let event_id = envelope.event_id().clone();
        let message_id = MessageId::from_event_id(&event_id);
        let canonical_signed_event_bytes = arkret_canonical::canonical_json_bytes(&envelope)?;
        let intent = QueuedEventIntent::new(
            EventIntent::from_authored(envelope.event()),
            envelope.digest_suite(),
        );
        let intent_digest = intent.digest()?;
        let queued = Self {
            intent,
            intent_digest: intent_digest.clone(),
            local_operation_id: scheduled_send_id.to_string(),
            authoring_idempotency_key: event_id.to_string(),
            authored_attempt: Some(QueuedAuthoredEventAttempt {
                intent_digest,
                envelope,
                transport_idempotency_key: event_id.to_string(),
                canonical_body_bytes: canonical_signed_event_bytes.clone(),
            }),
            supersedes_event_id: None,
            authoring_generation,
            post_accept: None,
            scheduled_dispatch: Some(ScheduledSendDispatchRecord {
                scheduled_send_id,
                event_id,
                message_id,
                canonical_signed_event_bytes,
                submission_state: ScheduledSendSubmissionState::Ready,
            }),
        };
        queued.validate()?;
        Ok(queued)
    }

    pub fn mark_scheduled_submission_uncertain(&mut self) -> bool {
        let Some(dispatch) = self.scheduled_dispatch.as_mut() else {
            return false;
        };
        if dispatch.submission_state != ScheduledSendSubmissionState::Ready {
            return false;
        }
        dispatch.submission_state = ScheduledSendSubmissionState::SubmissionUncertain;
        true
    }

    pub fn validate(&self) -> Result<()> {
        if self.local_operation_id.trim().is_empty()
            || self.authoring_idempotency_key.trim().is_empty()
            || self
                .authoring_generation
                .authority_principal_id
                .as_str()
                .trim()
                .is_empty()
            || self.authoring_generation.generation_ref.trim().is_empty()
        {
            return Err(Error::Protocol(
                "queued SDK event identity and authoring generation must be non-empty".to_owned(),
            ));
        }
        if self.intent.digest()? != self.intent_digest {
            return Err(Error::Protocol(
                "queued SDK event intent_digest does not match intent".to_owned(),
            ));
        }
        if let Some(attempt) = self.authored_attempt.as_ref() {
            if attempt.intent_digest != self.intent_digest {
                return Err(Error::Protocol(
                    "queued SDK authored attempt is bound to a different intent".to_owned(),
                ));
            }
            if attempt.transport_idempotency_key.is_empty()
                || attempt.canonical_body_bytes.is_empty()
                || attempt.envelope.digest_suite() != self.intent.digest_suite
            {
                return Err(Error::Protocol(
                    "queued SDK authored attempt must carry immutable transport identity, bytes, and digest suite"
                        .to_owned(),
                ));
            }
            let canonical = arkret_canonical::canonical_json_bytes(&attempt.envelope)?;
            if canonical != attempt.canonical_body_bytes {
                return Err(Error::Protocol(
                    "queued SDK authored attempt canonical bytes do not match envelope".to_owned(),
                ));
            }
            if !self
                .intent
                .authored_envelope_matches(attempt.envelope.event())
            {
                return Err(Error::Protocol(
                    "queued SDK authored envelope changes the bound semantic intent".to_owned(),
                ));
            }
        }
        if let Some(dispatch) = self.scheduled_dispatch.as_ref() {
            let attempt = self.authored_attempt.as_ref().ok_or_else(|| {
                Error::Protocol(
                    "scheduled dispatch record requires a frozen authored attempt".to_owned(),
                )
            })?;
            if self.local_operation_id != dispatch.scheduled_send_id.as_str()
                || self.intent.kind() != &EventKind::MessageCreate
                || attempt.envelope.event_id() != &dispatch.event_id
                || MessageId::from_event_id(&dispatch.event_id) != dispatch.message_id
                || attempt.canonical_body_bytes != dispatch.canonical_signed_event_bytes
            {
                return Err(Error::Protocol(
                    "scheduled dispatch record does not match its immutable authored Event"
                        .to_owned(),
                ));
            }
        }
        if let Some(action) = self.post_accept.as_ref() {
            let (realm_id, snapshot) = match action {
                QueuedPostAcceptAction::MlsAdmission {
                    realm_id,
                    actor_id,
                    device_id,
                    proposal_events,
                    stage: _,
                    commit_ingress_receipts: _,
                    commit_was_duplicate: _,
                    welcomes,
                    snapshot,
                } => {
                    if actor_id.trim().is_empty() || device_id.trim().is_empty() {
                        return Err(Error::Protocol(
                            "queued MLS admission actor and device must be non-empty".to_owned(),
                        ));
                    }
                    if proposal_events.is_empty()
                        || proposal_events.iter().any(|event| {
                            event.kind != EventKind::MlsProposal
                                || event.realm_id.as_str() != realm_id
                                || event.proofs.is_empty()
                        })
                    {
                        return Err(Error::Protocol(
                            "queued MLS admission requires signed same-Realm Add proposal Events"
                                .to_owned(),
                        ));
                    }
                    let commit = self.authored_attempt.as_ref().ok_or_else(|| {
                        Error::Protocol(
                            "queued MLS admission requires its authored Commit".to_owned(),
                        )
                    })?;
                    let commit_proposal_refs = commit
                        .envelope
                        .payload
                        .get("proposal_refs")
                        .and_then(serde_json::Value::as_array)
                        .ok_or_else(|| {
                            Error::Protocol(
                                "queued MLS admission Commit has no proposal_refs".to_owned(),
                            )
                        })?
                        .iter()
                        .map(|value| {
                            value
                                .as_str()
                                .ok_or_else(|| {
                                    Error::Protocol(
                                        "queued MLS admission Commit proposal ref is not a string"
                                            .to_owned(),
                                    )
                                })
                                .and_then(|value| {
                                    EventId::new(value.to_owned())
                                        .map_err(|error| Error::Protocol(error.to_string()))
                                })
                        })
                        .collect::<Result<Vec<_>>>()?;
                    let proposal_refs = proposal_events
                        .iter()
                        .map(|event| event.event_id().clone())
                        .collect::<Vec<_>>();
                    if commit_proposal_refs != proposal_refs {
                        return Err(Error::Protocol(
                            "queued MLS admission Commit does not reference its exact proposal Events"
                                .to_owned(),
                        ));
                    }
                    if welcomes
                        .realm_ids()
                        .into_iter()
                        .any(|realm_id| realm_id != self.intent.realm_id_opt())
                    {
                        return Err(Error::Protocol(
                            "queued MLS admission Welcome belongs to another Realm".to_owned(),
                        ));
                    }
                    if welcomes.is_empty()
                        || welcomes.authored().iter().any(|event| {
                            event.kind != EventKind::MlsWelcome || event.proofs.is_empty()
                        })
                    {
                        return Err(Error::Protocol(
                            "queued MLS admission requires signed Welcome Events before Commit submission"
                                .to_owned(),
                        ));
                    }
                    (realm_id, snapshot)
                }
            };
            if Some(realm_id.as_str()) != self.intent.realm_id_opt().map(RealmId::as_str)
                || snapshot.realm_id != *realm_id
            {
                return Err(Error::Protocol(
                    "queued post-accept snapshot belongs to another Realm".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

/// A Realm genesis unit in the durable queue.
///
/// There is no unauthored state here. A genesis unit's members name each other
/// by their final `event_id` — every follow-up is scoped to the Realm the create
/// Event derives — so the unit can only be assembled in one pass, and what the
/// queue receives is already the exact bytes it will send. The old
/// intent-then-prepare split is what forced preparation to retype the Realm id
/// after the fact, and it is gone with the placeholder that made it necessary.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum QueuedRealmBootstrap {
    Prepared {
        local_operation_id: String,
        transport_idempotency_key: String,
        intent_digest: Hash,
        events: Vec<AuthoredEvent>,
        canonical_signed_unit_bytes: Vec<u8>,
    },
    /// A fully authored Direct Conversation first-valid unit. Unlike an
    /// ordinary Realm bootstrap, all four Events and both evidence carriers
    /// are already frozen before enqueue. `accepted_outcome_bytes` is persisted
    /// in a separate prepare pass, followed by a durable exact-covering-Seal
    /// bit, before the queue is marked sent. A crash after either boundary can
    /// resume without losing the unique slot receipt or treating ingress as
    /// finality.
    DirectConversationPrepared {
        local_operation_id: String,
        transport_idempotency_key: String,
        first_event: Box<Event>,
        canonical_signed_unit_bytes: Vec<u8>,
        #[serde(deserialize_with = "deserialize_required_nullable")]
        accepted_outcome_bytes: Option<Vec<u8>>,
        /// Set only after every Event in the exact four-Event unit resolves
        /// with its accepted covering Seal. Ingress acceptance alone never
        /// advances a Direct Conversation into MLS bootstrap.
        #[serde(default)]
        founding_finality_confirmed: bool,
    },
}

impl QueuedRealmBootstrap {
    pub fn prepared(
        local_operation_id: String,
        transport_idempotency_key: String,
        events: Vec<AuthoredEvent>,
    ) -> Result<Self> {
        let intent_digest = Hash::new(arkret_canonical::canonical_sha256(&events)?)?;
        let canonical_signed_unit_bytes = arkret_canonical::canonical_json_bytes(&events)?;
        let queued = Self::Prepared {
            local_operation_id,
            transport_idempotency_key,
            intent_digest,
            events,
            canonical_signed_unit_bytes,
        };
        queued.validate()?;
        Ok(queued)
    }

    pub fn direct_conversation_prepared(
        submission: DirectConversationFoundingUnitSubmission,
    ) -> Result<Self> {
        let local_operation_id = submission.idempotency_key.to_string();
        let canonical_signed_unit_bytes = arkret_canonical::canonical_json_bytes(&submission)?;
        let queued = Self::DirectConversationPrepared {
            transport_idempotency_key: local_operation_id.clone(),
            local_operation_id,
            first_event: Box::new(submission.events[0].event.clone()),
            canonical_signed_unit_bytes,
            accepted_outcome_bytes: None,
            founding_finality_confirmed: false,
        };
        queued.validate()?;
        Ok(queued)
    }

    pub fn authority_context_event(&self) -> Result<&Event> {
        match self {
            Self::Prepared { events, .. } => events
                .first()
                .map(AuthoredEvent::event)
                .ok_or_else(|| Error::Protocol("queued Realm bootstrap unit is empty".to_owned())),
            Self::DirectConversationPrepared { first_event, .. } => Ok(first_event),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if let Self::DirectConversationPrepared {
            local_operation_id,
            transport_idempotency_key,
            first_event,
            canonical_signed_unit_bytes,
            accepted_outcome_bytes,
            founding_finality_confirmed,
        } = self
        {
            let submission: DirectConversationFoundingUnitSubmission =
                serde_json::from_slice(canonical_signed_unit_bytes).map_err(|error| {
                    Error::Protocol(format!(
                        "decode queued Direct Conversation founding unit: {error}"
                    ))
                })?;
            if local_operation_id.trim().is_empty()
                || transport_idempotency_key != local_operation_id
                || submission.idempotency_key.as_str() != local_operation_id
                || &submission.events[0].event != first_event.as_ref()
            {
                return Err(Error::Protocol(
                    "queued Direct Conversation founding identity mismatch".to_owned(),
                ));
            }
            if arkret_canonical::canonical_json_bytes(&submission)? != *canonical_signed_unit_bytes
            {
                return Err(Error::Protocol(
                    "queued Direct Conversation founding canonical bytes mismatch".to_owned(),
                ));
            }
            let events = submission
                .events
                .iter()
                .map(|item| &item.event)
                .collect::<Vec<_>>();
            let exact: [&Event; 4] = events.try_into().map_err(|_| {
                Error::Protocol(
                    "queued Direct Conversation founding unit must contain four Events".to_owned(),
                )
            })?;
            let plan = DirectConversationFoundingPlan::from_events(exact)?;
            if submission
                .events
                .iter()
                .any(|item| item.event.proofs.is_empty())
            {
                return Err(Error::Protocol(
                    "queued Direct Conversation founding unit contains an unsigned Event"
                        .to_owned(),
                ));
            }
            if let Some(bytes) = accepted_outcome_bytes {
                let outcome: DirectConversationFoundingAcceptanceOutcome =
                    serde_json::from_slice(bytes).map_err(|error| {
                        Error::Protocol(format!(
                            "decode queued Direct Conversation founding outcome: {error}"
                        ))
                    })?;
                if arkret_canonical::canonical_json_bytes(&outcome)? != *bytes {
                    return Err(Error::Protocol(
                        "queued Direct Conversation founding outcome bytes are not canonical"
                            .to_owned(),
                    ));
                }
                outcome.receipt.validate_shape()?;
                if outcome.event_ids != plan.event_ids
                    || outcome.receipt.realm_id != plan.realm_id
                    || outcome.receipt.main_strand_id != plan.main_strand_id
                    || outcome.receipt.founding_unit_digest != plan.founding_unit_digest
                {
                    return Err(Error::Protocol(
                        "queued Direct Conversation founding receipt does not match frozen unit"
                            .to_owned(),
                    ));
                }
            }
            if *founding_finality_confirmed && accepted_outcome_bytes.is_none() {
                return Err(Error::Protocol(
                    "queued Direct Conversation founding finality lacks an acceptance receipt"
                        .to_owned(),
                ));
            }
            return Ok(());
        }

        let (
            local_operation_id,
            transport_idempotency_key,
            intent_digest,
            events,
            canonical_signed_unit_bytes,
        ) = match self {
            Self::Prepared {
                local_operation_id,
                transport_idempotency_key,
                intent_digest,
                events,
                canonical_signed_unit_bytes,
                ..
            } => (
                local_operation_id,
                transport_idempotency_key,
                intent_digest,
                events,
                canonical_signed_unit_bytes,
            ),
            Self::DirectConversationPrepared { .. } => {
                unreachable!("Direct Conversation validation returned above")
            }
        };
        if local_operation_id.trim().is_empty() || transport_idempotency_key.trim().is_empty() {
            return Err(Error::Protocol(
                "queued Realm bootstrap identities must be non-empty".to_owned(),
            ));
        }
        let envelopes = events
            .iter()
            .map(AuthoredEvent::event)
            .cloned()
            .collect::<Vec<_>>();
        validate_realm_bootstrap_intent(&envelopes)?;
        let computed = Hash::new(arkret_canonical::canonical_sha256(events)?)?;
        if &computed != intent_digest {
            return Err(Error::Protocol(
                "queued Realm bootstrap unit digest mismatch".to_owned(),
            ));
        }
        if events.iter().any(|event| event.proofs.is_empty()) {
            return Err(Error::Protocol(
                "prepared Realm bootstrap contains an unsigned Event".to_owned(),
            ));
        }
        if arkret_canonical::canonical_json_bytes(events)? != *canonical_signed_unit_bytes {
            return Err(Error::Protocol(
                "prepared Realm bootstrap canonical bytes mismatch".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn direct_conversation_submission(
        &self,
    ) -> Result<Option<DirectConversationFoundingUnitSubmission>> {
        let Self::DirectConversationPrepared {
            canonical_signed_unit_bytes,
            ..
        } = self
        else {
            return Ok(None);
        };
        let submission = serde_json::from_slice(canonical_signed_unit_bytes).map_err(|error| {
            Error::Protocol(format!(
                "decode queued Direct Conversation founding unit: {error}"
            ))
        })?;
        Ok(Some(submission))
    }

    pub fn direct_conversation_accepted_outcome(
        &self,
    ) -> Result<Option<DirectConversationFoundingAcceptanceOutcome>> {
        let Self::DirectConversationPrepared {
            accepted_outcome_bytes,
            ..
        } = self
        else {
            return Ok(None);
        };
        accepted_outcome_bytes
            .as_deref()
            .map(|bytes| {
                serde_json::from_slice(bytes).map_err(|error| {
                    Error::Protocol(format!(
                        "decode queued Direct Conversation founding outcome: {error}"
                    ))
                })
            })
            .transpose()
    }

    pub fn with_direct_conversation_accepted_outcome(
        mut self,
        outcome: DirectConversationFoundingAcceptanceOutcome,
    ) -> Result<Self> {
        let Self::DirectConversationPrepared {
            accepted_outcome_bytes,
            ..
        } = &mut self
        else {
            return Err(Error::Protocol(
                "cannot attach a Direct Conversation outcome to an ordinary Realm bootstrap"
                    .to_owned(),
            ));
        };
        *accepted_outcome_bytes = Some(arkret_canonical::canonical_json_bytes(&outcome)?);
        self.validate()?;
        Ok(self)
    }

    pub fn direct_conversation_founding_finality_confirmed(&self) -> Result<Option<bool>> {
        let Self::DirectConversationPrepared {
            founding_finality_confirmed,
            ..
        } = self
        else {
            return Ok(None);
        };
        Ok(Some(*founding_finality_confirmed))
    }

    pub fn with_direct_conversation_founding_finality_confirmed(mut self) -> Result<Self> {
        let Self::DirectConversationPrepared {
            accepted_outcome_bytes,
            founding_finality_confirmed,
            ..
        } = &mut self
        else {
            return Err(Error::Protocol(
                "cannot attach Direct Conversation finality to an ordinary Realm bootstrap"
                    .to_owned(),
            ));
        };
        if accepted_outcome_bytes.is_none() {
            return Err(Error::Protocol(
                "cannot confirm Direct Conversation finality before acceptance".to_owned(),
            ));
        }
        *founding_finality_confirmed = true;
        self.validate()?;
        Ok(self)
    }
}

fn validate_realm_bootstrap_intent(events: &[Event]) -> Result<()> {
    let create = events
        .first()
        .ok_or_else(|| Error::Protocol("queued Realm bootstrap unit is empty".to_owned()))?;
    if create.kind != EventKind::RealmCreate {
        return Err(Error::Protocol(
            "queued Realm bootstrap must begin with ak.realm.create".to_owned(),
        ));
    }
    let payload: RealmCreatePayload =
        serde_json::from_value(serde_json::to_value(&create.payload)?)
            .map_err(|error| Error::Protocol(format!("decode Realm genesis: {error}")))?;
    payload
        .object
        .validate()
        .map_err(|error| Error::Protocol(error.to_string()))?;
    arkret_policy::realm_bootstrap::validate_realm_bootstrap_unit(events)
        .map(|_| ())
        .map_err(|error| Error::Protocol(error.reason_code().to_owned()))
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "record_type",
    content = "record",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum QueuedRecord {
    SdkEvent(Box<QueuedSdkEvent>),
    RealmBootstrap(Box<QueuedRealmBootstrap>),
}

impl QueuedRecord {
    pub fn event_kind(&self) -> Result<&EventKind> {
        match self {
            Self::SdkEvent(queued) => Ok(queued.intent.kind()),
            Self::RealmBootstrap(queued) => Ok(&queued.authority_context_event()?.kind),
        }
    }

    /// The Realm this record writes into.
    ///
    /// A Realm genesis has none: its Realm id is a function of the create Event
    /// id, so the answer only exists after authoring. Genesis units travel as
    /// [`QueuedRealmBootstrap`], whose events are already authored, so the
    /// missing case is a queued `ak.realm.create` in the ordinary lane, which is
    /// a caller error rather than a Realm to report.
    pub fn realm_id(&self) -> Result<&RealmId> {
        match self {
            Self::SdkEvent(queued) => queued.intent.realm_id_opt().ok_or_else(|| {
                Error::Protocol(
                    "queued SDK event is a Realm genesis and has no Realm scope yet".to_owned(),
                )
            }),
            Self::RealmBootstrap(queued) => Ok(&queued.authority_context_event()?.realm_id),
        }
    }

    pub fn actor_id(&self) -> Result<&ActorId> {
        match self {
            Self::SdkEvent(queued) => Ok(queued.intent.actor_id()),
            Self::RealmBootstrap(queued) => Ok(&queued.authority_context_event()?.actor_id),
        }
    }

    pub fn validate(&self) -> Result<()> {
        match self {
            Self::SdkEvent(queued) => queued.validate(),
            Self::RealmBootstrap(queued) => queued.validate(),
        }
    }
}
