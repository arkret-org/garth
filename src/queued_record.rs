use std::ops::Deref;

use arkret_identifiers::ScheduledSendId;
use arkret_models_collaboration::direct_conversation_ops::{
    DirectConversationFoundingAcceptanceOutcome, DirectConversationFoundingPlan,
    DirectConversationFoundingUnitSubmission,
};
use arkret_models_collaboration::events_payloads::RealmCreatePayload;
use arkret_wire::{DidCoreId, Event, EventId, EventKind, Hash, MessageId, RealmId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{Error, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthoringAuthorityModel {
    AcceptedDevice,
    ManagedAgent,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthoringGeneration {
    pub authority_model: AuthoringAuthorityModel,
    pub authority_principal_id: String,
    pub generation_ref: String,
}

impl AuthoringGeneration {
    pub fn managed_agent(
        controller: &str,
        controller_generation: &Self,
        authorization_ref: &str,
    ) -> Result<Self> {
        let authorization_ref = authorization_ref.trim();
        if authorization_ref.is_empty() {
            return Err(Error::Protocol(
                "managed Agent authoring requires authorization_ref".to_owned(),
            ));
        }
        let generation_ref = arkret_canonical::canonical_sha256(&serde_json::json!({
            "controller_authority_model": controller_generation.authority_model,
            "controller_generation_ref": controller_generation.generation_ref,
            "authorization_ref": authorization_ref,
        }))?;
        Ok(Self {
            authority_model: AuthoringAuthorityModel::ManagedAgent,
            authority_principal_id: controller.to_owned(),
            generation_ref,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueuedEventIntent {
    /// SDK-owned wire envelope normalized to its semantic, unauthored form.
    ///
    /// Keeping the envelope intact prevents the queue from defining a second
    /// `kind` + raw payload representation. Authoring-only fields are cleared
    /// by [`Self::from_event`] and are allocated again for each attempt.
    pub event: Event,
}

impl QueuedEventIntent {
    pub fn from_event(event: Event) -> Self {
        let mut event = event;
        event.actor_seq = 0;
        event.hlc = None;
        event.prev_refs.clear();
        event.seal_ref = None;
        event.auth_context = None;
        event.proofs.clear();
        event.unsigned.remove("local_operation_idempotency_alias");
        if event.kind != EventKind::InviteAccept {
            event.seal_basis = None;
        }
        Self { event }
    }

    pub fn to_unauthored_event(&self) -> Event {
        self.event.clone()
    }

    pub fn digest(&self) -> Result<Hash> {
        Ok(Hash::new(arkret_canonical::canonical_sha256(self)?)?)
    }
}

impl Deref for QueuedEventIntent {
    type Target = Event;

    fn deref(&self) -> &Self::Target {
        &self.event
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueuedAuthoredEventAttempt {
    pub intent_digest: Hash,
    pub envelope: Event,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
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

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum QueuedPostAcceptAction {
    MlsSnapshot {
        realm_id: String,
        snapshot: QueuedMlsSnapshot,
    },
    MlsAdmission {
        realm_id: String,
        actor_id: String,
        device_id: String,
        /// Durable protocol phase. Ingress acceptance is not finality: both
        /// the Commit and the Welcome batch wait for a covering accepted Seal
        /// before the next phase is allowed to run.
        stage: MlsAdmissionStage,
        #[serde(default)]
        commit_ingress_receipts: Vec<arkret_wire::IngressReceipt>,
        #[serde(default)]
        commit_was_duplicate: bool,
        welcomes: Vec<Event>,
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
        event: Event,
        local_operation_id: String,
        authoring_idempotency_key: String,
        supersedes_event_id: Option<EventId>,
        authoring_generation: AuthoringGeneration,
        post_accept: Option<QueuedPostAcceptAction>,
    ) -> Result<Self> {
        let intent = QueuedEventIntent::from_event(event);
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

    pub fn authored(
        envelope: Event,
        local_operation_id: String,
        transport_idempotency_key: String,
        canonical_body_bytes: Vec<u8>,
        supersedes_event_id: Option<EventId>,
        authoring_generation: AuthoringGeneration,
        post_accept: Option<QueuedPostAcceptAction>,
    ) -> Result<Self> {
        let intent = QueuedEventIntent::from_event(envelope.clone());
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

    pub fn scheduled_authored(
        scheduled_send_id: ScheduledSendId,
        envelope: Event,
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
        let derived_event_id = envelope.derive_event_id()?;
        if derived_event_id != envelope.event_id {
            return Err(Error::Protocol(
                "scheduled dispatch Event id does not match its canonical content".to_owned(),
            ));
        }
        let event_id = envelope.event_id.clone();
        let message_id = MessageId::from_event_id(&event_id);
        let canonical_signed_event_bytes = arkret_canonical::canonical_json_bytes(&envelope)?;
        let intent = QueuedEventIntent::from_event(envelope.clone());
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

    pub fn event_for_authority_context(&self) -> Event {
        self.authored_attempt
            .as_ref()
            .map(|attempt| attempt.envelope.clone())
            .unwrap_or_else(|| self.intent.to_unauthored_event())
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
            {
                return Err(Error::Protocol(
                    "queued SDK authored attempt must carry immutable transport identity and bytes"
                        .to_owned(),
                ));
            }
            let canonical = arkret_canonical::canonical_json_bytes(&attempt.envelope)?;
            if canonical != attempt.canonical_body_bytes {
                return Err(Error::Protocol(
                    "queued SDK authored attempt canonical bytes do not match envelope".to_owned(),
                ));
            }
            if QueuedEventIntent::from_event(attempt.envelope.clone()) != self.intent {
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
                || self.intent.kind != EventKind::MessageCreate
                || self.intent.event_id != dispatch.event_id
                || attempt.envelope.event_id != dispatch.event_id
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
                QueuedPostAcceptAction::MlsSnapshot { realm_id, snapshot } => (realm_id, snapshot),
                QueuedPostAcceptAction::MlsAdmission {
                    realm_id,
                    actor_id,
                    device_id,
                    stage,
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
                    if welcomes
                        .iter()
                        .any(|welcome| welcome.realm_id != self.intent.realm_id)
                    {
                        return Err(Error::Protocol(
                            "queued MLS admission Welcome belongs to another Realm".to_owned(),
                        ));
                    }
                    let welcomes_authored = matches!(
                        stage,
                        MlsAdmissionStage::WelcomesAuthored
                            | MlsAdmissionStage::WelcomesAcceptedWaitingSeal
                    );
                    if welcomes.iter().any(|welcome| {
                        if welcomes_authored {
                            welcome.proofs.is_empty()
                                || welcome.derive_event_id().ok().as_ref()
                                    != Some(&welcome.event_id)
                        } else {
                            !welcome.proofs.is_empty()
                        }
                    }) {
                        return Err(Error::Protocol(
                            "queued MLS admission Welcome authoring phase is inconsistent"
                                .to_owned(),
                        ));
                    }
                    (realm_id, snapshot)
                }
            };
            if realm_id != self.intent.realm_id.as_str() || snapshot.realm_id != *realm_id {
                return Err(Error::Protocol(
                    "queued post-accept snapshot belongs to another Realm".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum QueuedRealmBootstrap {
    Intent {
        local_operation_id: String,
        transport_idempotency_key: String,
        intent_digest: Hash,
        events: Vec<Event>,
    },
    Prepared {
        local_operation_id: String,
        transport_idempotency_key: String,
        intent_digest: Hash,
        events: Vec<Event>,
        canonical_signed_unit_bytes: Vec<u8>,
    },
    /// A fully authored Direct Conversation first-valid unit. Unlike an
    /// ordinary Realm bootstrap, all three Events and both evidence carriers
    /// are already frozen before enqueue. `accepted_outcome_bytes` is persisted
    /// in a separate prepare pass, followed by a durable exact-covering-Seal
    /// bit, before the queue is marked sent. A crash after either boundary can
    /// resume without losing the unique slot receipt or treating ingress as
    /// finality.
    DirectConversationPrepared {
        local_operation_id: String,
        transport_idempotency_key: String,
        first_event: Event,
        canonical_signed_unit_bytes: Vec<u8>,
        #[serde(deserialize_with = "deserialize_required_nullable")]
        accepted_outcome_bytes: Option<Vec<u8>>,
        /// Set only after every Event in the exact three-Event unit resolves
        /// with its accepted covering Seal. Ingress acceptance alone never
        /// advances a Direct Conversation into MLS bootstrap.
        #[serde(default)]
        founding_finality_confirmed: bool,
    },
}

impl QueuedRealmBootstrap {
    pub fn intent(
        local_operation_id: String,
        transport_idempotency_key: String,
        events: Vec<Event>,
    ) -> Result<Self> {
        validate_realm_bootstrap_intent(&events)?;
        let intent_digest = Hash::new(arkret_canonical::canonical_sha256(&events)?)?;
        let queued = Self::Intent {
            local_operation_id,
            transport_idempotency_key,
            intent_digest,
            events,
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
            first_event: submission.events[0].event.clone(),
            canonical_signed_unit_bytes,
            accepted_outcome_bytes: None,
            founding_finality_confirmed: false,
        };
        queued.validate()?;
        Ok(queued)
    }

    pub fn authority_context_event(&self) -> Result<&Event> {
        let events = match self {
            Self::Intent { events, .. } | Self::Prepared { events, .. } => events,
            Self::DirectConversationPrepared { first_event, .. } => {
                return Ok(first_event);
            }
        };
        events
            .first()
            .ok_or_else(|| Error::Protocol("queued Realm bootstrap unit is empty".to_owned()))
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
                || &submission.events[0].event != first_event
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
            let exact: [&Event; 3] = events.try_into().map_err(|_| {
                Error::Protocol(
                    "queued Direct Conversation founding unit must contain three Events".to_owned(),
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
            Self::Intent {
                local_operation_id,
                transport_idempotency_key,
                intent_digest,
                events,
                ..
            } => (
                local_operation_id,
                transport_idempotency_key,
                intent_digest,
                events,
                None,
            ),
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
                Some(canonical_signed_unit_bytes),
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
        validate_realm_bootstrap_intent(events)?;
        match canonical_signed_unit_bytes {
            None => {
                let computed = Hash::new(arkret_canonical::canonical_sha256(events)?)?;
                if &computed != intent_digest {
                    return Err(Error::Protocol(
                        "queued Realm bootstrap intent digest mismatch".to_owned(),
                    ));
                }
            }
            Some(canonical_signed_unit_bytes) => {
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
            }
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
    SdkEvent(QueuedSdkEvent),
    RealmBootstrap(QueuedRealmBootstrap),
}

impl QueuedRecord {
    pub fn event_kind(&self) -> Result<&EventKind> {
        match self {
            Self::SdkEvent(queued) => Ok(&queued.intent.kind),
            Self::RealmBootstrap(queued) => Ok(&queued.authority_context_event()?.kind),
        }
    }

    pub fn realm_id(&self) -> Result<&RealmId> {
        match self {
            Self::SdkEvent(queued) => Ok(&queued.intent.realm_id),
            Self::RealmBootstrap(queued) => Ok(&queued.authority_context_event()?.realm_id),
        }
    }

    pub fn actor_id(&self) -> Result<&DidCoreId> {
        match self {
            Self::SdkEvent(queued) => Ok(&queued.intent.actor_id),
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
