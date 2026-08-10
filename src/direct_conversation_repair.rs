//! Crash-safe client planning for Direct Conversation replacement repair.
//!
//! The protocol request and enqueue outcome remain SDK-owned DTOs. This module
//! only adds the local durable lifecycle needed to freeze an exact signed
//! dispatch and to keep transport enqueue distinct from business completion.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};

use crate::protocol::{
    DidCoreId, DirectConversationCoordinates, DirectConversationRepairDispatchRequest,
    DirectConversationRepairEnqueueOutcome, EventId, Hash, MemberRepairRequestPayload,
    NonEmptyString,
};
use crate::{Error, Result};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectConversationRepairRoute {
    pub source_service_id: DidCoreId,
    pub target_service_id: DidCoreId,
    pub coordinates: DirectConversationCoordinates,
    pub target_keypackage_ref: NonEmptyString,
}

impl DirectConversationRepairRoute {
    fn validate(&self) -> Result<()> {
        if self.coordinates.binding_event_ref.is_none() {
            return Err(Error::Protocol(
                "Direct Conversation repair requires accepted binding coordinates".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Local evidence that the exact self-rejoin Event used by the repair trigger
/// was accepted. It is a planner gate, not a new protocol carrier.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelfRejoinAcceptance {
    pub realm_id: crate::protocol::RealmId,
    pub requester_principal_id: DidCoreId,
    pub rejoin_event_id: EventId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub accepted_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FrozenDirectConversationRepairDispatch {
    pub request: DirectConversationRepairDispatchRequest,
    pub request_digest: Hash,
    /// Digest over the exact SDK request plus the local source/target route,
    /// coordinates and target KeyPackage reference that are not all repeated
    /// on the wire request.
    pub frozen_context_digest: Hash,
    pub canonical_request_bytes: Vec<u8>,
}

impl<'de> Deserialize<'de> for FrozenDirectConversationRepairDispatch {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            request: serde_json::Value,
            request_digest: Hash,
            frozen_context_digest: Hash,
            canonical_request_bytes: Vec<u8>,
        }

        let wire = Wire::deserialize(deserializer)?;
        Ok(Self {
            request: deserialize_dispatch_request(wire.request).map_err(D::Error::custom)?,
            request_digest: wire.request_digest,
            frozen_context_digest: wire.frozen_context_digest,
            canonical_request_bytes: wire.canonical_request_bytes,
        })
    }
}

fn deserialize_dispatch_request(
    value: serde_json::Value,
) -> std::result::Result<DirectConversationRepairDispatchRequest, serde_json::Error> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Wire {
        request_id: crate::protocol::Base64UrlString,
        content: serde_json::Value,
        requester_authorization:
            arkret_models_collaboration::direct_conversation_repair::DirectConversationRepairAuthorization,
    }

    let wire: Wire = serde_json::from_value(value)?;
    Ok(DirectConversationRepairDispatchRequest {
        request_id: wire.request_id,
        content: deserialize_member_repair_payload(wire.content)?,
        requester_authorization: wire.requester_authorization,
    })
}

fn deserialize_member_repair_payload(
    value: serde_json::Value,
) -> std::result::Result<MemberRepairRequestPayload, serde_json::Error> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Wire {
        realm_id: crate::protocol::RealmId,
        requester_principal_id: DidCoreId,
        #[serde(default)]
        requester_device_id: Option<crate::protocol::DeviceId>,
        #[serde(default)]
        requester_agent_id: Option<DidCoreId>,
        #[serde(default)]
        requester_agent_verification_method: Option<crate::protocol::DidUrl>,
        #[serde(default)]
        agent_key_authorize_event_id: Option<EventId>,
        requester_keypackage_ref: NonEmptyString,
        observed_active_generation_value_digest: Hash,
        rejoin_event_id: EventId,
        #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
        created_at: DateTime<Utc>,
    }

    let wire: Wire = serde_json::from_value(value)?;
    let requester = match (
        wire.requester_device_id,
        wire.requester_agent_id,
        wire.requester_agent_verification_method,
        wire.agent_key_authorize_event_id,
    ) {
        (Some(requester_device_id), None, None, None) => {
            arkret_models_collaboration::events_payloads::MemberRepairRequester::Device {
                requester_device_id,
            }
        }
        (
            None,
            Some(requester_agent_id),
            Some(requester_agent_verification_method),
            Some(agent_key_authorize_event_id),
        ) => arkret_models_collaboration::events_payloads::MemberRepairRequester::NativeAgent {
            requester_agent_id,
            requester_agent_verification_method,
            agent_key_authorize_event_id,
        },
        _ => {
            return Err(<serde_json::Error as serde::de::Error>::custom(
                "repair requester identity must select exactly one closed branch",
            ));
        }
    };
    Ok(MemberRepairRequestPayload {
        realm_id: wire.realm_id,
        requester_principal_id: wire.requester_principal_id,
        requester,
        requester_keypackage_ref: wire.requester_keypackage_ref,
        observed_active_generation_value_digest: wire.observed_active_generation_value_digest,
        rejoin_event_id: wire.rejoin_event_id,
        created_at: wire.created_at,
    })
}

fn deserialize_optional_member_repair_payload<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<MemberRepairRequestPayload>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<serde_json::Value>::deserialize(deserializer)?
        .map(deserialize_member_repair_payload)
        .transpose()
        .map_err(D::Error::custom)
}

impl FrozenDirectConversationRepairDispatch {
    fn freeze(
        request: DirectConversationRepairDispatchRequest,
        route: &DirectConversationRepairRoute,
    ) -> Result<Self> {
        request.validate_shape()?;
        let canonical_request_bytes = arkret_canonical::canonical_json_bytes(&request)?;
        let request_digest = Hash::new(arkret_canonical::canonical_sha256(&request)?)?;
        let frozen_context_digest = frozen_context_digest(route, &request)?;
        Ok(Self {
            request,
            request_digest,
            frozen_context_digest,
            canonical_request_bytes,
        })
    }

    fn validate(&self, route: &DirectConversationRepairRoute) -> Result<()> {
        self.request.validate_shape()?;
        if arkret_canonical::canonical_json_bytes(&self.request)? != self.canonical_request_bytes {
            return Err(Error::Protocol(
                "frozen repair request canonical bytes changed".to_owned(),
            ));
        }
        if Hash::new(arkret_canonical::canonical_sha256(&self.request)?)? != self.request_digest {
            return Err(Error::Protocol(
                "frozen repair request digest changed".to_owned(),
            ));
        }
        if frozen_context_digest(route, &self.request)? != self.frozen_context_digest {
            return Err(Error::Protocol(
                "frozen repair route or request context changed".to_owned(),
            ));
        }
        Ok(())
    }
}

fn frozen_context_digest(
    route: &DirectConversationRepairRoute,
    request: &DirectConversationRepairDispatchRequest,
) -> Result<Hash> {
    Ok(Hash::new(arkret_canonical::canonical_sha256(
        &serde_json::json!({
            "route": route,
            "request": request,
        }),
    )?)?)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectConversationRepairStage {
    AwaitingSelfRejoinAcceptance,
    SelfRejoinAccepted,
    DispatchFrozen,
    DispatchRetryable,
    EnqueueOutcomePendingDurability,
    Enqueued,
    WelcomeDurable,
    Activated,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DirectConversationRepairAction {
    AwaitSelfRejoinAcceptance,
    SignExactRequest,
    SubmitExactRequest,
    PersistEnqueueOutcome,
    AuthorWelcome,
    ActivateReplacementGeneration,
    Complete,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectConversationRepairSnapshot {
    pub route: DirectConversationRepairRoute,
    pub stage: DirectConversationRepairStage,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub self_rejoin_acceptance: Option<SelfRejoinAcceptance>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "deserialize_optional_member_repair_payload")]
    pub expected_content: Option<MemberRepairRequestPayload>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frozen_dispatch: Option<FrozenDirectConversationRepairDispatch>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enqueue_outcome: Option<DirectConversationRepairEnqueueOutcome>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_dispatch_error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub welcome_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activation_event_id: Option<EventId>,
}

impl DirectConversationRepairSnapshot {
    fn validate(&self) -> Result<()> {
        self.route.validate()?;
        let accepted = self.self_rejoin_acceptance.as_ref();
        let content = self.expected_content.as_ref();
        if accepted.is_some() != content.is_some() {
            return Err(Error::Protocol(
                "repair self-rejoin acceptance and expected content must be stored together"
                    .to_owned(),
            ));
        }
        if let (Some(accepted), Some(content)) = (accepted, content) {
            content.validate()?;
            if content.realm_id != self.route.coordinates.realm_id
                || content.realm_id != accepted.realm_id
                || content.requester_principal_id != accepted.requester_principal_id
                || content.rejoin_event_id != accepted.rejoin_event_id
                || accepted.accepted_at < content.created_at
                || content.requester_keypackage_ref.as_str()
                    != self.route.target_keypackage_ref.as_str()
            {
                return Err(Error::Protocol(
                    "repair content differs from accepted self-rejoin or frozen route".to_owned(),
                ));
            }
        }
        if let Some(dispatch) = self.frozen_dispatch.as_ref() {
            dispatch.validate(&self.route)?;
            if Some(&dispatch.request.content) != content {
                return Err(Error::Protocol(
                    "frozen repair request differs from accepted repair content".to_owned(),
                ));
            }
        }
        if let Some(outcome) = self.enqueue_outcome.as_ref() {
            outcome.validate_shape()?;
            let dispatch = self.frozen_dispatch.as_ref().ok_or_else(|| {
                Error::Protocol("repair enqueue outcome has no frozen request".to_owned())
            })?;
            if outcome.request_id != dispatch.request.request_id
                || outcome.request_digest != dispatch.request_digest
                || outcome.destination_service_id != self.route.target_service_id
            {
                return Err(Error::Protocol(
                    "repair enqueue outcome differs from frozen dispatch identity".to_owned(),
                ));
            }
        }

        let shape_valid = match self.stage {
            DirectConversationRepairStage::AwaitingSelfRejoinAcceptance => {
                accepted.is_none()
                    && self.frozen_dispatch.is_none()
                    && self.enqueue_outcome.is_none()
                    && self.last_dispatch_error.is_none()
                    && self.welcome_digest.is_none()
                    && self.activation_event_id.is_none()
            }
            DirectConversationRepairStage::SelfRejoinAccepted => {
                accepted.is_some()
                    && self.frozen_dispatch.is_none()
                    && self.enqueue_outcome.is_none()
                    && self.last_dispatch_error.is_none()
                    && self.welcome_digest.is_none()
                    && self.activation_event_id.is_none()
            }
            DirectConversationRepairStage::DispatchFrozen => {
                self.frozen_dispatch.is_some()
                    && self.enqueue_outcome.is_none()
                    && self.last_dispatch_error.is_none()
                    && self.welcome_digest.is_none()
                    && self.activation_event_id.is_none()
            }
            DirectConversationRepairStage::DispatchRetryable => {
                self.frozen_dispatch.is_some()
                    && self.enqueue_outcome.is_none()
                    && self
                        .last_dispatch_error
                        .as_ref()
                        .is_some_and(|error| !error.trim().is_empty())
                    && self.welcome_digest.is_none()
                    && self.activation_event_id.is_none()
            }
            DirectConversationRepairStage::EnqueueOutcomePendingDurability
            | DirectConversationRepairStage::Enqueued => {
                self.frozen_dispatch.is_some()
                    && self.enqueue_outcome.is_some()
                    && self.last_dispatch_error.is_none()
                    && self.welcome_digest.is_none()
                    && self.activation_event_id.is_none()
            }
            DirectConversationRepairStage::WelcomeDurable => {
                self.enqueue_outcome.is_some()
                    && self.last_dispatch_error.is_none()
                    && self.welcome_digest.is_some()
                    && self.activation_event_id.is_none()
            }
            DirectConversationRepairStage::Activated => {
                self.enqueue_outcome.is_some()
                    && self.last_dispatch_error.is_none()
                    && self.welcome_digest.is_some()
                    && self.activation_event_id.is_some()
            }
        };
        if !shape_valid {
            return Err(Error::Protocol(
                "repair durable stage does not match its retained evidence".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct DirectConversationRepairPlanner {
    state: DirectConversationRepairSnapshot,
}

impl DirectConversationRepairPlanner {
    pub fn new(route: DirectConversationRepairRoute) -> Result<Self> {
        route.validate()?;
        Ok(Self {
            state: DirectConversationRepairSnapshot {
                route,
                stage: DirectConversationRepairStage::AwaitingSelfRejoinAcceptance,
                self_rejoin_acceptance: None,
                expected_content: None,
                frozen_dispatch: None,
                enqueue_outcome: None,
                last_dispatch_error: None,
                welcome_digest: None,
                activation_event_id: None,
            },
        })
    }

    /// Restore state that was read from durable storage. A pending enqueue
    /// outcome becomes usable here because the snapshot itself proves that the
    /// outcome crossed the persistence boundary before the crash.
    pub fn restore_durable(mut snapshot: DirectConversationRepairSnapshot) -> Result<Self> {
        snapshot.validate()?;
        if snapshot.stage == DirectConversationRepairStage::EnqueueOutcomePendingDurability {
            snapshot.stage = DirectConversationRepairStage::Enqueued;
        }
        snapshot.validate()?;
        Ok(Self { state: snapshot })
    }

    #[must_use]
    pub fn snapshot(&self) -> DirectConversationRepairSnapshot {
        self.state.clone()
    }

    #[must_use]
    pub const fn stage(&self) -> DirectConversationRepairStage {
        self.state.stage
    }

    #[must_use]
    pub fn next_action(&self) -> DirectConversationRepairAction {
        match self.state.stage {
            DirectConversationRepairStage::AwaitingSelfRejoinAcceptance => {
                DirectConversationRepairAction::AwaitSelfRejoinAcceptance
            }
            DirectConversationRepairStage::SelfRejoinAccepted => {
                DirectConversationRepairAction::SignExactRequest
            }
            DirectConversationRepairStage::DispatchFrozen
            | DirectConversationRepairStage::DispatchRetryable => {
                DirectConversationRepairAction::SubmitExactRequest
            }
            DirectConversationRepairStage::EnqueueOutcomePendingDurability => {
                DirectConversationRepairAction::PersistEnqueueOutcome
            }
            DirectConversationRepairStage::Enqueued => {
                DirectConversationRepairAction::AuthorWelcome
            }
            DirectConversationRepairStage::WelcomeDurable => {
                DirectConversationRepairAction::ActivateReplacementGeneration
            }
            DirectConversationRepairStage::Activated => DirectConversationRepairAction::Complete,
        }
    }

    #[must_use]
    pub const fn is_business_complete(&self) -> bool {
        matches!(self.state.stage, DirectConversationRepairStage::Activated)
    }

    pub fn observe_self_rejoin_accepted(
        &mut self,
        acceptance: SelfRejoinAcceptance,
        content: MemberRepairRequestPayload,
    ) -> Result<()> {
        if self.state.stage != DirectConversationRepairStage::AwaitingSelfRejoinAcceptance {
            return if self.state.self_rejoin_acceptance.as_ref() == Some(&acceptance)
                && self.state.expected_content.as_ref() == Some(&content)
            {
                Ok(())
            } else {
                Err(Error::IdempotencyConflict(
                    acceptance.rejoin_event_id.to_string(),
                ))
            };
        }
        let mut candidate = self.state.clone();
        candidate.self_rejoin_acceptance = Some(acceptance);
        candidate.expected_content = Some(content);
        candidate.stage = DirectConversationRepairStage::SelfRejoinAccepted;
        candidate.validate()?;
        self.state = candidate;
        Ok(())
    }

    pub fn freeze_signed_request(
        &mut self,
        request: DirectConversationRepairDispatchRequest,
    ) -> Result<&FrozenDirectConversationRepairDispatch> {
        if self.state.frozen_dispatch.is_some() {
            let candidate = arkret_canonical::canonical_json_bytes(&request)?;
            if candidate
                == self
                    .state
                    .frozen_dispatch
                    .as_ref()
                    .expect("checked above")
                    .canonical_request_bytes
            {
                return Ok(self.state.frozen_dispatch.as_ref().expect("checked above"));
            }
            return Err(Error::IdempotencyConflict(request.request_id.to_string()));
        }
        if self.state.stage != DirectConversationRepairStage::SelfRejoinAccepted {
            return Err(Error::Protocol(
                "repair request cannot be signed before self-rejoin acceptance".to_owned(),
            ));
        }
        let frozen = FrozenDirectConversationRepairDispatch::freeze(request, &self.state.route)?;
        if self.state.expected_content.as_ref() != Some(&frozen.request.content) {
            return Err(Error::Protocol(
                "signed repair request changes accepted repair content".to_owned(),
            ));
        }
        self.state.frozen_dispatch = Some(frozen);
        self.state.stage = DirectConversationRepairStage::DispatchFrozen;
        self.state.validate()?;
        Ok(self.state.frozen_dispatch.as_ref().expect("frozen above"))
    }

    pub fn exact_retry_bytes(
        &self,
        request: &DirectConversationRepairDispatchRequest,
    ) -> Result<&[u8]> {
        let frozen = self
            .state
            .frozen_dispatch
            .as_ref()
            .ok_or_else(|| Error::Protocol("repair dispatch has not been frozen".to_owned()))?;
        if arkret_canonical::canonical_json_bytes(request)? != frozen.canonical_request_bytes {
            return Err(Error::IdempotencyConflict(request.request_id.to_string()));
        }
        Ok(&frozen.canonical_request_bytes)
    }

    pub fn record_dispatch_failure(&mut self, error: impl Into<String>) -> Result<()> {
        if !matches!(
            self.state.stage,
            DirectConversationRepairStage::DispatchFrozen
                | DirectConversationRepairStage::DispatchRetryable
        ) {
            return Err(Error::Protocol(
                "repair dispatch failure recorded in the wrong stage".to_owned(),
            ));
        }
        let error = error.into();
        if error.trim().is_empty() {
            return Err(Error::Protocol(
                "repair dispatch failure must not be blank".to_owned(),
            ));
        }
        self.state.last_dispatch_error = Some(error);
        self.state.stage = DirectConversationRepairStage::DispatchRetryable;
        self.state.validate()
    }

    pub fn record_enqueue_outcome(
        &mut self,
        outcome: DirectConversationRepairEnqueueOutcome,
    ) -> Result<()> {
        if let Some(existing) = self.state.enqueue_outcome.as_ref() {
            return if existing == &outcome {
                Ok(())
            } else {
                Err(Error::IdempotencyConflict(outcome.request_id.to_string()))
            };
        }
        if !matches!(
            self.state.stage,
            DirectConversationRepairStage::DispatchFrozen
                | DirectConversationRepairStage::DispatchRetryable
        ) {
            return Err(Error::Protocol(
                "repair enqueue outcome recorded before exact dispatch".to_owned(),
            ));
        }
        let mut candidate = self.state.clone();
        candidate.enqueue_outcome = Some(outcome);
        candidate.last_dispatch_error = None;
        candidate.stage = DirectConversationRepairStage::EnqueueOutcomePendingDurability;
        candidate.validate()?;
        self.state = candidate;
        Ok(())
    }

    /// Call only after `snapshot()` containing the enqueue outcome has been
    /// durably committed. Until this transition Welcome authoring is blocked.
    pub fn confirm_enqueue_outcome_durable(&mut self) -> Result<()> {
        if self.state.stage == DirectConversationRepairStage::Enqueued {
            return Ok(());
        }
        if self.state.stage != DirectConversationRepairStage::EnqueueOutcomePendingDurability {
            return Err(Error::Protocol(
                "repair enqueue outcome is not awaiting durability".to_owned(),
            ));
        }
        self.state.stage = DirectConversationRepairStage::Enqueued;
        self.state.validate()
    }

    pub fn record_welcome_durable(&mut self, welcome_digest: Hash) -> Result<()> {
        if matches!(
            self.state.stage,
            DirectConversationRepairStage::WelcomeDurable
                | DirectConversationRepairStage::Activated
        ) && self.state.welcome_digest.as_ref() == Some(&welcome_digest)
        {
            return Ok(());
        }
        if self.state.stage != DirectConversationRepairStage::Enqueued {
            return Err(Error::Protocol(
                "repair Welcome cannot advance before durable enqueue acceptance".to_owned(),
            ));
        }
        self.state.welcome_digest = Some(welcome_digest);
        self.state.stage = DirectConversationRepairStage::WelcomeDurable;
        self.state.validate()
    }

    pub fn record_activation_durable(&mut self, activation_event_id: EventId) -> Result<()> {
        if self.state.stage == DirectConversationRepairStage::Activated
            && self.state.activation_event_id.as_ref() == Some(&activation_event_id)
        {
            return Ok(());
        }
        if self.state.stage != DirectConversationRepairStage::WelcomeDurable {
            return Err(Error::Protocol(
                "repair activation cannot advance before durable Welcome".to_owned(),
            ));
        }
        self.state.activation_event_id = Some(activation_event_id);
        self.state.stage = DirectConversationRepairStage::Activated;
        self.state.validate()
    }
}

#[cfg(test)]
mod tests {
    use arkret_models_collaboration::direct_conversation_repair::{
        DirectConversationRepairAuthorization, DirectConversationRepairEnqueueStatus,
        DirectConversationRepairRecipientTarget,
    };
    use arkret_models_collaboration::events_payloads::MemberRepairRequester;
    use arkret_wire::{Base64UrlString, DidUrl, ProtocolSignature, RealmId, StrandId};
    use chrono::{Duration, TimeZone as _};

    use super::*;

    const REALM: &str = "ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI";
    const REJOIN: &str = "ak:event:Af-qizSfVETcKiliXG093VVneO4nQF194ZXGkMWJijix";
    const AUTHORIZE: &str = "ak:event:AY2gmtVpH4CNWqvZ25JTuYdzI56aAbxr3k-TrqvZfsKv";
    const BINDING: &str = "ak:event:AZL87nwhLc8pnnvIhrfEQSfNkZvdPzaV3rFGVoJCQWW6";
    const ACTIVATION: &str = "ak:event:ARVUUS5MsgtJTHxDUnT_24cP4k86XFFUI-95GFfyLv6j";

    fn hash(byte: char) -> Hash {
        Hash::new(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
    }

    fn principal() -> DidCoreId {
        DidCoreId::new("ak:did_core:key:z6MkRepairRequester").unwrap()
    }

    fn route() -> DirectConversationRepairRoute {
        DirectConversationRepairRoute {
            source_service_id: DidCoreId::new("ak:did_core:web:source.example").unwrap(),
            target_service_id: DidCoreId::new("ak:did_core:web:target.example").unwrap(),
            coordinates: DirectConversationCoordinates {
                pair_key: hash('a'),
                realm_id: RealmId::new(REALM).unwrap(),
                main_strand_id: StrandId::new(
                    "ak:strand:AT3ARBdH1FM6GjXK9ulTx-YMvQOXys39dlUzZV6KyID9",
                )
                .unwrap(),
                binding_event_ref: Some(EventId::new(BINDING).unwrap()),
            },
            target_keypackage_ref: NonEmptyString::new("kp-exact-repair-target").unwrap(),
        }
    }

    fn content() -> MemberRepairRequestPayload {
        let verification_method = DidUrl::new("did:key:z6MkRepairRequester#agent-signing").unwrap();
        MemberRepairRequestPayload {
            realm_id: RealmId::new(REALM).unwrap(),
            requester_principal_id: principal(),
            requester: MemberRepairRequester::NativeAgent {
                requester_agent_id: principal(),
                requester_agent_verification_method: verification_method,
                agent_key_authorize_event_id: EventId::new(AUTHORIZE).unwrap(),
            },
            requester_keypackage_ref: NonEmptyString::new("kp-exact-repair-target").unwrap(),
            observed_active_generation_value_digest: hash('b'),
            rejoin_event_id: EventId::new(REJOIN).unwrap(),
            created_at: chrono::Utc.with_ymd_and_hms(2026, 8, 10, 10, 0, 0).unwrap(),
        }
    }

    fn acceptance() -> SelfRejoinAcceptance {
        SelfRejoinAcceptance {
            realm_id: RealmId::new(REALM).unwrap(),
            requester_principal_id: principal(),
            rejoin_event_id: EventId::new(REJOIN).unwrap(),
            accepted_at: content().created_at + Duration::seconds(1),
        }
    }

    fn request() -> DirectConversationRepairDispatchRequest {
        let created_at = content().created_at + Duration::seconds(2);
        let verification_method = DidUrl::new("did:key:z6MkRepairRequester#agent-signing").unwrap();
        DirectConversationRepairDispatchRequest {
            request_id: Base64UrlString::new("A".repeat(32)).unwrap(),
            content: content(),
            requester_authorization: DirectConversationRepairAuthorization::NativeAgent {
                requester_agent_id: principal(),
                verification_method: verification_method.clone(),
                agent_key_authorize_event_id: EventId::new(AUTHORIZE).unwrap(),
                signed_at: created_at,
                signature: ProtocolSignature {
                    verification_method,
                    created_at,
                    jws: Base64UrlString::new("repair-signature").unwrap(),
                },
            },
        }
    }

    fn ready() -> DirectConversationRepairPlanner {
        let mut planner = DirectConversationRepairPlanner::new(route()).unwrap();
        planner
            .observe_self_rejoin_accepted(acceptance(), content())
            .unwrap();
        planner.freeze_signed_request(request()).unwrap();
        planner
    }

    fn outcome(
        planner: &DirectConversationRepairPlanner,
    ) -> DirectConversationRepairEnqueueOutcome {
        let frozen = planner.snapshot().frozen_dispatch.unwrap();
        DirectConversationRepairEnqueueOutcome {
            request_id: frozen.request.request_id,
            request_digest: frozen.request_digest,
            destination_service_id: route().target_service_id,
            status: DirectConversationRepairEnqueueStatus::Enqueued,
            recipient_target: DirectConversationRepairRecipientTarget::NativeAgent {
                target_snapshot_digest: hash('c'),
                enqueued_target_count: 1,
            },
            accepted_at: content().created_at + Duration::seconds(3),
        }
    }

    #[test]
    fn repair_order_requires_accepted_rejoin_and_durable_enqueue() {
        let mut planner = DirectConversationRepairPlanner::new(route()).unwrap();
        assert!(planner.freeze_signed_request(request()).is_err());
        planner
            .observe_self_rejoin_accepted(acceptance(), content())
            .unwrap();
        planner.freeze_signed_request(request()).unwrap();
        assert!(planner.record_welcome_durable(hash('d')).is_err());

        let enqueue = outcome(&planner);
        planner.record_enqueue_outcome(enqueue).unwrap();
        assert_eq!(
            planner.next_action(),
            DirectConversationRepairAction::PersistEnqueueOutcome
        );
        assert!(!planner.is_business_complete());
        assert!(planner.record_welcome_durable(hash('d')).is_err());
        planner.confirm_enqueue_outcome_durable().unwrap();
        planner.record_welcome_durable(hash('d')).unwrap();
        planner
            .record_activation_durable(EventId::new(ACTIVATION).unwrap())
            .unwrap();
        assert!(planner.is_business_complete());
    }

    #[test]
    fn repair_restore_rejects_tampered_frozen_bytes() {
        let planner = ready();
        let mut snapshot = planner.snapshot();
        snapshot
            .frozen_dispatch
            .as_mut()
            .unwrap()
            .canonical_request_bytes
            .push(b' ');
        assert!(DirectConversationRepairPlanner::restore_durable(snapshot).is_err());

        let mut route_tampered = planner.snapshot();
        route_tampered.route.target_service_id =
            DidCoreId::new("ak:did_core:web:attacker.example").unwrap();
        assert!(DirectConversationRepairPlanner::restore_durable(route_tampered).is_err());
    }

    #[test]
    fn repair_retry_is_byte_identical_and_rejects_a_new_request() {
        let mut planner = ready();
        let exact = planner.exact_retry_bytes(&request()).unwrap().to_vec();
        planner.record_dispatch_failure("connection reset").unwrap();
        let restored =
            DirectConversationRepairPlanner::restore_durable(planner.snapshot()).unwrap();
        assert_eq!(
            restored.next_action(),
            DirectConversationRepairAction::SubmitExactRequest
        );
        assert_eq!(restored.exact_retry_bytes(&request()).unwrap(), exact);

        let mut changed = request();
        changed.request_id = Base64UrlString::new("B".repeat(32)).unwrap();
        assert!(restored.exact_retry_bytes(&changed).is_err());
    }

    #[test]
    fn repair_rejects_mismatched_enqueue_outcome_without_advancing() {
        let mut planner = ready();
        let mut mismatched = outcome(&planner);
        mismatched.request_digest = hash('f');
        assert!(planner.record_enqueue_outcome(mismatched).is_err());
        assert_eq!(
            planner.stage(),
            DirectConversationRepairStage::DispatchFrozen
        );
    }

    #[test]
    fn durable_restore_advances_only_the_persisted_enqueue_boundary() {
        let mut planner = ready();
        let enqueue = outcome(&planner);
        planner.record_enqueue_outcome(enqueue).unwrap();
        let durable_bytes = serde_json::to_vec(&planner.snapshot()).unwrap();
        let durable_snapshot: DirectConversationRepairSnapshot =
            serde_json::from_slice(&durable_bytes).unwrap();
        let restored = DirectConversationRepairPlanner::restore_durable(durable_snapshot).unwrap();
        assert_eq!(restored.stage(), DirectConversationRepairStage::Enqueued);
        assert_eq!(
            restored.next_action(),
            DirectConversationRepairAction::AuthorWelcome
        );
        assert!(!restored.is_business_complete());
    }
}
