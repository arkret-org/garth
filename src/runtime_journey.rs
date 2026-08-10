//! Runtime-only planning and admission gates for the Personal Agent journey.
//!
//! Wire objects remain owned by the SDK. This module only combines already
//! verified facts; none of the local fact wrappers serialize into a competing
//! protocol DTO.

use chrono::{DateTime, Utc};

use crate::protocol::{
    ActorId, AgentSignerEvidenceQuerySelector, Error, EventId, Hash, NonEmptyString,
    ParticipationBits, ProtocolOperationId, Result, ServiceId,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeActorView {
    Controller,
    PairingHandle,
    AuthorizedKeyWithoutSession,
    AuthenticatedRuntime,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeReadyAction {
    ContinuePairing,
    RequestSessionGrant,
    SubmitParticipationReplacement,
    ConsumeAcceptedWelcome,
    SendReply,
    AddReaction,
    RemoveReaction,
    AcceptThirdPartyMention,
    ActOnBehalf,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeBlocker {
    PairingHandleMissing,
    ActiveKeyMissing,
    SessionMissing,
    RecoveryStale,
    CurrentLifecycleInactive,
    CurrentMembershipInactive,
    CurrentGrantInactive,
    WelcomeNotAccepted,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimePlan {
    pub actor_view: RuntimeActorView,
    pub ready_actions: Vec<RuntimeReadyAction>,
    pub blockers: Vec<RuntimeBlocker>,
}

/// Inputs that are local/session facts, never authority-bearing wire state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimePlanFacts {
    pub actor_view: RuntimeActorView,
    pub pairing_handle_open: bool,
    pub active_key: bool,
    pub session_available: bool,
    pub recovery_stale: bool,
    pub accepted_welcome_available: bool,
}

pub fn plan_runtime(facts: RuntimePlanFacts) -> RuntimePlan {
    let mut ready_actions = Vec::new();
    let mut blockers = Vec::new();
    match facts.actor_view {
        RuntimeActorView::Controller => {
            ready_actions.push(RuntimeReadyAction::SubmitParticipationReplacement);
        }
        RuntimeActorView::PairingHandle => {
            if facts.pairing_handle_open {
                ready_actions.push(RuntimeReadyAction::ContinuePairing);
            } else {
                blockers.push(RuntimeBlocker::PairingHandleMissing);
            }
        }
        RuntimeActorView::AuthorizedKeyWithoutSession => {
            if !facts.active_key {
                blockers.push(RuntimeBlocker::ActiveKeyMissing);
            } else {
                // A valid authorized key can bootstrap its own session. A
                // missing session is not a generic Agent readiness blocker.
                ready_actions.push(RuntimeReadyAction::RequestSessionGrant);
            }
            if facts.recovery_stale {
                blockers.push(RuntimeBlocker::RecoveryStale);
            }
        }
        RuntimeActorView::AuthenticatedRuntime => {
            if !facts.active_key {
                blockers.push(RuntimeBlocker::ActiveKeyMissing);
            }
            if !facts.session_available {
                blockers.push(RuntimeBlocker::SessionMissing);
            }
            if facts.accepted_welcome_available {
                ready_actions.push(RuntimeReadyAction::ConsumeAcceptedWelcome);
            } else {
                blockers.push(RuntimeBlocker::WelcomeNotAccepted);
            }
        }
    }
    RuntimePlan {
        actor_view: facts.actor_view,
        ready_actions,
        blockers,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParticipationAction {
    ReplyMessage,
    ReactionAdd,
    ReactionRemove,
    AcceptThirdPartyMention,
    ActOnBehalf,
}

#[derive(Clone, Debug)]
pub struct ParticipationAdmissionFacts {
    pub selection: ParticipationBits,
    pub target_policy: ParticipationBits,
    pub target_policy_resolved: bool,
    pub agent_active: bool,
    pub controller_account_active: bool,
    pub membership_active: bool,
    pub grant_active: bool,
}

impl ParticipationAdmissionFacts {
    pub fn effective_bits(&self) -> Result<ParticipationBits> {
        if !self.target_policy_resolved {
            return Err(Error::Protocol(
                "current target participation policy is unresolved".to_owned(),
            ));
        }
        if !self.agent_active || !self.controller_account_active {
            return Err(Error::Protocol(
                "current Agent/controller lifecycle denies participation".to_owned(),
            ));
        }
        if !self.membership_active || !self.grant_active {
            return Err(Error::Protocol(
                "current membership or grant denies participation".to_owned(),
            ));
        }
        Ok(self.selection.intersect(self.target_policy))
    }

    pub fn allows(&self, action: ParticipationAction) -> Result<bool> {
        let bits = self.effective_bits()?;
        Ok(participation_bit(bits, action))
    }
}

fn participation_bit(bits: ParticipationBits, action: ParticipationAction) -> bool {
    match action {
        ParticipationAction::ReplyMessage => bits.reply_message,
        ParticipationAction::ReactionAdd => bits.reaction_add,
        ParticipationAction::ReactionRemove => bits.reaction_remove,
        ParticipationAction::AcceptThirdPartyMention => bits.accept_third_party_mention,
        ParticipationAction::ActOnBehalf => bits.act_on_behalf,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SignerEvidenceUse {
    CurrentAdmission {
        agent_id: ActorId,
        verification_method: arkret_wire::DidUrl,
        now: DateTime<Utc>,
        operation_id: ProtocolOperationId,
        request_digest: Hash,
        verifier_id: ServiceId,
        audience: ServiceId,
        challenge: NonEmptyString,
    },
    HistoricalVerification {
        agent_id: ActorId,
        verification_method: arkret_wire::DidUrl,
        now: DateTime<Utc>,
        event_id: EventId,
        event_digest: Hash,
        receiver_service_id: ServiceId,
    },
}

pub fn signer_evidence_selector(
    usage: &SignerEvidenceUse,
) -> Result<AgentSignerEvidenceQuerySelector> {
    if let SignerEvidenceUse::CurrentAdmission { challenge, .. } = usage
        && !(16..=512).contains(&challenge.as_str().chars().count())
    {
        return Err(Error::Protocol(
            "signer evidence challenge must contain 16..=512 characters".to_owned(),
        ));
    }
    Ok(match usage {
        SignerEvidenceUse::CurrentAdmission {
            operation_id,
            request_digest,
            verifier_id,
            audience,
            challenge,
            agent_id,
            verification_method,
            ..
        } => AgentSignerEvidenceQuerySelector::CurrentAdmission {
            agent_id: agent_id.clone(),
            verification_method: verification_method.clone(),
            operation_id: operation_id.clone(),
            request_digest: request_digest.clone(),
            verifier_id: verifier_id.clone(),
            audience: audience.clone(),
            challenge: challenge.clone(),
        },
        SignerEvidenceUse::HistoricalVerification {
            event_id,
            event_digest,
            receiver_service_id,
            agent_id,
            verification_method,
            ..
        } => AgentSignerEvidenceQuerySelector::HistoricalEvent {
            agent_id: agent_id.clone(),
            verification_method: verification_method.clone(),
            event_id: event_id.clone(),
            event_digest: event_digest.clone(),
            receiver_service_id: receiver_service_id.clone(),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorized_key_without_session_can_request_its_own_session() {
        let plan = plan_runtime(RuntimePlanFacts {
            actor_view: RuntimeActorView::AuthorizedKeyWithoutSession,
            pairing_handle_open: false,
            active_key: true,
            session_available: false,
            recovery_stale: false,
            accepted_welcome_available: false,
        });
        assert_eq!(
            plan.ready_actions,
            vec![RuntimeReadyAction::RequestSessionGrant]
        );
        assert!(!plan.blockers.contains(&RuntimeBlocker::SessionMissing));
    }

    #[test]
    fn pairing_handle_view_cannot_inherit_controller_or_session_actions() {
        let plan = plan_runtime(RuntimePlanFacts {
            actor_view: RuntimeActorView::PairingHandle,
            pairing_handle_open: true,
            active_key: true,
            session_available: true,
            recovery_stale: false,
            accepted_welcome_available: true,
        });
        assert_eq!(
            plan.ready_actions,
            vec![RuntimeReadyAction::ContinuePairing]
        );
    }

    #[test]
    fn signer_selector_separates_current_and_historical_queries() {
        let agent = ActorId::new("ak:did_core:webvh:z6mkfixture:agent.example").unwrap();
        let method =
            arkret_wire::DidUrl::new("did:webvh:z6mkfixture:agent.example#runtime-key-1").unwrap();
        let request_digest =
            Hash::new("sha256:1111111111111111111111111111111111111111111111111111111111111111")
                .unwrap();
        let current = signer_evidence_selector(&SignerEvidenceUse::CurrentAdmission {
            agent_id: agent.clone(),
            verification_method: method.clone(),
            now: Utc::now(),
            operation_id: ProtocolOperationId::new("ak:operation:signer-current-1").unwrap(),
            request_digest: request_digest.clone(),
            verifier_id: ServiceId::new("ak:did_core:webvh:z6mkfixture:verifier.example").unwrap(),
            audience: ServiceId::new("ak:did_core:webvh:z6mkfixture:audience.example").unwrap(),
            challenge: NonEmptyString::new("0123456789abcdef").unwrap(),
        })
        .unwrap();
        assert!(matches!(
            current,
            AgentSignerEvidenceQuerySelector::CurrentAdmission { request_digest: digest, .. }
                if digest == request_digest
        ));

        let event_digest =
            Hash::new("sha256:2222222222222222222222222222222222222222222222222222222222222222")
                .unwrap();
        let event_id = EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [0x22; 32]);
        let historical = signer_evidence_selector(&SignerEvidenceUse::HistoricalVerification {
            agent_id: agent,
            verification_method: method,
            now: Utc::now(),
            event_id: event_id.clone(),
            event_digest,
            receiver_service_id: ServiceId::new("ak:did_core:webvh:z6mkfixture:receiver.example")
                .unwrap(),
        })
        .unwrap();
        assert!(matches!(
            historical,
            AgentSignerEvidenceQuerySelector::HistoricalEvent {
                event_id: selected_event_id,
                ..
            } if selected_event_id == event_id
        ));
    }

    #[test]
    fn participation_actions_map_to_five_distinct_bits() {
        let bits = ParticipationBits {
            reply_message: true,
            reaction_add: false,
            reaction_remove: true,
            accept_third_party_mention: false,
            act_on_behalf: true,
        };
        assert!(participation_bit(bits, ParticipationAction::ReplyMessage));
        assert!(!participation_bit(bits, ParticipationAction::ReactionAdd));
        assert!(participation_bit(bits, ParticipationAction::ReactionRemove));
        assert!(!participation_bit(
            bits,
            ParticipationAction::AcceptThirdPartyMention
        ));
        assert!(participation_bit(bits, ParticipationAction::ActOnBehalf));
    }
}
