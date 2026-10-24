//! Runtime-only admission gates for the Agent journey.
//!
//! Wire objects remain owned by the SDK. This module only combines already
//! verified facts; none of the local fact wrappers serialize into a competing
//! protocol DTO.

use arkret_models_collaboration::governance::agent_participation::ParticipationBits;

use crate::{Error, Result};

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
    pub owner_selection_current: bool,
    pub target_policy: ParticipationBits,
    pub target_policy_resolved: bool,
    pub agent_active: bool,
    pub controller_account_active: bool,
    pub membership_active: bool,
    pub grant_active: bool,
}

impl ParticipationAdmissionFacts {
    pub fn effective_bits(&self) -> Result<ParticipationBits> {
        if !self.target_policy_resolved || !self.owner_selection_current {
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
        ParticipationAction::ReplyMessage => bits.message_creation_allowed,
        ParticipationAction::ReactionAdd => bits.reaction_addition_allowed,
        ParticipationAction::ReactionRemove => bits.reaction_removal_allowed,
        ParticipationAction::AcceptThirdPartyMention => bits.third_party_mention_delivery_allowed,
        ParticipationAction::ActOnBehalf => bits.acting_on_behalf_allowed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn participation_actions_map_to_five_distinct_bits() {
        let bits = ParticipationBits {
            message_creation_allowed: true,
            reaction_addition_allowed: false,
            reaction_removal_allowed: true,
            third_party_mention_delivery_allowed: false,
            acting_on_behalf_allowed: true,
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
