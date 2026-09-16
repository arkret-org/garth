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

#[cfg(test)]
mod tests {
    use super::*;

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
