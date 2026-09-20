//! Runtime-only next actions for Direct Conversation resolution.

use arkret_models_collaboration::direct_conversation::{
    DirectConversationCoordinates, DirectConversationFoundingInput,
    DirectConversationResolveOutcome, DirectConversationSendBlocker,
};

/// Product action after resolving the pair against current authority state.
#[derive(Clone, Debug)]
pub enum DirectConversationAction {
    /// Author the profile's creation Events and submit them through the
    /// governance authority transport.
    SubmitCreation {
        next_founding_input: DirectConversationFoundingInput,
    },
    /// Creation cannot be authored yet; surface the blockers to the holder.
    Blocked {
        blockers: Vec<DirectConversationSendBlocker>,
    },
    /// The founding participant has not yet authored the pair.
    AwaitFounder {
        retry_after_ms: Option<u64>,
    },
    Existing(DirectConversationCoordinates),
    RetryResolve {
        retry_after_ms: Option<u64>,
    },
}

#[must_use]
pub fn direct_conversation_action(
    outcome: &DirectConversationResolveOutcome,
) -> DirectConversationAction {
    match outcome {
        DirectConversationResolveOutcome::CreationRequired {
            next_founding_input,
        } => DirectConversationAction::SubmitCreation {
            next_founding_input: next_founding_input.clone(),
        },
        DirectConversationResolveOutcome::CreationBlocked { blockers } => {
            DirectConversationAction::Blocked {
                blockers: blockers.clone(),
            }
        }
        DirectConversationResolveOutcome::AwaitingFounder { retry_after_ms } => {
            DirectConversationAction::AwaitFounder {
                retry_after_ms: *retry_after_ms,
            }
        }
        DirectConversationResolveOutcome::Provisional { coordinates, .. }
        | DirectConversationResolveOutcome::Found { coordinates, .. }
        | DirectConversationResolveOutcome::Suspended { coordinates, .. } => {
            DirectConversationAction::Existing(coordinates.clone())
        }
        DirectConversationResolveOutcome::TemporarilyUnavailable { retry_after_ms } => {
            DirectConversationAction::RetryResolve {
                retry_after_ms: *retry_after_ms,
            }
        }
    }
}
