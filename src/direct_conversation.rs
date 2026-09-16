//! Runtime-only next actions for Direct Conversation resolution.

use arkret_models_collaboration::direct_conversation::{
    DirectConversationCoordinates, DirectConversationResolveOutcome,
};

/// Product action after resolving the pair against current authority state.
#[derive(Clone, Debug)]
pub enum DirectConversationAction {
    /// Author the profile's creation Events and submit them through the
    /// governance authority transport.
    SubmitCreation,
    /// The current authority is materializing or committing creation.
    AwaitAuthority {
        retry_after_ms: Option<u64>,
    },
    Existing(DirectConversationCoordinates),
    RetryResolve {
        retry_after_ms: Option<u64>,
    },
}

pub fn direct_conversation_action(
    outcome: &DirectConversationResolveOutcome,
) -> DirectConversationAction {
    match outcome {
        DirectConversationResolveOutcome::CreationRequired => {
            DirectConversationAction::SubmitCreation
        }
        DirectConversationResolveOutcome::AwaitingAuthority { retry_after_ms } => {
            DirectConversationAction::AwaitAuthority {
                retry_after_ms: *retry_after_ms,
            }
        }
        DirectConversationResolveOutcome::Found { coordinates }
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
