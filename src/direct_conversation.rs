//! Runtime-only next actions for Direct Conversation resolution.

use arkret_models_collaboration::direct_conversation::{
    DirectConversationCoordinates, DirectConversationFoundingInput,
    DirectConversationResolveResponseBody, DirectConversationSendBlocker,
};

/// Product action after resolving the pair against current authority state.
#[derive(Clone, Debug)]
pub enum DirectConversationAction {
    /// Author the profile's creation Events and submit them through the
    /// governance authority transport.
    SubmitCreation {
        next_founding_input: Box<DirectConversationFoundingInput>,
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
    outcome: &DirectConversationResolveResponseBody,
) -> DirectConversationAction {
    match outcome {
        DirectConversationResolveResponseBody::CreationRequired {
            next_founding_input,
        } => DirectConversationAction::SubmitCreation {
            next_founding_input: Box::new(next_founding_input.clone()),
        },
        DirectConversationResolveResponseBody::CreationBlocked { blockers } => {
            DirectConversationAction::Blocked {
                blockers: blockers.clone(),
            }
        }
        DirectConversationResolveResponseBody::AwaitingFounder { retry_after_ms } => {
            DirectConversationAction::AwaitFounder {
                retry_after_ms: *retry_after_ms,
            }
        }
        DirectConversationResolveResponseBody::Provisional { coordinates, .. }
        | DirectConversationResolveResponseBody::Found { coordinates, .. }
        | DirectConversationResolveResponseBody::Suspended { coordinates, .. } => {
            DirectConversationAction::Existing(coordinates.clone())
        }
        DirectConversationResolveResponseBody::TemporarilyUnavailable { retry_after_ms } => {
            DirectConversationAction::RetryResolve {
                retry_after_ms: *retry_after_ms,
            }
        }
    }
}
