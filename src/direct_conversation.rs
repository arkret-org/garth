//! Runtime-neutral Direct Conversation founding state transition.

use arkret_models_collaboration::direct_conversation_ops::{
    DirectConversationCoordinates, DirectConversationFoundingPlan,
    DirectConversationFoundingUnitSubmission, DirectConversationResolveOutcome,
};

use crate::{Error, Result};

/// The only legal next action after a query-only Direct Conversation resolve.
#[derive(Debug)]
pub enum DirectConversationFoundingAction {
    Submit(DirectConversationFoundingUnitSubmission),
    AwaitFounder,
    Existing(DirectConversationCoordinates),
    Blocked,
    RetryResolve,
}

/// Gate a caller-authored unit through the SDK planner before transport.
///
/// The engine never authors a replacement after an ambiguous result. The caller persists the
/// returned `Submit` value and retries those exact signed bytes until it receives the receipt.
pub fn direct_conversation_founding_action(
    resolve: &DirectConversationResolveOutcome,
    prepared: Option<DirectConversationFoundingUnitSubmission>,
) -> Result<DirectConversationFoundingAction> {
    match resolve {
        DirectConversationResolveOutcome::CreationRequired { .. } => {
            let prepared = prepared.ok_or_else(|| {
                Error::Protocol("founder has not prepared the closed four-Event unit".to_owned())
            })?;
            let events = prepared
                .events
                .iter()
                .map(|item| &item.event)
                .collect::<Vec<_>>();
            let exact = events
                .try_into()
                .expect("the typed founding carrier always contains exactly four Events");
            DirectConversationFoundingPlan::from_events(exact)
                .map_err(|error| Error::Protocol(error.to_string()))?;
            Ok(DirectConversationFoundingAction::Submit(prepared))
        }
        DirectConversationResolveOutcome::AwaitingFounder { .. } => {
            Ok(DirectConversationFoundingAction::AwaitFounder)
        }
        DirectConversationResolveOutcome::Provisional { coordinates, .. }
        | DirectConversationResolveOutcome::Found { coordinates, .. }
        | DirectConversationResolveOutcome::Suspended { coordinates, .. } => Ok(
            DirectConversationFoundingAction::Existing(coordinates.clone()),
        ),
        DirectConversationResolveOutcome::CreationBlocked { .. } => {
            Ok(DirectConversationFoundingAction::Blocked)
        }
        DirectConversationResolveOutcome::TemporarilyUnavailable { .. } => {
            Ok(DirectConversationFoundingAction::RetryResolve)
        }
    }
}
