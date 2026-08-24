//! Runtime-neutral Direct Conversation founding state transition.

use arkret_models_collaboration::direct_conversation_ops::{
    DirectConversationCoordinates, DirectConversationFoundingPlan,
    DirectConversationFoundingUnitSubmission, DirectConversationResolveOutcome,
};

use crate::{Error, Result};

/// The only legal next action after a query-only Direct Conversation resolve.
#[derive(Debug)]
pub enum DirectConversationFoundingAction {
    Submit(Box<DirectConversationFoundingUnitSubmission>),
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
            Ok(DirectConversationFoundingAction::Submit(Box::new(prepared)))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suspended_existing_realm_never_reopens_founding() {
        let outcome: DirectConversationResolveOutcome = serde_json::from_value(serde_json::json!({
            "state": "suspended",
            "coordinates": {
                "pair_key": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "realm_id": "ak:realm:ASZ8VNF9qzH4Hcjd-1qOOKONYlZmfQOIRvMYdkQ0XXBH",
                "main_strand_id": "ak:strand:AcsXlJSItqSzy43Swu0nFz2ijj4Yaf0RgjmoTeivRt8M",
                "binding_event_ref": "ak:event:AZ6GqZWWvnQ2KFwbBD-MenomzWNz-31MUAuKzBXIP0zv"
            },
            "blockers": ["mls_reconcile_required"]
        }))
        .expect("suspended Direct Conversation outcome");

        let action = direct_conversation_founding_action(&outcome, None)
            .expect("suspended outcome is a closed existing coordinate");

        let DirectConversationFoundingAction::Existing(coordinates) = action else {
            panic!("suspended pair must never produce a founding submission");
        };
        assert_eq!(
            coordinates.realm_id.as_str(),
            "ak:realm:ASZ8VNF9qzH4Hcjd-1qOOKONYlZmfQOIRvMYdkQ0XXBH"
        );
    }
}
