//! The accepted MLS transition a device installs, and the checks that make it
//! safe to install.
//!
//! An MLS transition becomes installable exactly when the governance Station
//! has committed its Event into the scope's own independent commit stream. The
//! client never asks a separate endpoint whether a transition was accepted: a
//! locally authored Commit pairs its Event with the `RealmCommit` the submit
//! returned, and a remote transition arrives as a full committed-event view.

use arkret_wire::{CommittedEventFullView, MlsGroupId};

/// One accepted `ak.mls.genesis` / `ak.mls.commit` with the exact commit
/// coordinate that ordered it.
#[derive(Clone, Debug, PartialEq)]
pub struct AcceptedMlsTransition {
    pub item: CommittedEventFullView,
    pub effective_scope: arkret_wire::ScopeRef,
    pub mls_group_id: MlsGroupId,
    pub previous_epoch: u64,
    pub next_epoch: u64,
}

impl AcceptedMlsTransition {
    /// The Event this transition materialized.
    pub fn event(&self) -> &arkret_wire::Event {
        &self.item.event
    }
}

/// Read one accepted stream row as an MLS transition.
///
/// Every cross-check the installer depends on happens here: the commit must
/// bind this exact Event in this exact scope stream, the payload's governance
/// binding must name the same scope, and the group id must be the one derived
/// from that scope. A transition that fails any of them is refused rather than
/// installed under a scope it does not belong to.
pub fn accepted_mls_transition(
    item: &CommittedEventFullView,
) -> Result<AcceptedMlsTransition, String> {
    item.validate_shape()
        .map_err(|error| format!("accepted MLS transition is malformed: {error}"))?;
    let binding = match &item.event.kind {
        arkret_wire::EventKind::MlsGenesis => {
            let payload: arkret_models_collaboration::events_payloads::MlsGenesisPayload =
                event_payload(&item.event)?;
            payload
                .validate()
                .map_err(|error| format!("invalid accepted MLS Genesis: {error}"))?;
            payload.governance_binding
        }
        arkret_wire::EventKind::MlsCommit => {
            let payload: arkret_models_collaboration::events_payloads::MlsCommitPayload =
                event_payload(&item.event)?;
            payload
                .validate()
                .map_err(|error| format!("invalid accepted MLS Commit: {error}"))?;
            payload.governance_binding().clone()
        }
        other => {
            return Err(format!(
                "accepted MLS transition must be a genesis or commit Event, not {}",
                other.as_str()
            ));
        }
    };
    if binding.effective_scope() != &item.event.scope_ref {
        return Err(
            "accepted MLS governance binding names another scope than its Event".to_owned(),
        );
    }
    let mls_group_id = binding
        .mls_group_id()
        .map_err(|error| format!("accepted MLS transition has no group id: {error}"))?;
    Ok(AcceptedMlsTransition {
        item: item.clone(),
        effective_scope: binding.effective_scope().clone(),
        mls_group_id,
        previous_epoch: binding.previous_epoch(),
        next_epoch: binding.next_epoch(),
    })
}

/// Pair a locally authored MLS Event with the `RealmCommit` its submission
/// returned, which is the same accepted shape the scan path delivers.
pub fn accepted_from_submission(
    event: arkret_wire::Event,
    commit: arkret_wire::RealmCommit,
) -> Result<AcceptedMlsTransition, String> {
    accepted_mls_transition(&CommittedEventFullView { commit, event })
}

fn event_payload<T: serde::de::DeserializeOwned>(event: &arkret_wire::Event) -> Result<T, String> {
    let payload = serde_json::Value::Object(event.payload.clone().into_iter().collect());
    serde_json::from_value(payload)
        .map_err(|error| format!("accepted MLS payload is unreadable: {error}"))
}
