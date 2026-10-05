//! Agent interaction reads through the caller's authenticated Account Station.
//!
//! The independent typed snapshot supplies the accepted Realm cut. The exact
//! read must bind that same head and generation; missing or changing material
//! is unknown, never the private default. DID method history remains a Station
//! responsibility and this ordinary-client path performs no discovery.

use arkret_http_client::Client;
use arkret_models_collaboration::agent_interaction::AgentInteractionExactCurrentSelector;
use arkret_models_collaboration::exact_current_results::{
    ExactCurrentResultSelector, ExactCurrentResultsReadOutcome, ExactCurrentResultsReadRequestBody,
};
use arkret_wire::{AccountId, CommitStreamRef, RealmId, RealmStateSnapshot};

use crate::{Error, Result};

pub async fn read_verified_agent_interaction(
    http: &Client,
    realm: &RealmId,
    agent: &AccountId,
) -> Result<ExactCurrentResultsReadOutcome> {
    let request = ExactCurrentResultsReadRequestBody {
        realm_id: realm.clone(),
        selector: ExactCurrentResultSelector::AgentInteraction(
            AgentInteractionExactCurrentSelector::new(agent.clone()),
        ),
    };
    let snapshot = http.realm_state_snapshot_head(realm).await?;
    let outcome = http
        .exact_current_result(&request, snapshot.governance_generation)
        .await?;
    bind_to_snapshot(&request, &snapshot, &outcome)?;
    Ok(outcome)
}

fn bind_to_snapshot(
    request: &ExactCurrentResultsReadRequestBody,
    snapshot: &RealmStateSnapshot,
    outcome: &ExactCurrentResultsReadOutcome,
) -> Result<()> {
    if snapshot.realm_id != request.realm_id {
        return Err(Error::Protocol(
            "Agent mode snapshot belongs to another Realm".into(),
        ));
    }
    outcome
        .validate_for_request(request, snapshot.governance_generation)
        .map_err(|error| Error::Protocol(error.to_string()))?;
    let stream = CommitStreamRef::Realm {
        realm_id: request.realm_id.clone(),
    };
    let mut heads = snapshot
        .visible_stream_heads
        .iter()
        .filter(|head| head.stream_ref == stream);
    let head = heads
        .next()
        .ok_or_else(|| Error::Protocol("Agent mode snapshot omits its Realm cut".into()))?;
    if heads.next().is_some() {
        return Err(Error::Protocol(
            "Agent mode snapshot repeats its Realm cut".into(),
        ));
    }
    let effective = match outcome {
        ExactCurrentResultsReadOutcome::Present {
            effective_stream_head,
            ..
        }
        | ExactCurrentResultsReadOutcome::NeverWritten {
            effective_stream_head,
            ..
        } => effective_stream_head,
    };
    if effective != head {
        return Err(Error::Protocol(
            "Agent mode changed between snapshot and exact read".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use arkret_models_collaboration::exact_current_results::NeverWrittenExactCurrentSelector;
    use arkret_wire::{CommitStreamHead, RealmCommitId};

    use super::*;

    #[test]
    fn exact_read_binds_complete_account_generation_and_independent_head() {
        let realm = crate::test_fixtures::realm_id();
        let agent = AccountId::new(
            arkret_wire::DidCoreId::new("ak:did_core:web:agent.example").unwrap(),
            arkret_wire::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        );
        let selector = AgentInteractionExactCurrentSelector::new(agent);
        let request = ExactCurrentResultsReadRequestBody {
            realm_id: realm.clone(),
            selector: ExactCurrentResultSelector::AgentInteraction(selector.clone()),
        };
        let head = CommitStreamHead {
            stream_ref: CommitStreamRef::Realm {
                realm_id: realm.clone(),
            },
            stream_position: 4,
            commit_id: RealmCommitId::from_digest([4; 32]),
        };
        let mut snapshot = RealmStateSnapshot {
            snapshot_id: arkret_wire::RealmSnapshotId::from_digest([8; 32]),
            realm_id: realm.clone(),
            governance_generation: 2,
            visible_stream_heads: vec![head.clone()],
            current_state_entries: Vec::new(),
            retention_and_history_floor: arkret_wire::RetentionAndHistoryFloor {
                history_access: arkret_wire::HistoryAccess::AllHistoryForCurrentMembers,
                stream_floors: vec![arkret_wire::StreamHistoryFloor {
                    stream_ref: head.stream_ref.clone(),
                    oldest_position: 0,
                }],
            },
            created_at: crate::test_fixtures::at(0),
            signature: crate::test_fixtures::detached_signature(
                arkret_wire::DetachedSignatureContext::RealmSnapshot,
            ),
        };
        let outcome = ExactCurrentResultsReadOutcome::NeverWritten {
            realm_id: realm,
            governance_generation: 2,
            effective_stream_head: head,
            selector: NeverWrittenExactCurrentSelector::AgentInteraction(selector),
        };
        bind_to_snapshot(&request, &snapshot, &outcome).unwrap();
        snapshot.governance_generation = 3;
        assert!(bind_to_snapshot(&request, &snapshot, &outcome).is_err());
        snapshot.governance_generation = 2;
        snapshot.visible_stream_heads[0].commit_id = RealmCommitId::from_digest([9; 32]);
        assert!(bind_to_snapshot(&request, &snapshot, &outcome).is_err());
        snapshot.visible_stream_heads.clear();
        assert!(bind_to_snapshot(&request, &snapshot, &outcome).is_err());
    }
}
