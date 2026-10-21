//! Agent interaction reads through the caller's authenticated Account Station.
//!
//! The independent typed snapshot supplies the accepted Realm cut. The exact
//! read must bind that same head and generation; missing or changing material
//! is unknown, never the private default. DID method history remains a Station
//! responsibility and this ordinary-client path performs no discovery.

use arkret_http_client::Client;
use arkret_models_collaboration::agent_interaction::AgentInteractionExactCurrentSelector;
use arkret_models_collaboration::exact_current_results::{
    ExactCurrentResultEntry, ExactCurrentResultSelector, ExactCurrentResultsReadOutcome,
    ExactCurrentResultsReadRequestBody,
};
use arkret_wire::{
    AccountId, CommitStreamRef, CurrentSelector, RealmId, RealmStateSnapshot, TypedCurrentRow,
};

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
    if let Some(outcome) = present_from_snapshot(&request, &snapshot)? {
        return Ok(outcome);
    }
    let outcome = http
        .exact_current_result(&request, snapshot.governance_generation)
        .await?;
    bind_to_snapshot(&request, &snapshot, &outcome)?;
    Ok(outcome)
}

// A present typed row in the authorized snapshot already supplies the exact
// selector, revision and current cut. Do not require a second service scope to
// reread that same fact. Absence is never a never-written proof.
pub(crate) fn present_from_snapshot(
    request: &ExactCurrentResultsReadRequestBody,
    snapshot: &RealmStateSnapshot,
) -> Result<Option<ExactCurrentResultsReadOutcome>> {
    let ExactCurrentResultSelector::AgentInteraction(selector) = &request.selector else {
        return Err(Error::Protocol(
            "Agent mode requires an Agent selector".into(),
        ));
    };
    let mut rows = snapshot
        .current_state_entries
        .iter()
        .filter_map(|row| match row {
            TypedCurrentRow::Value {
                selector: CurrentSelector::AgentInteraction { agent_account_id },
                source_stream_ref,
                revision,
                value,
            } if agent_account_id == &selector.agent_account_id => {
                Some((source_stream_ref, revision, value))
            }
            _ => None,
        });
    let Some((source_stream_ref, revision, value)) = rows.next() else {
        return Ok(None);
    };
    if rows.next().is_some() {
        return Err(Error::Protocol(
            "Agent mode snapshot repeats its selector".into(),
        ));
    }
    let expected_stream = CommitStreamRef::Realm {
        realm_id: request.realm_id.clone(),
    };
    let head = snapshot
        .visible_stream_heads
        .iter()
        .find(|head| head.stream_ref == expected_stream)
        .ok_or_else(|| Error::Protocol("Agent mode snapshot omits its Realm cut".into()))?;
    let value = serde_json::from_value(value.clone())
        .map_err(|error| Error::Protocol(format!("invalid Agent mode snapshot value: {error}")))?;
    let outcome = ExactCurrentResultsReadOutcome::Present {
        realm_id: snapshot.realm_id.clone(),
        governance_generation: snapshot.governance_generation,
        effective_stream_head: head.clone(),
        entry: ExactCurrentResultEntry::AgentInteraction(
            arkret_models_collaboration::agent_interaction::AgentInteractionExactCurrentRow {
                selector: selector.clone(),
                source_stream_ref: source_stream_ref.clone(),
                revision: revision.clone(),
                value,
            },
        ),
    };
    bind_to_snapshot(request, snapshot, &outcome)?;
    Ok(Some(outcome))
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
            purpose: arkret_wire::RealmSnapshotPurpose::FullRecovery,
            history_basis: None,
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

        let ExactCurrentResultsReadOutcome::NeverWritten {
            effective_stream_head,
            ..
        } = &outcome
        else {
            unreachable!();
        };
        snapshot.visible_stream_heads = vec![effective_stream_head.clone()];
        let ExactCurrentResultSelector::AgentInteraction(selector) = &request.selector else {
            unreachable!();
        };
        let row = TypedCurrentRow::Value {
            selector: CurrentSelector::AgentInteraction {
                agent_account_id: selector.agent_account_id.clone(),
            },
            source_stream_ref: effective_stream_head.stream_ref.clone(),
            revision: arkret_wire::CurrentRevision {
                commit_id: effective_stream_head.commit_id.clone(),
                stream_position: effective_stream_head.stream_position,
            },
            value: serde_json::json!({
                "controller_account_id": selector.agent_account_id,
                "interaction_mode": "public",
            }),
        };
        // Missing authorized projection rows cannot prove the private default.
        assert!(
            present_from_snapshot(&request, &snapshot)
                .unwrap()
                .is_none()
        );
        snapshot.current_state_entries = vec![row.clone()];
        assert!(matches!(
            present_from_snapshot(&request, &snapshot).unwrap(),
            Some(ExactCurrentResultsReadOutcome::Present { .. })
        ));
        snapshot.current_state_entries.push(row.clone());
        assert!(present_from_snapshot(&request, &snapshot).is_err());
        snapshot.current_state_entries = vec![row];
        for bad_value in [
            serde_json::json!({"controller_account_id": selector.agent_account_id, "interaction_mode": "unknown"}),
            serde_json::json!({"controller_account_id": {"principal_id": selector.agent_account_id.principal_id}, "interaction_mode": "public"}),
            serde_json::json!({"controller_account_id": selector.agent_account_id, "interaction_mode": "public", "scope_ref": {}}),
        ] {
            let mut bad = snapshot.clone();
            let TypedCurrentRow::Value { value, .. } = &mut bad.current_state_entries[0];
            *value = bad_value;
            assert!(present_from_snapshot(&request, &bad).is_err());
        }
        let mut bad = snapshot.clone();
        let TypedCurrentRow::Value { revision, .. } = &mut bad.current_state_entries[0];
        revision.stream_position += 1;
        assert!(present_from_snapshot(&request, &bad).is_err());
        let mut bad = snapshot.clone();
        let TypedCurrentRow::Value {
            source_stream_ref, ..
        } = &mut bad.current_state_entries[0];
        *source_stream_ref = CommitStreamRef::Realm {
            realm_id: arkret_wire::RealmId::from_event_id(&arkret_wire::EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                [9; 32],
            )),
        };
        assert!(present_from_snapshot(&request, &bad).is_err());
    }
}
