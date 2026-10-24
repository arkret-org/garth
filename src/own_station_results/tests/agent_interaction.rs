use arkret_models_collaboration::agent_interaction::{
    AgentInteractionCurrentValue, AgentInteractionExactCurrentSelector, AgentInteractionMode,
};
use arkret_models_collaboration::exact_current_state::{
    ExactCurrentState, ExactCurrentStateReadResponseBody, NeverWrittenExactCurrentSelector,
};

use super::*;

fn account(name: &str) -> arkret_wire::AccountId {
    arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new(format!("ak:did_core:web:{name}.example")).unwrap(),
        arkret_wire::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
    )
}

fn current(position: u64, generation: u64) -> RealmStateSnapshot {
    snapshot_at_floor_and_generation(vec![head(&commit(position, None))], 0, generation)
}

fn wire(snapshot: &RealmStateSnapshot) -> serde_json::Value {
    serde_json::to_value(snapshot).unwrap()
}

fn seal(mut snapshot: RealmStateSnapshot) -> RealmStateSnapshot {
    let mut value = wire(&snapshot);
    value.as_object_mut().unwrap().remove("snapshot_id");
    value.as_object_mut().unwrap().remove("signature");
    snapshot.snapshot_id = RealmSnapshotId::from_digest(arkret_canonical::sha256_bytes(
        arkret_canonical::canonical_json_bytes(&value).unwrap(),
    ));
    snapshot
}

fn never_written(snapshot: &RealmStateSnapshot) -> serde_json::Value {
    serde_json::to_value(ExactCurrentStateReadResponseBody::NeverWritten {
        realm_id: snapshot.realm_id.clone(),
        governance_generation: snapshot.governance_generation,
        effective_stream_head: snapshot.visible_stream_heads[0].clone(),
        selector: NeverWrittenExactCurrentSelector::AgentInteraction(
            AgentInteractionExactCurrentSelector::new(account("agent")),
        ),
    })
    .unwrap()
}

#[tokio::test]
async fn advancing_mode_cut_repeats_the_complete_read_before_accepting_never_written() {
    let before = current(0, 0);
    let after = current(1, 1);
    let (client, server, requests) = observed_client(vec![
        wire(&before),
        never_written(&before),
        wire(&after),
        wire(&after),
        never_written(&after),
        wire(&after),
    ]);
    let result = read_own_station_agent_interaction(&client, &before.realm_id, &account("agent"))
        .await
        .unwrap()
        .into_value()
        .unwrap();
    assert!(
        matches!(result, ExactCurrentStateReadResponseBody::NeverWritten {
        governance_generation: 1, effective_stream_head, ..
    } if effective_stream_head == after.visible_stream_heads[0])
    );
    server.join().unwrap();
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 6);
    assert_eq!(
        requests
            .iter()
            .filter(|path| path.contains("/current-state/exact"))
            .count(),
        2
    );
    assert!(
        requests
            .iter()
            .all(|path| !path.contains("/_arkret/self/events"))
    );
}

#[tokio::test]
async fn a_public_mode_written_during_the_read_replaces_the_discarded_private_default() {
    let before = current(0, 0);
    let mut after = current(1, 1);
    let accepted = &after.visible_stream_heads[0];
    after.current_state_entries.push(CurrentState::Value {
        selector: arkret_wire::CurrentSelector::AgentInteraction {
            agent_account_id: account("agent"),
        },
        source_stream_ref: accepted.stream_ref.clone(),
        revision: arkret_wire::CurrentRevision {
            commit_id: accepted.commit_id.clone(),
            stream_position: accepted.stream_position,
        },
        value: serde_json::to_value(AgentInteractionCurrentValue {
            controller_account_id: account("alice"),
            interaction_mode: AgentInteractionMode::Public,
        })
        .unwrap(),
    });
    let after = seal(after);
    let (client, server, requests) = observed_client(vec![
        wire(&before),
        never_written(&before),
        wire(&after),
        wire(&after),
    ]);
    let result = read_own_station_agent_interaction(&client, &before.realm_id, &account("agent"))
        .await
        .unwrap()
        .into_value()
        .unwrap();
    assert!(
        matches!(result, ExactCurrentStateReadResponseBody::Present {
        current_state: ExactCurrentState::AgentInteraction(entry), ..
    } if entry.value.interaction_mode == AgentInteractionMode::Public
        && entry.value.controller_account_id == account("alice"))
    );
    server.join().unwrap();
    assert_eq!(requests.lock().unwrap().len(), 4);
}

#[tokio::test]
async fn a_stable_mode_cut_mismatch_fails_without_retrying() {
    let stable = current(1, 0);
    let (client, server, requests) = observed_client(vec![
        wire(&stable),
        never_written(&current(0, 0)),
        wire(&stable),
    ]);
    let result =
        read_own_station_agent_interaction(&client, &stable.realm_id, &account("agent")).await;
    assert!(
        matches!(result, Err(Error::Protocol(message)) if message.contains("crossed a current cut"))
    );
    server.join().unwrap();
    assert_eq!(requests.lock().unwrap().len(), 3);
}

#[tokio::test]
async fn a_continuously_advancing_mode_cut_exhausts_three_reads_without_an_allow_value() {
    let mut responses = Vec::new();
    for position in 0..3 {
        let before = current(position, position);
        responses.extend([
            wire(&before),
            never_written(&before),
            wire(&current(position + 1, position + 1)),
        ]);
    }
    let (client, server, requests) = observed_client(responses);
    let result = read_own_station_agent_interaction(
        &client,
        &crate::test_fixtures::realm_id(),
        &account("agent"),
    )
    .await;
    assert!(
        matches!(result, Err(Error::Protocol(message)) if message.contains("crossed a current cut"))
    );
    server.join().unwrap();
    assert_eq!(requests.lock().unwrap().len(), 9);
}

#[tokio::test]
async fn mode_cut_rollback_or_same_position_fork_is_not_forward_progress() {
    let before = current(1, 1);
    let mut fork = before.clone();
    fork.visible_stream_heads[0].commit_id = arkret_wire::RealmCommitId::from_digest([99; 32]);
    for after in [current(0, 1), current(2, 0), seal(fork)] {
        let (client, server, requests) =
            observed_client(vec![wire(&before), never_written(&before), wire(&after)]);
        let result =
            read_own_station_agent_interaction(&client, &before.realm_id, &account("agent")).await;
        assert!(
            matches!(result, Err(Error::Protocol(message)) if message.contains("crossed a current cut"))
        );
        server.join().unwrap();
        assert_eq!(requests.lock().unwrap().len(), 3);
    }
}
