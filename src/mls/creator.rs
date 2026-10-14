//! Exact creator reads shared by Device hosts and Agent runtimes.

use arkret_http_client::own_station_results::OwnStationResultClient;
use arkret_models_collaboration::events_payloads::RealmGenesis;
use arkret_models_collaboration::mls_creator_bootstrap::{
    MlsCreatorBootstrapAcceptedCreate, MlsCreatorBootstrapAuthority, MlsCreatorBootstrapIntent,
    validate_creator_genesis_absence_snapshot,
};
use arkret_wire::{
    CommitStreamRef, CommittedEventFullView, CommittedEventRef, CommittedEventView,
    CurrentSelector, EventKind, RealmStateSnapshot, StreamScanDirection, StreamScanRequest,
    TypedCurrentRow,
};

use crate::own_station_results::{OwnStationReplica, consume_bound_event};
use crate::{Error, Result};

/// An exact original Create and the independently replayed Genesis slot at one
/// unchanged current cut. No local record or HTTP submit result proves acceptance.
pub struct CreatorScopeRead {
    pub accepted_create: MlsCreatorBootstrapAcceptedCreate,
    pub snapshot: RealmStateSnapshot,
    pub authority: MlsCreatorBootstrapAuthority,
    pub genesis: Option<CommittedEventFullView>,
}

fn protocol(message: impl ToString) -> Error {
    Error::Protocol(message.to_string())
}

pub async fn read_creator_scope(
    client: &OwnStationResultClient,
    intent: &MlsCreatorBootstrapIntent,
) -> Result<CreatorScopeRead> {
    static NEXT_READ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    intent.validate()?;
    let realm = intent.effective_scope().realm_id();
    let before = client.snapshot_head(realm).await?;
    let snapshot = before.value()?;
    let mut replica = OwnStationReplica::new(realm.clone());
    replica.install_bound_snapshot(&before)?;
    let realm_stream = CommitStreamRef::Realm {
        realm_id: realm.clone(),
    };
    let origin = snapshot
        .current_state_entries
        .iter()
        .find_map(|row| match row {
            TypedCurrentRow::Value {
                selector: CurrentSelector::RealmGenesis,
                source_stream_ref,
                value,
                ..
            } if source_stream_ref == &realm_stream => Some(value),
            _ => None,
        })
        .ok_or_else(|| protocol("creator current cut omits Realm origin"))?;
    let origin: RealmGenesis = serde_json::from_value(origin.clone()).map_err(protocol)?;
    let sequence = NEXT_READ
        .fetch_update(
            std::sync::atomic::Ordering::SeqCst,
            std::sync::atomic::Ordering::SeqCst,
            |value| value.checked_add(1),
        )
        .map_err(|_| protocol("creator query sequence exhausted"))?
        + 1;
    let session = before.session();
    if intent.owner_actor_id().as_account_id() != Some(session.account_id()) {
        return Err(protocol("creator read belongs to another complete Account"));
    }
    let authority = MlsCreatorBootstrapAuthority::own_station(
        snapshot.clone(),
        origin,
        session.account_id().clone(),
        session.grant_id().clone(),
        session.epoch(),
        sequence,
    )?;
    let response = client
        .committed_event_get(intent.scope_create_event_id())
        .await?;
    let CommittedEventView::Full(full) = response.value()? else {
        return Err(protocol("creator original Create is withheld"));
    };
    let full = full.clone();
    let reference = CommittedEventRef {
        event_id: full.event.event_id.clone(),
        commit_id: full.commit.commit_id.clone(),
        stream_ref: full.commit.stream_ref.clone(),
        stream_position: full.commit.stream_position,
    };
    consume_bound_event(client, &reference, response)
        .await?
        .value()?;
    let accepted_create = MlsCreatorBootstrapAcceptedCreate::new(
        intent,
        full.event,
        full.commit,
        realm.digest_suite_code().digest_suite(),
        authority.clone(),
    )?;
    let stream = CommitStreamRef::from_scope(intent.effective_scope(), Some(realm.clone()))?;
    let head = snapshot
        .visible_stream_heads
        .iter()
        .find(|head| head.stream_ref == stream)
        .ok_or_else(|| protocol("creator exact scope has no current head"))?;
    let mut after = None;
    let mut genesis = None;
    let mut bytes = 0usize;
    loop {
        let next = after
            .map_or(Some(0), |value: u64| value.checked_add(1))
            .ok_or_else(|| protocol("creator stream position exhausted"))?;
        if next > head.stream_position {
            break;
        }
        let remaining = head.stream_position - next;
        let request = StreamScanRequest {
            realm_id: realm.clone(),
            stream_ref: stream.clone(),
            direction: StreamScanDirection::After(after),
            limit: remaining.min(255) as u16 + 1,
        };
        let response = client.scan_commit_stream(&request).await?;
        if response
            .value()?
            .readable_floor
            .as_ref()
            .is_some_and(|floor| floor.oldest_position > next)
        {
            return Err(protocol("creator complete original history is unavailable"));
        }
        let page = replica.apply_bound_scan(client, response).await?;
        if page.rows()?.is_empty() {
            return Err(protocol("creator stream ended before its current head"));
        }
        for row in page.rows()? {
            let CommittedEventView::Full(full) = row else {
                return Err(protocol("creator original history is withheld"));
            };
            bytes = bytes
                .checked_add(serde_json::to_vec(full).map_err(protocol)?.len())
                .ok_or_else(|| protocol("creator read capacity overflow"))?;
            if bytes > 64 * 1024 * 1024 {
                return Err(protocol(
                    "creator original history exceeds bounded read capacity",
                ));
            }
            if full.event.kind == EventKind::MlsGenesis
                && full.event.scope_ref == *intent.effective_scope()
                && genesis.replace(full.clone()).is_some()
            {
                return Err(protocol(
                    "creator exact scope has multiple accepted Genesis",
                ));
            }
        }
        after = replica.head(&stream).map(|head| head.stream_position);
    }
    if replica.head(&stream) != Some(head) {
        return Err(Error::AuthorityCutBehind);
    }
    if genesis.is_none() {
        validate_creator_genesis_absence_snapshot(intent, &accepted_create, snapshot)?;
    }
    let after = client.snapshot_head(realm).await?;
    let after = after.value()?;
    if after.governance_generation != snapshot.governance_generation
        || after.visible_stream_heads != snapshot.visible_stream_heads
    {
        return Err(Error::AuthorityCutBehind);
    }
    before.value()?;
    client.check_session()?;
    Ok(CreatorScopeRead {
        accepted_create,
        snapshot: before.into_value()?,
        authority,
        genesis,
    })
}
