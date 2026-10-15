//! Bounded recovery through the accepted authenticated Station. Historical
//! windows, current bootstrap and durable checkpoints retain distinct starts.
//! The host installs returned admitted pages before advancing any local cursor.

use std::collections::BTreeMap;

use arkret_http_client::own_station_results::{BoundOwnStationResponse, OwnStationResultClient};
use arkret_wire::{
    CommitStreamRef, CommittedEventView, RealmId, RealmStateSnapshot, StreamScanRequest,
};

use crate::own_station_results::{OwnStationReplica, OwnStationScanPage};

const MAX_PREFIX_BYTES: usize = 64 * 1024 * 1024;
const MAX_REPLAY_BYTES: usize = 64 * 1024 * 1024;
const SCAN_LIMIT: u16 = 200;
type SnapshotResponse = BoundOwnStationResponse<RealmId, RealmStateSnapshot>;
type CreatorOwnSnapshot = SnapshotResponse;
fn protocol(error: impl std::fmt::Display) -> crate::Error {
    crate::Error::Protocol(error.to_string())
}

pub async fn window_pages(
    client: &OwnStationResultClient,
    realm: &arkret_wire::RealmId,
    current: &SnapshotResponse,
    replica: &mut OwnStationReplica,
    window: &arkret_models_collaboration::sync_frames::account_sync::RealmStreamWindow,
) -> crate::Result<Option<Vec<OwnStationScanPage>>> {
    replica.install_bound_snapshot(current)?;
    let mut after = None;
    let mut pages = Vec::new();
    let mut retained_bytes = 0usize;
    let basis = snapshot_window_basis(window);
    let mut floor_response = None;
    let mut dependencies = BTreeMap::new();
    if let Some(basis) = basis {
        basis.validate().map_err(protocol)?;
        let response = client.snapshot_by_ref(realm, &basis.snapshot_ref).await?;
        crate::own_station_results::consume_bound_snapshot(&response, realm)?;
        for dependency in basis.accepted_dependency_refs.iter().flatten() {
            if dependency.stream_ref == window.stream_ref
                || dependency.stream_ref.realm_id() != realm
            {
                return Err(protocol("own Station floor dependency has wrong scope"));
            }
            if dependencies.contains_key(dependency) {
                continue;
            }
            let original =
                crate::own_station_results::read_window_dependency(client, dependency).await?;
            retained_bytes = retained_bytes
                .checked_add(original.encoded_len()?)
                .ok_or_else(|| protocol("own-Station dependency capacity overflow"))?;
            if retained_bytes > MAX_PREFIX_BYTES {
                return Err(protocol(
                    "own-Station dependencies exceed bounded candidate capacity",
                ));
            }
            dependencies.insert(dependency.clone(), original);
        }
        after = Some(basis.anchor_position);
        floor_response = Some(response);
    }
    loop {
        let next = after.map_or(Ok(0), |position: u64| {
            position
                .checked_add(1)
                .ok_or_else(|| protocol("stream position overflow"))
        })?;
        let remaining = window
            .next_position
            .checked_sub(next)
            .ok_or_else(|| protocol("Account window lies behind its exact basis"))?;
        let request = StreamScanRequest {
            realm_id: realm.clone(),
            stream_ref: window.stream_ref.clone(),
            direction: arkret_wire::StreamScanDirection::After(after),
            limit: remaining.min(u64::from(SCAN_LIMIT)).max(1) as u16,
        };
        let response = client.scan_commit_stream(&request).await?;
        let outcome = response.value()?;
        if let Some(basis) = basis {
            if let Some(snapshot) = floor_response.take() {
                let floor = outcome
                    .readable_floor
                    .as_ref()
                    .ok_or_else(|| protocol("own Station floor scan omits its floor"))?;
                replica.install_bound_floor_predecessor(
                    &window.stream_ref,
                    basis,
                    floor,
                    snapshot,
                    &dependencies,
                )?;
            }
        } else if pages.is_empty()
            && outcome
                .readable_floor
                .as_ref()
                .is_some_and(|floor| floor.oldest_position > 0)
        {
            if window.preview_only == Some(true) {
                return Ok(None);
            }
            return Err(above_genesis_without_basis());
        }
        if remaining == 0 {
            response.value()?;
            break;
        }
        let truncated = outcome.truncated;
        let page = replica.apply_bound_scan(client, response).await?;
        let empty = page.rows()?.is_empty();
        after = replica
            .head(&window.stream_ref)
            .map(|head| head.stream_position);
        retained_bytes = retained_bytes
            .checked_add(serde_json::to_vec(page.rows()?).map_err(protocol)?.len())
            .ok_or_else(|| protocol("own-Station prefix capacity overflow"))?;
        if retained_bytes > MAX_PREFIX_BYTES {
            return Err(protocol(
                "own-Station prefix exceeds bounded candidate capacity",
            ));
        }
        pages.push(page);
        if empty
            || !truncated
            || after.and_then(|position| position.checked_add(1)) == Some(window.next_position)
        {
            break;
        }
    }
    Ok(Some(pages))
}

pub async fn genesis_pages(
    client: &OwnStationResultClient,
    realm: &arkret_wire::RealmId,
    stream: &CommitStreamRef,
    end: u64,
    replica: &mut OwnStationReplica,
) -> crate::Result<Option<Vec<OwnStationScanPage>>> {
    let mut after = None;
    let mut pages = Vec::new();
    let mut retained_bytes = 0usize;
    loop {
        let next = after.map_or(Ok(0), |position: u64| {
            position
                .checked_add(1)
                .ok_or_else(|| protocol("stream position overflow"))
        })?;
        let remaining = end
            .checked_sub(next)
            .ok_or_else(|| protocol("own stream crossed its requested prefix"))?;
        if remaining == 0 {
            break;
        }
        let request = StreamScanRequest {
            realm_id: realm.clone(),
            stream_ref: stream.clone(),
            direction: arkret_wire::StreamScanDirection::After(after),
            limit: remaining.min(u64::from(SCAN_LIMIT)) as u16,
        };
        let response = client.scan_commit_stream(&request).await?;
        if pages.is_empty()
            && response
                .value()?
                .readable_floor
                .as_ref()
                .is_some_and(|floor| floor.oldest_position > 0)
        {
            return Ok(None);
        }
        let truncated = response.value()?.truncated;
        let page = replica.apply_bound_scan(client, response).await?;
        let empty = page.rows()?.is_empty();
        after = replica.head(stream).map(|head| head.stream_position);
        retained_bytes = retained_bytes
            .checked_add(serde_json::to_vec(page.rows()?).map_err(protocol)?.len())
            .ok_or_else(|| protocol("own-Station prefix capacity overflow"))?;
        if retained_bytes > MAX_PREFIX_BYTES {
            return Err(protocol(
                "own-Station prefix exceeds bounded candidate capacity",
            ));
        }
        pages.push(page);
        if empty || !truncated {
            break;
        }
    }
    Ok(Some(pages))
}

pub async fn replay_with_admitted_replica(
    client: &OwnStationResultClient,
    realm: &arkret_wire::RealmId,
    stream: &CommitStreamRef,
    snapshot: &CreatorOwnSnapshot,
    saved: Option<&arkret_wire::CommitStreamHead>,
    mut replica: OwnStationReplica,
) -> crate::Result<(OwnStationReplica, Vec<OwnStationScanPage>)> {
    replica.install_bound_snapshot(snapshot)?;
    let cap = snapshot
        .value()?
        .visible_stream_heads
        .iter()
        .find(|h| &h.stream_ref == stream)
        .ok_or_else(|| protocol("own-Station current omits the followed stream"))?;
    if let Some(saved) = saved {
        if saved.stream_position > cap.stream_position
            || (saved.stream_position == cap.stream_position && saved.commit_id != cap.commit_id)
        {
            return Err(protocol(
                "current cut regresses or forks the durable stream",
            ));
        }
        // Only the same session's admitted original can avoid a new read.
        // Durable coordinates alone still require exact-original admission.
        if replica.head(stream) != Some(saved) {
            replica.restore_checkpoint_head(client, saved).await?;
        }
    }
    if saved.is_none()
        && snapshot
            .value()?
            .retention_and_history_floor
            .stream_floors
            .iter()
            .any(|floor| &floor.stream_ref == stream && floor.oldest_position > 0)
    {
        replica.bootstrap_current_head(client, stream).await?;
        return Ok((replica, Vec::new()));
    }
    let mut after = saved.map(|h| h.stream_position);
    let mut pages = Vec::new();
    let mut retained_bytes = 0usize;
    while after != Some(cap.stream_position) {
        let next = after.map_or(Ok(0), |p| {
            p.checked_add(1).ok_or_else(|| protocol("stream overflow"))
        })?;
        let remaining = cap
            .stream_position
            .checked_add(1)
            .and_then(|end| end.checked_sub(next))
            .ok_or_else(|| protocol("stream exceeded frozen cut"))?;
        let request = StreamScanRequest {
            realm_id: realm.clone(),
            stream_ref: stream.clone(),
            direction: arkret_wire::StreamScanDirection::After(after),
            limit: remaining.min(u64::from(SCAN_LIMIT)) as u16,
        };
        let response = client.scan_commit_stream(&request).await?;
        if after.is_none()
            && response
                .value()?
                .readable_floor
                .as_ref()
                .is_some_and(|f| f.oldest_position > 0)
        {
            // Limited history remains preview. Live bootstrap starts at the
            // verified current cut and admits only its exact original head;
            // none of the unanchored historical rows becomes display history.
            replica.bootstrap_current_head(client, stream).await?;
            break;
        }
        let page = replica.apply_bound_scan(client, response).await?;
        if page.rows()?.is_empty() {
            return Err(protocol("own-Station scan ended before its frozen head"));
        }
        retained_bytes = retained_bytes
            .checked_add(serde_json::to_vec(page.rows()?).map_err(protocol)?.len())
            .ok_or_else(|| protocol("live replay capacity overflow"))?;
        if retained_bytes > MAX_REPLAY_BYTES {
            return Err(protocol("live replay exceeds bounded candidate capacity"));
        }
        after = replica.head(stream).map(|h| h.stream_position);
        pages.push(page);
    }
    if replica.head(stream) != Some(cap) {
        return Err(protocol(
            "own-Station replay does not reach the frozen head",
        ));
    }
    Ok((replica, pages))
}

pub fn snapshot_window_basis(
    window: &arkret_models_collaboration::sync_frames::account_sync::RealmStreamWindow,
) -> Option<&arkret_models_collaboration::sync_frames::account_sync::StreamWindowStartBasis> {
    if window.preview_only == Some(true) {
        return None;
    }
    window.window_start_basis.as_ref()
}

pub fn above_genesis_without_basis() -> crate::Error {
    crate::Error::Protocol(
        "verified stream requires a signed readable-floor snapshot anchor".to_owned(),
    )
}

pub fn require_exact_claimed_rows(
    claimed_rows: &[&CommittedEventView],
    scanned: &[&CommittedEventView],
) -> crate::Result<()> {
    for claimed in claimed_rows {
        let exact = scanned.iter().find(|item| {
            item.commit().stream_ref == claimed.commit().stream_ref
                && item.commit().stream_position == claimed.commit().stream_position
        });
        if exact.is_none_or(|item| *item != *claimed) {
            return Err(crate::Error::Protocol(format!(
                "account frame Commit differs from verified stream row: stream={:?}, position={}, scanned={}, commit_matches={}, claimed_disclosed={}, scanned_disclosed={}",
                claimed.commit().stream_ref,
                claimed.commit().stream_position,
                exact.is_some(),
                exact.is_some_and(|item| item.commit() == claimed.commit()),
                claimed.reducer_input().is_some(),
                exact.is_some_and(|item| item.reducer_input().is_some()),
            )));
        }
    }
    Ok(())
}
