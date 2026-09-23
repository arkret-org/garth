//! Native durable state shared safely by independent client handles.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use arkret_wire::EventId;

use super::{
    AccountCursorCheckpoint, CursorScope, CursorStore, DEFAULT_SEEN_EVENTS_CAPACITY,
    DeliveryErrorClass, DeliveryId, DurableInboxStore, EventCacheStore, MAX_DELIVERY_ERROR_BYTES,
    MAX_PENDING_DELIVERIES, MAX_PENDING_READ, OpaqueCursor, PendingDelivery, StoreState,
};
use crate::{Error, Result};

/// Native JSON store for cursors, recent committed Event identities and stamp floors.
///
/// Each operation takes a sidecar OS lock and reloads the file. Separate
/// `FileStore` instances therefore cannot overwrite one another with stale
/// in-memory snapshots.
#[derive(Clone, Debug)]
pub struct FileStore {
    path: Arc<PathBuf>,
    seen_capacity: usize,
}

impl FileStore {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self> {
        Self::open_with_seen_capacity(path, DEFAULT_SEEN_EVENTS_CAPACITY)
    }

    pub fn open_with_seen_capacity(path: impl Into<PathBuf>, seen_capacity: usize) -> Result<Self> {
        let store = Self {
            path: Arc::new(path.into()),
            seen_capacity: seen_capacity.max(1),
        };
        let _guard = acquire_store_lock(&store.path)?;
        let mut state = load_state(&store.path)?;
        let changed = trim_seen_events(&mut state, store.seen_capacity);
        if changed {
            persist(&store.path, &state)?;
        }
        Ok(store)
    }

    fn read<T>(&self, read: impl FnOnce(&StoreState) -> T) -> Result<T> {
        let _guard = acquire_store_lock(&self.path)?;
        let state = load_state(&self.path)?;
        Ok(read(&state))
    }

    fn mutate<T>(&self, mutation: impl FnOnce(&mut StoreState) -> Result<(T, bool)>) -> Result<T> {
        let _guard = acquire_store_lock(&self.path)?;
        let mut state = load_state(&self.path)?;
        let trimmed = trim_seen_events(&mut state, self.seen_capacity);
        let (value, changed) = mutation(&mut state)?;
        if trimmed || changed {
            persist(&self.path, &state)?;
        }
        Ok(value)
    }

    /// Persist one projected account batch and its cursor checkpoint under one
    /// file lock and one atomic replace. A replay of the same cursor does not
    /// append a second delivery.
    pub fn commit_account_batch(
        &self,
        scope: CursorScope,
        checkpoint: AccountCursorCheckpoint,
        events: Vec<crate::ClientEvent>,
    ) -> Result<()> {
        self.mutate(|state| {
            if state.account_checkpoints.get(&scope) == Some(&checkpoint) {
                return Ok(((), false));
            }
            if !events.is_empty() {
                if state.inbox.len() >= MAX_PENDING_DELIVERIES {
                    return Err(Error::Storage("durable account inbox is full".to_owned()));
                }
                let id = next_inbox_id(state)?;
                state.inbox.insert(
                    id,
                    PendingDelivery {
                        id,
                        scope: scope.clone(),
                        cursor: Some(checkpoint.cursor.clone()),
                        payload: events,
                        attempts: 0,
                        next_attempt_at_ms: None,
                        error_class: None,
                        last_error: None,
                    },
                );
            }
            state
                .cursors
                .insert(scope.clone(), checkpoint.cursor.clone());
            state.account_checkpoints.insert(scope, checkpoint);
            Ok(((), true))
        })
    }

    pub fn has_active_outbound(&self) -> Result<bool> {
        self.read(|state| {
            state
                .outbound
                .items
                .iter()
                .any(|item| !item.status.is_terminal())
        })
    }

    /// Advance and durably commit an HLC floor under the cross-process lock
    /// for synchronous local authoring paths.
    pub fn advance_floor_sync(
        &self,
        scope: crate::StampScope,
        update: crate::StampFloorUpdate,
    ) -> Result<crate::StampFloor> {
        self.mutate(|state| {
            let next = state
                .stamp_floors
                .get(&scope)
                .copied()
                .unwrap_or_default()
                .apply(update)?;
            let changed = state.stamp_floors.get(&scope).copied() != Some(next);
            state.stamp_floors.insert(scope, next);
            Ok((next, changed))
        })
    }
}

fn next_inbox_id(state: &mut StoreState) -> Result<DeliveryId> {
    let next = state.inbox_next_id.max(1);
    let id = DeliveryId::from_stored_u64(next)?;
    state.inbox_next_id = next
        .checked_add(1)
        .ok_or_else(|| Error::Storage("durable account inbox id overflow".to_owned()))?;
    Ok(id)
}

impl DurableInboxStore<Vec<crate::ClientEvent>> for FileStore {
    async fn commit(
        &self,
        scope: CursorScope,
        cursor: Option<OpaqueCursor>,
        payload: Vec<crate::ClientEvent>,
    ) -> Result<DeliveryId> {
        self.mutate(|state| {
            if state.inbox.len() >= MAX_PENDING_DELIVERIES {
                return Err(Error::Storage("durable account inbox is full".to_owned()));
            }
            let id = next_inbox_id(state)?;
            if let Some(ref value) = cursor {
                state.cursors.insert(scope.clone(), value.clone());
            }
            state.inbox.insert(
                id,
                PendingDelivery {
                    id,
                    scope,
                    cursor,
                    payload,
                    attempts: 0,
                    next_attempt_at_ms: None,
                    error_class: None,
                    last_error: None,
                },
            );
            Ok((id, true))
        })
    }

    async fn pending(&self, limit: usize) -> Result<Vec<PendingDelivery<Vec<crate::ClientEvent>>>> {
        self.read(|state| {
            state
                .inbox
                .values()
                .take(limit.clamp(1, MAX_PENDING_READ))
                .cloned()
                .collect()
        })
    }

    async fn ack(&self, id: DeliveryId) -> Result<bool> {
        self.mutate(|state| {
            let removed = state.inbox.remove(&id).is_some();
            Ok((removed, removed))
        })
    }

    async fn retry(
        &self,
        id: DeliveryId,
        next_attempt_at_ms: Option<i64>,
        error_class: DeliveryErrorClass,
        mut error: String,
    ) -> Result<bool> {
        error.truncate(error.floor_char_boundary(MAX_DELIVERY_ERROR_BYTES));
        self.mutate(|state| {
            let Some(delivery) = state.inbox.get_mut(&id) else {
                return Ok((false, false));
            };
            delivery.attempts = delivery.attempts.saturating_add(1);
            delivery.next_attempt_at_ms = next_attempt_at_ms;
            delivery.error_class = Some(error_class);
            delivery.last_error = Some(error);
            Ok((true, true))
        })
    }
}

impl CursorStore for FileStore {
    async fn load(&self, scope: CursorScope) -> Result<Option<OpaqueCursor>> {
        self.read(|state| state.cursors.get(&scope).cloned())
    }

    async fn save(&self, scope: CursorScope, cursor: OpaqueCursor) -> Result<()> {
        self.mutate(|state| {
            let checkpoint_removed = state.account_checkpoints.remove(&scope).is_some();
            if state.cursors.get(&scope) == Some(&cursor) && !checkpoint_removed {
                Ok(((), false))
            } else {
                state.cursors.insert(scope, cursor);
                Ok(((), true))
            }
        })
    }

    async fn clear(&self, scope: CursorScope) -> Result<()> {
        self.mutate(|state| {
            let cursor = state.cursors.remove(&scope).is_some();
            let checkpoint = state.account_checkpoints.remove(&scope).is_some();
            Ok(((), cursor || checkpoint))
        })
    }

    async fn load_account_checkpoint(
        &self,
        scope: CursorScope,
    ) -> Result<Option<AccountCursorCheckpoint>> {
        self.read(|state| state.account_checkpoints.get(&scope).cloned())
    }

    async fn save_account_checkpoint(
        &self,
        scope: CursorScope,
        checkpoint: AccountCursorCheckpoint,
    ) -> Result<()> {
        self.mutate(|state| {
            let changed = state.cursors.get(&scope) != Some(&checkpoint.cursor)
                || state.account_checkpoints.get(&scope) != Some(&checkpoint);
            state
                .cursors
                .insert(scope.clone(), checkpoint.cursor.clone());
            state.account_checkpoints.insert(scope, checkpoint);
            Ok(((), changed))
        })
    }
}

impl EventCacheStore for FileStore {
    async fn seen(&self, event_id: EventId) -> Result<bool> {
        self.read(|state| state.committed_events.contains(&event_id))
    }

    async fn remember(&self, event_id: EventId) -> Result<()> {
        self.mutate(|state| {
            if state.committed_events.contains(&event_id) {
                return Ok(((), false));
            }
            state.committed_events.push_back(event_id);
            trim_seen_events(state, self.seen_capacity);
            Ok(((), true))
        })
    }
}

impl crate::OutboundQueueStore for FileStore {
    fn mutate_outbound<'a, R>(
        &'a self,
        mutation: impl FnOnce(&mut crate::SendQueue) -> Result<R> + crate::MaybeSend + 'a,
    ) -> crate::outbound::BoxOutboundFuture<'a, R>
    where
        R: crate::MaybeSend + 'a,
    {
        Box::pin(async move {
            self.mutate(|state| {
                let mut queue =
                    crate::SendQueue::from_snapshot(std::mem::take(&mut state.outbound));
                let value = mutation(&mut queue)?;
                state.outbound = queue.snapshot();
                Ok((value, true))
            })
        })
    }
}

impl crate::MonotonicStampStore for FileStore {
    async fn load_floor(&self, scope: crate::StampScope) -> Result<Option<crate::StampFloor>> {
        self.read(|state| state.stamp_floors.get(&scope).copied())
    }

    async fn advance_floor(
        &self,
        scope: crate::StampScope,
        update: crate::StampFloorUpdate,
    ) -> Result<crate::StampFloor> {
        self.advance_floor_sync(scope, update)
    }
}

fn trim_seen_events(state: &mut StoreState, capacity: usize) -> bool {
    let mut changed = false;
    while state.committed_events.len() > capacity {
        state.committed_events.pop_front();
        changed = true;
    }
    changed
}

fn lock_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".lock");
    PathBuf::from(name)
}

fn acquire_store_lock(path: &Path) -> Result<File> {
    let lock_path = lock_path(path);
    if let Some(parent) = lock_path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .map_err(|error| Error::Storage(format!("create {}: {error}", parent.display())))?;
    }
    let lock = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(|error| Error::Storage(format!("open {}: {error}", lock_path.display())))?;
    lock.lock()
        .map_err(|error| Error::Storage(format!("lock {}: {error}", lock_path.display())))?;
    Ok(lock)
}

fn load_state(path: &Path) -> Result<StoreState> {
    if !path.exists() {
        return Ok(StoreState::default());
    }
    let bytes = std::fs::read(path)
        .map_err(|error| Error::Storage(format!("read {}: {error}", path.display())))?;
    if bytes.is_empty() {
        return Ok(StoreState::default());
    }
    serde_json::from_slice(&bytes).map_err(Error::CanonicalJson)
}

fn persist(path: &Path, state: &StoreState) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .map_err(|error| Error::Storage(format!("create {}: {error}", parent.display())))?;
    }
    let bytes = serde_json::to_vec(state)?;
    let temporary_path = path.with_extension("garth-tmp");
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&temporary_path)
        .map_err(|error| Error::Storage(format!("open {}: {error}", temporary_path.display())))?;
    file.write_all(&bytes)
        .map_err(|error| Error::Storage(format!("write {}: {error}", path.display())))?;
    file.sync_all()
        .map_err(|error| Error::Storage(format!("sync {}: {error}", temporary_path.display())))?;
    drop(file);
    std::fs::rename(&temporary_path, path).map_err(|error| {
        Error::Storage(format!(
            "replace {} from {}: {error}",
            path.display(),
            temporary_path.display()
        ))
    })
}

#[cfg(test)]
mod inbox_tests {
    use arkret_wire::{AccountId, ActorId, DeviceId, DidCoreId};

    use super::*;

    fn scope() -> CursorScope {
        let principal = DidCoreId::new("ak:did_core:web:agent.example").unwrap();
        let station = DidCoreId::new("ak:did_core:web:station.example").unwrap();
        CursorScope::Account {
            service_id: Some(station.clone()),
            actor_id: ActorId::account(AccountId::new(principal, station)),
            device_id: DeviceId::new("ak:device:01964139-0000-7000-8000-000000000001").unwrap(),
        }
    }

    #[tokio::test]
    async fn account_batch_and_cursor_survive_reopen_without_replay_duplication() {
        let home = tempfile::tempdir().unwrap();
        let path = home.path().join("account.json");
        let checkpoint = AccountCursorCheckpoint {
            cursor: "cursor-one".to_owned(),
            station_cas: crate::StationCasProjection::default(),
        };
        let batch = vec![crate::ClientEvent::AccountUpdates(Default::default())];
        FileStore::open(&path)
            .unwrap()
            .commit_account_batch(scope(), checkpoint.clone(), batch)
            .unwrap();

        let reopened = FileStore::open(&path).unwrap();
        assert_eq!(
            reopened.load_account_checkpoint(scope()).await.unwrap(),
            Some(checkpoint.clone())
        );
        let pending = reopened.pending(32).await.unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].payload.len(), 1);

        reopened
            .commit_account_batch(
                scope(),
                checkpoint,
                vec![crate::ClientEvent::AccountUpdates(Default::default())],
            )
            .unwrap();
        assert_eq!(reopened.pending(32).await.unwrap().len(), 1);
        assert!(reopened.ack(pending[0].id).await.unwrap());
        assert!(
            FileStore::open(&path)
                .unwrap()
                .pending(32)
                .await
                .unwrap()
                .is_empty()
        );
    }
}
