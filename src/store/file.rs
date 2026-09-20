//! Native durable state shared safely by independent client handles.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use arkret_wire::EventId;

use super::{
    AccountCursorCheckpoint, CursorScope, CursorStore, DEFAULT_SEEN_EVENTS_CAPACITY,
    EventCacheStore, OpaqueCursor, StoreState,
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
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
        .map_err(|error| Error::Storage(format!("open {}: {error}", path.display())))?;
    file.write_all(&bytes)
        .map_err(|error| Error::Storage(format!("write {}: {error}", path.display())))?;
    file.sync_all()
        .map_err(|error| Error::Storage(format!("sync {}: {error}", path.display())))
}
