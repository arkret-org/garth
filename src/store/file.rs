//! Default native file-backed [`CursorStore`] + [`EventCacheStore`].
//!
//! A batteries-included durable store for native clients so a consumer does not
//! re-implement one (this converges savfox's hand-written `FileArkretAccountStore`
//! into garth). State is a single JSON file, written atomically (temp + rename)
//! after each mutation. Web clients provide an IndexedDB-backed store instead.

use std::collections::{BTreeMap, VecDeque};
use std::fs::{File, OpenOptions};
use std::future::Future;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use serde::{Deserialize, Serialize};

use super::inbox::{bounded_delivery_error, bounded_pending_limit};
use super::seen_window::{BoundedSeenWindow, DEFAULT_SEEN_EVENTS_CAPACITY};
use super::{
    CursorScope, CursorStore, DeliveryErrorClass, DeliveryId, DurableInboxStore, EventCacheStore,
    OpaqueCursor, PendingDelivery,
};
use crate::protocol::{Error, EventId, Result};
use crate::stamp::{MonotonicStampStore, StampFloor, StampFloorUpdate, StampScope};
use crate::{ClientEvent, OutboundQueueStore};

/// Unit separator used to build a flat, deterministic string key from a
/// structured [`CursorScope`] for the on-disk map.
const SEP: char = '\u{1f}';

/// File-backed durable store. Cheap to clone (shared handle); mutations that
/// actually change state persist the whole state to the backing file.
#[derive(Clone, Debug)]
pub struct FileStore {
    inner: Arc<Mutex<FileStoreInner>>,
    persist: Arc<Mutex<FileStorePersist>>,
    mutation: Arc<tokio::sync::Mutex<()>>,
}

#[derive(Clone, Debug)]
struct FileStoreInner {
    path: PathBuf,
    state: FileState,
    /// Runtime lookup index over `state.seen_event_ids` (not persisted).
    seen_window: BoundedSeenWindow<String>,
    generation: u64,
}

#[derive(Debug, Default)]
struct FileStorePersist {
    generation: u64,
}

#[derive(Debug)]
struct PersistSnapshot {
    path: PathBuf,
    state: FileState,
    generation: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct FileState {
    cursors: BTreeMap<String, OpaqueCursor>,
    /// Insertion-ordered full Event identity dedupe window, oldest first.
    seen_event_ids: VecDeque<String>,
    next_delivery_id: u64,
    deliveries: VecDeque<PendingDelivery>,
    outbound: crate::sync_client::SendQueueSnapshot,
    stamp_floors: BTreeMap<String, StampFloor>,
    accepted_mls_artifacts: crate::VersionedAcceptedMlsArtifactState,
}

impl FileStore {
    /// Open (or create) a store backed by `path`. A missing file starts empty;
    /// an unreadable/corrupt file is a hard error rather than silent data loss.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self> {
        Self::open_with_seen_capacity(path, DEFAULT_SEEN_EVENTS_CAPACITY)
    }

    /// [`Self::open`] with a custom dedupe-window bound (oldest entries are
    /// evicted once the bound is exceeded).
    pub fn open_with_seen_capacity(path: impl Into<PathBuf>, capacity: usize) -> Result<Self> {
        let path = path.into();
        let mut state = load_state(&path)?;
        let seen_event_ids = std::mem::take(&mut state.seen_event_ids);
        let seen_window = BoundedSeenWindow::from_entries(seen_event_ids, capacity);
        state.seen_event_ids = seen_window.entries().clone();
        Ok(Self {
            inner: Arc::new(Mutex::new(FileStoreInner {
                path,
                state,
                seen_window,
                generation: 0,
            })),
            persist: Arc::new(Mutex::new(FileStorePersist::default())),
            mutation: Arc::new(tokio::sync::Mutex::new(())),
        })
    }

    pub fn path(&self) -> Result<PathBuf> {
        self.read(|inner| inner.path.clone())
    }

    /// Return whether the durable outbound queue contains non-terminal work.
    ///
    /// This is a read-only preflight for hosts that periodically drain both
    /// the durable inbox and outbound queue. It deliberately excludes terminal
    /// history (`sent`, `cancelled`, and `superseded`) so an idle host does not
    /// need to build a transport client just to discover `Idle`.
    pub fn has_active_outbound(&self) -> Result<bool> {
        let snapshot = self.read(|inner| inner.state.outbound.clone())?;
        let queue = crate::sync_client::SendQueue::from_snapshot(snapshot)?;
        Ok(!queue.active_items().is_empty())
    }

    /// Synchronous stamp-floor transition for host builders that cannot await.
    /// The same sidecar OS lock and atomic file replace used by async mutations
    /// preserve cross-handle and cross-process uniqueness.
    pub fn advance_stamp_floor_blocking(
        &self,
        scope: StampScope,
        update: StampFloorUpdate,
    ) -> Result<StampFloor> {
        let path = self.path()?;
        let _file_lock = acquire_store_lock(&path)?;
        let mut state = load_state(&path)?;
        let key = stamp_scope_key(&scope);
        let floor = state
            .stamp_floors
            .get(&key)
            .copied()
            .unwrap_or_default()
            .apply(update)?;
        state.stamp_floors.insert(key.clone(), floor);
        persist(&path, &state)?;
        let mut inner = self
            .inner
            .lock()
            .map_err(|error| Error::Protocol(format!("file store lock: {error}")))?;
        inner.state.stamp_floors.insert(key, floor);
        Ok(floor)
    }

    async fn mutate<T>(&self, f: impl FnOnce(&mut FileStoreInner) -> T) -> Result<T> {
        // Serialize clones in-process, then take a stable sidecar lock shared
        // by every handle and process. The data file itself is atomically
        // replaced, so locking that inode would not survive a rename.
        let _mutation = self.mutation.lock().await;
        let _file_lock = self.acquire_exclusive_lock().await?;
        let (out, candidate, snapshot) = self.stage_mutation(f)?;
        // Keep the OS lock alive through the complete durable commit. This is
        // intentionally synchronous: cancelling the async caller must not
        // detach a background writer after the cross-process lock is dropped.
        if let Some(snapshot) = snapshot {
            self.persist_snapshot(snapshot)?;
        }
        let mut guard = self
            .inner
            .lock()
            .map_err(|err: PoisonError<_>| Error::Protocol(format!("file store lock: {err}")))?;
        *guard = candidate;
        Ok(out)
    }

    async fn acquire_exclusive_lock(&self) -> Result<File> {
        let path = self.path()?;
        tokio::task::spawn_blocking(move || acquire_store_lock(&path))
            .await
            .map_err(|err| Error::Protocol(format!("file store lock task: {err}")))?
    }

    fn stage_mutation<T>(
        &self,
        f: impl FnOnce(&mut FileStoreInner) -> T,
    ) -> Result<(T, FileStoreInner, Option<PersistSnapshot>)> {
        let guard = self
            .inner
            .lock()
            .map_err(|err: PoisonError<_>| Error::Protocol(format!("file store lock: {err}")))?;
        let path = guard.path.clone();
        let capacity = guard.seen_window.capacity();
        let generation = guard.generation;
        drop(guard);
        let path_exists = path.exists();
        let mut state = load_state(&path)?;
        let seen_event_ids = std::mem::take(&mut state.seen_event_ids);
        let seen_window = BoundedSeenWindow::from_entries(seen_event_ids, capacity);
        state.seen_event_ids = seen_window.entries().clone();
        let before = serde_json::to_vec(&state)
            .map_err(|err| Error::Protocol(format!("serialize file store: {err}")))?;
        let mut candidate = FileStoreInner {
            path,
            state,
            seen_window,
            generation,
        };
        let out = f(&mut candidate);
        let after = serde_json::to_vec(&candidate.state)
            .map_err(|err| Error::Protocol(format!("serialize file store: {err}")))?;
        if path_exists && before == after {
            return Ok((out, candidate, None));
        }
        candidate.generation = candidate
            .generation
            .checked_add(1)
            .ok_or_else(|| Error::Protocol("file store generation overflow".to_owned()))?;
        let snapshot = PersistSnapshot {
            path: candidate.path.clone(),
            state: candidate.state.clone(),
            generation: candidate.generation,
        };
        Ok((out, candidate, Some(snapshot)))
    }

    fn persist_snapshot(&self, snapshot: PersistSnapshot) -> Result<()> {
        let mut guard = self.persist.lock().map_err(|err: PoisonError<_>| {
            Error::Protocol(format!("file store persist lock: {err}"))
        })?;
        if guard.generation >= snapshot.generation {
            return Ok(());
        }
        persist(&snapshot.path, &snapshot.state)?;
        guard.generation = snapshot.generation;
        Ok(())
    }

    fn read<T>(&self, f: impl FnOnce(&FileStoreInner) -> T) -> Result<T> {
        let guard = self
            .inner
            .lock()
            .map_err(|err: PoisonError<_>| Error::Protocol(format!("file store lock: {err}")))?;
        Ok(f(&guard))
    }
}

fn store_lock_path(path: &Path) -> PathBuf {
    let mut lock = path.as_os_str().to_owned();
    lock.push(".lock");
    PathBuf::from(lock)
}

fn acquire_store_lock(path: &Path) -> Result<File> {
    let lock_path = store_lock_path(path);
    if let Some(parent) = lock_path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).map_err(|err| {
            Error::Protocol(format!(
                "create file store lock parent {}: {err}",
                parent.display()
            ))
        })?;
    }
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(|err| {
            Error::Protocol(format!(
                "open file store lock {}: {err}",
                lock_path.display()
            ))
        })?;
    file.lock().map_err(|err| {
        Error::Protocol(format!(
            "acquire file store lock {}: {err}",
            lock_path.display()
        ))
    })?;
    Ok(file)
}

fn scope_key(scope: &CursorScope) -> String {
    fn did(value: &Option<crate::protocol::DidCoreId>) -> String {
        value
            .as_ref()
            .map(|d| d.as_str().to_owned())
            .unwrap_or_default()
    }
    match scope {
        CursorScope::Account {
            service_id,
            actor_id,
            device_id,
        } => format!(
            "account{SEP}{}{SEP}{}{SEP}{}",
            did(service_id),
            actor_id.as_str(),
            device_id.as_str()
        ),
        CursorScope::RealmEvents {
            service_id,
            realm_id,
        } => format!("realm{SEP}{}{SEP}{}", did(service_id), realm_id.as_str()),
        CursorScope::DeviceMessages {
            service_id,
            actor_id,
            device_id,
        } => format!(
            "device_messages{SEP}{}{SEP}{}{SEP}{}",
            did(service_id),
            actor_id.as_str(),
            device_id.as_str()
        ),
    }
}

fn stamp_scope_key(scope: &StampScope) -> String {
    let service = scope
        .service_id
        .as_ref()
        .map(|d| d.as_str().to_owned())
        .unwrap_or_default();
    format!(
        "stamp{SEP}{}{SEP}{}{SEP}{}{SEP}{}",
        service,
        scope.actor_id.as_str(),
        scope.device_id.as_str(),
        scope.realm_id.as_str()
    )
}

fn load_state(path: &Path) -> Result<FileState> {
    if !path.exists() {
        return Ok(FileState::default());
    }
    let bytes = std::fs::read(path)
        .map_err(|err| Error::Protocol(format!("read file store {}: {err}", path.display())))?;
    if bytes.is_empty() {
        return Ok(FileState::default());
    }
    serde_json::from_slice(&bytes)
        .map_err(|err| Error::Protocol(format!("parse file store {}: {err}", path.display())))
}

fn persist(path: &Path, state: &FileState) -> Result<()> {
    let bytes = serde_json::to_vec(state)
        .map_err(|err| Error::Protocol(format!("serialize file store: {err}")))?;
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).map_err(|err| {
            Error::Protocol(format!(
                "create file store parent {}: {err}",
                parent.display()
            ))
        })?;
    }
    // Atomic replace: write and sync a sibling temp, then rename over the
    // target so a crash mid-write never leaves a half-written store.
    let tmp = path.with_extension("tmp");
    {
        let mut file = std::fs::File::create(&tmp).map_err(|err| {
            Error::Protocol(format!("create file store {}: {err}", tmp.display()))
        })?;
        file.write_all(&bytes)
            .map_err(|err| Error::Protocol(format!("write file store {}: {err}", tmp.display())))?;
        file.sync_all()
            .map_err(|err| Error::Protocol(format!("sync file store {}: {err}", tmp.display())))?;
    }
    std::fs::rename(&tmp, path)
        .map_err(|err| Error::Protocol(format!("commit file store {}: {err}", path.display())))?;
    Ok(())
}

impl CursorStore for FileStore {
    fn load(&self, scope: CursorScope) -> impl Future<Output = Result<Option<OpaqueCursor>>> + '_ {
        async move { self.read(|inner| inner.state.cursors.get(&scope_key(&scope)).cloned()) }
    }

    fn save(
        &self,
        scope: CursorScope,
        cursor: OpaqueCursor,
    ) -> impl Future<Output = Result<()>> + '_ {
        async move {
            self.mutate(|inner| {
                inner.state.cursors.insert(scope_key(&scope), cursor);
            })
            .await
        }
    }

    fn clear(&self, scope: CursorScope) -> impl Future<Output = Result<()>> + '_ {
        async move {
            self.mutate(|inner| {
                inner.state.cursors.remove(&scope_key(&scope));
            })
            .await
        }
    }
}

impl EventCacheStore for FileStore {
    fn seen(&self, event_id: EventId) -> impl Future<Output = Result<bool>> + '_ {
        async move { self.read(|inner| inner.seen_window.contains(event_id.as_str())) }
    }

    fn remember(&self, event_id: EventId) -> impl Future<Output = Result<()>> + '_ {
        async move {
            self.mutate(|inner| {
                let identity = event_id.to_string();
                if inner.seen_window.remember(identity) {
                    inner.state.seen_event_ids = inner.seen_window.entries().clone();
                }
            })
            .await
        }
    }
}

impl OutboundQueueStore for FileStore {
    fn mutate_outbound<'a, R>(
        &'a self,
        mutation: impl FnOnce(&mut crate::sync_client::SendQueue) -> Result<R> + crate::MaybeSend + 'a,
    ) -> crate::outbound::BoxOutboundFuture<'a, R>
    where
        R: crate::MaybeSend + 'a,
    {
        Box::pin(async move {
            self.mutate(|inner| {
                let mut queue =
                    crate::sync_client::SendQueue::from_snapshot(inner.state.outbound.clone())?;
                let output = mutation(&mut queue)?;
                inner.state.outbound = queue.snapshot();
                Ok(output)
            })
            .await?
        })
    }
}

impl DurableInboxStore for FileStore {
    fn commit(
        &self,
        scope: CursorScope,
        cursor: Option<OpaqueCursor>,
        events: Vec<ClientEvent>,
    ) -> impl Future<Output = Result<Option<DeliveryId>>> + '_ {
        async move {
            self.mutate(|inner| {
                if !events.is_empty()
                    && inner.state.deliveries.len() >= super::MAX_PENDING_DELIVERIES
                {
                    return Err(Error::Protocol(
                        "durable inbox capacity reached; acknowledge pending deliveries before polling"
                            .to_owned(),
                    ));
                }
                match cursor.clone() {
                    Some(cursor) => {
                        inner.state.cursors.insert(scope_key(&scope), cursor);
                    }
                    None => {
                        inner.state.cursors.remove(&scope_key(&scope));
                    }
                }
                if events.is_empty() {
                    return Ok(None);
                }
                inner.state.next_delivery_id = inner
                    .state
                    .next_delivery_id
                    .checked_add(1)
                    .ok_or_else(|| Error::Protocol("delivery id overflow".to_owned()))?;
                let id = DeliveryId::new(inner.state.next_delivery_id);
                inner.state.deliveries.push_back(PendingDelivery {
                    id,
                    scope,
                    cursor,
                    events,
                    attempts: 0,
                    next_attempt_at_ms: None,
                    error_class: None,
                    last_error: None,
                });
                Ok(Some(id))
            })
            .await?
        }
    }

    fn pending(&self, limit: usize) -> impl Future<Output = Result<Vec<PendingDelivery>>> + '_ {
        async move {
            self.read(|inner| {
                inner
                    .state
                    .deliveries
                    .iter()
                    .take(bounded_pending_limit(limit))
                    .cloned()
                    .collect()
            })
        }
    }

    fn ack(&self, id: DeliveryId) -> impl Future<Output = Result<bool>> + '_ {
        async move {
            self.mutate(|inner| {
                let before = inner.state.deliveries.len();
                inner.state.deliveries.retain(|delivery| delivery.id != id);
                inner.state.deliveries.len() != before
            })
            .await
        }
    }

    fn retry(
        &self,
        id: DeliveryId,
        next_attempt_at_ms: Option<i64>,
        error_class: DeliveryErrorClass,
        error: String,
    ) -> impl Future<Output = Result<bool>> + '_ {
        async move {
            self.mutate(|inner| {
                let Some(delivery) = inner
                    .state
                    .deliveries
                    .iter_mut()
                    .find(|delivery| delivery.id == id)
                else {
                    return Ok(false);
                };
                delivery.attempts = delivery
                    .attempts
                    .checked_add(1)
                    .ok_or_else(|| Error::Protocol("delivery attempts overflow".to_owned()))?;
                delivery.next_attempt_at_ms = next_attempt_at_ms;
                delivery.error_class = Some(error_class);
                delivery.last_error = Some(bounded_delivery_error(error));
                Ok(true)
            })
            .await?
        }
    }
}

impl crate::AcceptedMlsArtifactStore for FileStore {
    fn load_accepted_mls_artifacts(&self) -> Result<crate::VersionedAcceptedMlsArtifactState> {
        self.read(|inner| crate::VersionedAcceptedMlsArtifactState {
            revision: inner.state.accepted_mls_artifacts.revision,
            snapshot: inner.state.accepted_mls_artifacts.snapshot.clone(),
        })
    }

    fn compare_and_swap_accepted_mls_artifacts<'a>(
        &'a self,
        expected_revision: u64,
        snapshot: &'a crate::AcceptedMlsArtifactState,
    ) -> impl Future<Output = Result<bool>> + crate::MaybeSend + 'a {
        async move {
            self.mutate(|inner| {
                if inner.state.accepted_mls_artifacts.revision != expected_revision {
                    return Ok(false);
                }
                inner.state.accepted_mls_artifacts.revision = inner
                    .state
                    .accepted_mls_artifacts
                    .revision
                    .checked_add(1)
                    .ok_or_else(|| {
                        Error::Protocol("accepted MLS artifact revision overflow".to_owned())
                    })?;
                inner.state.accepted_mls_artifacts.snapshot = snapshot.clone();
                Ok(true)
            })
            .await?
        }
    }
}

impl MonotonicStampStore for FileStore {
    fn load_floor(
        &self,
        scope: StampScope,
    ) -> impl Future<Output = Result<Option<StampFloor>>> + '_ {
        async move {
            let _file_lock = self.acquire_exclusive_lock().await?;
            let state = load_state(&self.path()?)?;
            Ok(state.stamp_floors.get(&stamp_scope_key(&scope)).copied())
        }
    }

    fn advance_floor(
        &self,
        scope: StampScope,
        update: StampFloorUpdate,
    ) -> impl Future<Output = Result<StampFloor>> + '_ {
        async move {
            self.mutate(|inner| {
                let key = stamp_scope_key(&scope);
                let floor = inner
                    .state
                    .stamp_floors
                    .get(&key)
                    .copied()
                    .unwrap_or_default()
                    .apply(update)?;
                inner.state.stamp_floors.insert(key, floor);
                Ok(floor)
            })
            .await?
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{
        DeviceId, DidCoreId, EventId, EventKind, Hlc, NotificationDelta, NotificationDeltaAction,
        NotificationId, RealmId, ScopeRef,
    };
    use crate::{AcceptedMlsArtifactStore, DurableAcceptedMlsArtifact, QueuedMlsLocalCheckpoint};

    fn temp_path(name: &str) -> PathBuf {
        // Index-derived unique name (no wall-clock / rng in this crate).
        std::env::temp_dir().join(format!("garth-filestore-test-{name}.json"))
    }

    fn account_scope() -> CursorScope {
        CursorScope::Account {
            service_id: None,
            actor_id: DidCoreId::new("ak:did_core:webvh:z6mkfixture:alice.example").unwrap(),
            device_id: DeviceId::new("ak:device:01904100-0000-7000-8000-000000000001").unwrap(),
        }
    }

    fn realm_scope() -> CursorScope {
        CursorScope::RealmEvents {
            service_id: None,
            realm_id: RealmId::new("ak:realm:AfuGzJo578BJKgyC0bGwDqxsCPVeZViXjoIRGcW7-S6x")
                .unwrap(),
        }
    }

    fn stamp_scope() -> StampScope {
        StampScope {
            service_id: None,
            actor_id: DidCoreId::new("ak:did_core:webvh:z6mkfixture:alice.example").unwrap(),
            device_id: DeviceId::new("ak:device:01904100-0000-7000-8000-000000000001").unwrap(),
            realm_id: RealmId::new("ak:realm:AfuGzJo578BJKgyC0bGwDqxsCPVeZViXjoIRGcW7-S6x")
                .unwrap(),
        }
    }

    #[tokio::test]
    async fn accepted_mls_ready_checkpoint_survives_process_reopen() {
        let path = temp_path("accepted-mls-reopen");
        let _ = std::fs::remove_file(&path);
        let realm_id =
            RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19").unwrap();
        let scope = ScopeRef::Realm {
            realm_id: realm_id.clone(),
        };
        let group_id = scope.canonical_mls_group_id().unwrap();
        let event = arkret_wire::test_support::raw_event(
            EventKind::MlsGenesis.as_str(),
            scope.clone(),
            DidCoreId::new("ak:did_core:webvh:z6mkfixture:alice.example").unwrap(),
            DidCoreId::new("ak:did_core:webvh:z6mkfixture:server.example").unwrap(),
            1,
            Hlc::new("01970e589d21-0001-a13f9c2e").unwrap(),
            serde_json::json!({}),
        )
        .unwrap();
        let event_key = event.event_id.to_string();
        let mut snapshot = crate::AcceptedMlsArtifactState::default();
        snapshot.artifacts.insert(
            event_key.clone(),
            DurableAcceptedMlsArtifact {
                transition_head: arkret_models_crypto::MlsEpochHead {
                    transition_ref: event.event_id.clone(),
                    transition_event_digest: event.event_id.event_digest(),
                    mls_transition_digest: event.event_id.event_digest(),
                    effective_scope: scope.clone(),
                    mls_group_id: arkret_wire::Base64UrlString::new(group_id.clone()).unwrap(),
                    previous_epoch: 0,
                    next_epoch: 0,
                    content_scheme: arkret_wire::ContentScheme::MlsRfc9420,
                },
                event_digest: event.event_id.identity_key().event_digest(),
                winning_transition_ref: event.event_id.clone(),
                event,
                history_secret: crate::QueuedMlsHistorySecret {
                    group_id: group_id.clone(),
                    epoch: 0,
                    transition_ref: EventId::new(event_key.clone()).unwrap(),
                    ciphertext: vec![4],
                },
                snapshot: QueuedMlsLocalCheckpoint {
                    realm_id: realm_id.to_string(),
                    group_id: group_id.clone(),
                    epoch: 0,
                    admission_epoch: 0,
                    group_state_event_id: EventId::new(event_key.clone()).ok(),
                    salt_hex: "01".to_owned(),
                    ciphertext_hex: "02".to_owned(),
                    mac_hex: "03".to_owned(),
                    recorded_at: chrono::Utc::now(),
                    epoch_started_at: chrono::Utc::now(),
                    app_messages_observed: 0,
                    aead_version: 1,
                },
            },
        );
        snapshot.ready_groups.insert(
            format!("{}\u{1f}{group_id}", serde_json::to_string(&scope).unwrap()),
            event_key.clone(),
        );
        snapshot.history_secrets.insert(
            format!("{group_id}\u{1f}{:020}", 0),
            crate::QueuedMlsHistorySecret {
                group_id: group_id.clone(),
                epoch: 0,
                transition_ref: EventId::new(event_key).unwrap(),
                ciphertext: vec![4],
            },
        );
        {
            let store = FileStore::open(&path).unwrap();
            assert!(
                store
                    .compare_and_swap_accepted_mls_artifacts(0, &snapshot)
                    .await
                    .unwrap()
            );
        }
        let reopened = FileStore::open(&path).unwrap();
        let durable = reopened.load_accepted_mls_artifacts().unwrap();
        assert_eq!(durable.revision, 1);
        assert_eq!(durable.snapshot, snapshot);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("json.lock"));
    }

    #[tokio::test]
    async fn stamp_floor_persists_across_reopen() {
        let path = temp_path("stamp-floor-roundtrip");
        let _ = std::fs::remove_file(&path);
        let floor = StampFloor {
            hlc_physical_ms: 0x01970e589d21,
            hlc_logical: 7,
        };
        {
            let store = FileStore::open(&path).unwrap();
            store
                .advance_floor(
                    stamp_scope(),
                    StampFloorUpdate::Observe(crate::stamp::RemoteStamp {
                        hlc: Some(crate::protocol::Hlc::new("01970e589d21-0007-a13f9c2e").unwrap()),
                    }),
                )
                .await
                .unwrap();
        }
        let reopened = FileStore::open(&path).unwrap();
        assert_eq!(
            reopened.load_floor(stamp_scope()).await.unwrap(),
            Some(floor)
        );
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn persists_and_reloads_cursor_across_reopen() {
        let path = temp_path("cursor-roundtrip");
        let _ = std::fs::remove_file(&path);
        {
            let store = FileStore::open(&path).unwrap();
            store
                .save(account_scope(), "ak:cursor:acct".to_owned())
                .await
                .unwrap();
            store
                .save(realm_scope(), "ak:cursor:realm".to_owned())
                .await
                .unwrap();
        }
        // Reopen from the same file: state survives the process boundary.
        let reopened = FileStore::open(&path).unwrap();
        assert_eq!(
            reopened.load(account_scope()).await.unwrap().as_deref(),
            Some("ak:cursor:acct")
        );
        assert_eq!(
            reopened.load(realm_scope()).await.unwrap().as_deref(),
            Some("ak:cursor:realm")
        );
        // Scopes do not collide.
        reopened.clear(account_scope()).await.unwrap();
        assert!(reopened.load(account_scope()).await.unwrap().is_none());
        assert_eq!(
            reopened.load(realm_scope()).await.unwrap().as_deref(),
            Some("ak:cursor:realm")
        );
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn dedupe_survives_reopen() {
        let path = temp_path("dedupe-roundtrip");
        let _ = std::fs::remove_file(&path);
        let event = event_id(0xaa);
        {
            let store = FileStore::open(&path).unwrap();
            assert!(!store.seen(event.clone()).await.unwrap());
            store.remember(event.clone()).await.unwrap();
            assert!(store.seen(event.clone()).await.unwrap());
        }
        let reopened = FileStore::open(&path).unwrap();
        assert!(reopened.seen(event).await.unwrap());
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn no_op_mutations_do_not_replace_the_state_file() {
        let path = temp_path("no-op-mutations");
        let _ = std::fs::remove_file(&path);
        let store = FileStore::open(&path).unwrap();
        let scope = account_scope();
        let cursor = "ak:cursor:stable".to_owned();
        let event = event_id(77);

        store.save(scope.clone(), cursor.clone()).await.unwrap();
        store.remember(event.clone()).await.unwrap();
        let before_bytes = std::fs::read(&path).unwrap();
        let before_modified = std::fs::metadata(&path).unwrap().modified().unwrap();
        let before_generation = store.persist.lock().unwrap().generation;

        // Ensure a replacement would be observable even on filesystems with a
        // relatively coarse modification-time clock.
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        store.save(scope.clone(), cursor.clone()).await.unwrap();
        store.commit(scope, Some(cursor), Vec::new()).await.unwrap();
        store.remember(event).await.unwrap();
        store.mutate_outbound(|_| Ok::<_, Error>(())).await.unwrap();
        assert!(!store.ack(DeliveryId::new(999)).await.unwrap());

        assert_eq!(std::fs::read(&path).unwrap(), before_bytes);
        assert_eq!(
            std::fs::metadata(&path).unwrap().modified().unwrap(),
            before_modified
        );
        assert_eq!(store.persist.lock().unwrap().generation, before_generation);
        assert!(!store.has_active_outbound().unwrap());
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn concurrent_mutations_reopen_with_complete_state() {
        let path = temp_path("concurrent-mutations");
        let _ = std::fs::remove_file(&path);
        let store = FileStore::open(&path).unwrap();

        let account_save = store.save(account_scope(), "ak:cursor:account".to_owned());
        let realm_save = store.save(realm_scope(), "ak:cursor:realm".to_owned());
        let (account_result, realm_result) = tokio::join!(account_save, realm_save);
        account_result.unwrap();
        realm_result.unwrap();

        let reopened = FileStore::open(&path).unwrap();
        assert_eq!(
            reopened.load(account_scope()).await.unwrap().as_deref(),
            Some("ak:cursor:account")
        );
        assert_eq!(
            reopened.load(realm_scope()).await.unwrap().as_deref(),
            Some("ak:cursor:realm")
        );
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn stale_snapshot_does_not_overwrite_newer_generation() {
        let path = temp_path("stale-snapshot");
        let _ = std::fs::remove_file(&path);
        let store = FileStore::open(&path).unwrap();
        let key = scope_key(&account_scope());

        let mut older = FileState::default();
        older
            .cursors
            .insert(key.clone(), "ak:cursor:older".to_owned());
        let mut newer = older.clone();
        newer.cursors.insert(key, "ak:cursor:newer".to_owned());

        store
            .persist_snapshot(PersistSnapshot {
                path: path.clone(),
                state: newer,
                generation: 2,
            })
            .unwrap();
        store
            .persist_snapshot(PersistSnapshot {
                path: path.clone(),
                state: older,
                generation: 1,
            })
            .unwrap();

        let reopened = FileStore::open(&path).unwrap();
        assert_eq!(
            reopened.load(account_scope()).await.unwrap().as_deref(),
            Some("ak:cursor:newer")
        );
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn save_propagates_blocking_persist_errors() {
        let parent = std::env::temp_dir().join("garth-filestore-test-invalid-parent");
        let path = parent.join("store.json");
        let _ = std::fs::remove_file(&parent);
        let _ = std::fs::remove_dir_all(&parent);
        std::fs::write(&parent, b"not a directory").unwrap();
        let store = FileStore::open(&path).unwrap();

        let err = store
            .save(account_scope(), "ak:cursor:account".to_owned())
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("file store"),
            "unexpected error: {err}"
        );
        assert_eq!(store.load(account_scope()).await.unwrap(), None);
        let _ = std::fs::remove_file(parent);
    }

    fn event_id(n: usize) -> EventId {
        EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [n as u8; 32])
    }

    #[tokio::test]
    async fn dedupe_window_evicts_oldest_beyond_capacity() {
        let path = temp_path("dedupe-capacity");
        let _ = std::fs::remove_file(&path);
        let store = FileStore::open_with_seen_capacity(&path, 3).unwrap();
        for n in 0..4 {
            store.remember(event_id(n)).await.unwrap();
        }
        // Oldest entry evicted, newest three retained.
        assert!(!store.seen(event_id(0)).await.unwrap());
        for n in 1..4 {
            assert!(store.seen(event_id(n)).await.unwrap());
        }
        // Eviction survives reopen (bounded state is what got persisted).
        let reopened = FileStore::open_with_seen_capacity(&path, 3).unwrap();
        assert!(!reopened.seen(event_id(0)).await.unwrap());
        assert!(reopened.seen(event_id(3)).await.unwrap());
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn reopen_with_smaller_capacity_trims_oldest() {
        let path = temp_path("dedupe-shrink");
        let _ = std::fs::remove_file(&path);
        {
            let store = FileStore::open(&path).unwrap();
            for n in 0..4 {
                store.remember(event_id(n)).await.unwrap();
            }
        }
        let reopened = FileStore::open_with_seen_capacity(&path, 2).unwrap();
        assert!(!reopened.seen(event_id(0)).await.unwrap());
        assert!(!reopened.seen(event_id(1)).await.unwrap());
        assert!(reopened.seen(event_id(2)).await.unwrap());
        assert!(reopened.seen(event_id(3)).await.unwrap());
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn inbox_crash_points_preserve_at_least_once_delivery() {
        let path = temp_path("inbox-crash-reopen");
        let _ = std::fs::remove_file(&path);
        let scope = account_scope();
        let event = ClientEvent::Notification(NotificationDelta {
            id: NotificationId::new("ak:notification:01964137-0000-7000-8000-000000000012")
                .unwrap(),
            action: NotificationDeltaAction::Remove,
            data: None,
        });

        // Crash before commit: neither cursor nor delivery may appear.
        let before_commit = FileStore::open(&path).unwrap();
        assert!(before_commit.load(scope.clone()).await.unwrap().is_none());
        assert!(before_commit.pending(10).await.unwrap().is_empty());
        drop(before_commit);

        let delivery_id = {
            let store = FileStore::open(&path).unwrap();
            store
                .commit(
                    scope.clone(),
                    Some("ak:cursor:committed".to_owned()),
                    vec![event],
                )
                .await
                .unwrap()
                .unwrap()
        };

        let reopened = FileStore::open(&path).unwrap();
        assert_eq!(
            reopened.load(scope.clone()).await.unwrap().as_deref(),
            Some("ak:cursor:committed")
        );
        let pending = reopened.pending(10).await.unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].id, delivery_id);
        assert_eq!(pending[0].events.len(), 1);

        assert!(
            reopened
                .retry(
                    delivery_id,
                    Some(1234),
                    DeliveryErrorClass::Processing,
                    "temporary failure".to_owned(),
                )
                .await
                .unwrap()
        );
        let retried = reopened.pending(10).await.unwrap();
        assert_eq!(retried[0].attempts, 1);
        assert_eq!(retried[0].next_attempt_at_ms, Some(1234));
        drop(reopened);

        // Crash during worker retry: attempt/deadline and the delivery survive.
        let after_retry = FileStore::open(&path).unwrap();
        let retried = after_retry.pending(10).await.unwrap();
        assert_eq!(retried[0].id, delivery_id);
        assert_eq!(retried[0].attempts, 1);
        assert!(after_retry.ack(delivery_id).await.unwrap());
        drop(after_retry);

        // Crash after ack: completion is durable and ack remains idempotent.
        let after_ack = FileStore::open(&path).unwrap();
        assert!(after_ack.pending(10).await.unwrap().is_empty());
        assert!(!after_ack.ack(delivery_id).await.unwrap());
        assert_eq!(
            after_ack.load(scope).await.unwrap().as_deref(),
            Some("ak:cursor:committed")
        );
        let _ = std::fs::remove_file(&path);
    }
}
