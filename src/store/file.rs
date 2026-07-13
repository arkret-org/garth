//! Default native file-backed [`CursorStore`] + [`EventCacheStore`].
//!
//! A batteries-included durable store for native clients so a consumer does not
//! re-implement one (this converges savfox's hand-written `FileArkretAccountStore`
//! into garth). State is a single JSON file, written atomically (temp + rename)
//! after each mutation. Web clients provide an IndexedDB-backed store instead.

use std::collections::{BTreeMap, VecDeque};
use std::future::Future;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use arkret_core::{Error, EventId, Result};
use serde::{Deserialize, Serialize};

use super::inbox::{bounded_delivery_error, bounded_pending_limit};
use super::seen_window::{BoundedSeenWindow, DEFAULT_SEEN_EVENTS_CAPACITY};
use super::{
    CursorScope, CursorStore, DeliveryErrorClass, DeliveryId, DurableInboxStore, EventCacheStore,
    OpaqueCursor, PendingDelivery,
};
use crate::{ClientEvent, OutboundQueueStore};

/// Unit separator used to build a flat, deterministic string key from a
/// structured [`CursorScope`] for the on-disk map.
const SEP: char = '\u{1f}';

/// File-backed durable store. Cheap to clone (shared handle); every mutation
/// persists the whole state to the backing file.
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
    /// Runtime lookup index over `state.seen_events` (not persisted).
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
    #[serde(default)]
    cursors: BTreeMap<String, OpaqueCursor>,
    /// Insertion-ordered dedupe window, oldest first. Reads legacy files that
    /// persisted a sorted set (any JSON array of strings deserializes here).
    #[serde(default)]
    seen_events: VecDeque<String>,
    #[serde(default)]
    next_delivery_id: u64,
    #[serde(default)]
    deliveries: VecDeque<PendingDelivery>,
    #[serde(default)]
    outbound: arkret::sync_client::SendQueueSnapshot,
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
        let seen_events = std::mem::take(&mut state.seen_events);
        let seen_window = BoundedSeenWindow::from_entries(seen_events, capacity);
        state.seen_events = seen_window.entries().clone();
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

    pub async fn ensure_created(&self) -> Result<()> {
        self.mutate(|_| ()).await
    }

    async fn mutate<T>(&self, f: impl FnOnce(&mut FileStoreInner) -> T) -> Result<T> {
        // Serialize the complete transaction and do not publish candidate
        // state to readers until its durable snapshot has succeeded.
        let _mutation = self.mutation.lock().await;
        let (out, candidate, snapshot) = self.stage_mutation(f)?;
        self.persist_snapshot(snapshot).await?;
        let mut guard = self
            .inner
            .lock()
            .map_err(|err: PoisonError<_>| Error::Protocol(format!("file store lock: {err}")))?;
        *guard = candidate;
        Ok(out)
    }

    fn stage_mutation<T>(
        &self,
        f: impl FnOnce(&mut FileStoreInner) -> T,
    ) -> Result<(T, FileStoreInner, PersistSnapshot)> {
        let guard = self
            .inner
            .lock()
            .map_err(|err: PoisonError<_>| Error::Protocol(format!("file store lock: {err}")))?;
        let mut candidate = guard.clone();
        drop(guard);
        let out = f(&mut candidate);
        candidate.generation = candidate
            .generation
            .checked_add(1)
            .ok_or_else(|| Error::Protocol("file store generation overflow".to_owned()))?;
        let snapshot = PersistSnapshot {
            path: candidate.path.clone(),
            state: candidate.state.clone(),
            generation: candidate.generation,
        };
        Ok((out, candidate, snapshot))
    }

    async fn persist_snapshot(&self, snapshot: PersistSnapshot) -> Result<()> {
        let persist_state = self.persist.clone();
        tokio::task::spawn_blocking(move || {
            let mut guard = persist_state.lock().map_err(|err: PoisonError<_>| {
                Error::Protocol(format!("file store persist lock: {err}"))
            })?;
            if guard.generation >= snapshot.generation {
                return Ok(());
            }
            persist(&snapshot.path, &snapshot.state)?;
            guard.generation = snapshot.generation;
            Ok(())
        })
        .await
        .map_err(|err| Error::Protocol(format!("file store persist task: {err}")))?
    }

    fn read<T>(&self, f: impl FnOnce(&FileStoreInner) -> T) -> Result<T> {
        let guard = self
            .inner
            .lock()
            .map_err(|err: PoisonError<_>| Error::Protocol(format!("file store lock: {err}")))?;
        Ok(f(&guard))
    }
}

fn scope_key(scope: &CursorScope) -> String {
    fn did(value: &Option<arkret_core::Did>) -> String {
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
                let id = event_id.as_str().to_owned();
                if inner.seen_window.remember(id) {
                    inner.state.seen_events = inner.seen_window.entries().clone();
                }
            })
            .await
        }
    }
}

impl OutboundQueueStore for FileStore {
    fn mutate_outbound<'a, R>(
        &'a self,
        mutation: impl FnOnce(&mut arkret::sync_client::SendQueue) -> Result<R> + crate::MaybeSend + 'a,
    ) -> crate::outbound::BoxOutboundFuture<'a, R>
    where
        R: crate::MaybeSend + 'a,
    {
        Box::pin(async move {
            self.mutate(|inner| {
                let mut queue =
                    arkret::sync_client::SendQueue::from_snapshot(inner.state.outbound.clone())?;
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

#[cfg(test)]
mod tests {
    use arkret_core::{DeviceId, Did, RealmId};

    use super::*;

    fn temp_path(name: &str) -> PathBuf {
        // Index-derived unique name (no wall-clock / rng in this crate).
        std::env::temp_dir().join(format!("garth-filestore-test-{name}.json"))
    }

    fn account_scope() -> CursorScope {
        CursorScope::Account {
            service_id: None,
            actor_id: Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
            device_id: DeviceId::new("ak:device:01904100-0000-7000-8000-000000000001").unwrap(),
        }
    }

    fn realm_scope() -> CursorScope {
        CursorScope::RealmEvents {
            service_id: None,
            realm_id: RealmId::new("ak:realm:01904100-0000-7000-8000-000000000009").unwrap(),
        }
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
        let event = EventId::new("ak:event:01904100-0000-7000-8000-0000000000aa").unwrap();
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
            .await
            .unwrap();
        store
            .persist_snapshot(PersistSnapshot {
                path: path.clone(),
                state: older,
                generation: 1,
            })
            .await
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
        EventId::new(format!("ak:event:01904100-0000-7000-8000-{n:012}")).unwrap()
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
        let event = ClientEvent::Notification(
            serde_json::from_value(serde_json::json!({
                "id": "ak:notification:01964137-0000-7000-8000-000000000012",
                "type": "agent",
                "action": "remove"
            }))
            .unwrap(),
        );

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
