//! Default native file-backed [`CursorStore`] + [`EventCacheStore`].
//!
//! A batteries-included durable store for native clients so a consumer does not
//! re-implement one (this converges savfox's hand-written `FileCokretAccountStore`
//! into garth). State is a single JSON file, written atomically (temp + rename)
//! after each mutation. Web clients provide an IndexedDB-backed store instead.

use std::collections::{BTreeMap, VecDeque};
use std::future::Future;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use cokret_core::{Error, EventId, Result};
use serde::{Deserialize, Serialize};

use super::seen_window::{BoundedSeenWindow, DEFAULT_SEEN_EVENTS_CAPACITY};
use super::{CursorScope, CursorStore, EventCacheStore, OpaqueCursor};

/// Unit separator used to build a flat, deterministic string key from a
/// structured [`CursorScope`] for the on-disk map.
const SEP: char = '\u{1f}';

/// File-backed durable store. Cheap to clone (shared handle); every mutation
/// persists the whole state to the backing file.
#[derive(Clone, Debug)]
pub struct FileStore {
    inner: Arc<Mutex<FileStoreInner>>,
}

#[derive(Debug)]
struct FileStoreInner {
    path: PathBuf,
    state: FileState,
    /// Runtime lookup index over `state.seen_events` (not persisted).
    seen_window: BoundedSeenWindow<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct FileState {
    #[serde(default)]
    cursors: BTreeMap<String, OpaqueCursor>,
    /// Insertion-ordered dedupe window, oldest first. Reads legacy files that
    /// persisted a sorted set (any JSON array of strings deserializes here).
    #[serde(default)]
    seen_events: VecDeque<String>,
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
            })),
        })
    }

    fn mutate<T>(&self, f: impl FnOnce(&mut FileStoreInner) -> T) -> Result<T> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|err: PoisonError<_>| Error::Protocol(format!("file store lock: {err}")))?;
        let out = f(&mut guard);
        persist(&guard.path, &guard.state)?;
        Ok(out)
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
    fn did(value: &Option<cokret_core::Did>) -> String {
        value
            .as_ref()
            .map(|d| d.as_str().to_owned())
            .unwrap_or_default()
    }
    match scope {
        CursorScope::Account {
            service_did,
            actor_id,
            device_id,
        } => format!(
            "account{SEP}{}{SEP}{}{SEP}{}",
            did(service_did),
            actor_id.as_str(),
            device_id.as_str()
        ),
        CursorScope::RealmEvents {
            service_did,
            realm_id,
        } => format!("realm{SEP}{}{SEP}{}", did(service_did), realm_id.as_str()),
        CursorScope::EventsQuery {
            service_did,
            realms,
            actors,
            order,
            filter_digest,
        } => {
            let realms = realms
                .iter()
                .map(|r| r.as_str())
                .collect::<Vec<_>>()
                .join(",");
            let actors = actors
                .iter()
                .map(|a| a.as_str())
                .collect::<Vec<_>>()
                .join(",");
            let digest = filter_digest
                .as_ref()
                .map(|d| d.as_str().to_owned())
                .unwrap_or_default();
            format!(
                "query{SEP}{}{SEP}{realms}{SEP}{actors}{SEP}{}{SEP}{digest}",
                did(service_did),
                order.clone().unwrap_or_default(),
            )
        }
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
        }
    }

    fn clear(&self, scope: CursorScope) -> impl Future<Output = Result<()>> + '_ {
        async move {
            self.mutate(|inner| {
                inner.state.cursors.remove(&scope_key(&scope));
            })
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
        }
    }
}

#[cfg(test)]
mod tests {
    use cokret_core::{DeviceId, Did, RealmId};

    use super::*;

    fn temp_path(name: &str) -> PathBuf {
        // Index-derived unique name (no wall-clock / rng in this crate).
        std::env::temp_dir().join(format!("garth-filestore-test-{name}.json"))
    }

    fn account_scope() -> CursorScope {
        CursorScope::Account {
            service_did: None,
            actor_id: Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
            device_id: DeviceId::new("ck:device:01904100-0000-7000-8000-000000000001").unwrap(),
        }
    }

    fn realm_scope() -> CursorScope {
        CursorScope::RealmEvents {
            service_did: None,
            realm_id: RealmId::new("ck:realm:01904100-0000-7000-8000-000000000009").unwrap(),
        }
    }

    #[tokio::test]
    async fn persists_and_reloads_cursor_across_reopen() {
        let path = temp_path("cursor-roundtrip");
        let _ = std::fs::remove_file(&path);
        {
            let store = FileStore::open(&path).unwrap();
            store
                .save(account_scope(), "ck:cursor:acct".to_owned())
                .await
                .unwrap();
            store
                .save(realm_scope(), "ck:cursor:realm".to_owned())
                .await
                .unwrap();
        }
        // Reopen from the same file: state survives the process boundary.
        let reopened = FileStore::open(&path).unwrap();
        assert_eq!(
            reopened.load(account_scope()).await.unwrap().as_deref(),
            Some("ck:cursor:acct")
        );
        assert_eq!(
            reopened.load(realm_scope()).await.unwrap().as_deref(),
            Some("ck:cursor:realm")
        );
        // Scopes do not collide.
        reopened.clear(account_scope()).await.unwrap();
        assert!(reopened.load(account_scope()).await.unwrap().is_none());
        assert_eq!(
            reopened.load(realm_scope()).await.unwrap().as_deref(),
            Some("ck:cursor:realm")
        );
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn dedupe_survives_reopen() {
        let path = temp_path("dedupe-roundtrip");
        let _ = std::fs::remove_file(&path);
        let event = EventId::new("ck:event:01904100-0000-7000-8000-0000000000aa").unwrap();
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

    fn event_id(n: usize) -> EventId {
        EventId::new(format!("ck:event:01904100-0000-7000-8000-{n:012}")).unwrap()
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
}
