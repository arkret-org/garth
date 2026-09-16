//! Small runtime-neutral cursor and committed-Event cache.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::sync::{Arc, Mutex};

use arkret_wire::{ActorId, CommitStreamRef, DeviceId, DidCoreId, EventId};
use serde::{Deserialize, Serialize};

use crate::{MaybeSendSync, Result};

#[path = "store/keystore.rs"]
mod keystore;
#[path = "store/seen_window.rs"]
mod seen_window;

pub use keystore::{
    MemorySecureKeyStore, PutSecretOptions, SdkKeyStoreAdapter, SdkKeyStoreSecureAdapter,
    SecretClass, SecretDurability, SecureKeyStore, SecureKeyStoreBackendInfo, SecureKeyStoreError,
    SecureKeyStoreResult, account_id_storage_digest, device_storage_digest,
};
pub use seen_window::{BoundedSeenWindow, DEFAULT_SEEN_EVENTS_CAPACITY};

#[cfg(all(feature = "native", not(target_arch = "wasm32")))]
use crate::Error;

pub type OpaqueCursor = String;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CursorScope {
    Account {
        service_id: Option<DidCoreId>,
        actor_id: ActorId,
        device_id: DeviceId,
    },
    CommitStream {
        service_id: Option<DidCoreId>,
        stream_ref: CommitStreamRef,
    },
    DeviceMessages {
        service_id: Option<DidCoreId>,
        actor_id: ActorId,
        device_id: DeviceId,
    },
}

pub const MAX_PENDING_DELIVERIES: usize = 4096;
pub const MAX_PENDING_READ: usize = 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DeliveryId(u64);

impl DeliveryId {
    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Debug)]
pub struct PendingDelivery<T> {
    pub id: DeliveryId,
    pub scope: CursorScope,
    pub cursor: Option<OpaqueCursor>,
    pub payload: T,
    pub attempts: u32,
    pub next_attempt_at_ms: Option<i64>,
    pub last_error: Option<String>,
}

pub trait DurableInboxStore<T>: Clone + MaybeSendSync + 'static
where
    T: Clone + MaybeSendSync + 'static,
{
    fn commit(
        &self,
        scope: CursorScope,
        cursor: Option<OpaqueCursor>,
        payload: T,
    ) -> impl Future<Output = Result<DeliveryId>> + '_;
    fn pending(&self, limit: usize) -> impl Future<Output = Result<Vec<PendingDelivery<T>>>> + '_;
    fn ack(&self, id: DeliveryId) -> impl Future<Output = Result<bool>> + '_;
    fn retry(
        &self,
        id: DeliveryId,
        next_attempt_at_ms: Option<i64>,
        error: String,
    ) -> impl Future<Output = Result<bool>> + '_;
}

#[derive(Clone, Debug)]
struct InboxState<T> {
    next_id: u64,
    cursors: BTreeMap<CursorScope, OpaqueCursor>,
    pending: BTreeMap<DeliveryId, PendingDelivery<T>>,
}

impl<T> Default for InboxState<T> {
    fn default() -> Self {
        Self {
            next_id: 1,
            cursors: BTreeMap::new(),
            pending: BTreeMap::new(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct MemoryInboxStore<T> {
    state: Arc<Mutex<InboxState<T>>>,
}

impl<T> Default for MemoryInboxStore<T> {
    fn default() -> Self {
        Self {
            state: Arc::new(Mutex::new(InboxState::default())),
        }
    }
}

impl<T> DurableInboxStore<T> for MemoryInboxStore<T>
where
    T: Clone + MaybeSendSync + 'static,
{
    async fn commit(
        &self,
        scope: CursorScope,
        cursor: Option<OpaqueCursor>,
        payload: T,
    ) -> Result<DeliveryId> {
        let mut state = self.state.lock().unwrap();
        if state.pending.len() >= MAX_PENDING_DELIVERIES {
            return Err(crate::Error::Storage(
                "durable inbox is at its pending-delivery limit".to_owned(),
            ));
        }
        let id = DeliveryId(state.next_id);
        state.next_id = state
            .next_id
            .checked_add(1)
            .ok_or_else(|| crate::Error::Storage("delivery id overflow".to_owned()))?;
        if let Some(cursor) = &cursor {
            state.cursors.insert(scope.clone(), cursor.clone());
        }
        state.pending.insert(
            id,
            PendingDelivery {
                id,
                scope,
                cursor,
                payload,
                attempts: 0,
                next_attempt_at_ms: None,
                last_error: None,
            },
        );
        Ok(id)
    }

    async fn pending(&self, limit: usize) -> Result<Vec<PendingDelivery<T>>> {
        Ok(self
            .state
            .lock()
            .unwrap()
            .pending
            .values()
            .take(limit.clamp(1, MAX_PENDING_READ))
            .cloned()
            .collect())
    }

    async fn ack(&self, id: DeliveryId) -> Result<bool> {
        Ok(self.state.lock().unwrap().pending.remove(&id).is_some())
    }

    async fn retry(
        &self,
        id: DeliveryId,
        next_attempt_at_ms: Option<i64>,
        mut error: String,
    ) -> Result<bool> {
        error.truncate(error.floor_char_boundary(2048));
        let mut state = self.state.lock().unwrap();
        let Some(delivery) = state.pending.get_mut(&id) else {
            return Ok(false);
        };
        delivery.attempts = delivery.attempts.saturating_add(1);
        delivery.next_attempt_at_ms = next_attempt_at_ms;
        delivery.last_error = Some(error);
        Ok(true)
    }
}

pub trait CursorStore: Clone + MaybeSendSync + 'static {
    fn load(&self, scope: CursorScope) -> impl Future<Output = Result<Option<OpaqueCursor>>> + '_;
    fn save(
        &self,
        scope: CursorScope,
        cursor: OpaqueCursor,
    ) -> impl Future<Output = Result<()>> + '_;
    fn clear(&self, scope: CursorScope) -> impl Future<Output = Result<()>> + '_;
}

pub trait EventCacheStore: Clone + MaybeSendSync + 'static {
    fn seen(&self, event_id: EventId) -> impl Future<Output = Result<bool>> + '_;
    fn remember(&self, event_id: EventId) -> impl Future<Output = Result<()>> + '_;
}

#[derive(Clone, Debug, Default)]
struct StoreState {
    cursors: BTreeMap<CursorScope, OpaqueCursor>,
    committed_events: BTreeSet<EventId>,
    stamp_floors: BTreeMap<crate::StampScope, crate::StampFloor>,
}

/// JSON objects require string keys. Persist typed map keys as sorted entry
/// arrays so every `CursorScope` and `StampScope` round-trips losslessly.
#[derive(Serialize, Deserialize)]
struct StoredState {
    #[serde(default)]
    cursors: Vec<(CursorScope, OpaqueCursor)>,
    #[serde(default)]
    committed_events: BTreeSet<EventId>,
    #[serde(default)]
    stamp_floors: Vec<(crate::StampScope, crate::StampFloor)>,
}

impl Serialize for StoreState {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        StoredState {
            cursors: self
                .cursors
                .iter()
                .map(|(scope, cursor)| (scope.clone(), cursor.clone()))
                .collect(),
            committed_events: self.committed_events.clone(),
            stamp_floors: self
                .stamp_floors
                .iter()
                .map(|(scope, floor)| (scope.clone(), *floor))
                .collect(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for StoreState {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let stored = StoredState::deserialize(deserializer)?;
        Ok(Self {
            cursors: stored.cursors.into_iter().collect(),
            committed_events: stored.committed_events,
            stamp_floors: stored.stamp_floors.into_iter().collect(),
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct MemoryStore {
    state: Arc<Mutex<StoreState>>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl CursorStore for MemoryStore {
    async fn load(&self, scope: CursorScope) -> Result<Option<OpaqueCursor>> {
        Ok(self.state.lock().unwrap().cursors.get(&scope).cloned())
    }

    async fn save(&self, scope: CursorScope, cursor: OpaqueCursor) -> Result<()> {
        self.state.lock().unwrap().cursors.insert(scope, cursor);
        Ok(())
    }

    async fn clear(&self, scope: CursorScope) -> Result<()> {
        self.state.lock().unwrap().cursors.remove(&scope);
        Ok(())
    }
}

impl EventCacheStore for MemoryStore {
    async fn seen(&self, event_id: EventId) -> Result<bool> {
        Ok(self
            .state
            .lock()
            .unwrap()
            .committed_events
            .contains(&event_id))
    }

    async fn remember(&self, event_id: EventId) -> Result<()> {
        self.state.lock().unwrap().committed_events.insert(event_id);
        Ok(())
    }
}

impl crate::MonotonicStampStore for MemoryStore {
    async fn load_floor(&self, scope: crate::StampScope) -> Result<Option<crate::StampFloor>> {
        Ok(self.state.lock().unwrap().stamp_floors.get(&scope).copied())
    }

    async fn advance_floor(
        &self,
        scope: crate::StampScope,
        update: crate::StampFloorUpdate,
    ) -> Result<crate::StampFloor> {
        let mut state = self.state.lock().unwrap();
        let next = state
            .stamp_floors
            .get(&scope)
            .copied()
            .unwrap_or_default()
            .apply(update)?;
        state.stamp_floors.insert(scope, next);
        Ok(next)
    }
}

#[cfg(all(feature = "native", not(target_arch = "wasm32")))]
#[derive(Clone, Debug)]
pub struct FileStore {
    path: Arc<std::path::PathBuf>,
    state: Arc<Mutex<StoreState>>,
}

#[cfg(all(feature = "native", not(target_arch = "wasm32")))]
impl FileStore {
    pub fn open(path: impl Into<std::path::PathBuf>) -> Result<Self> {
        let path = path.into();
        let state = if path.exists() {
            let bytes = std::fs::read(&path)
                .map_err(|error| Error::Storage(format!("read {}: {error}", path.display())))?;
            serde_json::from_slice(&bytes).map_err(Error::CanonicalJson)?
        } else {
            StoreState::default()
        };
        Ok(Self {
            path: Arc::new(path),
            state: Arc::new(Mutex::new(state)),
        })
    }

    fn mutate(&self, mutation: impl FnOnce(&mut StoreState) -> bool) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        if !mutation(&mut state) {
            return Ok(());
        }
        let bytes = serde_json::to_vec(&*state)?;
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| Error::Storage(format!("create {}: {error}", parent.display())))?;
        }
        std::fs::write(self.path.as_ref(), bytes)
            .map_err(|error| Error::Storage(format!("write {}: {error}", self.path.display())))
    }
}

#[cfg(all(feature = "native", not(target_arch = "wasm32")))]
impl CursorStore for FileStore {
    async fn load(&self, scope: CursorScope) -> Result<Option<OpaqueCursor>> {
        Ok(self.state.lock().unwrap().cursors.get(&scope).cloned())
    }

    async fn save(&self, scope: CursorScope, cursor: OpaqueCursor) -> Result<()> {
        self.mutate(|state| {
            if state.cursors.get(&scope) == Some(&cursor) {
                false
            } else {
                state.cursors.insert(scope, cursor);
                true
            }
        })
    }

    async fn clear(&self, scope: CursorScope) -> Result<()> {
        self.mutate(|state| state.cursors.remove(&scope).is_some())
    }
}

#[cfg(all(feature = "native", not(target_arch = "wasm32")))]
impl EventCacheStore for FileStore {
    async fn seen(&self, event_id: EventId) -> Result<bool> {
        Ok(self
            .state
            .lock()
            .unwrap()
            .committed_events
            .contains(&event_id))
    }

    async fn remember(&self, event_id: EventId) -> Result<()> {
        self.mutate(|state| state.committed_events.insert(event_id))
    }
}

#[cfg(all(feature = "native", not(target_arch = "wasm32")))]
impl crate::MonotonicStampStore for FileStore {
    async fn load_floor(&self, scope: crate::StampScope) -> Result<Option<crate::StampFloor>> {
        Ok(self.state.lock().unwrap().stamp_floors.get(&scope).copied())
    }

    async fn advance_floor(
        &self,
        scope: crate::StampScope,
        update: crate::StampFloorUpdate,
    ) -> Result<crate::StampFloor> {
        let next = {
            let mut state = self.state.lock().unwrap();
            let next = state
                .stamp_floors
                .get(&scope)
                .copied()
                .unwrap_or_default()
                .apply(update)?;
            state.stamp_floors.insert(scope, next);
            let bytes = serde_json::to_vec(&*state)?;
            if let Some(parent) = self.path.parent() {
                std::fs::create_dir_all(parent).map_err(|error| {
                    Error::Storage(format!("create {}: {error}", parent.display()))
                })?;
            }
            std::fs::write(self.path.as_ref(), bytes).map_err(|error| {
                Error::Storage(format!("write {}: {error}", self.path.display()))
            })?;
            next
        };
        Ok(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn memory_store_round_trips_opaque_cursor() {
        let store = MemoryStore::new();
        let scope = CursorScope::CommitStream {
            service_id: None,
            stream_ref: CommitStreamRef::Realm {
                realm_id: arkret_wire::RealmId::new(
                    "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
                )
                .unwrap(),
            },
        };
        store
            .save(scope.clone(), "ak:cursor:test".to_owned())
            .await
            .unwrap();
        assert_eq!(
            store.load(scope).await.unwrap().as_deref(),
            Some("ak:cursor:test")
        );
    }

    #[tokio::test]
    async fn memory_event_cache_is_idempotent() {
        let store = MemoryStore::new();
        let event_id = EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [8; 32]);
        assert!(!store.seen(event_id.clone()).await.unwrap());
        store.remember(event_id.clone()).await.unwrap();
        store.remember(event_id.clone()).await.unwrap();
        assert!(store.seen(event_id).await.unwrap());
    }

    #[tokio::test]
    async fn durable_inbox_retries_then_acknowledges_one_delivery() {
        let inbox = MemoryInboxStore::<String>::default();
        let scope = CursorScope::CommitStream {
            service_id: None,
            stream_ref: CommitStreamRef::Realm {
                realm_id: arkret_wire::RealmId::new(
                    "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
                )
                .unwrap(),
            },
        };
        let id = inbox
            .commit(
                scope.clone(),
                Some("ak:cursor:delivery".to_owned()),
                "payload".to_owned(),
            )
            .await
            .unwrap();
        inbox
            .retry(id, Some(500), "temporary".to_owned())
            .await
            .unwrap();
        let pending = inbox.pending(10).await.unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].scope, scope);
        assert_eq!(pending[0].attempts, 1);
        assert_eq!(pending[0].next_attempt_at_ms, Some(500));
        assert_eq!(pending[0].last_error.as_deref(), Some("temporary"));
        assert!(inbox.ack(id).await.unwrap());
        assert!(inbox.pending(10).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn durable_inbox_missing_delivery_mutations_are_noops() {
        let inbox = MemoryInboxStore::<String>::default();
        let missing = DeliveryId(99);
        assert!(
            !inbox
                .retry(missing, None, "not found".to_owned())
                .await
                .unwrap()
        );
        assert!(!inbox.ack(missing).await.unwrap());
    }
}
