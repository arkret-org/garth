use std::collections::BTreeMap;
use std::future::Future;
use std::sync::{Arc, Mutex, PoisonError};

use arkret_core::{Error, EventId, Result};

use super::seen_window::BoundedSeenWindow;
use super::{CursorScope, CursorStore, EventCacheStore, OpaqueCursor};

#[derive(Clone, Debug, Default)]
pub struct MemoryStore {
    inner: Arc<Mutex<MemoryState>>,
}

#[derive(Debug, Default)]
struct MemoryState {
    cursors: BTreeMap<CursorScope, OpaqueCursor>,
    seen_events: BoundedSeenWindow<EventId>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_seen_capacity(capacity: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(MemoryState {
                cursors: BTreeMap::new(),
                seen_events: BoundedSeenWindow::new(capacity),
            })),
        }
    }

    fn with_state<T>(&self, f: impl FnOnce(&mut MemoryState) -> T) -> Result<T> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|err: PoisonError<_>| Error::Protocol(format!("memory store lock: {err}")))?;
        Ok(f(&mut guard))
    }
}

impl CursorStore for MemoryStore {
    fn load(&self, scope: CursorScope) -> impl Future<Output = Result<Option<OpaqueCursor>>> + '_ {
        async move { self.with_state(|state| state.cursors.get(&scope).cloned()) }
    }

    fn save(
        &self,
        scope: CursorScope,
        cursor: OpaqueCursor,
    ) -> impl Future<Output = Result<()>> + '_ {
        async move {
            self.with_state(|state| {
                state.cursors.insert(scope, cursor);
            })
        }
    }

    fn clear(&self, scope: CursorScope) -> impl Future<Output = Result<()>> + '_ {
        async move {
            self.with_state(|state| {
                state.cursors.remove(&scope);
            })
        }
    }
}

impl EventCacheStore for MemoryStore {
    fn seen(&self, event_id: EventId) -> impl Future<Output = Result<bool>> + '_ {
        async move { self.with_state(|state| state.seen_events.contains(&event_id)) }
    }

    fn remember(&self, event_id: EventId) -> impl Future<Output = Result<()>> + '_ {
        async move {
            self.with_state(|state| {
                state.seen_events.remember(event_id);
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use arkret_core::{DeviceId, Did, EventId};

    use super::*;

    fn account_scope() -> CursorScope {
        CursorScope::Account {
            service_id: None,
            actor_id: Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
            device_id: DeviceId::new("ak:device:01904100-0000-7000-8000-000000000001").unwrap(),
        }
    }

    #[tokio::test]
    async fn stores_cursors_by_scope() {
        let store = MemoryStore::new();
        store
            .save(account_scope(), "ak:cursor:account".to_owned())
            .await
            .unwrap();
        assert_eq!(
            store.load(account_scope()).await.unwrap().as_deref(),
            Some("ak:cursor:account")
        );
    }

    fn event_id(n: usize) -> EventId {
        EventId::new(format!("ak:event:01904100-0000-7000-8000-{n:012}")).unwrap()
    }

    #[tokio::test]
    async fn dedupe_window_evicts_oldest_beyond_capacity() {
        let store = MemoryStore::with_seen_capacity(3);
        for n in 0..4 {
            store.remember(event_id(n)).await.unwrap();
        }

        assert!(!store.seen(event_id(0)).await.unwrap());
        for n in 1..4 {
            assert!(store.seen(event_id(n)).await.unwrap());
        }
    }
}
