use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::sync::{Arc, Mutex, PoisonError};

use cokret_core::{Error, EventId, Result};

use super::{CursorScope, CursorStore, EventCacheStore, OpaqueCursor};

#[derive(Clone, Debug, Default)]
pub struct MemoryStore {
    inner: Arc<Mutex<MemoryState>>,
}

#[derive(Debug, Default)]
struct MemoryState {
    cursors: BTreeMap<CursorScope, OpaqueCursor>,
    seen_events: BTreeSet<EventId>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
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
                state.seen_events.insert(event_id);
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use cokret_core::{DeviceId, Did};

    use super::*;

    fn account_scope() -> CursorScope {
        CursorScope::Account {
            service_did: None,
            actor_id: Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
            device_id: DeviceId::new("ck:device:01904100-0000-7000-8000-000000000001").unwrap(),
        }
    }

    #[tokio::test]
    async fn stores_cursors_by_scope() {
        let store = MemoryStore::new();
        store
            .save(account_scope(), "ck:cursor:account".to_owned())
            .await
            .unwrap();
        assert_eq!(
            store.load(account_scope()).await.unwrap().as_deref(),
            Some("ck:cursor:account")
        );
    }
}
