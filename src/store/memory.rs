use std::collections::{BTreeMap, VecDeque};
use std::future::Future;
use std::sync::{Arc, Mutex, PoisonError};

use arkret_core::{Error, EventId, Result};

use super::inbox::{bounded_delivery_error, bounded_pending_limit};
use super::seen_window::BoundedSeenWindow;
use super::{
    CursorScope, CursorStore, DeliveryErrorClass, DeliveryId, DurableInboxStore, EventCacheStore,
    OpaqueCursor, PendingDelivery,
};
use crate::stamp::{MonotonicStampStore, StampFloor, StampFloorUpdate, StampScope};
use crate::{ClientEvent, OutboundQueueStore};

#[derive(Clone, Debug, Default)]
pub struct MemoryStore {
    inner: Arc<Mutex<MemoryState>>,
}

#[derive(Debug, Default)]
struct MemoryState {
    cursors: BTreeMap<CursorScope, OpaqueCursor>,
    seen_events: BoundedSeenWindow<EventId>,
    next_delivery_id: u64,
    deliveries: VecDeque<PendingDelivery>,
    outbound: arkret::sync_client::SendQueueSnapshot,
    stamp_floors: BTreeMap<StampScope, StampFloor>,
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
                next_delivery_id: 0,
                deliveries: VecDeque::new(),
                outbound: arkret::sync_client::SendQueueSnapshot::default(),
                stamp_floors: BTreeMap::new(),
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

    pub fn advance_stamp_floor_blocking(
        &self,
        scope: StampScope,
        update: StampFloorUpdate,
    ) -> Result<StampFloor> {
        self.with_state(|state| {
            let floor = state
                .stamp_floors
                .get(&scope)
                .copied()
                .unwrap_or_default()
                .apply(update)?;
            state.stamp_floors.insert(scope, floor);
            Ok(floor)
        })?
    }
}

impl OutboundQueueStore for MemoryStore {
    fn mutate_outbound<'a, R>(
        &'a self,
        mutation: impl FnOnce(&mut arkret::sync_client::SendQueue) -> Result<R> + crate::MaybeSend + 'a,
    ) -> crate::outbound::BoxOutboundFuture<'a, R>
    where
        R: crate::MaybeSend + 'a,
    {
        Box::pin(async move {
            self.with_state(|state| {
                let mut queue =
                    arkret::sync_client::SendQueue::from_snapshot(state.outbound.clone())?;
                let output = mutation(&mut queue)?;
                state.outbound = queue.snapshot();
                Ok(output)
            })?
        })
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

impl DurableInboxStore for MemoryStore {
    fn commit(
        &self,
        scope: CursorScope,
        cursor: Option<OpaqueCursor>,
        events: Vec<ClientEvent>,
    ) -> impl Future<Output = Result<Option<DeliveryId>>> + '_ {
        async move {
            self.with_state(|state| {
                match cursor.clone() {
                    Some(cursor) => {
                        state.cursors.insert(scope.clone(), cursor);
                    }
                    None => {
                        state.cursors.remove(&scope);
                    }
                }
                if events.is_empty() {
                    return Ok(None);
                }
                state.next_delivery_id = state
                    .next_delivery_id
                    .checked_add(1)
                    .ok_or_else(|| Error::Protocol("delivery id overflow".to_owned()))?;
                let id = DeliveryId::new(state.next_delivery_id);
                state.deliveries.push_back(PendingDelivery {
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
            })?
        }
    }

    fn pending(&self, limit: usize) -> impl Future<Output = Result<Vec<PendingDelivery>>> + '_ {
        async move {
            self.with_state(|state| {
                state
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
            self.with_state(|state| {
                let before = state.deliveries.len();
                state.deliveries.retain(|delivery| delivery.id != id);
                state.deliveries.len() != before
            })
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
            self.with_state(|state| {
                let Some(delivery) = state
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
            })?
        }
    }
}

impl MonotonicStampStore for MemoryStore {
    fn load_floor(
        &self,
        scope: StampScope,
    ) -> impl Future<Output = Result<Option<StampFloor>>> + '_ {
        async move { self.with_state(|state| state.stamp_floors.get(&scope).copied()) }
    }

    fn advance_floor(
        &self,
        scope: StampScope,
        update: StampFloorUpdate,
    ) -> impl Future<Output = Result<StampFloor>> + '_ {
        async move {
            self.with_state(|state| {
                let floor = state
                    .stamp_floors
                    .get(&scope)
                    .copied()
                    .unwrap_or_default()
                    .apply(update)?;
                state.stamp_floors.insert(scope, floor);
                Ok(floor)
            })?
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
