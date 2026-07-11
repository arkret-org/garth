use crate::{CursorStore, EventCacheStore, Executor, SubscriptionEngine};

/// Root handle for shared client runtime components.
///
/// The facade owns shared runtime loop wiring. Compose it with
/// [`crate::SessionTransportProvider`] when grant refresh and authenticated
/// transport rebuild are required; secret storage remains a host adapter.
#[derive(Clone, Debug)]
pub struct ArkretClient<E, C, D> {
    pub executor: E,
    pub cursor_store: C,
    pub event_cache_store: D,
}

impl<E, C, D> ArkretClient<E, C, D>
where
    E: Executor,
    C: CursorStore,
    D: EventCacheStore,
{
    pub fn new(executor: E, cursor_store: C, event_cache_store: D) -> Self {
        Self {
            executor,
            cursor_store,
            event_cache_store,
        }
    }

    pub fn subscription_engine(&self) -> SubscriptionEngine<E, C, D>
    where
        E: Clone,
    {
        SubscriptionEngine::new(
            self.executor.clone(),
            self.cursor_store.clone(),
            self.event_cache_store.clone(),
        )
    }
}
