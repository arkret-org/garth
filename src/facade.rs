use crate::{CursorStore, EventCacheStore, Executor, SubscriptionEngine};

/// Root handle for shared client runtime components.
///
/// The facade only owns the shared runtime loop wiring. Session grant and
/// secure-key storage are separate concerns: hosts that need session refresh
/// should construct [`crate::SessionEngine`] directly with the transport they
/// use, and hosts should keep their secure-key store beside their durable
/// client state.
#[derive(Clone, Debug)]
pub struct CokretClient<E, C, D> {
    pub executor: E,
    pub cursor_store: C,
    pub event_cache_store: D,
}

impl<E, C, D> CokretClient<E, C, D>
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
