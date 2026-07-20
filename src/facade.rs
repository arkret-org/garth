use std::sync::Arc;

use crate::EphemeralDeviceKeyResolver;

use crate::{CursorStore, EventCacheStore, Executor, SubscriptionEngine};

/// Root handle for shared client runtime components.
///
/// The facade owns shared runtime loop wiring. Compose it with
/// [`crate::SessionTransportProvider`] when grant refresh and authenticated
/// transport rebuild are required; secret storage remains a host adapter.
#[derive(Clone)]
pub struct ArkretClient<E, C, D> {
    pub executor: E,
    pub cursor_store: C,
    pub event_cache_store: D,
    pub(crate) backoff_seed: u64,
    ephemeral_device_key_resolver: Option<Arc<dyn EphemeralDeviceKeyResolver>>,
}

impl<E, C, D> std::fmt::Debug for ArkretClient<E, C, D>
where
    E: std::fmt::Debug,
    C: std::fmt::Debug,
    D: std::fmt::Debug,
{
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ArkretClient")
            .field("executor", &self.executor)
            .field("cursor_store", &self.cursor_store)
            .field("event_cache_store", &self.event_cache_store)
            .field("backoff_seed", &self.backoff_seed)
            .field(
                "has_ephemeral_device_key_resolver",
                &self.ephemeral_device_key_resolver.is_some(),
            )
            .finish()
    }
}

impl<E, C, D> ArkretClient<E, C, D>
where
    E: Executor,
    C: CursorStore,
    D: EventCacheStore,
{
    pub fn new(executor: E, cursor_store: C, event_cache_store: D) -> Self {
        let backoff_seed = getrandom::u64().expect("host randomness unavailable");
        Self::new_with_backoff_seed(executor, cursor_store, event_cache_store, backoff_seed)
    }

    /// Build a client with an explicit per-instance backoff seed.
    ///
    /// Production hosts should normally use [`Self::new`]. This constructor is
    /// available for deterministic simulations and hosts that already own a
    /// suitable entropy source.
    pub fn new_with_backoff_seed(
        executor: E,
        cursor_store: C,
        event_cache_store: D,
        backoff_seed: u64,
    ) -> Self {
        Self {
            executor,
            cursor_store,
            event_cache_store,
            backoff_seed,
            ephemeral_device_key_resolver: None,
        }
    }

    /// Configure the authoritative active-device key resolver used by every
    /// account loop created by this client. Without one the Arkret SDK drops
    /// ephemeral presence updates fail-closed.
    pub fn with_ephemeral_device_key_resolver(
        mut self,
        resolver: Arc<dyn EphemeralDeviceKeyResolver>,
    ) -> Self {
        self.ephemeral_device_key_resolver = Some(resolver);
        self
    }

    pub fn subscription_engine(&self) -> SubscriptionEngine<E, C, D>
    where
        E: Clone,
    {
        let mut engine = SubscriptionEngine::new(
            self.executor.clone(),
            self.cursor_store.clone(),
            self.event_cache_store.clone(),
        );
        if let Some(resolver) = self.ephemeral_device_key_resolver.clone() {
            engine = engine.with_ephemeral_device_key_resolver(resolver);
        }
        engine
    }
}
