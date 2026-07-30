use crate::{CursorStore, EventCacheStore, Executor, SubscriptionEngine};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static FALLBACK_SEED_COUNTER: AtomicU64 = AtomicU64::new(0);
static FALLBACK_SEED_BASE: OnceLock<u64> = OnceLock::new();

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
        let backoff_seed = getrandom::u64().unwrap_or_else(|_| fallback_backoff_seed());
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

fn fallback_backoff_seed() -> u64 {
    let time_seed = *FALLBACK_SEED_BASE.get_or_init(|| {
        let elapsed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        elapsed.as_secs() ^ u64::from(elapsed.subsec_nanos()).rotate_left(32)
    });
    time_seed ^ FALLBACK_SEED_COUNTER.fetch_add(1, Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::fallback_backoff_seed;

    #[test]
    fn fallback_backoff_seeds_are_distinct() {
        assert_ne!(fallback_backoff_seed(), fallback_backoff_seed());
    }
}
