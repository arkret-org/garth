use cokret_core::{EventId, Result};

use crate::EventCacheStore;

#[derive(Clone, Debug)]
pub struct EventDedupe<S> {
    store: S,
}

impl<S> EventDedupe<S>
where
    S: EventCacheStore,
{
    pub fn new(store: S) -> Self {
        Self { store }
    }

    pub async fn remember_if_new(&self, event_id: EventId) -> Result<bool> {
        if self.store.seen(event_id.clone()).await? {
            return Ok(false);
        }
        self.store.remember(event_id).await?;
        Ok(true)
    }

    /// Split-phase dedupe for callers whose processing may fail: check `seen`
    /// first, process, then `remember` only on success — so a failed
    /// processing leaves the event eligible for redelivery.
    pub async fn seen(&self, event_id: EventId) -> Result<bool> {
        self.store.seen(event_id).await
    }

    pub async fn remember(&self, event_id: EventId) -> Result<()> {
        self.store.remember(event_id).await
    }
}
