use std::future::Future;
use std::pin::Pin;

use cokret_core::{Did, RealmId, Result, SyncBackfillOutcome};

use crate::{CursorScope, CursorStore, OpaqueCursor};

pub type BoxScanFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventsScanRequest {
    pub realm_id: RealmId,
    pub before: Option<OpaqueCursor>,
    pub after: Option<OpaqueCursor>,
    pub order: Option<String>,
    pub limit: Option<u32>,
}

pub trait EventsScanTransport {
    fn scan_events<'a>(
        &'a self,
        request: EventsScanRequest,
    ) -> BoxScanFuture<'a, SyncBackfillOutcome>;
}

impl<F, Fut> EventsScanTransport for F
where
    F: Fn(EventsScanRequest) -> Fut + Send + Sync,
    Fut: Future<Output = Result<SyncBackfillOutcome>> + Send + 'static,
{
    fn scan_events<'a>(
        &'a self,
        request: EventsScanRequest,
    ) -> BoxScanFuture<'a, SyncBackfillOutcome> {
        Box::pin(self(request))
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl EventsScanTransport for cokret_http_client::Client {
    fn scan_events<'a>(
        &'a self,
        request: EventsScanRequest,
    ) -> BoxScanFuture<'a, SyncBackfillOutcome> {
        Box::pin(async move {
            self.events_query(
                request.realm_id.as_str(),
                request.before.as_deref(),
                request.after.as_deref(),
                request.order.as_deref(),
                request.limit,
            )
            .await
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScanCatchupOptions {
    pub before: Option<OpaqueCursor>,
    pub after: Option<OpaqueCursor>,
    pub order: Option<String>,
    pub limit: Option<u32>,
    pub max_pages: usize,
}

impl Default for ScanCatchupOptions {
    fn default() -> Self {
        Self {
            before: None,
            after: None,
            order: None,
            limit: None,
            max_pages: 64,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ScanCatchup<S> {
    store: S,
    service_did: Option<Did>,
}

impl<S> ScanCatchup<S>
where
    S: CursorStore,
{
    pub fn new(store: S) -> Self {
        Self {
            store,
            service_did: None,
        }
    }

    pub fn with_service_did(mut self, service_did: Did) -> Self {
        self.service_did = Some(service_did);
        self
    }

    pub async fn scan_realm_once<T>(
        &self,
        transport: &T,
        realm_id: RealmId,
        options: ScanCatchupOptions,
    ) -> Result<SyncBackfillOutcome>
    where
        T: EventsScanTransport + ?Sized,
    {
        let scope = self.scope(&realm_id);
        let after = self.after_cursor(scope.clone(), options.after).await?;
        let outcome = transport
            .scan_events(EventsScanRequest {
                realm_id,
                before: options.before,
                after,
                order: options.order,
                limit: options.limit,
            })
            .await?;
        self.save_next_cursor(scope, outcome.next_cursor.clone())
            .await?;
        Ok(outcome)
    }

    pub async fn scan_realm_catchup<T>(
        &self,
        transport: &T,
        realm_id: RealmId,
        options: ScanCatchupOptions,
    ) -> Result<SyncBackfillOutcome>
    where
        T: EventsScanTransport + ?Sized,
    {
        let scope = self.scope(&realm_id);
        let mut after = self.after_cursor(scope.clone(), options.after).await?;
        let mut aggregate = SyncBackfillOutcome {
            events: Vec::new(),
            snapshot_bootstrap: None,
            prev_cursor: None,
            next_cursor: None,
            limited: false,
        };
        let max_pages = options.max_pages.max(1);

        for _ in 0..max_pages {
            let mut outcome = transport
                .scan_events(EventsScanRequest {
                    realm_id: realm_id.clone(),
                    before: options.before.clone(),
                    after,
                    order: options.order.clone(),
                    limit: options.limit,
                })
                .await?;
            if aggregate.prev_cursor.is_none() {
                aggregate.prev_cursor = outcome.prev_cursor.clone();
            }
            if aggregate.snapshot_bootstrap.is_none() {
                aggregate.snapshot_bootstrap = outcome.snapshot_bootstrap.take();
            }
            let next_cursor = outcome.next_cursor.clone();
            let limited = outcome.limited;
            aggregate.events.append(&mut outcome.events);
            aggregate.next_cursor = next_cursor.clone();
            aggregate.limited = limited;
            self.save_next_cursor(scope.clone(), next_cursor.clone())
                .await?;

            match (limited, next_cursor) {
                (true, Some(next)) => after = Some(next),
                _ => return Ok(aggregate),
            }
        }

        aggregate.limited = true;
        Ok(aggregate)
    }

    fn scope(&self, realm_id: &RealmId) -> CursorScope {
        CursorScope::RealmEvents {
            service_did: self.service_did.clone(),
            realm_id: realm_id.clone(),
        }
    }

    async fn after_cursor(
        &self,
        scope: CursorScope,
        explicit_after: Option<OpaqueCursor>,
    ) -> Result<Option<OpaqueCursor>> {
        match explicit_after {
            Some(cursor) => Ok(Some(cursor)),
            None => self.store.load(scope).await,
        }
    }

    async fn save_next_cursor(
        &self,
        scope: CursorScope,
        next_cursor: Option<OpaqueCursor>,
    ) -> Result<()> {
        if let Some(next_cursor) = next_cursor {
            self.store.save(scope, next_cursor).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::MemoryStore;
    use crate::store::CursorStore;

    fn realm_id() -> RealmId {
        RealmId::new("ck:realm:01904100-0000-7000-8000-000000000001").unwrap()
    }

    fn scope() -> CursorScope {
        CursorScope::RealmEvents {
            service_did: None,
            realm_id: realm_id(),
        }
    }

    fn outcome(next_cursor: Option<&str>, limited: bool) -> SyncBackfillOutcome {
        SyncBackfillOutcome {
            events: Vec::new(),
            snapshot_bootstrap: None,
            prev_cursor: None,
            next_cursor: next_cursor.map(str::to_owned),
            limited,
        }
    }

    #[tokio::test]
    async fn scan_once_uses_stored_cursor_and_saves_next_cursor() {
        let store = MemoryStore::new();
        store
            .save(scope(), "ck:cursor:stored".to_owned())
            .await
            .unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let requests_for_transport = Arc::clone(&requests);
        let transport = move |request: EventsScanRequest| {
            requests_for_transport.lock().unwrap().push(request);
            async { Ok(outcome(Some("ck:cursor:next"), false)) }
        };

        let catchup = ScanCatchup::new(store.clone());
        let response = catchup
            .scan_realm_once(&transport, realm_id(), ScanCatchupOptions::default())
            .await
            .unwrap();

        assert_eq!(response.next_cursor.as_deref(), Some("ck:cursor:next"));
        assert_eq!(
            requests.lock().unwrap()[0].after.as_deref(),
            Some("ck:cursor:stored")
        );
        assert_eq!(
            store.load(scope()).await.unwrap().as_deref(),
            Some("ck:cursor:next")
        );
    }

    #[tokio::test]
    async fn scan_catchup_pages_until_range_is_not_limited() {
        let store = MemoryStore::new();
        let responses = Arc::new(Mutex::new(VecDeque::from([
            outcome(Some("ck:cursor:p2"), true),
            outcome(Some("ck:cursor:p3"), false),
        ])));
        let afters = Arc::new(Mutex::new(Vec::new()));
        let responses_for_transport = Arc::clone(&responses);
        let afters_for_transport = Arc::clone(&afters);
        let transport = move |request: EventsScanRequest| {
            afters_for_transport.lock().unwrap().push(request.after);
            let responses_for_transport = Arc::clone(&responses_for_transport);
            async move { Ok(responses_for_transport.lock().unwrap().pop_front().unwrap()) }
        };

        let catchup = ScanCatchup::new(store.clone());
        let response = catchup
            .scan_realm_catchup(&transport, realm_id(), ScanCatchupOptions::default())
            .await
            .unwrap();

        assert!(!response.limited);
        assert_eq!(response.next_cursor.as_deref(), Some("ck:cursor:p3"));
        assert_eq!(
            afters.lock().unwrap().as_slice(),
            &[None, Some("ck:cursor:p2".to_owned())]
        );
        assert_eq!(
            store.load(scope()).await.unwrap().as_deref(),
            Some("ck:cursor:p3")
        );
    }
}
