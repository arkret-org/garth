use std::future::Future;
use std::pin::Pin;

use crate::protocol::{EventsQueryOrder, EventsQueryOutcome, RealmId, Result};

use super::{ProjectedRunError, ProjectedRunResult};
use crate::{MaybeSend, MaybeSendSync, OpaqueCursor};

// Native builds keep the boxed scan future `Send` so host runtimes can move it
// across worker threads, matching `BoxSessionFuture` / `BoxRealmStreamFuture`.
// Wasm builds drop `Send` because browser futures are commonly single-threaded
// and JS-interop transports are `!Send`.
#[cfg(not(target_arch = "wasm32"))]
pub type BoxScanFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

#[cfg(target_arch = "wasm32")]
pub type BoxScanFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + 'a>>;

/// Runtime-neutral host request for one realm scan.
///
/// This is intentionally a transport seam rather than an alias of the HTTP
/// parameter object: hosts may not use HTTP, and client cursor tokens must stay
/// opaque. Closed protocol choices such as `order` still reuse SDK types.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventsScanRequest {
    pub realm_id: RealmId,
    pub before: Option<OpaqueCursor>,
    pub after: Option<OpaqueCursor>,
    pub order: Option<EventsQueryOrder>,
    pub limit: Option<u32>,
}

pub trait EventsScanTransport {
    fn scan_events<'a>(
        &'a self,
        request: EventsScanRequest,
    ) -> BoxScanFuture<'a, EventsQueryOutcome>;
}

impl<F, Fut> EventsScanTransport for F
where
    F: Fn(EventsScanRequest) -> Fut + MaybeSendSync,
    Fut: Future<Output = Result<EventsQueryOutcome>> + MaybeSend + 'static,
{
    fn scan_events<'a>(
        &'a self,
        request: EventsScanRequest,
    ) -> BoxScanFuture<'a, EventsQueryOutcome> {
        Box::pin(self(request))
    }
}

impl EventsScanTransport for arkret_http_client::Client {
    fn scan_events<'a>(
        &'a self,
        request: EventsScanRequest,
    ) -> BoxScanFuture<'a, EventsQueryOutcome> {
        Box::pin(async move {
            self.events_read_outcome(
                request.realm_id.as_str(),
                request.before.as_deref(),
                request.after.as_deref(),
                request.order.map(EventsQueryOrder::as_str),
                request.limit,
            )
            .await
            .map_err(crate::protocol::Error::from)
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScanCatchupOptions {
    pub before: Option<OpaqueCursor>,
    pub after: Option<OpaqueCursor>,
    pub order: Option<EventsQueryOrder>,
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

/// Paged realm-history scan. Scans are always uncheckpointed: scan and
/// subscribe cursors carry different filter digests and are not
/// interchangeable, so a scan never writes a cursor slot; the caller supplies
/// any resume position explicitly through [`ScanCatchupOptions::after`].
pub(crate) async fn scan_realm_catchup_uncheckpointed_classified<T>(
    transport: &T,
    realm_id: RealmId,
    options: ScanCatchupOptions,
) -> ProjectedRunResult<EventsQueryOutcome>
where
    T: EventsScanTransport + ?Sized,
{
    let mut after = options.after;
    let mut aggregate = EventsQueryOutcome {
        events: Vec::new(),
        snapshot_bootstrap: None,
        prev_cursor: None,
        next_cursor: None,
        has_more: false,
    };
    let max_pages = options.max_pages.max(1);

    for _ in 0..max_pages {
        let mut outcome = transport
            .scan_events(EventsScanRequest {
                realm_id: realm_id.clone(),
                before: options.before.clone(),
                after,
                order: options.order,
                limit: options.limit,
            })
            .await
            .map_err(ProjectedRunError::Transport)?;
        if aggregate.prev_cursor.is_none() {
            aggregate.prev_cursor = outcome.prev_cursor.clone();
        }
        if aggregate.snapshot_bootstrap.is_none() {
            aggregate.snapshot_bootstrap = outcome.snapshot_bootstrap.take();
        }
        let next_cursor = outcome.next_cursor.clone();
        let has_more = outcome.has_more;
        aggregate.events.append(&mut outcome.events);
        aggregate.next_cursor = next_cursor.clone();
        aggregate.has_more = has_more;

        match (has_more, next_cursor) {
            (true, Some(next)) => after = Some(next),
            _ => return Ok(aggregate),
        }
    }

    aggregate.has_more = true;
    Ok(aggregate)
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    use super::*;

    fn realm_id() -> RealmId {
        RealmId::new("ak:realm:AfF-hFqRoMbajXkPapH-xaq0xwK-UKt2ph2zTs9JZRAO").unwrap()
    }

    fn outcome(next_cursor: Option<&str>, has_more: bool) -> EventsQueryOutcome {
        EventsQueryOutcome {
            events: Vec::new(),
            snapshot_bootstrap: None,
            prev_cursor: None,
            next_cursor: next_cursor.map(str::to_owned),
            has_more,
        }
    }

    #[tokio::test]
    async fn scan_catchup_pages_until_range_is_not_limited() {
        let responses = Arc::new(Mutex::new(VecDeque::from([
            outcome(Some("ak:cursor:p2"), true),
            outcome(Some("ak:cursor:p3"), false),
        ])));
        let afters = Arc::new(Mutex::new(Vec::new()));
        let responses_for_transport = Arc::clone(&responses);
        let afters_for_transport = Arc::clone(&afters);
        let transport = move |request: EventsScanRequest| {
            afters_for_transport.lock().unwrap().push(request.after);
            let responses_for_transport = Arc::clone(&responses_for_transport);
            async move { Ok(responses_for_transport.lock().unwrap().pop_front().unwrap()) }
        };

        let response = scan_realm_catchup_uncheckpointed_classified(
            &transport,
            realm_id(),
            ScanCatchupOptions::default(),
        )
        .await
        .map_err(ProjectedRunError::into_error)
        .unwrap();

        assert!(!response.has_more);
        assert_eq!(response.next_cursor.as_deref(), Some("ak:cursor:p3"));
        assert_eq!(
            afters.lock().unwrap().as_slice(),
            &[None, Some("ak:cursor:p2".to_owned())]
        );
    }
}
