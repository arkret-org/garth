pub mod account;
pub mod dedupe;
pub mod driver;
pub mod realm;
pub mod scan;
#[cfg(test)]
mod test_support;

pub use account::emit_account_updates;
use cokret::{
    AsyncSyncTransport, SyncGapStrategy, SyncLoop, SyncLoopControl, SyncLoopSnapshot, SyncLoopStep,
};
use cokret_core::{DeviceId, Did, RealmId, Result};
pub use driver::{SubscriptionLoopDriver, SubscriptionStopReason};
pub use realm::{
    BoxRealmStreamFuture, RealmEventsDriver, RealmEventsFrameSource, RealmEventsTransport,
    RealmStreamStopReason,
};
pub use scan::{EventsScanRequest, EventsScanTransport, ScanCatchup, ScanCatchupOptions};

use crate::{
    ClientEvent, ClientEventSink, ClientProjector, CursorScope, CursorStore, EventCacheStore,
    Executor, OpaqueCursor,
};

#[derive(Clone, Debug)]
pub struct SubscriptionEngine<E, C, D> {
    executor: E,
    cursor_store: C,
    event_cache_store: D,
    control: SyncLoopControl,
    service_did: Option<Did>,
}

impl<E, C, D> SubscriptionEngine<E, C, D>
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
            control: SyncLoopControl::new(),
            service_did: None,
        }
    }

    pub fn with_service_did(mut self, service_did: Did) -> Self {
        self.service_did = Some(service_did);
        self
    }

    /// Use a caller-owned cancellation control instead of the engine's own, so
    /// a host that holds a clone can `cancel()` a running loop (used by the
    /// [`crate::CokretClient`] orchestrator).
    pub fn with_control(mut self, control: SyncLoopControl) -> Self {
        self.control = control;
        self
    }

    pub fn control(&self) -> SyncLoopControl {
        self.control.clone()
    }

    pub fn cancel(&self) {
        self.control.cancel();
    }

    pub async fn run_account<T, S>(
        &self,
        actor_id: Did,
        device_id: DeviceId,
        transport: &T,
        sink: &S,
    ) -> Result<SubscriptionStopReason>
    where
        T: AsyncSyncTransport + ?Sized,
        S: ClientEventSink + ?Sized,
    {
        let scope = self.account_scope(actor_id, device_id);
        let mut sync_loop = self.restore_account_loop(scope.clone()).await?;

        // Reuse the shared account loop from `SubscriptionLoopDriver`, injecting
        // cursor checkpointing as the per-step hook so the `SyncLoopStep`
        // dispatch is not duplicated across the two entry points.
        let driver =
            SubscriptionLoopDriver::with_control(self.executor.clone(), self.control.clone());
        driver
            .run_account_checkpointed(&mut sync_loop, transport, sink, |token| {
                self.checkpoint_account_cursor(scope.clone(), token)
            })
            .await
    }

    /// Projector-driven account loop (orchestrator seam). Unlike
    /// [`Self::run_account`] — which checkpoints the cursor BEFORE emitting to
    /// the sink — this awaits the async [`ClientProjector`] and checkpoints the
    /// cursor ONLY after `project` returns `Ok`, so the projector's durable
    /// write gates cursor advance (uniform with the realm loop, crash-safe).
    pub async fn run_account_projected<T, P>(
        &self,
        actor_id: Did,
        device_id: DeviceId,
        transport: &T,
        projector: &P,
    ) -> Result<SubscriptionStopReason>
    where
        T: AsyncSyncTransport + ?Sized,
        P: ClientProjector + ?Sized,
    {
        let scope = self.account_scope(actor_id, device_id);
        let mut sync_loop = self.restore_account_loop(scope.clone()).await?;

        loop {
            match sync_loop
                .step_async_with_control(transport, &self.control)
                .await
            {
                SyncLoopStep::Updates(updates) => {
                    let batch = account::account_updates_to_events(updates);
                    if !batch.is_empty() {
                        // Gate: project must persist before the cursor moves.
                        projector.project(batch).await?;
                    }
                    self.checkpoint_account_cursor(
                        scope.clone(),
                        sync_loop.token().map(str::to_owned),
                    )
                    .await?;
                }
                SyncLoopStep::Retry { retry_after, .. } => {
                    self.checkpoint_account_cursor(
                        scope.clone(),
                        sync_loop.token().map(str::to_owned),
                    )
                    .await?;
                    self.executor.sleep(retry_after).await;
                }
                SyncLoopStep::Backpressure { retry_after } => {
                    self.executor.sleep(retry_after).await;
                }
                SyncLoopStep::Cancelled => return Ok(SubscriptionStopReason::Cancelled),
                SyncLoopStep::Unauthorized { reason } => {
                    return Ok(SubscriptionStopReason::Unauthorized { reason });
                }
            }
        }
    }

    pub async fn run_realm<T, S>(
        &self,
        transport: &T,
        realm_id: RealmId,
        sink: &S,
    ) -> Result<RealmStreamStopReason>
    where
        T: RealmEventsTransport + EventsScanTransport + ?Sized,
        S: ClientEventSink + ?Sized,
    {
        let mut driver =
            RealmEventsDriver::new(self.cursor_store.clone(), self.event_cache_store.clone());
        if let Some(service_did) = self.service_did.clone() {
            driver = driver.with_service_did(service_did);
        }
        let reason = driver.run_realm(transport, realm_id.clone(), sink).await?;
        match reason {
            RealmStreamStopReason::Dropped {
                cursor: Some(cursor),
                reconnect_after_ms,
            } => {
                let outcome = self
                    .scan_realm_catchup(
                        transport,
                        realm_id.clone(),
                        ScanCatchupOptions {
                            before: Some(cursor.clone()),
                            after: None,
                            order: None,
                            limit: None,
                            max_pages: 64,
                        },
                    )
                    .await?;
                sink.emit(ClientEvent::Backfill { realm_id, outcome });
                if let Some(reconnect_after_ms) = reconnect_after_ms {
                    self.executor
                        .sleep(std::time::Duration::from_millis(reconnect_after_ms))
                        .await;
                }
                Ok(RealmStreamStopReason::Dropped {
                    cursor: Some(cursor),
                    reconnect_after_ms,
                })
            }
            RealmStreamStopReason::Dropped {
                cursor: None,
                reconnect_after_ms,
            } => {
                self.cursor_store.clear(self.realm_scope(realm_id)).await?;
                if let Some(reconnect_after_ms) = reconnect_after_ms {
                    self.executor
                        .sleep(std::time::Duration::from_millis(reconnect_after_ms))
                        .await;
                }
                Ok(RealmStreamStopReason::ResyncRequired { reconnect_after_ms })
            }
            other => Ok(other),
        }
    }

    /// Projector-driven realm loop (orchestrator seam). Mirrors
    /// [`Self::run_realm`] — including the `Dropped` -> scan-catchup ->
    /// backfill recovery — but the recovered backfill and every decoded event
    /// go through the async [`ClientProjector`], and the cursor advances only
    /// after `project` returns `Ok` (see
    /// [`RealmEventsDriver::run_realm_projected`]).
    pub async fn run_realm_projected<T, P>(
        &self,
        transport: &T,
        realm_id: RealmId,
        projector: &P,
    ) -> Result<RealmStreamStopReason>
    where
        T: RealmEventsTransport + EventsScanTransport + ?Sized,
        P: ClientProjector + ?Sized,
    {
        let mut driver =
            RealmEventsDriver::new(self.cursor_store.clone(), self.event_cache_store.clone());
        if let Some(service_did) = self.service_did.clone() {
            driver = driver.with_service_did(service_did);
        }
        let reason = driver
            .run_realm_projected(transport, realm_id.clone(), projector)
            .await?;
        match reason {
            RealmStreamStopReason::Dropped {
                cursor: Some(cursor),
                reconnect_after_ms,
            } => {
                let outcome = self
                    .scan_realm_catchup_uncheckpointed(
                        transport,
                        realm_id.clone(),
                        ScanCatchupOptions {
                            before: Some(cursor.clone()),
                            after: None,
                            order: None,
                            limit: None,
                            max_pages: 64,
                        },
                    )
                    .await?;
                let next_cursor = outcome.next_cursor.clone();
                projector
                    .project(vec![ClientEvent::Backfill {
                        realm_id: realm_id.clone(),
                        outcome,
                    }])
                    .await?;
                self.save_realm_cursor_after_project(realm_id.clone(), next_cursor)
                    .await?;
                if let Some(reconnect_after_ms) = reconnect_after_ms {
                    self.executor
                        .sleep(std::time::Duration::from_millis(reconnect_after_ms))
                        .await;
                }
                Ok(RealmStreamStopReason::Dropped {
                    cursor: Some(cursor),
                    reconnect_after_ms,
                })
            }
            RealmStreamStopReason::Dropped {
                cursor: None,
                reconnect_after_ms,
            } => {
                self.cursor_store.clear(self.realm_scope(realm_id)).await?;
                if let Some(reconnect_after_ms) = reconnect_after_ms {
                    self.executor
                        .sleep(std::time::Duration::from_millis(reconnect_after_ms))
                        .await;
                }
                Ok(RealmStreamStopReason::ResyncRequired { reconnect_after_ms })
            }
            other => Ok(other),
        }
    }

    pub async fn scan_realm_catchup<T>(
        &self,
        transport: &T,
        realm_id: RealmId,
        options: ScanCatchupOptions,
    ) -> Result<cokret_core::SyncBackfillOutcome>
    where
        T: EventsScanTransport + ?Sized,
    {
        let mut scan = ScanCatchup::new(self.cursor_store.clone());
        if let Some(service_did) = self.service_did.clone() {
            scan = scan.with_service_did(service_did);
        }
        scan.scan_realm_catchup(transport, realm_id, options).await
    }

    async fn scan_realm_catchup_uncheckpointed<T>(
        &self,
        transport: &T,
        realm_id: RealmId,
        options: ScanCatchupOptions,
    ) -> Result<cokret_core::SyncBackfillOutcome>
    where
        T: EventsScanTransport + ?Sized,
    {
        let mut scan = ScanCatchup::new(self.cursor_store.clone());
        if let Some(service_did) = self.service_did.clone() {
            scan = scan.with_service_did(service_did);
        }
        scan.scan_realm_catchup_uncheckpointed(transport, realm_id, options)
            .await
    }

    async fn save_realm_cursor_after_project(
        &self,
        realm_id: RealmId,
        next_cursor: Option<OpaqueCursor>,
    ) -> Result<()> {
        if let Some(next_cursor) = next_cursor {
            self.cursor_store
                .save(self.realm_scope(realm_id), next_cursor)
                .await?;
        }
        Ok(())
    }

    async fn restore_account_loop(&self, scope: CursorScope) -> Result<SyncLoop> {
        let token = self.cursor_store.load(scope).await?;
        Ok(SyncLoop::from_snapshot(SyncLoopSnapshot {
            token,
            timeout_ms: 30_000,
            gap_strategy: SyncGapStrategy::PreserveTokenAndBackfill,
        }))
    }

    async fn checkpoint_account_cursor(
        &self,
        scope: CursorScope,
        token: Option<OpaqueCursor>,
    ) -> Result<()> {
        match token {
            Some(cursor) => self.cursor_store.save(scope, cursor).await,
            None => self.cursor_store.clear(scope).await,
        }
    }

    fn account_scope(&self, actor_id: Did, device_id: DeviceId) -> CursorScope {
        CursorScope::Account {
            service_did: self.service_did.clone(),
            actor_id,
            device_id,
        }
    }

    fn realm_scope(&self, realm_id: RealmId) -> CursorScope {
        CursorScope::RealmEvents {
            service_did: self.service_did.clone(),
            realm_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use cokret::{AccountStreamInterrupt, Error, SyncRequestBody};
    use cokret_core::identifiers::Cursor;
    use cokret_core::{EventsSubscribeFrame, EventsSubscribeFrameKind, SyncBackfillOutcome};
    use serde_json::Value;

    use super::realm::BoxRealmStreamFuture;
    use super::scan::BoxScanFuture;
    use super::test_support::{RecordingExecutor, queued_transport, sync_response};
    use super::*;
    use crate::{ClientEvent, MemoryStore};

    fn actor_id() -> Did {
        Did::new("did:webvh:z6mkfixture:alice.example").unwrap()
    }

    fn device_id() -> DeviceId {
        DeviceId::new("ck:device:01904100-0000-7000-8000-000000000001").unwrap()
    }

    fn realm_id() -> RealmId {
        RealmId::new("ck:realm:01904100-0000-7000-8000-000000000001").unwrap()
    }

    fn account_scope() -> CursorScope {
        CursorScope::Account {
            service_did: None,
            actor_id: actor_id(),
            device_id: device_id(),
        }
    }

    fn realm_scope() -> CursorScope {
        CursorScope::RealmEvents {
            service_did: None,
            realm_id: realm_id(),
        }
    }

    fn backfill_outcome(next_cursor: Option<&str>) -> SyncBackfillOutcome {
        SyncBackfillOutcome {
            events: Vec::new(),
            snapshot_bootstrap: None,
            prev_cursor: None,
            next_cursor: next_cursor.map(str::to_owned),
            limited: false,
        }
    }

    fn realm_frame(kind: EventsSubscribeFrameKind) -> EventsSubscribeFrame {
        EventsSubscribeFrame {
            kind,
            realm_id: Some(realm_id()),
            cursor: None,
            payload: Value::Null,
            reconnect_after_ms: None,
        }
    }

    #[tokio::test]
    async fn engine_restores_and_checkpoints_account_cursor() {
        let store = MemoryStore::new();
        store
            .save(account_scope(), "ck:cursor:stored".to_owned())
            .await
            .unwrap();
        let seen_after = Arc::new(Mutex::new(Vec::new()));
        let seen_after_for_transport = Arc::clone(&seen_after);
        let transport = move |request: SyncRequestBody| {
            seen_after_for_transport.lock().unwrap().push(request.after);
            async { Ok(sync_response("ck:cursor:next")) }
        };
        let engine =
            SubscriptionEngine::new(RecordingExecutor::default(), store.clone(), store.clone());
        let control = engine.control();
        let sink = move |event: ClientEvent| {
            if matches!(event, ClientEvent::AccountUpdates(_)) {
                control.cancel();
            }
        };

        let reason = engine
            .run_account(actor_id(), device_id(), &transport, &sink)
            .await
            .unwrap();

        assert_eq!(reason, SubscriptionStopReason::Cancelled);
        assert_eq!(
            seen_after.lock().unwrap().as_slice(),
            &[Some("ck:cursor:stored".to_owned())]
        );
        assert_eq!(
            store.load(account_scope()).await.unwrap().as_deref(),
            Some("ck:cursor:next")
        );
    }

    #[tokio::test]
    async fn engine_clears_account_cursor_after_resync_interrupt() {
        let store = MemoryStore::new();
        store
            .save(account_scope(), "ck:cursor:stored".to_owned())
            .await
            .unwrap();
        let executor = RecordingExecutor::default();
        let responses = Arc::new(Mutex::new(VecDeque::from([
            Err(Error::AccountStreamInterrupt(
                AccountStreamInterrupt::ResyncRequired {
                    reconnect_after_ms: Some(15),
                },
            )),
            Err(Error::AccountStreamInterrupt(
                AccountStreamInterrupt::Unauthorized {
                    reason: Some("revoked".to_owned()),
                },
            )),
        ])));
        let transport = queued_transport(responses);
        let engine = SubscriptionEngine::new(executor.clone(), store.clone(), store.clone());

        let reason = engine
            .run_account(
                actor_id(),
                device_id(),
                &transport,
                &|_event: ClientEvent| {},
            )
            .await
            .unwrap();

        assert_eq!(
            reason,
            SubscriptionStopReason::Unauthorized {
                reason: Some("revoked".to_owned())
            }
        );
        assert!(store.load(account_scope()).await.unwrap().is_none());
        assert_eq!(executor.sleeps(), vec![Duration::from_millis(15)]);
    }

    struct VecRealmSource {
        frames: VecDeque<EventsSubscribeFrame>,
    }

    impl RealmEventsFrameSource for VecRealmSource {
        fn next_frame<'a>(&'a mut self) -> BoxRealmStreamFuture<'a, Option<EventsSubscribeFrame>> {
            let frame = self.frames.pop_front();
            Box::pin(async move { Ok(frame) })
        }
    }

    struct RealmRecoveryTransport {
        source: Mutex<Option<VecRealmSource>>,
        scans: Arc<Mutex<Vec<EventsScanRequest>>>,
        scan_outcomes: Arc<Mutex<VecDeque<SyncBackfillOutcome>>>,
    }

    impl RealmRecoveryTransport {
        fn new(frames: Vec<EventsSubscribeFrame>, outcomes: Vec<SyncBackfillOutcome>) -> Self {
            Self {
                source: Mutex::new(Some(VecRealmSource {
                    frames: VecDeque::from(frames),
                })),
                scans: Arc::new(Mutex::new(Vec::new())),
                scan_outcomes: Arc::new(Mutex::new(VecDeque::from(outcomes))),
            }
        }

        fn scans(&self) -> Vec<EventsScanRequest> {
            self.scans.lock().unwrap().clone()
        }
    }

    impl RealmEventsTransport for RealmRecoveryTransport {
        type Source = VecRealmSource;

        fn open_realm_events<'a>(
            &'a self,
            _realm_id: &'a RealmId,
            _after: Option<&'a str>,
        ) -> BoxRealmStreamFuture<'a, Self::Source> {
            let source = self.source.lock().unwrap().take().unwrap();
            Box::pin(async move { Ok(source) })
        }
    }

    impl EventsScanTransport for RealmRecoveryTransport {
        fn scan_events<'a>(
            &'a self,
            request: EventsScanRequest,
        ) -> BoxScanFuture<'a, SyncBackfillOutcome> {
            self.scans.lock().unwrap().push(request);
            let outcome = self.scan_outcomes.lock().unwrap().pop_front().unwrap();
            Box::pin(async move { Ok(outcome) })
        }
    }

    struct RecordingProjector {
        batches: Arc<Mutex<Vec<usize>>>,
        fail: bool,
    }

    impl ClientProjector for RecordingProjector {
        fn project(
            &self,
            batch: Vec<ClientEvent>,
        ) -> impl std::future::Future<Output = Result<()>> + '_ {
            let batches = Arc::clone(&self.batches);
            let fail = self.fail;
            async move {
                batches.lock().unwrap().push(batch.len());
                if fail {
                    Err(Error::Protocol("projector failed".to_owned()))
                } else {
                    Ok(())
                }
            }
        }
    }

    #[tokio::test]
    async fn engine_recovers_dropped_realm_stream_with_scan_catchup() {
        let store = MemoryStore::new();
        store
            .save(realm_scope(), "ck:cursor:stored".to_owned())
            .await
            .unwrap();
        let executor = RecordingExecutor::default();
        let mut dropped = realm_frame(EventsSubscribeFrameKind::Dropped);
        dropped.cursor = Some(Cursor::new("ck:cursor:dropped").unwrap());
        dropped.reconnect_after_ms = Some(25);
        let transport = RealmRecoveryTransport::new(
            vec![dropped],
            vec![backfill_outcome(Some("ck:cursor:next"))],
        );
        let emitted = Arc::new(Mutex::new(Vec::new()));
        let emitted_for_sink = Arc::clone(&emitted);
        let engine = SubscriptionEngine::new(executor.clone(), store.clone(), store.clone());

        let reason = engine
            .run_realm(&transport, realm_id(), &move |event: ClientEvent| {
                emitted_for_sink.lock().unwrap().push(event);
            })
            .await
            .unwrap();

        assert_eq!(
            reason,
            RealmStreamStopReason::Dropped {
                cursor: Some("ck:cursor:dropped".to_owned()),
                reconnect_after_ms: Some(25)
            }
        );
        let scans = transport.scans();
        assert_eq!(scans.len(), 1);
        assert_eq!(scans[0].after.as_deref(), Some("ck:cursor:stored"));
        assert_eq!(scans[0].before.as_deref(), Some("ck:cursor:dropped"));
        assert_eq!(
            store.load(realm_scope()).await.unwrap().as_deref(),
            Some("ck:cursor:next")
        );
        assert_eq!(executor.sleeps(), vec![Duration::from_millis(25)]);
        assert!(matches!(
            emitted.lock().unwrap().as_slice(),
            [ClientEvent::Backfill { .. }]
        ));
    }

    #[tokio::test]
    async fn engine_projected_backfill_checkpoints_after_project_ok() {
        let store = MemoryStore::new();
        store
            .save(realm_scope(), "ck:cursor:stored".to_owned())
            .await
            .unwrap();
        let mut dropped = realm_frame(EventsSubscribeFrameKind::Dropped);
        dropped.cursor = Some(Cursor::new("ck:cursor:dropped").unwrap());
        let transport = RealmRecoveryTransport::new(
            vec![dropped],
            vec![backfill_outcome(Some("ck:cursor:next"))],
        );
        let projector = RecordingProjector {
            batches: Arc::new(Mutex::new(Vec::new())),
            fail: false,
        };
        let engine =
            SubscriptionEngine::new(RecordingExecutor::default(), store.clone(), store.clone());

        let reason = engine
            .run_realm_projected(&transport, realm_id(), &projector)
            .await
            .unwrap();

        assert_eq!(
            reason,
            RealmStreamStopReason::Dropped {
                cursor: Some("ck:cursor:dropped".to_owned()),
                reconnect_after_ms: None
            }
        );
        assert_eq!(projector.batches.lock().unwrap().as_slice(), &[1]);
        assert_eq!(
            store.load(realm_scope()).await.unwrap().as_deref(),
            Some("ck:cursor:next")
        );
    }

    #[tokio::test]
    async fn engine_projected_backfill_does_not_checkpoint_when_project_errs() {
        let store = MemoryStore::new();
        store
            .save(realm_scope(), "ck:cursor:stored".to_owned())
            .await
            .unwrap();
        let mut dropped = realm_frame(EventsSubscribeFrameKind::Dropped);
        dropped.cursor = Some(Cursor::new("ck:cursor:dropped").unwrap());
        let transport = RealmRecoveryTransport::new(
            vec![dropped],
            vec![backfill_outcome(Some("ck:cursor:next"))],
        );
        let projector = RecordingProjector {
            batches: Arc::new(Mutex::new(Vec::new())),
            fail: true,
        };
        let engine =
            SubscriptionEngine::new(RecordingExecutor::default(), store.clone(), store.clone());

        let result = engine
            .run_realm_projected(&transport, realm_id(), &projector)
            .await;

        assert!(result.is_err());
        assert_eq!(projector.batches.lock().unwrap().as_slice(), &[1]);
        assert_eq!(
            store.load(realm_scope()).await.unwrap().as_deref(),
            Some("ck:cursor:stored")
        );
    }

    #[tokio::test]
    async fn engine_treats_dropped_without_cursor_as_realm_resync() {
        let store = MemoryStore::new();
        store
            .save(realm_scope(), "ck:cursor:stored".to_owned())
            .await
            .unwrap();
        let executor = RecordingExecutor::default();
        let mut dropped = realm_frame(EventsSubscribeFrameKind::Dropped);
        dropped.reconnect_after_ms = Some(40);
        let transport = RealmRecoveryTransport::new(vec![dropped], Vec::new());
        let engine = SubscriptionEngine::new(executor.clone(), store.clone(), store.clone());

        let reason = engine
            .run_realm(&transport, realm_id(), &|_event: ClientEvent| {})
            .await
            .unwrap();

        assert_eq!(
            reason,
            RealmStreamStopReason::ResyncRequired {
                reconnect_after_ms: Some(40)
            }
        );
        assert!(transport.scans().is_empty());
        assert!(store.load(realm_scope()).await.unwrap().is_none());
        assert_eq!(executor.sleeps(), vec![Duration::from_millis(40)]);
    }
}
