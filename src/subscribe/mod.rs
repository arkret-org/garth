pub mod account;
pub mod driver;
pub mod realm;
pub mod scan;
#[cfg(test)]
pub(crate) mod test_support;

pub use account::account_updates_to_events;
use arkret::{AsyncSyncTransport, SyncGapStrategy, SyncLoop, SyncLoopControl, SyncLoopSnapshot};
use arkret_core::{DeviceId, Did, Error, RealmId, Result};
pub use driver::{SubscriptionLoopDriver, SubscriptionStopReason};
pub use realm::{
    BoxRealmStreamFuture, RealmEventsDriver, RealmEventsFrameSource, RealmEventsTransport,
    RealmStreamStopReason,
};
pub use scan::{EventsScanRequest, EventsScanTransport, ScanCatchup, ScanCatchupOptions};

use crate::{
    ClientEvent, ClientProjector, CursorScope, CursorStore, DurableInboxStore, EventCacheStore,
    Executor, OpaqueCursor,
};

pub(crate) type ProjectedRunResult<T> = std::result::Result<T, ProjectedRunError>;

#[derive(Debug)]
pub(crate) enum ProjectedRunError {
    Store(Error),
    Transport(Error),
    Projector(Error),
}

impl ProjectedRunError {
    pub(crate) fn into_error(self) -> Error {
        match self {
            Self::Store(error) | Self::Transport(error) | Self::Projector(error) => error,
        }
    }
}

#[derive(Clone, Debug)]
pub struct SubscriptionEngine<E, C, D> {
    executor: E,
    cursor_store: C,
    event_cache_store: D,
    control: SyncLoopControl,
    service_id: Option<Did>,
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
            service_id: None,
        }
    }

    pub fn with_service_id(mut self, service_id: Did) -> Self {
        self.service_id = Some(service_id);
        self
    }

    /// Use a caller-owned cancellation control instead of the engine's own, so
    /// a host that holds a clone can `cancel()` a running loop (used by the
    /// [`crate::ArkretClient`] orchestrator).
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

    pub async fn run_account<T, P>(
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
        let cursor_store = self.cursor_store.clone();
        SubscriptionLoopDriver::with_control(self.executor.clone(), self.control.clone())
            .run_account_checkpointed(&mut sync_loop, transport, projector, move |token| {
                let cursor_store = cursor_store.clone();
                let scope = scope.clone();
                async move {
                    match token {
                        Some(cursor) => cursor_store.save(scope, cursor).await,
                        None => cursor_store.clear(scope).await,
                    }
                }
            })
            .await
            .map_err(ProjectedRunError::into_error)
    }

    /// Account subscription with atomic cursor + durable-inbox delivery.
    /// Available when the engine's cursor store is also the inbox store, which
    /// prevents a process crash from advancing beyond undispatched work.
    pub async fn run_account_to_inbox<T>(
        &self,
        actor_id: Did,
        device_id: DeviceId,
        transport: &T,
    ) -> Result<SubscriptionStopReason>
    where
        T: AsyncSyncTransport + ?Sized,
        C: DurableInboxStore,
    {
        let scope = self.account_scope(actor_id, device_id);
        let mut sync_loop = self.restore_account_loop(scope.clone()).await?;
        SubscriptionLoopDriver::with_control(self.executor.clone(), self.control.clone())
            .run_account_to_inbox(&mut sync_loop, transport, scope, &self.cursor_store)
            .await
    }

    pub async fn run_realm_stream<T, P>(
        &self,
        transport: &T,
        realm_id: RealmId,
        projector: &P,
    ) -> Result<RealmStreamStopReason>
    where
        T: RealmEventsTransport + EventsScanTransport + ?Sized,
        P: ClientProjector + ?Sized,
    {
        self.run_realm_stream_classified(transport, realm_id, projector)
            .await
            .map_err(ProjectedRunError::into_error)
    }

    /// Realm subscription with atomic cursor + durable-inbox delivery.
    pub async fn run_realm_stream_to_inbox<T>(
        &self,
        transport: &T,
        realm_id: RealmId,
    ) -> Result<RealmStreamStopReason>
    where
        T: RealmEventsTransport + ?Sized,
        C: DurableInboxStore,
    {
        let mut driver =
            RealmEventsDriver::new(self.cursor_store.clone(), self.event_cache_store.clone());
        if let Some(service_id) = self.service_id.clone() {
            driver = driver.with_service_id(service_id);
        }
        driver.run_stream_to_inbox(transport, realm_id).await
    }

    pub(crate) async fn run_realm_stream_classified<T, P>(
        &self,
        transport: &T,
        realm_id: RealmId,
        projector: &P,
    ) -> ProjectedRunResult<RealmStreamStopReason>
    where
        T: RealmEventsTransport + EventsScanTransport + ?Sized,
        P: ClientProjector + ?Sized,
    {
        let mut driver =
            RealmEventsDriver::new(self.cursor_store.clone(), self.event_cache_store.clone());
        if let Some(service_id) = self.service_id.clone() {
            driver = driver.with_service_id(service_id);
        }
        let reason = driver
            .run_stream_classified(transport, realm_id.clone(), projector)
            .await?;
        match reason {
            // A cursorless dropped frame is rejected as a trace violation
            // inside the driver (the server MUST send `resync_required`), so
            // the dropped cursor is always available for scan backfill.
            RealmStreamStopReason::Dropped {
                cursor,
                reconnect_after_ms,
            } => {
                let outcome = self
                    .scan_realm_catchup_uncheckpointed_classified(
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
                    .await
                    .map_err(ProjectedRunError::Projector)?;
                self.save_realm_cursor_after_project(realm_id.clone(), next_cursor)
                    .await
                    .map_err(ProjectedRunError::Store)?;
                Ok(RealmStreamStopReason::Dropped {
                    cursor,
                    reconnect_after_ms,
                })
            }
            other => Ok(other),
        }
    }

    pub async fn scan_realm_catchup<T>(
        &self,
        transport: &T,
        realm_id: RealmId,
        options: ScanCatchupOptions,
    ) -> Result<arkret_core::SyncBackfillOutcome>
    where
        T: EventsScanTransport + ?Sized,
    {
        let mut scan = ScanCatchup::new(self.cursor_store.clone());
        if let Some(service_id) = self.service_id.clone() {
            scan = scan.with_service_id(service_id);
        }
        scan.scan_realm_catchup(transport, realm_id, options).await
    }

    /// Scan durable Realm history, project it, and only then checkpoint the
    /// returned cursor. This is the crash-safe bootstrap path for a client
    /// that has no Realm stream cursor yet; `events/subscribe` without an
    /// `after` cursor is a live tail, not an implicit full-history replay.
    pub async fn bootstrap_realm_history<T, P>(
        &self,
        transport: &T,
        realm_id: RealmId,
        projector: &P,
        options: ScanCatchupOptions,
    ) -> Result<arkret_core::SyncBackfillOutcome>
    where
        T: EventsScanTransport + ?Sized,
        P: ClientProjector + ?Sized,
    {
        let outcome = self
            .scan_realm_catchup_uncheckpointed_classified(transport, realm_id.clone(), options)
            .await
            .map_err(ProjectedRunError::into_error)?;

        let decoder = arkret_core::InboundDecoder::new();
        let mut batch = Vec::new();
        let mut accepted_ids = Vec::new();
        for event in outcome.events.iter().cloned() {
            let event_id = event.event_id.clone();
            if self.event_cache_store.seen(event_id.clone()).await? {
                continue;
            }
            match decoder.decode_event(event) {
                arkret_core::DecodedInbound::Message(message) => {
                    batch.push(ClientEvent::Message(message));
                }
                arkret_core::DecodedInbound::Event(event) => {
                    batch.push(ClientEvent::Event(event));
                }
            }
            accepted_ids.push(event_id);
        }
        if !batch.is_empty() {
            projector.project(batch).await?;
            for event_id in accepted_ids {
                self.event_cache_store.remember(event_id).await?;
            }
        }
        self.save_realm_cursor_after_project(realm_id, outcome.next_cursor.clone())
            .await?;
        Ok(outcome)
    }

    async fn scan_realm_catchup_uncheckpointed_classified<T>(
        &self,
        transport: &T,
        realm_id: RealmId,
        options: ScanCatchupOptions,
    ) -> ProjectedRunResult<arkret_core::SyncBackfillOutcome>
    where
        T: EventsScanTransport + ?Sized,
    {
        let mut scan = ScanCatchup::new(self.cursor_store.clone());
        if let Some(service_id) = self.service_id.clone() {
            scan = scan.with_service_id(service_id);
        }
        scan.scan_realm_catchup_uncheckpointed_classified(transport, realm_id, options)
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

    pub(crate) async fn restore_account_loop(&self, scope: CursorScope) -> Result<SyncLoop> {
        let token = self.cursor_store.load(scope).await?;
        Ok(SyncLoop::from_snapshot(SyncLoopSnapshot {
            token,
            timeout_ms: 30_000,
            gap_strategy: SyncGapStrategy::PreserveTokenAndBackfill,
        }))
    }

    pub(crate) async fn checkpoint_account_cursor(
        &self,
        scope: CursorScope,
        token: Option<OpaqueCursor>,
    ) -> Result<()> {
        match token {
            Some(cursor) => self.cursor_store.save(scope, cursor).await,
            None => self.cursor_store.clear(scope).await,
        }
    }

    pub(crate) fn account_scope(&self, actor_id: Did, device_id: DeviceId) -> CursorScope {
        CursorScope::Account {
            service_id: self.service_id.clone(),
            actor_id,
            device_id,
        }
    }

    fn realm_scope(&self, realm_id: RealmId) -> CursorScope {
        CursorScope::RealmEvents {
            service_id: self.service_id.clone(),
            realm_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use arkret::{AccountStreamInterrupt, Error, SyncRequestBody};
    use arkret_core::identifiers::Cursor;
    use arkret_core::{EventsSubscribeFrame, EventsSubscribeFrameKind, SyncBackfillOutcome};
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
        DeviceId::new("ak:device:01904100-0000-7000-8000-000000000001").unwrap()
    }

    fn realm_id() -> RealmId {
        RealmId::new("ak:realm:01904100-0000-7000-8000-000000000001").unwrap()
    }

    fn account_scope() -> CursorScope {
        CursorScope::Account {
            service_id: None,
            actor_id: actor_id(),
            device_id: device_id(),
        }
    }

    fn realm_scope() -> CursorScope {
        CursorScope::RealmEvents {
            service_id: None,
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
            .save(account_scope(), "ak:cursor:stored".to_owned())
            .await
            .unwrap();
        let seen_after = Arc::new(Mutex::new(Vec::new()));
        let seen_after_for_transport = Arc::clone(&seen_after);
        let transport = move |request: SyncRequestBody| {
            seen_after_for_transport.lock().unwrap().push(request.after);
            async { Ok(sync_response("ak:cursor:next")) }
        };
        let engine =
            SubscriptionEngine::new(RecordingExecutor::default(), store.clone(), store.clone());
        let control = engine.control();
        let projector = RecordingProjector {
            batches: Arc::new(Mutex::new(Vec::new())),
            fail: false,
            control: Some(control),
        };

        let reason = engine
            .run_account(actor_id(), device_id(), &transport, &projector)
            .await
            .unwrap();

        assert_eq!(reason, SubscriptionStopReason::Cancelled);
        assert_eq!(
            seen_after.lock().unwrap().as_slice(),
            &[Some("ak:cursor:stored".to_owned())]
        );
        assert_eq!(
            store.load(account_scope()).await.unwrap().as_deref(),
            Some("ak:cursor:next")
        );
    }

    #[tokio::test]
    async fn engine_commits_account_cursor_and_delivery_to_inbox() {
        let store = MemoryStore::new();
        let responses = Arc::new(Mutex::new(VecDeque::from([
            Ok(sync_response("ak:cursor:inbox")),
            Err(Error::AccountStreamInterrupt(
                AccountStreamInterrupt::Unauthorized,
            )),
        ])));
        let transport = queued_transport(responses);
        let engine =
            SubscriptionEngine::new(RecordingExecutor::default(), store.clone(), store.clone());

        let reason = engine
            .run_account_to_inbox(actor_id(), device_id(), &transport)
            .await
            .unwrap();

        assert_eq!(
            reason,
            SubscriptionStopReason::Unauthorized { reason: None }
        );
        assert_eq!(
            store.load(account_scope()).await.unwrap().as_deref(),
            Some("ak:cursor:inbox")
        );
        let pending = store.pending(10).await.unwrap();
        assert_eq!(pending.len(), 1);
        assert!(matches!(
            pending[0].events.as_slice(),
            [ClientEvent::AccountUpdates(_), ..]
        ));
    }

    #[tokio::test]
    async fn engine_clears_account_cursor_after_resync_interrupt() {
        let store = MemoryStore::new();
        store
            .save(account_scope(), "ak:cursor:stored".to_owned())
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
                AccountStreamInterrupt::Unauthorized,
            )),
        ])));
        let transport = queued_transport(responses);
        let engine = SubscriptionEngine::new(executor.clone(), store.clone(), store.clone());
        let projector = RecordingProjector {
            batches: Arc::new(Mutex::new(Vec::new())),
            fail: false,
            control: None,
        };

        let reason = engine
            .run_account(actor_id(), device_id(), &transport, &projector)
            .await
            .unwrap();

        assert_eq!(
            reason,
            SubscriptionStopReason::Unauthorized { reason: None }
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
        batches: Arc<Mutex<Vec<Vec<ClientEvent>>>>,
        fail: bool,
        control: Option<SyncLoopControl>,
    }

    impl ClientProjector for RecordingProjector {
        fn project(
            &self,
            batch: Vec<ClientEvent>,
        ) -> impl std::future::Future<Output = Result<()>> + '_ {
            let batches = Arc::clone(&self.batches);
            let fail = self.fail;
            let control = self.control.clone();
            async move {
                batches.lock().unwrap().push(batch);
                if let Some(control) = control {
                    control.cancel();
                }
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
            .save(realm_scope(), "ak:cursor:stored".to_owned())
            .await
            .unwrap();
        let executor = RecordingExecutor::default();
        let mut dropped = realm_frame(EventsSubscribeFrameKind::Dropped);
        dropped.cursor = Some(Cursor::new("ak:cursor:dropped").unwrap());
        dropped.reconnect_after_ms = Some(25);
        let transport = RealmRecoveryTransport::new(
            vec![dropped],
            vec![backfill_outcome(Some("ak:cursor:next"))],
        );
        let projector = RecordingProjector {
            batches: Arc::new(Mutex::new(Vec::new())),
            fail: false,
            control: None,
        };
        let engine = SubscriptionEngine::new(executor.clone(), store.clone(), store.clone());

        let reason = engine
            .run_realm_stream(&transport, realm_id(), &projector)
            .await
            .unwrap();

        assert_eq!(
            reason,
            RealmStreamStopReason::Dropped {
                cursor: "ak:cursor:dropped".to_owned(),
                reconnect_after_ms: Some(25)
            }
        );
        let scans = transport.scans();
        assert_eq!(scans.len(), 1);
        assert_eq!(scans[0].after.as_deref(), Some("ak:cursor:stored"));
        assert_eq!(scans[0].before.as_deref(), Some("ak:cursor:dropped"));
        assert_eq!(
            store.load(realm_scope()).await.unwrap().as_deref(),
            Some("ak:cursor:next")
        );
        // Reconnect policy belongs to the high-level runner so the wait can be
        // interrupted by cancellation or a host lifecycle transition.
        assert!(executor.sleeps().is_empty());
        let batches = projector.batches.lock().unwrap();
        assert_eq!(batches.len(), 1);
        assert!(matches!(
            batches[0].as_slice(),
            [ClientEvent::Backfill { .. }]
        ));
    }

    #[tokio::test]
    async fn engine_projected_backfill_checkpoints_after_project_ok() {
        let store = MemoryStore::new();
        store
            .save(realm_scope(), "ak:cursor:stored".to_owned())
            .await
            .unwrap();
        let mut dropped = realm_frame(EventsSubscribeFrameKind::Dropped);
        dropped.cursor = Some(Cursor::new("ak:cursor:dropped").unwrap());
        let transport = RealmRecoveryTransport::new(
            vec![dropped],
            vec![backfill_outcome(Some("ak:cursor:next"))],
        );
        let projector = RecordingProjector {
            batches: Arc::new(Mutex::new(Vec::new())),
            fail: false,
            control: None,
        };
        let engine =
            SubscriptionEngine::new(RecordingExecutor::default(), store.clone(), store.clone());

        let reason = engine
            .run_realm_stream(&transport, realm_id(), &projector)
            .await
            .unwrap();

        assert_eq!(
            reason,
            RealmStreamStopReason::Dropped {
                cursor: "ak:cursor:dropped".to_owned(),
                reconnect_after_ms: None
            }
        );
        assert_eq!(projector.batches.lock().unwrap()[0].len(), 1);
        assert_eq!(
            store.load(realm_scope()).await.unwrap().as_deref(),
            Some("ak:cursor:next")
        );
    }

    #[tokio::test]
    async fn engine_projected_backfill_does_not_checkpoint_when_project_errs() {
        let store = MemoryStore::new();
        store
            .save(realm_scope(), "ak:cursor:stored".to_owned())
            .await
            .unwrap();
        let mut dropped = realm_frame(EventsSubscribeFrameKind::Dropped);
        dropped.cursor = Some(Cursor::new("ak:cursor:dropped").unwrap());
        let transport = RealmRecoveryTransport::new(
            vec![dropped],
            vec![backfill_outcome(Some("ak:cursor:next"))],
        );
        let projector = RecordingProjector {
            batches: Arc::new(Mutex::new(Vec::new())),
            fail: true,
            control: None,
        };
        let engine =
            SubscriptionEngine::new(RecordingExecutor::default(), store.clone(), store.clone());

        let result = engine
            .run_realm_stream(&transport, realm_id(), &projector)
            .await;

        assert!(result.is_err());
        assert_eq!(projector.batches.lock().unwrap()[0].len(), 1);
        assert_eq!(
            store.load(realm_scope()).await.unwrap().as_deref(),
            Some("ak:cursor:stored")
        );
    }

    #[tokio::test]
    async fn engine_rejects_dropped_without_cursor_as_trace_violation() {
        // transport-bindings.md §1.1 rule 2: a server with no resume cursor
        // MUST send `resync_required`; a cursorless `dropped` is a protocol
        // error, not a silent resync.
        let store = MemoryStore::new();
        store
            .save(realm_scope(), "ak:cursor:stored".to_owned())
            .await
            .unwrap();
        let executor = RecordingExecutor::default();
        let mut dropped = realm_frame(EventsSubscribeFrameKind::Dropped);
        dropped.reconnect_after_ms = Some(40);
        let transport = RealmRecoveryTransport::new(vec![dropped], Vec::new());
        let engine = SubscriptionEngine::new(executor.clone(), store.clone(), store.clone());
        let projector = RecordingProjector {
            batches: Arc::new(Mutex::new(Vec::new())),
            fail: false,
            control: None,
        };

        let error = engine
            .run_realm_stream(&transport, realm_id(), &projector)
            .await
            .unwrap_err();

        assert!(error.to_string().contains("dropped_missing_cursor"));
        assert!(transport.scans().is_empty());
        // The rejected trace leaves the stored reconnect position untouched.
        assert_eq!(
            store.load(realm_scope()).await.unwrap().as_deref(),
            Some("ak:cursor:stored")
        );
        assert!(executor.sleeps().is_empty());
    }
}
