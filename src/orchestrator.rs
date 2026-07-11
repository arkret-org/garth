//! Batteries-included run loops on [`ArkretClient`].
//!
//! These own the OUTER resilience loop that consumers previously hand-rolled:
//! (re)acquire a transport, run the projector-driven engine, auto-resume with
//! backoff on recoverable transport errors and stops (realm `StreamEnded` /
//! `Dropped` / `ResyncRequired`), and stop on cancellation or `Unauthorized`.
//! Cursor, dedupe, drop/scan-backfill and the emit/await-then-checkpoint gate
//! live in the engines; the projector is the only host seam.
//!
//! Refresh coordination: on `Unauthorized` the runner returns
//! [`RunStopReason::Unauthorized`] so the host can refresh (or require sign-in) and
//! re-invoke. Because the transport is obtained through [`TransportProvider`]
//! on every (re)start, a provider that refreshes credentials on `provide`
//! transparently recovers across restarts without the runner owning SDK auth.

use std::time::Duration;

use arkret::{AsyncSyncTransport, SyncLoopControl, SyncLoopStep};
use arkret_core::{DeviceId, Did, RealmId, Result};

use crate::subscribe::{
    EventsScanTransport, ProjectedRunError, RealmEventsTransport, RealmStreamStopReason,
};
use crate::{
    ArkretClient, ClientProjector, CursorStore, EventCacheStore, Executor,
    subscribe::account::account_updates_to_events,
};

/// Host seam that yields a ready-to-use transport (SDK http-client) with
/// current credentials. Called on each (re)start of a run loop; a provider that
/// refreshes credentials here makes the run loop recover across restarts.
pub trait TransportProvider {
    type Transport;

    fn provide(&self) -> impl std::future::Future<Output = Result<Self::Transport>> + '_;
}

/// Backoff / heartbeat knobs for the resilient run loops.
#[derive(Clone, Copy, Debug)]
pub struct RunOptions {
    /// Pause after a clean end-of-window before re-subscribing, so an
    /// immediately-returning server cannot spin the loop at network RTT.
    pub beat: Duration,
    /// Initial reconnect backoff after a recoverable drop/resync.
    pub min_backoff: Duration,
    /// Backoff ceiling.
    pub max_backoff: Duration,
}

impl Default for RunOptions {
    fn default() -> Self {
        Self {
            beat: Duration::from_millis(250),
            min_backoff: Duration::from_millis(500),
            max_backoff: Duration::from_secs(30),
        }
    }
}

/// Terminal reason a run loop returned to its host.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RunStopReason {
    /// The engine's cancellation control was tripped (`SubscriptionEngine::cancel`).
    Cancelled,
    /// The session grant is no longer accepted; host should refresh / sign in.
    Unauthorized { reason: Option<String> },
}

impl<E, C, D> ArkretClient<E, C, D>
where
    E: Executor + Clone,
    C: CursorStore,
    D: EventCacheStore,
{
    /// Resilient realm run loop: subscribe -> project -> checkpoint, auto-resume
    /// with backoff on `StreamEnded` / `Dropped` / `ResyncRequired`, stop on
    /// cancellation or `Unauthorized`. The projector's durable write gates
    /// cursor advance (see [`ClientProjector`]).
    pub async fn run_realm<TP, P>(
        &self,
        provider: &TP,
        realm_id: RealmId,
        projector: &P,
        control: &SyncLoopControl,
        options: RunOptions,
    ) -> Result<RunStopReason>
    where
        TP: TransportProvider,
        TP::Transport: RealmEventsTransport + EventsScanTransport,
        P: ClientProjector + ?Sized,
    {
        let engine = self.subscription_engine().with_control(control.clone());
        let mut backoff = options.min_backoff;
        loop {
            if control.is_cancelled() {
                return Ok(RunStopReason::Cancelled);
            }
            let transport = match provider.provide().await {
                Ok(transport) => transport,
                Err(_) => {
                    self.executor.sleep(backoff).await;
                    backoff = backoff.saturating_mul(2).min(options.max_backoff);
                    continue;
                }
            };
            match engine
                .run_realm_stream_classified(&transport, realm_id.clone(), projector)
                .await
            {
                Ok(RealmStreamStopReason::StreamEnded) => {
                    backoff = options.min_backoff;
                    self.executor.sleep(options.beat).await;
                }
                Ok(
                    RealmStreamStopReason::Dropped {
                        reconnect_after_ms, ..
                    }
                    | RealmStreamStopReason::ResyncRequired { reconnect_after_ms },
                ) => {
                    // The engine already honored a server-provided
                    // `reconnect_after_ms` before returning; only apply the
                    // local backoff when the server gave no hint.
                    if reconnect_after_ms.is_none() {
                        self.executor.sleep(backoff).await;
                    }
                    backoff = backoff.saturating_mul(2).min(options.max_backoff);
                }
                Ok(RealmStreamStopReason::Unauthorized { reason }) => {
                    return Ok(RunStopReason::Unauthorized { reason });
                }
                Err(ProjectedRunError::Transport(_)) => {
                    self.executor.sleep(backoff).await;
                    backoff = backoff.saturating_mul(2).min(options.max_backoff);
                }
                Err(error) => return Err(error.into_error()),
            }
        }
    }

    /// Resilient account run loop. The SDK sync loop owns account stream retry
    /// math, while this wrapper re-acquires transport before every step so
    /// provider-side credential refresh participates in retry recovery. On
    /// `Unauthorized`, the host refreshes or signs in and re-invokes.
    pub async fn run_account<TP, P>(
        &self,
        actor_id: Did,
        device_id: DeviceId,
        provider: &TP,
        projector: &P,
        control: &SyncLoopControl,
        options: RunOptions,
    ) -> Result<RunStopReason>
    where
        TP: TransportProvider,
        TP::Transport: AsyncSyncTransport,
        P: ClientProjector + ?Sized,
    {
        let engine = self.subscription_engine().with_control(control.clone());
        let scope = engine.account_scope(actor_id, device_id);
        let mut sync_loop = engine.restore_account_loop(scope.clone()).await?;
        let mut provide_backoff = options.min_backoff;
        loop {
            if control.is_cancelled() {
                return Ok(RunStopReason::Cancelled);
            }
            let transport = match provider.provide().await {
                Ok(transport) => {
                    provide_backoff = options.min_backoff;
                    transport
                }
                Err(_) => {
                    self.executor.sleep(provide_backoff).await;
                    provide_backoff = provide_backoff.saturating_mul(2).min(options.max_backoff);
                    continue;
                }
            };
            match sync_loop.step_async_with_control(&transport, control).await {
                SyncLoopStep::Updates(updates) => {
                    let batch = account_updates_to_events(updates);
                    if !batch.is_empty() {
                        projector.project(batch).await?;
                    }
                    engine
                        .checkpoint_account_cursor(
                            scope.clone(),
                            sync_loop.token().map(str::to_owned),
                        )
                        .await?;
                }
                SyncLoopStep::Retry { retry_after, .. } => {
                    engine
                        .checkpoint_account_cursor(
                            scope.clone(),
                            sync_loop.token().map(str::to_owned),
                        )
                        .await?;
                    self.executor.sleep(retry_after).await;
                }
                SyncLoopStep::Backpressure { retry_after } => {
                    self.executor.sleep(retry_after).await;
                }
                SyncLoopStep::Cancelled => return Ok(RunStopReason::Cancelled),
                SyncLoopStep::Unauthorized { reason } => {
                    return Ok(RunStopReason::Unauthorized { reason });
                }
            }
        }
    }
}

#[cfg(all(test, feature = "native"))]
mod tests {
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use arkret::{AccountStreamInterrupt, BoxSyncFuture, Error, SyncOutcome, SyncRequestBody};
    use arkret_core::events::kinds;
    use arkret_core::{
        EventsSubscribeFrame, EventsSubscribeFrameKind, Hlc, RealmId, SyncBackfillOutcome,
    };
    use serde_json::{Value, json};

    use super::*;
    use crate::store::CursorStore;
    use crate::subscribe::scan::BoxScanFuture;
    use crate::subscribe::test_support::{RecordingExecutor, sync_response};
    use crate::{
        BoxRealmStreamFuture, ClientEvent, CursorScope, EventsScanRequest, MemoryStore,
        RealmEventsFrameSource,
    };

    fn test_client(
        executor: RecordingExecutor,
        store: MemoryStore,
    ) -> ArkretClient<RecordingExecutor, MemoryStore, MemoryStore> {
        ArkretClient::new(executor, store.clone(), store)
    }

    struct QueueProvider<T> {
        outcomes: Arc<Mutex<VecDeque<Result<T>>>>,
        calls: Arc<Mutex<usize>>,
    }

    impl<T> QueueProvider<T> {
        fn new(outcomes: Vec<Result<T>>) -> Self {
            Self {
                outcomes: Arc::new(Mutex::new(VecDeque::from(outcomes))),
                calls: Arc::new(Mutex::new(0)),
            }
        }

        fn calls(&self) -> usize {
            *self.calls.lock().unwrap()
        }
    }

    impl<T> TransportProvider for QueueProvider<T> {
        type Transport = T;

        fn provide(&self) -> impl std::future::Future<Output = Result<T>> + '_ {
            async move {
                *self.calls.lock().unwrap() += 1;
                self.outcomes
                    .lock()
                    .unwrap()
                    .pop_front()
                    .expect("test provider exhausted")
            }
        }
    }

    struct CountingProjector {
        calls: Arc<Mutex<usize>>,
        control: Option<SyncLoopControl>,
        fail: bool,
    }

    impl ClientProjector for CountingProjector {
        fn project(
            &self,
            _batch: Vec<ClientEvent>,
        ) -> impl std::future::Future<Output = Result<()>> + '_ {
            let calls = Arc::clone(&self.calls);
            let control = self.control.clone();
            let fail = self.fail;
            async move {
                *calls.lock().unwrap() += 1;
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

    struct TestRealmSource {
        frames: VecDeque<Result<EventsSubscribeFrame>>,
    }

    impl RealmEventsFrameSource for TestRealmSource {
        fn next_frame<'a>(&'a mut self) -> BoxRealmStreamFuture<'a, Option<EventsSubscribeFrame>> {
            let frame = self.frames.pop_front();
            Box::pin(async move { frame.transpose() })
        }
    }

    struct TestRealmTransport {
        open_error: Mutex<Option<Error>>,
        source: Mutex<Option<TestRealmSource>>,
    }

    impl TestRealmTransport {
        fn frames(frames: Vec<Result<EventsSubscribeFrame>>) -> Self {
            Self {
                open_error: Mutex::new(None),
                source: Mutex::new(Some(TestRealmSource {
                    frames: VecDeque::from(frames),
                })),
            }
        }
    }

    impl RealmEventsTransport for TestRealmTransport {
        type Source = TestRealmSource;

        fn open_realm_events<'a>(
            &'a self,
            _realm_id: &'a RealmId,
            _after: Option<&'a str>,
        ) -> BoxRealmStreamFuture<'a, Self::Source> {
            let error = self.open_error.lock().unwrap().take();
            let source = self.source.lock().unwrap().take();
            Box::pin(async move {
                match error {
                    Some(error) => Err(error),
                    None => Ok(source.unwrap_or(TestRealmSource {
                        frames: VecDeque::new(),
                    })),
                }
            })
        }
    }

    impl EventsScanTransport for TestRealmTransport {
        fn scan_events<'a>(
            &'a self,
            _request: EventsScanRequest,
        ) -> BoxScanFuture<'a, SyncBackfillOutcome> {
            Box::pin(async move {
                Ok(SyncBackfillOutcome {
                    events: Vec::new(),
                    snapshot_bootstrap: None,
                    prev_cursor: None,
                    next_cursor: None,
                    limited: false,
                })
            })
        }
    }

    struct AccountTransport {
        response: Mutex<Option<Result<SyncOutcome>>>,
    }

    impl AccountTransport {
        fn new(response: Result<SyncOutcome>) -> Self {
            Self {
                response: Mutex::new(Some(response)),
            }
        }
    }

    impl AsyncSyncTransport for AccountTransport {
        fn sync_async<'a>(&'a self, _request: SyncRequestBody) -> BoxSyncFuture<'a, SyncOutcome> {
            let response = self
                .response
                .lock()
                .unwrap()
                .take()
                .expect("test account transport exhausted");
            Box::pin(async move { response })
        }
    }

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

    fn options() -> RunOptions {
        RunOptions {
            beat: Duration::ZERO,
            min_backoff: Duration::from_millis(10),
            max_backoff: Duration::from_millis(30),
        }
    }

    fn frame(kind: EventsSubscribeFrameKind, payload: Value) -> EventsSubscribeFrame {
        EventsSubscribeFrame {
            kind,
            realm_id: Some(realm_id()),
            cursor: None,
            payload,
            reconnect_after_ms: None,
        }
    }

    fn unauthorized_frame(reason: &str) -> EventsSubscribeFrame {
        frame(
            EventsSubscribeFrameKind::Unauthorized,
            json!({ "reason": reason }),
        )
    }

    fn event_frame() -> EventsSubscribeFrame {
        let event = arkret_core::Event::new(
            kinds::MESSAGE_CREATE,
            realm_id(),
            actor_id(),
            1,
            Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
            json!({
                "content": {"kind": "ak.content.text", "body": "hello"},
                "strand_id": "ak:strand:01904100-0000-7000-8000-000000000002",
                "track_name": "discussion"
            }),
        )
        .unwrap();
        let mut framed = frame(
            EventsSubscribeFrameKind::Event,
            serde_json::to_value(event).unwrap(),
        );
        // Data frames are cursor-bearing under the §1.1 trace rules.
        framed.cursor =
            Some(arkret_core::identifiers::Cursor::new("ak:cursor:event-frame").unwrap());
        framed
    }

    fn projector(
        control: Option<SyncLoopControl>,
        fail: bool,
    ) -> (CountingProjector, Arc<Mutex<usize>>) {
        let calls = Arc::new(Mutex::new(0usize));
        (
            CountingProjector {
                calls: Arc::clone(&calls),
                control,
                fail,
            },
            calls,
        )
    }

    #[tokio::test]
    async fn run_realm_stops_immediately_when_control_pre_cancelled() {
        let client = test_client(RecordingExecutor::default(), MemoryStore::new());
        let provider = QueueProvider::<TestRealmTransport>::new(Vec::new());
        let control = SyncLoopControl::new();
        control.cancel();
        let (projector, calls) = projector(None, false);

        let stop = client
            .run_realm(
                &provider,
                realm_id(),
                &projector,
                &control,
                RunOptions::default(),
            )
            .await
            .unwrap();

        assert_eq!(stop, RunStopReason::Cancelled);
        // Pre-cancel short-circuits before any transport/projection work.
        assert_eq!(*calls.lock().unwrap(), 0);
        assert_eq!(provider.calls(), 0);
    }

    #[tokio::test]
    async fn run_realm_retries_provider_error_with_backoff() {
        let executor = RecordingExecutor::default();
        let client = test_client(executor.clone(), MemoryStore::new());
        let provider = QueueProvider::new(vec![
            Err(Error::Protocol("provider offline".to_owned())),
            Ok(TestRealmTransport::frames(vec![Ok(unauthorized_frame(
                "revoked",
            ))])),
        ]);
        let control = SyncLoopControl::new();
        let (projector, calls) = projector(None, false);

        let stop = client
            .run_realm(&provider, realm_id(), &projector, &control, options())
            .await
            .unwrap();

        assert_eq!(
            stop,
            RunStopReason::Unauthorized {
                reason: Some("revoked".to_owned())
            }
        );
        assert_eq!(provider.calls(), 2);
        assert_eq!(executor.sleeps(), vec![Duration::from_millis(10)]);
        assert_eq!(*calls.lock().unwrap(), 0);
    }

    #[tokio::test]
    async fn run_realm_retries_stream_transport_error_with_backoff() {
        let executor = RecordingExecutor::default();
        let client = test_client(executor.clone(), MemoryStore::new());
        let provider = QueueProvider::new(vec![
            Ok(TestRealmTransport::frames(vec![Err(Error::Protocol(
                "stream reset".to_owned(),
            ))])),
            Ok(TestRealmTransport::frames(vec![Ok(unauthorized_frame(
                "revoked",
            ))])),
        ]);
        let control = SyncLoopControl::new();
        let (projector, calls) = projector(None, false);

        let stop = client
            .run_realm(&provider, realm_id(), &projector, &control, options())
            .await
            .unwrap();

        assert_eq!(
            stop,
            RunStopReason::Unauthorized {
                reason: Some("revoked".to_owned())
            }
        );
        assert_eq!(provider.calls(), 2);
        assert_eq!(executor.sleeps(), vec![Duration::from_millis(10)]);
        assert_eq!(*calls.lock().unwrap(), 0);
    }

    #[tokio::test]
    async fn run_realm_server_hint_suppresses_local_backoff() {
        let executor = RecordingExecutor::default();
        let client = test_client(executor.clone(), MemoryStore::new());
        // A `dropped` frame MUST carry a cursor (transport-bindings.md §1.1);
        // the engine backfills from it, honours the server's 25ms hint, and
        // the orchestrator then skips its local backoff sleep.
        let mut dropped = frame(EventsSubscribeFrameKind::Dropped, Value::Null);
        dropped.cursor = Some(arkret_core::identifiers::Cursor::new("ak:cursor:dropped").unwrap());
        dropped.reconnect_after_ms = Some(25);
        let provider = QueueProvider::new(vec![
            Ok(TestRealmTransport::frames(vec![Ok(dropped)])),
            Ok(TestRealmTransport::frames(vec![Ok(unauthorized_frame(
                "revoked",
            ))])),
        ]);
        let control = SyncLoopControl::new();
        let (projector, calls) = projector(None, false);

        let stop = client
            .run_realm(&provider, realm_id(), &projector, &control, options())
            .await
            .unwrap();

        assert_eq!(
            stop,
            RunStopReason::Unauthorized {
                reason: Some("revoked".to_owned())
            }
        );
        assert_eq!(provider.calls(), 2);
        assert_eq!(executor.sleeps(), vec![Duration::from_millis(25)]);
        // The dropped-cursor recovery projected exactly one Backfill batch.
        assert_eq!(*calls.lock().unwrap(), 1);
    }

    #[tokio::test]
    async fn run_realm_projector_error_is_not_retried() {
        let executor = RecordingExecutor::default();
        let client = test_client(executor.clone(), MemoryStore::new());
        let provider =
            QueueProvider::new(vec![Ok(TestRealmTransport::frames(vec![
                Ok(event_frame()),
            ]))]);
        let control = SyncLoopControl::new();
        let (projector, calls) = projector(None, true);

        let result = client
            .run_realm(&provider, realm_id(), &projector, &control, options())
            .await;

        assert!(result.is_err());
        assert_eq!(provider.calls(), 1);
        assert!(executor.sleeps().is_empty());
        assert_eq!(*calls.lock().unwrap(), 1);
    }

    #[tokio::test]
    async fn run_account_retries_provider_error_with_backoff() {
        let executor = RecordingExecutor::default();
        let client = test_client(executor.clone(), MemoryStore::new());
        let provider = QueueProvider::new(vec![
            Err(Error::Protocol("provider offline".to_owned())),
            Ok(AccountTransport::new(Err(Error::AccountStreamInterrupt(
                AccountStreamInterrupt::Unauthorized {
                    reason: Some("revoked".to_owned()),
                },
            )))),
        ]);
        let control = SyncLoopControl::new();
        let (projector, calls) = projector(None, false);

        let stop = client
            .run_account(
                actor_id(),
                device_id(),
                &provider,
                &projector,
                &control,
                options(),
            )
            .await
            .unwrap();

        assert_eq!(
            stop,
            RunStopReason::Unauthorized {
                reason: Some("revoked".to_owned())
            }
        );
        assert_eq!(provider.calls(), 2);
        assert_eq!(executor.sleeps(), vec![Duration::from_millis(10)]);
        assert_eq!(*calls.lock().unwrap(), 0);
    }

    #[tokio::test]
    async fn run_account_reprovides_after_sync_retry() {
        let executor = RecordingExecutor::default();
        let store = MemoryStore::new();
        let client = test_client(executor.clone(), store.clone());
        let provider = QueueProvider::new(vec![
            Ok(AccountTransport::new(Err(Error::Protocol(
                "network down".to_owned(),
            )))),
            Ok(AccountTransport::new(Ok(sync_response("ak:cursor:next")))),
        ]);
        let control = SyncLoopControl::new();
        let (projector, calls) = projector(Some(control.clone()), false);

        let stop = client
            .run_account(
                actor_id(),
                device_id(),
                &provider,
                &projector,
                &control,
                options(),
            )
            .await
            .unwrap();

        assert_eq!(stop, RunStopReason::Cancelled);
        assert_eq!(provider.calls(), 2);
        assert_eq!(*calls.lock().unwrap(), 1);
        assert_eq!(
            store.load(account_scope()).await.unwrap().as_deref(),
            Some("ak:cursor:next")
        );
        assert_eq!(executor.sleeps().len(), 1);
    }
}
