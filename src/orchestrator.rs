//! Batteries-included run loops on [`ArkretClient`].
//!
//! These own the OUTER resilience loop that consumers previously hand-rolled:
//! (re)acquire a transport, run the projector-driven engine, auto-resume with
//! backoff on recoverable transport errors and stops (realm `StreamEnded` /
//! `Dropped` / `ResyncRequired`), and stop on cancellation or `Unauthorized`.
//! Cursor, dedupe, drop/scan-backfill and the emit/await-then-checkpoint gate
//! live in the engines; the projector is the only host seam.
//!
//! Refresh coordination: on `Unauthorized` the runner asks the
//! [`TransportProvider`] to recover and reconnects with the rebuilt transport.
//! [`RunStopReason::Unauthorized`] is returned only when the provider cannot
//! recover and the host must require sign-in or stop the client.

use std::time::Duration;

use arkret::{AsyncSyncTransport, SyncLoopControl, SyncLoopStep};
use arkret_core::{DeviceId, Did, RealmId, Result};

use crate::subscribe::{
    EventsScanTransport, ProjectedRunError, RealmEventsTransport, RealmStreamStopReason,
};
use crate::{
    ArkretClient, Backoff, ClientProjector, CursorStore, DurableInboxStore, EventCacheStore,
    Executor, subscribe::account::account_updates_to_events,
};

/// Host seam that yields a ready-to-use transport (SDK http-client) with
/// current credentials. Called on each (re)start of a run loop; a provider that
/// refreshes credentials here makes the run loop recover across restarts.
pub trait TransportProvider {
    type Transport;

    fn provide(&self) -> impl std::future::Future<Output = Result<Self::Transport>> + '_;

    fn recover_unauthorized(&self) -> impl std::future::Future<Output = Result<bool>> + '_ {
        async { Ok(false) }
    }

    fn observe(&self, _event: RunEvent) {}

    /// Host lifecycle guard (route/profile/channel generation). It is polled
    /// during network restarts and every backoff quantum.
    fn is_active(&self) -> bool {
        true
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RunEvent {
    Connecting,
    Online,
    Backoff { delay: Duration },
    Refreshing,
    CursorReset,
    DeliveryPending,
    Stopped { reason: RunStopReason },
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
    /// Fraction of reconnect delay randomized away to avoid fleet lockstep.
    pub jitter_ratio: f64,
}

impl Default for RunOptions {
    fn default() -> Self {
        Self {
            beat: Duration::from_millis(250),
            min_backoff: Duration::from_millis(500),
            max_backoff: Duration::from_secs(30),
            jitter_ratio: 0.2,
        }
    }
}

/// Terminal reason a run loop returned to its host.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RunStopReason {
    /// The engine's cancellation control was tripped (`SubscriptionEngine::cancel`).
    Cancelled,
    LifecycleEnded,
    /// The session grant is no longer accepted and provider recovery failed.
    Unauthorized {
        reason: Option<String>,
    },
    /// Observer-only terminal marker paired with a returned [`RunError`].
    Failed {
        class: RunErrorClass,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunErrorClass {
    RetryableTransport,
    RateLimited,
    Unauthorized,
    InvalidConfiguration,
    StoreFailure,
    ProjectorFailure,
    ProtocolViolation,
}

#[derive(Debug, thiserror::Error)]
#[error("client runner stopped ({class:?}): {source}")]
pub struct RunError {
    pub class: RunErrorClass,
    #[source]
    pub source: arkret_core::Error,
}

pub type RunResult<T> = std::result::Result<T, RunError>;

fn classify_error(error: &arkret_core::Error) -> RunErrorClass {
    use arkret_core::Error;
    match error {
        Error::Http(_) => RunErrorClass::RetryableTransport,
        Error::Api { status: 429, .. } => RunErrorClass::RateLimited,
        Error::Api { status: 401, .. } => RunErrorClass::Unauthorized,
        Error::Api { error, .. }
            if matches!(
                error.error.code.as_str(),
                "grant_already_consumed"
                    | "session_logged_out"
                    | "auth_expired"
                    | "unauthenticated"
                    | "audience_mismatch"
            ) =>
        {
            RunErrorClass::Unauthorized
        }
        Error::Api { status, .. } if *status == 408 || *status >= 500 => {
            RunErrorClass::RetryableTransport
        }
        Error::InvalidId(_) | Error::Url(_) | Error::InsecureUrl(_) => {
            RunErrorClass::InvalidConfiguration
        }
        Error::Protocol(_) | Error::Api { .. } | Error::AccountStreamInterrupt(_) => {
            RunErrorClass::ProtocolViolation
        }
        _ => RunErrorClass::InvalidConfiguration,
    }
}

fn retryable(class: RunErrorClass) -> bool {
    matches!(
        class,
        RunErrorClass::RetryableTransport | RunErrorClass::RateLimited
    )
}

enum UnauthorizedRecovery {
    Recovered,
    Retry,
    Unavailable,
    GuardedStop(RunStopReason),
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
    ) -> RunResult<RunStopReason>
    where
        TP: TransportProvider,
        TP::Transport: RealmEventsTransport + EventsScanTransport,
        P: ClientProjector + ?Sized,
    {
        let engine = self.subscription_engine().with_control(control.clone());
        let mut backoff = Backoff::new(options.min_backoff, options.max_backoff)
            .with_jitter(options.jitter_ratio, 0xA11C_E001);
        loop {
            if !provider.is_active() {
                return Ok(Self::stop(provider, RunStopReason::LifecycleEnded));
            }
            if control.is_cancelled() {
                return Ok(Self::stop(provider, RunStopReason::Cancelled));
            }
            provider.observe(RunEvent::Connecting);
            let transport = match provider.provide().await {
                Ok(transport) => {
                    provider.observe(RunEvent::Online);
                    transport
                }
                Err(error) if retryable(classify_error(&error)) => {
                    let delay = backoff.next_delay();
                    provider.observe(RunEvent::Backoff { delay });
                    if let Some(reason) = self.wait_guarded(delay, control, provider).await {
                        return Ok(Self::stop(provider, reason));
                    }
                    continue;
                }
                Err(error) => {
                    return Err(Self::fail(provider, classify_error(&error), error));
                }
            };
            match engine
                .run_realm_stream_classified(&transport, realm_id.clone(), projector)
                .await
            {
                Ok(RealmStreamStopReason::StreamEnded) => {
                    backoff.reset();
                    if let Some(reason) = self.wait_guarded(options.beat, control, provider).await {
                        return Ok(Self::stop(provider, reason));
                    }
                }
                Ok(RealmStreamStopReason::Dropped {
                    reconnect_after_ms, ..
                }) => {
                    let delay =
                        backoff.next_delay_with_hint(reconnect_after_ms.map(Duration::from_millis));
                    provider.observe(RunEvent::Backoff { delay });
                    if let Some(reason) = self.wait_guarded(delay, control, provider).await {
                        return Ok(Self::stop(provider, reason));
                    }
                }
                Ok(RealmStreamStopReason::ResyncRequired { reconnect_after_ms }) => {
                    provider.observe(RunEvent::CursorReset);
                    let delay =
                        backoff.next_delay_with_hint(reconnect_after_ms.map(Duration::from_millis));
                    provider.observe(RunEvent::Backoff { delay });
                    if let Some(reason) = self.wait_guarded(delay, control, provider).await {
                        return Ok(Self::stop(provider, reason));
                    }
                }
                Ok(RealmStreamStopReason::Unauthorized { reason }) => {
                    match self
                        .recover_unauthorized(provider, control, &mut backoff)
                        .await?
                    {
                        UnauthorizedRecovery::Recovered | UnauthorizedRecovery::Retry => continue,
                        UnauthorizedRecovery::GuardedStop(reason) => return Ok(reason),
                        UnauthorizedRecovery::Unavailable => {}
                    }
                    return Ok(Self::stop(provider, RunStopReason::Unauthorized { reason }));
                }
                Err(ProjectedRunError::Transport(error)) if retryable(classify_error(&error)) => {
                    let delay = backoff.next_delay();
                    provider.observe(RunEvent::Backoff { delay });
                    if let Some(reason) = self.wait_guarded(delay, control, provider).await {
                        return Ok(Self::stop(provider, reason));
                    }
                }
                Err(ProjectedRunError::Transport(error)) => {
                    return Err(Self::fail(provider, classify_error(&error), error));
                }
                Err(ProjectedRunError::Store(error)) => {
                    return Err(Self::fail(provider, RunErrorClass::StoreFailure, error));
                }
                Err(ProjectedRunError::Projector(error)) => {
                    return Err(Self::fail(provider, RunErrorClass::ProjectorFailure, error));
                }
            }
        }
    }

    /// Resilient account run loop. The SDK sync loop owns account stream retry
    /// math, while this wrapper re-acquires transport before every step so
    /// provider-side credential refresh participates in retry recovery. On
    /// `Unauthorized`, the provider refreshes and rebuilds its transport.
    pub async fn run_account<TP, P>(
        &self,
        actor_id: Did,
        device_id: DeviceId,
        provider: &TP,
        projector: &P,
        control: &SyncLoopControl,
        options: RunOptions,
    ) -> RunResult<RunStopReason>
    where
        TP: TransportProvider,
        TP::Transport: AsyncSyncTransport,
        P: ClientProjector + ?Sized,
    {
        let engine = self.subscription_engine().with_control(control.clone());
        let scope = engine.account_scope(actor_id, device_id);
        let mut sync_loop = engine
            .restore_account_loop(scope.clone())
            .await
            .map_err(|error| Self::fail(provider, RunErrorClass::StoreFailure, error))?;
        let mut provide_backoff = Backoff::new(options.min_backoff, options.max_backoff)
            .with_jitter(options.jitter_ratio, 0xACC0_0011);
        loop {
            if !provider.is_active() {
                return Ok(Self::stop(provider, RunStopReason::LifecycleEnded));
            }
            if control.is_cancelled() {
                return Ok(Self::stop(provider, RunStopReason::Cancelled));
            }
            provider.observe(RunEvent::Connecting);
            let transport = match provider.provide().await {
                Ok(transport) => {
                    provide_backoff.reset();
                    provider.observe(RunEvent::Online);
                    transport
                }
                Err(error) if retryable(classify_error(&error)) => {
                    let delay = provide_backoff.next_delay();
                    provider.observe(RunEvent::Backoff { delay });
                    if let Some(reason) = self.wait_guarded(delay, control, provider).await {
                        return Ok(Self::stop(provider, reason));
                    }
                    continue;
                }
                Err(error) => {
                    return Err(Self::fail(provider, classify_error(&error), error));
                }
            };
            match sync_loop.step_async_with_control(&transport, control).await {
                SyncLoopStep::Updates(updates) => {
                    let batch = account_updates_to_events(updates);
                    if !batch.is_empty() {
                        projector.project(batch).await.map_err(|error| {
                            Self::fail(provider, RunErrorClass::ProjectorFailure, error)
                        })?;
                    }
                    engine
                        .checkpoint_account_cursor(
                            scope.clone(),
                            sync_loop.token().map(str::to_owned),
                        )
                        .await
                        .map_err(|error| {
                            Self::fail(provider, RunErrorClass::StoreFailure, error)
                        })?;
                }
                SyncLoopStep::Retry { retry_after, .. } => {
                    engine
                        .checkpoint_account_cursor(
                            scope.clone(),
                            sync_loop.token().map(str::to_owned),
                        )
                        .await
                        .map_err(|error| {
                            Self::fail(provider, RunErrorClass::StoreFailure, error)
                        })?;
                    if let Some(reason) = self.wait_guarded(retry_after, control, provider).await {
                        return Ok(Self::stop(provider, reason));
                    }
                }
                SyncLoopStep::Backpressure { retry_after } => {
                    if let Some(reason) = self.wait_guarded(retry_after, control, provider).await {
                        return Ok(Self::stop(provider, reason));
                    }
                }
                SyncLoopStep::Cancelled => {
                    return Ok(Self::stop(provider, RunStopReason::Cancelled));
                }
                SyncLoopStep::Unauthorized { reason } => {
                    match self
                        .recover_unauthorized(provider, control, &mut provide_backoff)
                        .await?
                    {
                        UnauthorizedRecovery::Recovered | UnauthorizedRecovery::Retry => continue,
                        UnauthorizedRecovery::GuardedStop(reason) => return Ok(reason),
                        UnauthorizedRecovery::Unavailable => {}
                    }
                    return Ok(Self::stop(provider, RunStopReason::Unauthorized { reason }));
                }
            }
        }
    }

    /// Resilient account runner whose successful checkpoint unit is an atomic
    /// durable-inbox commit instead of a synchronous host projection.
    pub async fn run_account_to_inbox<TP>(
        &self,
        actor_id: Did,
        device_id: DeviceId,
        service_id: Option<Did>,
        provider: &TP,
        control: &SyncLoopControl,
        options: RunOptions,
    ) -> RunResult<RunStopReason>
    where
        TP: TransportProvider,
        TP::Transport: AsyncSyncTransport,
        C: DurableInboxStore,
    {
        let mut engine = self.subscription_engine().with_control(control.clone());
        if let Some(service_id) = service_id {
            engine = engine.with_service_id(service_id);
        }
        let scope = engine.account_scope(actor_id, device_id);
        let mut sync_loop = engine
            .restore_account_loop(scope.clone())
            .await
            .map_err(|error| Self::fail(provider, RunErrorClass::StoreFailure, error))?;
        let mut backoff = Backoff::new(options.min_backoff, options.max_backoff)
            .with_jitter(options.jitter_ratio, 0x1AB0_0001);
        loop {
            if !provider.is_active() {
                return Ok(Self::stop(provider, RunStopReason::LifecycleEnded));
            }
            if control.is_cancelled() {
                return Ok(Self::stop(provider, RunStopReason::Cancelled));
            }
            provider.observe(RunEvent::Connecting);
            let transport = match provider.provide().await {
                Ok(transport) => {
                    backoff.reset();
                    provider.observe(RunEvent::Online);
                    transport
                }
                Err(error) if retryable(classify_error(&error)) => {
                    let delay = backoff.next_delay();
                    provider.observe(RunEvent::Backoff { delay });
                    if let Some(reason) = self.wait_guarded(delay, control, provider).await {
                        return Ok(Self::stop(provider, reason));
                    }
                    continue;
                }
                Err(error) => {
                    return Err(Self::fail(provider, classify_error(&error), error));
                }
            };
            match sync_loop.step_async_with_control(&transport, control).await {
                SyncLoopStep::Updates(updates) => {
                    let delivery_id = self
                        .cursor_store
                        .commit(
                            scope.clone(),
                            sync_loop.token().map(str::to_owned),
                            account_updates_to_events(updates),
                        )
                        .await
                        .map_err(|error| {
                            Self::fail(provider, RunErrorClass::StoreFailure, error)
                        })?;
                    if delivery_id.is_some() {
                        provider.observe(RunEvent::DeliveryPending);
                    }
                }
                SyncLoopStep::Retry { retry_after, .. } => {
                    self.cursor_store
                        .commit(
                            scope.clone(),
                            sync_loop.token().map(str::to_owned),
                            Vec::new(),
                        )
                        .await
                        .map_err(|error| {
                            Self::fail(provider, RunErrorClass::StoreFailure, error)
                        })?;
                    if let Some(reason) = self.wait_guarded(retry_after, control, provider).await {
                        return Ok(Self::stop(provider, reason));
                    }
                }
                SyncLoopStep::Backpressure { retry_after } => {
                    if let Some(reason) = self.wait_guarded(retry_after, control, provider).await {
                        return Ok(Self::stop(provider, reason));
                    }
                }
                SyncLoopStep::Cancelled => {
                    return Ok(Self::stop(provider, RunStopReason::Cancelled));
                }
                SyncLoopStep::Unauthorized { reason } => {
                    match self
                        .recover_unauthorized(provider, control, &mut backoff)
                        .await?
                    {
                        UnauthorizedRecovery::Recovered | UnauthorizedRecovery::Retry => continue,
                        UnauthorizedRecovery::GuardedStop(reason) => return Ok(reason),
                        UnauthorizedRecovery::Unavailable => {}
                    }
                    return Ok(Self::stop(provider, RunStopReason::Unauthorized { reason }));
                }
            }
        }
    }

    #[cfg(test)]
    async fn wait_cancellable(&self, duration: Duration, control: &SyncLoopControl) -> bool {
        const QUANTUM: Duration = Duration::from_millis(50);
        let mut remaining = duration;
        while !remaining.is_zero() {
            if control.is_cancelled() {
                return true;
            }
            let step = remaining.min(QUANTUM);
            self.executor.sleep(step).await;
            remaining = remaining.saturating_sub(step);
        }
        control.is_cancelled()
    }

    async fn wait_guarded<TP: TransportProvider + ?Sized>(
        &self,
        duration: Duration,
        control: &SyncLoopControl,
        provider: &TP,
    ) -> Option<RunStopReason> {
        const QUANTUM: Duration = Duration::from_millis(50);
        let mut remaining = duration;
        while !remaining.is_zero() {
            if control.is_cancelled() {
                return Some(RunStopReason::Cancelled);
            }
            if !provider.is_active() {
                return Some(RunStopReason::LifecycleEnded);
            }
            let step = remaining.min(QUANTUM);
            self.executor.sleep(step).await;
            remaining = remaining.saturating_sub(step);
        }
        if control.is_cancelled() {
            Some(RunStopReason::Cancelled)
        } else if !provider.is_active() {
            Some(RunStopReason::LifecycleEnded)
        } else {
            None
        }
    }

    async fn recover_unauthorized<TP: TransportProvider + ?Sized>(
        &self,
        provider: &TP,
        control: &SyncLoopControl,
        backoff: &mut Backoff,
    ) -> RunResult<UnauthorizedRecovery> {
        provider.observe(RunEvent::Refreshing);
        match provider.recover_unauthorized().await {
            Ok(true) => {
                backoff.reset();
                Ok(UnauthorizedRecovery::Recovered)
            }
            Ok(false) => Ok(UnauthorizedRecovery::Unavailable),
            Err(error) if retryable(classify_error(&error)) => {
                let delay = backoff.next_delay();
                provider.observe(RunEvent::Backoff { delay });
                if let Some(reason) = self.wait_guarded(delay, control, provider).await {
                    Ok(UnauthorizedRecovery::GuardedStop(Self::stop(
                        provider, reason,
                    )))
                } else {
                    Ok(UnauthorizedRecovery::Retry)
                }
            }
            Err(error) => Err(Self::fail(provider, classify_error(&error), error)),
        }
    }

    fn stop<TP: TransportProvider + ?Sized>(provider: &TP, reason: RunStopReason) -> RunStopReason {
        provider.observe(RunEvent::Stopped {
            reason: reason.clone(),
        });
        reason
    }

    fn fail<TP: TransportProvider + ?Sized>(
        provider: &TP,
        class: RunErrorClass,
        source: arkret_core::Error,
    ) -> RunError {
        provider.observe(RunEvent::Stopped {
            reason: RunStopReason::Failed { class },
        });
        RunError { class, source }
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
        BoxRealmStreamFuture, ClientEvent, CursorScope, DurableInboxStore, EventsScanRequest,
        MemoryStore, RealmEventsFrameSource,
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
        events: Arc<Mutex<Vec<RunEvent>>>,
        recoveries: Arc<Mutex<VecDeque<Result<bool>>>>,
    }

    impl<T> QueueProvider<T> {
        fn new(outcomes: Vec<Result<T>>) -> Self {
            Self {
                outcomes: Arc::new(Mutex::new(VecDeque::from(outcomes))),
                calls: Arc::new(Mutex::new(0)),
                events: Arc::new(Mutex::new(Vec::new())),
                recoveries: Arc::new(Mutex::new(VecDeque::new())),
            }
        }

        fn calls(&self) -> usize {
            *self.calls.lock().unwrap()
        }

        fn events(&self) -> Vec<RunEvent> {
            self.events.lock().unwrap().clone()
        }

        fn with_recoveries(self, recoveries: Vec<Result<bool>>) -> Self {
            *self.recoveries.lock().unwrap() = VecDeque::from(recoveries);
            self
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

        fn observe(&self, event: RunEvent) {
            self.events.lock().unwrap().push(event);
        }

        fn recover_unauthorized(&self) -> impl std::future::Future<Output = Result<bool>> + '_ {
            let outcome = self.recoveries.lock().unwrap().pop_front();
            async move { outcome.unwrap_or(Ok(false)) }
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
            jitter_ratio: 0.0,
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
        assert_eq!(
            provider.events(),
            vec![RunEvent::Stopped {
                reason: RunStopReason::Cancelled
            }]
        );
    }

    #[tokio::test]
    async fn account_engine_cancel_preserves_preexisting_pending_delivery() {
        let store = MemoryStore::new();
        let scope = account_scope();
        let delivery_id = store
            .commit(
                scope.clone(),
                Some("ak:cursor:pending-before-cancel".to_owned()),
                vec![ClientEvent::Notification(
                    serde_json::from_value(serde_json::json!({
                        "id": "ak:notification:01964137-0000-7000-8000-000000000011",
                        "type": "agent",
                        "action": "remove"
                    }))
                    .unwrap(),
                )],
            )
            .await
            .unwrap()
            .unwrap();
        let client = test_client(RecordingExecutor::default(), store.clone());
        let provider = QueueProvider::<AccountTransport>::new(Vec::new());
        let control = SyncLoopControl::new();
        control.cancel();

        let stop = client
            .run_account_to_inbox(
                actor_id(),
                device_id(),
                None,
                &provider,
                &control,
                RunOptions::default(),
            )
            .await
            .unwrap();

        assert_eq!(stop, RunStopReason::Cancelled);
        assert_eq!(provider.calls(), 0);
        let pending = store.pending(10).await.unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].id, delivery_id);
        assert_eq!(
            store.load(scope).await.unwrap().as_deref(),
            Some("ak:cursor:pending-before-cancel")
        );
    }

    #[tokio::test]
    async fn run_realm_retries_provider_error_with_backoff() {
        let executor = RecordingExecutor::default();
        let client = test_client(executor.clone(), MemoryStore::new());
        let provider = QueueProvider::new(vec![
            Err(Error::Http("provider offline".to_owned())),
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
            Ok(TestRealmTransport::frames(vec![Err(Error::Http(
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
    async fn run_realm_retries_transient_session_recovery_error() {
        let executor = RecordingExecutor::default();
        let client = test_client(executor.clone(), MemoryStore::new());
        let provider = QueueProvider::new(vec![
            Ok(TestRealmTransport::frames(vec![Ok(unauthorized_frame(
                "expired",
            ))])),
            Ok(TestRealmTransport::frames(vec![Ok(unauthorized_frame(
                "revoked",
            ))])),
        ])
        .with_recoveries(vec![
            Err(Error::Http("refresh offline".to_owned())),
            Ok(false),
        ]);
        let control = SyncLoopControl::new();
        let (projector, _) = projector(None, false);

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

        let error = result.unwrap_err();
        assert_eq!(error.class, RunErrorClass::ProjectorFailure);
        assert_eq!(provider.calls(), 1);
        assert!(executor.sleeps().is_empty());
        assert_eq!(*calls.lock().unwrap(), 1);
        assert!(matches!(
            provider.events().last(),
            Some(RunEvent::Stopped {
                reason: RunStopReason::Failed {
                    class: RunErrorClass::ProjectorFailure
                }
            })
        ));
    }

    #[tokio::test]
    async fn run_account_retries_provider_error_with_backoff() {
        let executor = RecordingExecutor::default();
        let client = test_client(executor.clone(), MemoryStore::new());
        let provider = QueueProvider::new(vec![
            Err(Error::Http("provider offline".to_owned())),
            Ok(AccountTransport::new(Err(Error::AccountStreamInterrupt(
                AccountStreamInterrupt::Unauthorized,
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

        assert_eq!(stop, RunStopReason::Unauthorized { reason: None });
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
        let waited = executor.sleeps().into_iter().sum::<Duration>();
        assert!(waited >= Duration::from_secs(1));
        assert!(waited <= Duration::from_millis(1200));
    }

    #[tokio::test]
    async fn thirty_second_wait_is_interrupted_by_cancellation() {
        let client = ArkretClient::new(
            crate::NativeExecutor,
            MemoryStore::new(),
            MemoryStore::new(),
        );
        let control = SyncLoopControl::new();
        let canceller = control.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            canceller.cancel();
        });

        let cancelled = tokio::time::timeout(
            Duration::from_millis(250),
            client.wait_cancellable(Duration::from_secs(30), &control),
        )
        .await
        .expect("cancellation must interrupt the long wait");
        assert!(cancelled);
    }
}
