//! Resilient run loops over the account aggregate subscription.
//!
//! The loop owns the outer resilience that hosts otherwise hand-roll:
//! (re)acquire an authenticated transport, project one delivered batch,
//! checkpoint the durable cursor only after the projector committed, resume
//! with spec backoff on a recoverable interrupt, reset the cursor when the
//! Station demands a resynchronization, and stop on explicit cancellation or
//! on an unrecoverable authorization failure.

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use arkret_models_collaboration::sync_frames::account_subscribe::{
    AccountStreamInterrupt, AccountSubscribeSnapshotResult, SyncRequestBody,
};
use arkret_retry::RetrySchedule;

use crate::{
    AccountSubscribeTransport, ClientProjector, CursorScope, CursorStore, Error, Executor,
    MaybeSend, Result, account_batch_to_client_events,
};

/// Host seam that yields a ready-to-use transport with current credentials.
/// It is called on every (re)start of a run loop, so a provider that refreshes
/// credentials here makes the loop recover across restarts.
pub trait TransportProvider {
    type Transport;

    fn provide(&self) -> impl Future<Output = Result<Self::Transport>> + MaybeSend + '_;

    /// Attempt to recover from an `unauthorized` control frame. `true` means
    /// the next `provide` will return a transport with fresh credentials.
    fn recover_unauthorized(&self) -> impl Future<Output = Result<bool>> + MaybeSend + '_ {
        async { Ok(false) }
    }

    fn observe(&self, _event: RunEvent) {}

    /// Build a complete aggregate request from the last durable cursor.
    fn account_request(&self, after: Option<String>) -> Result<SyncRequestBody> {
        Ok(SyncRequestBody {
            catchup: Some(after.is_none()),
            after,
            ..SyncRequestBody::default()
        })
    }

    /// Host lifecycle guard. It is polled before every network restart and
    /// after every backoff quantum.
    fn is_active(&self) -> bool {
        true
    }
}

/// Explicit cancellation for a run loop.
#[derive(Clone, Debug, Default)]
pub struct SyncLoopControl(Arc<AtomicBool>);

impl SyncLoopControl {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }

    pub fn reset(&self) {
        self.0.store(false, Ordering::Release);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

/// Backoff and heartbeat knobs for the resilient run loops.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RunOptions {
    /// Pause after a clean bounded delivery window before re-subscribing.
    pub beat: Duration,
    /// Initial reconnect backoff after a recoverable drop or resync.
    pub min_backoff: Duration,
    /// Backoff ceiling.
    pub max_backoff: Duration,
    /// Fraction of the reconnect delay randomized to avoid fleet lockstep.
    pub jitter_ratio: f64,
    /// Deterministic jitter seed; hosts vary it per instance.
    pub jitter_seed: u64,
}

impl Default for RunOptions {
    /// The reconnect cadence is normative rather than a tunable default: the
    /// first wait is at least 1,000 ms, the ceiling at least 60,000 ms, with
    /// 0-20% jitter.
    fn default() -> Self {
        Self {
            beat: Duration::from_millis(250),
            min_backoff: arkret_retry::SPEC_INITIAL_DELAY,
            max_backoff: arkret_retry::SPEC_MAX_DELAY,
            jitter_ratio: arkret_retry::SPEC_JITTER_RATIO,
            jitter_seed: 0x5EED_0BAC_C0FF_1E55,
        }
    }
}

/// Observable lifecycle transitions of a run loop.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RunEvent {
    Connecting,
    Online,
    Backoff { delay: Duration },
    Refreshing,
    CursorReset,
    Checkpointed,
    Stopped { reason: RunStopReason },
}

/// Terminal reason a run loop returned to its host.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RunStopReason {
    /// The cancellation control was tripped.
    Cancelled,
    /// The host lifecycle guard reported that this loop is no longer active.
    LifecycleEnded,
    /// The session grant is no longer accepted and provider recovery failed.
    Unauthorized,
    /// Observer-only terminal marker paired with a returned [`RunError`].
    Failed { class: RunErrorClass },
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
    pub source: Error,
}

pub type RunResult<T> = std::result::Result<T, RunError>;

pub fn classify_error(error: &Error) -> RunErrorClass {
    match error {
        Error::Http(_) => RunErrorClass::RetryableTransport,
        Error::Api { status: 429, .. } => RunErrorClass::RateLimited,
        Error::Api { status: 401, .. } => RunErrorClass::Unauthorized,
        Error::Api { error, .. }
            if matches!(
                error.code(),
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
        Error::Url(_) | Error::InsecureUrl(_) => RunErrorClass::InvalidConfiguration,
        Error::Storage(_) => RunErrorClass::StoreFailure,
        Error::AccountStreamInterrupt(AccountStreamInterrupt::Unauthorized) => {
            RunErrorClass::Unauthorized
        }
        Error::CanonicalJson(_) | Error::Protocol(_) | Error::Api { .. } => {
            RunErrorClass::ProtocolViolation
        }
        Error::AccountStreamInterrupt(_) => RunErrorClass::RetryableTransport,
    }
}

pub(crate) fn is_retryable(error: &Error) -> bool {
    matches!(
        classify_error(error),
        RunErrorClass::RetryableTransport | RunErrorClass::RateLimited
    )
}

/// Resilient account-aggregate run loop.
#[derive(Clone, Debug)]
pub struct AccountRunner<E, C> {
    executor: E,
    cursors: C,
    control: SyncLoopControl,
}

impl<E, C> AccountRunner<E, C>
where
    E: Executor,
    C: CursorStore,
{
    pub fn new(executor: E, cursors: C) -> Self {
        Self {
            executor,
            cursors,
            control: SyncLoopControl::new(),
        }
    }

    pub fn with_control(mut self, control: SyncLoopControl) -> Self {
        self.control = control;
        self
    }

    pub fn control(&self) -> SyncLoopControl {
        self.control.clone()
    }

    /// Subscribe, project, checkpoint, and resume until the loop is cancelled,
    /// the lifecycle guard closes it, or authorization is unrecoverable.
    pub async fn run<TP, P>(
        &self,
        provider: &TP,
        projector: &P,
        scope: CursorScope,
        options: RunOptions,
    ) -> RunResult<RunStopReason>
    where
        TP: TransportProvider,
        TP::Transport: AccountSubscribeTransport,
        P: ClientProjector + ?Sized,
    {
        let mut backoff = RetrySchedule::new(options.min_backoff, options.max_backoff)
            .with_jitter(options.jitter_ratio, options.jitter_seed);
        let mut after = self
            .cursors
            .load(scope.clone())
            .await
            .map_err(|error| fail(provider, RunErrorClass::StoreFailure, error))?;

        loop {
            if self.control.is_cancelled() {
                return Ok(stop(provider, RunStopReason::Cancelled));
            }
            if !provider.is_active() {
                return Ok(stop(provider, RunStopReason::LifecycleEnded));
            }
            provider.observe(RunEvent::Connecting);
            let transport = match provider.provide().await {
                Ok(transport) => {
                    provider.observe(RunEvent::Online);
                    backoff.reset();
                    transport
                }
                Err(error) if is_retryable(&error) => {
                    if let Some(reason) = self.backoff(provider, backoff.next_delay()).await {
                        return Ok(stop(provider, reason));
                    }
                    continue;
                }
                Err(error) => return Err(fail(provider, classify_error(&error), error)),
            };

            let initial_catchup = after.is_none();
            let request = provider
                .account_request(after.clone())
                .map_err(|error| fail(provider, classify_error(&error), error))?;
            request
                .validate()
                .map_err(|error| fail(provider, RunErrorClass::ProtocolViolation, error.into()))?;

            match transport.subscribe(&request).await {
                Ok(AccountSubscribeSnapshotResult::Batch(batch)) => {
                    let events = account_batch_to_client_events(&batch, initial_catchup)
                        .map_err(|error| fail(provider, RunErrorClass::ProtocolViolation, error))?;
                    if !events.is_empty() {
                        projector.project(events).await.map_err(|error| {
                            fail(provider, RunErrorClass::ProjectorFailure, error)
                        })?;
                    }
                    self.cursors
                        .save(scope.clone(), batch.cursor.clone())
                        .await
                        .map_err(|error| fail(provider, RunErrorClass::StoreFailure, error))?;
                    provider.observe(RunEvent::Checkpointed);
                    after = Some(batch.cursor);
                    if let Some(reason) = self.wait(provider, options.beat).await {
                        return Ok(stop(provider, reason));
                    }
                }
                Ok(AccountSubscribeSnapshotResult::ReconnectAfter {
                    reconnect_after_ms,
                    reconnect_cursor,
                    reset_cursor,
                    ..
                }) => {
                    if reset_cursor {
                        provider.observe(RunEvent::CursorReset);
                        self.cursors
                            .clear(scope.clone())
                            .await
                            .map_err(|error| fail(provider, RunErrorClass::StoreFailure, error))?;
                        after = None;
                    } else if let Some(cursor) = reconnect_cursor {
                        self.cursors
                            .save(scope.clone(), cursor.clone())
                            .await
                            .map_err(|error| fail(provider, RunErrorClass::StoreFailure, error))?;
                        after = Some(cursor);
                    }
                    let delay = backoff
                        .next_delay_with_hint(Some(Duration::from_millis(reconnect_after_ms)));
                    if let Some(reason) = self.backoff(provider, delay).await {
                        return Ok(stop(provider, reason));
                    }
                }
                Err(error) if matches!(classify_error(&error), RunErrorClass::Unauthorized) => {
                    provider.observe(RunEvent::Refreshing);
                    match provider.recover_unauthorized().await {
                        Ok(true) => continue,
                        Ok(false) => return Ok(stop(provider, RunStopReason::Unauthorized)),
                        Err(error) => {
                            return Err(fail(provider, classify_error(&error), error));
                        }
                    }
                }
                Err(error) if error.is_invalid_cursor() => {
                    provider.observe(RunEvent::CursorReset);
                    self.cursors
                        .clear(scope.clone())
                        .await
                        .map_err(|error| fail(provider, RunErrorClass::StoreFailure, error))?;
                    after = None;
                    if let Some(reason) = self.backoff(provider, backoff.next_delay()).await {
                        return Ok(stop(provider, reason));
                    }
                }
                Err(error) if is_retryable(&error) => {
                    if let Some(reason) = self.backoff(provider, backoff.next_delay()).await {
                        return Ok(stop(provider, reason));
                    }
                }
                Err(error) => return Err(fail(provider, classify_error(&error), error)),
            }
        }
    }

    async fn backoff<TP: TransportProvider>(
        &self,
        provider: &TP,
        delay: Duration,
    ) -> Option<RunStopReason> {
        provider.observe(RunEvent::Backoff { delay });
        self.wait(provider, delay).await
    }

    async fn wait<TP: TransportProvider>(
        &self,
        provider: &TP,
        delay: Duration,
    ) -> Option<RunStopReason> {
        if self.control.is_cancelled() {
            return Some(RunStopReason::Cancelled);
        }
        self.executor.sleep(delay).await;
        if self.control.is_cancelled() {
            return Some(RunStopReason::Cancelled);
        }
        (!provider.is_active()).then_some(RunStopReason::LifecycleEnded)
    }
}

fn stop<TP: TransportProvider>(provider: &TP, reason: RunStopReason) -> RunStopReason {
    provider.observe(RunEvent::Stopped {
        reason: reason.clone(),
    });
    reason
}

fn fail<TP: TransportProvider>(provider: &TP, class: RunErrorClass, source: Error) -> RunError {
    provider.observe(RunEvent::Stopped {
        reason: RunStopReason::Failed { class },
    });
    RunError { class, source }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;
    use std::sync::atomic::AtomicUsize;

    use arkret_models_collaboration::sync_frames::account_subscribe::{
        AccountSubscribeBatch, AccountSubscribeFrame, AccountSubscribeFrameKind,
    };
    use arkret_wire::Problem;

    use super::*;
    use crate::{ClientEvent, MemoryStore};

    #[derive(Clone, Copy, Debug)]
    struct ImmediateExecutor;

    impl Executor for ImmediateExecutor {
        async fn sleep(&self, _duration: Duration) {}
    }

    #[derive(Debug)]
    struct ScriptedTransport {
        response: Mutex<Option<Result<AccountSubscribeSnapshotResult>>>,
    }

    impl AccountSubscribeTransport for ScriptedTransport {
        async fn subscribe(
            &self,
            _request: &SyncRequestBody,
        ) -> Result<AccountSubscribeSnapshotResult> {
            self.response
                .lock()
                .unwrap()
                .take()
                .unwrap_or_else(|| Err(Error::Protocol("run test script exhausted".to_owned())))
        }
    }

    /// Serves one scripted response per loop iteration and trips the loop's
    /// cancellation once the script is exhausted, so every test runs exactly
    /// the iterations it scripted and then stops.
    #[derive(Debug)]
    struct Provider {
        responses: Mutex<VecDeque<Result<AccountSubscribeSnapshotResult>>>,
        control: SyncLoopControl,
        observed: Mutex<Vec<RunEvent>>,
        recovered: AtomicUsize,
        recovers: bool,
        provides: AtomicUsize,
    }

    impl Provider {
        fn new(
            control: SyncLoopControl,
            responses: Vec<Result<AccountSubscribeSnapshotResult>>,
        ) -> Self {
            Self {
                responses: Mutex::new(responses.into()),
                control,
                observed: Mutex::new(Vec::new()),
                recovered: AtomicUsize::new(0),
                recovers: false,
                provides: AtomicUsize::new(0),
            }
        }

        fn events(&self) -> Vec<RunEvent> {
            self.observed.lock().unwrap().clone()
        }
    }

    impl TransportProvider for Provider {
        type Transport = ScriptedTransport;

        async fn provide(&self) -> Result<ScriptedTransport> {
            self.provides.fetch_add(1, Ordering::SeqCst);
            let mut responses = self.responses.lock().unwrap();
            let next = responses.pop_front();
            if responses.is_empty() {
                self.control.cancel();
            }
            Ok(ScriptedTransport {
                response: Mutex::new(next),
            })
        }

        async fn recover_unauthorized(&self) -> Result<bool> {
            self.recovered.fetch_add(1, Ordering::SeqCst);
            Ok(self.recovers)
        }

        fn observe(&self, event: RunEvent) {
            self.observed.lock().unwrap().push(event);
        }
    }

    #[derive(Debug, Default)]
    struct Projector {
        batches: Mutex<Vec<Vec<ClientEvent>>>,
        fail: bool,
    }

    impl Projector {
        fn failing() -> Self {
            Self {
                batches: Mutex::new(Vec::new()),
                fail: true,
            }
        }

        fn projected(&self) -> usize {
            self.batches.lock().unwrap().len()
        }
    }

    impl ClientProjector for Projector {
        async fn project(&self, batch: Vec<ClientEvent>) -> Result<()> {
            self.batches.lock().unwrap().push(batch);
            if self.fail {
                Err(Error::Protocol("projection failed".to_owned()))
            } else {
                Ok(())
            }
        }
    }

    fn scope() -> CursorScope {
        CursorScope::Account {
            service_id: None,
            actor_id: crate::test_fixtures::actor_id(),
            device_id: crate::test_fixtures::device_id(),
        }
    }

    fn delta_frame(cursor: &str) -> AccountSubscribeFrame {
        AccountSubscribeFrame {
            kind: AccountSubscribeFrameKind::Delta,
            cursor: Some(cursor.to_owned()),
            realms: None,
            to_device: None,
            device_lists: None,
            account_data: None,
            agent_draft_pending_intents: None,
            notifications: None,
            partial: None,
            priority: None,
            reconnect_after_ms: None,
            realm_list: None,
            realm_list_changes: None,
            baseline: None,
            realm_invalidations: None,
        }
    }

    fn batch(cursor: &str) -> Result<AccountSubscribeSnapshotResult> {
        Ok(AccountSubscribeSnapshotResult::Batch(
            AccountSubscribeBatch {
                frames: vec![delta_frame(cursor)],
                cursor: cursor.to_owned(),
            },
        ))
    }

    #[tokio::test]
    async fn cancellation_before_connect_performs_no_network_call() {
        let runner = AccountRunner::new(ImmediateExecutor, MemoryStore::new());
        runner.control().cancel();
        let provider = Provider::new(runner.control(), Vec::new());
        let reason = runner
            .run(
                &provider,
                &Projector::default(),
                scope(),
                RunOptions::default(),
            )
            .await
            .unwrap();
        assert_eq!(reason, RunStopReason::Cancelled);
        assert_eq!(provider.provides.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn a_projected_batch_is_checkpointed_before_the_loop_continues() {
        let store = MemoryStore::new();
        let runner = AccountRunner::new(ImmediateExecutor, store.clone());
        let provider = Provider::new(runner.control(), vec![batch("ak:cursor:next")]);
        let projector = Projector::default();
        assert_eq!(
            runner
                .run(&provider, &projector, scope(), RunOptions::default())
                .await
                .unwrap(),
            RunStopReason::Cancelled
        );
        assert_eq!(projector.projected(), 1);
        assert_eq!(
            store.load(scope()).await.unwrap().as_deref(),
            Some("ak:cursor:next")
        );
        assert!(provider.events().contains(&RunEvent::Checkpointed));
    }

    #[tokio::test]
    async fn a_failing_projector_never_advances_the_cursor() {
        let store = MemoryStore::new();
        store
            .save(scope(), "ak:cursor:old".to_owned())
            .await
            .unwrap();
        let runner = AccountRunner::new(ImmediateExecutor, store.clone());
        let provider = Provider::new(runner.control(), vec![batch("ak:cursor:next")]);
        let error = runner
            .run(
                &provider,
                &Projector::failing(),
                scope(),
                RunOptions::default(),
            )
            .await
            .unwrap_err();
        assert_eq!(error.class, RunErrorClass::ProjectorFailure);
        assert_eq!(
            store.load(scope()).await.unwrap().as_deref(),
            Some("ak:cursor:old")
        );
        assert!(!provider.events().contains(&RunEvent::Checkpointed));
    }

    #[tokio::test]
    async fn a_resync_demand_clears_the_durable_cursor() {
        let store = MemoryStore::new();
        store
            .save(scope(), "ak:cursor:old".to_owned())
            .await
            .unwrap();
        let runner = AccountRunner::new(ImmediateExecutor, store.clone());
        let provider = Provider::new(
            runner.control(),
            vec![Ok(AccountSubscribeSnapshotResult::ReconnectAfter {
                reconnect_after_ms: 1,
                reconnect_cursor: None,
                reason: Some("snapshot changed".to_owned()),
                reset_cursor: true,
            })],
        );
        runner
            .run(
                &provider,
                &Projector::default(),
                scope(),
                RunOptions::default(),
            )
            .await
            .unwrap();
        assert!(store.load(scope()).await.unwrap().is_none());
        assert!(provider.events().contains(&RunEvent::CursorReset));
    }

    #[tokio::test]
    async fn a_reconnect_cursor_is_checkpointed_before_the_retry() {
        let store = MemoryStore::new();
        let runner = AccountRunner::new(ImmediateExecutor, store.clone());
        let provider = Provider::new(
            runner.control(),
            vec![Ok(AccountSubscribeSnapshotResult::ReconnectAfter {
                reconnect_after_ms: 1,
                reconnect_cursor: Some("ak:cursor:resume".to_owned()),
                reason: None,
                reset_cursor: false,
            })],
        );
        runner
            .run(
                &provider,
                &Projector::default(),
                scope(),
                RunOptions::default(),
            )
            .await
            .unwrap();
        assert_eq!(
            store.load(scope()).await.unwrap().as_deref(),
            Some("ak:cursor:resume")
        );
    }

    #[tokio::test]
    async fn an_unrecoverable_authorization_failure_stops_the_loop() {
        let runner = AccountRunner::new(ImmediateExecutor, MemoryStore::new());
        let provider = Provider::new(
            runner.control(),
            vec![Err(Error::Api {
                status: 401,
                error: Box::new(Problem::new("unauthenticated", 401, "grant rejected")),
            })],
        );
        let reason = runner
            .run(
                &provider,
                &Projector::default(),
                scope(),
                RunOptions::default(),
            )
            .await
            .unwrap();
        assert_eq!(reason, RunStopReason::Unauthorized);
        assert_eq!(provider.recovered.load(Ordering::SeqCst), 1);
        assert!(provider.events().contains(&RunEvent::Refreshing));
    }

    #[tokio::test]
    async fn an_expired_cursor_resets_and_resumes_from_catchup() {
        let store = MemoryStore::new();
        store
            .save(scope(), "ak:cursor:old".to_owned())
            .await
            .unwrap();
        let runner = AccountRunner::new(ImmediateExecutor, store.clone());
        let provider = Provider::new(
            runner.control(),
            vec![
                Err(Error::Api {
                    status: 400,
                    error: Box::new(Problem::new("cursor_expired", 400, "cursor expired")),
                }),
                batch("ak:cursor:fresh"),
            ],
        );
        runner
            .run(
                &provider,
                &Projector::default(),
                scope(),
                RunOptions::default(),
            )
            .await
            .unwrap();
        assert!(provider.events().contains(&RunEvent::CursorReset));
        assert_eq!(provider.provides.load(Ordering::SeqCst), 2);
        assert_eq!(
            store.load(scope()).await.unwrap().as_deref(),
            Some("ak:cursor:fresh")
        );
    }

    #[tokio::test]
    async fn a_retryable_transport_fault_reconnects_instead_of_failing() {
        let store = MemoryStore::new();
        let runner = AccountRunner::new(ImmediateExecutor, store.clone());
        let provider = Provider::new(
            runner.control(),
            vec![
                Err(Error::Http("connection reset".to_owned())),
                batch("ak:cursor:after-retry"),
            ],
        );
        runner
            .run(
                &provider,
                &Projector::default(),
                scope(),
                RunOptions::default(),
            )
            .await
            .unwrap();
        assert_eq!(provider.provides.load(Ordering::SeqCst), 2);
        assert_eq!(
            store.load(scope()).await.unwrap().as_deref(),
            Some("ak:cursor:after-retry")
        );
    }
}
