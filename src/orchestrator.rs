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
use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
};

use crate::protocol::{DeviceId, Did, RealmId, Result, SyncUpdates};
use crate::sync_client::{AsyncSyncTransport, SyncLoopControl, SyncLoopStep};

use crate::signal::{SignalDecryptor, SignalSenderKeyResolver};
use crate::subscribe::{
    EventsScanTransport, ProjectedRunError, RealmEventsTransport, RealmStreamStopReason,
    ScanCatchupOptions, SignalReceiveHandlers, SignalRunError, SignalSink, SignalStreamDriver,
    SignalStreamStopReason, SignalStreamTransport,
};
use crate::{
    ArkretClient, Backoff, ClientProjector, CursorStore, DurableInboxStore, EventCacheStore,
    Executor, HostClock,
    subscribe::account::{account_updates_to_events, account_updates_to_events_with_origin},
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

/// One validated account-stream checkpoint unit. The cursor comes from the
/// SDK trace validator and the updates are the typed fold of the same stream
/// step, so hosts never need to parse frames or reconstruct cursor ordering.
#[derive(Clone, Debug)]
pub struct AccountStreamStep {
    /// True when the request started without a resume cursor and therefore
    /// carries a server-authoritative full account snapshot.
    pub initial: bool,
    pub cursor: Option<String>,
    pub updates: SyncUpdates,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccountCommitOutcome {
    /// The validated cursor was durably committed with the raw updates.
    Committed,
    /// The host durably retained the updates but intentionally withheld the
    /// cursor (for example until incomplete to-device material is resolved).
    /// Garth must restore the stream loop from the durable cursor before the
    /// next request so the checkpoint unit is replayed.
    Replay,
}

/// Durable host boundary for an account-stream step.
///
/// Implementations must persist the raw typed updates and `cursor` in one
/// transaction before returning. Garth restores the next request from the
/// same [`CursorStore`], then invokes [`AccountPostCommitHook`] for product
/// work that must not hold the protocol cursor open (invite refresh, MLS,
/// calls, and to-device acknowledgements).
pub trait AccountStepCommitter {
    fn commit<'a>(
        &'a self,
        step: &'a AccountStreamStep,
    ) -> impl std::future::Future<Output = Result<AccountCommitOutcome>> + 'a;
}

/// Product-owned work that runs only after an [`AccountStreamStep`] is durable.
/// The hook receives the authenticated transport used for the step so it does
/// not rebuild credentials or a parallel HTTP client.
pub trait AccountPostCommitHook<T> {
    fn post_commit<'a>(
        &'a self,
        transport: &'a T,
        step: &'a AccountStreamStep,
    ) -> impl std::future::Future<Output = Result<AccountPostCommitOutcome>> + 'a;
}

/// The two host-owned boundaries for a standard account stream step.
/// Grouping them makes their commit-before-post-processing order explicit at
/// construction time.
#[derive(Clone, Copy)]
pub struct AccountStepHandlers<'a, C: ?Sized, H: ?Sized> {
    committer: &'a C,
    post_commit: &'a H,
}

impl<'a, C: ?Sized, H: ?Sized> AccountStepHandlers<'a, C, H> {
    pub fn new(committer: &'a C, post_commit: &'a H) -> Self {
        Self {
            committer,
            post_commit,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AccountPostCommitOutcome {
    Continue,
    Retry,
    Unauthorized { reason: Option<String> },
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
    /// Pause after a clean bounded realm-stream window before re-subscribing.
    /// Account long-poll timing is owned by the server-side subscribe window.
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
    pub source: crate::protocol::Error,
}

pub type RunResult<T> = std::result::Result<T, RunError>;

fn classify_error(error: &crate::protocol::Error) -> RunErrorClass {
    use crate::protocol::Error;
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
        Error::KeyStore(_) => RunErrorClass::StoreFailure,
        Error::Crypto(_)
        | Error::IdempotencyConflict(_)
        | Error::CanonicalJson(_)
        | Error::NonCanonicalNumber
        | Error::NumberOutOfSafeRange
        | Error::DuplicateObjectKey(_)
        | Error::NonCanonicalString(_) => RunErrorClass::ProtocolViolation,
        Error::Protocol(_) | Error::Api { .. } | Error::AccountStreamInterrupt(_) => {
            RunErrorClass::ProtocolViolation
        }
    }
}

fn retryable(class: RunErrorClass) -> bool {
    matches!(
        class,
        RunErrorClass::RetryableTransport | RunErrorClass::RateLimited
    )
}

fn stable_backoff_seed(instance_seed: u64, tag: u64, value: impl Hash) -> u64 {
    let mut hasher = DefaultHasher::new();
    instance_seed.hash(&mut hasher);
    tag.hash(&mut hasher);
    value.hash(&mut hasher);
    hasher.finish()
}

fn account_backoff_seed(instance_seed: u64, scope: &crate::CursorScope) -> u64 {
    stable_backoff_seed(instance_seed, 0xACC0_0011, scope)
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
        let backoff_seed = stable_backoff_seed(self.backoff_seed, 0xA11C_E001, &realm_id);
        let engine = self.subscription_engine().with_control(control.clone());
        let mut backoff = Backoff::new(options.min_backoff, options.max_backoff)
            .with_jitter(options.jitter_ratio, backoff_seed);
        // One reset may legitimately be needed for a persisted cursor. A
        // second invalid-cursor response before a healthy stream result is a
        // server/protocol fault and must stop instead of becoming a tight loop.
        let mut cursor_recovery_attempted = false;
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
                    cursor_recovery_attempted = false;
                    backoff.reset();
                    if let Some(reason) = self.wait_guarded(options.beat, control, provider).await {
                        return Ok(Self::stop(provider, reason));
                    }
                }
                Ok(RealmStreamStopReason::Dropped {
                    reconnect_after_ms, ..
                }) => {
                    cursor_recovery_attempted = false;
                    let delay =
                        backoff.next_delay_with_hint(reconnect_after_ms.map(Duration::from_millis));
                    provider.observe(RunEvent::Backoff { delay });
                    if let Some(reason) = self.wait_guarded(delay, control, provider).await {
                        return Ok(Self::stop(provider, reason));
                    }
                }
                Ok(RealmStreamStopReason::ResyncRequired { reconnect_after_ms }) => {
                    if cursor_recovery_attempted {
                        return Err(Self::fail(
                            provider,
                            RunErrorClass::ProtocolViolation,
                            crate::protocol::Error::Protocol(
                                "realm stream required resync again before recovery completed"
                                    .to_owned(),
                            ),
                        ));
                    }
                    provider.observe(RunEvent::CursorReset);
                    engine
                        .clear_realm_history_cursors(realm_id.clone())
                        .await
                        .map_err(|error| {
                            Self::fail(provider, RunErrorClass::StoreFailure, error)
                        })?;
                    engine
                        .bootstrap_realm_history(
                            &transport,
                            realm_id.clone(),
                            projector,
                            ScanCatchupOptions::default(),
                        )
                        .await
                        .map_err(|error| Self::fail(provider, classify_error(&error), error))?;
                    cursor_recovery_attempted = true;
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
                Err(ProjectedRunError::Transport(error)) if error.is_invalid_cursor() => {
                    if cursor_recovery_attempted {
                        return Err(Self::fail(
                            provider,
                            RunErrorClass::ProtocolViolation,
                            error,
                        ));
                    }
                    provider.observe(RunEvent::CursorReset);
                    engine
                        .clear_realm_history_cursors(realm_id.clone())
                        .await
                        .map_err(|error| {
                            Self::fail(provider, RunErrorClass::StoreFailure, error)
                        })?;
                    engine
                        .bootstrap_realm_history(
                            &transport,
                            realm_id.clone(),
                            projector,
                            ScanCatchupOptions::default(),
                        )
                        .await
                        .map_err(|error| Self::fail(provider, classify_error(&error), error))?;
                    cursor_recovery_attempted = true;
                    backoff.reset();
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
            .with_jitter(
                options.jitter_ratio,
                account_backoff_seed(self.backoff_seed, &scope),
            );
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
                    let batch = account_updates_to_events(*updates);
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
                SyncLoopStep::Failed { error } => {
                    return Err(Self::fail(
                        provider,
                        RunErrorClass::ProtocolViolation,
                        crate::protocol::Error::Protocol(error),
                    ));
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

    /// Resilient account runner with an atomic raw-step commit followed by
    /// product-owned post-processing. This is the composition point for hosts
    /// whose account loop includes MLS/invite/call work that does not belong in
    /// Garth, while trace validation, cursor restoration, session recovery,
    /// cancellation and bounded reconnect backoff remain shared here.
    pub async fn run_account_steps<TP, CMT, H>(
        &self,
        actor_id: Did,
        device_id: DeviceId,
        provider: &TP,
        handlers: AccountStepHandlers<'_, CMT, H>,
        control: &SyncLoopControl,
        options: RunOptions,
    ) -> RunResult<RunStopReason>
    where
        TP: TransportProvider,
        TP::Transport: AsyncSyncTransport,
        CMT: AccountStepCommitter + ?Sized,
        H: AccountPostCommitHook<TP::Transport> + ?Sized,
    {
        let engine = self.subscription_engine().with_control(control.clone());
        let scope = engine.account_scope(actor_id, device_id);
        let mut sync_loop = engine
            .restore_account_loop(scope.clone())
            .await
            .map_err(|error| Self::fail(provider, RunErrorClass::StoreFailure, error))?;
        let mut backoff = Backoff::new(options.min_backoff, options.max_backoff).with_jitter(
            options.jitter_ratio,
            account_backoff_seed(self.backoff_seed, &scope),
        );
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
                Err(error) => return Err(Self::fail(provider, classify_error(&error), error)),
            };
            let initial = sync_loop.token().is_none();
            match sync_loop.step_async_with_control(&transport, control).await {
                SyncLoopStep::Updates(updates) => {
                    let step = AccountStreamStep {
                        initial,
                        cursor: sync_loop.token().map(str::to_owned),
                        updates: *updates,
                    };
                    let commit_outcome =
                        handlers.committer.commit(&step).await.map_err(|error| {
                            Self::fail(provider, RunErrorClass::StoreFailure, error)
                        })?;
                    let post_commit = handlers
                        .post_commit
                        .post_commit(&transport, &step)
                        .await
                        .map_err(|error| {
                            Self::fail(provider, RunErrorClass::ProjectorFailure, error)
                        })?;
                    match post_commit {
                        AccountPostCommitOutcome::Continue => {}
                        AccountPostCommitOutcome::Retry => {
                            let delay = backoff.next_delay();
                            provider.observe(RunEvent::Backoff { delay });
                            if let Some(reason) = self.wait_guarded(delay, control, provider).await
                            {
                                return Ok(Self::stop(provider, reason));
                            }
                        }
                        AccountPostCommitOutcome::Unauthorized { reason } => {
                            match self
                                .recover_unauthorized(provider, control, &mut backoff)
                                .await?
                            {
                                UnauthorizedRecovery::Recovered | UnauthorizedRecovery::Retry => {
                                    continue;
                                }
                                UnauthorizedRecovery::GuardedStop(reason) => return Ok(reason),
                                UnauthorizedRecovery::Unavailable => {}
                            }
                            return Ok(Self::stop(
                                provider,
                                RunStopReason::Unauthorized { reason },
                            ));
                        }
                    }
                    if commit_outcome == AccountCommitOutcome::Replay {
                        sync_loop =
                            engine
                                .restore_account_loop(scope.clone())
                                .await
                                .map_err(|error| {
                                    Self::fail(provider, RunErrorClass::StoreFailure, error)
                                })?;
                        if let Some(reason) = self
                            .wait_guarded(options.min_backoff, control, provider)
                            .await
                        {
                            return Ok(Self::stop(provider, reason));
                        }
                    }
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
                SyncLoopStep::Failed { error } => {
                    return Err(Self::fail(
                        provider,
                        RunErrorClass::ProtocolViolation,
                        crate::protocol::Error::Protocol(error),
                    ));
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
        let mut backoff = Backoff::new(options.min_backoff, options.max_backoff).with_jitter(
            options.jitter_ratio,
            account_backoff_seed(self.backoff_seed, &scope),
        );
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
            let initial_catchup = sync_loop.token().is_none();
            match sync_loop.step_async_with_control(&transport, control).await {
                SyncLoopStep::Updates(updates) => {
                    let delivery_id = self
                        .cursor_store
                        .commit(
                            scope.clone(),
                            sync_loop.token().map(str::to_owned),
                            account_updates_to_events_with_origin(*updates, initial_catchup),
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
                SyncLoopStep::Failed { error } => {
                    return Err(Self::fail(
                        provider,
                        RunErrorClass::ProtocolViolation,
                        crate::protocol::Error::Protocol(error),
                    ));
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

    /// Resilient Signal receive rail: subscribe -> admit -> deliver, reconnect
    /// with backoff after every clean or drained connection, stop on
    /// cancellation or `Unauthorized`.
    ///
    /// There is no cursor, checkpoint or catch-up here and there must not be
    /// one: `signal.md` §4.1 gives the rail no durable position, so a reconnect
    /// re-establishes live fanout and nothing else. The only state carried
    /// across connections is the driver's §2 de-duplication window.
    pub async fn run_signal<TP, R, DEC, S, K>(
        &self,
        provider: &TP,
        handlers: SignalReceiveHandlers<'_, R, DEC, S>,
        clock: &K,
        control: &SyncLoopControl,
        options: RunOptions,
    ) -> RunResult<RunStopReason>
    where
        TP: TransportProvider,
        TP::Transport: SignalStreamTransport,
        R: SignalSenderKeyResolver,
        DEC: SignalDecryptor,
        S: SignalSink + ?Sized,
        K: HostClock,
    {
        let mut driver = SignalStreamDriver::new();
        // Tagged so the Signal rail's reconnect jitter does not move in
        // lockstep with the account and realm rails of the same client.
        let mut backoff = Backoff::new(options.min_backoff, options.max_backoff).with_jitter(
            options.jitter_ratio,
            stable_backoff_seed(self.backoff_seed, 0x5169_4E41, "signal"),
        );
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
                Err(error) => return Err(Self::fail(provider, classify_error(&error), error)),
            };
            match driver.run(&transport, handlers, clock).await {
                Ok(SignalStreamStopReason::StreamEnded) => {
                    backoff.reset();
                    if let Some(reason) = self.wait_guarded(options.beat, control, provider).await {
                        return Ok(Self::stop(provider, reason));
                    }
                }
                // A drain bounds only how soon the same session/device may
                // re-open the Signal rail. It is not a delivery receipt and it
                // never gates account/events reconnect.
                Ok(SignalStreamStopReason::Drain {
                    reconnect_after_ms, ..
                }) => {
                    let delay =
                        backoff.next_delay_with_hint(reconnect_after_ms.map(Duration::from_millis));
                    provider.observe(RunEvent::Backoff { delay });
                    if let Some(reason) = self.wait_guarded(delay, control, provider).await {
                        return Ok(Self::stop(provider, reason));
                    }
                }
                Ok(SignalStreamStopReason::Unauthorized { reason }) => {
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
                Err(SignalRunError::Transport(error)) if retryable(classify_error(&error)) => {
                    let delay = backoff.next_delay();
                    provider.observe(RunEvent::Backoff { delay });
                    if let Some(reason) = self.wait_guarded(delay, control, provider).await {
                        return Ok(Self::stop(provider, reason));
                    }
                }
                Err(SignalRunError::Transport(error)) => {
                    return Err(Self::fail(provider, classify_error(&error), error));
                }
                Err(SignalRunError::Sink(error)) => {
                    return Err(Self::fail(provider, RunErrorClass::ProjectorFailure, error));
                }
            }
        }
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
        source: crate::protocol::Error,
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

    use crate::protocol::{AccountStreamInterrupt, AccountSubscribeBatch, Error, SyncRequestBody};
    use crate::protocol::{
        ErrorEnvelope, EventsQueryOutcome, EventsSubscribeFrame, EventsSubscribeFrameKind, Hlc,
        NotificationDelta, NotificationDeltaAction, NotificationId, NotificationKind, RealmId,
    };
    use serde_json::{Value, json};

    use super::*;
    use crate::store::CursorStore;
    use crate::subscribe::scan::BoxScanFuture;
    use crate::subscribe::test_support::{RecordingExecutor, sync_response};
    use crate::{
        BoxRealmStreamFuture, BoxSyncFuture, ClientEvent, CursorScope, DurableInboxStore,
        EventsScanRequest, MemoryStore, RealmEventsFrameSource,
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
        ) -> BoxScanFuture<'a, EventsQueryOutcome> {
            Box::pin(async move {
                Ok(EventsQueryOutcome {
                    events: Vec::new(),
                    snapshot_bootstrap: None,
                    prev_cursor: None,
                    next_cursor: None,
                    has_more: false,
                    range_completeness: None,
                })
            })
        }
    }

    struct AccountTransport {
        response: Mutex<Option<Result<AccountSubscribeBatch>>>,
    }

    struct RecordingStepCommitter {
        order: Arc<Mutex<Vec<&'static str>>>,
        store: MemoryStore,
    }

    impl AccountStepCommitter for RecordingStepCommitter {
        fn commit<'a>(
            &'a self,
            step: &'a AccountStreamStep,
        ) -> impl std::future::Future<Output = Result<AccountCommitOutcome>> + 'a {
            async move {
                self.order.lock().unwrap().push("commit");
                let cursor = step
                    .cursor
                    .clone()
                    .ok_or_else(|| Error::Protocol("test step has no cursor".to_owned()))?;
                self.store.save(account_scope(), cursor).await?;
                Ok(AccountCommitOutcome::Committed)
            }
        }
    }

    struct RecordingPostCommitHook {
        order: Arc<Mutex<Vec<&'static str>>>,
        store: MemoryStore,
        control: SyncLoopControl,
    }

    impl AccountPostCommitHook<AccountTransport> for RecordingPostCommitHook {
        fn post_commit<'a>(
            &'a self,
            _transport: &'a AccountTransport,
            step: &'a AccountStreamStep,
        ) -> impl std::future::Future<Output = Result<AccountPostCommitOutcome>> + 'a {
            async move {
                assert_eq!(
                    self.store.load(account_scope()).await?.as_deref(),
                    step.cursor.as_deref(),
                    "post-commit work must observe the durable cursor"
                );
                self.order.lock().unwrap().push("hook");
                self.control.cancel();
                Ok(AccountPostCommitOutcome::Continue)
            }
        }
    }

    impl AccountTransport {
        fn new(response: Result<AccountSubscribeBatch>) -> Self {
            Self {
                response: Mutex::new(Some(response)),
            }
        }
    }

    impl AsyncSyncTransport for AccountTransport {
        fn sync_async<'a>(
            &'a self,
            _request: SyncRequestBody,
        ) -> BoxSyncFuture<'a, AccountSubscribeBatch> {
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

    #[test]
    fn backoff_seeds_are_stable_and_scope_specific() {
        let realm_a = realm_id();
        let realm_b = RealmId::new("ak:realm:01904100-0000-7000-8000-000000000002").unwrap();
        assert_eq!(
            stable_backoff_seed(11, 0xA11C_E001, &realm_a),
            stable_backoff_seed(11, 0xA11C_E001, &realm_a)
        );
        assert_ne!(
            stable_backoff_seed(11, 0xA11C_E001, &realm_a),
            stable_backoff_seed(12, 0xA11C_E001, &realm_a)
        );
        assert_ne!(
            stable_backoff_seed(11, 0xA11C_E001, &realm_a),
            stable_backoff_seed(11, 0xA11C_E001, &realm_b)
        );

        let scope_a = account_scope();
        let scope_b = CursorScope::Account {
            service_id: None,
            actor_id: actor_id(),
            device_id: DeviceId::new("ak:device:01904100-0000-7000-8000-000000000002").unwrap(),
        };
        assert_ne!(
            account_backoff_seed(11, &scope_a),
            account_backoff_seed(11, &scope_b)
        );
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
        let payload = if payload.is_null() {
            None
        } else {
            Some(serde_json::from_value(payload).expect("frame payload must be an object"))
        };
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
        let event = crate::protocol::Event::new(
            crate::protocol::events::EventKind::MESSAGE_CREATE,
            crate::protocol::ScopeRef::Realm {
                realm_id: realm_id(),
            },
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
            Some(crate::protocol::identifiers::Cursor::new("ak:cursor:event-frame").unwrap());
        framed
    }

    fn cursor_expired_error() -> Error {
        Error::Api {
            status: 410,
            error: Box::new(ErrorEnvelope::new("cursor_expired", "cursor expired")),
        }
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
                vec![ClientEvent::Notification(NotificationDelta {
                    id: NotificationId::new("ak:notification:01964137-0000-7000-8000-000000000011")
                        .unwrap(),
                    notification_kind: NotificationKind::Agent,
                    action: NotificationDeltaAction::Remove,
                    data: None,
                })],
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
    async fn run_realm_clears_all_cursors_bootstraps_and_reconnects_after_cursor_expiry() {
        let store = MemoryStore::new();
        let realm_scope = CursorScope::RealmEvents {
            service_id: None,
            realm_id: realm_id(),
        };
        let scan_scope = CursorScope::RealmEventsScan {
            service_id: None,
            realm_id: realm_id(),
            order: None,
        };
        store
            .save(realm_scope.clone(), "ak:cursor:expired-stream".to_owned())
            .await
            .unwrap();
        store
            .save(scan_scope.clone(), "ak:cursor:expired-scan".to_owned())
            .await
            .unwrap();
        let client = test_client(RecordingExecutor::default(), store.clone());
        let provider = QueueProvider::new(vec![
            Ok(TestRealmTransport {
                open_error: Mutex::new(Some(cursor_expired_error())),
                source: Mutex::new(None),
            }),
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
        assert!(store.load(realm_scope).await.unwrap().is_none());
        assert!(store.load(scan_scope).await.unwrap().is_none());
        assert_eq!(*calls.lock().unwrap(), 0);
        assert!(provider.events().contains(&RunEvent::CursorReset));
    }

    #[tokio::test]
    async fn run_realm_stops_instead_of_looping_when_cursorless_retry_is_rejected() {
        let store = MemoryStore::new();
        let scope = CursorScope::RealmEvents {
            service_id: None,
            realm_id: realm_id(),
        };
        store
            .save(scope.clone(), "ak:cursor:expired-stream".to_owned())
            .await
            .unwrap();
        let client = test_client(RecordingExecutor::default(), store.clone());
        let provider = QueueProvider::new(vec![
            Ok(TestRealmTransport {
                open_error: Mutex::new(Some(cursor_expired_error())),
                source: Mutex::new(None),
            }),
            Ok(TestRealmTransport {
                open_error: Mutex::new(Some(cursor_expired_error())),
                source: Mutex::new(None),
            }),
        ]);
        let control = SyncLoopControl::new();
        let (projector, _) = projector(None, false);

        let error = client
            .run_realm(&provider, realm_id(), &projector, &control, options())
            .await
            .unwrap_err();

        assert_eq!(error.class, RunErrorClass::ProtocolViolation);
        assert_eq!(provider.calls(), 2);
        assert!(store.load(scope).await.unwrap().is_none());
        assert_eq!(
            provider
                .events()
                .iter()
                .filter(|event| matches!(event, RunEvent::CursorReset))
                .count(),
            1
        );
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
        dropped.cursor =
            Some(crate::protocol::identifiers::Cursor::new("ak:cursor:dropped").unwrap());
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
    async fn run_account_steps_commits_before_host_postprocessing() {
        let store = MemoryStore::new();
        let client = test_client(RecordingExecutor::default(), store.clone());
        let provider = QueueProvider::new(vec![Ok(AccountTransport::new(Ok(sync_response(
            "ak:cursor:standard-step",
        ))))]);
        let control = SyncLoopControl::new();
        let order = Arc::new(Mutex::new(Vec::new()));
        let committer = RecordingStepCommitter {
            order: order.clone(),
            store: store.clone(),
        };
        let hook = RecordingPostCommitHook {
            order: order.clone(),
            store: store.clone(),
            control: control.clone(),
        };

        let stop = client
            .run_account_steps(
                actor_id(),
                device_id(),
                &provider,
                AccountStepHandlers::new(&committer, &hook),
                &control,
                options(),
            )
            .await
            .unwrap();

        assert_eq!(stop, RunStopReason::Cancelled);
        assert_eq!(*order.lock().unwrap(), vec!["commit", "hook"]);
        assert_eq!(provider.calls(), 1);
        assert_eq!(
            store.load(account_scope()).await.unwrap().as_deref(),
            Some("ak:cursor:standard-step")
        );
    }

    #[tokio::test]
    async fn run_account_reprovides_after_sync_retry() {
        let executor = RecordingExecutor::default();
        let store = MemoryStore::new();
        let client = test_client(executor.clone(), store.clone());
        let provider = QueueProvider::new(vec![
            Ok(AccountTransport::new(Err(Error::Api {
                status: 503,
                error: Box::new(ErrorEnvelope::new("service_unavailable", "network down")),
            }))),
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
    async fn run_account_stops_after_one_non_retryable_protocol_error() {
        let executor = RecordingExecutor::default();
        let store = MemoryStore::new();
        let client = test_client(executor.clone(), store);
        let provider = QueueProvider::new(vec![Ok(AccountTransport::new(Err(Error::Protocol(
            "malformed account frame".to_owned(),
        ))))]);
        let control = SyncLoopControl::new();
        let (projector, calls) = projector(Some(control.clone()), false);

        let error = client
            .run_account(
                actor_id(),
                device_id(),
                &provider,
                &projector,
                &control,
                options(),
            )
            .await
            .unwrap_err();

        assert_eq!(error.class, RunErrorClass::ProtocolViolation);
        assert_eq!(provider.calls(), 1);
        assert_eq!(*calls.lock().unwrap(), 0);
        assert!(executor.sleeps().is_empty());
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

        let provider = QueueProvider::<()>::new(Vec::new());
        let reason = tokio::time::timeout(
            Duration::from_millis(250),
            client.wait_guarded(Duration::from_secs(30), &control, &provider),
        )
        .await
        .expect("cancellation must interrupt the long wait");
        assert_eq!(reason, Some(RunStopReason::Cancelled));
    }
}
