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

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::time::Duration;

use crate::protocol::{DeviceId, DidCoreId, RealmId, Result, SyncUpdates};
use crate::signal::{SignalDecryptor, SignalSenderKeyResolver};
use crate::subscribe::account::{account_updates_to_events, account_updates_to_events_with_origin};
use crate::subscribe::{
    EventsScanTransport, ProjectedRunError, RealmEventsTransport, RealmStreamStopReason,
    ScanCatchupOptions, SignalReceiveHandlers, SignalRunError, SignalSink, SignalStreamDriver,
    SignalStreamStopReason, SignalStreamTransport,
};
use crate::sync_client::{AsyncSyncTransport, SyncLoopControl, SyncLoopStep};
use crate::{
    ArkretClient, ClientProjector, CursorStore, DurableInboxStore, EventCacheStore, Executor,
    HostClock, RetrySchedule,
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

fn next_signal_drain_delay(
    backoff: &mut RetrySchedule,
    reconnect_after_ms: Option<u64>,
) -> Duration {
    // Drain is a successful terminal control frame from an established live
    // rail, not another failed connection attempt. Normal bounded HTTP
    // rollovers must therefore restart at the floor instead of accumulating
    // exponential delay across healthy 30-second connections.
    backoff.reset();
    backoff.next_delay_with_hint(reconnect_after_ms.map(Duration::from_millis))
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
    /// Fraction of the reconnect delay randomized to avoid fleet lockstep.
    pub jitter_ratio: f64,
}

impl Default for RunOptions {
    /// The reconnect cadence is normative, not a tunable default:
    /// `sync/api-conventions.md` §9 requires a first wait of at least 1,000 ms,
    /// a ceiling of at least 60,000 ms and 0–20% jitter, and
    /// `sync/client-sync.md` §2.2.6 restates it for subscribe reconnects.
    /// The previous 500 ms / 30 s pair breached both bounds.
    fn default() -> Self {
        Self {
            beat: Duration::from_millis(250),
            min_backoff: arkret_retry::SPEC_INITIAL_DELAY,
            max_backoff: arkret_retry::SPEC_MAX_DELAY,
            jitter_ratio: arkret_retry::SPEC_JITTER_RATIO,
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
        digest_suite: arkret_canonical::DigestSuite,
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
        let mut backoff = RetrySchedule::new(options.min_backoff, options.max_backoff)
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
                .run_realm_stream_classified(&transport, realm_id.clone(), digest_suite, projector)
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
                        .bootstrap_realm_history_classified(
                            &transport,
                            realm_id.clone(),
                            digest_suite,
                            projector,
                            ScanCatchupOptions::default(),
                        )
                        .await
                        .map_err(|error| Self::fail_projected(provider, error))?;
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
                        .bootstrap_realm_history_classified(
                            &transport,
                            realm_id.clone(),
                            digest_suite,
                            projector,
                            ScanCatchupOptions::default(),
                        )
                        .await
                        .map_err(|error| Self::fail_projected(provider, error))?;
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

    /// Resilient Realm run loop whose checkpoint boundary is the durable
    /// inbox. Stream frames, dropped-cursor scan catch-up, and a fresh
    /// resynchronization baseline are persisted before their Realm cursor can
    /// advance, so dispatch may safely happen in a separate host worker.
    pub async fn run_realm_to_inbox<TP>(
        &self,
        provider: &TP,
        realm_id: RealmId,
        digest_suite: arkret_canonical::DigestSuite,
        control: &SyncLoopControl,
        options: RunOptions,
    ) -> RunResult<RunStopReason>
    where
        TP: TransportProvider,
        TP::Transport: RealmEventsTransport + EventsScanTransport,
        C: DurableInboxStore,
    {
        let backoff_seed = stable_backoff_seed(self.backoff_seed, 0xA11C_E001, &realm_id);
        let engine = self.subscription_engine().with_control(control.clone());
        let mut backoff = RetrySchedule::new(options.min_backoff, options.max_backoff)
            .with_jitter(options.jitter_ratio, backoff_seed);
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
                .run_realm_stream_to_inbox(&transport, realm_id.clone(), digest_suite)
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
                    provider.observe(RunEvent::DeliveryPending);
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
                        .bootstrap_realm_history_to_inbox(
                            &transport,
                            realm_id.clone(),
                            digest_suite,
                            ScanCatchupOptions::default(),
                        )
                        .await
                        .map_err(|error| Self::fail(provider, classify_error(&error), error))?;
                    provider.observe(RunEvent::DeliveryPending);
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
                Err(error) if error.is_invalid_cursor() => {
                    if cursor_recovery_attempted {
                        return Err(Self::fail(
                            provider,
                            RunErrorClass::ProtocolViolation,
                            error,
                        ));
                    }
                    provider.observe(RunEvent::CursorReset);
                    engine
                        .bootstrap_realm_history_to_inbox(
                            &transport,
                            realm_id.clone(),
                            digest_suite,
                            ScanCatchupOptions::default(),
                        )
                        .await
                        .map_err(|error| Self::fail(provider, classify_error(&error), error))?;
                    provider.observe(RunEvent::DeliveryPending);
                    cursor_recovery_attempted = true;
                    backoff.reset();
                }
                Err(error) if retryable(classify_error(&error)) => {
                    let delay = backoff.next_delay();
                    provider.observe(RunEvent::Backoff { delay });
                    if let Some(reason) = self.wait_guarded(delay, control, provider).await {
                        return Ok(Self::stop(provider, reason));
                    }
                }
                Err(error) => {
                    return Err(Self::fail(provider, classify_error(&error), error));
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
        actor_id: DidCoreId,
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
        let mut provide_backoff = RetrySchedule::new(options.min_backoff, options.max_backoff)
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
        actor_id: DidCoreId,
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
        let mut backoff = RetrySchedule::new(options.min_backoff, options.max_backoff).with_jitter(
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
        actor_id: DidCoreId,
        device_id: DeviceId,
        service_id: Option<DidCoreId>,
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
        let mut backoff = RetrySchedule::new(options.min_backoff, options.max_backoff).with_jitter(
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
        let mut backoff = RetrySchedule::new(options.min_backoff, options.max_backoff).with_jitter(
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
                    let delay = next_signal_drain_delay(&mut backoff, reconnect_after_ms);
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
        backoff: &mut RetrySchedule,
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

    /// Classify a projected run loop error by its origin: store and projector
    /// failures keep their attribution instead of being flattened through
    /// [`classify_error`], which only sees the bare protocol error.
    fn fail_projected<TP: TransportProvider + ?Sized>(
        provider: &TP,
        error: ProjectedRunError,
    ) -> RunError {
        match error {
            ProjectedRunError::Store(error) => {
                Self::fail(provider, RunErrorClass::StoreFailure, error)
            }
            ProjectedRunError::Transport(error) => {
                Self::fail(provider, classify_error(&error), error)
            }
            ProjectedRunError::Projector(error) => {
                Self::fail(provider, RunErrorClass::ProjectorFailure, error)
            }
        }
    }
}

#[cfg(test)]
mod signal_drain_backoff_tests {
    use super::*;

    #[test]
    fn healthy_signal_drain_resets_accumulated_reconnect_backoff() {
        let mut backoff =
            RetrySchedule::new(Duration::from_millis(10), Duration::from_millis(1_000));
        assert_eq!(backoff.next_delay(), Duration::from_millis(10));
        assert_eq!(backoff.next_delay(), Duration::from_millis(20));
        assert_eq!(backoff.retries(), 2);

        let delay = next_signal_drain_delay(&mut backoff, Some(25));

        assert_eq!(delay, Duration::from_millis(25));
        assert_eq!(backoff.retries(), 1);
    }
}

#[cfg(all(test, feature = "native"))]
#[path = "orchestrator/tests.rs"]
mod tests;
