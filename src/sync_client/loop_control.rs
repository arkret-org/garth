use arkret_retry::{Jitter, RetryPolicy};

use super::*;

/// Retry configuration for sync failures.
///
/// The curve itself is [`arkret_retry::RetryPolicy`]; this is the sync loop's
/// declarative view of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackoffConfig {
    /// Initial delay after the first failure.
    pub initial_delay: Duration,
    /// Maximum delay after repeated failures.
    pub max_delay: Duration,
    /// Multiplier applied after each failure.
    pub multiplier: u32,
    /// Apply 0–20% additive jitter to computed delays so a fleet of clients
    /// does not reconnect in lockstep (api-conventions.md §9 /
    /// client-sync.md §2.2.6).
    pub jitter: bool,
}

impl Default for BackoffConfig {
    /// `client-sync.md` §2.2.6 / `api-conventions.md` §9 reconnect backoff.
    fn default() -> Self {
        let policy = RetryPolicy::arkret_default();
        Self {
            initial_delay: policy.initial_delay(),
            max_delay: policy.max_delay(),
            multiplier: policy.factor(),
            jitter: true,
        }
    }
}

impl BackoffConfig {
    fn policy(&self) -> RetryPolicy {
        RetryPolicy::exponential(self.initial_delay, self.max_delay)
            .with_factor(self.multiplier)
            .with_jitter_ratio(if self.jitter {
                arkret_retry::SPEC_JITTER_RATIO
            } else {
                0.0
            })
    }
}

/// Exponential backoff state for the sync loop.
#[derive(Clone, Debug)]
pub struct ExponentialBackoff {
    config: BackoffConfig,
    policy: RetryPolicy,
    jitter: Jitter,
    failures: u32,
}

impl ExponentialBackoff {
    /// Create backoff state with a custom configuration.
    ///
    /// `arkret-retry` takes an injected jitter seed rather than reading the OS
    /// entropy source, which is what keeps the same curve usable on
    /// `wasm32-unknown-unknown`. The sync loop seeds it once per instance.
    pub fn new(config: BackoffConfig) -> Self {
        Self::with_jitter_seed(config, backoff_jitter_seed())
    }

    /// Create backoff state with an explicit jitter seed (deterministic tests).
    pub fn with_jitter_seed(config: BackoffConfig, seed: u64) -> Self {
        let policy = config.policy();
        Self {
            config,
            policy,
            jitter: Jitter::from_seed(seed),
            failures: 0,
        }
    }

    /// Record a failed sync attempt and return the next wait duration.
    pub fn record_failure(&mut self) -> Duration {
        self.failures = self.failures.saturating_add(1);
        self.policy
            .delay(self.failures.saturating_sub(1), &mut self.jitter)
    }

    /// Clear failure state after a successful sync.
    pub fn reset(&mut self) {
        self.failures = 0;
    }

    /// Number of consecutive failures.
    pub fn failures(&self) -> u32 {
        self.failures
    }

    /// The configuration this state was built from.
    pub fn config(&self) -> &BackoffConfig {
        &self.config
    }

    /// Current un-jittered delay for the consecutive failure count.
    pub fn current_delay(&self) -> Duration {
        if self.failures == 0 {
            return Duration::ZERO;
        }
        self.policy.base_delay(self.failures.saturating_sub(1))
    }
}

/// Per-instance jitter seed. Falls back to a fixed seed when the OS randomness
/// source is unavailable; jitter is de-correlation, never a security boundary.
fn backoff_jitter_seed() -> u64 {
    getrandom::u64().unwrap_or(0x5EED_0BAC_C0FF_1E55)
}

impl Default for ExponentialBackoff {
    fn default() -> Self {
        Self::new(BackoffConfig::default())
    }
}

/// Result of one sync-loop iteration.
#[derive(Clone, Debug)]
pub enum SyncLoopStep {
    /// A response was processed successfully.
    Updates(Box<SyncUpdates>),
    /// Sync failed; caller should wait for `retry_after` before trying again.
    Retry {
        retry_after: Duration,
        error: String,
    },
    /// Sync failed terminally; the caller should stop the loop and surface
    /// the error rather than retry. Consumed by cursor-owning run loops
    /// (e.g. garth) that distinguish retryable transport faults from
    /// non-retryable protocol failures.
    Failed { error: String },
    /// The caller requested cancellation before a transport request started.
    Cancelled,
    /// A request was deferred because the configured in-flight limit was reached.
    Backpressure { retry_after: Duration },
    /// The stream delivered an `unauthorized` control frame: this session
    /// may no longer consume the account stream. The caller MUST
    /// re-authenticate or sign out (client-sync.md §2.2.5); retrying with
    /// the same session is pointless.
    Unauthorized { reason: Option<String> },
}

/// Minimal transport abstraction used by [`SyncLoop`].
pub trait SyncTransport {
    /// Execute one sync request.
    fn sync(
        &mut self,
        request: SyncRequestBody,
        options: arkret_http_client::ClientRequestOptions,
    ) -> Result<AccountSubscribeBatch>;
}

impl<F> SyncTransport for F
where
    F: FnMut(
        SyncRequestBody,
        arkret_http_client::ClientRequestOptions,
    ) -> Result<AccountSubscribeBatch>,
{
    fn sync(
        &mut self,
        request: SyncRequestBody,
        options: arkret_http_client::ClientRequestOptions,
    ) -> Result<AccountSubscribeBatch> {
        self(request, options)
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub type BoxSyncFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;
#[cfg(target_arch = "wasm32")]
pub type BoxSyncFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + 'a>>;

/// Async transport abstraction used by [`SyncLoop::step_async`].
pub trait AsyncSyncTransport {
    /// Execute one async sync request.
    fn sync_async<'a>(
        &'a self,
        request: SyncRequestBody,
        options: arkret_http_client::ClientRequestOptions,
    ) -> BoxSyncFuture<'a, AccountSubscribeBatch>;
}

#[cfg(not(target_arch = "wasm32"))]
impl<F, Fut> AsyncSyncTransport for F
where
    F: Fn(SyncRequestBody, arkret_http_client::ClientRequestOptions) -> Fut + Send + Sync,
    Fut: Future<Output = Result<AccountSubscribeBatch>> + Send + 'static,
{
    fn sync_async<'a>(
        &'a self,
        request: SyncRequestBody,
        options: arkret_http_client::ClientRequestOptions,
    ) -> BoxSyncFuture<'a, AccountSubscribeBatch> {
        Box::pin(self(request, options))
    }
}

#[cfg(target_arch = "wasm32")]
impl<F, Fut> AsyncSyncTransport for F
where
    F: Fn(SyncRequestBody, arkret_http_client::ClientRequestOptions) -> Fut,
    Fut: Future<Output = Result<AccountSubscribeBatch>> + 'static,
{
    fn sync_async<'a>(
        &'a self,
        request: SyncRequestBody,
        options: arkret_http_client::ClientRequestOptions,
    ) -> BoxSyncFuture<'a, AccountSubscribeBatch> {
        Box::pin(self(request, options))
    }
}

// Browser HTTP futures contain `JsValue` and are intentionally `!Send`.
// `BoxSyncFuture` follows the same native/wasm boundary as the rest of the
// SDK async surface, so the concrete client remains the canonical transport
// on both native and single-threaded browser targets.
impl AsyncSyncTransport for arkret_http_client::Client {
    fn sync_async<'a>(
        &'a self,
        request: SyncRequestBody,
        options: arkret_http_client::ClientRequestOptions,
    ) -> BoxSyncFuture<'a, AccountSubscribeBatch> {
        Box::pin(async move {
            self.account_subscribe_batch_with_options(&request, &options)
                .await
                .map_err(Error::from)
        })
    }
}

/// Cancellation token that stays independent of a specific async runtime.
#[derive(Clone, Debug, Default)]
pub struct CancellationToken {
    cancelled: Arc<AtomicBool>,
}

impl CancellationToken {
    /// Create a non-cancelled token.
    pub fn new() -> Self {
        Self::default()
    }

    /// Request cancellation for future sync work.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    /// Clear a previous cancellation request.
    pub fn reset(&self) {
        self.cancelled.store(false, Ordering::SeqCst);
    }

    /// Whether cancellation has been requested.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }
}

/// Async sync backpressure settings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackpressureConfig {
    /// Maximum number of concurrent transport requests.
    pub max_in_flight_requests: usize,
    /// Delay returned when a caller should retry after backpressure.
    pub retry_after: Duration,
}

impl Default for BackpressureConfig {
    fn default() -> Self {
        Self {
            max_in_flight_requests: 1,
            retry_after: Duration::from_millis(100),
        }
    }
}

/// Runtime-neutral async sync loop controls.
#[derive(Clone, Debug)]
pub struct SyncLoopControl {
    cancellation: CancellationToken,
    backpressure: BackpressureConfig,
    in_flight: Arc<AtomicUsize>,
}

impl SyncLoopControl {
    /// Create controls with default cancellation and single-flight backpressure.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set backpressure behavior.
    pub fn with_backpressure(mut self, backpressure: BackpressureConfig) -> Self {
        self.backpressure = backpressure;
        self
    }

    /// Request cancellation.
    pub fn cancel(&self) {
        self.cancellation.cancel();
    }

    /// Whether cancellation has been requested.
    pub fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
    }

    /// Configured retry delay for backpressure responses.
    pub fn backpressure_retry_after(&self) -> Duration {
        self.backpressure.retry_after
    }

    pub(super) fn try_acquire(&self) -> Option<InFlightPermit> {
        let max = self.backpressure.max_in_flight_requests.max(1);
        let mut current = self.in_flight.load(Ordering::SeqCst);
        loop {
            if current >= max {
                return None;
            }
            match self.in_flight.compare_exchange(
                current,
                current + 1,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => {
                    return Some(InFlightPermit {
                        in_flight: Arc::clone(&self.in_flight),
                    });
                }
                Err(observed) => current = observed,
            }
        }
    }
}

impl Default for SyncLoopControl {
    fn default() -> Self {
        Self {
            cancellation: CancellationToken::default(),
            backpressure: BackpressureConfig::default(),
            in_flight: Arc::new(AtomicUsize::new(0)),
        }
    }
}

pub(super) struct InFlightPermit {
    in_flight: Arc<AtomicUsize>,
}

impl Drop for InFlightPermit {
    fn drop(&mut self) {
        self.in_flight.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Strategy used when a limited timeline indicates a sync gap.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncGapStrategy {
    /// Preserve the token and let the caller backfill gaps explicitly.
    #[default]
    PreserveTokenAndBackfill,
    /// Clear the token so the next sync restarts from an initial snapshot.
    ResetTokenOnLimitedTimeline,
}

/// Serializable sync loop state for durable token persistence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncLoopSnapshot {
    /// Last accepted sync token.
    pub token: Option<String>,
    /// Long-poll timeout persisted as milliseconds for portability.
    pub timeout_ms: u64,
    /// Gap handling strategy used by the loop.
    pub gap_strategy: SyncGapStrategy,
}

/// Long-polling sync loop state.
pub struct SyncLoop {
    token: Option<String>,
    timeout: Duration,
    filter: Option<SyncFilter>,
    wait_for: Option<String>,
    backoff: ExponentialBackoff,
    processor: SyncResponseProcessor,
    gap_strategy: SyncGapStrategy,
}

impl SyncLoop {
    /// Create a sync loop with a 30 second long-poll timeout.
    pub fn new() -> Self {
        Self {
            token: None,
            timeout: Duration::from_secs(30),
            filter: None,
            wait_for: None,
            backoff: ExponentialBackoff::default(),
            processor: SyncResponseProcessor::new(),
            gap_strategy: SyncGapStrategy::PreserveTokenAndBackfill,
        }
    }

    /// Restore a loop from a previously persisted snapshot.
    pub fn from_snapshot(snapshot: SyncLoopSnapshot) -> Self {
        let mut sync_loop = Self::new()
            .with_timeout(Duration::from_millis(snapshot.timeout_ms))
            .with_gap_strategy(snapshot.gap_strategy);
        sync_loop.token = snapshot.token;
        sync_loop
    }

    /// Set the long-poll timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set a frontier the server should wait for before returning.
    pub fn with_wait_for(mut self, wait_for: impl Into<String>) -> Self {
        self.wait_for = Some(wait_for.into());
        self
    }

    /// Set the gap strategy used after limited timelines.
    pub fn with_gap_strategy(mut self, strategy: SyncGapStrategy) -> Self {
        self.gap_strategy = strategy;
        self
    }

    /// Build the next long-poll request.
    ///
    /// The loop's `timeout` is intentionally not part of the wire request:
    /// `ak.self.account.stream.subscribe.v1` has no client-supplied long-poll
    /// timeout parameter (client-sync.md §2 — the wait window is a server /
    /// deployment default). It only feeds snapshot persistence and the
    /// caller's own scheduling.
    pub fn next_request(&self) -> SyncRequestBody {
        SyncRequestBody {
            after: self.token.clone(),
            catchup: Some(true),
            filter: self.filter.clone(),
        }
    }

    /// Build HTTP options for the next account-subscribe request.
    pub fn next_request_options(&self) -> arkret_http_client::ClientRequestOptions {
        self.wait_for
            .as_ref()
            .map_or_else(arkret_http_client::ClientRequestOptions::new, |barrier| {
                arkret_http_client::ClientRequestOptions::new().wait_for(barrier.clone())
            })
    }

    fn handle_response(&mut self, batch: AccountSubscribeBatch) -> SyncLoopStep {
        // Snapshot the pre-response cursor so a processing failure leaves
        // the loop positioned to re-fetch the same batch (at-least-once,
        // operations-sync.md): the token and backoff state only advance
        // after `process` succeeds.
        let cursor = batch.cursor.clone();
        if cursor.trim().is_empty() {
            return SyncLoopStep::Failed {
                error: "account subscribe batch requires a non-empty cursor".to_owned(),
            };
        }
        match self.processor.process(batch) {
            Ok(updates) => {
                self.backoff.reset();
                self.token = Some(cursor);
                if self.gap_strategy == SyncGapStrategy::ResetTokenOnLimitedTimeline
                    && updates.realm_updates.iter().any(|update| {
                        update
                            .entry
                            .timeline
                            .as_ref()
                            .is_some_and(|timeline| timeline.limited)
                    })
                {
                    self.token = None;
                    self.processor.clear();
                }
                SyncLoopStep::Updates(Box::new(updates))
            }
            Err(Error::Protocol(message))
                if message.starts_with("station_cas revision regressed")
                    || message.starts_with("station_cas revision conflict") =>
            {
                self.reset();
                SyncLoopStep::Retry {
                    retry_after: Duration::ZERO,
                    error: format!("{message}; restarting initial sync"),
                }
            }
            Err(error) => SyncLoopStep::Failed {
                error: error.to_string(),
            },
        }
    }

    /// React to a transport error, routing structured account-stream
    /// interrupts (client-sync.md §2.2) to their recovery paths.
    fn handle_transport_error(&mut self, error: Error) -> SyncLoopStep {
        if error.is_invalid_cursor() {
            // Continuation cursors are opaque and cannot be repaired locally.
            // Clear the in-memory position before returning so the owning
            // runner checkpoints `None` and the next request is an initial
            // catch-up instead of replaying the rejected cursor forever.
            self.reset();
            return SyncLoopStep::Retry {
                retry_after: Duration::ZERO,
                error: error.to_string(),
            };
        }
        if let Error::Api { error, .. } = &error
            && matches!(
                error.code(),
                "grant_already_consumed"
                    | "session_logged_out"
                    | "auth_expired"
                    | "unauthenticated"
                    | "audience_mismatch"
            )
        {
            return SyncLoopStep::Unauthorized {
                reason: Some(error.code().to_owned()),
            };
        }
        if matches!(&error, Error::Api { status: 401, .. }) {
            return SyncLoopStep::Unauthorized { reason: None };
        }
        let retryable_http = matches!(&error, Error::Http(_));
        let retryable_api = matches!(
            &error,
            Error::Api { status: 429, .. }
                | Error::Api { status: 408, .. }
                | Error::Api {
                    status: 500..=u16::MAX,
                    ..
                }
        );
        if retryable_http || retryable_api {
            let retry_after = self.backoff.record_failure();
            return SyncLoopStep::Retry {
                retry_after,
                error: error.to_string(),
            };
        }
        match error {
            Error::AccountStreamInterrupt(interrupt) => self.handle_interrupt(interrupt),
            error => SyncLoopStep::Failed {
                error: error.to_string(),
            },
        }
    }

    /// Apply the spec-mandated recovery for a control interrupt. A
    /// server-directed `reconnect_after_ms` is authoritative and is
    /// returned verbatim as the retry delay (client-sync.md §2.2.6: MUST
    /// prefer the server instruction); without one, reconnection may be
    /// immediate to shrink the inconsistency window.
    fn handle_interrupt(&mut self, interrupt: AccountStreamInterrupt) -> SyncLoopStep {
        match interrupt {
            AccountStreamInterrupt::Dropped {
                cursor,
                reconnect_after_ms,
            } => {
                // §2.2.3: reconnect from the required frame cursor with
                // catchup so the server replays the lost account delta.
                self.token = Some(cursor);
                SyncLoopStep::Retry {
                    retry_after: Duration::from_millis(reconnect_after_ms.unwrap_or(0)),
                    error: "account stream dropped; reconnecting with catch-up cursor".to_owned(),
                }
            }
            AccountStreamInterrupt::ResyncRequired { reconnect_after_ms } => {
                // §2.2.4: clear the cursor cache and redo initial sync.
                self.token = None;
                SyncLoopStep::Retry {
                    retry_after: Duration::from_millis(reconnect_after_ms.unwrap_or(0)),
                    error: "account stream requires resync; restarting initial sync".to_owned(),
                }
            }
            AccountStreamInterrupt::Unauthorized => SyncLoopStep::Unauthorized { reason: None },
        }
    }

    /// Execute one loop iteration.
    ///
    /// The caller owns sleeping and cancellation. This keeps the type portable
    /// across native and WASM runtimes.
    pub fn step<T>(&mut self, transport: &mut T) -> SyncLoopStep
    where
        T: SyncTransport,
    {
        let request = self.next_request();
        let options = self.next_request_options();
        match transport.sync(request, options) {
            Ok(response) => self.handle_response(response),
            Err(error) => self.handle_transport_error(error),
        }
    }

    /// Execute one async loop iteration with default controls.
    pub async fn step_async<T>(&mut self, transport: &T) -> SyncLoopStep
    where
        T: AsyncSyncTransport + ?Sized,
    {
        let control = SyncLoopControl::default();
        self.step_async_with_control(transport, &control).await
    }

    /// Execute one async loop iteration with cancellation and backpressure.
    pub async fn step_async_with_control<T>(
        &mut self,
        transport: &T,
        control: &SyncLoopControl,
    ) -> SyncLoopStep
    where
        T: AsyncSyncTransport + ?Sized,
    {
        if control.is_cancelled() {
            return SyncLoopStep::Cancelled;
        }
        let Some(_permit) = control.try_acquire() else {
            return SyncLoopStep::Backpressure {
                retry_after: control.backpressure_retry_after(),
            };
        };
        let request = self.next_request();
        let options = self.next_request_options();
        match transport.sync_async(request, options).await {
            Ok(response) => self.handle_response(response),
            Err(error) => self.handle_transport_error(error),
        }
    }

    /// Current sync token.
    pub fn token(&self) -> Option<&str> {
        self.token.as_deref()
    }

    /// Pending recovery actions accumulated from processed sync responses.
    pub fn recovery_actions(&self) -> Vec<SyncRecoveryAction> {
        self.processor.recovery_actions()
    }

    /// Drain pending recovery actions after the application schedules them.
    pub fn take_recovery_actions(&mut self) -> Vec<SyncRecoveryAction> {
        self.processor.take_recovery_actions()
    }

    /// Export durable sync loop state.
    pub fn snapshot(&self) -> SyncLoopSnapshot {
        SyncLoopSnapshot {
            token: self.token.clone(),
            timeout_ms: self.timeout.as_millis().min(u128::from(u64::MAX)) as u64,
            gap_strategy: self.gap_strategy,
        }
    }

    /// Reset the loop after unrecoverable state loss.
    pub fn reset(&mut self) {
        self.token = None;
        self.backoff.reset();
        self.processor.clear();
    }
}

impl Default for SyncLoop {
    fn default() -> Self {
        Self::new()
    }
}
