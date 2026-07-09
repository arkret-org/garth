//! Batteries-included run loops on [`CokretClient`].
//!
//! These own the OUTER resilience loop that consumers previously hand-rolled:
//! (re)acquire a transport, run the projector-driven engine, auto-resume with
//! backoff on recoverable stops (realm `StreamEnded` / `Dropped` /
//! `ResyncRequired`), and stop on cancellation or `Unauthorized`. Cursor,
//! dedupe, drop/scan-backfill and the emit/await-then-checkpoint gate live in
//! the engines; the projector is the only host seam.
//!
//! Refresh coordination: on `Unauthorized` the runner returns
//! [`RunStop::Unauthorized`] so the host can refresh (or require sign-in) and
//! re-invoke. Because the transport is obtained through [`TransportProvider`]
//! on every (re)start, a provider that refreshes credentials on `provide`
//! transparently recovers across restarts without the runner owning SDK auth.

use std::time::Duration;

use cokret::{AsyncSyncTransport, SyncLoopControl};
use cokret_core::{DeviceId, Did, RealmId, Result};

use crate::subscribe::{
    EventsScanTransport, RealmEventsTransport, RealmStreamStopReason, SubscriptionStopReason,
};
use crate::{
    ClientProjector, CokretClient, CursorStore, EventCacheStore, Executor, SecureKeyStore,
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
pub enum RunStop {
    /// The engine's cancellation control was tripped (`SubscriptionEngine::cancel`).
    Cancelled,
    /// The session grant is no longer accepted; host should refresh / sign in.
    Unauthorized { reason: Option<String> },
}

impl<E, C, D, K> CokretClient<E, C, D, K>
where
    E: Executor + Clone,
    C: CursorStore,
    D: EventCacheStore,
    K: SecureKeyStore,
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
    ) -> Result<RunStop>
    where
        TP: TransportProvider,
        TP::Transport: RealmEventsTransport + EventsScanTransport,
        P: ClientProjector + ?Sized,
    {
        let engine = self.subscription_engine().with_control(control.clone());
        let mut backoff = options.min_backoff;
        loop {
            if control.is_cancelled() {
                return Ok(RunStop::Cancelled);
            }
            let transport = provider.provide().await?;
            match engine
                .run_realm_projected(&transport, realm_id.clone(), projector)
                .await?
            {
                RealmStreamStopReason::StreamEnded => {
                    backoff = options.min_backoff;
                    self.executor.sleep(options.beat).await;
                }
                RealmStreamStopReason::Dropped {
                    reconnect_after_ms, ..
                }
                | RealmStreamStopReason::ResyncRequired { reconnect_after_ms } => {
                    // The engine already honored a server-provided
                    // `reconnect_after_ms` before returning; only apply the
                    // local backoff when the server gave no hint.
                    if reconnect_after_ms.is_none() {
                        self.executor.sleep(backoff).await;
                    }
                    backoff = backoff.saturating_mul(2).min(options.max_backoff);
                }
                RealmStreamStopReason::Unauthorized { reason } => {
                    return Ok(RunStop::Unauthorized { reason });
                }
            }
        }
    }

    /// Resilient account run loop. The inner `run_account_projected` already
    /// owns retry/backpressure via the SDK sync loop, so this wrapper maps its
    /// terminal stop to [`RunStop`]; on `Unauthorized` the host refreshes and
    /// re-invokes (the provider re-acquires a fresh-credential transport).
    pub async fn run_account<TP, P>(
        &self,
        actor_id: Did,
        device_id: DeviceId,
        provider: &TP,
        projector: &P,
        control: &SyncLoopControl,
    ) -> Result<RunStop>
    where
        TP: TransportProvider,
        TP::Transport: AsyncSyncTransport,
        P: ClientProjector + ?Sized,
    {
        let engine = self.subscription_engine().with_control(control.clone());
        if control.is_cancelled() {
            return Ok(RunStop::Cancelled);
        }
        let transport = provider.provide().await?;
        match engine
            .run_account_projected(actor_id, device_id, &transport, projector)
            .await?
        {
            SubscriptionStopReason::Cancelled => Ok(RunStop::Cancelled),
            SubscriptionStopReason::Unauthorized { reason } => Ok(RunStop::Unauthorized { reason }),
        }
    }
}

#[cfg(all(test, feature = "native"))]
mod tests {
    use std::sync::{Arc, Mutex};

    use cokret_core::RealmId;

    use super::*;
    use crate::{ClientEvent, MemorySecureKeyStore, MemoryStore, NativeExecutor};

    fn test_client() -> CokretClient<NativeExecutor, MemoryStore, MemoryStore, MemorySecureKeyStore>
    {
        // The http client is only used by `session_engine()`, which the realm
        // run loop never calls; a placeholder base URL is fine.
        let http = cokret_http_client::Client::new(url::Url::parse("https://localhost/").unwrap())
            .unwrap();
        let store = MemoryStore::new();
        CokretClient::new(
            http,
            NativeExecutor,
            store.clone(),
            store,
            MemorySecureKeyStore::new(),
        )
    }

    struct ClientProvider(cokret_http_client::Client);

    impl TransportProvider for ClientProvider {
        type Transport = cokret_http_client::Client;

        fn provide(&self) -> impl std::future::Future<Output = Result<Self::Transport>> + '_ {
            let client = self.0.clone();
            async move { Ok(client) }
        }
    }

    struct CountingProjector {
        calls: Arc<Mutex<usize>>,
    }

    impl ClientProjector for CountingProjector {
        fn project(
            &self,
            _batch: Vec<ClientEvent>,
        ) -> impl std::future::Future<Output = Result<()>> + '_ {
            let calls = Arc::clone(&self.calls);
            async move {
                *calls.lock().unwrap() += 1;
                Ok(())
            }
        }
    }

    fn realm_id() -> RealmId {
        RealmId::new("ck:realm:01904100-0000-7000-8000-000000000001").unwrap()
    }

    #[tokio::test]
    async fn run_realm_stops_immediately_when_control_pre_cancelled() {
        let client = test_client();
        let provider = ClientProvider(
            cokret_http_client::Client::new(url::Url::parse("https://localhost/").unwrap())
                .unwrap(),
        );
        let calls = Arc::new(Mutex::new(0usize));
        let projector = CountingProjector {
            calls: Arc::clone(&calls),
        };
        let control = SyncLoopControl::new();
        control.cancel();

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

        assert_eq!(stop, RunStop::Cancelled);
        // Pre-cancel short-circuits before any transport/projection work.
        assert_eq!(*calls.lock().unwrap(), 0);
    }
}
