use std::future::Future;

use super::account::account_updates_to_events_with_origin;
use super::{ProjectedRunError, ProjectedRunResult, account_updates_to_events};
use crate::protocol::Result;
use crate::sync_client::{AsyncSyncTransport, SyncLoop, SyncLoopControl, SyncLoopStep};
use crate::{ClientProjector, CursorScope, DurableInboxStore, Executor};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SubscriptionStopReason {
    Cancelled,
    Unauthorized { reason: Option<String> },
}

#[derive(Clone, Debug)]
pub struct SubscriptionLoopDriver<E> {
    executor: E,
    control: SyncLoopControl,
}

impl<E> SubscriptionLoopDriver<E>
where
    E: Executor,
{
    pub fn new(executor: E) -> Self {
        Self {
            executor,
            control: SyncLoopControl::new(),
        }
    }

    pub fn with_control(executor: E, control: SyncLoopControl) -> Self {
        Self { executor, control }
    }

    pub fn control(&self) -> SyncLoopControl {
        self.control.clone()
    }

    pub fn cancel(&self) {
        self.control.cancel();
    }

    pub async fn run_account<T, P>(
        &self,
        sync_loop: &mut SyncLoop,
        transport: &T,
        projector: &P,
    ) -> Result<SubscriptionStopReason>
    where
        T: AsyncSyncTransport + ?Sized,
        P: ClientProjector + ?Sized,
    {
        self.run_account_checkpointed(sync_loop, transport, projector, |_token| async { Ok(()) })
            .await
            .map_err(ProjectedRunError::into_error)
    }

    /// Run account sync with crash-safe non-blocking delivery. Each update
    /// batch and its cursor are committed atomically to `inbox`; a separate
    /// worker may process and acknowledge pending deliveries without blocking
    /// the subscription loop.
    pub async fn run_account_to_inbox<T, S>(
        &self,
        sync_loop: &mut SyncLoop,
        transport: &T,
        scope: CursorScope,
        inbox: &S,
    ) -> Result<SubscriptionStopReason>
    where
        T: AsyncSyncTransport + ?Sized,
        S: DurableInboxStore,
    {
        loop {
            let initial_catchup = sync_loop.token().is_none();
            match sync_loop
                .step_async_with_control(transport, &self.control)
                .await
            {
                SyncLoopStep::Updates(updates) => {
                    inbox
                        .commit(
                            scope.clone(),
                            sync_loop.token().map(str::to_owned),
                            account_updates_to_events_with_origin(*updates, initial_catchup),
                        )
                        .await?;
                }
                SyncLoopStep::Retry { retry_after, .. } => {
                    inbox
                        .commit(
                            scope.clone(),
                            sync_loop.token().map(str::to_owned),
                            Vec::new(),
                        )
                        .await?;
                    if crate::executor::wait_cancellable(&self.executor, retry_after, || {
                        self.control.is_cancelled()
                    })
                    .await
                    {
                        return Ok(SubscriptionStopReason::Cancelled);
                    }
                }
                SyncLoopStep::Failed { error } => {
                    return Err(crate::protocol::Error::Protocol(error));
                }
                SyncLoopStep::Backpressure { retry_after } => {
                    if crate::executor::wait_cancellable(&self.executor, retry_after, || {
                        self.control.is_cancelled()
                    })
                    .await
                    {
                        return Ok(SubscriptionStopReason::Cancelled);
                    }
                }
                SyncLoopStep::Cancelled => return Ok(SubscriptionStopReason::Cancelled),
                SyncLoopStep::Unauthorized { reason } => {
                    return Ok(SubscriptionStopReason::Unauthorized { reason });
                }
            }
        }
    }

    /// Shared account sync loop. `checkpoint` is invoked with the current sync
    /// token after each projected `Updates` batch and after each `Retry` step,
    /// so callers that persist a cursor can hook in without duplicating the
    /// `SyncLoopStep` dispatch. The token is passed by value so the hook's
    /// future may own it (a borrowed `&str` would run into closure-lending
    /// limits).
    pub(crate) async fn run_account_checkpointed<T, P, F, Fut>(
        &self,
        sync_loop: &mut SyncLoop,
        transport: &T,
        projector: &P,
        mut checkpoint: F,
    ) -> ProjectedRunResult<SubscriptionStopReason>
    where
        T: AsyncSyncTransport + ?Sized,
        P: ClientProjector + ?Sized,
        F: FnMut(Option<String>) -> Fut,
        Fut: Future<Output = Result<()>>,
    {
        loop {
            match sync_loop
                .step_async_with_control(transport, &self.control)
                .await
            {
                SyncLoopStep::Updates(updates) => {
                    let batch = account_updates_to_events(*updates);
                    if !batch.is_empty() {
                        projector
                            .project(batch)
                            .await
                            .map_err(ProjectedRunError::Projector)?;
                    }
                    checkpoint(sync_loop.token().map(str::to_owned))
                        .await
                        .map_err(ProjectedRunError::Store)?;
                }
                SyncLoopStep::Retry { retry_after, .. } => {
                    checkpoint(sync_loop.token().map(str::to_owned))
                        .await
                        .map_err(ProjectedRunError::Store)?;
                    if crate::executor::wait_cancellable(&self.executor, retry_after, || {
                        self.control.is_cancelled()
                    })
                    .await
                    {
                        return Ok(SubscriptionStopReason::Cancelled);
                    }
                }
                SyncLoopStep::Failed { error } => {
                    return Err(ProjectedRunError::Transport(
                        crate::protocol::Error::Protocol(error),
                    ));
                }
                SyncLoopStep::Backpressure { retry_after } => {
                    if crate::executor::wait_cancellable(&self.executor, retry_after, || {
                        self.control.is_cancelled()
                    })
                    .await
                    {
                        return Ok(SubscriptionStopReason::Cancelled);
                    }
                }
                SyncLoopStep::Cancelled => return Ok(SubscriptionStopReason::Cancelled),
                SyncLoopStep::Unauthorized { reason } => {
                    return Ok(SubscriptionStopReason::Unauthorized { reason });
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use super::super::test_support::{RecordingExecutor, queued_transport, sync_response};
    use super::*;
    use crate::ClientEvent;
    use crate::protocol::{Error, Problem};

    struct CountingProjector {
        events: Arc<Mutex<usize>>,
        control: SyncLoopControl,
    }

    impl ClientProjector for CountingProjector {
        fn project(
            &self,
            batch: Vec<ClientEvent>,
        ) -> impl Future<Output = crate::protocol::Result<()>> + '_ {
            let events = Arc::clone(&self.events);
            let control = self.control.clone();
            async move {
                for event in batch {
                    if matches!(event, ClientEvent::AccountUpdates(_)) {
                        *events.lock().unwrap() += 1;
                        control.cancel();
                    }
                }
                Ok(())
            }
        }
    }

    #[tokio::test]
    async fn account_driver_emits_updates_until_cancelled() {
        let executor = RecordingExecutor::default();
        let driver = SubscriptionLoopDriver::new(executor);
        let control = driver.control();
        let events = Arc::new(Mutex::new(0usize));
        let projector = CountingProjector {
            events: Arc::clone(&events),
            control,
        };
        let responses = Arc::new(Mutex::new(VecDeque::from([Ok(sync_response(
            "ak:cursor:czE",
        ))])));
        let transport = queued_transport(responses);
        let mut sync_loop = SyncLoop::new();

        let reason = driver
            .run_account(&mut sync_loop, &transport, &projector)
            .await
            .unwrap();

        assert_eq!(reason, SubscriptionStopReason::Cancelled);
        assert_eq!(*events.lock().unwrap(), 1);
        assert_eq!(sync_loop.token(), Some("ak:cursor:czE"));
    }

    #[tokio::test]
    async fn account_driver_sleeps_on_retry_before_next_step() {
        let executor = RecordingExecutor::default();
        let driver = SubscriptionLoopDriver::new(executor.clone());
        let control = driver.control();
        let projector = CountingProjector {
            events: Arc::new(Mutex::new(0)),
            control,
        };
        let responses = Arc::new(Mutex::new(VecDeque::from([
            Err(Error::Api {
                status: 503,
                error: Box::new(Problem::from_code("service_unavailable", "network down")),
            }),
            Ok(sync_response("ak:cursor:czE")),
        ])));
        let transport = queued_transport(responses);
        let mut sync_loop = SyncLoop::new();

        let reason = driver
            .run_account(&mut sync_loop, &transport, &projector)
            .await
            .unwrap();

        assert_eq!(reason, SubscriptionStopReason::Cancelled);
        assert_eq!(sync_loop.token(), Some("ak:cursor:czE"));
        let sleeps = executor.sleeps();
        assert!(sleeps.len() > 1);
        assert!(
            sleeps
                .iter()
                .all(|duration| *duration <= Duration::from_millis(50))
        );
    }

    #[tokio::test]
    async fn account_driver_stops_after_non_retryable_protocol_error() {
        let driver = SubscriptionLoopDriver::new(RecordingExecutor::default());
        let projector = CountingProjector {
            events: Arc::new(Mutex::new(0)),
            control: driver.control(),
        };
        let responses = Arc::new(Mutex::new(VecDeque::from([Err(Error::Protocol(
            "malformed account frame".to_owned(),
        ))])));
        let transport = queued_transport(responses);
        let mut sync_loop = SyncLoop::new();

        let error = driver
            .run_account(&mut sync_loop, &transport, &projector)
            .await
            .unwrap_err();

        assert!(
            matches!(error, Error::Protocol(message) if message.contains("malformed account frame"))
        );
    }
}
