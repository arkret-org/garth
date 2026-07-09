use std::convert::Infallible;
use std::future::Future;

use cokret::{AsyncSyncTransport, SyncLoop, SyncLoopControl, SyncLoopStep};

use super::emit_account_updates;
use crate::{ClientEventSink, Executor};

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

    pub async fn run_account<T, S>(
        &self,
        sync_loop: &mut SyncLoop,
        transport: &T,
        sink: &S,
    ) -> SubscriptionStopReason
    where
        T: AsyncSyncTransport + ?Sized,
        S: ClientEventSink + ?Sized,
    {
        // No checkpoint hook: delegate to the shared loop with an infallible
        // no-op so the state-machine handling lives in exactly one place.
        match self
            .run_account_checkpointed(sync_loop, transport, sink, |_token| async {
                Ok::<(), Infallible>(())
            })
            .await
        {
            Ok(reason) => reason,
            Err(never) => match never {},
        }
    }

    /// Shared account sync loop. `checkpoint` is invoked with the current sync
    /// token after each `Updates` and `Retry` step (before emitting/sleeping) so
    /// callers that persist a cursor can hook in without duplicating the
    /// `SyncLoopStep` dispatch; its error type is propagated to the caller. The
    /// token is passed by value so the hook's future may own it (a borrowed
    /// `&str` would run into closure-lending limits).
    pub(crate) async fn run_account_checkpointed<T, S, F, Fut, Er>(
        &self,
        sync_loop: &mut SyncLoop,
        transport: &T,
        sink: &S,
        mut checkpoint: F,
    ) -> Result<SubscriptionStopReason, Er>
    where
        T: AsyncSyncTransport + ?Sized,
        S: ClientEventSink + ?Sized,
        F: FnMut(Option<String>) -> Fut,
        Fut: Future<Output = Result<(), Er>>,
    {
        loop {
            match sync_loop
                .step_async_with_control(transport, &self.control)
                .await
            {
                SyncLoopStep::Updates(updates) => {
                    checkpoint(sync_loop.token().map(str::to_owned)).await?;
                    emit_account_updates(sink, updates);
                }
                SyncLoopStep::Retry { retry_after, .. } => {
                    checkpoint(sync_loop.token().map(str::to_owned)).await?;
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
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    use cokret::Error;

    use super::super::test_support::{RecordingExecutor, queued_transport, sync_response};
    use super::*;
    use crate::ClientEvent;

    #[tokio::test]
    async fn account_driver_emits_updates_until_cancelled() {
        let executor = RecordingExecutor::default();
        let driver = SubscriptionLoopDriver::new(executor);
        let control = driver.control();
        let events = Arc::new(Mutex::new(0usize));
        let sink_events = Arc::clone(&events);
        let sink = move |event: ClientEvent| {
            if matches!(event, ClientEvent::AccountUpdates(_)) {
                *sink_events.lock().unwrap() += 1;
                control.cancel();
            }
        };
        let responses = Arc::new(Mutex::new(VecDeque::from([Ok(sync_response("s1"))])));
        let transport = queued_transport(responses);
        let mut sync_loop = SyncLoop::new();

        let reason = driver.run_account(&mut sync_loop, &transport, &sink).await;

        assert_eq!(reason, SubscriptionStopReason::Cancelled);
        assert_eq!(*events.lock().unwrap(), 1);
        assert_eq!(sync_loop.token(), Some("s1"));
    }

    #[tokio::test]
    async fn account_driver_sleeps_on_retry_before_next_step() {
        let executor = RecordingExecutor::default();
        let driver = SubscriptionLoopDriver::new(executor.clone());
        let control = driver.control();
        let sink = move |event: ClientEvent| {
            if matches!(event, ClientEvent::AccountUpdates(_)) {
                control.cancel();
            }
        };
        let responses = Arc::new(Mutex::new(VecDeque::from([
            Err(Error::Protocol("network down".to_owned())),
            Ok(sync_response("s1")),
        ])));
        let transport = queued_transport(responses);
        let mut sync_loop = SyncLoop::new();

        let reason = driver.run_account(&mut sync_loop, &transport, &sink).await;

        assert_eq!(reason, SubscriptionStopReason::Cancelled);
        assert_eq!(sync_loop.token(), Some("s1"));
        assert_eq!(executor.sleeps().len(), 1);
    }
}
