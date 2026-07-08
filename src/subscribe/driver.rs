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
        loop {
            match sync_loop
                .step_async_with_control(transport, &self.control)
                .await
            {
                SyncLoopStep::Updates(updates) => {
                    emit_account_updates(sink, updates);
                }
                SyncLoopStep::Retry { retry_after, .. }
                | SyncLoopStep::Backpressure { retry_after } => {
                    self.executor.sleep(retry_after).await;
                }
                SyncLoopStep::Cancelled => return SubscriptionStopReason::Cancelled,
                SyncLoopStep::Unauthorized { reason } => {
                    return SubscriptionStopReason::Unauthorized { reason };
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, VecDeque};
    use std::future::Future;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use cokret::{Error, Result, SyncOutcome, SyncRequestBody};
    use serde_json::Value;

    use super::*;
    use crate::ClientEvent;

    #[derive(Clone, Debug, Default)]
    struct RecordingExecutor {
        sleeps: Arc<Mutex<Vec<Duration>>>,
    }

    impl RecordingExecutor {
        fn sleeps(&self) -> Vec<Duration> {
            self.sleeps.lock().unwrap().clone()
        }
    }

    impl Executor for RecordingExecutor {
        type JoinHandle = ();

        #[cfg(not(target_arch = "wasm32"))]
        fn spawn<F>(&self, _fut: F) -> Self::JoinHandle
        where
            F: Future<Output = ()> + Send + 'static,
        {
        }

        #[cfg(target_arch = "wasm32")]
        fn spawn<F>(&self, _fut: F) -> Self::JoinHandle
        where
            F: Future<Output = ()> + 'static,
        {
        }

        fn sleep(&self, dur: Duration) -> impl Future<Output = ()> + '_ {
            async move {
                self.sleeps.lock().unwrap().push(dur);
            }
        }
    }

    fn sync_response(cursor: &str) -> SyncOutcome {
        SyncOutcome {
            cursor: cursor.to_owned(),
            realms: BTreeMap::new(),
            left_realms: Vec::new(),
            to_device: Vec::new(),
            to_device_ack_token: None,
            to_device_limited: false,
            to_device_next_cursor: None,
            to_device_lost: None,
            device_lists: Value::Null,
            account_data: Vec::new(),
            presence: Vec::new(),
            notifications: Value::Null,
            partial: false,
        }
    }

    fn queued_transport(
        responses: Arc<Mutex<VecDeque<Result<SyncOutcome>>>>,
    ) -> impl Fn(SyncRequestBody) -> std::pin::Pin<Box<dyn Future<Output = Result<SyncOutcome>> + Send>>
    {
        move |_request| {
            let responses = Arc::clone(&responses);
            Box::pin(async move {
                responses
                    .lock()
                    .unwrap()
                    .pop_front()
                    .unwrap_or_else(|| Ok(sync_response("fallback")))
            })
        }
    }

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
