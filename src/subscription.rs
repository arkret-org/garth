//! Account-aggregate subscription runner.

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use arkret_models_collaboration::sync_frames::account_subscribe::{
    AccountSubscribeBatch, AccountSubscribeSnapshotResult, SyncRequestBody,
};
use arkret_wire::{ActorId, DeviceId, DidCoreId};

use crate::{
    AccountCursorCheckpoint, CursorScope, CursorStore, Executor, MaybeSend, MaybeSendSync, Result,
};

pub trait AccountSubscribeTransport: MaybeSendSync {
    fn subscribe<'a>(
        &'a self,
        request: &'a SyncRequestBody,
    ) -> impl Future<Output = Result<AccountSubscribeSnapshotResult>> + MaybeSend + 'a;
}

impl AccountSubscribeTransport for arkret_http_client::Client {
    async fn subscribe(&self, request: &SyncRequestBody) -> Result<AccountSubscribeSnapshotResult> {
        match self.account_subscribe_batch(request).await {
            Ok(batch) => Ok(AccountSubscribeSnapshotResult::Batch(batch)),
            Err(arkret_http_client::Error::AccountStreamInterrupt(interrupt)) => {
                use arkret_models_collaboration::sync_frames::account_subscribe::AccountStreamInterrupt;
                match interrupt {
                    AccountStreamInterrupt::Dropped {
                        cursor,
                        reconnect_after_ms,
                    } => Ok(AccountSubscribeSnapshotResult::ReconnectAfter {
                        reconnect_after_ms: reconnect_after_ms.unwrap_or(5_000),
                        reconnect_cursor: Some(cursor),
                        reason: None,
                        reset_cursor: false,
                    }),
                    AccountStreamInterrupt::ResyncRequired { reconnect_after_ms } => {
                        Ok(AccountSubscribeSnapshotResult::ReconnectAfter {
                            reconnect_after_ms: reconnect_after_ms.unwrap_or(5_000),
                            reconnect_cursor: None,
                            reason: None,
                            reset_cursor: true,
                        })
                    }
                    AccountStreamInterrupt::Unauthorized => Err(
                        crate::Error::AccountStreamInterrupt(AccountStreamInterrupt::Unauthorized),
                    ),
                }
            }
            Err(error) => Err(error.into()),
        }
    }
}

/// Synchronous-in-order projection lane for a caller-owned executor.
///
/// `AccountSubscription::run` awaits this projection before durably advancing
/// the cursor and never spawns the projector across threads. A native caller
/// that does move the whole runner onto a multithreaded executor must still
/// satisfy that executor's `Send` bound at the spawn site; local UI state may
/// instead remain on its single-thread executor without an unsafe wrapper.
pub trait AccountBatchProjector {
    fn project<'a>(
        &'a self,
        batch: &'a AccountSubscribeBatch,
    ) -> impl Future<Output = Result<()>> + 'a;
}

#[derive(Clone, Debug, Default)]
pub struct SubscriptionControl(Arc<AtomicBool>);

impl SubscriptionControl {
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubscriptionStopReason {
    Cancelled,
}

#[derive(Clone, Debug)]
pub struct AccountSubscription<E, C> {
    executor: E,
    cursors: C,
    control: SubscriptionControl,
}

impl<E, C> AccountSubscription<E, C>
where
    E: Executor,
    C: CursorStore,
{
    pub fn new(executor: E, cursors: C) -> Self {
        Self {
            executor,
            cursors,
            control: SubscriptionControl::default(),
        }
    }

    pub fn control(&self) -> SubscriptionControl {
        self.control.clone()
    }

    pub async fn run<T, P>(
        &self,
        transport: &T,
        projector: &P,
        service_id: Option<DidCoreId>,
        actor_id: ActorId,
        device_id: DeviceId,
        mut request: SyncRequestBody,
    ) -> Result<SubscriptionStopReason>
    where
        T: AccountSubscribeTransport + ?Sized,
        P: AccountBatchProjector + ?Sized,
    {
        request.validate()?;
        let scope = CursorScope::Account {
            service_id,
            actor_id,
            device_id,
        };
        let checkpoint = self.cursors.load_account_checkpoint(scope.clone()).await?;
        let mut station_cas = checkpoint
            .as_ref()
            .map_or_else(crate::StationCasProjection::default, |checkpoint| {
                checkpoint.station_cas.clone()
            });
        request.after = checkpoint.map(|checkpoint| checkpoint.cursor);
        request.catchup = Some(request.after.is_none());

        while !self.control.is_cancelled() {
            match transport.subscribe(&request).await? {
                AccountSubscribeSnapshotResult::Batch(batch) => {
                    let mut next_station_cas = station_cas.clone();
                    if request.after.is_none() {
                        next_station_cas.reset_for_initial_sync();
                    }
                    if let Err(error) = batch
                        .frames
                        .iter()
                        .try_for_each(|frame| next_station_cas.apply_frame(frame).map(|_| ()))
                    {
                        if crate::station_cas_projection::is_revision_integrity_error(&error) {
                            self.cursors.clear(scope.clone()).await?;
                            station_cas.reset_for_initial_sync();
                            request.after = None;
                            request.catchup = Some(true);
                            continue;
                        }
                        return Err(error);
                    }
                    projector.project(&batch).await?;
                    self.cursors
                        .save_account_checkpoint(
                            scope.clone(),
                            AccountCursorCheckpoint {
                                cursor: batch.cursor.clone(),
                                station_cas: next_station_cas.clone(),
                            },
                        )
                        .await?;
                    station_cas = next_station_cas;
                    request.after = Some(batch.cursor);
                    request.catchup = Some(false);
                }
                AccountSubscribeSnapshotResult::ReconnectAfter {
                    reconnect_after_ms,
                    reconnect_cursor,
                    reset_cursor,
                    ..
                } => {
                    if reset_cursor {
                        self.cursors.clear(scope.clone()).await?;
                        station_cas.reset_for_initial_sync();
                        request.after = None;
                        request.catchup = Some(true);
                    } else if let Some(cursor) = reconnect_cursor {
                        self.cursors
                            .save_account_checkpoint(
                                scope.clone(),
                                AccountCursorCheckpoint {
                                    cursor: cursor.clone(),
                                    station_cas: station_cas.clone(),
                                },
                            )
                            .await?;
                        request.after = Some(cursor);
                    }
                    self.executor
                        .sleep(Duration::from_millis(reconnect_after_ms))
                        .await;
                }
            }
        }
        Ok(SubscriptionStopReason::Cancelled)
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::collections::VecDeque;
    use std::rc::Rc;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::Error;

    #[derive(Clone, Debug, Default)]
    struct ImmediateExecutor;

    impl Executor for ImmediateExecutor {
        async fn sleep(&self, _duration: Duration) {}
    }

    #[derive(Debug)]
    struct ScriptedTransport {
        responses: Mutex<VecDeque<AccountSubscribeSnapshotResult>>,
        calls: AtomicUsize,
        cancel_on_call: Option<SubscriptionControl>,
    }

    impl ScriptedTransport {
        fn new(responses: Vec<AccountSubscribeSnapshotResult>) -> Self {
            Self {
                responses: Mutex::new(responses.into()),
                calls: AtomicUsize::new(0),
                cancel_on_call: None,
            }
        }

        fn cancelling(
            responses: Vec<AccountSubscribeSnapshotResult>,
            control: SubscriptionControl,
        ) -> Self {
            Self {
                responses: Mutex::new(responses.into()),
                calls: AtomicUsize::new(0),
                cancel_on_call: Some(control),
            }
        }
    }

    impl AccountSubscribeTransport for ScriptedTransport {
        async fn subscribe(
            &self,
            _request: &SyncRequestBody,
        ) -> Result<AccountSubscribeSnapshotResult> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if let Some(control) = &self.cancel_on_call {
                control.cancel();
            }
            self.responses
                .lock()
                .unwrap()
                .pop_front()
                .ok_or_else(|| Error::Protocol("subscription test script exhausted".to_owned()))
        }
    }

    #[derive(Debug)]
    struct Projector {
        calls: AtomicUsize,
        control: Option<SubscriptionControl>,
        fail: bool,
    }

    impl Projector {
        fn new(control: Option<SubscriptionControl>, fail: bool) -> Self {
            Self {
                calls: AtomicUsize::new(0),
                control,
                fail,
            }
        }
    }

    impl AccountBatchProjector for Projector {
        async fn project(&self, _batch: &AccountSubscribeBatch) -> Result<()> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if let Some(control) = &self.control {
                control.cancel();
            }
            if self.fail {
                Err(Error::Protocol("projection failed".to_owned()))
            } else {
                Ok(())
            }
        }
    }

    struct LocalProjector {
        calls: Rc<Cell<usize>>,
        control: SubscriptionControl,
    }

    impl AccountBatchProjector for LocalProjector {
        async fn project(&self, _batch: &AccountSubscribeBatch) -> Result<()> {
            self.calls.set(self.calls.get() + 1);
            self.control.cancel();
            Ok(())
        }
    }

    fn actor_id() -> ActorId {
        ActorId::service(DidCoreId::new("ak:did_core:web:alice.example").unwrap())
    }

    fn device_id() -> DeviceId {
        DeviceId::new("ak:device:0196419b-0000-7000-8000-000000000001").unwrap()
    }

    fn scope() -> CursorScope {
        CursorScope::Account {
            service_id: None,
            actor_id: actor_id(),
            device_id: device_id(),
        }
    }

    #[tokio::test]
    async fn cancellation_before_start_performs_no_network_call() {
        let subscription = AccountSubscription::new(ImmediateExecutor, crate::MemoryStore::new());
        subscription.control().cancel();
        let transport = ScriptedTransport::new(Vec::new());
        let projector = Projector::new(None, false);
        let reason = subscription
            .run(
                &transport,
                &projector,
                None,
                actor_id(),
                device_id(),
                SyncRequestBody::default(),
            )
            .await
            .unwrap();
        assert_eq!(reason, SubscriptionStopReason::Cancelled);
        assert_eq!(transport.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn reset_reconnect_clears_the_durable_cursor() {
        let store = crate::MemoryStore::new();
        store
            .save(scope(), "ak:cursor:old".to_owned())
            .await
            .unwrap();
        let subscription = AccountSubscription::new(ImmediateExecutor, store.clone());
        let transport = ScriptedTransport::cancelling(
            vec![AccountSubscribeSnapshotResult::ReconnectAfter {
                reconnect_after_ms: 1,
                reconnect_cursor: None,
                reason: Some("snapshot changed".to_owned()),
                reset_cursor: true,
            }],
            subscription.control(),
        );
        subscription
            .run(
                &transport,
                &Projector::new(None, false),
                None,
                actor_id(),
                device_id(),
                SyncRequestBody::default(),
            )
            .await
            .unwrap();
        assert!(store.load(scope()).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn reconnect_cursor_is_checkpointed_before_retry() {
        let store = crate::MemoryStore::new();
        let subscription = AccountSubscription::new(ImmediateExecutor, store.clone());
        let transport = ScriptedTransport::cancelling(
            vec![AccountSubscribeSnapshotResult::ReconnectAfter {
                reconnect_after_ms: 1,
                reconnect_cursor: Some("ak:cursor:resume".to_owned()),
                reason: None,
                reset_cursor: false,
            }],
            subscription.control(),
        );
        subscription
            .run(
                &transport,
                &Projector::new(None, false),
                None,
                actor_id(),
                device_id(),
                SyncRequestBody::default(),
            )
            .await
            .unwrap();
        assert_eq!(
            store.load(scope()).await.unwrap().as_deref(),
            Some("ak:cursor:resume")
        );
    }

    #[tokio::test]
    async fn successful_projection_is_checkpointed_then_cancelled() {
        let store = crate::MemoryStore::new();
        let subscription = AccountSubscription::new(ImmediateExecutor, store.clone());
        let projector = Projector::new(Some(subscription.control()), false);
        let transport = ScriptedTransport::new(vec![AccountSubscribeSnapshotResult::Batch(
            AccountSubscribeBatch {
                frames: Vec::new(),
                cursor: "ak:cursor:next".to_owned(),
            },
        )]);
        subscription
            .run(
                &transport,
                &projector,
                None,
                actor_id(),
                device_id(),
                SyncRequestBody::default(),
            )
            .await
            .unwrap();
        assert_eq!(
            store.load(scope()).await.unwrap().as_deref(),
            Some("ak:cursor:next")
        );
    }

    #[tokio::test]
    async fn local_non_send_projector_is_checkpointed_after_projection() {
        let store = crate::MemoryStore::new();
        let subscription = AccountSubscription::new(ImmediateExecutor, store.clone());
        let calls = Rc::new(Cell::new(0));
        let projector = LocalProjector {
            calls: calls.clone(),
            control: subscription.control(),
        };
        let transport = ScriptedTransport::new(vec![AccountSubscribeSnapshotResult::Batch(
            AccountSubscribeBatch {
                frames: Vec::new(),
                cursor: "ak:cursor:local".to_owned(),
            },
        )]);
        subscription
            .run(
                &transport,
                &projector,
                None,
                actor_id(),
                device_id(),
                SyncRequestBody::default(),
            )
            .await
            .unwrap();
        assert_eq!(calls.get(), 1);
        assert_eq!(store.load(scope()).await.unwrap().as_deref(), Some("ak:cursor:local"));
    }

    #[tokio::test]
    async fn failed_projection_never_advances_the_cursor() {
        let store = crate::MemoryStore::new();
        store
            .save(scope(), "ak:cursor:old".to_owned())
            .await
            .unwrap();
        let subscription = AccountSubscription::new(ImmediateExecutor, store.clone());
        let transport = ScriptedTransport::new(vec![AccountSubscribeSnapshotResult::Batch(
            AccountSubscribeBatch {
                frames: Vec::new(),
                cursor: "ak:cursor:next".to_owned(),
            },
        )]);
        assert!(
            subscription
                .run(
                    &transport,
                    &Projector::new(None, true),
                    None,
                    actor_id(),
                    device_id(),
                    SyncRequestBody::default(),
                )
                .await
                .is_err()
        );
        assert_eq!(
            store.load(scope()).await.unwrap().as_deref(),
            Some("ak:cursor:old")
        );
    }
}
