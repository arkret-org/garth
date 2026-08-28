use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::protocol::{AccountStreamInterrupt, AccountSubscribeBatch, Error, SyncRequestBody};
use crate::protocol::{
    ErrorEnvelope, EventKind, EventsQueryOutcome, EventsSubscribeFrame, Hlc, NotificationDelta,
    NotificationDeltaAction, NotificationId, RealmId,
};
use serde_json::json;

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
        _options: arkret_http_client::ClientRequestOptions,
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

fn actor_id() -> DidCoreId {
    DidCoreId::new("ak:did_core:webvh:z6mkfixture:alice.example").unwrap()
}

fn event_actor_id() -> crate::protocol::DidCoreId {
    actor_id()
}

fn device_id() -> DeviceId {
    DeviceId::new("ak:device:01904100-0000-7000-8000-000000000001").unwrap()
}

fn realm_id() -> RealmId {
    RealmId::new("ak:realm:AfF-hFqRoMbajXkPapH-xaq0xwK-UKt2ph2zTs9JZRAO").unwrap()
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
    let realm_b = RealmId::new("ak:realm:AT0jIIg6naB0Vkqbb-ip6eunf-bHr5-nh4pz2_kYNyVX").unwrap();
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

fn dropped_frame(reconnect_after_ms: Option<u64>) -> EventsSubscribeFrame {
    EventsSubscribeFrame::Dropped {
        realm_id: realm_id(),
        cursor: crate::protocol::identifiers::Cursor::new("ak:cursor:dropped").unwrap(),
        reconnect_after_ms,
    }
}

fn unauthorized_frame(_reason: &str) -> EventsSubscribeFrame {
    EventsSubscribeFrame::Unauthorized {
        realm_id: Some(realm_id()),
    }
}

fn accepted_event() -> arkret_wire::Event {
    let mut event = arkret_wire::test_support::raw_event(
        EventKind::MessageCreate.as_str(),
        crate::protocol::ScopeRef::Realm {
            realm_id: realm_id(),
        },
        event_actor_id(),
        crate::protocol::DidCoreId::new("ak:did_core:web:principal.example").unwrap(),
        1,
        Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
        json!({
            "content": {"kind": "ak.content.text", "body": "hello"},
            "strand_id": arkret_wire::StrandId::from_event_id(
                &arkret_wire::EventId::from_digest(
                    arkret_canonical::DigestSuite::Sha256,
                    [2; 32],
                ),
            ),
            "track_name": "discussion"
        }),
    )
    .unwrap();
    let event_digest = arkret_wire::Hash::new(
        event
            .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
            .unwrap(),
    )
    .unwrap();
    let producer = arkret_wire::ProducerEventProof {
        kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
        verification_method: arkret_wire::DidUrl::new(
            "did:webvh:z6mkfixture:alice.example#device-1",
        )
        .unwrap(),
        event_digest: event_digest.clone(),
        signer_resolution_evidence_ref: None,
        signer_resolution_evidence_digest: None,
        created_at: event.created_at,
        domain: None,
        audience: None,
        proof_purpose: None,
        jws: "header..producer".to_owned(),
    };
    let admission = arkret_wire::PrincipalServerAdmissionProof {
        kind: arkret_wire::PrincipalServerAdmissionProofKind::PrincipalServerAdmission,
        verification_method: arkret_wire::DidUrl::new("did:web:principal.example#admission-1")
            .unwrap(),
        event_digest,
        producer_proof_digest: arkret_wire::PrincipalServerAdmissionProof::producer_proof_digest(
            &producer,
        )
        .unwrap(),
        producer_verification_method: producer.verification_method.clone(),
        producer_signing_key: arkret_wire::DidKey::new("did:key:z6MkhFixtureDeviceKey").unwrap(),
        producer_signer_resolution_evidence_ref: None,
        producer_signer_resolution_evidence_digest: None,
        signer_resolution_evidence_ref: arkret_wire::SignerEvidenceRef::new(format!(
            "ak:signer_evidence:sha256:{}",
            "11".repeat(32)
        ))
        .unwrap(),
        signer_resolution_evidence_digest: arkret_wire::Hash::new(format!(
            "sha256:{}",
            "11".repeat(32)
        ))
        .unwrap(),
        accepted_at: event.created_at,
        jws: "header..admission".to_owned(),
    };
    event.proofs = vec![producer.into(), admission.into()];
    event
}

fn event_frame() -> EventsSubscribeFrame {
    let event = accepted_event();
    EventsSubscribeFrame::Event {
        realm_id: realm_id(),
        cursor: crate::protocol::identifiers::Cursor::new("ak:cursor:event-frame").unwrap(),
        payload: Box::new(event),
    }
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
            arkret_canonical::DigestSuite::Sha256,
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
async fn run_realm_to_inbox_stops_before_transport_when_pre_cancelled() {
    let store = MemoryStore::new();
    let client = test_client(RecordingExecutor::default(), store.clone());
    let provider = QueueProvider::<TestRealmTransport>::new(Vec::new());
    let control = SyncLoopControl::new();
    control.cancel();

    let stop = client
        .run_realm_to_inbox(
            &provider,
            realm_id(),
            arkret_canonical::DigestSuite::Sha256,
            &control,
            RunOptions::default(),
        )
        .await
        .unwrap();

    assert_eq!(stop, RunStopReason::Cancelled);
    assert_eq!(provider.calls(), 0);
    assert!(store.pending(10).await.unwrap().is_empty());
}

#[tokio::test]
async fn run_realm_to_inbox_atomically_queues_dropped_backfill_and_cursor() {
    let store = MemoryStore::new();
    let scope = CursorScope::RealmEvents {
        service_id: None,
        realm_id: realm_id(),
    };
    let client = test_client(RecordingExecutor::default(), store.clone());
    let dropped = dropped_frame(None);
    let provider = QueueProvider::new(vec![
        Ok(TestRealmTransport::frames(vec![Ok(dropped)])),
        Ok(TestRealmTransport::frames(vec![Ok(unauthorized_frame(
            "revoked",
        ))])),
    ]);
    let control = SyncLoopControl::new();

    let stop = client
        .run_realm_to_inbox(
            &provider,
            realm_id(),
            arkret_canonical::DigestSuite::Sha256,
            &control,
            options(),
        )
        .await
        .unwrap();

    assert_eq!(
        stop,
        RunStopReason::Unauthorized {
            reason: Some("revoked".to_owned())
        }
    );
    assert_eq!(
        store.load(scope).await.unwrap().as_deref(),
        Some("ak:cursor:dropped")
    );
    let pending = store.pending(10).await.unwrap();
    assert_eq!(pending.len(), 1);
    assert!(matches!(
        pending[0].events.as_slice(),
        [ClientEvent::Backfill { realm_id: queued_realm, .. }]
            if queued_realm == &realm_id()
    ));
    assert!(provider.events().contains(&RunEvent::DeliveryPending));
}

#[tokio::test]
async fn run_realm_to_inbox_replaces_expired_cursor_with_durable_baseline() {
    let store = MemoryStore::new();
    let realm_scope = CursorScope::RealmEvents {
        service_id: None,
        realm_id: realm_id(),
    };
    store
        .save(realm_scope.clone(), "ak:cursor:expired-stream".to_owned())
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

    let stop = client
        .run_realm_to_inbox(
            &provider,
            realm_id(),
            arkret_canonical::DigestSuite::Sha256,
            &SyncLoopControl::new(),
            options(),
        )
        .await
        .unwrap();

    assert_eq!(
        stop,
        RunStopReason::Unauthorized {
            reason: Some("revoked".to_owned())
        }
    );
    assert!(store.load(realm_scope).await.unwrap().is_none());
    let pending = store.pending(10).await.unwrap();
    assert_eq!(pending.len(), 1);
    assert!(matches!(
        pending[0].events.as_slice(),
        [ClientEvent::Backfill { realm_id: queued_realm, .. }]
            if queued_realm == &realm_id()
    ));
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
        .run_realm(
            &provider,
            realm_id(),
            arkret_canonical::DigestSuite::Sha256,
            &projector,
            &control,
            options(),
        )
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
        .run_realm(
            &provider,
            realm_id(),
            arkret_canonical::DigestSuite::Sha256,
            &projector,
            &control,
            options(),
        )
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
    store
        .save(realm_scope.clone(), "ak:cursor:expired-stream".to_owned())
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
        .run_realm(
            &provider,
            realm_id(),
            arkret_canonical::DigestSuite::Sha256,
            &projector,
            &control,
            options(),
        )
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
        .run_realm(
            &provider,
            realm_id(),
            arkret_canonical::DigestSuite::Sha256,
            &projector,
            &control,
            options(),
        )
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
        .run_realm(
            &provider,
            realm_id(),
            arkret_canonical::DigestSuite::Sha256,
            &projector,
            &control,
            options(),
        )
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
    let dropped = dropped_frame(Some(25));
    let provider = QueueProvider::new(vec![
        Ok(TestRealmTransport::frames(vec![Ok(dropped)])),
        Ok(TestRealmTransport::frames(vec![Ok(unauthorized_frame(
            "revoked",
        ))])),
    ]);
    let control = SyncLoopControl::new();
    let (projector, calls) = projector(None, false);

    let stop = client
        .run_realm(
            &provider,
            realm_id(),
            arkret_canonical::DigestSuite::Sha256,
            &projector,
            &control,
            options(),
        )
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
    let provider = QueueProvider::new(vec![Ok(TestRealmTransport::frames(vec![
        Ok(event_frame()),
    ]))]);
    let control = SyncLoopControl::new();
    let (projector, calls) = projector(None, true);

    let result = client
        .run_realm(
            &provider,
            realm_id(),
            arkret_canonical::DigestSuite::Sha256,
            &projector,
            &control,
            options(),
        )
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
