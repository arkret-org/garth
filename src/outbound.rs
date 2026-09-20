//! Durable producer-submission engine over the governance-authority seam.
//!
//! Every queued item is one `EventCommitSubmission { event }` (or the MLS
//! commit submission that carries its Welcome deliveries). The queue owns the
//! lifecycle — queued, forwarding, committed, rejected — and the authority
//! outcome is the only thing that moves an item out of `Forwarding`. A
//! producer Event never carries a predecessor, a basis or a position, so the
//! queue is a plain retry ledger rather than a causal structure.

use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arkret_http_client::ClientRequestOptions;
use arkret_retry::{Jitter, RetryPolicy};
use arkret_wire::{AuthoritySubmitRequest, EventId, RealmCommit};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{
    AuthorityClient, AuthorityTransport, Error, HostClock, MaybeSend, MaybeSendSync,
    QueuedSubmission, Result, SubmissionState,
};

/// Lifecycle of one durable outbound item.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SendQueueStatus {
    /// Durably recorded and waiting for its next attempt.
    Queued,
    /// Handed to the governance Station; the outcome is not known yet.
    Forwarding,
    /// The Station returned an authority-signed RealmCommit for this Event.
    Committed,
    /// The Station refused the Event with a reason code.
    Rejected,
    /// A non-retryable local or transport failure stopped this item.
    Failed,
    /// The producer withdrew the item before it reached the Station.
    Cancelled,
}

impl SendQueueStatus {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Committed | Self::Rejected | Self::Failed | Self::Cancelled
        )
    }
}

/// One durable outbound item: the frozen submission plus its retry ledger.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SendQueueItem {
    pub submission: QueuedSubmission,
    pub status: SendQueueStatus,
    pub attempts: u32,
    pub next_attempt_at_ms: i64,
    pub last_error: Option<String>,
    pub enqueued_at: DateTime<Utc>,
    pub settled_at: Option<DateTime<Utc>>,
}

impl SendQueueItem {
    pub fn event_id(&self) -> &EventId {
        &self.submission.event_id
    }

    pub fn request(&self) -> &AuthoritySubmitRequest {
        &self.submission.request
    }

    /// The authority-signed commit, once the Station produced one.
    pub fn commit(&self) -> Option<&RealmCommit> {
        match &self.submission.state {
            SubmissionState::Committed { commit, .. } => Some(commit),
            _ => None,
        }
    }

    pub fn rejection_reason_code(&self) -> Option<&str> {
        match &self.submission.state {
            SubmissionState::Rejected { reason_code, .. } => Some(reason_code),
            _ => None,
        }
    }
}

/// Serializable outbound queue state.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct SendQueueSnapshot {
    #[serde(default)]
    pub items: Vec<SendQueueItem>,
}

/// In-order producer queue. Items are attempted oldest first; a terminal item
/// stays visible until the host compacts it.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct SendQueue {
    items: Vec<SendQueueItem>,
}

impl SendQueue {
    pub fn from_snapshot(snapshot: SendQueueSnapshot) -> Self {
        Self {
            items: snapshot.items,
        }
    }

    pub fn snapshot(&self) -> SendQueueSnapshot {
        SendQueueSnapshot {
            items: self.items.clone(),
        }
    }

    pub fn items(&self) -> &[SendQueueItem] {
        &self.items
    }

    pub fn get(&self, event_id: &EventId) -> Option<&SendQueueItem> {
        self.items.iter().find(|item| item.event_id() == event_id)
    }

    /// Record one frozen submission. The same Event id is never queued twice.
    pub fn enqueue(&mut self, submission: QueuedSubmission, now: DateTime<Utc>) -> Result<()> {
        if !matches!(submission.state, SubmissionState::Queued) {
            return Err(Error::Protocol(
                "an outbound item must be enqueued before it has an authority outcome".to_owned(),
            ));
        }
        if self.get(&submission.event_id).is_some() {
            return Err(Error::Protocol(
                "this Event is already queued for authority submission".to_owned(),
            ));
        }
        self.items.push(SendQueueItem {
            submission,
            status: SendQueueStatus::Queued,
            attempts: 0,
            next_attempt_at_ms: now.timestamp_millis(),
            last_error: None,
            enqueued_at: now,
            settled_at: None,
        });
        Ok(())
    }

    /// Withdraw an item that has not been handed to the Station yet.
    pub fn cancel(&mut self, event_id: &EventId, now: DateTime<Utc>) -> Result<bool> {
        let Some(item) = self
            .items
            .iter_mut()
            .find(|item| item.event_id() == event_id)
        else {
            return Ok(false);
        };
        match item.status {
            SendQueueStatus::Queued => {
                item.status = SendQueueStatus::Cancelled;
                item.settled_at = Some(now);
                Ok(true)
            }
            SendQueueStatus::Forwarding => Err(Error::Protocol(
                "an in-flight submission cannot be cancelled; its outcome is still authoritative"
                    .to_owned(),
            )),
            _ => Ok(false),
        }
    }

    /// Claim the oldest item whose next attempt is due, marking it forwarding.
    fn claim_due(&mut self, now: DateTime<Utc>) -> Option<SendQueueItem> {
        let now_ms = now.timestamp_millis();
        let item = self.items.iter_mut().find(|item| {
            item.status == SendQueueStatus::Queued && item.next_attempt_at_ms <= now_ms
        })?;
        item.status = SendQueueStatus::Forwarding;
        item.attempts = item.attempts.saturating_add(1);
        Some(item.clone())
    }

    fn settle(
        &mut self,
        event_id: &EventId,
        status: SendQueueStatus,
        submission: Option<QueuedSubmission>,
        error: Option<String>,
        next_attempt_at_ms: Option<i64>,
        now: DateTime<Utc>,
    ) -> Result<SendQueueItem> {
        let item = self
            .items
            .iter_mut()
            .find(|item| item.event_id() == event_id)
            .ok_or_else(|| {
                Error::Storage("the outbound item disappeared while in flight".to_owned())
            })?;
        if let Some(submission) = submission {
            item.submission = submission;
        }
        item.status = status;
        item.last_error = error;
        if let Some(next) = next_attempt_at_ms {
            item.next_attempt_at_ms = next;
        }
        item.settled_at = status.is_terminal().then_some(now);
        Ok(item.clone())
    }

    /// Drop terminal items settled before `cutoff`, returning how many went.
    pub fn compact_terminal_before(&mut self, cutoff: DateTime<Utc>) -> usize {
        let before = self.items.len();
        self.items.retain(|item| {
            !item.status.is_terminal() || item.settled_at.is_none_or(|at| at >= cutoff)
        });
        before - self.items.len()
    }
}

/// Boxed mutation future. Native hosts keep it `Send` so a queue worker can
/// move across runtime threads; wasm hosts drop `Send` for JS-interop stores.
#[cfg(not(target_arch = "wasm32"))]
pub type BoxOutboundFuture<'a, T> = std::pin::Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;
#[cfg(target_arch = "wasm32")]
pub type BoxOutboundFuture<'a, T> = std::pin::Pin<Box<dyn Future<Output = Result<T>> + 'a>>;

/// Durable host boundary for the outbound queue. One mutation is one durable
/// transaction: the store persists the mutated queue before it returns.
pub trait OutboundQueueStore: Clone + MaybeSendSync + 'static {
    fn mutate_outbound<'a, R>(
        &'a self,
        mutation: impl FnOnce(&mut SendQueue) -> Result<R> + MaybeSend + 'a,
    ) -> BoxOutboundFuture<'a, R>
    where
        R: MaybeSend + 'a;
}

#[derive(Clone, Debug, Default)]
pub struct MemoryOutboundQueueStore {
    queue: Arc<Mutex<SendQueue>>,
}

impl MemoryOutboundQueueStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl OutboundQueueStore for MemoryOutboundQueueStore {
    fn mutate_outbound<'a, R>(
        &'a self,
        mutation: impl FnOnce(&mut SendQueue) -> Result<R> + MaybeSend + 'a,
    ) -> BoxOutboundFuture<'a, R>
    where
        R: MaybeSend + 'a,
    {
        Box::pin(async move {
            let mut queue = self.queue.lock().unwrap();
            mutation(&mut queue)
        })
    }
}

/// What one `submit_next` attempt produced.
#[derive(Clone, Debug, PartialEq)]
pub enum OutboundEngineOutcome {
    /// Nothing is due right now.
    Idle,
    /// The Station returned an authority-signed RealmCommit.
    Committed {
        item: Box<SendQueueItem>,
        commit: Box<RealmCommit>,
    },
    /// The Station refused the Event.
    Rejected {
        item: Box<SendQueueItem>,
        reason_code: String,
    },
    /// A retryable transport fault; the item is queued again after `delay`.
    Retry {
        item: Box<SendQueueItem>,
        delay: Duration,
    },
    /// A non-retryable failure stopped the item.
    Failed {
        item: Box<SendQueueItem>,
        error: String,
    },
}

/// Durable submission engine. The queue store is the only durable state; the
/// authority client is the only network seam.
#[derive(Clone, Debug)]
pub struct OutboundEngine<S, K> {
    store: S,
    clock: K,
    policy: RetryPolicy,
    jitter_seed: u64,
}

impl<S, K> OutboundEngine<S, K>
where
    S: OutboundQueueStore,
    K: HostClock,
{
    pub fn new(store: S, clock: K) -> Self {
        Self {
            store,
            clock,
            policy: RetryPolicy::arkret_default(),
            jitter_seed: 0x0A11_0B0A_0C0D_0E0F,
        }
    }

    pub fn with_retry_policy(mut self, policy: RetryPolicy) -> Self {
        self.policy = policy;
        self
    }

    pub fn with_jitter_seed(mut self, seed: u64) -> Self {
        self.jitter_seed = seed;
        self
    }

    pub fn store(&self) -> &S {
        &self.store
    }

    pub async fn enqueue(&self, submission: QueuedSubmission) -> Result<()> {
        let now = self.clock.now();
        self.store
            .mutate_outbound(move |queue| queue.enqueue(submission, now))
            .await
    }

    pub async fn cancel(&self, event_id: EventId) -> Result<bool> {
        let now = self.clock.now();
        self.store
            .mutate_outbound(move |queue| queue.cancel(&event_id, now))
            .await
    }

    pub async fn snapshot(&self) -> Result<SendQueueSnapshot> {
        self.store
            .mutate_outbound(|queue| Ok(queue.snapshot()))
            .await
    }

    pub async fn compact_terminal_before(&self, cutoff: DateTime<Utc>) -> Result<usize> {
        self.store
            .mutate_outbound(move |queue| Ok(queue.compact_terminal_before(cutoff)))
            .await
    }

    /// Forward the oldest due item and durably record its authority outcome.
    pub async fn submit_next<T: AuthorityTransport>(
        &self,
        authority: &AuthorityClient<T>,
        options: &ClientRequestOptions,
    ) -> Result<OutboundEngineOutcome> {
        let now = self.clock.now();
        let Some(claimed) = self
            .store
            .mutate_outbound(move |queue| Ok(queue.claim_due(now)))
            .await?
        else {
            return Ok(OutboundEngineOutcome::Idle);
        };

        let mut submission = claimed.submission.clone();
        let event_id = submission.event_id.clone();
        let settled_at = self.clock.now();
        match authority.submit(&mut submission, options).await {
            Ok(()) => {
                let status = match &submission.state {
                    SubmissionState::Committed { .. } => SendQueueStatus::Committed,
                    SubmissionState::Rejected { .. } => SendQueueStatus::Rejected,
                    SubmissionState::Queued => {
                        return Err(Error::Protocol(
                            "an accepted authority response must leave the queued state".to_owned(),
                        ));
                    }
                };
                let state = submission.state.clone();
                let item = self
                    .store
                    .mutate_outbound(move |queue| {
                        queue.settle(&event_id, status, Some(submission), None, None, settled_at)
                    })
                    .await?;
                Ok(match state {
                    SubmissionState::Committed { commit, .. } => OutboundEngineOutcome::Committed {
                        item: Box::new(item),
                        commit,
                    },
                    SubmissionState::Rejected { reason_code, .. } => {
                        OutboundEngineOutcome::Rejected {
                            item: Box::new(item),
                            reason_code,
                        }
                    }
                    SubmissionState::Queued => unreachable!("checked above"),
                })
            }
            Err(error) => {
                let message = error.to_string();
                if crate::run::is_retryable(&error) {
                    let delay = self.policy.delay(
                        claimed.attempts.saturating_sub(1),
                        &mut Jitter::from_seed(self.jitter_seed ^ u64::from(claimed.attempts)),
                    );
                    let next = settled_at.timestamp_millis()
                        + i64::try_from(delay.as_millis()).unwrap_or(i64::MAX);
                    let item = self
                        .store
                        .mutate_outbound(move |queue| {
                            queue.settle(
                                &event_id,
                                SendQueueStatus::Queued,
                                None,
                                Some(message),
                                Some(next),
                                settled_at,
                            )
                        })
                        .await?;
                    return Ok(OutboundEngineOutcome::Retry {
                        item: Box::new(item),
                        delay,
                    });
                }
                let recorded = message.clone();
                let item = self
                    .store
                    .mutate_outbound(move |queue| {
                        queue.settle(
                            &event_id,
                            SendQueueStatus::Failed,
                            None,
                            Some(recorded),
                            None,
                            settled_at,
                        )
                    })
                    .await?;
                Ok(OutboundEngineOutcome::Failed {
                    item: Box::new(item),
                    error: message,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use arkret_canonical::DigestSuite;
    use arkret_signatures::{Ed25519DetachedJwsSigner, SignEventOptions};
    use arkret_wire::{
        ActorId, AuthoredEvent, AuthorityBundleRequest, AuthorityCommitStatus,
        AuthorityHandoffRequest, AuthorityRejectionStatus, AuthoritySubmitOutcome,
        AuthoritySubmitRequest, CommitStreamRef, CommittedEventResolveOutcome,
        CommittedEventResolveRequest, DidCoreId, Event, EventId, EventKind, Problem,
        RealmAuthorityBundle, RealmAuthorityHandoff, RealmId, ScopeRef, StreamScanOutcome,
        StreamScanRequest,
    };

    use super::*;
    use crate::SystemClock;
    use crate::test_fixtures::commit;

    #[derive(Clone, Copy, Debug)]
    struct FixedClock;

    impl HostClock for FixedClock {
        fn now(&self) -> DateTime<Utc> {
            crate::test_fixtures::at(0)
        }
    }

    /// One genuinely authored and signed producer submission, so the engine
    /// exercises the same validation an application submission goes through.
    fn submission(seed: u8) -> QueuedSubmission {
        let seed_id = EventId::from_digest(DigestSuite::Sha256, [seed; 32]);
        let realm_id = RealmId::from_event_id(&seed_id);
        let authored = AuthoredEvent::finalize_with_digest_suite(
            Event {
                event_id: seed_id,
                kind: EventKind::MessageCreate,
                realm_id: realm_id.clone(),
                scope_ref: ScopeRef::Realm { realm_id },
                actor_id: ActorId::service(
                    DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
                ),
                executed_by: None,
                authorization_ref: None,
                applet_id: None,
                external_ref: None,
                created_at: crate::test_fixtures::at(0),
                refs: Vec::new(),
                payload: BTreeMap::from([("seed".to_owned(), serde_json::json!(seed))]),
                producer_proof: None,
            },
            DigestSuite::Sha256,
        )
        .unwrap();
        let signer = Ed25519DetachedJwsSigner::new(
            ed25519_dalek::SigningKey::from_bytes(&[9; 32]),
            "did:web:alice.example#key-1",
        );
        let request = crate::author_message(authored, &signer, SignEventOptions::new()).unwrap();
        crate::queue_authored_message(request).unwrap()
    }

    enum Scripted {
        Accept,
        Reject,
        Transport,
        Protocol,
    }

    struct ScriptedTransport {
        script: Scripted,
        calls: AtomicUsize,
    }

    impl ScriptedTransport {
        fn new(script: Scripted) -> Self {
            Self {
                script,
                calls: AtomicUsize::new(0),
            }
        }
    }

    impl AuthorityTransport for ScriptedTransport {
        async fn submit(
            &self,
            request: &AuthoritySubmitRequest,
            _options: &ClientRequestOptions,
        ) -> Result<AuthoritySubmitOutcome> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let AuthoritySubmitRequest::Event(submission) = request else {
                panic!("the fixture only submits ordinary Events");
            };
            match self.script {
                Scripted::Accept => Ok(AuthoritySubmitOutcome::Accepted {
                    status: AuthorityCommitStatus::Committed,
                    commit: commit(
                        7,
                        &submission.event,
                        CommitStreamRef::Realm {
                            realm_id: submission.event.realm_id.clone(),
                        },
                        1,
                    ),
                }),
                Scripted::Reject => Ok(AuthoritySubmitOutcome::Rejected {
                    status: AuthorityRejectionStatus::Rejected,
                    reason_code: "authorization_denied".to_owned(),
                }),
                Scripted::Transport => Err(Error::Http("connection reset".to_owned())),
                Scripted::Protocol => Err(Error::Api {
                    status: 400,
                    error: Box::new(Problem::new("param_invalid", 400, "bad payload")),
                }),
            }
        }

        async fn scan(&self, _request: &StreamScanRequest) -> Result<StreamScanOutcome> {
            unreachable!("the outbound engine never scans")
        }

        async fn resolve(
            &self,
            _request: &CommittedEventResolveRequest,
        ) -> Result<CommittedEventResolveOutcome> {
            unreachable!("the outbound engine never resolves")
        }

        async fn authority_bundle(
            &self,
            _request: &AuthorityBundleRequest,
        ) -> Result<RealmAuthorityBundle> {
            unreachable!("the outbound engine never resolves authority")
        }

        async fn install_handoff(
            &self,
            _request: &AuthorityHandoffRequest,
            _options: &ClientRequestOptions,
        ) -> Result<RealmAuthorityHandoff> {
            unreachable!("the outbound engine never installs a handoff")
        }
    }

    fn engine() -> OutboundEngine<MemoryOutboundQueueStore, FixedClock> {
        OutboundEngine::new(MemoryOutboundQueueStore::new(), FixedClock)
    }

    #[tokio::test]
    async fn an_empty_queue_is_idle() {
        let engine = engine();
        let authority = AuthorityClient::new(ScriptedTransport::new(Scripted::Accept));
        assert_eq!(
            engine
                .submit_next(&authority, &ClientRequestOptions::default())
                .await
                .unwrap(),
            OutboundEngineOutcome::Idle
        );
    }

    #[tokio::test]
    async fn an_accepted_submission_becomes_committed_with_its_commit() {
        let engine = engine();
        engine.enqueue(submission(3)).await.unwrap();
        let authority = AuthorityClient::new(ScriptedTransport::new(Scripted::Accept));
        let outcome = engine
            .submit_next(&authority, &ClientRequestOptions::default())
            .await
            .unwrap();
        let OutboundEngineOutcome::Committed { item, commit } = outcome else {
            panic!("an accepted submission must expose its authority commit");
        };
        assert_eq!(item.status, SendQueueStatus::Committed);
        assert_eq!(commit.stream_position, 1);
        assert_eq!(item.commit().map(|commit| commit.stream_position), Some(1));
    }

    #[tokio::test]
    async fn a_refused_submission_keeps_its_reason_code() {
        let engine = engine();
        engine.enqueue(submission(3)).await.unwrap();
        let authority = AuthorityClient::new(ScriptedTransport::new(Scripted::Reject));
        let outcome = engine
            .submit_next(&authority, &ClientRequestOptions::default())
            .await
            .unwrap();
        let OutboundEngineOutcome::Rejected { item, reason_code } = outcome else {
            panic!("a refused submission must expose its reason code");
        };
        assert_eq!(reason_code, "authorization_denied");
        assert_eq!(item.rejection_reason_code(), Some("authorization_denied"));
    }

    #[tokio::test]
    async fn a_transport_fault_requeues_the_same_item_with_a_delay() {
        let engine = engine();
        engine.enqueue(submission(3)).await.unwrap();
        let authority = AuthorityClient::new(ScriptedTransport::new(Scripted::Transport));
        let outcome = engine
            .submit_next(&authority, &ClientRequestOptions::default())
            .await
            .unwrap();
        let OutboundEngineOutcome::Retry { item, delay } = outcome else {
            panic!("a transport fault must stay retryable");
        };
        assert_eq!(item.status, SendQueueStatus::Queued);
        assert_eq!(item.attempts, 1);
        assert!(delay > Duration::ZERO);
        assert!(item.next_attempt_at_ms > FixedClock.now().timestamp_millis());
        // The item is no longer due at the fixed clock, so the engine idles.
        assert_eq!(
            engine
                .submit_next(&authority, &ClientRequestOptions::default())
                .await
                .unwrap(),
            OutboundEngineOutcome::Idle
        );
    }

    #[tokio::test]
    async fn a_rejected_request_shape_fails_without_retrying() {
        let engine = engine();
        engine.enqueue(submission(3)).await.unwrap();
        let authority = AuthorityClient::new(ScriptedTransport::new(Scripted::Protocol));
        let outcome = engine
            .submit_next(&authority, &ClientRequestOptions::default())
            .await
            .unwrap();
        let OutboundEngineOutcome::Failed { item, .. } = outcome else {
            panic!("a protocol violation is not retryable");
        };
        assert_eq!(item.status, SendQueueStatus::Failed);
    }

    #[tokio::test]
    async fn the_same_event_is_never_queued_twice() {
        let engine = engine();
        engine.enqueue(submission(3)).await.unwrap();
        assert!(engine.enqueue(submission(3)).await.is_err());
    }

    #[tokio::test]
    async fn an_in_flight_item_cannot_be_cancelled() {
        let store = MemoryOutboundQueueStore::new();
        let engine = OutboundEngine::new(store.clone(), FixedClock);
        let queued = submission(3);
        let event_id = queued.event_id.clone();
        engine.enqueue(queued).await.unwrap();
        let now = FixedClock.now();
        store
            .mutate_outbound(move |queue| {
                assert!(queue.claim_due(now).is_some());
                Ok(())
            })
            .await
            .unwrap();
        assert!(engine.cancel(event_id).await.is_err());
    }

    #[tokio::test]
    async fn a_queued_item_can_be_withdrawn_before_it_is_forwarded() {
        let engine = engine();
        let queued = submission(3);
        let event_id = queued.event_id.clone();
        engine.enqueue(queued).await.unwrap();
        assert!(engine.cancel(event_id.clone()).await.unwrap());
        let snapshot = engine.snapshot().await.unwrap();
        assert_eq!(snapshot.items[0].status, SendQueueStatus::Cancelled);
        let authority = AuthorityClient::new(ScriptedTransport::new(Scripted::Accept));
        assert_eq!(
            engine
                .submit_next(&authority, &ClientRequestOptions::default())
                .await
                .unwrap(),
            OutboundEngineOutcome::Idle
        );
        assert_eq!(authority.transport().calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn terminal_items_are_compacted_only_after_the_cutoff() {
        let engine = OutboundEngine::new(MemoryOutboundQueueStore::new(), SystemClock);
        let queued = submission(3);
        let event_id = queued.event_id.clone();
        engine.enqueue(queued).await.unwrap();
        engine.cancel(event_id).await.unwrap();
        assert_eq!(
            engine
                .compact_terminal_before(crate::test_fixtures::at(0))
                .await
                .unwrap(),
            0
        );
        assert_eq!(engine.compact_terminal_before(Utc::now()).await.unwrap(), 1);
        assert!(engine.snapshot().await.unwrap().items.is_empty());
    }

    #[tokio::test]
    async fn the_queue_snapshot_round_trips_through_serialization() {
        let engine = engine();
        engine.enqueue(submission(3)).await.unwrap();
        let snapshot = engine.snapshot().await.unwrap();
        let bytes = serde_json::to_vec(&snapshot).unwrap();
        let restored: SendQueueSnapshot = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(SendQueue::from_snapshot(restored).snapshot(), snapshot);
    }
}
