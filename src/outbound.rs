use std::collections::hash_map::DefaultHasher;
use std::future::Future;
use std::hash::{Hash, Hasher};
use std::pin::Pin;
use std::time::Duration;

use chrono::{DateTime, Utc};

use crate::protocol::{Error, EventId, IngressReceipt, RealmId, Result};
use crate::sync_client::{SendQueue, SendQueueItem, SendQueueSnapshot};
use crate::{MaybeSendSync, QueuedRecord};

#[cfg(not(target_arch = "wasm32"))]
pub type BoxOutboundFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;
#[cfg(target_arch = "wasm32")]
pub type BoxOutboundFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + 'a>>;

pub trait OutboundQueueStore: Clone + MaybeSendSync + 'static {
    fn mutate_outbound<'a, R>(
        &'a self,
        mutation: impl FnOnce(&mut SendQueue) -> Result<R> + crate::MaybeSend + 'a,
    ) -> BoxOutboundFuture<'a, R>
    where
        R: crate::MaybeSend + 'a;
}

pub trait OutboundSubmitter: crate::MaybeSendSync {
    fn submit<'a>(&'a self, item: SendQueueItem) -> BoxOutboundFuture<'a, OutboundSubmitOutcome>;
}

/// Host-owned authoring-generation fence for durable outbound work.
///
/// The fence is evaluated again immediately before an item is marked
/// `Sending`. This closes the restart/recovery gap where a queued event was
/// authored by a device generation that is no longer active. Implementations
/// must derive their decision from authoritative, already-verified local
/// projection state; an unknown or conflicted generation must fail closed.
pub trait OutboundGenerationFence: crate::MaybeSendSync {
    fn evaluate(&self, item: &SendQueueItem) -> Result<OutboundGenerationFenceDecision>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OutboundGenerationFenceDecision {
    Current,
    Quarantine { reason: String },
}

#[cfg(test)]
struct NoopGenerationFence;

#[cfg(test)]
impl OutboundGenerationFence for NoopGenerationFence {
    fn evaluate(&self, _item: &SendQueueItem) -> Result<OutboundGenerationFenceDecision> {
        Ok(OutboundGenerationFenceDecision::Current)
    }
}

/// Host-owned durable side effect that must commit after server acceptance but
/// before the queue item becomes `Sent` (for example an MLS post-commit
/// snapshot). Implementations must be idempotent: a crash or hook error causes
/// the event to be submitted again, normally producing `Duplicate`, and the
/// hook is invoked again before completion.
pub trait OutboundPostAcceptHook: crate::MaybeSendSync {
    fn post_accept<'a>(
        &'a self,
        item: &'a SendQueueItem,
        event_id: &'a EventId,
        duplicate: bool,
    ) -> BoxOutboundFuture<'a, ()>;
}

struct NoopPostAcceptHook;

impl OutboundPostAcceptHook for NoopPostAcceptHook {
    fn post_accept<'a>(
        &'a self,
        _item: &'a SendQueueItem,
        _event_id: &'a EventId,
        _duplicate: bool,
    ) -> BoxOutboundFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum OutboundSubmitOutcome {
    /// Host prepared and signed the queued unsigned intent. Persist it before
    /// beginning transport.
    Prepared {
        record: QueuedRecord,
    },
    /// The ingress admitted the Event and issued its receipts.
    ///
    /// `ingress_receipts` are the receipts the service returned in
    /// `EventsSubmitOutcome.ingress_receipts[]`; they are the only evidence
    /// that this Event arrived inside its lease window, so the queue refuses
    /// an acceptance that carries none.
    Accepted {
        event_id: EventId,
        ingress_receipts: Vec<IngressReceipt>,
    },
    /// The same canonical Event was already admitted.
    ///
    /// The service MUST return the *original* receipts here rather than
    /// re-signing with a later `received_at`
    /// (`offline-publication.md` §2.1). The queue keeps whatever it already
    /// stored, so a service that violates that cannot silently extend the
    /// revocation window of a locally persisted item.
    Duplicate {
        event_id: EventId,
        ingress_receipts: Vec<IngressReceipt>,
    },
    Rejected {
        reason: String,
    },
    RetryAfter {
        delay: Duration,
        reason: String,
    },
    Terminal {
        reason: String,
    },
    /// The service explicitly rejected the old authoring frontiers without
    /// accepting the Event. Persist this new immutable attempt before any
    /// network send is allowed.
    Supersede {
        transaction_id: String,
        realm_id: RealmId,
        record: QueuedRecord,
        depends_on: Vec<String>,
    },
}

#[derive(Clone, Debug, PartialEq)]
pub enum OutboundEngineOutcome {
    Idle,
    Prepared(SendQueueItem),
    Accepted(SendQueueItem),
    Duplicate(SendQueueItem),
    Rejected {
        item: SendQueueItem,
        reason: String,
    },
    RetryAt {
        item: SendQueueItem,
        at: DateTime<Utc>,
    },
    Terminal {
        item: SendQueueItem,
        reason: String,
    },
    Quarantined {
        item: SendQueueItem,
        reason: String,
    },
    Superseded {
        previous: SendQueueItem,
        replacement: Box<SendQueueItem>,
    },
}

#[derive(Clone, Debug)]
pub struct OutboundEngine<S> {
    store: S,
}

impl<S: OutboundQueueStore> OutboundEngine<S> {
    pub fn new(store: S) -> Self {
        Self { store }
    }

    pub async fn enqueue(
        &self,
        transaction_id: Option<String>,
        realm_id: RealmId,
        record: QueuedRecord,
        depends_on: Vec<String>,
        now: DateTime<Utc>,
    ) -> Result<SendQueueItem> {
        self.store
            .mutate_outbound(move |queue| {
                queue.enqueue(transaction_id, realm_id, record, depends_on, now)
            })
            .await
    }

    pub async fn enqueue_scoped(
        &self,
        transaction_id: Option<String>,
        realm_id: RealmId,
        actor_id: crate::protocol::ActorId,
        record: QueuedRecord,
        depends_on: Vec<String>,
        now: DateTime<Utc>,
    ) -> Result<SendQueueItem> {
        self.store
            .mutate_outbound(move |queue| {
                let item = queue.enqueue(transaction_id, realm_id, record, depends_on, now)?;
                queue.set_actor_scope(&item.transaction_id, actor_id)?;
                owned_item(queue, &item.transaction_id)
            })
            .await
    }

    pub async fn snapshot(&self) -> Result<SendQueueSnapshot> {
        self.store
            .mutate_outbound(|queue| Ok(queue.snapshot()))
            .await
    }

    pub async fn compact_terminal_before(&self, cutoff: DateTime<Utc>) -> Result<usize> {
        self.store
            .mutate_outbound(move |queue| Ok(queue.prune_terminal_before(cutoff)))
            .await
    }

    pub async fn submit_next_with_fence<
        T: OutboundSubmitter + ?Sized,
        F: OutboundGenerationFence + ?Sized,
    >(
        &self,
        submitter: &T,
        fence: &F,
        now: DateTime<Utc>,
    ) -> Result<OutboundEngineOutcome> {
        self.submit_next_with_fence_and_hook(submitter, fence, &NoopPostAcceptHook, now)
            .await
    }

    pub async fn submit_next_with_fence_and_hook<
        T: OutboundSubmitter + ?Sized,
        F: OutboundGenerationFence + ?Sized,
        H: OutboundPostAcceptHook + ?Sized,
    >(
        &self,
        submitter: &T,
        fence: &F,
        hook: &H,
        now: DateTime<Utc>,
    ) -> Result<OutboundEngineOutcome> {
        let item = self
            .store
            .mutate_outbound(move |queue| {
                for candidate in queue.active_items() {
                    if let OutboundGenerationFenceDecision::Quarantine { reason } =
                        fence.evaluate(&candidate)?
                    {
                        queue.cancel(&candidate.transaction_id, true, now)?;
                        return Ok(QueuePreflight::Quarantined {
                            item: owned_item(queue, &candidate.transaction_id)?,
                            reason,
                        });
                    }
                }
                let Some(item) = queue.ready_batch(now, 1).into_iter().next() else {
                    if let Some((item, at)) = queue
                        .active_items()
                        .into_iter()
                        .filter_map(|item| item.next_retry_at.map(|at| (item, at)))
                        .min_by_key(|(_, at)| *at)
                    {
                        return Ok(QueuePreflight::Waiting { item, at });
                    }
                    return Ok(QueuePreflight::Idle);
                };
                queue.mark_sending(&item.transaction_id, now)?;
                Ok(QueuePreflight::Ready(owned_item(
                    queue,
                    &item.transaction_id,
                )?))
            })
            .await?;
        let item = match item {
            QueuePreflight::Idle => return Ok(OutboundEngineOutcome::Idle),
            QueuePreflight::Waiting { item, at } => {
                return Ok(OutboundEngineOutcome::RetryAt { item, at });
            }
            QueuePreflight::Quarantined { item, reason } => {
                return Ok(OutboundEngineOutcome::Quarantined { item, reason });
            }
            QueuePreflight::Ready(item) => item,
        };
        let transaction_id = item.transaction_id.clone();
        let hook_item = item.clone();
        let submit_outcome = match submitter.submit(item).await {
            Ok(outcome) => outcome,
            Err(error) => {
                return self
                    .retry_local_or_terminal(transaction_id, error.to_string(), now)
                    .await;
            }
        };
        match submit_outcome {
            OutboundSubmitOutcome::Prepared { record } => {
                let item = self
                    .store
                    .mutate_outbound(move |queue| queue.mark_prepared(&transaction_id, record, now))
                    .await?;
                Ok(OutboundEngineOutcome::Prepared(item))
            }
            OutboundSubmitOutcome::Accepted {
                event_id,
                ingress_receipts,
            } => {
                if let Err(error) = hook.post_accept(&hook_item, &event_id, false).await {
                    return self
                        .retry_local_or_terminal(transaction_id, error.to_string(), now)
                        .await;
                }
                Ok(OutboundEngineOutcome::Accepted(
                    self.mark_sent(transaction_id, event_id, ingress_receipts, now)
                        .await?,
                ))
            }
            OutboundSubmitOutcome::Duplicate {
                event_id,
                ingress_receipts,
            } => {
                if let Err(error) = hook.post_accept(&hook_item, &event_id, true).await {
                    return self
                        .retry_local_or_terminal(transaction_id, error.to_string(), now)
                        .await;
                }
                Ok(OutboundEngineOutcome::Duplicate(
                    self.mark_sent(transaction_id, event_id, ingress_receipts, now)
                        .await?,
                ))
            }
            OutboundSubmitOutcome::RetryAfter { delay, .. } => {
                let item = self.mark_retry(transaction_id, delay, now).await?;
                Ok(OutboundEngineOutcome::RetryAt {
                    at: item.next_retry_at.unwrap_or(now),
                    item,
                })
            }
            OutboundSubmitOutcome::Rejected { reason } => Ok(OutboundEngineOutcome::Rejected {
                item: self.cancel(transaction_id, now).await?,
                reason,
            }),
            OutboundSubmitOutcome::Terminal { reason } => Ok(OutboundEngineOutcome::Terminal {
                item: self.cancel(transaction_id, now).await?,
                reason,
            }),
            OutboundSubmitOutcome::Supersede {
                transaction_id: replacement_id,
                realm_id,
                record,
                depends_on,
            } => {
                let previous_id = transaction_id;
                self.store
                    .mutate_outbound(move |queue| {
                        let previous = owned_item(queue, &previous_id)?;
                        let replacement = queue.supersede(
                            &previous_id,
                            replacement_id,
                            realm_id,
                            record,
                            depends_on,
                            now,
                        )?;
                        Ok(OutboundEngineOutcome::Superseded {
                            previous,
                            replacement: Box::new(replacement),
                        })
                    })
                    .await
            }
        }
    }

    async fn mark_sent(
        &self,
        id: String,
        event_id: EventId,
        ingress_receipts: Vec<IngressReceipt>,
        now: DateTime<Utc>,
    ) -> Result<SendQueueItem> {
        self.store
            .mutate_outbound(move |queue| {
                queue.mark_sent(&id, event_id, ingress_receipts, now)?;
                owned_item(queue, &id)
            })
            .await
    }

    async fn cancel(&self, id: String, now: DateTime<Utc>) -> Result<SendQueueItem> {
        self.store
            .mutate_outbound(move |queue| {
                queue.cancel(&id, true, now)?;
                owned_item(queue, &id)
            })
            .await
    }

    async fn mark_retry(
        &self,
        id: String,
        delay: Duration,
        now: DateTime<Utc>,
    ) -> Result<SendQueueItem> {
        self.store
            .mutate_outbound(move |queue| {
                queue.mark_failed(&id, delay, now)?;
                owned_item(queue, &id)
            })
            .await
    }

    async fn retry_local_or_terminal(
        &self,
        id: String,
        reason: String,
        now: DateTime<Utc>,
    ) -> Result<OutboundEngineOutcome> {
        const MAX_LOCAL_ATTEMPTS: u32 = 8;
        self.store
            .mutate_outbound(move |queue| {
                let attempts = queue
                    .get(&id)
                    .ok_or_else(|| Error::Protocol("outbound queue item disappeared".to_owned()))?
                    .attempts;
                if attempts >= MAX_LOCAL_ATTEMPTS {
                    queue.cancel(&id, true, now)?;
                    return Ok(OutboundEngineOutcome::Terminal {
                        item: owned_item(queue, &id)?,
                        reason,
                    });
                }
                queue.mark_failed(&id, local_retry_delay(&id, attempts), now)?;
                let item = owned_item(queue, &id)?;
                Ok(OutboundEngineOutcome::RetryAt {
                    at: item.next_retry_at.unwrap_or(now),
                    item,
                })
            })
            .await
    }
}

fn local_retry_delay(transaction_id: &str, attempts: u32) -> Duration {
    let mut hasher = DefaultHasher::new();
    transaction_id.hash(&mut hasher);
    let mut backoff = crate::RetrySchedule::new(Duration::from_secs(1), Duration::from_secs(60))
        .with_jitter(0.2, hasher.finish());
    let mut delay = Duration::from_secs(1);
    for _ in 0..attempts.max(1) {
        delay = backoff.next_delay();
    }
    delay
}

enum QueuePreflight {
    Idle,
    Waiting {
        item: SendQueueItem,
        at: DateTime<Utc>,
    },
    Ready(SendQueueItem),
    Quarantined {
        item: SendQueueItem,
        reason: String,
    },
}

fn owned_item(queue: &SendQueue, id: &str) -> Result<SendQueueItem> {
    queue.get(id).cloned().ok_or_else(|| {
        Error::Protocol("outbound queue item disappeared during mutation".to_owned())
    })
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    use arkret_wire::{Did, DidCoreId, EventKind, Hlc, ScopeRef, project_did_to_core_id};

    use super::*;
    use crate::MemoryStore;

    fn actor_id() -> crate::protocol::ActorId {
        crate::protocol::ActorId::account(crate::protocol::AccountId::new(
            project_did_to_core_id(&Did::new("did:webvh:z6mkfixture:alice.example").unwrap())
                .unwrap(),
            DidCoreId::new("ak:did_core:web:principal.example").unwrap(),
        ))
    }
    use serde_json::Value;

    fn queued_record(realm_id: &RealmId, payload: Value) -> QueuedRecord {
        let generation_ref = payload
            .get("generation")
            .and_then(Value::as_str)
            .unwrap_or("test-generation")
            .to_owned();
        let event = arkret_wire::test_support::raw_event_at(
            EventKind::MessageCreate.as_str(),
            ScopeRef::Realm {
                realm_id: realm_id.clone(),
            },
            actor_id().signing_principal_id().clone(),
            arkret_wire::DidCoreId::new("ak:did_core:web:principal.example").unwrap(),
            1,
            Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
            payload,
            chrono::DateTime::parse_from_rfc3339("2026-07-13T10:00:00.000Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
        )
        .unwrap();
        QueuedRecord::SdkEvent(Box::new(
            crate::QueuedSdkEvent::unauthored(
                crate::QueuedEventIntent::new(
                    arkret_event_draft::EventIntent::from_authored(&event),
                    arkret_canonical::DigestSuite::Sha256,
                ),
                "test-operation".to_owned(),
                "test-attempt".to_owned(),
                None,
                crate::AuthoringGeneration {
                    authority_model: crate::AuthoringAuthorityModel::AcceptedDevice,
                    authority_principal_id: arkret_wire::DidCoreId::new(
                        "ak:did_core:webvh:z6mkfixture",
                    )
                    .unwrap(),
                    generation_ref,
                },
                None,
            )
            .unwrap(),
        ))
    }

    #[derive(Clone)]
    struct QueueSubmitter {
        outcomes: Arc<Mutex<VecDeque<OutboundSubmitOutcome>>>,
    }

    struct FailingSubmitter;

    struct RejectGeneration(&'static str);

    impl OutboundGenerationFence for RejectGeneration {
        fn evaluate(&self, item: &SendQueueItem) -> Result<OutboundGenerationFenceDecision> {
            let QueuedRecord::SdkEvent(queued) = &item.record else {
                return Ok(OutboundGenerationFenceDecision::Current);
            };
            if queued.authoring_generation.generation_ref == self.0 {
                Ok(OutboundGenerationFenceDecision::Current)
            } else {
                Ok(OutboundGenerationFenceDecision::Quarantine {
                    reason: "authoring_generation_superseded".to_owned(),
                })
            }
        }
    }

    #[derive(Clone, Default)]
    struct FailingOncePostAcceptHook {
        calls: Arc<Mutex<usize>>,
    }

    impl OutboundPostAcceptHook for FailingOncePostAcceptHook {
        fn post_accept<'a>(
            &'a self,
            _item: &'a SendQueueItem,
            _event_id: &'a EventId,
            _duplicate: bool,
        ) -> BoxOutboundFuture<'a, ()> {
            let mut calls = self.calls.lock().unwrap();
            *calls += 1;
            let call = *calls;
            Box::pin(async move {
                if call == 1 {
                    Err(Error::Protocol("post-accept persist failed".to_owned()))
                } else {
                    Ok(())
                }
            })
        }
    }

    impl OutboundSubmitter for FailingSubmitter {
        fn submit<'a>(
            &'a self,
            _item: SendQueueItem,
        ) -> BoxOutboundFuture<'a, OutboundSubmitOutcome> {
            Box::pin(async { Err(Error::Http("offline".to_owned())) })
        }
    }

    impl OutboundSubmitter for QueueSubmitter {
        fn submit<'a>(
            &'a self,
            _item: SendQueueItem,
        ) -> BoxOutboundFuture<'a, OutboundSubmitOutcome> {
            let outcome = self.outcomes.lock().unwrap().pop_front().unwrap();
            Box::pin(async move { Ok(outcome) })
        }
    }

    fn realm_id() -> RealmId {
        RealmId::new("ak:realm:AfF-hFqRoMbajXkPapH-xaq0xwK-UKt2ph2zTs9JZRAO").unwrap()
    }

    /// The receipt a policy-accepted ingress returns alongside an
    /// accepted submission (`offline-publication.md` §2.1).
    fn accepted_receipt() -> crate::protocol::IngressReceipt {
        let issued_at = Utc::now() - chrono::Duration::minutes(5);
        crate::sync_client::test_publication::receipt(issued_at + chrono::Duration::minutes(1))
    }

    fn event_id() -> EventId {
        EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [1; 32])
    }

    #[tokio::test]
    async fn enqueue_is_idempotent_and_acceptance_is_persisted() {
        let engine = OutboundEngine::new(MemoryStore::new());
        let record = queued_record(&realm_id(), serde_json::json!({"body": "hello"}));
        let first = engine
            .enqueue(
                Some("txn-1".to_owned()),
                realm_id(),
                record.clone(),
                Vec::new(),
                Utc::now(),
            )
            .await
            .unwrap();
        let second = engine
            .enqueue(
                Some("txn-1".to_owned()),
                realm_id(),
                record,
                Vec::new(),
                Utc::now(),
            )
            .await
            .unwrap();
        assert_eq!(first, second);

        let submitter = QueueSubmitter {
            outcomes: Arc::new(Mutex::new(VecDeque::from([
                OutboundSubmitOutcome::Accepted {
                    event_id: event_id(),
                    ingress_receipts: vec![accepted_receipt()],
                },
            ]))),
        };
        assert!(matches!(
            engine
                .submit_next_with_fence(&submitter, &NoopGenerationFence, Utc::now())
                .await
                .unwrap(),
            OutboundEngineOutcome::Accepted(_)
        ));
        assert_eq!(engine.snapshot().await.unwrap().items.len(), 1);
        assert_eq!(
            engine.snapshot().await.unwrap().items[0].remote_event_id,
            Some(event_id())
        );
    }

    #[tokio::test]
    async fn unsigned_intent_is_prepared_and_persisted_before_transport() {
        let engine = OutboundEngine::new(MemoryStore::new());
        engine
            .enqueue_scoped(
                Some("local-operation-1".to_owned()),
                realm_id(),
                actor_id(),
                queued_record(&realm_id(), serde_json::json!({"intent": "unsigned"})),
                Vec::new(),
                Utc::now(),
            )
            .await
            .unwrap();
        let submitter = QueueSubmitter {
            outcomes: Arc::new(Mutex::new(VecDeque::from([
                OutboundSubmitOutcome::Prepared {
                    record: queued_record(&realm_id(), serde_json::json!({"intent": "unsigned"})),
                },
                OutboundSubmitOutcome::Accepted {
                    event_id: event_id(),
                    ingress_receipts: vec![accepted_receipt()],
                },
            ]))),
        };

        let prepared = engine
            .submit_next_with_fence(&submitter, &NoopGenerationFence, Utc::now())
            .await
            .unwrap();
        assert!(matches!(prepared, OutboundEngineOutcome::Prepared(_)));
        let snapshot = engine.snapshot().await.unwrap();
        assert_eq!(snapshot.items[0].transaction_id, "local-operation-1");
        assert!(matches!(
            snapshot.items[0].record,
            QueuedRecord::SdkEvent(_)
        ));
        assert!(!snapshot.items[0].canonical_payload_bytes.is_empty());

        assert!(matches!(
            engine
                .submit_next_with_fence(&submitter, &NoopGenerationFence, Utc::now())
                .await
                .unwrap(),
            OutboundEngineOutcome::Accepted(_)
        ));
    }

    #[tokio::test]
    async fn submitter_error_persists_retry_state_before_returning() {
        let engine = OutboundEngine::new(MemoryStore::new());
        engine
            .enqueue(
                Some("txn-offline".to_owned()),
                realm_id(),
                queued_record(&realm_id(), serde_json::json!({"body": "hello"})),
                Vec::new(),
                Utc::now(),
            )
            .await
            .unwrap();

        let outcome = engine
            .submit_next_with_fence(&FailingSubmitter, &NoopGenerationFence, Utc::now())
            .await
            .unwrap();
        assert!(matches!(outcome, OutboundEngineOutcome::RetryAt { .. }));
        let item = engine.snapshot().await.unwrap().items.remove(0);
        assert_eq!(item.status, crate::sync_client::SendQueueStatus::Failed);
        assert_eq!(item.attempts, 1);
        assert!(item.next_retry_at.is_some());
    }

    #[tokio::test]
    async fn scheduled_retry_is_reported_instead_of_becoming_idle() {
        let engine = OutboundEngine::new(MemoryStore::new());
        let now = Utc::now();
        engine
            .enqueue(
                Some("txn-waiting".to_owned()),
                realm_id(),
                queued_record(&realm_id(), serde_json::json!({"body": "hello"})),
                Vec::new(),
                now,
            )
            .await
            .unwrap();

        let first = engine
            .submit_next_with_fence(&FailingSubmitter, &NoopGenerationFence, now)
            .await
            .unwrap();
        let (retry_at, attempts) = match first {
            OutboundEngineOutcome::RetryAt { item, at } => (at, item.attempts),
            other => panic!("expected scheduled retry, got {other:?}"),
        };

        let waiting = engine
            .submit_next_with_fence(&FailingSubmitter, &NoopGenerationFence, now)
            .await
            .unwrap();
        match waiting {
            OutboundEngineOutcome::RetryAt { item, at } => {
                assert_eq!(item.transaction_id, "txn-waiting");
                assert_eq!(item.attempts, attempts);
                assert_eq!(at, retry_at);
            }
            other => panic!("scheduled work must not disappear into Idle: {other:?}"),
        }
    }

    #[tokio::test]
    async fn retry_after_counts_only_the_attempt_that_reached_the_server() {
        let engine = OutboundEngine::new(MemoryStore::new());
        engine
            .enqueue(
                Some("txn-throttled".to_owned()),
                realm_id(),
                queued_record(&realm_id(), serde_json::json!({"body": "hello"})),
                Vec::new(),
                Utc::now(),
            )
            .await
            .unwrap();
        let submitter = QueueSubmitter {
            outcomes: Arc::new(Mutex::new(VecDeque::from([
                OutboundSubmitOutcome::RetryAfter {
                    delay: Duration::from_secs(30),
                    reason: "rate_limited".to_owned(),
                },
            ]))),
        };

        let outcome = engine
            .submit_next_with_fence(&submitter, &NoopGenerationFence, Utc::now())
            .await
            .unwrap();
        assert!(matches!(outcome, OutboundEngineOutcome::RetryAt { .. }));
        let item = engine.snapshot().await.unwrap().items.remove(0);
        assert_eq!(item.attempts, 1);
        assert!(item.next_retry_at.is_some());
    }

    #[tokio::test]
    async fn post_accept_failure_retries_before_marking_sent() {
        let engine = OutboundEngine::new(MemoryStore::new());
        engine
            .enqueue(
                Some("txn-post-accept".to_owned()),
                realm_id(),
                queued_record(&realm_id(), serde_json::json!({"body": "hello"})),
                Vec::new(),
                Utc::now(),
            )
            .await
            .unwrap();
        let submitter = QueueSubmitter {
            outcomes: Arc::new(Mutex::new(VecDeque::from([
                OutboundSubmitOutcome::Accepted {
                    event_id: event_id(),
                    ingress_receipts: vec![accepted_receipt()],
                },
                OutboundSubmitOutcome::Duplicate {
                    event_id: event_id(),
                    ingress_receipts: vec![accepted_receipt()],
                },
            ]))),
        };
        let hook = FailingOncePostAcceptHook::default();

        let outcome = engine
            .submit_next_with_fence_and_hook(&submitter, &NoopGenerationFence, &hook, Utc::now())
            .await
            .unwrap();
        assert!(matches!(outcome, OutboundEngineOutcome::RetryAt { .. }));
        let failed = engine.snapshot().await.unwrap().items.remove(0);
        assert_eq!(failed.status, crate::sync_client::SendQueueStatus::Failed);
        assert!(failed.remote_event_id.is_none());

        let outcome = engine
            .submit_next_with_fence_and_hook(
                &submitter,
                &NoopGenerationFence,
                &hook,
                Utc::now() + chrono::Duration::seconds(2),
            )
            .await
            .unwrap();
        assert!(matches!(outcome, OutboundEngineOutcome::Duplicate(_)));
        assert_eq!(*hook.calls.lock().unwrap(), 2);
        assert_eq!(
            engine.snapshot().await.unwrap().items[0].remote_event_id,
            Some(event_id())
        );
    }

    #[tokio::test]
    async fn generation_fence_quarantines_before_submit_and_cascades() {
        let engine = OutboundEngine::new(MemoryStore::new());
        let stale = engine
            .enqueue(
                Some("txn-stale".to_owned()),
                realm_id(),
                queued_record(&realm_id(), serde_json::json!({"generation": "1-old"})),
                Vec::new(),
                Utc::now(),
            )
            .await
            .unwrap();
        engine
            .enqueue(
                Some("txn-dependent".to_owned()),
                realm_id(),
                queued_record(&realm_id(), serde_json::json!({"generation": "2-current"})),
                vec![stale.transaction_id],
                Utc::now(),
            )
            .await
            .unwrap();
        let submitter = QueueSubmitter {
            outcomes: Arc::new(Mutex::new(VecDeque::new())),
        };

        let outcome = engine
            .submit_next_with_fence(&submitter, &RejectGeneration("2-current"), Utc::now())
            .await
            .unwrap();
        assert!(matches!(
            outcome,
            OutboundEngineOutcome::Quarantined { ref item, ref reason }
                if item.transaction_id == "txn-stale"
                    && reason == "authoring_generation_superseded"
        ));
        let snapshot = engine.snapshot().await.unwrap();
        assert!(snapshot.items.iter().all(|item| {
            item.status == crate::sync_client::SendQueueStatus::Cancelled && item.attempts == 0
        }));
    }

    #[cfg(all(feature = "native", not(target_arch = "wasm32")))]
    #[tokio::test]
    async fn sending_item_is_retried_after_file_store_reopen() {
        use crate::FileStore;

        let path = std::env::temp_dir().join(format!(
            "garth-outbound-{}-{}.json",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        let store = FileStore::open(&path).unwrap();
        let engine = OutboundEngine::new(store.clone());
        let item = engine
            .enqueue(
                Some("txn-reopen".to_owned()),
                realm_id(),
                queued_record(&realm_id(), serde_json::json!({"body": "hello"})),
                Vec::new(),
                Utc::now(),
            )
            .await
            .unwrap();
        store
            .mutate_outbound(|queue| queue.mark_sending(&item.transaction_id, Utc::now()))
            .await
            .unwrap();
        drop(engine);
        drop(store);

        let reopened = OutboundEngine::new(FileStore::open(&path).unwrap());
        let submitter = QueueSubmitter {
            outcomes: Arc::new(Mutex::new(VecDeque::from([
                OutboundSubmitOutcome::Duplicate {
                    event_id: event_id(),
                    ingress_receipts: vec![accepted_receipt()],
                },
            ]))),
        };
        assert!(matches!(
            reopened
                .submit_next_with_fence(&submitter, &NoopGenerationFence, Utc::now())
                .await
                .unwrap(),
            OutboundEngineOutcome::Duplicate(_)
        ));
        let _ = std::fs::remove_file(path);
    }
}
