use std::{future::Future, pin::Pin, time::Duration};

use arkret::sync_client::{SendQueue, SendQueueItem, SendQueueItemKind, SendQueueSnapshot};
use arkret_core::{Error, EventId, RealmId, Result};
use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::MaybeSendSync;

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

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OutboundSubmitOutcome {
    Accepted { event_id: EventId },
    Duplicate { event_id: EventId },
    Rejected { reason: String },
    RetryAfter { delay: Duration, reason: String },
    Terminal { reason: String },
}

#[derive(Clone, Debug, PartialEq)]
pub enum OutboundEngineOutcome {
    Idle,
    Accepted(SendQueueItem),
    Duplicate(SendQueueItem),
    Rejected(SendQueueItem),
    RetryAt {
        item: SendQueueItem,
        at: DateTime<Utc>,
    },
    Terminal(SendQueueItem),
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
        kind: SendQueueItemKind,
        content: Value,
        depends_on: Vec<String>,
    ) -> Result<SendQueueItem> {
        self.store
            .mutate_outbound(move |queue| {
                queue.enqueue(transaction_id, realm_id, kind, content, depends_on)
            })
            .await
    }

    pub async fn snapshot(&self) -> Result<SendQueueSnapshot> {
        self.store
            .mutate_outbound(|queue| Ok(queue.snapshot()))
            .await
    }

    pub async fn submit_next<T: OutboundSubmitter + ?Sized>(
        &self,
        submitter: &T,
        now: DateTime<Utc>,
    ) -> Result<OutboundEngineOutcome> {
        let item = self
            .store
            .mutate_outbound(move |queue| {
                let Some(item) = queue.ready_batch(now, 1).into_iter().next() else {
                    return Ok(None);
                };
                queue.mark_sending(&item.transaction_id)?;
                Ok(queue.get(&item.transaction_id).cloned())
            })
            .await?;
        let Some(item) = item else {
            return Ok(OutboundEngineOutcome::Idle);
        };
        let transaction_id = item.transaction_id.clone();
        let submit_outcome = match submitter.submit(item).await {
            Ok(outcome) => outcome,
            Err(error) => {
                self.mark_retry(transaction_id, Duration::from_secs(1))
                    .await?;
                return Err(error);
            }
        };
        match submit_outcome {
            OutboundSubmitOutcome::Accepted { event_id } => Ok(OutboundEngineOutcome::Accepted(
                self.mark_sent(transaction_id, event_id).await?,
            )),
            OutboundSubmitOutcome::Duplicate { event_id } => Ok(OutboundEngineOutcome::Duplicate(
                self.mark_sent(transaction_id, event_id).await?,
            )),
            OutboundSubmitOutcome::RetryAfter { delay, .. } => {
                let item = self.mark_retry(transaction_id, delay).await?;
                Ok(OutboundEngineOutcome::RetryAt {
                    at: item.next_retry_at.unwrap_or(now),
                    item,
                })
            }
            OutboundSubmitOutcome::Rejected { .. } => Ok(OutboundEngineOutcome::Rejected(
                self.cancel(transaction_id).await?,
            )),
            OutboundSubmitOutcome::Terminal { .. } => Ok(OutboundEngineOutcome::Terminal(
                self.cancel(transaction_id).await?,
            )),
        }
    }

    async fn mark_sent(&self, id: String, event_id: EventId) -> Result<SendQueueItem> {
        self.store
            .mutate_outbound(move |queue| {
                queue.mark_sent(&id, event_id)?;
                owned_item(queue, &id)
            })
            .await
    }

    async fn cancel(&self, id: String) -> Result<SendQueueItem> {
        self.store
            .mutate_outbound(move |queue| {
                queue.cancel(&id, true)?;
                owned_item(queue, &id)
            })
            .await
    }

    async fn mark_retry(&self, id: String, delay: Duration) -> Result<SendQueueItem> {
        self.store
            .mutate_outbound(move |queue| {
                queue.mark_failed(&id, delay)?;
                owned_item(queue, &id)
            })
            .await
    }
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

    use super::*;
    use crate::MemoryStore;

    #[derive(Clone)]
    struct QueueSubmitter {
        outcomes: Arc<Mutex<VecDeque<OutboundSubmitOutcome>>>,
    }

    struct FailingSubmitter;

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
        RealmId::new("ak:realm:01904100-0000-7000-8000-000000000001").unwrap()
    }

    fn event_id() -> EventId {
        EventId::new("ak:event:01904100-0000-7000-8000-000000000001").unwrap()
    }

    #[tokio::test]
    async fn enqueue_is_idempotent_and_acceptance_is_persisted() {
        let engine = OutboundEngine::new(MemoryStore::new());
        let first = engine
            .enqueue(
                Some("txn-1".to_owned()),
                realm_id(),
                SendQueueItemKind::Message,
                serde_json::json!({"body": "hello"}),
                Vec::new(),
            )
            .await
            .unwrap();
        let second = engine
            .enqueue(
                Some("txn-1".to_owned()),
                realm_id(),
                SendQueueItemKind::Message,
                serde_json::json!({"body": "hello"}),
                Vec::new(),
            )
            .await
            .unwrap();
        assert_eq!(first, second);

        let submitter = QueueSubmitter {
            outcomes: Arc::new(Mutex::new(VecDeque::from([
                OutboundSubmitOutcome::Accepted {
                    event_id: event_id(),
                },
            ]))),
        };
        assert!(matches!(
            engine.submit_next(&submitter, Utc::now()).await.unwrap(),
            OutboundEngineOutcome::Accepted(_)
        ));
        assert_eq!(engine.snapshot().await.unwrap().items.len(), 1);
        assert_eq!(
            engine.snapshot().await.unwrap().items[0].remote_event_id,
            Some(event_id())
        );
    }

    #[tokio::test]
    async fn submitter_error_persists_retry_state_before_returning() {
        let engine = OutboundEngine::new(MemoryStore::new());
        engine
            .enqueue(
                Some("txn-offline".to_owned()),
                realm_id(),
                SendQueueItemKind::Message,
                serde_json::json!({"body": "hello"}),
                Vec::new(),
            )
            .await
            .unwrap();

        let error = engine
            .submit_next(&FailingSubmitter, Utc::now())
            .await
            .unwrap_err();
        assert!(matches!(error, Error::Http(_)));
        let item = engine.snapshot().await.unwrap().items.remove(0);
        assert_eq!(item.status, arkret::sync_client::SendQueueStatus::Failed);
        assert_eq!(item.attempts, 1);
        assert!(item.next_retry_at.is_some());
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
                SendQueueItemKind::Message,
                serde_json::json!({"body": "hello"}),
                Vec::new(),
            )
            .await
            .unwrap();
        store
            .mutate_outbound(|queue| queue.mark_sending(&item.transaction_id))
            .await
            .unwrap();
        drop(engine);
        drop(store);

        let reopened = OutboundEngine::new(FileStore::open(&path).unwrap());
        let submitter = QueueSubmitter {
            outcomes: Arc::new(Mutex::new(VecDeque::from([
                OutboundSubmitOutcome::Duplicate {
                    event_id: event_id(),
                },
            ]))),
        };
        assert!(matches!(
            reopened.submit_next(&submitter, Utc::now()).await.unwrap(),
            OutboundEngineOutcome::Duplicate(_)
        ));
        let _ = std::fs::remove_file(path);
    }
}
