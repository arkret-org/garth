//! Durable queue seam for governance-authority submissions.

use std::collections::VecDeque;
use std::future::Future;
use std::sync::{Arc, Mutex};

use arkret_http_client::ClientRequestOptions;

use crate::{
    AuthorityClient, AuthorityTransport, MaybeSend, MaybeSendSync, QueuedSubmission, Result,
    SubmissionState,
};

pub trait SubmissionQueueStore: Clone + MaybeSendSync + 'static {
    fn enqueue(
        &self,
        queued: QueuedSubmission,
    ) -> impl Future<Output = Result<()>> + MaybeSend + '_;
    fn front(&self) -> impl Future<Output = Result<Option<QueuedSubmission>>> + MaybeSend + '_;
    fn replace_front(
        &self,
        queued: QueuedSubmission,
    ) -> impl Future<Output = Result<()>> + MaybeSend + '_;
    fn pop_front(&self) -> impl Future<Output = Result<Option<QueuedSubmission>>> + MaybeSend + '_;
}

#[derive(Clone, Debug, Default)]
pub struct MemorySubmissionQueueStore {
    queue: Arc<Mutex<VecDeque<QueuedSubmission>>>,
}

impl SubmissionQueueStore for MemorySubmissionQueueStore {
    async fn enqueue(&self, queued: QueuedSubmission) -> Result<()> {
        self.queue.lock().unwrap().push_back(queued);
        Ok(())
    }

    async fn front(&self) -> Result<Option<QueuedSubmission>> {
        Ok(self.queue.lock().unwrap().front().cloned())
    }

    async fn replace_front(&self, queued: QueuedSubmission) -> Result<()> {
        let mut queue = self.queue.lock().unwrap();
        let Some(front) = queue.front_mut() else {
            return Err(crate::Error::Storage(
                "submission queue has no front item".to_owned(),
            ));
        };
        *front = queued;
        Ok(())
    }

    async fn pop_front(&self) -> Result<Option<QueuedSubmission>> {
        Ok(self.queue.lock().unwrap().pop_front())
    }
}

#[derive(Clone, Debug)]
pub struct SubmissionWorker<T, S> {
    authority: AuthorityClient<T>,
    queue: S,
}

impl<T, S> SubmissionWorker<T, S>
where
    T: AuthorityTransport,
    S: SubmissionQueueStore,
{
    pub fn new(authority: AuthorityClient<T>, queue: S) -> Self {
        Self { authority, queue }
    }

    pub async fn submit_next(
        &self,
        options: &ClientRequestOptions,
    ) -> Result<Option<QueuedSubmission>> {
        let Some(mut queued) = self.queue.front().await? else {
            return Ok(None);
        };
        self.authority.submit(&mut queued, options).await?;
        self.queue.replace_front(queued.clone()).await?;
        if !matches!(queued.state, SubmissionState::Queued) {
            self.queue.pop_front().await?;
        }
        Ok(Some(queued))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use arkret_canonical::DigestSuite;
    use arkret_signatures::{Ed25519DetachedJwsSigner, SignEventOptions};
    use arkret_wire::{
        ActorId, AuthoredEvent, DidCoreId, Event, EventId, EventKind, RealmId, ScopeRef,
    };
    use chrono::TimeZone;
    use ed25519_dalek::SigningKey;

    use super::*;

    fn queued(seed: u8) -> QueuedSubmission {
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
                created_at: chrono::Utc.with_ymd_and_hms(2026, 9, 16, 0, 0, 0).unwrap(),
                refs: Vec::new(),
                payload: BTreeMap::from([("seed".to_owned(), serde_json::json!(seed))]),
                proofs: Vec::new(),
            },
            DigestSuite::Sha256,
        )
        .unwrap();
        let signer = Ed25519DetachedJwsSigner::new(
            SigningKey::from_bytes(&[9; 32]),
            "did:web:alice.example#key-1",
        );
        let request = crate::author_message(authored, &signer, SignEventOptions::new()).unwrap();
        crate::queue_authored_message(request).unwrap()
    }

    #[tokio::test]
    async fn memory_queue_preserves_fifo_submission_order() {
        let store = MemorySubmissionQueueStore::default();
        let first = queued(1);
        let second = queued(2);
        store.enqueue(first.clone()).await.unwrap();
        store.enqueue(second.clone()).await.unwrap();
        assert_eq!(store.pop_front().await.unwrap(), Some(first));
        assert_eq!(store.pop_front().await.unwrap(), Some(second));
        assert!(store.pop_front().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn replacing_an_empty_queue_fails_closed() {
        let store = MemorySubmissionQueueStore::default();
        assert!(store.replace_front(queued(1)).await.is_err());
    }
}
