use std::future::Future;
use std::pin::Pin;

use crate::protocol::{
    DidCoreId, Event, EventsSubscribeFrame, RealmId, Result, StreamTraceValidator,
};

use super::{ProjectedRunError, ProjectedRunResult};
use crate::{
    ClientEvent, ClientProjector, CursorScope, CursorStore, DurableInboxStore, EventCacheStore,
    OpaqueCursor,
};

// Native builds keep boxed stream futures (and the frame source held across
// awaits) `Send` so host runtimes can move realm loops across worker threads,
// matching `BoxScanFuture`, `BoxSessionFuture` and the SDK sync loop. Wasm
// builds drop `Send` because browser futures are commonly single-threaded.
#[cfg(not(target_arch = "wasm32"))]
pub type BoxRealmStreamFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

#[cfg(target_arch = "wasm32")]
pub type BoxRealmStreamFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + 'a>>;

#[cfg(not(target_arch = "wasm32"))]
pub trait RealmEventsFrameSource: Send {
    fn next_frame<'a>(&'a mut self) -> BoxRealmStreamFuture<'a, Option<EventsSubscribeFrame>>;
}

#[cfg(target_arch = "wasm32")]
pub trait RealmEventsFrameSource {
    fn next_frame<'a>(&'a mut self) -> BoxRealmStreamFuture<'a, Option<EventsSubscribeFrame>>;
}

pub trait RealmEventsTransport {
    #[cfg(not(target_arch = "wasm32"))]
    type Source: RealmEventsFrameSource + Send;

    #[cfg(target_arch = "wasm32")]
    type Source: RealmEventsFrameSource;

    fn open_realm_events<'a>(
        &'a self,
        realm_id: &'a RealmId,
        after: Option<&'a str>,
    ) -> BoxRealmStreamFuture<'a, Self::Source>;
}

impl RealmEventsFrameSource for arkret_http_client::EventsSubscribeFrameStream {
    fn next_frame<'a>(&'a mut self) -> BoxRealmStreamFuture<'a, Option<EventsSubscribeFrame>> {
        Box::pin(async move {
            self.next_frame()
                .await
                .map_err(crate::protocol::Error::from)
        })
    }
}

impl RealmEventsTransport for arkret_http_client::Client {
    type Source = arkret_http_client::EventsSubscribeFrameStream;

    fn open_realm_events<'a>(
        &'a self,
        realm_id: &'a RealmId,
        after: Option<&'a str>,
    ) -> BoxRealmStreamFuture<'a, Self::Source> {
        Box::pin(async move {
            // A cursorless subscribe starts at the live tail. Supplying a
            // durable cursor requests bounded catch-up from that position.
            // Keep the HTTP client's validator in agreement with the driver.
            let mut options =
                arkret_http_client::EventsSubscribeOptions::new().realm(realm_id.clone());
            if let Some(after) = after {
                options = options.after(after.to_owned()).catchup(true);
            }
            self.events_subscribe_frames(&options)
                .await
                .map_err(crate::protocol::Error::from)
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RealmStreamStopReason {
    StreamEnded,
    /// The server dropped the stream but supplied a resume position. A
    /// cursorless `dropped` frame is a trace violation (the server MUST send
    /// `resync_required` instead), so the cursor here is always present.
    Dropped {
        cursor: OpaqueCursor,
        reconnect_after_ms: Option<u64>,
    },
    ResyncRequired {
        reconnect_after_ms: Option<u64>,
    },
    Unauthorized {
        reason: Option<String>,
    },
}

#[derive(Clone, Debug)]
pub struct RealmEventsDriver<C, D> {
    cursor_store: C,
    event_cache_store: D,
    service_id: Option<DidCoreId>,
}

impl<C, D> RealmEventsDriver<C, D>
where
    C: CursorStore,
    D: EventCacheStore,
{
    pub fn new(cursor_store: C, event_cache_store: D) -> Self {
        Self {
            cursor_store,
            event_cache_store,
            service_id: None,
        }
    }

    pub fn with_service_id(mut self, service_id: DidCoreId) -> Self {
        self.service_id = Some(service_id);
        self
    }

    pub async fn run_stream<T, P>(
        &self,
        transport: &T,
        realm_id: RealmId,
        digest_suite: arkret_canonical::DigestSuite,
        projector: &P,
    ) -> Result<RealmStreamStopReason>
    where
        T: RealmEventsTransport + ?Sized,
        P: ClientProjector + ?Sized,
    {
        self.run_stream_classified(transport, realm_id, digest_suite, projector)
            .await
            .map_err(ProjectedRunError::into_error)
    }

    /// Realm subscription with atomic cursor + durable-inbox delivery.
    pub async fn run_stream_to_inbox<T>(
        &self,
        transport: &T,
        realm_id: RealmId,
        digest_suite: arkret_canonical::DigestSuite,
    ) -> Result<RealmStreamStopReason>
    where
        T: RealmEventsTransport + ?Sized,
        C: DurableInboxStore,
    {
        let scope = self.scope(&realm_id);
        let after = self.cursor_store.load(scope.clone()).await?;
        let mut trace = StreamTraceValidator::new(after.is_some(), after.clone());
        let mut source = transport
            .open_realm_events(&realm_id, after.as_deref())
            .await?;

        while let Some(frame) = source.next_frame().await? {
            let update = trace.push(&frame).map_err(crate::protocol::Error::from)?;
            let cursor = frame.cursor().map(|cursor| cursor.as_str().to_owned());
            let mut batch = Vec::new();
            let mut remember_after_commit = None;

            match frame {
                EventsSubscribeFrame::Event { payload, .. } => {
                    let event = *payload;
                    let event_id = crate::protocol::verified_event_id(&event, digest_suite)?;
                    if !self.event_cache_store.seen(event_id.clone()).await? {
                        batch = self.realm_event_batch(event, &realm_id, digest_suite);
                        remember_after_commit = Some(event_id);
                    }
                }
                EventsSubscribeFrame::Heartbeat
                | EventsSubscribeFrame::Frontier { .. }
                | EventsSubscribeFrame::CatchupComplete { .. }
                | EventsSubscribeFrame::EpochRotation { .. } => {}
                EventsSubscribeFrame::Dropped {
                    cursor,
                    reconnect_after_ms,
                    ..
                } => {
                    return Ok(RealmStreamStopReason::Dropped {
                        cursor: cursor.into_string(),
                        reconnect_after_ms,
                    });
                }
                EventsSubscribeFrame::ResyncRequired {
                    reconnect_after_ms, ..
                } => {
                    self.cursor_store.clear(scope.clone()).await?;
                    return Ok(RealmStreamStopReason::ResyncRequired { reconnect_after_ms });
                }
                EventsSubscribeFrame::Unauthorized { .. } => {
                    return Ok(RealmStreamStopReason::Unauthorized { reason: None });
                }
            }

            if update.cursor_advanced
                && !update.terminal
                && let Some(cursor) = cursor
            {
                self.cursor_store
                    .commit(scope.clone(), Some(cursor), batch)
                    .await?;
                if let Some(event_id) = remember_after_commit {
                    self.event_cache_store.remember(event_id).await?;
                }
            }
        }

        trace.finish().map_err(crate::protocol::Error::from)?;
        Ok(RealmStreamStopReason::StreamEnded)
    }

    /// Projector-driven realm loop (orchestrator seam). Each decoded event
    /// batch is handed to the async [`ClientProjector`] and the cursor is
    /// checkpointed ONLY after `project` returns `Ok` — the projector's durable
    /// write gates cursor advance. `Dropped` / `Unauthorized` are returned to
    /// the caller (the facade orchestrator handles scan-backfill / refresh);
    /// `ResyncRequired` clears the cursor here.
    pub(crate) async fn run_stream_classified<T, P>(
        &self,
        transport: &T,
        realm_id: RealmId,
        digest_suite: arkret_canonical::DigestSuite,
        projector: &P,
    ) -> ProjectedRunResult<RealmStreamStopReason>
    where
        T: RealmEventsTransport + ?Sized,
        P: ClientProjector + ?Sized,
    {
        let scope = self.scope(&realm_id);
        let after = self
            .cursor_store
            .load(scope.clone())
            .await
            .map_err(ProjectedRunError::Store)?;
        // Request-aware trace context: a cursorless Realm subscribe starts at
        // the live tail. Supplying `after` requests bounded catch-up from that
        // durable position, so only the resumed form may emit
        // `catchup_complete` after replay data.
        let mut trace = StreamTraceValidator::new(after.is_some(), after.clone());
        let mut source = transport
            .open_realm_events(&realm_id, after.as_deref())
            .await
            .map_err(ProjectedRunError::Transport)?;

        while let Some(frame) = source
            .next_frame()
            .await
            .map_err(ProjectedRunError::Transport)?
        {
            // The full trace state machine runs BEFORE any frame effect: a
            // violating frame (cursorless dropped, completion-before-delta,
            // non-catch-up completion, frame-after-terminal, …) is a protocol
            // error — never silently projected or checkpointed.
            let update = trace
                .push(&frame)
                .map_err(|error| ProjectedRunError::Transport(error.into()))?;
            let cursor = frame.cursor().map(|cursor| cursor.as_str().to_owned());

            match frame {
                EventsSubscribeFrame::Event { payload, .. } => {
                    let event = *payload;
                    match crate::protocol::verified_event_id(&event, digest_suite) {
                        Ok(event_id) => {
                            if !self
                                .event_cache_store
                                .seen(event_id.clone())
                                .await
                                .map_err(ProjectedRunError::Store)?
                            {
                                let batch = self.realm_event_batch(event, &realm_id, digest_suite);
                                if !batch.is_empty() {
                                    // Gate: project must persist before the cursor moves.
                                    projector
                                        .project(batch)
                                        .await
                                        .map_err(ProjectedRunError::Projector)?;
                                }
                                // Remember only after a successful projection: a
                                // projector error must leave BOTH the cursor and
                                // the dedupe cache untouched, so the redelivered
                                // frame is projected again instead of being
                                // silently swallowed by dedupe.
                                self.event_cache_store
                                    .remember(event_id)
                                    .await
                                    .map_err(ProjectedRunError::Store)?;
                            }
                        }
                        Err(error) => {
                            tracing::warn!(
                                %error,
                                event_id = %event.event_id,
                                realm_id = %realm_id,
                                "skipping invalid event frame while advancing its durable cursor"
                            );
                        }
                    }
                }
                EventsSubscribeFrame::Heartbeat
                | EventsSubscribeFrame::Frontier { .. }
                | EventsSubscribeFrame::CatchupComplete { .. }
                | EventsSubscribeFrame::EpochRotation { .. } => {}
                EventsSubscribeFrame::Dropped {
                    cursor,
                    reconnect_after_ms,
                    ..
                } => {
                    return Ok(RealmStreamStopReason::Dropped {
                        cursor: cursor.into_string(),
                        reconnect_after_ms,
                    });
                }
                EventsSubscribeFrame::ResyncRequired {
                    reconnect_after_ms, ..
                } => {
                    self.cursor_store
                        .clear(scope.clone())
                        .await
                        .map_err(ProjectedRunError::Store)?;
                    return Ok(RealmStreamStopReason::ResyncRequired { reconnect_after_ms });
                }
                EventsSubscribeFrame::Unauthorized { .. } => {
                    return Ok(RealmStreamStopReason::Unauthorized { reason: None });
                }
            }

            // Durable checkpoint: only frames the validator acknowledged as
            // cursor-advancing AND non-terminal (data / frontier /
            // catchup_complete) move the stored cursor. Heartbeat and
            // epoch_rotation cursors never advance the reconnect position;
            // the Dropped cursor travels in the stop reason for the
            // orchestrator's backfill decision, not into the durable store.
            if update.cursor_advanced
                && !update.terminal
                && let Some(cursor) = cursor
            {
                self.cursor_store
                    .save(scope.clone(), cursor)
                    .await
                    .map_err(ProjectedRunError::Store)?;
            }
        }

        // End-of-stream trace obligations: a catch-up subscribe that ends
        // without `catchup_complete` is an incomplete trace, not a clean end.
        trace
            .finish()
            .map_err(|error| ProjectedRunError::Transport(error.into()))?;
        Ok(RealmStreamStopReason::StreamEnded)
    }

    fn realm_event_batch(
        &self,
        event: Event,
        realm_id: &RealmId,
        digest_suite: arkret_canonical::DigestSuite,
    ) -> Vec<ClientEvent> {
        vec![ClientEvent::RealmAccepted {
            realm_id: realm_id.clone(),
            digest_suite,
            event,
        }]
    }

    fn scope(&self, realm_id: &RealmId) -> CursorScope {
        CursorScope::RealmEvents {
            service_id: self.service_id.clone(),
            realm_id: realm_id.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use arkret_models_collaboration::http_bodies::EventsSubscribeFrameKind;
    use arkret_wire::EventKind;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    use crate::protocol::identifiers::Cursor;
    use crate::protocol::{DidCoreId, Event, Hlc};
    use serde_json::{Value, json};

    use super::*;
    use crate::MemoryStore;
    use crate::store::{CursorStore, DurableInboxStore};

    struct VecFrameSource {
        frames: VecDeque<EventsSubscribeFrame>,
    }

    impl RealmEventsFrameSource for VecFrameSource {
        fn next_frame<'a>(&'a mut self) -> BoxRealmStreamFuture<'a, Option<EventsSubscribeFrame>> {
            let frame = self.frames.pop_front();
            Box::pin(async move { Ok(frame) })
        }
    }

    struct VecTransport {
        source: Mutex<Option<VecFrameSource>>,
        afters: Arc<Mutex<Vec<Option<String>>>>,
    }

    impl VecTransport {
        fn new(frames: Vec<EventsSubscribeFrame>) -> Self {
            Self {
                source: Mutex::new(Some(VecFrameSource {
                    frames: VecDeque::from(frames),
                })),
                afters: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn afters(&self) -> Vec<Option<String>> {
            self.afters.lock().unwrap().clone()
        }
    }

    impl RealmEventsTransport for VecTransport {
        type Source = VecFrameSource;

        fn open_realm_events<'a>(
            &'a self,
            _realm_id: &'a RealmId,
            after: Option<&'a str>,
        ) -> BoxRealmStreamFuture<'a, Self::Source> {
            self.afters.lock().unwrap().push(after.map(str::to_owned));
            let source = self.source.lock().unwrap().take().unwrap();
            Box::pin(async move { Ok(source) })
        }
    }

    fn realm_id() -> RealmId {
        RealmId::new("ak:realm:AfF-hFqRoMbajXkPapH-xaq0xwK-UKt2ph2zTs9JZRAO").unwrap()
    }

    fn event_actor_id() -> crate::protocol::DidCoreId {
        DidCoreId::new("ak:did_core:webvh:z6mkfixture:alice.example").unwrap()
    }

    fn scope() -> CursorScope {
        CursorScope::RealmEvents {
            service_id: None,
            realm_id: realm_id(),
        }
    }

    fn message_event() -> Event {
        accepted_event(
            arkret_wire::test_support::raw_event(
                EventKind::MessageCreate.as_str(),
                crate::protocol::ScopeRef::Realm {
                    realm_id: realm_id(),
                },
                event_actor_id(),
                DidCoreId::new("ak:did_core:web:principal.example").unwrap(),
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
            .unwrap(),
        )
    }

    fn accepted_event(mut event: Event) -> Event {
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
            producer_proof_digest:
                arkret_wire::PrincipalServerAdmissionProof::producer_proof_digest(&producer)
                    .unwrap(),
            producer_verification_method: producer.verification_method.clone(),
            producer_signing_key_did: arkret_wire::DidKey::new("did:key:z6MkhFixtureDeviceKey")
                .unwrap(),
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

    fn frame(kind: EventsSubscribeFrameKind, payload: Value) -> EventsSubscribeFrame {
        match kind {
            EventsSubscribeFrameKind::Event => EventsSubscribeFrame::Event {
                realm_id: realm_id(),
                cursor: Cursor::new("ak:cursor:frame").unwrap(),
                payload: Box::new(
                    serde_json::from_value(payload).expect("frame payload must be an Event"),
                ),
            },
            EventsSubscribeFrameKind::EpochRotation => EventsSubscribeFrame::EpochRotation {
                realm_id: realm_id(),
                payload: serde_json::from_value(payload)
                    .expect("frame payload must be an epoch rotation"),
            },
            EventsSubscribeFrameKind::Frontier => EventsSubscribeFrame::Frontier {
                cursor: Cursor::new("ak:cursor:frame").unwrap(),
            },
            EventsSubscribeFrameKind::CatchupComplete => EventsSubscribeFrame::CatchupComplete {
                cursor: Cursor::new("ak:cursor:frame").unwrap(),
            },
            EventsSubscribeFrameKind::Dropped => EventsSubscribeFrame::Dropped {
                realm_id: realm_id(),
                cursor: Cursor::new("ak:cursor:dropped").unwrap(),
                reconnect_after_ms: None,
            },
            EventsSubscribeFrameKind::ResyncRequired => EventsSubscribeFrame::ResyncRequired {
                realm_id: Some(realm_id()),
                reconnect_after_ms: None,
            },
            EventsSubscribeFrameKind::Unauthorized => EventsSubscribeFrame::Unauthorized {
                realm_id: Some(realm_id()),
            },
            EventsSubscribeFrameKind::Heartbeat => EventsSubscribeFrame::Heartbeat,
            _ => panic!("unsupported test frame kind {kind:?}"),
        }
    }

    fn cursor_frame(
        kind: EventsSubscribeFrameKind,
        payload: Value,
        cursor: &str,
    ) -> EventsSubscribeFrame {
        let cursor = Cursor::new(cursor).unwrap();
        match kind {
            EventsSubscribeFrameKind::Event => EventsSubscribeFrame::Event {
                realm_id: realm_id(),
                cursor,
                payload: Box::new(
                    serde_json::from_value(payload).expect("frame payload must be an Event"),
                ),
            },
            EventsSubscribeFrameKind::Frontier => EventsSubscribeFrame::Frontier { cursor },
            EventsSubscribeFrameKind::CatchupComplete => {
                EventsSubscribeFrame::CatchupComplete { cursor }
            }
            EventsSubscribeFrameKind::Dropped => EventsSubscribeFrame::Dropped {
                realm_id: realm_id(),
                cursor,
                reconnect_after_ms: None,
            },
            _ => panic!("{kind:?} is not cursor-bearing"),
        }
    }

    fn resync_frame(reconnect_after_ms: Option<u64>) -> EventsSubscribeFrame {
        EventsSubscribeFrame::ResyncRequired {
            realm_id: Some(realm_id()),
            reconnect_after_ms,
        }
    }

    fn dropped_frame(cursor: &str, reconnect_after_ms: Option<u64>) -> EventsSubscribeFrame {
        EventsSubscribeFrame::Dropped {
            realm_id: realm_id(),
            cursor: Cursor::new(cursor).unwrap(),
            reconnect_after_ms,
        }
    }

    #[tokio::test]
    async fn realm_driver_emits_event_frames_and_dedupes() {
        let store = MemoryStore::new();
        store
            .save(scope(), "ak:cursor:stored".to_owned())
            .await
            .unwrap();
        let event = message_event();
        let payload = serde_json::to_value(event).unwrap();
        // A resumed subscribe is a bounded catch-up and must end with a
        // cursor-bearing catchup_complete.
        let transport = VecTransport::new(vec![
            cursor_frame(
                EventsSubscribeFrameKind::Event,
                payload.clone(),
                "ak:cursor:frame1",
            ),
            cursor_frame(EventsSubscribeFrameKind::Event, payload, "ak:cursor:frame2"),
            cursor_frame(
                EventsSubscribeFrameKind::CatchupComplete,
                Value::Null,
                "ak:cursor:frame2",
            ),
        ]);
        let projector = RecordingProjector {
            batches: Arc::new(Mutex::new(Vec::new())),
            fail: false,
        };
        let driver = RealmEventsDriver::new(store.clone(), store);

        let reason = driver
            .run_stream(
                &transport,
                realm_id(),
                arkret_canonical::DigestSuite::Sha256,
                &projector,
            )
            .await
            .unwrap();

        assert_eq!(reason, RealmStreamStopReason::StreamEnded);
        assert_eq!(projector.batches.lock().unwrap().as_slice(), &[1]);
    }

    #[tokio::test]
    async fn realm_driver_commits_event_and_cursor_to_inbox() {
        let store = MemoryStore::new();
        let transport = VecTransport::new(vec![cursor_frame(
            EventsSubscribeFrameKind::Event,
            serde_json::to_value(message_event()).unwrap(),
            "ak:cursor:frame1",
        )]);
        let driver = RealmEventsDriver::new(store.clone(), store.clone());

        let reason = driver
            .run_stream_to_inbox(
                &transport,
                realm_id(),
                arkret_canonical::DigestSuite::Sha256,
            )
            .await
            .unwrap();

        assert_eq!(reason, RealmStreamStopReason::StreamEnded);
        assert_eq!(
            store.load(scope()).await.unwrap().as_deref(),
            Some("ak:cursor:frame1")
        );
        let pending = store.pending(10).await.unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].cursor.as_deref(), Some("ak:cursor:frame1"));
        assert_eq!(pending[0].events.len(), 1);
    }

    #[tokio::test]
    async fn realm_driver_saves_data_cursor_but_never_heartbeat_cursor() {
        let store = MemoryStore::new();
        // transport-bindings.md §1.1 rule 3: heartbeat has no cursor in the
        // closed frame union; frontier is cursor-bearing and does advance.
        let heartbeat = frame(EventsSubscribeFrameKind::Heartbeat, Value::Null);
        let frontier = cursor_frame(
            EventsSubscribeFrameKind::Frontier,
            Value::Null,
            "ak:cursor:frontier",
        );
        let transport = VecTransport::new(vec![heartbeat, frontier]);
        let driver = RealmEventsDriver::new(store.clone(), store.clone());
        let projector = RecordingProjector {
            batches: Arc::new(Mutex::new(Vec::new())),
            fail: false,
        };

        let reason = driver
            .run_stream(
                &transport,
                realm_id(),
                arkret_canonical::DigestSuite::Sha256,
                &projector,
            )
            .await
            .unwrap();

        assert_eq!(reason, RealmStreamStopReason::StreamEnded);
        assert_eq!(transport.afters(), vec![None]);
        assert_eq!(
            store.load(scope()).await.unwrap().as_deref(),
            Some("ak:cursor:frontier")
        );
    }

    #[tokio::test]
    async fn realm_driver_clears_cursor_on_resync_required() {
        let store = MemoryStore::new();
        store
            .save(scope(), "ak:cursor:stored".to_owned())
            .await
            .unwrap();
        let resync = resync_frame(Some(25));
        let transport = VecTransport::new(vec![resync]);
        let driver = RealmEventsDriver::new(store.clone(), store.clone());
        let projector = RecordingProjector {
            batches: Arc::new(Mutex::new(Vec::new())),
            fail: false,
        };

        let reason = driver
            .run_stream(
                &transport,
                realm_id(),
                arkret_canonical::DigestSuite::Sha256,
                &projector,
            )
            .await
            .unwrap();

        assert_eq!(
            reason,
            RealmStreamStopReason::ResyncRequired {
                reconnect_after_ms: Some(25)
            }
        );
        assert!(store.load(scope()).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn realm_driver_does_not_checkpoint_dropped_cursor() {
        let store = MemoryStore::new();
        store
            .save(scope(), "ak:cursor:stored".to_owned())
            .await
            .unwrap();
        let dropped = dropped_frame("ak:cursor:dropped", Some(50));
        let transport = VecTransport::new(vec![dropped]);
        let driver = RealmEventsDriver::new(store.clone(), store.clone());
        let projector = RecordingProjector {
            batches: Arc::new(Mutex::new(Vec::new())),
            fail: false,
        };

        let reason = driver
            .run_stream(
                &transport,
                realm_id(),
                arkret_canonical::DigestSuite::Sha256,
                &projector,
            )
            .await
            .unwrap();

        assert_eq!(
            reason,
            RealmStreamStopReason::Dropped {
                cursor: "ak:cursor:dropped".to_owned(),
                reconnect_after_ms: Some(50)
            }
        );
        assert_eq!(
            store.load(scope()).await.unwrap().as_deref(),
            Some("ak:cursor:stored")
        );
    }

    #[test]
    fn realm_frame_shape_rejects_cursorless_dropped() {
        let malformed = json!({
            "kind": "dropped",
            "realm_id": realm_id(),
            "reconnect_after_ms": 50
        });
        assert!(serde_json::from_value::<EventsSubscribeFrame>(malformed).is_err());
    }

    #[tokio::test]
    async fn realm_driver_rejects_completion_before_baseline_delta() {
        // A resumed catch-up subscribe: `catchup_complete` before the
        // first data frame is a trace violation.
        let store = MemoryStore::new();
        store
            .save(scope(), "ak:cursor:stored".to_owned())
            .await
            .unwrap();
        let transport = VecTransport::new(vec![cursor_frame(
            EventsSubscribeFrameKind::CatchupComplete,
            Value::Null,
            "ak:cursor:frame1",
        )]);
        let driver = RealmEventsDriver::new(store.clone(), store.clone());
        let projector = RecordingProjector {
            batches: Arc::new(Mutex::new(Vec::new())),
            fail: false,
        };

        let error = driver
            .run_stream(
                &transport,
                realm_id(),
                arkret_canonical::DigestSuite::Sha256,
                &projector,
            )
            .await
            .unwrap_err();

        assert!(error.to_string().contains("catchup_complete_before_delta"));
        assert_eq!(
            store.load(scope()).await.unwrap().as_deref(),
            Some("ak:cursor:stored")
        );
    }

    #[tokio::test]
    async fn realm_driver_rejects_completion_on_non_catchup_subscribe() {
        // A cursorless request starts at the live tail, so `catchup_complete`
        // is forbidden.
        let store = MemoryStore::new();
        let transport = VecTransport::new(vec![cursor_frame(
            EventsSubscribeFrameKind::CatchupComplete,
            Value::Null,
            "ak:cursor:frame1",
        )]);
        let driver = RealmEventsDriver::new(store.clone(), store.clone());
        let projector = RecordingProjector {
            batches: Arc::new(Mutex::new(Vec::new())),
            fail: false,
        };

        let error = driver
            .run_stream(
                &transport,
                realm_id(),
                arkret_canonical::DigestSuite::Sha256,
                &projector,
            )
            .await
            .unwrap_err();

        assert!(error.to_string().contains("unexpected_catchup_complete"));
        assert!(store.load(scope()).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn realm_driver_rejects_catchup_stream_that_ends_without_completion() {
        let store = MemoryStore::new();
        store
            .save(scope(), "ak:cursor:stored".to_owned())
            .await
            .unwrap();
        let transport = VecTransport::new(vec![cursor_frame(
            EventsSubscribeFrameKind::Event,
            serde_json::to_value(message_event()).unwrap(),
            "ak:cursor:frame1",
        )]);
        let driver = RealmEventsDriver::new(store.clone(), store.clone());
        let projector = RecordingProjector {
            batches: Arc::new(Mutex::new(Vec::new())),
            fail: false,
        };

        let error = driver
            .run_stream(
                &transport,
                realm_id(),
                arkret_canonical::DigestSuite::Sha256,
                &projector,
            )
            .await
            .unwrap_err();

        assert!(error.to_string().contains("catchup_incomplete"));
    }

    #[tokio::test]
    async fn realm_driver_does_not_clear_cursor_on_unauthorized() {
        let store = MemoryStore::new();
        store
            .save(scope(), "ak:cursor:stored".to_owned())
            .await
            .unwrap();
        let unauthorized = frame(EventsSubscribeFrameKind::Unauthorized, Value::Null);
        let transport = VecTransport::new(vec![unauthorized]);
        let driver = RealmEventsDriver::new(store.clone(), store.clone());
        let projector = RecordingProjector {
            batches: Arc::new(Mutex::new(Vec::new())),
            fail: false,
        };

        let reason = driver
            .run_stream(
                &transport,
                realm_id(),
                arkret_canonical::DigestSuite::Sha256,
                &projector,
            )
            .await
            .unwrap();

        assert_eq!(reason, RealmStreamStopReason::Unauthorized { reason: None });
        assert_eq!(
            store.load(scope()).await.unwrap().as_deref(),
            Some("ak:cursor:stored")
        );
    }

    struct RecordingProjector {
        batches: Arc<Mutex<Vec<usize>>>,
        fail: bool,
    }

    impl crate::ClientProjector for RecordingProjector {
        fn project(
            &self,
            batch: Vec<ClientEvent>,
        ) -> impl std::future::Future<Output = Result<()>> + '_ {
            let batches = Arc::clone(&self.batches);
            let fail = self.fail;
            async move {
                batches.lock().unwrap().push(batch.len());
                if fail {
                    Err(crate::protocol::Error::Protocol(
                        "projector failed".to_owned(),
                    ))
                } else {
                    Ok(())
                }
            }
        }
    }

    #[tokio::test]
    async fn realm_projected_checkpoints_only_after_project_ok() {
        let store = MemoryStore::new();
        store
            .save(scope(), "ak:cursor:stored".to_owned())
            .await
            .unwrap();
        let event_frame = cursor_frame(
            EventsSubscribeFrameKind::Event,
            serde_json::to_value(message_event()).unwrap(),
            "ak:cursor:frame1",
        );
        let completion = cursor_frame(
            EventsSubscribeFrameKind::CatchupComplete,
            Value::Null,
            "ak:cursor:frame1",
        );
        let transport = VecTransport::new(vec![event_frame, completion]);
        let projector = RecordingProjector {
            batches: Arc::new(Mutex::new(Vec::new())),
            fail: false,
        };
        let driver = RealmEventsDriver::new(store.clone(), store.clone());

        let reason = driver
            .run_stream(
                &transport,
                realm_id(),
                arkret_canonical::DigestSuite::Sha256,
                &projector,
            )
            .await
            .unwrap();

        assert_eq!(reason, RealmStreamStopReason::StreamEnded);
        // The decoded message reached the projector as a one-event batch...
        assert_eq!(projector.batches.lock().unwrap().as_slice(), &[1]);
        // ...and only then did the cursor advance.
        assert_eq!(
            store.load(scope()).await.unwrap().as_deref(),
            Some("ak:cursor:frame1")
        );
    }

    #[tokio::test]
    async fn realm_projected_redelivers_after_project_error() {
        // A transient projector failure must NOT poison dedupe: the redelivered
        // frame (cursor did not advance) must reach the projector again.
        let store = MemoryStore::new();
        store
            .save(scope(), "ak:cursor:stored".to_owned())
            .await
            .unwrap();
        let payload = serde_json::to_value(message_event()).unwrap();
        let event_frame = cursor_frame(
            EventsSubscribeFrameKind::Event,
            payload.clone(),
            "ak:cursor:frame1",
        );
        let driver = RealmEventsDriver::new(store.clone(), store.clone());

        let completion = cursor_frame(
            EventsSubscribeFrameKind::CatchupComplete,
            Value::Null,
            "ak:cursor:frame1",
        );
        let failing = RecordingProjector {
            batches: Arc::new(Mutex::new(Vec::new())),
            fail: true,
        };
        let transport = VecTransport::new(vec![event_frame.clone(), completion.clone()]);
        assert!(
            driver
                .run_stream(
                    &transport,
                    realm_id(),
                    arkret_canonical::DigestSuite::Sha256,
                    &failing,
                )
                .await
                .is_err()
        );
        assert_eq!(
            store.load(scope()).await.unwrap().as_deref(),
            Some("ak:cursor:stored")
        );

        // Server redelivers the same frame on the next subscribe.
        let succeeding = RecordingProjector {
            batches: Arc::new(Mutex::new(Vec::new())),
            fail: false,
        };
        let transport = VecTransport::new(vec![event_frame, completion]);
        let reason = driver
            .run_stream(
                &transport,
                realm_id(),
                arkret_canonical::DigestSuite::Sha256,
                &succeeding,
            )
            .await
            .unwrap();

        assert_eq!(reason, RealmStreamStopReason::StreamEnded);
        // The redelivered event was projected (not swallowed by dedupe)...
        assert_eq!(succeeding.batches.lock().unwrap().as_slice(), &[1]);
        // ...and only now does the cursor advance.
        assert_eq!(
            store.load(scope()).await.unwrap().as_deref(),
            Some("ak:cursor:frame1")
        );
    }

    #[test]
    fn realm_frame_shape_rejects_malformed_event_payload() {
        let malformed = json!({
            "kind": "event",
            "realm_id": realm_id(),
            "cursor": "ak:cursor:frame1",
            "payload": {"not": "an event"}
        });
        assert!(serde_json::from_value::<EventsSubscribeFrame>(malformed).is_err());
    }

    #[tokio::test]
    async fn realm_projected_degrades_invalid_payload_to_raw_event() {
        // A known kind with an invalid business payload degrades to a raw
        // `ClientEvent::Event` instead of erroring the loop.
        let store = MemoryStore::new();
        let event = accepted_event(
            arkret_wire::test_support::raw_event(
                EventKind::MessageCreate.as_str(),
                crate::protocol::ScopeRef::Realm {
                    realm_id: realm_id(),
                },
                event_actor_id(),
                DidCoreId::new("ak:did_core:web:principal.example").unwrap(),
                1,
                Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
                json!({"content": {"kind": "ak.content.text", "body": "missing strand"}}),
            )
            .unwrap(),
        );
        store
            .save(scope(), "ak:cursor:stored".to_owned())
            .await
            .unwrap();
        let transport = VecTransport::new(vec![
            cursor_frame(
                EventsSubscribeFrameKind::Event,
                serde_json::to_value(event).unwrap(),
                "ak:cursor:frame1",
            ),
            cursor_frame(
                EventsSubscribeFrameKind::CatchupComplete,
                Value::Null,
                "ak:cursor:frame1",
            ),
        ]);
        let projector = RecordingProjector {
            batches: Arc::new(Mutex::new(Vec::new())),
            fail: false,
        };
        let driver = RealmEventsDriver::new(store.clone(), store.clone());

        let reason = driver
            .run_stream(
                &transport,
                realm_id(),
                arkret_canonical::DigestSuite::Sha256,
                &projector,
            )
            .await
            .unwrap();

        assert_eq!(reason, RealmStreamStopReason::StreamEnded);
        assert_eq!(projector.batches.lock().unwrap().as_slice(), &[1]);
    }

    #[tokio::test]
    async fn realm_projected_does_not_checkpoint_when_project_errs() {
        let store = MemoryStore::new();
        store
            .save(scope(), "ak:cursor:stored".to_owned())
            .await
            .unwrap();
        let event_frame = cursor_frame(
            EventsSubscribeFrameKind::Event,
            serde_json::to_value(message_event()).unwrap(),
            "ak:cursor:frame1",
        );
        let transport = VecTransport::new(vec![event_frame]);
        let projector = RecordingProjector {
            batches: Arc::new(Mutex::new(Vec::new())),
            fail: true,
        };
        let driver = RealmEventsDriver::new(store.clone(), store.clone());

        let result = driver
            .run_stream(
                &transport,
                realm_id(),
                arkret_canonical::DigestSuite::Sha256,
                &projector,
            )
            .await;

        // The projector error aborts the loop...
        assert!(result.is_err());
        // ...and the cursor stayed at its pre-frame value (the event will be
        // redelivered on the next subscribe).
        assert_eq!(
            store.load(scope()).await.unwrap().as_deref(),
            Some("ak:cursor:stored")
        );
    }
}
