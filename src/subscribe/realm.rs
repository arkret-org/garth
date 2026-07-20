use std::future::Future;
use std::pin::Pin;

use crate::protocol::{
    Did, Event, EventsSubscribeFrame, EventsSubscribeFrameKind, RealmId, Result,
    StreamTraceValidator,
};

use super::{ProjectedRunError, ProjectedRunResult};
use crate::{
    ClientEvent, ClientProjector, CursorScope, CursorStore, DecodedInbound, DurableInboxStore,
    EventCacheStore, InboundDecoder, OpaqueCursor,
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
            let mut options = arkret_http_client::EventsSubscribeOptions::new()
                .realm(realm_id.as_str().to_owned());
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
    decoder: InboundDecoder,
    service_id: Option<Did>,
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
            decoder: InboundDecoder::new(),
            service_id: None,
        }
    }

    pub fn with_service_id(mut self, service_id: Did) -> Self {
        self.service_id = Some(service_id);
        self
    }

    pub async fn run_stream<T, P>(
        &self,
        transport: &T,
        realm_id: RealmId,
        projector: &P,
    ) -> Result<RealmStreamStopReason>
    where
        T: RealmEventsTransport + ?Sized,
        P: ClientProjector + ?Sized,
    {
        self.run_stream_classified(transport, realm_id, projector)
            .await
            .map_err(ProjectedRunError::into_error)
    }

    /// Realm subscription with atomic cursor + durable-inbox delivery.
    pub async fn run_stream_to_inbox<T>(
        &self,
        transport: &T,
        realm_id: RealmId,
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
            let cursor = frame
                .cursor
                .as_ref()
                .map(|cursor| cursor.as_str().to_owned());
            let mut batch = Vec::new();
            let mut remember_after_commit = None;

            match frame.kind {
                EventsSubscribeFrameKind::Event => {
                    if let Some(payload) = frame.payload
                        && let Ok(event) = serde_json::from_value::<Event>(
                            serde_json::Value::Object(payload.into_iter().collect()),
                        )
                    {
                        let event_id = event.event_id.clone();
                        if !self.event_cache_store.seen(event_id.clone()).await? {
                            batch = self.decode_event_batch(event);
                            remember_after_commit = Some(event_id);
                        }
                    }
                }
                EventsSubscribeFrameKind::Heartbeat
                | EventsSubscribeFrameKind::Frontier
                | EventsSubscribeFrameKind::CatchupComplete
                | EventsSubscribeFrameKind::EpochRotation => {}
                EventsSubscribeFrameKind::Dropped => {
                    let Some(cursor) = cursor else {
                        return Err(crate::protocol::Error::Protocol(
                            "dropped frame passed trace validation without a cursor".to_owned(),
                        ));
                    };
                    return Ok(RealmStreamStopReason::Dropped {
                        cursor,
                        reconnect_after_ms: frame.reconnect_after_ms,
                    });
                }
                EventsSubscribeFrameKind::ResyncRequired => {
                    self.cursor_store.clear(scope.clone()).await?;
                    return Ok(RealmStreamStopReason::ResyncRequired {
                        reconnect_after_ms: frame.reconnect_after_ms,
                    });
                }
                EventsSubscribeFrameKind::Unauthorized => {
                    let reason = frame
                        .payload
                        .as_ref()
                        .and_then(|payload| payload.get("reason"))
                        .and_then(|reason| reason.as_str())
                        .map(str::to_owned);
                    return Ok(RealmStreamStopReason::Unauthorized { reason });
                }
                _ => {}
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
            let cursor = frame
                .cursor
                .as_ref()
                .map(|cursor| cursor.as_str().to_owned());

            match frame.kind {
                EventsSubscribeFrameKind::Event => {
                    // A malformed Event frame must not poison the stream
                    // Skip it and let the cursor advance, otherwise every
                    // reconnect would replay the same frame and wedge realm
                    // sync permanently.
                    if let Some(payload) = frame.payload
                        && let Ok(event) = serde_json::from_value::<Event>(
                            serde_json::Value::Object(payload.into_iter().collect()),
                        )
                    {
                        let event_id = event.event_id.clone();
                        if !self
                            .event_cache_store
                            .seen(event_id.clone())
                            .await
                            .map_err(ProjectedRunError::Store)?
                        {
                            let batch = self.decode_event_batch(event);
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
                }
                EventsSubscribeFrameKind::Heartbeat
                | EventsSubscribeFrameKind::Frontier
                | EventsSubscribeFrameKind::CatchupComplete
                | EventsSubscribeFrameKind::EpochRotation => {}
                EventsSubscribeFrameKind::Dropped => {
                    // The validator already rejected a cursorless dropped
                    // frame (the server MUST use `resync_required` instead),
                    // so the cursor is guaranteed here.
                    let Some(cursor) = cursor else {
                        return Err(ProjectedRunError::Transport(
                            crate::protocol::Error::Protocol(
                                "dropped frame passed trace validation without a cursor".to_owned(),
                            ),
                        ));
                    };
                    return Ok(RealmStreamStopReason::Dropped {
                        cursor,
                        reconnect_after_ms: frame.reconnect_after_ms,
                    });
                }
                EventsSubscribeFrameKind::ResyncRequired => {
                    self.cursor_store
                        .clear(scope.clone())
                        .await
                        .map_err(ProjectedRunError::Store)?;
                    return Ok(RealmStreamStopReason::ResyncRequired {
                        reconnect_after_ms: frame.reconnect_after_ms,
                    });
                }
                EventsSubscribeFrameKind::Unauthorized => {
                    let reason = frame
                        .payload
                        .as_ref()
                        .and_then(|payload| payload.get("reason"))
                        .and_then(|reason| reason.as_str())
                        .map(str::to_owned);
                    return Ok(RealmStreamStopReason::Unauthorized { reason });
                }
                _ => {}
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

    /// Decode a wire event into the `ClientEvent`(s) a host projector consumes.
    /// Fault-tolerant decode: an event whose business payload is invalid
    /// degrades to a raw `ClientEvent::Event` for the host to inspect, rather
    /// than erroring the loop (which would wedge the stream on the same frame
    /// every reconnect).
    fn decode_event_batch(&self, event: Event) -> Vec<ClientEvent> {
        match self.decoder.decode_event(event) {
            DecodedInbound::Message(message) => vec![ClientEvent::Message(*message)],
            DecodedInbound::Event(event) => vec![ClientEvent::Event(*event)],
        }
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
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    use crate::protocol::identifiers::Cursor;
    use crate::protocol::{Did, Event, Hlc};
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
        RealmId::new("ak:realm:01904100-0000-7000-8000-000000000001").unwrap()
    }

    fn scope() -> CursorScope {
        CursorScope::RealmEvents {
            service_id: None,
            realm_id: realm_id(),
        }
    }

    fn message_event() -> Event {
        Event::new(
            crate::protocol::events::EventKind::MESSAGE_CREATE,
            realm_id(),
            Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
            1,
            Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
            json!({
                "content": {"kind": "ak.content.text", "body": "hello"},
                "strand_id": "ak:strand:01904100-0000-7000-8000-000000000002",
                "track_name": "discussion"
            }),
        )
        .unwrap()
    }

    fn frame(kind: EventsSubscribeFrameKind, payload: Value) -> EventsSubscribeFrame {
        let payload = if payload.is_null() {
            None
        } else {
            Some(serde_json::from_value(payload).expect("frame payload must be an object"))
        };
        EventsSubscribeFrame {
            kind,
            realm_id: Some(realm_id()),
            cursor: None,
            payload,
            reconnect_after_ms: None,
        }
    }

    fn cursor_frame(
        kind: EventsSubscribeFrameKind,
        payload: Value,
        cursor: &str,
    ) -> EventsSubscribeFrame {
        let mut framed = frame(kind, payload);
        framed.cursor = Some(Cursor::new(cursor).unwrap());
        framed
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
            .run_stream(&transport, realm_id(), &projector)
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
            .run_stream_to_inbox(&transport, realm_id())
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
        // transport-bindings.md §1.1 rule 3: heartbeat MUST NOT advance the
        // reconnect position even when it (illegally) carries a cursor;
        // frontier is cursor-bearing and does advance.
        let mut heartbeat = frame(EventsSubscribeFrameKind::Heartbeat, Value::Null);
        heartbeat.cursor = Some(Cursor::new("ak:cursor:heartbeat").unwrap());
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
            .run_stream(&transport, realm_id(), &projector)
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
        let mut resync = frame(EventsSubscribeFrameKind::ResyncRequired, Value::Null);
        resync.reconnect_after_ms = Some(25);
        let transport = VecTransport::new(vec![resync]);
        let driver = RealmEventsDriver::new(store.clone(), store.clone());
        let projector = RecordingProjector {
            batches: Arc::new(Mutex::new(Vec::new())),
            fail: false,
        };

        let reason = driver
            .run_stream(&transport, realm_id(), &projector)
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
        let mut dropped = frame(EventsSubscribeFrameKind::Dropped, Value::Null);
        dropped.cursor = Some(Cursor::new("ak:cursor:dropped").unwrap());
        dropped.reconnect_after_ms = Some(50);
        let transport = VecTransport::new(vec![dropped]);
        let driver = RealmEventsDriver::new(store.clone(), store.clone());
        let projector = RecordingProjector {
            batches: Arc::new(Mutex::new(Vec::new())),
            fail: false,
        };

        let reason = driver
            .run_stream(&transport, realm_id(), &projector)
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

    #[tokio::test]
    async fn realm_driver_rejects_cursorless_dropped_as_protocol_error() {
        // transport-bindings.md §1.1 rule 2: a `dropped` frame MUST carry a
        // cursor; the server signals a lost position with `resync_required`.
        let store = MemoryStore::new();
        store
            .save(scope(), "ak:cursor:stored".to_owned())
            .await
            .unwrap();
        let mut dropped = frame(EventsSubscribeFrameKind::Dropped, Value::Null);
        dropped.reconnect_after_ms = Some(50);
        let transport = VecTransport::new(vec![dropped]);
        let driver = RealmEventsDriver::new(store.clone(), store.clone());
        let projector = RecordingProjector {
            batches: Arc::new(Mutex::new(Vec::new())),
            fail: false,
        };

        let error = driver
            .run_stream(&transport, realm_id(), &projector)
            .await
            .unwrap_err();

        assert!(error.to_string().contains("dropped_missing_cursor"));
        // The stored reconnect position is untouched by the rejected trace.
        assert_eq!(
            store.load(scope()).await.unwrap().as_deref(),
            Some("ak:cursor:stored")
        );
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
            .run_stream(&transport, realm_id(), &projector)
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
            .run_stream(&transport, realm_id(), &projector)
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
            .run_stream(&transport, realm_id(), &projector)
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
        let unauthorized = frame(
            EventsSubscribeFrameKind::Unauthorized,
            json!({"reason": "revoked"}),
        );
        let transport = VecTransport::new(vec![unauthorized]);
        let driver = RealmEventsDriver::new(store.clone(), store.clone());
        let projector = RecordingProjector {
            batches: Arc::new(Mutex::new(Vec::new())),
            fail: false,
        };

        let reason = driver
            .run_stream(&transport, realm_id(), &projector)
            .await
            .unwrap();

        assert_eq!(
            reason,
            RealmStreamStopReason::Unauthorized {
                reason: Some("revoked".to_owned())
            }
        );
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
        let mut event_frame = frame(
            EventsSubscribeFrameKind::Event,
            serde_json::to_value(message_event()).unwrap(),
        );
        event_frame.cursor = Some(Cursor::new("ak:cursor:frame1").unwrap());
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
            .run_stream(&transport, realm_id(), &projector)
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
        let mut event_frame = frame(EventsSubscribeFrameKind::Event, payload.clone());
        event_frame.cursor = Some(Cursor::new("ak:cursor:frame1").unwrap());
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
                .run_stream(&transport, realm_id(), &failing)
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
            .run_stream(&transport, realm_id(), &succeeding)
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

    #[tokio::test]
    async fn realm_projected_skips_malformed_event_frame() {
        // An unparseable Event frame must not wedge the stream: skip it and
        // let the cursor advance past it.
        let store = MemoryStore::new();
        store
            .save(scope(), "ak:cursor:stored".to_owned())
            .await
            .unwrap();
        let mut bad_frame = frame(EventsSubscribeFrameKind::Event, json!({"not": "an event"}));
        bad_frame.cursor = Some(Cursor::new("ak:cursor:frame1").unwrap());
        let transport = VecTransport::new(vec![
            bad_frame,
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
            .run_stream(&transport, realm_id(), &projector)
            .await
            .unwrap();

        assert_eq!(reason, RealmStreamStopReason::StreamEnded);
        assert!(projector.batches.lock().unwrap().is_empty());
        assert_eq!(
            store.load(scope()).await.unwrap().as_deref(),
            Some("ak:cursor:frame1")
        );
    }

    #[tokio::test]
    async fn realm_projected_degrades_invalid_payload_to_raw_event() {
        // A known kind with an invalid business payload degrades to a raw
        // `ClientEvent::Event` instead of erroring the loop.
        let store = MemoryStore::new();
        let event = Event::new(
            crate::protocol::events::EventKind::MESSAGE_CREATE,
            realm_id(),
            Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
            1,
            Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
            json!({"content": {"kind": "ak.content.text", "body": "missing strand"}}),
        )
        .unwrap();
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
            .run_stream(&transport, realm_id(), &projector)
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
        let mut event_frame = frame(
            EventsSubscribeFrameKind::Event,
            serde_json::to_value(message_event()).unwrap(),
        );
        event_frame.cursor = Some(Cursor::new("ak:cursor:frame1").unwrap());
        let transport = VecTransport::new(vec![event_frame]);
        let projector = RecordingProjector {
            batches: Arc::new(Mutex::new(Vec::new())),
            fail: true,
        };
        let driver = RealmEventsDriver::new(store.clone(), store.clone());

        let result = driver.run_stream(&transport, realm_id(), &projector).await;

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
