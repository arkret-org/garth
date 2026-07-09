use std::future::Future;
use std::pin::Pin;

use cokret_core::{
    Did, Event, EventId, EventsSubscribeFrame, EventsSubscribeFrameKind, RealmId, Result,
};

use super::{ProjectedRunError, ProjectedRunResult};
use crate::{
    ClientEvent, ClientEventSink, ClientProjector, CursorScope, CursorStore, DecodedInbound,
    EventCacheStore, InboundDecoder, OpaqueCursor,
};

// Native builds require the boxed stream futures (and the frame source held
// across awaits) to be `Send` so that `run_realm` can be handed to
// `executor.spawn` — matching `BoxScanFuture`, `BoxSessionFuture` and the SDK
// sync loop. Wasm builds drop `Send` because browser futures are commonly
// single-threaded.
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

#[cfg(not(target_arch = "wasm32"))]
impl RealmEventsFrameSource for cokret_http_client::EventsSubscribeFrameStream {
    fn next_frame<'a>(&'a mut self) -> BoxRealmStreamFuture<'a, Option<EventsSubscribeFrame>> {
        Box::pin(async move { self.next_frame().await })
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl RealmEventsTransport for cokret_http_client::Client {
    type Source = cokret_http_client::EventsSubscribeFrameStream;

    fn open_realm_events<'a>(
        &'a self,
        realm_id: &'a RealmId,
        after: Option<&'a str>,
    ) -> BoxRealmStreamFuture<'a, Self::Source> {
        Box::pin(async move {
            let mut options = cokret_http_client::EventsSubscribeOptions::new()
                .realm(realm_id.as_str().to_owned());
            if let Some(after) = after {
                options = options.after(after.to_owned());
            }
            self.events_subscribe_frames(&options).await
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RealmStreamStopReason {
    StreamEnded,
    Dropped {
        cursor: Option<OpaqueCursor>,
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
    service_did: Option<Did>,
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
            service_did: None,
        }
    }

    pub fn with_service_did(mut self, service_did: Did) -> Self {
        self.service_did = Some(service_did);
        self
    }

    pub async fn run_realm<T, S>(
        &self,
        transport: &T,
        realm_id: RealmId,
        sink: &S,
    ) -> Result<RealmStreamStopReason>
    where
        T: RealmEventsTransport + ?Sized,
        S: ClientEventSink + ?Sized,
    {
        let scope = self.scope(&realm_id);
        let after = self.cursor_store.load(scope.clone()).await?;
        let mut source = transport
            .open_realm_events(&realm_id, after.as_deref())
            .await?;

        while let Some(frame) = source.next_frame().await? {
            let cursor = frame
                .cursor
                .as_ref()
                .map(|cursor| cursor.as_str().to_owned());
            let should_checkpoint = matches!(
                frame.kind,
                EventsSubscribeFrameKind::Event
                    | EventsSubscribeFrameKind::Heartbeat
                    | EventsSubscribeFrameKind::Frontier
                    | EventsSubscribeFrameKind::CatchupComplete
                    | EventsSubscribeFrameKind::EpochRotation
            );

            if let Some(reason) = self.handle_frame(frame, sink).await? {
                match reason {
                    RealmStreamStopReason::ResyncRequired { .. } => {
                        self.cursor_store.clear(scope.clone()).await?;
                    }
                    RealmStreamStopReason::Dropped { .. }
                    | RealmStreamStopReason::Unauthorized { .. }
                    | RealmStreamStopReason::StreamEnded => {}
                }
                return Ok(reason);
            }

            if should_checkpoint {
                if let Some(cursor) = cursor {
                    self.cursor_store.save(scope.clone(), cursor).await?;
                }
            }
        }

        Ok(RealmStreamStopReason::StreamEnded)
    }

    /// Projector-driven realm loop (orchestrator seam). Same frame handling as
    /// [`Self::run_realm`], but each decoded event batch is handed to the async
    /// [`ClientProjector`] and the cursor is checkpointed ONLY after
    /// `project` returns `Ok` — the projector's durable write gates cursor
    /// advance. `Dropped` / `Unauthorized` are returned to the caller (the
    /// facade orchestrator handles scan-backfill / refresh); `ResyncRequired`
    /// clears the cursor here.
    pub async fn run_realm_projected<T, P>(
        &self,
        transport: &T,
        realm_id: RealmId,
        projector: &P,
    ) -> Result<RealmStreamStopReason>
    where
        T: RealmEventsTransport + ?Sized,
        P: ClientProjector + ?Sized,
    {
        self.run_realm_projected_classified(transport, realm_id, projector)
            .await
            .map_err(ProjectedRunError::into_error)
    }

    pub(crate) async fn run_realm_projected_classified<T, P>(
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
        let mut source = transport
            .open_realm_events(&realm_id, after.as_deref())
            .await
            .map_err(ProjectedRunError::Transport)?;

        while let Some(frame) = source
            .next_frame()
            .await
            .map_err(ProjectedRunError::Transport)?
        {
            let cursor = frame
                .cursor
                .as_ref()
                .map(|cursor| cursor.as_str().to_owned());
            let should_checkpoint = matches!(
                frame.kind,
                EventsSubscribeFrameKind::Event
                    | EventsSubscribeFrameKind::Heartbeat
                    | EventsSubscribeFrameKind::Frontier
                    | EventsSubscribeFrameKind::CatchupComplete
                    | EventsSubscribeFrameKind::EpochRotation
            );

            match frame.kind {
                EventsSubscribeFrameKind::Event => {
                    // A malformed Event frame must not poison the stream
                    // (mirrors the sink path): skip it and let the cursor
                    // advance, otherwise every reconnect would replay the same
                    // frame and wedge realm sync permanently.
                    if let Ok(event) = serde_json::from_value::<Event>(frame.payload) {
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
                    return Ok(RealmStreamStopReason::Dropped {
                        cursor: frame.cursor.map(|cursor| cursor.as_str().to_owned()),
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
                        .get("reason")
                        .and_then(|reason| reason.as_str())
                        .map(str::to_owned);
                    return Ok(RealmStreamStopReason::Unauthorized { reason });
                }
                _ => {}
            }

            if should_checkpoint {
                if let Some(cursor) = cursor {
                    self.cursor_store
                        .save(scope.clone(), cursor)
                        .await
                        .map_err(ProjectedRunError::Store)?;
                }
            }
        }

        Ok(RealmStreamStopReason::StreamEnded)
    }

    /// Decode a wire event into the `ClientEvent`(s) a host projector consumes.
    /// Mirrors [`Self::emit_event`] — including the fault-tolerant decode: an
    /// event whose business payload is invalid degrades to a raw
    /// `ClientEvent::Event` for the host to inspect, rather than erroring the
    /// loop (which would wedge the stream on the same frame every reconnect).
    fn decode_event_batch(&self, event: Event) -> Vec<ClientEvent> {
        match self.decoder.decode_event(event) {
            DecodedInbound::Message(message) => vec![ClientEvent::Message(message)],
            DecodedInbound::Notification(notification) => {
                vec![ClientEvent::Event(notification.event)]
            }
            DecodedInbound::Event(event) => vec![ClientEvent::Event(event)],
        }
    }

    async fn handle_frame<S>(
        &self,
        frame: EventsSubscribeFrame,
        sink: &S,
    ) -> Result<Option<RealmStreamStopReason>>
    where
        S: ClientEventSink + ?Sized,
    {
        match frame.kind {
            EventsSubscribeFrameKind::Event => {
                // A malformed Event frame must not poison the stream: if the
                // payload cannot be parsed as an `Event` we skip it and let the
                // cursor advance, otherwise every reconnect would replay the same
                // frame and wedge realm sync permanently.
                match serde_json::from_value::<Event>(frame.payload) {
                    Ok(event) => {
                        if self.remember_if_new(event.event_id.clone()).await? {
                            self.emit_event(event, sink);
                        }
                    }
                    Err(_) => {
                        // Unparseable frame; drop it and continue.
                    }
                }
                Ok(None)
            }
            EventsSubscribeFrameKind::Heartbeat
            | EventsSubscribeFrameKind::Frontier
            | EventsSubscribeFrameKind::CatchupComplete
            | EventsSubscribeFrameKind::EpochRotation => Ok(None),
            EventsSubscribeFrameKind::Dropped => Ok(Some(RealmStreamStopReason::Dropped {
                cursor: frame.cursor.map(|cursor| cursor.as_str().to_owned()),
                reconnect_after_ms: frame.reconnect_after_ms,
            })),
            EventsSubscribeFrameKind::ResyncRequired => {
                Ok(Some(RealmStreamStopReason::ResyncRequired {
                    reconnect_after_ms: frame.reconnect_after_ms,
                }))
            }
            EventsSubscribeFrameKind::Unauthorized => {
                let reason = frame
                    .payload
                    .get("reason")
                    .and_then(|reason| reason.as_str())
                    .map(str::to_owned);
                Ok(Some(RealmStreamStopReason::Unauthorized { reason }))
            }
            _ => Ok(None),
        }
    }

    fn emit_event<S>(&self, event: Event, sink: &S)
    where
        S: ClientEventSink + ?Sized,
    {
        // Use the fault-tolerant decoder: an event whose business payload is
        // invalid falls back to a raw `Event` rather than aborting the stream.
        match self.decoder.decode_event(event) {
            DecodedInbound::Message(message) => sink.emit(ClientEvent::Message(message)),
            DecodedInbound::Notification(notification) => {
                sink.emit(ClientEvent::Event(notification.event));
            }
            DecodedInbound::Event(event) => sink.emit(ClientEvent::Event(event)),
        }
    }

    async fn remember_if_new(&self, event_id: EventId) -> Result<bool> {
        if self.event_cache_store.seen(event_id.clone()).await? {
            return Ok(false);
        }
        self.event_cache_store.remember(event_id).await?;
        Ok(true)
    }

    fn scope(&self, realm_id: &RealmId) -> CursorScope {
        CursorScope::RealmEvents {
            service_did: self.service_did.clone(),
            realm_id: realm_id.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    use cokret_core::events::kinds;
    use cokret_core::identifiers::Cursor;
    use cokret_core::{Did, Event, Hlc};
    use serde_json::{Value, json};

    use super::*;
    use crate::MemoryStore;
    use crate::store::CursorStore;

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
        RealmId::new("ck:realm:01904100-0000-7000-8000-000000000001").unwrap()
    }

    fn scope() -> CursorScope {
        CursorScope::RealmEvents {
            service_did: None,
            realm_id: realm_id(),
        }
    }

    fn message_event() -> Event {
        Event::new(
            kinds::MESSAGE_CREATE,
            realm_id(),
            Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
            1,
            Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
            json!({
                "content": {"kind": "ck.content.text", "body": "hello"},
                "strand_id": "ck:strand:01904100-0000-7000-8000-000000000002",
                "track_name": "discussion"
            }),
        )
        .unwrap()
    }

    fn frame(kind: EventsSubscribeFrameKind, payload: Value) -> EventsSubscribeFrame {
        EventsSubscribeFrame {
            kind,
            realm_id: Some(realm_id()),
            cursor: None,
            payload,
            reconnect_after_ms: None,
        }
    }

    #[tokio::test]
    async fn realm_driver_emits_event_frames_and_dedupes() {
        let store = MemoryStore::new();
        let event = message_event();
        let payload = serde_json::to_value(event).unwrap();
        let transport = VecTransport::new(vec![
            frame(EventsSubscribeFrameKind::Event, payload.clone()),
            frame(EventsSubscribeFrameKind::Event, payload),
        ]);
        let emitted = Arc::new(Mutex::new(0usize));
        let emitted_for_sink = Arc::clone(&emitted);
        let sink = move |event: ClientEvent| {
            if matches!(event, ClientEvent::Message(_)) {
                *emitted_for_sink.lock().unwrap() += 1;
            }
        };
        let driver = RealmEventsDriver::new(store.clone(), store);

        let reason = driver
            .run_realm(&transport, realm_id(), &sink)
            .await
            .unwrap();

        assert_eq!(reason, RealmStreamStopReason::StreamEnded);
        assert_eq!(*emitted.lock().unwrap(), 1);
    }

    #[tokio::test]
    async fn realm_driver_uses_and_saves_cursor() {
        let store = MemoryStore::new();
        store
            .save(scope(), "ck:cursor:stored".to_owned())
            .await
            .unwrap();
        let mut heartbeat = frame(EventsSubscribeFrameKind::Heartbeat, Value::Null);
        heartbeat.cursor = Some(Cursor::new("ck:cursor:frame1").unwrap());
        let transport = VecTransport::new(vec![heartbeat]);
        let driver = RealmEventsDriver::new(store.clone(), store.clone());

        let reason = driver
            .run_realm(&transport, realm_id(), &|_event: ClientEvent| {})
            .await
            .unwrap();

        assert_eq!(reason, RealmStreamStopReason::StreamEnded);
        assert_eq!(
            transport.afters(),
            vec![Some("ck:cursor:stored".to_owned())]
        );
        assert_eq!(
            store.load(scope()).await.unwrap().as_deref(),
            Some("ck:cursor:frame1")
        );
    }

    #[tokio::test]
    async fn realm_driver_clears_cursor_on_resync_required() {
        let store = MemoryStore::new();
        store
            .save(scope(), "ck:cursor:stored".to_owned())
            .await
            .unwrap();
        let mut resync = frame(EventsSubscribeFrameKind::ResyncRequired, Value::Null);
        resync.reconnect_after_ms = Some(25);
        let transport = VecTransport::new(vec![resync]);
        let driver = RealmEventsDriver::new(store.clone(), store.clone());

        let reason = driver
            .run_realm(&transport, realm_id(), &|_event: ClientEvent| {})
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
            .save(scope(), "ck:cursor:stored".to_owned())
            .await
            .unwrap();
        let mut dropped = frame(EventsSubscribeFrameKind::Dropped, Value::Null);
        dropped.cursor = Some(Cursor::new("ck:cursor:dropped").unwrap());
        dropped.reconnect_after_ms = Some(50);
        let transport = VecTransport::new(vec![dropped]);
        let driver = RealmEventsDriver::new(store.clone(), store.clone());

        let reason = driver
            .run_realm(&transport, realm_id(), &|_event: ClientEvent| {})
            .await
            .unwrap();

        assert_eq!(
            reason,
            RealmStreamStopReason::Dropped {
                cursor: Some("ck:cursor:dropped".to_owned()),
                reconnect_after_ms: Some(50)
            }
        );
        assert_eq!(
            store.load(scope()).await.unwrap().as_deref(),
            Some("ck:cursor:stored")
        );
    }

    #[tokio::test]
    async fn realm_driver_does_not_clear_cursor_on_unauthorized() {
        let store = MemoryStore::new();
        store
            .save(scope(), "ck:cursor:stored".to_owned())
            .await
            .unwrap();
        let unauthorized = frame(
            EventsSubscribeFrameKind::Unauthorized,
            json!({"reason": "revoked"}),
        );
        let transport = VecTransport::new(vec![unauthorized]);
        let driver = RealmEventsDriver::new(store.clone(), store.clone());

        let reason = driver
            .run_realm(&transport, realm_id(), &|_event: ClientEvent| {})
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
            Some("ck:cursor:stored")
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
                    Err(cokret_core::Error::Protocol("projector failed".to_owned()))
                } else {
                    Ok(())
                }
            }
        }
    }

    #[tokio::test]
    async fn realm_projected_checkpoints_only_after_project_ok() {
        let store = MemoryStore::new();
        let mut event_frame = frame(
            EventsSubscribeFrameKind::Event,
            serde_json::to_value(message_event()).unwrap(),
        );
        event_frame.cursor = Some(Cursor::new("ck:cursor:frame1").unwrap());
        let transport = VecTransport::new(vec![event_frame]);
        let projector = RecordingProjector {
            batches: Arc::new(Mutex::new(Vec::new())),
            fail: false,
        };
        let driver = RealmEventsDriver::new(store.clone(), store.clone());

        let reason = driver
            .run_realm_projected(&transport, realm_id(), &projector)
            .await
            .unwrap();

        assert_eq!(reason, RealmStreamStopReason::StreamEnded);
        // The decoded message reached the projector as a one-event batch...
        assert_eq!(projector.batches.lock().unwrap().as_slice(), &[1]);
        // ...and only then did the cursor advance.
        assert_eq!(
            store.load(scope()).await.unwrap().as_deref(),
            Some("ck:cursor:frame1")
        );
    }

    #[tokio::test]
    async fn realm_projected_redelivers_after_project_error() {
        // A transient projector failure must NOT poison dedupe: the redelivered
        // frame (cursor did not advance) must reach the projector again.
        let store = MemoryStore::new();
        let payload = serde_json::to_value(message_event()).unwrap();
        let mut event_frame = frame(EventsSubscribeFrameKind::Event, payload.clone());
        event_frame.cursor = Some(Cursor::new("ck:cursor:frame1").unwrap());
        let driver = RealmEventsDriver::new(store.clone(), store.clone());

        let failing = RecordingProjector {
            batches: Arc::new(Mutex::new(Vec::new())),
            fail: true,
        };
        let transport = VecTransport::new(vec![event_frame.clone()]);
        assert!(
            driver
                .run_realm_projected(&transport, realm_id(), &failing)
                .await
                .is_err()
        );
        assert!(store.load(scope()).await.unwrap().is_none());

        // Server redelivers the same frame on the next subscribe.
        let succeeding = RecordingProjector {
            batches: Arc::new(Mutex::new(Vec::new())),
            fail: false,
        };
        let transport = VecTransport::new(vec![event_frame]);
        let reason = driver
            .run_realm_projected(&transport, realm_id(), &succeeding)
            .await
            .unwrap();

        assert_eq!(reason, RealmStreamStopReason::StreamEnded);
        // The redelivered event was projected (not swallowed by dedupe)...
        assert_eq!(succeeding.batches.lock().unwrap().as_slice(), &[1]);
        // ...and only now does the cursor advance.
        assert_eq!(
            store.load(scope()).await.unwrap().as_deref(),
            Some("ck:cursor:frame1")
        );
    }

    #[tokio::test]
    async fn realm_projected_skips_malformed_event_frame() {
        // An unparseable Event frame must not wedge the stream: skip it and
        // let the cursor advance past it (mirrors the sink path).
        let store = MemoryStore::new();
        let mut bad_frame = frame(EventsSubscribeFrameKind::Event, json!({"not": "an event"}));
        bad_frame.cursor = Some(Cursor::new("ck:cursor:frame1").unwrap());
        let transport = VecTransport::new(vec![bad_frame]);
        let projector = RecordingProjector {
            batches: Arc::new(Mutex::new(Vec::new())),
            fail: false,
        };
        let driver = RealmEventsDriver::new(store.clone(), store.clone());

        let reason = driver
            .run_realm_projected(&transport, realm_id(), &projector)
            .await
            .unwrap();

        assert_eq!(reason, RealmStreamStopReason::StreamEnded);
        assert!(projector.batches.lock().unwrap().is_empty());
        assert_eq!(
            store.load(scope()).await.unwrap().as_deref(),
            Some("ck:cursor:frame1")
        );
    }

    #[tokio::test]
    async fn realm_projected_degrades_invalid_payload_to_raw_event() {
        // A known kind with an invalid business payload degrades to a raw
        // `ClientEvent::Event` instead of erroring the loop.
        let store = MemoryStore::new();
        let event = Event::new(
            kinds::MESSAGE_CREATE,
            realm_id(),
            Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
            1,
            Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
            json!({"content": {"kind": "ck.content.text", "body": "missing strand"}}),
        )
        .unwrap();
        let transport = VecTransport::new(vec![frame(
            EventsSubscribeFrameKind::Event,
            serde_json::to_value(event).unwrap(),
        )]);
        let projector = RecordingProjector {
            batches: Arc::new(Mutex::new(Vec::new())),
            fail: false,
        };
        let driver = RealmEventsDriver::new(store.clone(), store.clone());

        let reason = driver
            .run_realm_projected(&transport, realm_id(), &projector)
            .await
            .unwrap();

        assert_eq!(reason, RealmStreamStopReason::StreamEnded);
        assert_eq!(projector.batches.lock().unwrap().as_slice(), &[1]);
    }

    #[tokio::test]
    async fn realm_projected_does_not_checkpoint_when_project_errs() {
        let store = MemoryStore::new();
        store
            .save(scope(), "ck:cursor:stored".to_owned())
            .await
            .unwrap();
        let mut event_frame = frame(
            EventsSubscribeFrameKind::Event,
            serde_json::to_value(message_event()).unwrap(),
        );
        event_frame.cursor = Some(Cursor::new("ck:cursor:frame1").unwrap());
        let transport = VecTransport::new(vec![event_frame]);
        let projector = RecordingProjector {
            batches: Arc::new(Mutex::new(Vec::new())),
            fail: true,
        };
        let driver = RealmEventsDriver::new(store.clone(), store.clone());

        let result = driver
            .run_realm_projected(&transport, realm_id(), &projector)
            .await;

        // The projector error aborts the loop...
        assert!(result.is_err());
        // ...and the cursor stayed at its pre-frame value (the event will be
        // redelivered on the next subscribe).
        assert_eq!(
            store.load(scope()).await.unwrap().as_deref(),
            Some("ck:cursor:stored")
        );
    }
}
