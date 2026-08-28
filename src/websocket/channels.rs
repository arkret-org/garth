//! The three channel adapters.
//!
//! Each one satisfies the transport seam its existing driver already uses, so
//! switching a stream to the WebSocket binding changes which value is handed
//! to the driver and nothing else. No driver, projection, cursor rule or
//! Signal admission check is duplicated here.

use std::collections::VecDeque;

use arkret_models_collaboration::sync_frames::account_subscribe::{
    AccountSubscribeBatch, AccountSubscribeFrame,
};
use arkret_models_collaboration::sync_frames::client_sync::SyncRequestBody;
use arkret_models_collaboration::sync_frames::websocket_binding::{
    WebSocketAccountOpenParameters, WebSocketChannelControlPayload, WebSocketDataPayload,
    WebSocketEventsOpenParameters, WebSocketOpenParameters,
};
use arkret_wire::{Cursor, RealmId, SignalStreamFrame};

use crate::protocol::{Error, Result};
use crate::subscribe::realm::{BoxRealmStreamFuture, RealmEventsFrameSource, RealmEventsTransport};
use crate::subscribe::signal::{
    BoxSignalStreamFuture, SignalStreamFrameSource, SignalStreamTransport,
};
use crate::sync_client::{AsyncSyncTransport, BoxSyncFuture};

use super::connection::{ChannelFrame, WebSocketChannelState};
use super::shared::SharedCell;
use super::socket::WebSocketPacer;

// garth has no cross-task notification primitive that works on both targets,
// and adding one would mean a runtime dependency. An adapter therefore
// re-checks its queue on the host's own cadence
// ([`WebSocketPacer`](super::socket::WebSocketPacer)); the pump loop is never
// delayed by it.

/// The connection state shared between the pump loop and the adapters.
///
/// The socket is deliberately not part of it: see
/// [`WebSocketConnection`](super::connection::WebSocketConnection).
pub type SharedConnection = SharedCell<WebSocketChannelState>;

/// The three channels of one connection, handed to the existing drivers.
pub struct WebSocketTransport<E> {
    connection: SharedConnection,
    pacer: E,
}

impl<E> WebSocketTransport<E>
where
    E: WebSocketPacer,
{
    pub fn new(connection: SharedConnection, pacer: E) -> Self {
        Self { connection, pacer }
    }

    pub fn connection(&self) -> SharedConnection {
        self.connection.clone()
    }

    /// Open the account channel and return the seam `SyncLoop` already drives.
    pub fn open_account(&self, after: Option<&str>) -> Result<WebSocketAccountChannel<E>> {
        let parameters = WebSocketOpenParameters::Account(WebSocketAccountOpenParameters {
            after: after
                .map(|value| Cursor::new(value.to_owned()))
                .transpose()?,
            // §6.1 — a resume cursor asks for bounded catch-up from that
            // position; a cursorless open is an initial sync.
            catchup: after.is_some().then_some(true),
            filter: None,
            wait_for: None,
        });
        let channel_id = self.open(&parameters)?;
        Ok(WebSocketAccountChannel {
            connection: self.connection.clone(),
            pacer: self.pacer.clone(),
            channel_id,
        })
    }

    /// Open the Signal channel. §6.2 gives it no selector at all.
    pub fn open_signal(&self) -> Result<WebSocketSignalChannel<E>> {
        let channel_id = self.open(&WebSocketOpenParameters::Signal)?;
        Ok(WebSocketSignalChannel {
            connection: self.connection.clone(),
            pacer: self.pacer.clone(),
            channel_id,
            pending: VecDeque::new(),
        })
    }

    /// Open one events channel over a Realm selector.
    pub fn open_events(
        &self,
        realms: Vec<RealmId>,
        after: Option<&str>,
    ) -> Result<WebSocketEventsChannel<E>> {
        let parameters = WebSocketOpenParameters::Events(WebSocketEventsOpenParameters {
            realm_ids: Some(realms),
            actor_ids: None,
            after: after
                .map(|value| Cursor::new(value.to_owned()))
                .transpose()?,
            catchup: after.is_some().then_some(true),
        });
        let channel_id = self.open(&parameters)?;
        Ok(WebSocketEventsChannel {
            connection: self.connection.clone(),
            pacer: self.pacer.clone(),
            channel_id,
            pending: VecDeque::new(),
        })
    }

    /// Mint the channel id and queue its `open`. The pump loop writes it — an
    /// adapter never touches the socket, which is what keeps the connection
    /// single-owner.
    fn open(&self, parameters: &WebSocketOpenParameters) -> Result<String> {
        self.connection.with_mut(|connection| {
            let channel_id = connection.next_channel_id(parameters.operation());
            connection.enqueue_open(&channel_id, parameters)?;
            Ok(channel_id)
        })
    }
}

/// Take whatever is queued for a channel, waiting until at least one frame is
/// available or the channel is gone.
async fn next_frames<E>(
    connection: &SharedConnection,
    pacer: &E,
    channel_id: &str,
) -> Vec<ChannelFrame>
where
    E: WebSocketPacer,
{
    loop {
        let frames = connection.with_mut(|connection| connection.take_channel_frames(channel_id));
        if !frames.is_empty() {
            return frames;
        }
        let _ = pacer.pace().await;
    }
}

/// Account channel as an [`AsyncSyncTransport`].
///
/// `SyncLoop` asks for "the next batch from this cursor". On a long-lived
/// channel the `open` already carried that cursor, so a call here awaits the
/// next server frames rather than issuing a request. The cursor the batch
/// reports is the channel's own, which is what keeps `SyncLoop`'s resume rule
/// identical on both transports.
pub struct WebSocketAccountChannel<E> {
    connection: SharedConnection,
    pacer: E,
    channel_id: String,
}

impl<E> WebSocketAccountChannel<E> {
    pub fn channel_id(&self) -> &str {
        &self.channel_id
    }
}

impl<E> AsyncSyncTransport for WebSocketAccountChannel<E>
where
    E: WebSocketPacer,
{
    fn sync_async<'a>(
        &'a self,
        _request: SyncRequestBody,
        _options: arkret_http_client::ClientRequestOptions,
    ) -> BoxSyncFuture<'a, AccountSubscribeBatch> {
        Box::pin(async move {
            let mut frames: Vec<AccountSubscribeFrame> = Vec::new();
            loop {
                for frame in next_frames(&self.connection, &self.pacer, &self.channel_id).await {
                    match frame {
                        ChannelFrame::Data(WebSocketDataPayload::Account(payload)) => {
                            frames.push(*payload);
                        }
                        ChannelFrame::Control(WebSocketChannelControlPayload::Account(payload)) => {
                            frames.push(*payload);
                        }
                        ChannelFrame::Closed => {
                            if frames.is_empty() {
                                return Err(Error::Protocol(
                                    "the account channel closed".to_owned(),
                                ));
                            }
                        }
                        ChannelFrame::Failed(error) => {
                            return Err(Error::Protocol(error.message));
                        }
                        // A payload of another operation can only reach here
                        // through a state-machine bug; refusing keeps the
                        // channel's contract intact.
                        _ => {
                            return Err(Error::Protocol(
                                "a foreign payload reached the account channel".to_owned(),
                            ));
                        }
                    }
                }
                if frames.is_empty() {
                    continue;
                }
                // §6.1 — the batch's resume point is the last cursor observed,
                // and it becomes durable only once the caller checkpoints.
                let cursor = frames
                    .iter()
                    .rev()
                    .find_map(|frame| frame.cursor.clone())
                    .unwrap_or_default();
                self.connection
                    .with_mut(|connection| connection.checkpoint(&self.channel_id));
                return Ok(AccountSubscribeBatch { frames, cursor });
            }
        })
    }
}

/// Events channel as a [`RealmEventsFrameSource`].
pub struct WebSocketEventsChannel<E> {
    connection: SharedConnection,
    pacer: E,
    channel_id: String,
    /// One wake can hand back a burst. The frame-source seam yields a single
    /// frame per call, so the rest of the batch waits here instead of being
    /// dropped on the floor.
    pending: VecDeque<ChannelFrame>,
}

impl<E> WebSocketEventsChannel<E> {
    pub fn channel_id(&self) -> &str {
        &self.channel_id
    }
}

impl<E> RealmEventsFrameSource for WebSocketEventsChannel<E>
where
    E: WebSocketPacer,
{
    fn next_frame<'a>(
        &'a mut self,
    ) -> BoxRealmStreamFuture<
        'a,
        Option<arkret_models_collaboration::http_bodies::EventsSubscribeFrame>,
    > {
        Box::pin(async move {
            if self.pending.is_empty() {
                self.pending
                    .extend(next_frames(&self.connection, &self.pacer, &self.channel_id).await);
            }
            match self.pending.pop_front() {
                Some(ChannelFrame::Data(WebSocketDataPayload::Events(payload)))
                | Some(ChannelFrame::Control(WebSocketChannelControlPayload::Events(payload))) => {
                    self.connection
                        .with_mut(|connection| connection.checkpoint(&self.channel_id));
                    Ok(Some(*payload))
                }
                Some(ChannelFrame::Closed) | None => Ok(None),
                Some(ChannelFrame::Failed(error)) => Err(Error::Protocol(error.message)),
                Some(_) => Err(Error::Protocol(
                    "a foreign payload reached the events channel".to_owned(),
                )),
            }
        })
    }
}

impl<E> RealmEventsTransport for WebSocketTransport<E>
where
    E: WebSocketPacer,
{
    type Source = WebSocketEventsChannel<E>;

    fn open_realm_events<'a>(
        &'a self,
        realm_id: &'a RealmId,
        after: Option<&'a str>,
    ) -> BoxRealmStreamFuture<'a, Self::Source> {
        Box::pin(async move { self.open_events(vec![realm_id.clone()], after) })
    }
}

/// Signal channel as a [`SignalStreamFrameSource`].
///
/// The frames go straight to the shared `SignalStreamDriver`, so sender-key
/// resolution, AEAD open, de-duplication and the TTL rules are the same code
/// the HTTP rail runs. §6.2's "no cursor, no catch-up, no receipt" needs no
/// enforcement here because the channel simply has nowhere to put one.
pub struct WebSocketSignalChannel<E> {
    connection: SharedConnection,
    pacer: E,
    channel_id: String,
    /// See [`WebSocketEventsChannel::pending`].
    pending: VecDeque<ChannelFrame>,
}

impl<E> WebSocketSignalChannel<E> {
    pub fn channel_id(&self) -> &str {
        &self.channel_id
    }
}

impl<E> SignalStreamFrameSource for WebSocketSignalChannel<E>
where
    E: WebSocketPacer,
{
    fn next_frame<'a>(&'a mut self) -> BoxSignalStreamFuture<'a, Option<SignalStreamFrame>> {
        Box::pin(async move {
            if self.pending.is_empty() {
                self.pending
                    .extend(next_frames(&self.connection, &self.pacer, &self.channel_id).await);
            }
            match self.pending.pop_front() {
                Some(ChannelFrame::Data(WebSocketDataPayload::Signal(payload)))
                | Some(ChannelFrame::Control(WebSocketChannelControlPayload::Signal(payload))) => {
                    Ok(Some(*payload))
                }
                Some(ChannelFrame::Closed) | None => Ok(None),
                Some(ChannelFrame::Failed(error)) => Err(Error::Protocol(error.message)),
                Some(_) => Err(Error::Protocol(
                    "a foreign payload reached the Signal channel".to_owned(),
                )),
            }
        })
    }
}

impl<E> SignalStreamTransport for WebSocketTransport<E>
where
    E: WebSocketPacer,
{
    type Source = WebSocketSignalChannel<E>;

    fn open_signal_stream<'a>(&'a self) -> BoxSignalStreamFuture<'a, Self::Source> {
        Box::pin(async move { self.open_signal() })
    }
}
