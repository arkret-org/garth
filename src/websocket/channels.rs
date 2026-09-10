//! The three channel adapters.
//!
//! Each one satisfies the transport seam its existing driver already uses, so
//! switching a stream to the WebSocket binding changes which value is handed
//! to the driver and nothing else. No driver, projection, cursor rule or
//! Signal admission check is duplicated here.

use std::collections::VecDeque;

use arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeFrame;
use arkret_models_collaboration::sync_frames::client_sync::SyncRequestBody;
use arkret_models_collaboration::sync_frames::websocket_binding::{
    WebSocketAccountOpenParameters, WebSocketChannelControlPayload, WebSocketDataPayload,
    WebSocketEventsOpenParameters, WebSocketOpenParameters,
};
use arkret_wire::{Cursor, RealmId, SignalStreamFrame};

use super::connection::{ChannelFrame, WebSocketChannelState};
use super::shared::SharedCell;
use super::socket::WebSocketPacer;
use crate::protocol::{Error, Result};
use crate::subscribe::realm::{BoxRealmStreamFuture, RealmEventsFrameSource, RealmEventsTransport};
use crate::subscribe::signal::{
    BoxSignalStreamFuture, SignalStreamFrameSource, SignalStreamTransport,
};
use crate::sync_client::BoxSyncFuture;

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
    pub fn open_account(&self, request: SyncRequestBody) -> Result<WebSocketAccountChannel<E>> {
        let trace = crate::protocol::StreamTraceValidator::new(
            request.catchup.unwrap_or(false),
            request.after.clone(),
        );
        let parameters = WebSocketOpenParameters::Account(WebSocketAccountOpenParameters {
            after: request
                .after
                .as_deref()
                .map(|value| Cursor::new(value.to_owned()))
                .transpose()?,
            // §6.1 — a resume cursor asks for bounded catch-up from that
            // position; a cursorless open is an initial sync.
            catchup: request.catchup,
            filter: request.filter,
            realm_list: request.realm_list,
            replace_filter: request.replace_filter,
            wait_for: None,
        });
        let channel_id = self.open(&parameters)?;
        Ok(WebSocketAccountChannel {
            connection: self.connection.clone(),
            pacer: self.pacer.clone(),
            channel_id,
            trace,
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

/// A demand-bound account source. The shared pump queues at most two frames.
pub struct WebSocketAccountChannel<E> {
    connection: SharedConnection,
    pacer: E,
    channel_id: String,
    trace: crate::protocol::StreamTraceValidator,
}

impl<E> WebSocketAccountChannel<E> {
    pub fn channel_id(&self) -> &str {
        &self.channel_id
    }
}

impl<E> Drop for WebSocketAccountChannel<E> {
    fn drop(&mut self) {
        let _ = self.connection.with_mut(|connection| connection.enqueue_close_channel(
            &self.channel_id,
            arkret_models_collaboration::sync_frames::websocket_binding::WebSocketCloseReason::ClientRequest,
        ));
    }
}

impl<E: WebSocketPacer> crate::AccountFrameSource for WebSocketAccountChannel<E> {
    fn next_frame(&mut self) -> BoxSyncFuture<'_, Option<AccountSubscribeFrame>> {
        Box::pin(async move {
            loop {
                let queued = self
                    .connection
                    .with_mut(|connection| connection.take_account_frame(&self.channel_id));
                match queued {
                    Some(ChannelFrame::Data(WebSocketDataPayload::Account(frame)))
                    | Some(ChannelFrame::Control(WebSocketChannelControlPayload::Account(frame))) =>
                    {
                        self.trace.push(frame.as_ref())?;
                        return Ok(Some(*frame));
                    }
                    Some(ChannelFrame::Closed) => {
                        self.trace.finish()?;
                        return Ok(None);
                    }
                    Some(ChannelFrame::Failed(error)) => {
                        return Err(Error::Api {
                            status: error.code.http_status(),
                            error: Box::new(arkret_wire::Problem::from_code(
                                error.code.as_str(),
                                error.message,
                            )),
                        });
                    }
                    Some(_) => {
                        return Err(Error::Protocol("foreign payload on account channel".into()));
                    }
                    None => {
                        self.pacer.pace().await?;
                    }
                }
            }
        })
    }

    fn committed(&mut self, cursor: &str) -> Result<()> {
        self.connection
            .with_mut(|connection| connection.checkpoint_exact(&self.channel_id, cursor))
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
