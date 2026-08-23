//! One physical `ak.profile.binding.websocket.v1` connection.
//!
//! The handshake, the frame codec, the channel state machine and the
//! close-code decision table all come from the SDK; this module drives them
//! against a host socket and demultiplexes the result into per-channel queues.
//!
//! ## Why a pump instead of a background task
//!
//! garth is runtime-neutral: it has no `spawn`, and a browser build is
//! single-threaded. So the connection does not read on its own — the host runs
//! [`WebSocketConnection::pump`] in one loop, and the per-channel adapters read
//! from the queues that loop fills.
//!
//! The socket is therefore *not* shared. [`WebSocketConnection`] owns it and
//! holds `&mut self` across its I/O awaits; the adapters share only
//! [`WebSocketChannelState`] and touch it in short synchronous sections. That
//! split is what lets a blocking lock be correct here: it never spans an await.
//! Everything an adapter wants to send is enqueued and drained by the pump, so
//! the connection has exactly one writer — the same single-owner discipline §8
//! demands of the transport as a whole, applied one level down.

use std::collections::BTreeMap;

use arkret_models_collaboration::sync_frames::websocket_binding::{
    WebSocketChannelControlPayload, WebSocketClientFrame, WebSocketCloseReason,
    WebSocketConnectionControlPayload, WebSocketConnectionLimits, WebSocketDataPayload,
    WebSocketOpenParameters, WebSocketServerFrame,
};
use arkret_models_collaboration::sync_frames::websocket_session::{
    WebSocketConnectionState, WebSocketFrameCodec, WebSocketServerEvent,
};
use arkret_wire::DomainSeparationId;
use arkret_wire::websocket_binding::{
    WEBSOCKET_AUTHENTICATION_DEADLINE_MS, WebSocketCloseCode, WebSocketOperationId,
    WebSocketTransportError,
};

use crate::protocol::{Error, Result};

use super::shared::SharedCell;
use super::socket::{AuthProofRequest, WebSocketConnector, WebSocketInbound, WebSocketSocket};

/// One frame handed to a channel adapter, already resolved against the
/// channel's operation by the SDK state machine.
#[derive(Debug)]
pub enum ChannelFrame {
    Data(WebSocketDataPayload),
    Control(WebSocketChannelControlPayload),
    /// The channel terminated. §8 is explicit that this is not a cursor
    /// checkpoint and not a Signal delivery receipt.
    Closed,
    /// A channel-scoped error preceded the close.
    Failed(WebSocketTransportError),
}

/// Why [`WebSocketConnection::pump`] returned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PumpOutcome {
    /// A frame was processed; call again.
    Continue,
    /// The connection ended. The code is what the transport-selection table
    /// consumes to decide retry or HTTP fallback.
    Closed {
        code: WebSocketCloseCode,
        /// The `reconnect_after_ms` of the last connection-scoped drain, if
        /// one arrived. §8 requires it to be honoured before reconnecting.
        drain_reconnect_after_ms: Option<u32>,
    },
    /// The service asked for a reauth. The host signs a fresh proof over this
    /// nonce and calls [`WebSocketChannelState::enqueue_authenticate`]; §3
    /// gives it the same 5 second deadline as the initial handshake.
    ReauthRequired { nonce: String },
}

/// Everything about a connection except the socket. Shared with the adapters.
pub struct WebSocketChannelState {
    codec: WebSocketFrameCodec,
    state: WebSocketConnectionState,
    inbound: BTreeMap<String, Vec<ChannelFrame>>,
    outbound: Vec<String>,
    base_url: String,
    drain_reconnect_after_ms: Option<u32>,
    proof_sequence: u32,
    channel_sequence: u32,
}

impl WebSocketChannelState {
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub fn connection_id(&self) -> &str {
        self.state.connection_id()
    }

    pub fn limits(&self) -> WebSocketConnectionLimits {
        self.state.limits()
    }

    /// Mint a channel id that has not been used on this connection. §4 makes
    /// the reservation permanent, so ids are never recycled.
    pub fn next_channel_id(&mut self, operation: WebSocketOperationId) -> String {
        let prefix = match operation {
            WebSocketOperationId::AccountStreamSubscribe => "account",
            WebSocketOperationId::EventsStreamSubscribe => "events",
            WebSocketOperationId::SignalStreamSubscribe => "signal",
        };
        self.channel_sequence += 1;
        format!("{prefix}-{}", self.channel_sequence)
    }

    /// Queue `open` and register the channel locally.
    ///
    /// The service still answers with `opened`; registering here is what lets
    /// the demultiplexer resolve a payload's operation the moment the first
    /// frame lands.
    pub fn enqueue_open(
        &mut self,
        channel_id: &str,
        parameters: &WebSocketOpenParameters,
    ) -> Result<()> {
        let frame = WebSocketClientFrame::open(channel_id, parameters)?;
        frame.validate()?;
        self.outbound.push(self.codec.encode(&frame)?);
        self.state
            .record_opened(channel_id, parameters.operation())?;
        self.inbound.insert(channel_id.to_owned(), Vec::new());
        Ok(())
    }

    /// Queue a `close` for one channel, leaving its siblings untouched.
    pub fn enqueue_close_channel(
        &mut self,
        channel_id: &str,
        reason: WebSocketCloseReason,
    ) -> Result<()> {
        let frame = WebSocketClientFrame::Close {
            channel_id: channel_id.to_owned(),
            reason,
        };
        frame.validate()?;
        self.outbound.push(self.codec.encode(&frame)?);
        self.state.close_channel(channel_id);
        Ok(())
    }

    /// The inputs the host needs to sign a reauth proof.
    ///
    /// §3 requires `nonce`, `ath`, `iat` and `jti` to all be new; reusing any
    /// of them fails and closes the whole connection with `1008`. The `jti`
    /// here comes from a per-connection counter, so it is fresh for every proof
    /// without garth needing an RNG seam.
    pub fn reauth_proof_request(&mut self, nonce: &str, session_grant: String) -> AuthProofRequest {
        self.proof_sequence += 1;
        AuthProofRequest {
            base_url: self.base_url.clone(),
            session_grant,
            nonce: nonce.to_owned(),
            jti: fresh_jti(self.state.connection_id(), nonce, self.proof_sequence),
        }
    }

    /// Queue the reauth `authenticate` the host just signed.
    pub fn enqueue_authenticate(
        &mut self,
        request: &AuthProofRequest,
        proof: String,
    ) -> Result<()> {
        let frame = WebSocketClientFrame::Authenticate {
            connection_id: self.state.connection_id().to_owned(),
            session_grant: request.session_grant.clone(),
            dpop_proof: proof,
        };
        frame.validate()?;
        self.outbound.push(self.codec.encode(&frame)?);
        self.state.reauthenticated();
        Ok(())
    }

    /// Take everything queued for one channel.
    pub fn take_channel_frames(&mut self, channel_id: &str) -> Vec<ChannelFrame> {
        self.inbound
            .get_mut(channel_id)
            .map(std::mem::take)
            .unwrap_or_default()
    }

    /// The resume point the receiver has checkpointed for a channel. Only this
    /// value may be used to re-open on the next connection (§6.1).
    pub fn durable_cursor(&self, channel_id: &str) -> Option<&str> {
        self.state
            .channel(channel_id)
            .or_else(|| self.state.retired_channel(channel_id))
            .and_then(|channel| channel.durable_cursor.as_deref())
    }

    /// Promote a channel's observed cursor to its durable resume point. The
    /// caller does this only after its own durable write landed.
    pub fn checkpoint(&mut self, channel_id: &str) -> Option<String> {
        self.state
            .channel_mut(channel_id)
            .and_then(|channel| channel.checkpoint().map(str::to_owned))
    }

    fn push(&mut self, channel_id: &str, frame: ChannelFrame) {
        self.inbound
            .entry(channel_id.to_owned())
            .or_default()
            .push(frame);
    }

    fn closed(&mut self, code: WebSocketCloseCode) -> PumpOutcome {
        let open: Vec<String> = self
            .state
            .open_channel_ids()
            .into_iter()
            .map(str::to_owned)
            .collect();
        for channel_id in open {
            self.push(&channel_id, ChannelFrame::Closed);
        }
        self.state.closed();
        PumpOutcome::Closed {
            code,
            drain_reconnect_after_ms: self.drain_reconnect_after_ms,
        }
    }
}

/// A live, authenticated connection. The pump loop owns it and the socket.
pub struct WebSocketConnection<S> {
    socket: S,
    shared: SharedCell<WebSocketChannelState>,
}

impl<S> WebSocketConnection<S>
where
    S: WebSocketSocket,
{
    /// Run the §3 handshake on a freshly opened socket.
    ///
    /// Order is normative: the service challenges first, the client answers
    /// inside the deadline, and nothing but `challenge` / `welcome` may cross
    /// before the connection is authenticated. The handshake owns the socket
    /// outright — the pump loop only starts once this returns.
    pub async fn establish<C>(
        connector: &C,
        base_url: &str,
        advertised_max_frame_bytes: u32,
        mut socket: S,
    ) -> Result<Self>
    where
        C: WebSocketConnector<Socket = S> + ?Sized,
    {
        let handshake_codec = WebSocketFrameCodec::new(advertised_max_frame_bytes, None);

        let WebSocketServerFrame::Challenge {
            connection_id,
            nonce,
            ..
        } = read_server_frame(&mut socket, &handshake_codec).await?
        else {
            return Err(Error::Protocol(
                "the first WebSocket frame must be a challenge".to_owned(),
            ));
        };
        let mut state = WebSocketConnectionState::new(
            connection_id.clone(),
            handshake_limits(advertised_max_frame_bytes),
        );

        let session_grant = connector.session_grant().await?;
        let dpop_proof = connector
            .sign_auth_proof(&AuthProofRequest {
                base_url: base_url.to_owned(),
                session_grant: session_grant.clone(),
                nonce: nonce.clone(),
                jti: fresh_jti(&connection_id, &nonce, 0),
            })
            .await?;
        let authenticate = WebSocketClientFrame::Authenticate {
            connection_id: connection_id.clone(),
            session_grant,
            dpop_proof,
        };
        authenticate.validate()?;
        socket
            .send_text(handshake_codec.encode(&authenticate)?)
            .await?;

        let welcome = read_server_frame(&mut socket, &handshake_codec).await?;
        let limits = welcome.connection_limits().ok_or_else(|| {
            Error::Protocol("the frame after authenticate must be welcome".to_owned())
        })?;
        state
            .accept_server_frame(&welcome)
            .map_err(|rejection| Error::Protocol(rejection.error.message))?;

        Ok(Self {
            socket,
            shared: SharedCell::new(WebSocketChannelState {
                // §4 — the effective limit is the minimum of discovery,
                // `welcome` and the 1 MiB hard ceiling.
                codec: WebSocketFrameCodec::new(
                    advertised_max_frame_bytes,
                    Some(limits.max_frame_bytes),
                ),
                state,
                inbound: BTreeMap::new(),
                outbound: Vec::new(),
                base_url: base_url.to_owned(),
                drain_reconnect_after_ms: None,
                proof_sequence: 0,
                channel_sequence: 0,
            }),
        })
    }

    /// The handle the channel adapters share.
    pub fn shared(&self) -> SharedCell<WebSocketChannelState> {
        self.shared.clone()
    }

    /// Drain the outbound queue, then read and dispatch one inbound message.
    pub async fn pump(&mut self) -> Result<PumpOutcome> {
        for encoded in self
            .shared
            .with_mut(|state| std::mem::take(&mut state.outbound))
        {
            self.socket.send_text(encoded).await?;
        }

        let Some(inbound) = self.socket.recv().await? else {
            return Ok(self
                .shared
                .with_mut(|state| state.closed(WebSocketCloseCode::Normal)));
        };
        let text = match inbound {
            WebSocketInbound::Text(text) => text,
            // §4 — a binary message is never a frame.
            WebSocketInbound::Binary => {
                return Ok(self.fail(WebSocketCloseCode::ProtocolError, "binary").await);
            }
            WebSocketInbound::TooLarge => {
                return Ok(self.fail(WebSocketCloseCode::MessageTooBig, "size").await);
            }
            WebSocketInbound::Closed(code) => {
                // An unregistered or absent code cannot be trusted to mean
                // "retryable", so it is treated as a protocol failure.
                let code = code
                    .and_then(WebSocketCloseCode::from_u16)
                    .unwrap_or(WebSocketCloseCode::ProtocolError);
                return Ok(self.shared.with_mut(|state| state.closed(code)));
            }
        };

        match self.shared.with_mut(|state| state.dispatch(&text)) {
            Dispatch::Continue => Ok(PumpOutcome::Continue),
            Dispatch::Reauth { nonce } => Ok(PumpOutcome::ReauthRequired { nonce }),
            Dispatch::Fail { code, reason } => Ok(self.fail(code, reason).await),
        }
    }

    /// Close the physical connection and mark every channel terminated.
    pub async fn shutdown(&mut self, code: WebSocketCloseCode, reason: &str) {
        let _ = self.socket.close(code, reason).await;
        self.shared.with_mut(|state| state.state.closed());
    }

    async fn fail(&mut self, code: WebSocketCloseCode, reason: &'static str) -> PumpOutcome {
        let _ = self.socket.close(code, reason).await;
        self.shared.with_mut(|state| state.closed(code))
    }
}

/// What one inbound message meant, decided entirely under the lock so the pump
/// only has to perform the I/O the decision implies.
enum Dispatch {
    Continue,
    Reauth {
        nonce: String,
    },
    Fail {
        code: WebSocketCloseCode,
        reason: &'static str,
    },
}

impl WebSocketChannelState {
    fn dispatch(&mut self, text: &str) -> Dispatch {
        let frame = match self.codec.decode_server_frame(text.as_bytes()) {
            Ok(frame) => frame,
            Err(rejection) => {
                return Dispatch::Fail {
                    code: rejection
                        .close_code
                        .unwrap_or(WebSocketCloseCode::ProtocolError),
                    reason: "frame",
                };
            }
        };

        let event = match self.state.accept_server_frame(&frame) {
            Ok(event) => event,
            Err(rejection) => {
                let Some(code) = rejection.close_code else {
                    // §7 — a channel-scoped refusal kills only that channel.
                    if let Some(channel_id) = rejection.channel_id.clone() {
                        self.push(&channel_id, ChannelFrame::Failed(rejection.error));
                        self.push(&channel_id, ChannelFrame::Closed);
                        let _ = self.enqueue_close_channel(
                            &channel_id,
                            WebSocketCloseReason::ClientRequest,
                        );
                    }
                    return Dispatch::Continue;
                };
                return Dispatch::Fail {
                    code,
                    reason: "state",
                };
            }
        };

        match event {
            WebSocketServerEvent::Data {
                channel_id,
                payload,
                ..
            } => self.push(&channel_id, ChannelFrame::Data(payload)),
            WebSocketServerEvent::ChannelControl {
                channel_id,
                payload,
            } => self.push(&channel_id, ChannelFrame::Control(payload)),
            WebSocketServerEvent::ChannelError { channel_id, error } => {
                self.push(&channel_id, ChannelFrame::Failed(error));
            }
            WebSocketServerEvent::ChannelClosed { channel_id } => {
                self.push(&channel_id, ChannelFrame::Closed);
            }
            WebSocketServerEvent::ConnectionControl { payload } => {
                let WebSocketConnectionControlPayload::Drain {
                    reconnect_after_ms, ..
                } = payload;
                self.drain_reconnect_after_ms = Some(reconnect_after_ms);
            }
            WebSocketServerEvent::ConnectionError { .. } => {
                return Dispatch::Fail {
                    code: WebSocketCloseCode::InternalError,
                    reason: "error",
                };
            }
            WebSocketServerEvent::Ping { ping_id } => {
                // §6 — pong proves the physical connection only; it advances
                // no business cursor.
                let pong = WebSocketClientFrame::Pong { ping_id };
                match self.codec.encode(&pong) {
                    Ok(encoded) => self.outbound.push(encoded),
                    Err(_) => {
                        return Dispatch::Fail {
                            code: WebSocketCloseCode::InternalError,
                            reason: "pong",
                        };
                    }
                }
            }
            WebSocketServerEvent::ReauthRequired { nonce } => return Dispatch::Reauth { nonce },
            WebSocketServerEvent::Challenge { .. }
            | WebSocketServerEvent::Welcome { .. }
            | WebSocketServerEvent::Opened { .. } => {}
        }
        Dispatch::Continue
    }
}

async fn read_server_frame<S>(
    socket: &mut S,
    codec: &WebSocketFrameCodec,
) -> Result<WebSocketServerFrame>
where
    S: WebSocketSocket + ?Sized,
{
    let Some(WebSocketInbound::Text(text)) = socket.recv().await? else {
        return Err(Error::Protocol(
            "the WebSocket handshake needs a text frame".to_owned(),
        ));
    };
    codec
        .decode_server_frame(text.as_bytes())
        .map_err(|rejection| Error::Protocol(rejection.error.message))
}

/// Handshake-time limits. `welcome` replaces them wholesale, and no channel may
/// be opened before it arrives, so only the frame ceiling is meaningful here —
/// and the codec carries that separately.
fn handshake_limits(advertised_max_frame_bytes: u32) -> WebSocketConnectionLimits {
    WebSocketConnectionLimits {
        max_frame_bytes: advertised_max_frame_bytes,
        max_channels: 1,
        max_connection_pending_bytes: 1024,
        max_channel_pending_bytes: 1024,
        max_connection_pending_frames: 1,
        max_channel_pending_frames: 1,
        heartbeat_interval_ms: WEBSOCKET_AUTHENTICATION_DEADLINE_MS as u32,
    }
}

/// A per-proof identifier. §3.1 wants at least 96 bits of entropy; the
/// connection id and the nonce each carry at least 128 bits of server
/// randomness, so hashing them with a per-connection counter is fresh for every
/// proof without garth needing an RNG seam of its own.
fn fresh_jti(connection_id: &str, nonce: &str, sequence: u32) -> String {
    arkret_canonical::canonical::sha256_base64url(
        format!(
            "{}|{connection_id}|{nonce}|{sequence}",
            DomainSeparationId::WEBSOCKET_AUTH_V1
        )
        .as_bytes(),
    )
}
