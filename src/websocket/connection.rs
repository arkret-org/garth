//! Authenticated connection pump for `ak.profile.binding.websocket.v1`.
//!
//! Protocol frames and their state machine remain SDK-owned. This module owns
//! only host I/O sequencing: one socket writer, challenge authentication,
//! canonical frame encoding, channel-isolated queues and physical close codes.

use std::collections::BTreeMap;

use arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeFrame;
use arkret_models_collaboration::sync_frames::committed_event_subscribe::CommittedEventSubscribeFrame;
use arkret_models_collaboration::sync_frames::websocket::{
    WebSocketChannelControlPayload, WebSocketClientFrame, WebSocketCloseReason,
    WebSocketConnectionLimits, WebSocketConnectionState, WebSocketDataPayload,
    WebSocketOpenParameters, WebSocketServerFrame,
};
use arkret_wire::{
    DomainSeparationId, SignalStreamFrame, WEBSOCKET_HARD_MAX_FRAME_BYTES, WebSocketCloseCode,
    WebSocketOperationId, WebSocketTransportError,
};

use super::shared::SharedCell;
use super::socket::{AuthProofRequest, WebSocketConnector, WebSocketInbound, WebSocketSocket};
use crate::{Error, Result};

#[derive(Clone, Debug)]
pub enum ChannelFrame {
    Data(WebSocketDataPayload),
    Control(WebSocketChannelControlPayload),
    Failed(WebSocketTransportError),
    Closed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PumpOutcome {
    Continue,
    Draining {
        reconnect_after_ms: u32,
    },
    ReauthRequired {
        nonce: String,
    },
    Failed {
        code: WebSocketCloseCode,
        error: WebSocketTransportError,
    },
    Closed {
        code: WebSocketCloseCode,
        drain_reconnect_after_ms: Option<u32>,
    },
}

#[derive(Debug)]
pub struct WebSocketChannelState {
    state: WebSocketConnectionState,
    inbound: BTreeMap<String, Vec<ChannelFrame>>,
    outbound: Vec<String>,
    durable_cursors: BTreeMap<String, String>,
    base_url: String,
    max_frame_bytes: usize,
    drain_reconnect_after_ms: Option<u32>,
    proof_sequence: u32,
    channel_sequence: u32,
    terminated: bool,
}

impl WebSocketChannelState {
    pub fn connection_id(&self) -> &str {
        self.state
            .connection_id()
            .expect("an established connection always has an id")
    }

    pub fn limits(&self) -> &WebSocketConnectionLimits {
        self.state
            .limits()
            .expect("an established connection always has limits")
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub fn is_terminated(&self) -> bool {
        self.terminated
    }

    pub fn open_channel(&mut self, parameters: WebSocketOpenParameters) -> Result<String> {
        if self.terminated {
            return Err(Error::Protocol(
                "cannot open a channel on a terminated WebSocket".to_owned(),
            ));
        }
        let operation_id = match &parameters {
            WebSocketOpenParameters::Account(_) => WebSocketOperationId::AccountStreamSubscribe,
            WebSocketOpenParameters::Events(_) => {
                WebSocketOperationId::CommittedEventStreamSubscribe
            }
            WebSocketOpenParameters::Signal(_) => WebSocketOperationId::SignalStreamSubscribe,
        };
        self.channel_sequence = self
            .channel_sequence
            .checked_add(1)
            .ok_or_else(|| Error::Protocol("WebSocket channel sequence overflow".to_owned()))?;
        let prefix = match operation_id {
            WebSocketOperationId::AccountStreamSubscribe => "account",
            WebSocketOperationId::CommittedEventStreamSubscribe => "events",
            WebSocketOperationId::SignalStreamSubscribe => "signal",
        };
        let channel_id = format!("{prefix}-{}", self.channel_sequence);
        let frame = WebSocketClientFrame::Open {
            channel_id: channel_id.clone(),
            operation_id,
            parameters,
        };
        let encoded = encode_client(&frame, self.max_frame_bytes)?;
        self.state.observe_client(&frame)?;
        self.outbound.push(encoded);
        self.inbound.insert(channel_id.clone(), Vec::new());
        Ok(channel_id)
    }

    pub fn close_channel(&mut self, channel_id: &str) -> Result<()> {
        let frame = WebSocketClientFrame::Close {
            channel_id: channel_id.to_owned(),
            reason: WebSocketCloseReason::ClientRequest,
        };
        let encoded = encode_client(&frame, self.max_frame_bytes)?;
        self.state.observe_client(&frame)?;
        self.outbound.push(encoded);
        Ok(())
    }

    pub fn take_channel_frames(&mut self, channel_id: &str) -> Vec<ChannelFrame> {
        self.inbound
            .get_mut(channel_id)
            .map(std::mem::take)
            .unwrap_or_default()
    }

    pub fn durable_cursor(&self, channel_id: &str) -> Option<&str> {
        self.durable_cursors.get(channel_id).map(String::as_str)
    }

    /// Promote only the exact cursor most recently accepted by the SDK state
    /// machine. Receiving a frame alone never makes its cursor durable.
    pub fn checkpoint_exact(&mut self, channel_id: &str, cursor: &str) -> Result<()> {
        let channel = self
            .state
            .channel(channel_id)
            .ok_or_else(|| Error::Protocol("WebSocket channel is absent".to_owned()))?;
        if !channel.operation_id.is_durable() {
            return Err(Error::Protocol(
                "a Signal WebSocket channel has no durable cursor".to_owned(),
            ));
        }
        if channel.resume_cursor.as_deref() != Some(cursor) {
            return Err(Error::Protocol(
                "durable cursor does not equal the channel's observed cursor".to_owned(),
            ));
        }
        self.durable_cursors
            .insert(channel_id.to_owned(), cursor.to_owned());
        Ok(())
    }

    fn reauth_request(&mut self, nonce: &str, session_grant: String) -> Result<AuthProofRequest> {
        self.proof_sequence = self
            .proof_sequence
            .checked_add(1)
            .ok_or_else(|| Error::Protocol("WebSocket proof sequence overflow".to_owned()))?;
        Ok(AuthProofRequest {
            base_url: self.base_url.clone(),
            session_grant,
            nonce: nonce.to_owned(),
            jti: fresh_jti(self.connection_id(), nonce, self.proof_sequence),
        })
    }

    fn enqueue_authenticate(&mut self, request: &AuthProofRequest, proof: String) -> Result<()> {
        let frame = WebSocketClientFrame::Authenticate {
            connection_id: self.connection_id().to_owned(),
            session_grant: request.session_grant.clone(),
            dpop_proof: proof,
        };
        let encoded = encode_client(&frame, self.max_frame_bytes)?;
        self.state.observe_client(&frame)?;
        self.outbound.push(encoded);
        Ok(())
    }

    fn push(&mut self, channel_id: &str, frame: ChannelFrame) {
        self.inbound
            .entry(channel_id.to_owned())
            .or_default()
            .push(frame);
    }

    fn push_closed(&mut self, channel_id: &str) {
        let frames = self.inbound.entry(channel_id.to_owned()).or_default();
        if !matches!(frames.last(), Some(ChannelFrame::Closed)) {
            frames.push(ChannelFrame::Closed);
        }
    }

    fn terminate(&mut self, code: WebSocketCloseCode) -> PumpOutcome {
        for channel_id in self.inbound.keys().cloned().collect::<Vec<_>>() {
            self.push_closed(&channel_id);
        }
        self.terminated = true;
        PumpOutcome::Closed {
            code,
            drain_reconnect_after_ms: self.drain_reconnect_after_ms,
        }
    }

    fn dispatch(&mut self, text: &str) -> Dispatch {
        let frame = match self.decode_server_frame(text) {
            Ok(frame) => frame,
            Err(_) => {
                return Dispatch::Close {
                    code: WebSocketCloseCode::ProtocolError,
                    reason: "frame",
                };
            }
        };
        if self.state.observe_server(&frame).is_err() {
            return Dispatch::Close {
                code: WebSocketCloseCode::ProtocolError,
                reason: "state",
            };
        }
        match frame {
            WebSocketServerFrame::Data {
                channel_id,
                payload,
            } => self.push(&channel_id, ChannelFrame::Data(payload)),
            WebSocketServerFrame::ChannelControl {
                channel_id,
                payload,
                ..
            } => {
                let terminal = payload.is_terminal();
                self.push(&channel_id, ChannelFrame::Control(payload));
                if terminal {
                    self.push_closed(&channel_id);
                }
            }
            WebSocketServerFrame::ChannelError {
                channel_id, error, ..
            } => {
                self.push(&channel_id, ChannelFrame::Failed(error));
                self.push_closed(&channel_id);
            }
            WebSocketServerFrame::Closed { channel_id, .. } => self.push_closed(&channel_id),
            WebSocketServerFrame::ConnectionControl { payload, .. } => {
                self.drain_reconnect_after_ms = Some(payload.reconnect_after_ms);
                return Dispatch::Draining {
                    reconnect_after_ms: payload.reconnect_after_ms,
                };
            }
            WebSocketServerFrame::ConnectionError { error, .. } => {
                return Dispatch::Failed(error);
            }
            WebSocketServerFrame::Ping { ping_id, .. } => {
                let pong = WebSocketClientFrame::Pong { ping_id };
                let encoded = match encode_client(&pong, self.max_frame_bytes) {
                    Ok(encoded) => encoded,
                    Err(_) => {
                        return Dispatch::Close {
                            code: WebSocketCloseCode::InternalError,
                            reason: "pong",
                        };
                    }
                };
                if self.state.observe_client(&pong).is_err() {
                    return Dispatch::Close {
                        code: WebSocketCloseCode::InternalError,
                        reason: "pong",
                    };
                }
                self.outbound.push(encoded);
            }
            WebSocketServerFrame::ReauthRequired { nonce, .. } => {
                return Dispatch::Reauth { nonce };
            }
            WebSocketServerFrame::Opened { .. }
            | WebSocketServerFrame::Challenge { .. }
            | WebSocketServerFrame::Welcome { .. } => {}
        }
        Dispatch::Continue
    }

    /// The payload has no discriminator of its own. Decode it using the
    /// operation of the already-open channel; heartbeat shapes overlap across
    /// the account, events and Signal rails.
    fn decode_server_frame(&self, text: &str) -> Result<WebSocketServerFrame> {
        if text.len() > self.max_frame_bytes {
            return Err(Error::Protocol(
                "WebSocket frame exceeds the effective byte limit".to_owned(),
            ));
        }
        let value = arkret_canonical::parse_canonical_json(text.as_bytes())?;
        let mut frame: WebSocketServerFrame = serde_json::from_value(value.clone())?;
        let Some(channel_id) = frame.channel_id() else {
            return Ok(frame);
        };
        let Some(channel) = self.state.channel(channel_id) else {
            return Ok(frame);
        };
        let Some(payload) = value.get("payload").cloned() else {
            return Ok(frame);
        };
        match &mut frame {
            WebSocketServerFrame::Data { payload: slot, .. } => {
                *slot = match channel.operation_id {
                    WebSocketOperationId::AccountStreamSubscribe => {
                        WebSocketDataPayload::Account(Box::new(serde_json::from_value::<
                            AccountSubscribeFrame,
                        >(payload)?))
                    }
                    WebSocketOperationId::CommittedEventStreamSubscribe => {
                        WebSocketDataPayload::Events(Box::new(serde_json::from_value::<
                            CommittedEventSubscribeFrame,
                        >(payload)?))
                    }
                    WebSocketOperationId::SignalStreamSubscribe => {
                        WebSocketDataPayload::Signal(Box::new(serde_json::from_value::<
                            SignalStreamFrame,
                        >(payload)?))
                    }
                };
            }
            WebSocketServerFrame::ChannelControl { payload: slot, .. } => {
                *slot =
                    match channel.operation_id {
                        WebSocketOperationId::AccountStreamSubscribe => {
                            WebSocketChannelControlPayload::Account(Box::new(
                                serde_json::from_value::<AccountSubscribeFrame>(payload)?,
                            ))
                        }
                        WebSocketOperationId::CommittedEventStreamSubscribe => {
                            WebSocketChannelControlPayload::Events(Box::new(
                                serde_json::from_value::<CommittedEventSubscribeFrame>(payload)?,
                            ))
                        }
                        WebSocketOperationId::SignalStreamSubscribe => {
                            WebSocketChannelControlPayload::Signal(Box::new(
                                serde_json::from_value::<SignalStreamFrame>(payload)?,
                            ))
                        }
                    };
            }
            _ => {}
        }
        Ok(frame)
    }
}

enum Dispatch {
    Continue,
    Draining {
        reconnect_after_ms: u32,
    },
    Reauth {
        nonce: String,
    },
    Failed(WebSocketTransportError),
    Close {
        code: WebSocketCloseCode,
        reason: &'static str,
    },
}

pub struct WebSocketConnection<S> {
    socket: S,
    shared: SharedCell<WebSocketChannelState>,
}

impl<S> WebSocketConnection<S>
where
    S: WebSocketSocket,
{
    pub async fn establish<C>(
        connector: &C,
        base_url: &str,
        advertised_max_frame_bytes: u32,
        mut socket: S,
    ) -> Result<Self>
    where
        C: WebSocketConnector<Socket = S> + ?Sized,
    {
        let advertised_max_frame_bytes = usize::try_from(advertised_max_frame_bytes)
            .map_err(|_| Error::Protocol("WebSocket frame limit does not fit usize".to_owned()))?;
        if !(1024..=WEBSOCKET_HARD_MAX_FRAME_BYTES).contains(&advertised_max_frame_bytes) {
            return Err(Error::Protocol(
                "advertised WebSocket frame limit is outside the registered range".to_owned(),
            ));
        }
        let challenge = read_server_frame(&mut socket, advertised_max_frame_bytes).await?;
        let WebSocketServerFrame::Challenge {
            connection_id,
            nonce,
            ..
        } = &challenge
        else {
            return Err(Error::Protocol(
                "the first WebSocket frame must be a challenge".to_owned(),
            ));
        };
        let mut state = WebSocketConnectionState::new();
        state.observe_server(&challenge)?;

        let session_grant = connector.session_grant().await?;
        let request = AuthProofRequest {
            base_url: base_url.to_owned(),
            session_grant: session_grant.clone(),
            nonce: nonce.clone(),
            jti: fresh_jti(connection_id, nonce, 0),
        };
        let authenticate = WebSocketClientFrame::Authenticate {
            connection_id: connection_id.clone(),
            session_grant,
            dpop_proof: connector.sign_auth_proof(&request).await?,
        };
        let encoded = encode_client(&authenticate, advertised_max_frame_bytes)?;
        state.observe_client(&authenticate)?;
        socket.send_text(encoded).await?;

        let welcome = read_server_frame(&mut socket, advertised_max_frame_bytes).await?;
        let WebSocketServerFrame::Welcome { limits, .. } = &welcome else {
            return Err(Error::Protocol(
                "the frame after authenticate must be welcome".to_owned(),
            ));
        };
        state.observe_server(&welcome)?;
        let max_frame_bytes = advertised_max_frame_bytes
            .min(limits.max_frame_bytes as usize)
            .min(WEBSOCKET_HARD_MAX_FRAME_BYTES);

        Ok(Self {
            socket,
            shared: SharedCell::new(WebSocketChannelState {
                state,
                inbound: BTreeMap::new(),
                outbound: Vec::new(),
                durable_cursors: BTreeMap::new(),
                base_url: base_url.to_owned(),
                max_frame_bytes,
                drain_reconnect_after_ms: None,
                proof_sequence: 0,
                channel_sequence: 0,
                terminated: false,
            }),
        })
    }

    pub fn shared(&self) -> SharedCell<WebSocketChannelState> {
        self.shared.clone()
    }

    pub async fn reauthenticate<C>(&mut self, connector: &C, nonce: &str) -> Result<()>
    where
        C: WebSocketConnector<Socket = S> + ?Sized,
    {
        let session_grant = connector.session_grant().await?;
        let request = self
            .shared
            .with_mut(|state| state.reauth_request(nonce, session_grant))?;
        let proof = connector.sign_auth_proof(&request).await?;
        self.shared
            .with_mut(|state| state.enqueue_authenticate(&request, proof))
    }

    pub async fn pump(&mut self) -> Result<PumpOutcome> {
        for frame in self
            .shared
            .with_mut(|state| std::mem::take(&mut state.outbound))
        {
            self.socket.send_text(frame).await?;
        }
        let Some(inbound) = self.socket.recv().await? else {
            return Ok(self
                .shared
                .with_mut(|state| state.terminate(WebSocketCloseCode::Normal)));
        };
        let text = match inbound {
            WebSocketInbound::Text(text) => text,
            WebSocketInbound::Binary => {
                return Ok(self.fail(WebSocketCloseCode::ProtocolError, "binary").await);
            }
            WebSocketInbound::TooLarge => {
                return Ok(self.fail(WebSocketCloseCode::MessageTooBig, "size").await);
            }
            WebSocketInbound::Closed(code) => {
                let code = code
                    .and_then(WebSocketCloseCode::from_u16)
                    .unwrap_or(WebSocketCloseCode::ProtocolError);
                return Ok(self.shared.with_mut(|state| state.terminate(code)));
            }
        };
        match self.shared.with_mut(|state| state.dispatch(&text)) {
            Dispatch::Continue => Ok(PumpOutcome::Continue),
            Dispatch::Draining { reconnect_after_ms } => {
                Ok(PumpOutcome::Draining { reconnect_after_ms })
            }
            Dispatch::Reauth { nonce } => Ok(PumpOutcome::ReauthRequired { nonce }),
            Dispatch::Failed(error) => {
                let code = WebSocketCloseCode::InternalError;
                let _ = self.socket.close(code, "error").await;
                self.shared.with_mut(|state| {
                    state.terminate(code);
                });
                Ok(PumpOutcome::Failed { code, error })
            }
            Dispatch::Close { code, reason } => Ok(self.fail(code, reason).await),
        }
    }

    pub async fn shutdown(&mut self, code: WebSocketCloseCode, reason: &str) -> PumpOutcome {
        let _ = self.socket.close(code, reason).await;
        self.shared.with_mut(|state| state.terminate(code))
    }

    async fn fail(&mut self, code: WebSocketCloseCode, reason: &'static str) -> PumpOutcome {
        let _ = self.socket.close(code, reason).await;
        self.shared.with_mut(|state| state.terminate(code))
    }
}

pub async fn connect_websocket<C>(
    connector: &C,
    base_url: &str,
    advertised_max_frame_bytes: u32,
) -> Result<WebSocketConnection<C::Socket>>
where
    C: WebSocketConnector + ?Sized,
{
    let socket = connector.connect(base_url).await?;
    WebSocketConnection::establish(connector, base_url, advertised_max_frame_bytes, socket).await
}

async fn read_server_frame<S>(
    socket: &mut S,
    max_frame_bytes: usize,
) -> Result<WebSocketServerFrame>
where
    S: WebSocketSocket + ?Sized,
{
    let Some(WebSocketInbound::Text(text)) = socket.recv().await? else {
        return Err(Error::Protocol(
            "the WebSocket handshake requires a text frame".to_owned(),
        ));
    };
    decode_server(&text, max_frame_bytes)
}

fn decode_server(text: &str, max_frame_bytes: usize) -> Result<WebSocketServerFrame> {
    if text.len() > max_frame_bytes {
        return Err(Error::Protocol(
            "WebSocket frame exceeds the effective byte limit".to_owned(),
        ));
    }
    Ok(arkret_canonical::from_canonical_json_slice(
        text.as_bytes(),
    )?)
}

fn encode_client(frame: &WebSocketClientFrame, max_frame_bytes: usize) -> Result<String> {
    let bytes = arkret_canonical::canonical_json_bytes(frame)?;
    if bytes.len() > max_frame_bytes {
        return Err(Error::Protocol(
            "outbound WebSocket frame exceeds the effective byte limit".to_owned(),
        ));
    }
    String::from_utf8(bytes)
        .map_err(|error| Error::Protocol(format!("WebSocket frame is not UTF-8: {error}")))
}

fn fresh_jti(connection_id: &str, nonce: &str, sequence: u32) -> String {
    arkret_canonical::canonical::sha256_base64url(
        format!(
            "{}|{connection_id}|{nonce}|{sequence}",
            DomainSeparationId::WEBSOCKET_AUTH_V1
        )
        .as_bytes(),
    )
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use arkret_models_collaboration::sync_frames::websocket::{
        WebSocketAccountOpenParameters, WebSocketOpenParameters, WebSocketSignalOpenParameters,
    };
    use serde_json::json;

    use super::*;
    use crate::websocket::socket::BoxSocketFuture;

    const CONNECTION_ID: &str = "Y29ubmVjdGlvbi0wMTIzNDU2Nzg5YWJjZGVm";
    const NONCE: &str = "bm9uY2UtMDEyMzQ1Njc4OWFiY2RlZg";
    const REAUTH_NONCE: &str = "cmVhdXRoLTAxMjM0NTY3ODlhYmNkZWY";
    const BASE_URL: &str = "wss://server.example/_arkret/ws";
    const PROOF: &str = "aaaaaaaaaaa.bbbbbbbbbbb.cccccccccccc";

    #[derive(Clone)]
    struct SocketRecord {
        sent: SharedCell<Vec<String>>,
        closed: SharedCell<Vec<WebSocketCloseCode>>,
    }

    struct ScriptedSocket {
        inbound: VecDeque<WebSocketInbound>,
        record: SocketRecord,
    }

    impl WebSocketSocket for ScriptedSocket {
        fn recv(&mut self) -> BoxSocketFuture<'_, Option<WebSocketInbound>> {
            Box::pin(async move { Ok(self.inbound.pop_front()) })
        }

        fn send_text(&mut self, payload: String) -> BoxSocketFuture<'_, ()> {
            Box::pin(async move {
                self.record.sent.with_mut(|sent| sent.push(payload));
                Ok(())
            })
        }

        fn close<'a>(
            &'a mut self,
            code: WebSocketCloseCode,
            _reason: &'a str,
        ) -> BoxSocketFuture<'a, ()> {
            Box::pin(async move {
                self.record.closed.with_mut(|closed| closed.push(code));
                Ok(())
            })
        }
    }

    struct ScriptedConnector {
        grants: SharedCell<VecDeque<String>>,
        proof_requests: SharedCell<Vec<AuthProofRequest>>,
    }

    impl ScriptedConnector {
        fn new() -> Self {
            Self {
                grants: SharedCell::new(VecDeque::from([
                    "ak.session.grant.fixture.websocket.v1".to_owned(),
                    "ak.session.grant.fixture.websocket.v2".to_owned(),
                ])),
                proof_requests: SharedCell::new(Vec::new()),
            }
        }
    }

    impl WebSocketConnector for ScriptedConnector {
        type Socket = ScriptedSocket;

        fn connect<'a>(
            &'a self,
            _base_url: &'a str,
        ) -> super::super::socket::BoxSocketFuture<'a, Self::Socket> {
            Box::pin(async move {
                Err(Error::Protocol(
                    "tests supply the socket directly".to_owned(),
                ))
            })
        }

        fn session_grant(&self) -> BoxSocketFuture<'_, String> {
            Box::pin(async move {
                self.grants
                    .with_mut(VecDeque::pop_front)
                    .ok_or_else(|| Error::Protocol("no scripted session grant".to_owned()))
            })
        }

        fn sign_auth_proof<'a>(
            &'a self,
            request: &'a AuthProofRequest,
        ) -> BoxSocketFuture<'a, String> {
            Box::pin(async move {
                self.proof_requests
                    .with_mut(|requests| requests.push(request.clone()));
                Ok(PROOF.to_owned())
            })
        }
    }

    fn challenge() -> String {
        serde_json::to_string(&json!({
            "kind": "challenge",
            "connection_id": CONNECTION_ID,
            "nonce": NONCE,
            "expires_at": "2026-09-19T12:00:05.000Z"
        }))
        .unwrap()
    }

    fn welcome() -> String {
        serde_json::to_string(&json!({
            "kind": "welcome",
            "connection_id": CONNECTION_ID,
            "max_frame_bytes": 65536,
            "max_channels": 16,
            "max_connection_pending_bytes": 65536,
            "max_channel_pending_bytes": 16384,
            "max_connection_pending_frames": 128,
            "max_channel_pending_frames": 32,
            "heartbeat_interval_ms": 30000,
            "auth_expires_at": "2026-09-19T12:15:00.000Z"
        }))
        .unwrap()
    }

    fn scripted_socket(extra: Vec<WebSocketInbound>) -> (ScriptedSocket, SocketRecord) {
        let record = SocketRecord {
            sent: SharedCell::new(Vec::new()),
            closed: SharedCell::new(Vec::new()),
        };
        let mut inbound = VecDeque::from([
            WebSocketInbound::Text(challenge()),
            WebSocketInbound::Text(welcome()),
        ]);
        inbound.extend(extra);
        (
            ScriptedSocket {
                inbound,
                record: record.clone(),
            },
            record,
        )
    }

    async fn establish(
        extra: Vec<WebSocketInbound>,
    ) -> (
        WebSocketConnection<ScriptedSocket>,
        ScriptedConnector,
        SocketRecord,
    ) {
        let connector = ScriptedConnector::new();
        let (socket, record) = scripted_socket(extra);
        let connection = WebSocketConnection::establish(&connector, BASE_URL, 65_536, socket)
            .await
            .unwrap();
        (connection, connector, record)
    }

    #[tokio::test]
    async fn handshake_sends_authenticate_only_after_challenge() {
        let (connection, connector, record) = establish(Vec::new()).await;
        connection.shared().with_mut(|state| {
            assert_eq!(state.connection_id(), CONNECTION_ID);
            assert_eq!(state.limits().max_frame_bytes, 65_536);
        });
        let sent = record.sent.with_mut(|sent| sent.clone());
        assert_eq!(sent.len(), 1);
        assert_eq!(
            arkret_canonical::from_canonical_json_str::<WebSocketClientFrame>(&sent[0]).unwrap(),
            WebSocketClientFrame::Authenticate {
                connection_id: CONNECTION_ID.to_owned(),
                session_grant: "ak.session.grant.fixture.websocket.v1".to_owned(),
                dpop_proof: PROOF.to_owned(),
            }
        );
        assert_eq!(
            connector.proof_requests.with_mut(|requests| requests.len()),
            1
        );
    }

    #[tokio::test]
    async fn data_and_control_frames_are_isolated_by_channel() {
        let account_data = WebSocketInbound::Text(
            "{\"channel_id\":\"account-1\",\"kind\":\"data\",\"payload\":{\"cursor\":\"ak:cursor:YWNjountY3Vyc29yLTAwMDE\",\"kind\":\"delta\"}}"
                .to_owned(),
        );
        let signal_control = WebSocketInbound::Text(
            "{\"channel_id\":\"signal-2\",\"frame_scope\":\"channel\",\"kind\":\"control\",\"payload\":{\"kind\":\"heartbeat\"}}"
                .to_owned(),
        );
        let (mut connection, ..) = establish(vec![account_data, signal_control]).await;
        let shared = connection.shared();
        shared.with_mut(|state| {
            assert_eq!(
                state
                    .open_channel(WebSocketOpenParameters::Account(
                        WebSocketAccountOpenParameters::default()
                    ))
                    .unwrap(),
                "account-1"
            );
            assert_eq!(
                state
                    .open_channel(WebSocketOpenParameters::Signal(
                        WebSocketSignalOpenParameters {}
                    ))
                    .unwrap(),
                "signal-2"
            );
        });
        assert_eq!(connection.pump().await.unwrap(), PumpOutcome::Continue);
        assert_eq!(connection.pump().await.unwrap(), PumpOutcome::Continue);
        shared.with_mut(|state| {
            assert!(matches!(
                state.take_channel_frames("account-1").as_slice(),
                [ChannelFrame::Data(WebSocketDataPayload::Account(_))]
            ));
            assert!(matches!(
                state.take_channel_frames("signal-2").as_slice(),
                [ChannelFrame::Control(
                    WebSocketChannelControlPayload::Signal(_)
                )]
            ));
            assert_eq!(state.durable_cursor("account-1"), None);
            state
                .checkpoint_exact("account-1", "ak:cursor:YWNjountY3Vyc29yLTAwMDE")
                .unwrap();
        });
    }

    #[tokio::test]
    async fn ping_queues_pong_without_advancing_a_durable_cursor() {
        let ping = WebSocketInbound::Text(
            "{\"kind\":\"ping\",\"ping_id\":\"cGluZy0wMTIzNDU2Nzg5YWJjZGVm\",\"sent_at\":\"2026-09-19T12:01:00.000Z\"}"
                .to_owned(),
        );
        let (mut connection, _, record) = establish(vec![ping]).await;
        assert_eq!(connection.pump().await.unwrap(), PumpOutcome::Continue);
        assert!(matches!(
            connection.pump().await.unwrap(),
            PumpOutcome::Closed {
                code: WebSocketCloseCode::Normal,
                ..
            }
        ));
        let sent = record.sent.with_mut(|sent| sent.clone());
        assert!(sent.iter().any(|frame| frame.contains("\"kind\":\"pong\"")));
    }

    #[tokio::test]
    async fn binary_and_oversized_messages_close_with_registered_codes() {
        for (inbound, expected) in [
            (WebSocketInbound::Binary, WebSocketCloseCode::ProtocolError),
            (
                WebSocketInbound::TooLarge,
                WebSocketCloseCode::MessageTooBig,
            ),
        ] {
            let (mut connection, _, record) = establish(vec![inbound]).await;
            assert!(matches!(
                connection.pump().await.unwrap(),
                PumpOutcome::Closed { code, .. } if code == expected
            ));
            assert_eq!(record.closed.with_mut(|closed| closed.clone()), [expected]);
        }
    }

    #[tokio::test]
    async fn reauth_requires_fresh_host_inputs() {
        let reauth = WebSocketInbound::Text(
            serde_json::to_string(&json!({
                "kind": "reauth_required",
                "connection_id": CONNECTION_ID,
                "nonce": REAUTH_NONCE,
                "expires_at": "2026-09-19T12:05:05.000Z",
                "reason": "grant_expiring"
            }))
            .unwrap(),
        );
        let (mut connection, connector, record) = establish(vec![reauth]).await;
        assert_eq!(
            connection.pump().await.unwrap(),
            PumpOutcome::ReauthRequired {
                nonce: REAUTH_NONCE.to_owned()
            }
        );
        connection
            .reauthenticate(&connector, REAUTH_NONCE)
            .await
            .unwrap();
        let _ = connection.pump().await.unwrap();
        let requests = connector
            .proof_requests
            .with_mut(|requests| requests.clone());
        assert_eq!(requests.len(), 2);
        assert_ne!(requests[0].session_grant, requests[1].session_grant);
        assert_ne!(requests[0].nonce, requests[1].nonce);
        assert_ne!(requests[0].jti, requests[1].jti);
        assert_eq!(record.sent.with_mut(|sent| sent.len()), 2);
    }
}
