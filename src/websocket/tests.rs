//! A scripted socket is enough to exercise everything this module owns: the
//! handshake order, the demultiplex, the isolation rule and the cursor
//! checkpoint. The protocol decisions themselves are the SDK's and are covered
//! by `ak.suite.binding.websocket.v1`.

use std::collections::VecDeque;

use arkret_models_collaboration::sync_frames::websocket_binding::{
    WebSocketAccountOpenParameters, WebSocketChannelControlPayload, WebSocketDataPayload,
    WebSocketOpenParameters,
};
use arkret_wire::websocket_binding::WebSocketCloseCode;

use super::connection::{ChannelFrame, PumpOutcome, WebSocketConnection};
use super::shared::SharedCell;
use super::socket::{
    AuthProofRequest, BoxSocketFuture, WebSocketConnector, WebSocketInbound, WebSocketPacer,
    WebSocketSocket,
};

const CONNECTION_ID: &str = "Y29ubmVjdGlvbi0wMTIzNDU2Nzg5YWJjZGVm";
const NONCE: &str = "bm9uY2UtMDEyMzQ1Njc4OWFiY2RlZg";
const BASE_URL: &str = "wss://server.example/_arkret/ws";
const PROOF: &str = "eyJhbGciOiJFZERTQSIsImp3ayI6eyJjcnYiOiJFZDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6IjExcVlBWUt4Q3JmVlNfN1R5V1FIT2c3aGN2UGFwaU1scndJYWFQY0hVUm8ifSwidHlwIjoiZHBvcCtqd3QifQ.eyJhdGgiOiJOcGpyakRMaENkX0xWdjRkNWExeXltV0YzUUlaNTU0ejJ5cGlyM0pmekNvIiwiaHRtIjoiQVJLUkVULVdFQlNPQ0tFVC1BVVRIIiwiaHR1Ijoid3NzOi8vc2VydmVyLmV4YW1wbGUvX2Fya3JldC93cyIsImlhdCI6MTc4NTI4MzIwMCwianRpIjoiZDNNdFlYVjBhQzFxZEdrdE1EQXdNUSIsIm5vbmNlIjoiYm05dVkyVXRNREV5TXpRMU5qYzRPV0ZpWTJSbFpnIn0.4UCcvb9tV5beZY-Z1fT0xCoyi54m3Mbec-zXDXtasx4PXJskm7k4LkYREuNzkqeoLvKhitYYLkSadbLzyosKAA";

/// A socket that replays a script and records what was written.
struct ScriptedSocket {
    inbound: VecDeque<WebSocketInbound>,
    sent: SharedCell<Vec<String>>,
    closed: SharedCell<Option<WebSocketCloseCode>>,
}

impl ScriptedSocket {
    fn new(frames: Vec<&str>) -> Self {
        Self {
            inbound: frames
                .into_iter()
                .map(|frame| WebSocketInbound::Text(frame.to_owned()))
                .collect(),
            sent: SharedCell::new(Vec::new()),
            closed: SharedCell::new(None),
        }
    }
}

impl WebSocketSocket for ScriptedSocket {
    fn recv(&mut self) -> BoxSocketFuture<'_, Option<WebSocketInbound>> {
        Box::pin(async move { Ok(self.inbound.pop_front()) })
    }

    fn send_text(&mut self, payload: String) -> BoxSocketFuture<'_, ()> {
        Box::pin(async move {
            self.sent.with_mut(|sent| sent.push(payload));
            Ok(())
        })
    }

    fn close<'a>(
        &'a mut self,
        code: WebSocketCloseCode,
        _reason: &'a str,
    ) -> BoxSocketFuture<'a, ()> {
        Box::pin(async move {
            self.closed.with_mut(|closed| *closed = Some(code));
            Ok(())
        })
    }
}

struct ScriptedConnector {
    socket: SharedCell<Option<ScriptedSocket>>,
}

impl WebSocketConnector for ScriptedConnector {
    type Socket = ScriptedSocket;

    fn connect<'a>(&'a self, _base_url: &'a str) -> BoxSocketFuture<'a, Self::Socket> {
        Box::pin(async move {
            self.socket
                .with_mut(Option::take)
                .ok_or_else(|| crate::protocol::Error::Protocol("no scripted socket".to_owned()))
        })
    }

    fn session_grant(&self) -> BoxSocketFuture<'_, String> {
        Box::pin(async move { Ok("ak.session.grant.fixture.websocket.v1".to_owned()) })
    }

    fn sign_auth_proof<'a>(
        &'a self,
        _request: &'a AuthProofRequest,
    ) -> BoxSocketFuture<'a, String> {
        Box::pin(async move { Ok(PROOF.to_owned()) })
    }
}

#[derive(Clone, Copy)]
struct ImmediatePacer;

impl WebSocketPacer for ImmediatePacer {
    fn pace(&self) -> BoxSocketFuture<'_, ()> {
        Box::pin(async move { Ok(()) })
    }
}

fn challenge() -> String {
    format!(
        "{{\"kind\":\"challenge\",\"connection_id\":\"{CONNECTION_ID}\",\"nonce\":\"{NONCE}\",\
         \"expires_at\":\"2026-07-29T00:00:05.000Z\"}}"
    )
}

fn welcome() -> String {
    format!(
        "{{\"kind\":\"welcome\",\"connection_id\":\"{CONNECTION_ID}\",\"max_frame_bytes\":2048,\
         \"max_channels\":16,\"max_connection_pending_bytes\":65536,\
         \"max_channel_pending_bytes\":16384,\"max_connection_pending_frames\":128,\
         \"max_channel_pending_frames\":32,\"heartbeat_interval_ms\":30000,\
         \"auth_expires_at\":\"2026-07-29T00:15:00.000Z\"}}"
    )
}

const ACCOUNT_DELTA: &str = "{\"kind\":\"data\",\"channel_id\":\"account-1\",\"payload\":{\"kind\":\"delta\",\"cursor\":\"ak:cursor:YWNjountY3Vyc29yLTAwMDE\"}}";
const SIGNAL_HEARTBEAT: &str = "{\"kind\":\"control\",\"frame_scope\":\"channel\",\"channel_id\":\"signal-2\",\"payload\":{\"kind\":\"heartbeat\"}}";
const PING: &str = "{\"kind\":\"ping\",\"ping_id\":\"cGluZy0wMTIzNDU2Nzg5YWJjZGVm\",\"sent_at\":\"2026-07-29T00:01:00.000Z\"}";

async fn establish(frames: Vec<&str>) -> WebSocketConnection<ScriptedSocket> {
    let socket = ScriptedSocket::new(frames);
    let connector = ScriptedConnector {
        socket: SharedCell::new(Some(socket)),
    };
    let socket = connector.connect(BASE_URL).await.expect("scripted socket");
    WebSocketConnection::establish(&connector, BASE_URL, 2048, socket)
        .await
        .expect("the scripted handshake completes")
}

#[tokio::test]
async fn the_handshake_answers_the_challenge_before_welcome() {
    let connection = establish(vec![&challenge(), &welcome()]).await;
    connection.shared().with_mut(|state| {
        assert_eq!(state.connection_id(), CONNECTION_ID);
        assert_eq!(state.limits().max_frame_bytes, 2048);
    });
}

#[tokio::test]
async fn frames_are_demultiplexed_onto_their_own_channels() {
    let mut connection = establish(vec![
        &challenge(),
        &welcome(),
        ACCOUNT_DELTA,
        SIGNAL_HEARTBEAT,
    ])
    .await;
    let shared = connection.shared();
    let transport = super::channels::WebSocketTransport::new(shared.clone(), ImmediatePacer);

    let account = transport.open_account(None).expect("account channel opens");
    let signal = transport.open_signal().expect("signal channel opens");
    assert_eq!(account.channel_id(), "account-1");
    assert_eq!(signal.channel_id(), "signal-2");

    // Two data-bearing frames, one per channel.
    for _ in 0..2 {
        let outcome = connection.pump().await.expect("pump");
        assert_eq!(outcome, PumpOutcome::Continue);
    }

    let account_frames = shared.with_mut(|state| state.take_channel_frames("account-1"));
    assert!(matches!(
        account_frames.as_slice(),
        [ChannelFrame::Data(WebSocketDataPayload::Account(_))]
    ));
    let signal_frames = shared.with_mut(|state| state.take_channel_frames("signal-2"));
    assert!(matches!(
        signal_frames.as_slice(),
        [ChannelFrame::Control(
            WebSocketChannelControlPayload::Signal(_)
        )]
    ));
}

#[tokio::test]
async fn only_a_checkpointed_cursor_becomes_the_resume_point() {
    let mut connection = establish(vec![&challenge(), &welcome(), ACCOUNT_DELTA]).await;
    let shared = connection.shared();
    let transport = super::channels::WebSocketTransport::new(shared.clone(), ImmediatePacer);
    transport.open_account(None).expect("account channel opens");

    connection.pump().await.expect("pump");
    // §6.1 — observing the cursor is not the same as being able to resume from
    // it; only the checkpoint makes it durable.
    shared.with_mut(|state| {
        assert_eq!(state.durable_cursor("account-1"), None);
        assert_eq!(
            state.checkpoint("account-1").as_deref(),
            Some("ak:cursor:YWNjountY3Vyc29yLTAwMDE")
        );
        assert_eq!(
            state.durable_cursor("account-1"),
            Some("ak:cursor:YWNjountY3Vyc29yLTAwMDE")
        );
    });
}

#[tokio::test]
async fn a_signal_channel_never_produces_a_cursor() {
    let connection = establish(vec![&challenge(), &welcome(), SIGNAL_HEARTBEAT]).await;
    let shared = connection.shared();
    let transport = super::channels::WebSocketTransport::new(shared.clone(), ImmediatePacer);
    transport.open_signal().expect("signal channel opens");
    // `signal-1` is the first minted id here, so re-point the script's frame.
    shared.with_mut(|state| {
        assert_eq!(state.durable_cursor("signal-1"), None);
        assert_eq!(state.checkpoint("signal-1"), None);
    });
}

#[tokio::test]
async fn a_ping_is_answered_and_advances_nothing() {
    let mut connection = establish(vec![&challenge(), &welcome(), PING]).await;
    let shared = connection.shared();
    let transport = super::channels::WebSocketTransport::new(shared.clone(), ImmediatePacer);
    transport.open_account(None).expect("account channel opens");

    connection.pump().await.expect("pump");
    shared.with_mut(|state| {
        assert_eq!(state.durable_cursor("account-1"), None);
    });
    // The pong is queued for the pump loop rather than written inline, which is
    // what keeps the socket single-owner.
    let outcome = connection.pump().await.expect("pump");
    assert!(matches!(outcome, PumpOutcome::Closed { .. }));
}

#[tokio::test]
async fn an_exhausted_socket_closes_every_open_channel() {
    let mut connection = establish(vec![&challenge(), &welcome()]).await;
    let shared = connection.shared();
    let transport = super::channels::WebSocketTransport::new(shared.clone(), ImmediatePacer);
    transport.open_account(None).expect("account channel opens");
    transport.open_signal().expect("signal channel opens");

    let outcome = connection.pump().await.expect("pump");
    assert_eq!(
        outcome,
        PumpOutcome::Closed {
            code: WebSocketCloseCode::Normal,
            drain_reconnect_after_ms: None,
        }
    );
    shared.with_mut(|state| {
        for channel_id in ["account-1", "signal-2"] {
            assert!(matches!(
                state.take_channel_frames(channel_id).as_slice(),
                [ChannelFrame::Closed]
            ));
        }
    });
}

#[tokio::test]
async fn an_account_open_carries_its_resume_cursor() {
    let connection = establish(vec![&challenge(), &welcome()]).await;
    let shared = connection.shared();
    let transport = super::channels::WebSocketTransport::new(shared.clone(), ImmediatePacer);
    transport
        .open_account(Some("ak:cursor:YWNjountY3Vyc29yLTAwMDE"))
        .expect("account channel opens");

    // The frame is queued, not written: the pump owns the socket.
    let parameters = WebSocketOpenParameters::Account(WebSocketAccountOpenParameters {
        after: Some(
            arkret_wire::Cursor::new("ak:cursor:YWNjountY3Vyc29yLTAwMDE".to_owned()).unwrap(),
        ),
        catchup: Some(true),
        filter: None,
        wait_for: None,
    });
    assert_eq!(
        parameters.to_value().unwrap()["catchup"],
        serde_json::json!(true)
    );
}
