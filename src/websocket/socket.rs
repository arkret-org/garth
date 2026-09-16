//! Host seam for the raw WebSocket.
//!
//! garth owns the `ak.profile.binding.websocket.v1` protocol; the host owns the
//! socket. On native that is a tungstenite stream, in a browser it is the
//! platform `WebSocket` — neither belongs in a runtime-neutral engine, and the
//! protocol layer needs nothing from them beyond "hand me the next message"
//! and "send this text".

use std::future::Future;
use std::pin::Pin;

use arkret_wire::websocket_binding::WebSocketCloseCode;

use crate::Result;
use crate::maybe_send::MaybeSendSync;

#[cfg(not(target_arch = "wasm32"))]
pub type BoxSocketFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

#[cfg(target_arch = "wasm32")]
pub type BoxSocketFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + 'a>>;

/// One inbound WebSocket message, already reassembled by the host.
///
/// Fragmentation is the host's problem: §4 lets an implementation reassemble,
/// but the byte limit has to be enforced on the accumulated bytes before the
/// JSON parser runs. Hosts obtain that ceiling from the selected SDK discovery
/// binding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WebSocketInbound {
    Text(String),
    /// §4 — a binary message is a protocol error, not a frame. It is surfaced
    /// rather than dropped so the connection closes with `1002`.
    Binary,
    /// The peer closed. `None` when no close frame carried a code.
    Closed(Option<u16>),
    /// The host's own accumulation gate tripped: the reassembled message would
    /// have exceeded the effective limit, so it was never buffered whole.
    TooLarge,
}

/// The physical socket, as the protocol layer needs it.
pub trait WebSocketSocket: MaybeSendSync {
    /// The next inbound message, or `Ok(None)` at end of stream.
    fn recv<'a>(&'a mut self) -> BoxSocketFuture<'a, Option<WebSocketInbound>>;

    /// Send one text message.
    fn send_text<'a>(&'a mut self, payload: String) -> BoxSocketFuture<'a, ()>;

    /// Close the physical connection with an RFC 6455 code. §8.1 caps the
    /// reason at 123 UTF-8 bytes and forbids putting a grant, proof, nonce,
    /// DID or cursor in it, so the protocol layer only ever passes short tags.
    fn close<'a>(
        &'a mut self,
        code: WebSocketCloseCode,
        reason: &'a str,
    ) -> BoxSocketFuture<'a, ()>;
}

/// How a host opens a socket for one connection attempt.
///
/// The connector is asked for a fresh socket per attempt, which is what makes
/// §8.1's "one fresh grant + fresh socket retry" expressible: the same
/// connector is called again and returns a new socket.
pub trait WebSocketConnector: MaybeSendSync {
    #[cfg(not(target_arch = "wasm32"))]
    type Socket: WebSocketSocket + Send;

    #[cfg(target_arch = "wasm32")]
    type Socket: WebSocketSocket;

    /// Open the socket against `base_url`, requesting the `arkret.v1`
    /// subprotocol. The host MUST fail the attempt — not silently continue —
    /// when the response is not `101` or the subprotocol was not selected;
    /// the attempt must fail rather than silently continuing on another
    /// subprotocol.
    fn connect<'a>(&'a self, base_url: &'a str) -> BoxSocketFuture<'a, Self::Socket>;

    /// The current session grant to authenticate with. Asked per attempt so a
    /// reauth or a retry picks up a refreshed grant instead of replaying the
    /// old one, which §3 requires.
    fn session_grant<'a>(&'a self) -> BoxSocketFuture<'a, String>;

    /// Sign one `challenge_dpop_session_v1` proof.
    ///
    /// The holder private key never leaves the host, so signing is a seam
    /// rather than a value. The host builds the proof with
    /// [`arkret_signatures::websocket_auth::build_websocket_auth_proof`], which
    /// is the only implementation of that transcript.
    fn sign_auth_proof<'a>(&'a self, request: &'a AuthProofRequest) -> BoxSocketFuture<'a, String>;
}

/// Everything the host needs to build one authentication proof. Mirrors
/// `arkret_signatures::websocket_auth::WebSocketAuthProofRequest` with owned
/// fields so it can cross an async host boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthProofRequest {
    /// The discovery `base_url`, verbatim; it becomes `htu`.
    pub base_url: String,
    /// The grant this connection authenticates with; its hash becomes `ath`.
    pub session_grant: String,
    /// The `nonce` of the challenge being answered.
    pub nonce: String,
    /// A fresh per-proof identifier. Never reused across a reauth (§3).
    pub jti: String,
}

/// How a channel adapter yields to the pump loop.
///
/// [`Executor::sleep`](crate::executor::Executor::sleep) returns an opaque
/// future with no `Send` bound, which is right for the drivers that own their
/// own loop but cannot cross the boxed `Send` seams the native stream sources
/// use. This is the same future in the boxed, `#[cfg]`-split form every other
/// garth transport trait already speaks.
pub trait WebSocketPacer: Clone + MaybeSendSync {
    fn pace(&self) -> BoxSocketFuture<'_, ()>;
}

/// Default cadence: short enough that a channel adapter adds no perceptible
/// latency to a frame the pump has already read, long enough that an idle
/// channel does not spin.
pub const CHANNEL_PACE: std::time::Duration = std::time::Duration::from_millis(10);

#[cfg(all(feature = "native", not(target_arch = "wasm32")))]
impl WebSocketPacer for crate::executor::NativeExecutor {
    fn pace(&self) -> BoxSocketFuture<'_, ()> {
        Box::pin(async move {
            tokio::time::sleep(CHANNEL_PACE).await;
            Ok(())
        })
    }
}

#[cfg(all(feature = "wasm", target_arch = "wasm32"))]
impl WebSocketPacer for crate::executor::WasmExecutor {
    fn pace(&self) -> BoxSocketFuture<'_, ()> {
        Box::pin(async move {
            gloo_timers::future::sleep(CHANNEL_PACE).await;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::*;

    #[derive(Debug, Default)]
    struct FakeSocket {
        inbound: VecDeque<WebSocketInbound>,
        sent: Vec<String>,
        closed: Vec<(WebSocketCloseCode, String)>,
    }

    impl WebSocketSocket for FakeSocket {
        fn recv<'a>(&'a mut self) -> BoxSocketFuture<'a, Option<WebSocketInbound>> {
            Box::pin(async move { Ok(self.inbound.pop_front()) })
        }

        fn send_text<'a>(&'a mut self, payload: String) -> BoxSocketFuture<'a, ()> {
            Box::pin(async move {
                self.sent.push(payload);
                Ok(())
            })
        }

        fn close<'a>(
            &'a mut self,
            code: WebSocketCloseCode,
            reason: &'a str,
        ) -> BoxSocketFuture<'a, ()> {
            Box::pin(async move {
                self.closed.push((code, reason.to_owned()));
                Ok(())
            })
        }
    }

    #[tokio::test]
    async fn raw_socket_preserves_control_relevant_inbound_kinds() {
        let mut socket = FakeSocket {
            inbound: VecDeque::from([
                WebSocketInbound::Binary,
                WebSocketInbound::TooLarge,
                WebSocketInbound::Closed(Some(1001)),
            ]),
            ..FakeSocket::default()
        };
        assert_eq!(socket.recv().await.unwrap(), Some(WebSocketInbound::Binary));
        assert_eq!(
            socket.recv().await.unwrap(),
            Some(WebSocketInbound::TooLarge)
        );
        assert_eq!(
            socket.recv().await.unwrap(),
            Some(WebSocketInbound::Closed(Some(1001)))
        );
        assert_eq!(socket.recv().await.unwrap(), None);
    }

    #[tokio::test]
    async fn raw_socket_forwards_text_and_typed_close_code() {
        let mut socket = FakeSocket::default();
        socket
            .send_text("{\"type\":\"ping\"}".to_owned())
            .await
            .unwrap();
        socket
            .close(WebSocketCloseCode::ProtocolError, "invalid_frame")
            .await
            .unwrap();
        assert_eq!(socket.sent, ["{\"type\":\"ping\"}"]);
        assert_eq!(
            socket.closed,
            [(
                WebSocketCloseCode::ProtocolError,
                "invalid_frame".to_owned()
            )]
        );
    }

    #[test]
    fn auth_proof_request_keeps_fresh_attempt_inputs_separate() {
        let first = AuthProofRequest {
            base_url: "https://station.example".to_owned(),
            session_grant: "grant-a".to_owned(),
            nonce: "nonce-a".to_owned(),
            jti: "jti-a".to_owned(),
        };
        let mut second = first.clone();
        second.session_grant = "grant-b".to_owned();
        second.nonce = "nonce-b".to_owned();
        second.jti = "jti-b".to_owned();
        assert_ne!(first, second);
    }
}
