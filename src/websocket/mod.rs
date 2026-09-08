//! `ak.profile.binding.websocket.v1` client transport.
//!
//! The optional binding replaces the *transport* of three stream operations,
//! not their semantics: an account channel still resumes from a durable
//! cursor, an events channel still tails the same frames, and a Signal channel
//! still has no cursor, no catch-up and no delivery receipt (§6.1 / §6.2). So
//! this module does not introduce a second set of drivers — it produces the
//! same [`subscribe`](crate::subscribe) seams the HTTP client already
//! satisfies, backed by channels on one physical socket.
//!
//! Layering, deliberately:
//!
//! - the SDK owns every protocol decision (frames, codec, channel state, close-code table, proof);
//! - this module owns the connection lifecycle and the demultiplex;
//! - the host owns the socket and the holder key ([`socket`]).
//!
//! Nothing here re-implements a validation the HTTP path already performs. In
//! particular the Signal channel hands its envelopes to the same
//! [`SignalStreamDriver`](crate::subscribe::signal::SignalStreamDriver), so
//! there is exactly one Signal admission path in the client.

mod channels;
mod connection;
mod shared;
pub mod socket;
#[cfg(test)]
mod tests;

// Re-exported so a host can drive the §8.1 decision table without depending on
// `arkret-models-collaboration` directly.
pub use arkret_models_collaboration::sync_frames::websocket_session::{
    WebSocketConsumerHandoff, WebSocketConsumerOwner, WebSocketFallbackPolicy,
    WebSocketHandshakeFailure, WebSocketTransportDecision,
};
pub use arkret_models_discovery::websocket_binding::select_websocket_binding;
pub use channels::{
    SharedConnection, WebSocketAccountChannel, WebSocketEventsChannel, WebSocketSignalChannel,
    WebSocketTransport,
};
pub use connection::{ChannelFrame, PumpOutcome, WebSocketChannelState, WebSocketConnection};
pub use shared::SharedCell;
pub use socket::{
    AuthProofRequest, BoxSocketFuture, WebSocketConnector, WebSocketInbound, WebSocketPacer,
    WebSocketSocket,
};
