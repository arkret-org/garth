//! Host-neutral raw WebSocket seams for the advertised Arkret binding.
//!
//! Protocol frame schemas and transition rules remain SDK-owned. Garth exposes
//! the physical socket and holder-signing seams plus a single-owner connection
//! pump that applies those SDK transitions and isolates channel queues. It
//! creates no second finality or stream model.

mod connection;
mod shared;
pub mod socket;

pub use arkret_models_discovery::{
    select_websocket_binding, validate_websocket_transport, websocket_operations_reachable,
};
pub use connection::{
    ChannelFrame, PumpOutcome, WebSocketChannelState, WebSocketConnection, connect_websocket,
};
pub use shared::SharedCell;
pub use socket::{
    AuthProofRequest, BoxSocketFuture, WebSocketConnector, WebSocketInbound, WebSocketPacer,
    WebSocketSocket,
};
