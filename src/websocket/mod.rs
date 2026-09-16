//! Host-neutral raw WebSocket seams for the advertised Arkret binding.
//!
//! Protocol frame schemas remain SDK-owned. Garth only exposes the physical
//! socket and holder-signing boundary, so enabling WebSocket transport cannot
//! create a second finality or stream model.

pub mod socket;

pub use arkret_models_discovery::{
    select_websocket_binding, validate_websocket_transport, websocket_operations_reachable,
};
pub use socket::{
    AuthProofRequest, BoxSocketFuture, WebSocketConnector, WebSocketInbound, WebSocketPacer,
    WebSocketSocket,
};
