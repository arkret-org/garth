//! Runtime-neutral shared client engine for Cokret v1 applications.
//!
//! This crate holds the orchestration seams shared by UI clients and agent
//! clients: executor binding, durable cursor/event caches, secure secret
//! storage, event emission, decoding and the facade root.

pub mod decode;
pub mod event;
pub mod executor;
pub mod facade;
pub mod outbound;
pub mod projection;
pub mod session;
pub mod store;
pub mod subscribe;

pub use decode::{DecodedInbound, DecodedMessage, DecodedNotification, InboundDecoder};
pub use event::{ClientEvent, ClientEventSink};
pub use executor::Executor;
#[cfg(feature = "native")]
pub use executor::NativeExecutor;
#[cfg(all(feature = "wasm", target_arch = "wasm32"))]
pub use executor::WasmExecutor;
pub use facade::CokretClient;
pub use outbound::{MessageCreateOptions, OutboundBuilder, OutboundCommandContext};
pub use session::{
    AgentKeyProofLogin, DidProofLogin, HolderProofLogin, LoginKind, OidcLogin, SessionEngine,
    SessionGrantState, SessionGrantTransport, SessionHandle, SessionProofFields,
    SessionRefreshOptions,
};
pub use store::{
    CursorScope, CursorStore, EventCacheStore, MemorySecureKeyStore, MemoryStore, OpaqueCursor,
    PutSecretOptions, SdkKeyStoreAdapter, SdkKeyStoreSecureAdapter, SecretBytes, SecretClass,
    SecretDurability, SecureKeyStore, SecureKeyStoreBackendInfo, SecureKeyStoreError,
};
pub use subscribe::{
    EventsScanRequest, EventsScanTransport, RealmEventsDriver, RealmEventsFrameSource,
    RealmEventsTransport, RealmStreamStopReason, ScanCatchup, ScanCatchupOptions,
    SubscriptionEngine, SubscriptionLoopDriver, SubscriptionStopReason, emit_account_updates,
};
