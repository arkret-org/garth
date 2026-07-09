//! Runtime-neutral shared client engine for Arkret v1 applications.
//!
//! This crate holds the orchestration seams shared by UI clients and agent
//! clients: executor binding, durable cursor/event caches, secure secret
//! storage, event emission, decoding and the facade root.

pub mod backoff;
pub mod decode;
pub mod event;
pub mod executor;
pub mod facade;
pub mod maybe_send;
pub mod orchestrator;
pub mod projection;
pub mod session;
pub mod store;
pub mod subscribe;

pub use arkret::SyncLoopControl;
pub use backoff::Backoff;
pub use decode::{DecodedInbound, DecodedMessage, DecodedNotification, InboundDecoder};
pub use event::{ClientEvent, ClientProjector};
pub use executor::Executor;
#[cfg(feature = "native")]
pub use executor::NativeExecutor;
#[cfg(all(feature = "wasm", target_arch = "wasm32"))]
pub use executor::WasmExecutor;
pub use facade::CokretClient;
pub use maybe_send::{MaybeSend, MaybeSendSync};
pub use orchestrator::{RunOptions, RunStopReason, TransportProvider};
pub use session::{
    AgentKeyProofLogin, DidProofLogin, GRANT_ROTATION_SKEW_SECS, HolderProofLogin, LoginKind,
    OidcLogin, POLL_INTERVAL_SECS, REFRESH_SKEW_SECS, RefreshDecision, SessionEngine,
    SessionGrantRefreshState, SessionGrantState, SessionGrantTransport, SessionHandle,
    SessionProofFields, SessionRefreshOptions, grant_due_for_rotation, grant_is_dead,
    refresh_decision,
};
#[cfg(all(feature = "native", not(target_arch = "wasm32")))]
pub use store::FileStore;
pub use store::{
    CursorScope, CursorStore, EventCacheStore, MemorySecureKeyStore, MemoryStore, OpaqueCursor,
    PutSecretOptions, SdkKeyStoreAdapter, SdkKeyStoreSecureAdapter, SecretBytes, SecretClass,
    SecretDurability, SecureCryptoStoreAdapter, SecureKeyStore, SecureKeyStoreBackendInfo,
    SecureKeyStoreError,
};
pub use subscribe::{
    BoxRealmStreamFuture, EventsScanRequest, EventsScanTransport, RealmEventsDriver,
    RealmEventsFrameSource, RealmEventsTransport, RealmStreamStopReason, ScanCatchup,
    ScanCatchupOptions, SubscriptionEngine, SubscriptionLoopDriver, SubscriptionStopReason,
    account_updates_to_events,
};
