//! Runtime-neutral shared client engine for Arkret v1 applications.
//!
//! This crate holds the orchestration seams shared by UI clients and agent
//! clients: executor binding, durable cursor/event caches, secure secret
//! storage, event emission, decoding and the facade root.

// RPITIT keeps these public traits usable on native and wasm without boxing;
// spelling implementations as `async fn` would obscure their explicit future
// bounds and is not supported by all downstream toolchains we gate.
#![allow(clippy::manual_async_fn)]

pub mod account_handoff;
pub mod backoff;
pub mod event;
pub mod executor;
pub mod facade;
pub mod maybe_send;
pub mod orchestrator;
pub mod outbound;
pub mod projection;
pub mod session;
pub mod stamp;
pub mod store;
pub mod subscribe;

pub use account_handoff::{
    AccountHandoffDisposition, OidcAccountHandoffInput, account_handoff_disposition,
    identity_binding_challenge_request, identity_creation_register_request,
    oidc_account_handoff_request, pre_registration_session_grant_request, validate_binding_receipt,
};
pub use arkret::SyncLoopControl;
pub use backoff::Backoff;
pub use event::{ClientEvent, ClientProjector};
#[cfg(feature = "native")]
pub use executor::NativeExecutor;
#[cfg(all(feature = "wasm", target_arch = "wasm32"))]
pub use executor::WasmExecutor;
pub use executor::{Executor, HostClock, SystemClock};
pub use facade::ArkretClient;
pub use maybe_send::{MaybeSend, MaybeSendSync};
pub use orchestrator::{
    AccountCommitOutcome, AccountPostCommitHook, AccountPostCommitOutcome, AccountStepCommitter,
    AccountStreamStep, RunError, RunErrorClass, RunEvent, RunOptions, RunResult, RunStopReason,
    TransportProvider,
};
pub use outbound::{
    OutboundEngine, OutboundEngineOutcome, OutboundGenerationFence,
    OutboundGenerationFenceDecision, OutboundPostAcceptHook, OutboundQueueStore,
    OutboundSubmitOutcome, OutboundSubmitter,
};
pub use session::{
    AgentKeyProofLogin, AuthenticatedTransportFactory, DidProofLogin, GRANT_ROTATION_SKEW_SECS,
    HolderProofLogin, LoginKind, NoopSessionGrantStore, OidcLogin, POLL_INTERVAL_SECS,
    PreRegistrationHandoffLogin, REFRESH_SKEW_SECS, RefreshDecision, SecureSessionGrantStore,
    SessionEngine, SessionGrantRefreshState, SessionGrantState, SessionGrantStore,
    SessionGrantTransport, SessionHandle, SessionProofFields, SessionRefreshOptions,
    SessionTransportProvider, grant_due_for_rotation, grant_is_dead, refresh_decision,
};
pub use stamp::{
    MonotonicStampStore, RemoteStamp, SigningStamp, SigningStampAllocator, StampFloor,
    StampFloorUpdate, StampScope, hlc_from_floor,
};
#[cfg(all(feature = "native", not(target_arch = "wasm32")))]
pub use store::FileStore;
pub use store::{
    BoundedSeenWindow, CursorScope, CursorStore, DEFAULT_SEEN_EVENTS_CAPACITY, DeliveryErrorClass,
    DeliveryId, DurableInboxStore, EventCacheStore, MAX_DELIVERY_ERROR_BYTES, MAX_PENDING_READ,
    MemorySecureKeyStore, MemoryStore, OpaqueCursor, PendingDelivery, PutSecretOptions,
    SdkKeyStoreAdapter, SdkKeyStoreSecureAdapter, SecretBytes, SecretClass, SecretDurability,
    SecureCryptoStoreAdapter, SecureKeyStore, SecureKeyStoreBackendInfo, SecureKeyStoreError,
};
pub use subscribe::{
    BoxRealmStreamFuture, EventsScanRequest, EventsScanTransport, RealmEventsDriver,
    RealmEventsFrameSource, RealmEventsTransport, RealmStreamStopReason, ScanCatchup,
    ScanCatchupOptions, SubscriptionEngine, SubscriptionLoopDriver, SubscriptionStopReason,
    account_updates_to_events,
};
