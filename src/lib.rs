//! Runtime-neutral shared client engine for Arkret v1 applications.
//!
//! This crate holds the orchestration seams shared by UI clients and agent
//! clients: executor binding, durable cursor/event caches, secure secret
//! storage, event emission, decoding and the facade root.

// RPITIT keeps these public traits usable on native and wasm without boxing;
// spelling implementations as `async fn` would obscure their explicit future
// bounds and is not supported by all downstream toolchains we gate.
#![allow(clippy::manual_async_fn)]

mod crypto_box;
mod error;
mod protocol;

pub use error::{Error, Result};

pub mod account_handoff;
pub mod backoff;
pub mod crypto_state_store;
pub mod event;
pub mod executor;
pub mod facade;
pub mod inbound;
pub mod maybe_send;
pub mod orchestrator;
pub mod outbound;
pub mod projection;
pub mod runtime_store;
pub mod security_transaction;
pub mod session;
pub mod signal;
pub mod signal_message_stream;
pub mod stamp;
pub mod store;
pub mod subscribe;
pub mod sync_client;
pub use account_handoff::{
    AccountHandoffDisposition, OidcAccountHandoffInput, account_handoff_disposition,
    identity_binding_challenge_request, identity_creation_register_request,
    oidc_account_handoff_request, pre_registration_session_grant_request, validate_binding_receipt,
};
pub use backoff::Backoff;
pub use crypto_state_store::{
    CRYPTO_STORE_BACKUP_VERSION, CryptoStore, CryptoStoreBackupEnvelope, MemoryCryptoStore,
    MlsCommitSource, MlsEpochSecretRecord, MlsGroupStateRecord, MlsGroupStateSink,
    MlsRecoveryAction, MlsRecoveryPlan, StoredDeviceVerification,
};
pub use event::{AccountUpdateContext, ClientEvent, ClientProjector};
#[cfg(feature = "native")]
pub use executor::NativeExecutor;
#[cfg(all(feature = "wasm", target_arch = "wasm32"))]
pub use executor::WasmExecutor;
pub use executor::{Executor, HostClock, SystemClock};
pub use facade::ArkretClient;
pub use inbound::{DecodedInbound, DecodedMessage, InboundDecoder};
pub use maybe_send::{MaybeSend, MaybeSendSync};
pub use orchestrator::{
    AccountCommitOutcome, AccountPostCommitHook, AccountPostCommitOutcome, AccountStepCommitter,
    AccountStepHandlers, AccountStreamStep, RunError, RunErrorClass, RunEvent, RunOptions,
    RunResult, RunStopReason, TransportProvider,
};
pub use outbound::{
    OutboundEngine, OutboundEngineOutcome, OutboundGenerationFence,
    OutboundGenerationFenceDecision, OutboundPostAcceptHook, OutboundQueueStore,
    OutboundSubmitOutcome, OutboundSubmitter,
};
pub use projection::{ProjectionMount, RealmStateReducer};
pub use runtime_store::{
    AccountSessionStore, AuditAction, AuditEntry, AuditLogStore, BlobMetadataStore,
    EventCacheStore as EventBodyCacheStore, MemoryPersistenceStore, StateSnapshotStore, StoreCache,
    StoreEncryptionKey, StoredAccountData, rebuild_realm_state_from_events,
    restore_realm_state_from_persistence,
};
pub use security_transaction::{
    BoxSecurityTransactionFuture, DurableSecurityTransaction, MemorySecurityTransactionStore,
    PendingSecurityTransactionContinue, SecurityTransactionEngine, SecurityTransactionProgress,
    SecurityTransactionStore, SecurityTransactionTransport,
};
pub use session::{
    AgentKeyProofLogin, AuthenticatedTransportFactory, DidProofLogin, GRANT_ROTATION_SKEW_SECS,
    HolderProofLogin, LoginKind, NoopSessionGrantStore, OidcLogin, POLL_INTERVAL_SECS,
    PreRegistrationHandoffLogin, REFRESH_SKEW_SECS, RefreshDecision, SecureSessionGrantStore,
    SessionEngine, SessionGrantRefreshState, SessionGrantState, SessionGrantStore,
    SessionGrantTransport, SessionHandle, SessionProofFields, SessionRefreshOptions,
    SessionTransportProvider, grant_due_for_rotation, grant_is_dead, refresh_decision,
};
pub use signal::{
    PresenceObservation, PresenceProjection, PresenceStatus, SIGNAL_PLAINTEXT_KIND_PRESENCE,
    SignalDecryptor, SignalPlaintext, SignalReceiver, SignalSenderKeyResolver,
    aggregate_presence_states,
};
pub use signal_message_stream::{
    MessageStreamApplyOutcome, MessageStreamAuthorizer, MessageStreamIgnoreReason,
    MessageStreamPreview, MessageStreamPreviewStatus, MessageStreamProjection,
    SIGNAL_PLAINTEXT_KIND_MESSAGE_STREAM,
};
pub use stamp::{
    MonotonicStampStore, RemoteStamp, SigningStamp, SigningStampAllocator, StampFloor,
    StampFloorUpdate, StampScope, hlc_from_floor,
};
#[cfg(all(feature = "native", not(target_arch = "wasm32")))]
pub use store::FileStore;
pub use store::{
    BoundedSeenWindow, CursorScope, CursorStore, DEFAULT_SEEN_EVENTS_CAPACITY, DeliveryErrorClass,
    DeliveryId, DurableInboxStore, EventCacheStore, MAX_DELIVERY_ERROR_BYTES,
    MAX_PENDING_DELIVERIES, MAX_PENDING_READ, MemorySecureKeyStore, MemoryStore, OpaqueCursor,
    PendingDelivery, PutSecretOptions, SdkKeyStoreAdapter, SdkKeyStoreSecureAdapter, SecretBytes,
    SecretClass, SecretDurability, SecureCryptoStoreAdapter, SecureKeyStore,
    SecureKeyStoreBackendInfo, SecureKeyStoreError,
};
pub use subscribe::{
    BoxRealmStreamFuture, EventsScanRequest, EventsScanTransport, RealmEventsDriver,
    RealmEventsFrameSource, RealmEventsTransport, RealmStreamStopReason, ScanCatchup,
    ScanCatchupOptions, SubscriptionEngine, SubscriptionLoopDriver, SubscriptionStopReason,
    account_updates_to_events,
};
pub use sync_client::{
    AsyncSyncTransport, BackoffConfig, BackpressureConfig, BoxSyncFuture, CancellationToken,
    EventsSubscribeTransport, ExponentialBackoff, LocalEcho, ProcessedRealm, SendQueue,
    SendQueueItem, SendQueueItemKind, SendQueueSnapshot, SendQueueStatus, SyncGapStrategy,
    SyncLoop, SyncLoopControl, SyncLoopSnapshot, SyncLoopStep, SyncRecoveryAction,
    SyncResponseProcessor, SyncTransport,
};
