//! Runtime-neutral shared client engine for Arkret v1 applications.
//!
//! This crate holds the orchestration seams shared by UI clients and agent
//! clients: executor binding, durable cursor/event caches, secure secret
//! storage, event emission, decoding and the facade root.

// RPITIT keeps these public traits usable on native and wasm without boxing;
// spelling implementations as `async fn` would obscure their explicit future
// bounds and is not supported by all downstream toolchains we gate.
#![allow(clippy::manual_async_fn)]

mod error;
mod protocol;

pub use error::{Error, Result};

pub mod account_handoff;
pub mod crypto_state_store;
pub mod direct_conversation;
pub mod direct_conversation_repair;
pub mod event;
pub mod executor;
pub mod facade;
pub mod inbound;
pub mod maybe_send;
pub mod orchestrator;
pub mod outbound;
pub mod projection;
pub mod queued_record;
pub mod runtime_journey;
pub mod security_transaction;
pub mod service_route;
pub mod session;
pub mod signal;
pub mod signal_message_stream;
pub mod stamp;
pub mod store;
pub mod subscribe;
pub mod sync_client;
pub mod websocket;
pub use account_handoff::{
    AccountHandoffDisposition, BoundSessionRoute, IdentityCreationNextStep,
    IdentityCreationReconciliation, LocalEvidenceHydration, LocalEvidenceNormalization,
    LocalEvidenceUnavailableReason, NormalizedLocalEvidence, OidcAccountHandoffInput,
    ReturningDeviceCandidate, account_handoff_disposition, identity_binding_challenge_request,
    identity_creation_register_request, normalize_local_evidence, oidc_account_handoff_request,
    reconcile_identity_creation, route_bound_session, validate_identity_creation_outcome,
    verify_binding_receipt_at_issuance,
};
pub use arkret_identity::{
    AuthorityDidHistoryResolver, AuthorityHistoryUnavailable, AuthorityHistoryVerificationError,
    VerifiedAccountBindingReceipt,
};
pub use arkret_models_collaboration::signal_message_stream::MESSAGE_STREAM_KIND;
/// The shared Arkret retry cadence (`arkret-retry`). The ladder, its jitter
/// and the `Retry-After` floor are spec-normative; see that crate's docs.
pub use arkret_retry::RetrySchedule as Backoff;
pub use crypto_state_store::{
    CryptoStore, MemoryCryptoStore, MlsCommitSource, MlsEpochSecretRecord, MlsGroupStateRecord,
    MlsGroupStateSink, MlsRecoveryAction, MlsRecoveryPlan, MlsWelcomeState,
    StoredDeviceVerification,
};
pub use direct_conversation::{
    DirectConversationFoundingAction, direct_conversation_founding_action,
};
pub use direct_conversation_repair::{
    DirectConversationRepairAction, DirectConversationRepairPlanner, DirectConversationRepairRoute,
    DirectConversationRepairSnapshot, DirectConversationRepairStage,
    FrozenDirectConversationRepairDispatch, SelfRejoinAcceptance,
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
/// The Signal plaintext family (`sync/signal.md` §1.1).
///
/// Published because [`SignalPlaintext::payload`] carries the typed profile:
/// a consumer has to be able to name the variant it matches, and
/// `open_signal_plaintext` is the only admitted way to turn decrypted bytes
/// into one.
pub use protocol::{
    PresencePlaintext, ReadReceipt, SdkSignalPlaintext, TypingPlaintext, open_signal_plaintext,
};
pub use queued_record::{
    AuthoringAuthorityModel, AuthoringGeneration, MlsAdmissionStage, QueuedAuthoredEventAttempt,
    QueuedEventIntent, QueuedMlsSnapshot, QueuedMlsWelcomes, QueuedPostAcceptAction,
    QueuedRealmBootstrap, QueuedRecord, QueuedSdkEvent, ScheduledSendDispatchRecord,
    ScheduledSendSubmissionState,
};
pub use runtime_journey::{ParticipationAction, ParticipationAdmissionFacts};
pub use security_transaction::{
    BoxSecurityTransactionFuture, DurableSecurityTransaction, MemorySecurityTransactionStore,
    PendingSecurityTransactionContinue, SecurityTransactionEngine, SecurityTransactionProgress,
    SecurityTransactionStore, SecurityTransactionTransport,
};
pub use service_route::{
    MemoryServiceRouteStateStore, RouteCandidateSource, RouteForkQuarantine, RouteResolution,
    ServiceDescribeBinding, ServiceRouteCandidate, ServiceRouteDurableSnapshot,
    ServiceRouteEvaluator, ServiceRouteNoticeCandidate, ServiceRouteSource, ServiceRouteStateStore,
};
pub use session::{
    AgentKeyProofLogin, AuthenticatedTransportFactory, GRANT_ROTATION_SKEW_SECS, LoginKind,
    NoopSessionGrantStore, POLL_INTERVAL_SECS, REFRESH_SKEW_SECS, RefreshDecision,
    SecureSessionGrantStore, SessionEngine, SessionGrantRefreshState, SessionGrantState,
    SessionGrantStore, SessionGrantTransport, SessionHandle, SessionRefreshOptions,
    SessionTransportProvider, grant_due_for_rotation, grant_is_dead, refresh_decision,
};
pub use signal::{
    PresenceObservation, PresenceProjection, PresenceStatus, SIGNAL_PLAINTEXT_KIND_CALL,
    SIGNAL_PLAINTEXT_KIND_PRESENCE, SignalDecryptor, SignalPlaintext, SignalReceiver,
    SignalSenderKeyResolver, VerifiedSignalSenderKey, aggregate_presence_states,
};
pub use signal_message_stream::{
    MessageStreamApplyOutcome, MessageStreamAuthorizer, MessageStreamIgnoreReason,
    MessageStreamPreview, MessageStreamPreviewStatus, MessageStreamProjection,
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
    SecretClass, SecretDurability, SecureKeyStore, SecureKeyStoreBackendInfo, SecureKeyStoreError,
};
pub use subscribe::{
    BoxRealmStreamFuture, BoxSignalStreamFuture, EventsScanRequest, EventsScanTransport,
    RealmEventsDriver, RealmEventsFrameSource, RealmEventsTransport, RealmStreamStopReason,
    ScanCatchup, ScanCatchupOptions, SignalReceiveHandlers, SignalRejection, SignalRunError,
    SignalRunResult, SignalSink, SignalStreamDriver, SignalStreamFrameSource,
    SignalStreamStopReason, SignalStreamTransport, SubscriptionEngine, SubscriptionLoopDriver,
    SubscriptionStopReason, account_updates_to_events,
};
pub use sync_client::{
    AsyncSyncTransport, BackoffConfig, BackpressureConfig, BoxSyncFuture, CancellationToken,
    ExponentialBackoff, LocalEcho, ProcessedRealm, SendQueue, SendQueueItem, SendQueueSnapshot,
    SendQueueStatus, SyncGapStrategy, SyncLoop, SyncLoopControl, SyncLoopSnapshot, SyncLoopStep,
    SyncRecoveryAction, SyncResponseProcessor, SyncTransport,
};
