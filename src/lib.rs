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
pub mod event;
pub mod executor;
pub mod facade;
pub mod history_candidates;
pub mod history_outbox;
pub mod history_runtime;
pub mod inbound;
pub mod maybe_send;
pub mod mls;
pub mod orchestrator;
pub mod outbound;
pub mod projection;
pub mod queued_record;
pub mod runtime_journey;
pub mod security_transaction;
pub mod service_route;
pub mod service_route_material;
pub mod session;
pub mod signal;
pub mod signal_message_stream;
pub mod stamp;
pub mod store;
pub mod subscribe;
pub mod sync_client;
pub mod websocket;
pub use account_handoff::{
    AccountHandoffDisposition, BoundCompletionCheckpointStage, BoundCompletionContradiction,
    BoundCompletionHandoffState, BoundCompletionMaterial, BoundCompletionMaterialState,
    BoundCompletionResumeDisposition, BoundCompletionResumeFacts, BoundCompletionResumeReadError,
    BoundSessionRoute, IdentityCreationNextStep, IdentityCreationReconciliation,
    LocalEvidenceHydration, LocalEvidenceNormalization, LocalEvidenceUnavailableReason,
    NormalizedLocalEvidence, OidcAccountHandoffInput, RegistrationCheckpointDisposition,
    RegistrationCheckpointFacts, ReturningDeviceCandidate, account_handoff_disposition,
    classify_bound_completion_resume, classify_registration_checkpoint,
    identity_binding_challenge_request, identity_creation_register_request,
    normalize_local_evidence, oidc_account_handoff_request, reconcile_identity_creation,
    route_bound_session, validate_identity_creation_outcome,
};
pub use arkret_identity::{
    AuthorityDidHistoryResolver, AuthorityHistoryUnavailable, AuthorityHistoryVerificationError,
    VerifiedAccountBindingReceipt,
};
pub use arkret_models_collaboration::governance::realm_lifecycle::{
    CircleHistoryAccessPayload, HistoryAccessPayload,
};
pub use arkret_models_collaboration::history_key::{
    HistoryGovernanceTraversalIntent, HistoryGovernanceTraversalRetention, HistoryKeyRequest,
    HistoryKeyRequestReceipt, HistoryKeyResponseRecord, HistoryKeyResponseSendReceipt,
    OrganizationRecoveryArchivePlaintext, PeerHistoryTraversalAccess, SelfHistoryTraversalAccess,
};
pub use arkret_models_collaboration::signal_message_stream::MESSAGE_STREAM_KIND;
/// The shared Arkret retry cadence (`arkret-retry`). The ladder, its jitter
/// and the `Retry-After` floor are spec-normative; see that crate's docs.
pub use arkret_retry::RetrySchedule;
pub use arkret_wire::{HistoryAccess, HistoryEffectiveScope, OrganizationRecoveryArchive};
pub use crypto_state_store::{
    AcceptedMlsArtifactApplicator, AcceptedMlsArtifactCommit, AcceptedMlsArtifactCommitOutcome,
    AcceptedMlsArtifactConsumer, AcceptedMlsArtifactState, AcceptedMlsArtifactStore, CryptoStore,
    DurableAcceptedMlsArtifact, MemoryCryptoStore, MlsCommitSource, MlsEpochSecretRecord,
    MlsGroupStateRecord, MlsGroupStateSink, MlsWelcomeState, PreparedAcceptedMlsArtifact,
    QueuedMlsHistorySecret, StoredDeviceVerification, VersionedAcceptedMlsArtifactState,
    is_checkpoint_winning_accepted_mls_artifact,
};
pub use direct_conversation::{
    DirectConversationFoundingAction, direct_conversation_founding_action,
};
pub use event::{AccountUpdateContext, ClientEvent, ClientProjector};
#[cfg(feature = "native")]
pub use executor::NativeExecutor;
#[cfg(all(feature = "wasm", target_arch = "wasm32"))]
pub use executor::WasmExecutor;
pub use executor::{Executor, HostClock, SystemClock};
pub use facade::ArkretClient;
pub use history_candidates::{
    HistoryCandidateEngine, HistoryCandidateStateStore, MemoryHistoryCandidateStateStore,
    StagedHistoryCandidate, persist_staged_history_candidate_secret,
};
pub use history_outbox::{
    DurableHistorySourceAttempt, DurableStagedHistoryRecord, HistorySourceAttemptBundle,
    HistorySourceAttemptIdentity, HistorySourceAttemptStatus, HistorySourceBlobStore,
    HistorySourceOutboundRecord, HistorySourceOutbox, HistorySourceOutboxSnapshot,
    HistorySourceOutboxStore, HistorySourceRoute, MemoryHistorySourceBlobStore,
    MemoryHistorySourceOutboxStore, VersionedHistorySourceOutboxSnapshot,
};
pub use history_runtime::{
    DurableHistoryRequest, DurableHistoryResponseStream, DurableVerifiedHistoryManifest,
    HistoryResponseCapabilityOpener, HistoryRuntime, HistoryRuntimeSnapshot, HistoryRuntimeStore,
    HistoryRuntimeTransport, MemoryHistoryRuntimeStore, ReceiptBoundHistoryTraversal,
    VerifiedHistoryTraversal, VersionedHistoryRuntimeSnapshot,
    cryptographically_rejected_disposition,
};
pub use inbound::{DecodedInbound, DecodedMessage, InboundDecoder};
pub use maybe_send::{MaybeSend, MaybeSendSync};
pub use mls::{
    ACCOUNT_MLS_SECRET_CURRENT_VERSION, AEAD_VERSION_CHACHA20_POLY1305, AccountMlsSecretRotation,
    EnvelopeError, MLS_ENVELOPE_MAGIC, MlsLocalCheckpointEnvelope, MlsRuntimeError,
    MlsRuntimeStatus, SELF_PRESERVATION_JITTER_SLOTS, SELF_PRESERVATION_MAX_EPOCH_AGE_DAYS,
    SELF_PRESERVATION_MAX_EPOCH_APP_MESSAGES, StoredAccountMlsSecret,
    canonical_mls_remove_membership_frontier, idle_self_update_jitter_passed,
    mls_commit_preconditions, should_force_epoch_advance,
};
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
pub use projection::{
    BottomCellHead, BottomCellInfo, LocalSealView, ProjectionMount, RealmProjectionFrame,
    RealmStateReducer, encryption_profile_is_encrypted, realm_authority_root_controller_for_realm,
    realm_authority_root_controller_from_events, realm_authority_root_value_for_realm,
    realm_projection_is_encrypted, realm_projection_security_state, reconcile_realm_projection,
    security_projection_for_scope_id, strand_projection_security_state,
};
/// The Signal plaintext family (`sync/signal.md` §1.1).
///
/// Published because [`SignalPlaintext::payload`] carries the typed profile:
/// a consumer has to be able to name the variant it matches, and
/// `open_signal_plaintext` is the only admitted way to turn decrypted bytes
/// into one.
pub use protocol::{PresencePlaintext, ReadReceipt, TypingPlaintext, open_signal_plaintext};
pub use queued_record::{
    AuthoringAuthorityModel, AuthoringGeneration, MlsAdmissionStage, QueuedAuthoredEventAttempt,
    QueuedEventIntent, QueuedMlsLocalCheckpoint, QueuedMlsWelcomes, QueuedPostAcceptAction,
    QueuedRealmBootstrap, QueuedRecord, QueuedSdkEvent, ScheduledSendDispatchRecord,
    ScheduledSendSubmissionState,
};
pub use runtime_journey::{ParticipationAction, ParticipationAdmissionFacts};
pub use security_transaction::{
    BoxSecurityTransactionFuture, DurableSecurityTransaction, PendingSecurityTransactionContinue,
    SecurityTransactionEngine, SecurityTransactionProgress, SecurityTransactionStore,
    SecurityTransactionTransport,
};
pub use service_route::{
    MemoryServiceRouteStateStore, RouteCandidateSource, RouteForkQuarantine, RouteResolution,
    ServiceDescribeBinding, ServiceRouteCandidate, ServiceRouteDurableSnapshot,
    ServiceRouteEvaluator, ServiceRouteSource, ServiceRouteStateStore,
};
pub use service_route_material::{
    PrefetchedRouteSource, authenticate_fetched_resolution, describe_route_binding,
};
pub use session::{
    AgentKeyProofLogin, AuthenticatedTransportFactory, GRANT_ROTATION_SKEW_SECS, LoginKind,
    NoopSessionGrantStore, POLL_INTERVAL_SECS, REFRESH_SKEW_SECS, RefreshDecision,
    SecureSessionGrantStore, SessionEngine, SessionGrantRefreshState, SessionGrantState,
    SessionGrantStore, SessionGrantTransport, SessionHandle, SessionRefreshOptions,
    SessionTransportProvider, grant_due_for_rotation, grant_is_dead, refresh_decision,
};
pub use signal::{
    BoxSignalDecryptFuture, LiveSignalBody, LiveSignalProjection, MAX_LIVE_SIGNAL_BODIES,
    PresenceObservation, PresenceProjection, PresenceStatus, SIGNAL_PLAINTEXT_KIND_CALL,
    SIGNAL_PLAINTEXT_KIND_PRESENCE, SignalDecryptor, SignalPlaintext, SignalReceiver,
    SignalSenderKeyResolver, VerifiedSignalSenderAuthority, VerifiedSignalSenderKey,
    aggregate_presence_states, live_signal_projection_key,
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
    PendingDelivery, PutSecretOptions, SdkKeyStoreAdapter, SdkKeyStoreSecureAdapter, SecretClass,
    SecretDurability, SecureKeyStore, SecureKeyStoreBackendInfo, SecureKeyStoreError,
    account_id_storage_digest, device_storage_digest,
};
pub use subscribe::{
    BoxRealmStreamFuture, BoxSignalStreamFuture, EventsScanRequest, EventsScanTransport,
    RealmEventsDriver, RealmEventsFrameSource, RealmEventsTransport, RealmStreamStopReason,
    ScanCatchupOptions, SignalReceiveHandlers, SignalRejection, SignalRunError, SignalRunResult,
    SignalSink, SignalStreamDriver, SignalStreamFrameSource, SignalStreamStopReason,
    SignalStreamTransport, SubscriptionEngine, SubscriptionLoopDriver, SubscriptionStopReason,
    account_updates_to_events, expand_realm_delivery_events,
};
pub use sync_client::{
    AsyncSyncTransport, BackoffConfig, BackpressureConfig, BoxSyncFuture, CancellationToken,
    ExponentialBackoff, LocalEcho, ProcessedRealm, SendQueue, SendQueueItem, SendQueueSnapshot,
    SendQueueStatus, SyncGapStrategy, SyncLoop, SyncLoopControl, SyncLoopSnapshot, SyncLoopStep,
    SyncRecoveryAction, SyncResponseProcessor, SyncTransport,
};
