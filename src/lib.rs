//! Runtime-neutral client primitives for the Arkret governance-authority protocol.
//!
//! Producer Events carry no predecessor graph. Finality is represented only by
//! the current governance Station's RealmCommit chains, with one independent
//! stream for the Realm and for each Circle and Sidecar.

#![allow(clippy::manual_async_fn)]

mod error;

pub mod account_handoff;
pub mod account_sync;
pub mod actor_profile_directory;
pub mod agent_draft_pending_intent_projection;
pub mod authority;
pub mod direct_conversation;
pub mod executor;
pub mod facade;
pub mod maybe_send;
pub mod message_authoring;
pub mod mls;
pub mod notification_projection;
pub mod outbound;
pub mod presence;
pub mod projection;
pub mod replica;
pub mod run;
pub mod runtime_journey;
pub mod security_transaction;
pub mod service_route;
pub mod service_route_material;
pub mod session;
pub mod signal;
pub mod signal_message_stream;
pub mod stamp;
pub mod station_cas_projection;
pub mod store;
pub mod submission_queue;
pub mod subscription;
pub mod websocket;

#[cfg(test)]
mod test_fixtures;

pub use account_handoff::*;
pub use account_sync::*;
pub use actor_profile_directory::{
    ActorProfileDirectory, ActorProfileResolveTransport, ActorProfileUnavailableCause,
    ActorProfileView, DEFAULT_ACTOR_PROFILE_FRESH_FOR_SECONDS,
};
pub use agent_draft_pending_intent_projection::{
    AgentDraftPendingIntentProjection, AgentDraftPendingIntentProjectionUpdate,
};
pub use arkret_models_collaboration::signal_plaintext::{
    MAX_SIGNAL_PLAINTEXT_TTL_MS, SignalPlaintext, SignalPlaintextKind, SignalPlaintextProfile,
    SignalSequence, SignalSequenceDecision, SignalSequenceDomain, SignalSequenceEndpoint,
    SignalSequenceHighWater, open_signal_plaintext, seal_signal_plaintext,
    validate_signal_plaintext,
};
pub use arkret_retry::{RetryPolicy, RetrySchedule};
pub use arkret_wire::{
    AuthorityBundleRequest, AuthorityHandoffRequest, AuthoritySubmitOutcome,
    AuthoritySubmitRequest, CommitStreamHead, CommitStreamRef, CommittedEventFullView,
    CommittedEventRef, CommittedEventView, CommittedEventWithheldView, EventAdmissionSubmission,
    RealmAuthorityBundle, RealmAuthorityHandoff, RealmCommit, RealmStateSnapshot,
    StreamScanOutcome, StreamScanRequest,
};
pub use authority::{AuthorityClient, AuthorityTransport, QueuedSubmission, SubmissionState};
pub use direct_conversation::{DirectConversationAction, direct_conversation_action};
pub use error::{Error, Result};
#[cfg(feature = "native")]
pub use executor::NativeExecutor;
#[cfg(all(feature = "wasm", target_arch = "wasm32"))]
pub use executor::WasmExecutor;
pub use executor::{Executor, HostClock, SystemClock};
pub use facade::ArkretClient;
pub use maybe_send::{MaybeSend, MaybeSendSync};
pub use message_authoring::{
    MessageAuthoringContent, MessageAuthoringFailure, MessageAuthoringIntent,
    MessageAuthoringRecovery, MessageEncryptionContext, MessagePrepareOutcome,
    MessagePrepareRequestBody, MessageSubmitRequestBody, author_message,
    classify_authority_rejection, classify_message_authoring_error, queue_authored_message,
    verify_prepared_message,
};
pub use mls::{
    AcceptedMlsArtifact, InstalledMlsEpoch, LocalMlsEndpoint, MemoryMlsLocalStateStore,
    MlsDeviceSecretStore, MlsInstallQueue, MlsInstaller, MlsKeyPackageInventoryStore,
    MlsLocalStateStore, MlsRuntimeError, MlsRuntimeStatus, QueuedMlsInstall,
    SecureMlsLocalStateStore, admit_welcome, installed_mls_epoch, key_package_deficit,
    mls_group_id_for_realm, mls_group_id_for_scope, retain_admissible_welcomes,
    select_active_series_tail, select_active_series_tail_for_recipient_method,
    should_force_epoch_advance, verify_series_chain,
};
pub use notification_projection::{NotificationProjection, NotificationProjectionUpdate};
pub use outbound::{
    MemoryOutboundQueueStore, OutboundEngine, OutboundEngineOutcome, OutboundQueueStore, SendQueue,
    SendQueueItem, SendQueueSnapshot, SendQueueStatus,
};
pub use projection::{
    AccountUpdateContext, ClientEvent, ClientProjector, CommittedDelta, DecodedInbound,
    DecodedMessage, InboundDecoder, RealmProjectionFrame, RealmProjectionState,
    account_batch_to_client_events, account_frame_to_client_events, reconcile_realm_projection,
};
pub use replica::{RealmReplica, StreamReplica};
pub use run::{
    AccountRunner, RunError, RunErrorClass, RunEvent, RunOptions, RunResult, RunStopReason,
    SyncLoopControl, TransportProvider, classify_error,
};
pub use runtime_journey::{ParticipationAction, ParticipationAdmissionFacts};
pub use security_transaction::{
    ClientStepAttestation, DurableCompletedRecoveryReceipt, DurableSecurityTransaction,
    MemorySecurityTransactionStore, PcrPolicyRecoveryPlan, PendingSecurityTransactionContinue,
    RecoveryReceipt, RecoveryTerminalCommit, RecoveryTransactionCreateRequest, SecurityTransaction,
    SecurityTransactionContinueRequest, SecurityTransactionCreateRequest,
    SecurityTransactionEngine, SecurityTransactionPreparedPlan, SecurityTransactionStore,
    SecurityTransactionTerminalOutcome, SecurityTransactionTransport,
    validate_recovery_commit_boundary,
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
    AgentKeyProofLogin, AuthenticatedTransportFactory, BoxSessionFuture, GRANT_ROTATION_SKEW_SECS,
    LoginKind, NoopSessionGrantStore, POLL_INTERVAL_SECS, REFRESH_SKEW_SECS, RefreshDecision,
    SecureSessionGrantStore, SessionEngine, SessionGrantRefreshState, SessionGrantState,
    SessionGrantStore, SessionGrantTransport, SessionHandle, SessionRefreshOptions,
    SessionTransportProvider, grant_due_for_rotation, grant_is_dead, refresh_decision,
};
pub use signal::{
    SignalDecryptor, SignalFrameSource, SignalReceiveOutcome, SignalReceiver, SignalSink,
    SignalStreamStopReason,
};
pub use signal_message_stream::{
    MAX_MESSAGE_STREAM_LIFETIME_SECONDS, MAX_MESSAGE_STREAM_PREVIEW_BYTES,
    MAX_MESSAGE_STREAMS_PER_DEVICE, MESSAGE_STREAM_KIND, MESSAGE_STREAM_STALLED_AFTER_SECONDS,
    MessageStreamApplyOutcome, MessageStreamAuthorizer, MessageStreamFrame,
    MessageStreamIgnoreReason, MessageStreamPreview, MessageStreamPreviewStatus,
    MessageStreamProjection,
};
pub use stamp::{
    MonotonicStampStore, RemoteStamp, SigningStamp, SigningStampAllocator, StampFloor,
    StampFloorUpdate, StampScope, hlc_from_floor,
};
pub use station_cas_projection::{StationCasProjection, StationCasProjectionUpdate};
#[cfg(all(feature = "native", not(target_arch = "wasm32")))]
pub use store::FileStore;
pub use store::{
    AccountCursorCheckpoint, BoundedSeenWindow, CursorScope, CursorStore,
    DEFAULT_SEEN_EVENTS_CAPACITY, DeliveryErrorClass, DeliveryId, DurableInboxStore,
    EventCacheStore, MAX_DELIVERY_ERROR_BYTES, MAX_PENDING_DELIVERIES, MAX_PENDING_READ,
    MemoryInboxStore, MemorySecureKeyStore, MemoryStore, OpaqueCursor, PendingDelivery,
    PutSecretOptions, SdkKeyStoreAdapter, SdkKeyStoreSecureAdapter, SecretClass, SecretDurability,
    SecureKeyStore, SecureKeyStoreBackendInfo, SecureKeyStoreError, SecureKeyStoreResult,
    account_id_storage_digest, device_storage_digest,
};
pub use submission_queue::{MemorySubmissionQueueStore, SubmissionQueueStore, SubmissionWorker};
pub use subscription::{
    AccountBatchProjector, AccountSubscribeTransport, AccountSubscription, SubscriptionControl,
    SubscriptionStopReason,
};
pub use websocket::{
    AuthProofRequest, BoxSocketFuture, ChannelFrame, PumpOutcome, SharedCell,
    WebSocketChannelState, WebSocketConnection, WebSocketConnector, WebSocketInbound,
    WebSocketPacer, WebSocketSocket, connect_websocket, select_websocket_binding,
    validate_websocket_transport, websocket_operations_reachable,
};
