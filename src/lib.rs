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
pub mod authority;
pub mod direct_conversation;
pub mod executor;
pub mod facade;
pub mod maybe_send;
pub mod message_authoring;
pub mod mls;
pub mod replica;
pub mod runtime_journey;
pub mod security_transaction;
pub mod service_route;
pub mod service_route_material;
pub mod session;
pub mod signal;
pub mod stamp;
pub mod store;
pub mod submission_queue;
pub mod subscription;
pub mod websocket;

pub use account_handoff::*;
pub use account_sync::*;
pub use actor_profile_directory::{
    ActorProfileDirectory, ActorProfileResolveTransport, ActorProfileUnavailableCause,
    ActorProfileView, DEFAULT_ACTOR_PROFILE_FRESH_FOR_SECONDS,
};
pub use arkret_wire::{
    AuthorityBundleRequest, AuthorityHandoffRequest, AuthoritySubmitOutcome,
    AuthoritySubmitRequest, CommitStreamHead, CommitStreamRef, CommittedEventRef,
    CommittedEventResolveOutcome, CommittedEventResolveRequest, EventCommitSubmission,
    RealmAuthorityBundle, RealmAuthorityHandoff, RealmCommit, RealmStateSnapshot, StreamItem,
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
    MessageAuthoringContent, MessageAuthoringIntent, MessageEncryptionContext,
    MessageSubmitRequestBody, author_message, queue_authored_message,
};
pub use mls::{
    AcceptedMlsArtifact, MemoryMlsLocalStateStore, MlsDeviceSecretStore, MlsInstallQueue,
    MlsInstaller, MlsLocalStateStore, QueuedMlsInstall, SecureMlsLocalStateStore,
};
pub use replica::{RealmReplica, StreamReplica};
pub use runtime_journey::{ParticipationAction, ParticipationAdmissionFacts};
pub use security_transaction::{
    ClientStepAttestation, DurableSecurityTransaction, MemorySecurityTransactionStore,
    PcrPolicyRecoveryPlan, PendingSecurityTransactionContinue, RecoveryTerminalCommit,
    RecoveryTransactionCreateRequest, SecurityTransaction, SecurityTransactionContinueRequest,
    SecurityTransactionCreateRequest, SecurityTransactionEngine, SecurityTransactionPreparedPlan,
    SecurityTransactionStore, SecurityTransactionTerminalOutcome, SecurityTransactionTransport,
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
pub use stamp::{
    MonotonicStampStore, RemoteStamp, SigningStamp, SigningStampAllocator, StampFloor,
    StampFloorUpdate, StampScope, hlc_from_floor,
};
#[cfg(all(feature = "native", not(target_arch = "wasm32")))]
pub use store::FileStore;
pub use store::{
    BoundedSeenWindow, CursorScope, CursorStore, DEFAULT_SEEN_EVENTS_CAPACITY, DeliveryId,
    DurableInboxStore, EventCacheStore, MAX_PENDING_DELIVERIES, MAX_PENDING_READ, MemoryInboxStore,
    MemorySecureKeyStore, MemoryStore, OpaqueCursor, PendingDelivery, PutSecretOptions,
    SdkKeyStoreAdapter, SdkKeyStoreSecureAdapter, SecretClass, SecretDurability, SecureKeyStore,
    SecureKeyStoreBackendInfo, SecureKeyStoreError, SecureKeyStoreResult,
    account_id_storage_digest, device_storage_digest,
};
pub use submission_queue::{MemorySubmissionQueueStore, SubmissionQueueStore, SubmissionWorker};
pub use subscription::{
    AccountBatchProjector, AccountSubscribeTransport, AccountSubscription, SubscriptionControl,
    SubscriptionStopReason,
};
pub use websocket::{
    AuthProofRequest, BoxSocketFuture, WebSocketConnector, WebSocketInbound, WebSocketPacer,
    WebSocketSocket, select_websocket_binding, validate_websocket_transport,
    websocket_operations_reachable,
};
