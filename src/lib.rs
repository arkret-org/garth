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

pub use arkret_auth::AuthManager;
pub use arkret_canonical as canonical;
pub use arkret_crypto as crypto;
pub use arkret_models_collaboration::http_bodies::{EventsQueryOutcome, EventsSubscribeFrame};
pub use arkret_models_collaboration::session_grant_bodies::{
    SessionGrantOutcome, SessionGrantRefreshOutcome, SessionGrantRefreshRequestBody,
    SessionGrantRequestBody,
};
pub use arkret_models_collaboration::sync_frames::account_subscribe::{
    AccountSubscribeBatch, AccountSubscribeFrame, AccountSubscribeFrameKind, AccountSubscribeRealms,
};
pub use arkret_models_collaboration::sync_frames::account_sync::RealmSyncEntry;
pub use arkret_models_collaboration::sync_frames::client_sync::SyncRequestBody;
pub use arkret_state::resolver;
pub use arkret_state::resolver::RealmState;
pub use arkret_wire::GrantId;
pub use arkret_wire::{MorphId, Proof};
pub use error::{Error, Result};
pub use protocol::{
    ACTOR_PROFILE_SCHEMA, ActorKind, ActorProfile, ActorProfileId, ActorStatus, AppletId, BlobRef,
    CallId, CallRecordingId, CallStatePayloadRecordingResult, Cursor, DeviceId, Did,
    EncryptedEnvelope, Event, EventId, EventRequirements, Hash, Hlc, MORPH_SCHEMA, NonEmptyString,
    ObjectCreatePayload, ObjectPatchPayload, OperationType, Patch, RealmId, RecordingCaptureKind,
    RecordingMode, RecordingStartPayload, STRAND_SCHEMA, STRAND_TRACK_NAME_SYNTHESIS, SpaceId,
    StateSnapshot, StrandId, StrandTrackConfig, Timeline,
};

pub mod events {
    pub use arkret_wire::EventKind;
}

pub mod cursor {
    pub use arkret_hlc::*;
}

#[allow(ambiguous_glob_reexports, unused_imports)]
pub mod models {
    pub use arkret_event_draft::*;
    pub use arkret_models_collaboration::events_payloads::{
        account_misc::*, agent::*, call::*, capability_circle_consent_contact::*,
        content_block_poll::*, device_identity::*, ephemeral::*, event_wire::*,
        list_message_mimi_mls::*, mention::*, moderation::*, moderation_morph_misc::*,
        morph_message::*, object_create::*, preview_realm_reaction::*, redaction::*,
        strand_history_join::*, strand_ops::*,
    };
    pub use arkret_models_collaboration::governance::{
        accountability::*, agent_artifacts::*, agent_participation::*, audit::*, authorization::*,
        circle::*, delivery_binding::*, erasure::*, grant_constraint::*, handle_claim::*,
        history_visibility::*, invite_addressing::*, member_delivery_binding_candidate::*,
        membership_invite::*, moderation::*, moderation_appeal::*, moderation_queue::*,
        operation_wire::*, peer_contact::*, plaintext_visibility::*, policy_check::*,
        realm_governance::*, realm_lifecycle::*, resource_selector::*, third_party_invite::*,
    };
    pub use arkret_models_collaboration::object_lifecycle::*;
    pub use arkret_models_collaboration::objects::{
        account_status::*, blob::*, direct_conversation::*, interop::*, media::*, mimi::*,
        object_facets::*, productivity::*, profiles::*, queries::*, query_projection::*,
        read_receipts::*, realm::*, realm_alias::*, relation::*, space::*, strand::*, view::*,
    };
    pub use arkret_models_identity::*;
    pub use arkret_wire::*;
}

pub mod sync {
    pub use arkret_models_collaboration::sync_frames::{
        account_subscribe::*, account_sync::*, client_sync::*, snapshot::*, stream_trace::*,
    };
    pub use arkret_models_discovery::PresenceStatus;
}

pub mod account_handoff;
#[cfg(feature = "mls")]
pub mod agent_mls;
pub mod backoff;
pub mod crypto_state_store;
pub mod event;
pub mod executor;
pub mod facade;
pub mod inbound;
pub mod maybe_send;
pub mod orchestrator;
pub mod outbound;
pub mod profile;
pub mod projection;
pub mod runtime_store;
pub mod session;
pub mod stamp;
pub mod store;
pub mod subscribe;
pub mod sync_client;
pub use account_handoff::{
    AccountHandoffDisposition, OidcAccountHandoffInput, account_handoff_disposition,
    identity_binding_challenge_request, identity_creation_register_request,
    oidc_account_handoff_request, pre_registration_session_grant_request, validate_binding_receipt,
};
#[cfg(feature = "mls")]
pub use agent_mls::{
    AgentMlsAuthorizationBinding, AgentMlsConsumeIntent, AgentMlsRuntime, AgentMlsRuntimePhase,
    AgentMlsWelcomeInput, AgentMlsWelcomeOutcome, AgentMlsWelcomeVerifier,
};
pub use arkret_event_draft::MessageEventPayload;
pub use backoff::Backoff;
pub use crypto_state_store::{
    CRYPTO_STORE_BACKUP_VERSION, CryptoStore, CryptoStoreBackupEnvelope, CryptoStoreKeyRotation,
    EncryptedMemoryCryptoStore, MemoryCryptoStore, MlsCommitSource, MlsEpochSecretRecord,
    MlsGroupStateRecord, MlsGroupStateSink, MlsRecoveryAction, MlsRecoveryPlan,
    PlatformKeyStoreDescriptor, PlatformKeyStoreKind, StoredDeviceVerification,
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
pub use profile::*;
pub use projection::{ProjectionMount, RealmStateReducer};
pub use runtime_store::{
    AccountSessionStore, AuditAction, AuditEntry, AuditLogStore, BlobMetadataStore,
    EventCacheStore as EventBodyCacheStore, MemoryPersistenceStore, StateSnapshotStore, StoreCache,
    StoreEncryptionKey, StoredAccountData, rebuild_realm_state_from_events,
    restore_realm_state_from_persistence,
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
    EphemeralDeviceKeyResolver, EventsSubscribeTransport, ExponentialBackoff, LocalEcho,
    ProcessedRealm, SendQueue, SendQueueItem, SendQueueItemKind, SendQueueSnapshot,
    SendQueueStatus, SyncGapStrategy, SyncLoop, SyncLoopControl, SyncLoopSnapshot, SyncLoopStep,
    SyncRecoveryAction, SyncResponseProcessor, SyncTransport,
};
