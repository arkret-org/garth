//! Private, explicit imports from the focused SDK semantic crates.
//!
//! Runtime code imports protocol-owned types through this module so the
//! implementation remains readable without publishing a second protocol API.

pub(crate) use crate::{Error, Result};
pub(crate) use arkret_keystore::{KeyBytes, KeyStore, KeyStoreError};
pub(crate) use arkret_models_collaboration::account_lifecycle::AccountRegisterRequestBody;
pub(crate) use arkret_models_collaboration::agent_signer_evidence::{
    AgentSignerEvidence, AgentSignerEvidenceQuerySelector,
};
pub(crate) use arkret_models_collaboration::event_query::EventsQueryOrder;
pub(crate) use arkret_models_collaboration::events_payloads::MessageCreatePayload;
pub(crate) use arkret_models_collaboration::governance::agent_participation::ParticipationBits;
pub(crate) use arkret_models_collaboration::http_bodies::{
    EventsQueryOutcome, EventsSubscribeFrame, EventsSubscribeFrameKind,
};
pub(crate) use arkret_models_collaboration::session_grant_bodies::{
    SessionGrantAgentScopeRequest, SessionGrantAppletDelegation, SessionGrantDpopBindingProof,
    SessionGrantOutcome, SessionGrantRefreshOutcome, SessionGrantRefreshProof,
    SessionGrantRefreshRequestBody, SessionGrantRequestBody,
};
pub(crate) use arkret_models_collaboration::signal_message_stream::{
    MAX_MESSAGE_STREAM_LIFETIME_SECONDS, MAX_MESSAGE_STREAM_PREVIEW_BYTES,
    MAX_MESSAGE_STREAMS_PER_DEVICE, MESSAGE_STREAM_STALLED_AFTER_SECONDS, MessageStreamFormat,
    MessageStreamFrame,
};
/// The Signal plaintext family (`sync/signal.md` §1.1). Re-exported publicly
/// because [`crate::signal::SignalPlaintext`] carries the typed profile on a
/// public field: a consumer has to be able to name the variant it matches.
pub use arkret_models_collaboration::signal_plaintext::{
    PresencePlaintext, ReadReceipt, SignalPlaintext as SdkSignalPlaintext, TypingPlaintext,
    open_signal_plaintext,
};
pub(crate) use arkret_models_collaboration::sync_frames::account_subscribe::{
    AccountStreamInterrupt, AccountSubscribeBatch, AccountSubscribeFrameKind,
};
pub(crate) use arkret_models_collaboration::sync_frames::account_sync::{
    AccountSubscribeDeviceListChanges, AccountSubscribeRealmSummary, DeviceMessageEnvelope,
    NotificationDelta, NotificationDeltaAction, Timeline,
};
pub(crate) use arkret_models_collaboration::sync_frames::client_sync::{RealmUpdate, SyncUpdates};
pub(crate) use arkret_models_collaboration::sync_frames::stream_trace::StreamTraceValidator;
pub(crate) use arkret_models_crypto::{MlsCommitEnvelope, MlsKeyPackageRecord, MlsWelcomeEnvelope};
pub use arkret_models_discovery::{
    PresenceStatus, aggregate_presence_states, validate_last_active_at, validate_status_message,
};
pub(crate) use arkret_models_identity::{
    AccountBindingReceipt, AccountHandoffAuthenticationProof,
    AccountHandoffAuthenticationProofKind, AccountHandoffBinding, AccountHandoffOutcome,
    AccountHandoffRequestBody, DeviceVerificationState, DidOperationSubmitRequestBody,
    IdentityBindingChallengeOutcome, IdentityBindingChallengeRequestBody, IdentityBindingPurpose,
    IdentityCreationControlProof, IdentityCreationControlProofKind, IdentityCreationLease,
    IdentityCreationRegistration, ReservedIdentityCreation, SessionGrantProofKind,
};
pub(crate) use arkret_state::resolver::RealmState;
pub use arkret_wire::{AuthorizationLease, IngressReceipt};
pub(crate) use arkret_wire::{
    BlobRef, DeviceId, Did, DidUrl, Event, EventId, EventKind, Hash, Hlc, MessageId,
    MessageStreamId, NonEmptyString, RealmId, RequestId, ScopeRef, SealId, SessionGrantId,
    SidecarId, SignalEnvelope, SignalStreamFrame, StrandId,
};
pub(crate) use arkret_wire::{ProtocolOpaqueId, ProtocolOperationId};

pub(crate) fn verified_event_id(event: &Event) -> Result<EventId> {
    let digest_suite = event.event_id.digest_suite_code().digest_suite();
    event.verify_event_id_matches_content_with_digest_suite(digest_suite)?;
    Ok(event.event_id.clone())
}

#[cfg(test)]
pub(crate) mod signal {
    pub(crate) use arkret_wire::signal::{
        SIGNAL_AEAD_PURPOSE, SIGNAL_AEAD_SCHEME, SignalClass, SignalEncryptedPayload, SignalKeyRef,
        SignalProof,
    };
}

#[cfg(test)]
pub(crate) use arkret_models_collaboration::session_grant_bodies::SessionGrantScopeDetails;
#[cfg(test)]
pub(crate) use arkret_models_collaboration::sync_frames::account_subscribe::{
    AccountSubscribeFrame, AccountSubscribeRealms,
};
#[cfg(test)]
pub(crate) use arkret_models_collaboration::sync_frames::account_sync::{
    AccountNotificationDataKind, AccountSubscribeUnreadCounts,
    AgentRuntimeApprovalNotificationData, AgentRuntimeApprovalNotificationRemovalData,
    AgentRuntimeApprovalRemovalReason, DeviceMessageContainer, EventContainer,
    NotificationContainer, NotificationData, RealmSyncEntry,
};
#[cfg(test)]
pub(crate) use arkret_models_collaboration::sync_frames::client_sync::SyncRequestBody;
#[cfg(test)]
pub(crate) use arkret_models_crypto::MlsKeyPackageState;
#[cfg(test)]
pub(crate) use arkret_models_identity::{ACCOUNT_HANDOFF_ALLOWED_OPERATIONS, Handle};
#[cfg(test)]
pub(crate) use arkret_wire::{
    DeviceMessageId, ErrorEnvelope, EventRequirements, NotificationId, NotificationKind,
    ObjectState, ProtocolKind,
};

pub(crate) mod auth {
    pub(crate) use arkret_auth::AuthSession;
}

pub(crate) mod canonical {
    pub(crate) use arkret_canonical::{
        canonical_json_bytes, canonical_sha256, parse_canonical_json, sha256_bytes_from_slices,
        sha256_digest,
    };
}

pub(crate) mod dpop {
    pub(crate) use arkret_signatures::dpop::build_dpop_proof;
}

pub(crate) mod hlc {
    pub(crate) use arkret_hlc::HlcGenerator;
    pub(crate) use arkret_identifiers::hlc::{HLC_MAX_LOGICAL, HLC_MAX_PHYSICAL_MS, parse_hlc};
}

#[cfg(test)]
pub(crate) mod identifiers {
    pub(crate) use arkret_identifiers::Cursor;
}

pub(crate) mod models {
    pub(crate) use arkret_models_collaboration::agent_operations::{
        AgentSidecarDisplayMode, AgentSidecarEventExchangeBinding, AgentSidecarExchangeBindingRole,
        AgentSidecarExchangeCompletionPolicy, AgentSidecarExchangeControl,
        AgentSidecarExchangeControlAction, AgentSidecarExchangeFoldedFrontier,
        AgentSidecarExchangeId, AgentSidecarExchangeOrigin, AgentSidecarExchangeProjection,
        AgentSidecarExchangeProjectionSchema, AgentSidecarExchangeRequestContext,
        AgentSidecarExchangeStatus, AgentSidecarProjectionProvenance, AgentSidecarViewState,
        agent_sidecar_exchange_event_set_digest,
    };
    #[cfg(test)]
    pub(crate) use arkret_models_collaboration::agent_operations::{
        AgentSidecarExchangeControlSchema, AgentSidecarSourceTrackRef,
    };
    pub(crate) use arkret_models_collaboration::objects::blob::BlobMetadata;
}

pub(crate) mod resolver {
    #[cfg(test)]
    pub(crate) use arkret_state::resolver::SnapshotRestoreSource;
    pub(crate) use arkret_state::resolver::{RealmState, SnapshotRestore, StateSnapshot};
}

pub(crate) mod session_grant {
    pub use arkret_auth::session_grant::SessionGrantProofFields;
    pub(crate) use arkret_auth::session_grant::{
        agent_key_proof_session_grant_request, did_proof_session_grant_request,
        holder_proof_session_grant_request, oidc_session_grant_request,
        pre_registration_handoff_session_grant_request,
    };
}

pub(crate) mod signatures {
    pub(crate) use arkret_signatures::PublicKeyMaterial;
    pub(crate) use arkret_signatures::proof::verify_ed25519_signal_proof;
    #[cfg(test)]
    pub(crate) use arkret_signatures::sign_ed25519_detached_jws;
    pub(crate) use arkret_signatures::webvh;
}

pub(crate) mod sync {
    pub(crate) use arkret_models_collaboration::sync_frames::client_sync::{
        LimitedTimelineState, RealmUpdate, SubscriptionConfig, SyncFilter, SyncGap,
        SyncRequestBody, SyncUpdates, ToDeviceAck, ToDeviceAckStatus,
    };
}
