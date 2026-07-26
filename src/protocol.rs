//! Private, explicit imports from the focused SDK semantic crates.
//!
//! Runtime code imports protocol-owned types through this module so the
//! implementation remains readable without publishing a second protocol API.

pub(crate) use crate::{Error, Result};
pub(crate) use arkret_keystore::{KeyBytes, KeyStore, KeyStoreError};
pub(crate) use arkret_models_collaboration::account_lifecycle::AccountRegisterRequestBody;
pub(crate) use arkret_models_collaboration::agent_signer_evidence::AgentSignerEvidence;
pub(crate) use arkret_models_collaboration::event_query::EventsQueryOrder;
pub(crate) use arkret_models_collaboration::events_payloads::ephemeral::EphemeralEnvelope;
pub(crate) use arkret_models_collaboration::http_bodies::{
    EventsQueryOutcome, EventsSubscribeFrame, EventsSubscribeFrameKind,
};
pub(crate) use arkret_models_collaboration::session_grant_bodies::{
    SessionGrantAgentScopeRequest, SessionGrantAppletDelegation, SessionGrantDpopBindingProof,
    SessionGrantOutcome, SessionGrantRefreshOutcome, SessionGrantRefreshProof,
    SessionGrantRefreshRequestBody, SessionGrantRequestBody,
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
pub(crate) use arkret_models_discovery::{
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
pub(crate) use arkret_wire::{
    BlobRef, DeviceId, Did, Event, EventId, GrantId, Hash, Hlc, NonEmptyString, RealmId, RequestId,
    SidecarId, StrandId,
};

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
    AgentRuntimeApprovalRemovalReason, DeviceMessageContainer, EphemeralEventContainer,
    EventContainer, NotificationContainer, NotificationData, RealmSyncEntry,
};
#[cfg(test)]
pub(crate) use arkret_models_collaboration::sync_frames::client_sync::SyncRequestBody;
#[cfg(test)]
pub(crate) use arkret_models_crypto::MlsKeyPackageState;
#[cfg(test)]
pub(crate) use arkret_models_identity::{ACCOUNT_HANDOFF_ALLOWED_OPERATIONS, Handle};
#[cfg(test)]
pub(crate) use arkret_wire::{
    BLOB_SCHEMA, DeviceMessageId, ErrorEnvelope, EventRequirements, MORPH_SCHEMA, NotificationId,
    NotificationType, ObjectState, Proof, ProtocolKind,
};

pub(crate) mod auth {
    pub(crate) use arkret_auth::AuthSession;
}

pub(crate) mod canonical {
    pub(crate) use arkret_canonical::{
        canonical_json_bytes, canonical_sha256, sha256_bytes_from_slices, sha256_digest,
    };
}

pub(crate) mod dpop {
    pub(crate) use arkret_signatures::dpop::build_dpop_proof;
}

#[cfg(test)]
pub(crate) mod events {
    pub(crate) use arkret_wire::EventKind;
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
    pub(crate) use arkret_signatures::webvh;
    #[cfg(test)]
    pub(crate) use arkret_signatures::{PublicKeyMaterial, sign_eddsa_detached_jws};
}

pub(crate) mod sync {
    #[cfg(test)]
    pub(crate) use arkret_models_collaboration::sync_frames::client_sync::SyncStreamPosition;
    pub(crate) use arkret_models_collaboration::sync_frames::client_sync::{
        LimitedTimelineState, RealmUpdate, SubscriptionConfig, SyncFilter, SyncGap,
        SyncRequestBody, SyncUpdates, ToDeviceAck, ToDeviceAckStatus, WaitForFrontier,
    };
}
