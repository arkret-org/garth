//! Private, explicit imports from the focused SDK semantic crates.
//!
//! Runtime code imports protocol-owned types through this module so the
//! implementation remains readable without publishing a second protocol API.

pub(crate) use arkret_keystore::{KeyBytes, KeyStore, KeyStoreError};
pub(crate) use arkret_models_collaboration::account_lifecycle::{
    AccountRegisterOutcome, AccountRegisterRequestBody,
};
pub(crate) use arkret_models_collaboration::agent_operations::AgentRequestedScopeDisclosure;
pub(crate) use arkret_models_collaboration::event_query::EventsQueryOrder;
pub(crate) use arkret_models_collaboration::events_payloads::MessageCreatePayload;
pub(crate) use arkret_models_collaboration::governance::agent_participation::ParticipationBits;
pub(crate) use arkret_models_collaboration::http_bodies::{
    EventsQueryOutcome, EventsSubscribeFrame,
};
pub(crate) use arkret_models_collaboration::session_grant_bodies::{
    SessionGrantAgentScopeRequest, SessionGrantDpopBindingProof, SessionGrantOutcome,
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
    PresencePlaintext, ReadReceipt, SignalSequence, SignalSequenceDecision, SignalSequenceDomain,
    SignalSequenceEndpoint, SignalSequenceHighWater, TypingPlaintext, open_signal_plaintext,
};
#[cfg(test)]
pub(crate) use arkret_models_collaboration::sync_frames::account_subscribe::{
    AccountDataContainer, StationCasAccountDataRemoval,
};
pub(crate) use arkret_models_collaboration::sync_frames::account_subscribe::{
    AccountStreamInterrupt, AccountSubscribeBatch, AccountSubscribeFrameKind,
    StationCasAccountDataContainer,
};
// The sender endpoint is only constructed by the sync-loop fixtures: the
// runtime consumes envelopes it decodes rather than building them.
#[cfg(test)]
pub(crate) use arkret_models_collaboration::sync_frames::account_sync::DeviceMessageSender;
pub(crate) use arkret_models_collaboration::sync_frames::account_sync::{
    AccountSubscribeDeviceListChanges, AccountSubscribeRealmSummary, DeviceMessageEnvelope,
    NotificationDelta, NotificationDeltaAction, Timeline,
};
pub(crate) use arkret_models_collaboration::sync_frames::client_sync::{RealmUpdate, SyncUpdates};
pub(crate) use arkret_models_collaboration::sync_frames::stream_trace::StreamTraceValidator;
pub(crate) use arkret_models_crypto::{
    MlsCommitEnvelope, MlsEndpointIdentity, MlsKeyPackageRecord, MlsWelcomeEnvelope,
};
pub use arkret_models_discovery::{
    PresenceStatus, aggregate_presence_states, validate_last_active_at, validate_status_message,
};
pub(crate) use arkret_models_identity::agent_signer_evidence::AgentSignerEvidence;
pub(crate) use arkret_models_identity::{
    AccountBindingReceipt, AccountDataRow, AccountHandoffBinding, AccountHandoffOutcome,
    AccountHandoffRequestBody, DeviceVerificationState, DidOperationSubmitRequestBody,
    IdentityBindingChallengeOutcome, IdentityBindingChallengeRequestBody, IdentityBindingPurpose,
    IdentityCreationCommandKind, IdentityCreationGoal, IdentityCreationLease,
    IdentityCreationLeaseState, IdentityCreationLocalArtifactKind,
    IdentityCreationRecoveryKeyState, IdentityCreationRegistration, InitialSessionGrantIntent,
    ReservedIdentityCreation, UnsignedAccountHandoffAuthenticationProof,
    UnsignedAccountHandoffRequestBody, UnsignedIdentityCreationControlProof,
    UnsignedIdentityCreationControlProofBody,
};
pub(crate) use arkret_state::resolver::RealmState;
pub(crate) use arkret_wire::{
    AccountId, ActorId, Base64UrlString, DeviceId, Did, DidCoreId, DidUrl, Event, EventId,
    EventKind, Hash, Hlc, MessageId, MessageStreamId, NonEmptyString, PcrGenesisUnit, RealmId,
    RequestId, ScopeRef, SealId, SessionGrantId, SidecarId, SignalEnvelope, SignalStreamFrame,
    StrandId, project_did_to_core_id,
};
pub use arkret_wire::{AuthorizationLease, IngressReceipt};

pub(crate) use crate::{Error, Result};

pub(crate) fn verified_event_id(
    event: &Event,
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<EventId> {
    event.verify_event_id_matches_content_with_digest_suite(digest_suite)?;
    event.validate_station_admission_binding(digest_suite)?;
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
pub(crate) use arkret_models_collaboration::sync_frames::account_subscribe::{
    AccountSubscribeFrame, AccountSubscribeRealms,
};
#[cfg(test)]
pub(crate) use arkret_models_collaboration::sync_frames::account_sync::{
    AccountSubscribeUnreadCounts, AgentRuntimeApprovalNotificationData,
    AgentRuntimeApprovalNotificationRemovalData, AgentRuntimeApprovalRemovalReason,
    DeviceMessageContainer, NotificationContainer, NotificationData, RealmSyncEntry,
};
#[cfg(test)]
pub(crate) use arkret_models_collaboration::sync_frames::client_sync::SyncRequestBody;
#[cfg(test)]
pub(crate) use arkret_models_crypto::MlsKeyPackageState;
#[cfg(test)]
pub(crate) use arkret_models_identity::{ACCOUNT_HANDOFF_ALLOWED_OPERATIONS, Handle};
#[cfg(test)]
pub(crate) use arkret_wire::{DeviceMessageId, NotificationId, Problem, ProtocolKind};

pub(crate) mod canonical {
    pub(crate) use arkret_canonical::{canonical_json_bytes, canonical_sha256};
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
        AgentSidecarExchangeControl, AgentSidecarExchangeControlAction,
        AgentSidecarExchangeFoldedFrontier, AgentSidecarExchangeId, AgentSidecarExchangeProjection,
        AgentSidecarExchangeProjectionSchema, AgentSidecarExchangeRequestContext,
        AgentSidecarExchangeStatus, AgentSidecarProjectionProvenance, AgentSidecarViewState,
        agent_sidecar_exchange_event_set_digest,
    };
    // The v1 exchange profile fixes the completion policy, so only a fixture
    // that authors a request context still names the enum.
    #[cfg(test)]
    pub(crate) use arkret_models_collaboration::agent_operations::{
        AgentSidecarExchangeCompletionPolicy, AgentSidecarExchangeControlSchema,
        AgentSidecarSourceTrackRef,
    };
}

pub(crate) mod session_grant {
    pub(crate) use arkret_auth::session_grant::agent_key_proof_session_grant_request;
}

pub(crate) mod signatures {
    pub(crate) use arkret_signatures::proof::verify_ed25519_signal_proof;
    #[cfg(test)]
    pub(crate) use arkret_signatures::sign_ed25519_detached_jws;
    pub(crate) use arkret_signatures::{PublicKeyMaterial, webvh};
}

pub(crate) mod sync {
    pub(crate) use arkret_models_collaboration::sync_frames::client_sync::{
        LimitedTimelineState, RealmUpdate, SyncFilter, SyncGap, SyncRequestBody, SyncUpdates,
    };
}
