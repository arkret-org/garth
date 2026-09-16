//! Runtime-neutral account-first onboarding request orchestration.
//!
//! Hosts own navigation, durable public checkpoints and custody prompts. This
//! module owns the canonical request sequence and delegates all protocol
//! cryptography and DTO validation to the Arkret SDK.

use std::collections::BTreeSet;

use arkret_models_collaboration::account_operations::{
    AccountRegisterOutcome, AccountRegisterRequestBody,
};
use arkret_models_identity::{
    AccountHandoffBinding, AccountHandoffOutcome, AccountHandoffRequestBody,
    IdentityBindingChallengeOutcome, IdentityBindingChallengeRequestBody, IdentityBindingPurpose,
    IdentityCreationCommandKind, IdentityCreationControlProofKind,
    IdentityCreationGoal, IdentityCreationLease, IdentityCreationLeaseState,
    IdentityCreationLocalArtifactKind, IdentityCreationRecoveryKeyState,
    IdentityCreationRegistration, InitialSessionGrantIntent, PrincipalRegistrationAnchor,
    ReservedIdentityCreation, UnsignedAccountHandoffAuthenticationProof,
    UnsignedAccountHandoffRequestBody, UnsignedIdentityCreationControlProof,
    UnsignedIdentityCreationControlProofBody,
};
use arkret_wire::{Base64UrlString, DeviceId, Did, DidCoreId, Hash, PcrGenesisUnit, RequestId};

use crate::{Error, Result};

#[derive(Clone, Debug)]
pub struct OidcAccountHandoffInput {
    pub request_id: RequestId,
    pub audience_id: DidCoreId,
    pub issuer_uri: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub state: String,
    pub nonce: String,
    pub authorization_code: String,
    pub code_verifier: String,
}

#[derive(Clone, Debug, PartialEq)]
pub enum AccountHandoffDisposition {
    IdentityCreationActive(Box<IdentityCreationLease>),
    IdentityCreationBusy {
        retry_after_ms: u64,
        expires_at: chrono::DateTime<chrono::Utc>,
    },
    Bound {
        principal_id: DidCoreId,
        did: Did,
    },
}

/// Host-local secure material observed after the store has been scoped and
/// hydrated. The reference is opaque to Garth; only the host may dereference
/// it into a signing capability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReturningDeviceCandidate {
    pub principal_id: DidCoreId,
    pub device_id: DeviceId,
    pub signer_ref: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LocalEvidenceHydration {
    Loading,
    Ready,
    Failed { reason: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LocalEvidenceUnavailableReason {
    HydrationInProgress,
    StorageFailure { reason: String },
    InvalidSignerReference,
    AmbiguousReturningDevices,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NormalizedLocalEvidence {
    ReturningDevice(ReturningDeviceCandidate),
    NoReturningDevice,
    Unavailable(LocalEvidenceUnavailableReason),
}

/// Result of local normalization. Foreign-account candidates are quarantined
/// from the current transaction, never erased or interpreted as absence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalEvidenceNormalization {
    pub evidence: NormalizedLocalEvidence,
    pub quarantined_candidates: Vec<ReturningDeviceCandidate>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BoundSessionRoute {
    IssueOrReplay(ReturningDeviceCandidate),
    DeviceSetupRequired,
    Diagnostics(LocalEvidenceUnavailableReason),
}

/// Reduce fully hydrated host evidence to one canonical returning-device fact.
///
/// Loading and storage failure are explicit outcomes. A different account's
/// candidate is quarantined, not deleted. Multiple distinct candidates for the
/// authenticated principal are a contradiction and fail closed.
pub fn normalize_local_evidence(
    authenticated_principal_id: &DidCoreId,
    hydration: LocalEvidenceHydration,
    candidates: impl IntoIterator<Item = ReturningDeviceCandidate>,
) -> LocalEvidenceNormalization {
    let mut quarantined_candidates = Vec::new();
    let mut matching_candidates = Vec::new();
    for candidate in candidates {
        if &candidate.principal_id == authenticated_principal_id {
            if !matching_candidates.contains(&candidate) {
                matching_candidates.push(candidate);
            }
        } else {
            quarantined_candidates.push(candidate);
        }
    }

    let evidence =
        match hydration {
            LocalEvidenceHydration::Loading => NormalizedLocalEvidence::Unavailable(
                LocalEvidenceUnavailableReason::HydrationInProgress,
            ),
            LocalEvidenceHydration::Failed { reason } => NormalizedLocalEvidence::Unavailable(
                LocalEvidenceUnavailableReason::StorageFailure { reason },
            ),
            LocalEvidenceHydration::Ready => match matching_candidates.as_slice() {
                [] => NormalizedLocalEvidence::NoReturningDevice,
                [candidate] if candidate.signer_ref.trim().is_empty() => {
                    NormalizedLocalEvidence::Unavailable(
                        LocalEvidenceUnavailableReason::InvalidSignerReference,
                    )
                }
                [candidate] => NormalizedLocalEvidence::ReturningDevice(candidate.clone()),
                _ => NormalizedLocalEvidence::Unavailable(
                    LocalEvidenceUnavailableReason::AmbiguousReturningDevices,
                ),
            },
        };

    LocalEvidenceNormalization {
        evidence,
        quarantined_candidates,
    }
}

/// Host-normalized relation between one locally persisted identity-creation
/// checkpoint and the sign-in transaction that is about to start.
///
/// Every field is a fact the host already proved against durable state; this
/// stage never re-derives them from UI signals or bare `Option` presence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegistrationCheckpointFacts {
    /// The checkpoint's authority, audience, account subject and transaction
    /// identity all match the account handoff this sign-in continues.
    pub continues_current_transaction: bool,
    /// The continued handoff still carries the exact identity-creation lease
    /// id and fence frozen into the checkpoint, or the server already bound
    /// the identity this checkpoint created.
    pub lease_matches: bool,
    /// The identity-creation lease window observed on the continued handoff
    /// has elapsed.
    pub lease_expired: bool,
    /// The Account Authority closed identity creation for this account without
    /// adopting this checkpoint.
    pub identity_creation_terminal: bool,
}

/// What a sign-in transaction may do with one persisted registration
/// checkpoint before the Account Authority has spoken.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistrationCheckpointDisposition {
    /// Identity creation legitimately owns this authentication. The returning
    /// device candidate is not part of this transaction's input.
    ContinuesIdentityCreation,
    /// Current-transaction temporary state that is provably fenced out,
    /// expired or terminal. It may be erased in the same local commit and
    /// never suppresses a returning device candidate.
    DiscardStale,
    /// The checkpoint belongs to another transaction or another account. It is
    /// excluded from this transaction's input and retained untouched.
    Quarantine,
}

/// Decide how a persisted registration checkpoint participates in the sign-in
/// transaction that is starting.
///
/// Absence of a matching transaction is never authority to delete durable
/// draft material, and a checkpoint that this transaction cannot continue can
/// never suppress a returning device candidate.
pub fn classify_registration_checkpoint(
    facts: RegistrationCheckpointFacts,
) -> RegistrationCheckpointDisposition {
    if !facts.continues_current_transaction {
        return RegistrationCheckpointDisposition::Quarantine;
    }
    if facts.identity_creation_terminal || facts.lease_expired || !facts.lease_matches {
        return RegistrationCheckpointDisposition::DiscardStale;
    }
    RegistrationCheckpointDisposition::ContinuesIdentityCreation
}

/// Closed observation of one durable or server-authored onboarding fact.
///
/// A backend read failure is deliberately not equivalent to absence. Hosts
/// must surface [`BoundCompletionResumeReadError`] as retryable storage/server
/// diagnostics instead of routing to identity recovery or abandonment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BoundCompletionMaterialState {
    Present,
    Absent,
    ReadError,
    NotRequired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BoundCompletionHandoffState {
    ActiveBound,
    MissingOrExpired,
    ReadError,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BoundCompletionCheckpointStage {
    Accepted,
    RecoveryMaterialComplete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BoundCompletionMaterial {
    Handoff,
    RecoveryPolicy,
    DeviceId,
    SigningSeed,
    GrantBindingKey,
    SessionGrant,
    RecoveryEvidence,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BoundCompletionResumeReadError {
    pub material: BoundCompletionMaterial,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BoundCompletionContradiction {
    AuthorityMismatch,
    DeviceSlotConflict,
    CompletedStageMissingEvidence,
}

/// Durable local inventory plus the server facts needed to resume a bound
/// identity-creation transaction.
///
/// `hpke_private_key` is diagnostic-only in this classifier. Its repair and
/// KeyPackage rotation semantics belong to the MLS recovery transaction, but
/// retaining it here ensures every transition can record the complete custody
/// inventory without letting an HPKE absence bypass the Recovery Key gate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BoundCompletionResumeFacts {
    pub handoff: BoundCompletionHandoffState,
    pub checkpoint_stage: BoundCompletionCheckpointStage,
    pub recovery_policy: BoundCompletionMaterialState,
    pub device_id: BoundCompletionMaterialState,
    pub signing_seed: BoundCompletionMaterialState,
    pub grant_binding_key: BoundCompletionMaterialState,
    pub session_grant: BoundCompletionMaterialState,
    pub recovery_evidence: BoundCompletionMaterialState,
    pub hpke_private_key: BoundCompletionMaterialState,
    pub authority_matches: bool,
    pub device_slot_matches: bool,
    pub grant_matches_account: bool,
    pub grant_is_live: bool,
    pub grant_binding_matches_handoff: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BoundCompletionResumeDisposition {
    RestoreRuntime,
    ReissueGrant,
    RecoverWithPolicy,
    StrandedIdentity,
    ReauthRequired,
    Contradiction {
        reason: BoundCompletionContradiction,
    },
}

/// Classify a bound onboarding continuation from proved local and server facts.
///
/// This function never infers server truth from local absence. In particular,
/// a missing signer becomes `StrandedIdentity` only after the host has also
/// proved that the server has no active recovery policy. Recovery-policy state
/// is not required while the accepted signer is present.
pub fn classify_bound_completion_resume(
    facts: BoundCompletionResumeFacts,
) -> std::result::Result<BoundCompletionResumeDisposition, BoundCompletionResumeReadError> {
    use BoundCompletionMaterial as Material;
    use BoundCompletionMaterialState as State;

    if facts.handoff == BoundCompletionHandoffState::ReadError {
        return Err(BoundCompletionResumeReadError {
            material: Material::Handoff,
        });
    }
    for (material, state) in [
        (Material::DeviceId, facts.device_id),
        (Material::SigningSeed, facts.signing_seed),
        (Material::GrantBindingKey, facts.grant_binding_key),
        (Material::SessionGrant, facts.session_grant),
        (Material::RecoveryEvidence, facts.recovery_evidence),
    ] {
        if matches!(state, State::ReadError | State::NotRequired) {
            return Err(BoundCompletionResumeReadError { material });
        }
    }

    if !facts.authority_matches {
        return Ok(BoundCompletionResumeDisposition::Contradiction {
            reason: BoundCompletionContradiction::AuthorityMismatch,
        });
    }
    if !facts.device_slot_matches {
        return Ok(BoundCompletionResumeDisposition::Contradiction {
            reason: BoundCompletionContradiction::DeviceSlotConflict,
        });
    }
    if facts.checkpoint_stage == BoundCompletionCheckpointStage::RecoveryMaterialComplete
        && facts.recovery_evidence == State::Absent
    {
        return Ok(BoundCompletionResumeDisposition::Contradiction {
            reason: BoundCompletionContradiction::CompletedStageMissingEvidence,
        });
    }
    if facts.handoff == BoundCompletionHandoffState::MissingOrExpired {
        return Ok(BoundCompletionResumeDisposition::ReauthRequired);
    }
    if facts.signing_seed == State::Absent {
        if matches!(facts.recovery_policy, State::ReadError | State::NotRequired) {
            return Err(BoundCompletionResumeReadError {
                material: Material::RecoveryPolicy,
            });
        }
        return Ok(if facts.recovery_policy == State::Present {
            BoundCompletionResumeDisposition::RecoverWithPolicy
        } else {
            BoundCompletionResumeDisposition::StrandedIdentity
        });
    }

    let runtime_is_restorable = facts.device_id == State::Present
        && facts.grant_binding_key == State::Present
        && facts.session_grant == State::Present
        && facts.grant_matches_account
        && facts.grant_is_live
        && facts.grant_binding_matches_handoff;
    Ok(if runtime_is_restorable {
        BoundCompletionResumeDisposition::RestoreRuntime
    } else {
        BoundCompletionResumeDisposition::ReissueGrant
    })
}

/// Route only a bound handoff. Identity-creation outcomes belong to their own
/// state machine and are rejected here rather than coerced into device setup.
pub fn route_bound_session(
    disposition: &AccountHandoffDisposition,
    normalization: LocalEvidenceNormalization,
) -> Result<BoundSessionRoute> {
    if !matches!(disposition, AccountHandoffDisposition::Bound { .. }) {
        return Err(protocol(
            "bound-session routing requires a bound account handoff",
        ));
    }
    Ok(match normalization.evidence {
        NormalizedLocalEvidence::ReturningDevice(candidate) => {
            BoundSessionRoute::IssueOrReplay(candidate)
        }
        NormalizedLocalEvidence::NoReturningDevice => BoundSessionRoute::DeviceSetupRequired,
        NormalizedLocalEvidence::Unavailable(reason) => BoundSessionRoute::Diagnostics(reason),
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityCreationNextStep {
    GenerateRecoveryKey,
    ConfirmRecoveryKey,
    EnterExistingRecoveryKey,
    Collect(IdentityCreationLocalArtifactKind),
    Authenticate,
    Execute(IdentityCreationCommandKind),
    Complete,
}

/// Deterministic reconciliation of server-authored onboarding state with
/// host-local artifacts. `stored_artifacts` describes everything found on the
/// device; `valid_artifacts` is the subset the host proved belongs to the
/// current lease/fence/identity. Anything outside `keep_artifacts` must be
/// erased before executing `next_step`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentityCreationReconciliation {
    pub goal: IdentityCreationGoal,
    pub keep_artifacts: Vec<IdentityCreationLocalArtifactKind>,
    pub discard_artifacts: Vec<IdentityCreationLocalArtifactKind>,
    pub missing_artifacts: Vec<IdentityCreationLocalArtifactKind>,
    pub next_step: IdentityCreationNextStep,
}

pub fn reconcile_identity_creation(
    lease: &IdentityCreationLease,
    goal: IdentityCreationGoal,
    recovery_key_state: IdentityCreationRecoveryKeyState,
    stored_artifacts: impl IntoIterator<Item = IdentityCreationLocalArtifactKind>,
    valid_artifacts: impl IntoIterator<Item = IdentityCreationLocalArtifactKind>,
) -> Result<IdentityCreationReconciliation> {
    lease.validate()?;
    let stored = stored_artifacts.into_iter().collect::<BTreeSet<_>>();
    let valid = valid_artifacts.into_iter().collect::<BTreeSet<_>>();
    if !valid.is_subset(&stored) {
        return Err(protocol(
            "valid onboarding artifacts must be a subset of stored artifacts",
        ));
    }
    let required = lease
        .required_local_artifacts(goal)?
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let mut allowed = required.clone();
    if goal == IdentityCreationGoal::CompleteIdentity
        && lease.state == IdentityCreationLeaseState::Reserved
    {
        // A prepared request remains reusable across holder-lease renewal.
        // It is optional until prepared, so it is not a required artifact.
        allowed.insert(IdentityCreationLocalArtifactKind::PreparedRegistrationRequest);
    }
    let keep = stored
        .intersection(&valid)
        .copied()
        .collect::<BTreeSet<_>>()
        .intersection(&allowed)
        .copied()
        .collect::<Vec<_>>();
    let keep_set = keep.iter().copied().collect::<BTreeSet<_>>();
    let discard = stored.difference(&keep_set).copied().collect::<Vec<_>>();
    let missing = required.difference(&keep_set).copied().collect::<Vec<_>>();

    use IdentityCreationCommandKind::{
        ConfirmAbandonment, IssueIdentityBindingChallenge, SubmitRegistration,
    };
    use IdentityCreationGoal::{AbandonProvisionalIdentity, CompleteIdentity};
    use IdentityCreationLeaseState::{
        AccountBound, Active, Completed, DidPublished, PcrAccepted, Reserved,
    };
    use IdentityCreationLocalArtifactKind::{
        FreshAccountHandoff, PreparedRegistrationRequest, RegistrationCheckpoint,
    };

    let next_step = match goal {
        CompleteIdentity if lease.state == Completed => IdentityCreationNextStep::Complete,
        CompleteIdentity => {
            if recovery_key_state == IdentityCreationRecoveryKeyState::Unavailable {
                if lease.state == Active {
                    IdentityCreationNextStep::GenerateRecoveryKey
                } else {
                    IdentityCreationNextStep::EnterExistingRecoveryKey
                }
            } else if recovery_key_state.needs_confirmation() {
                IdentityCreationNextStep::ConfirmRecoveryKey
            } else if !recovery_key_state.can_control_identity() {
                return Err(protocol(
                    "identity creation recovery-key state is not usable for completion",
                ));
            } else if !keep_set.contains(&RegistrationCheckpoint) {
                IdentityCreationNextStep::Collect(RegistrationCheckpoint)
            } else {
                match lease.state {
                    Reserved if keep_set.contains(&PreparedRegistrationRequest) => {
                        IdentityCreationNextStep::Execute(SubmitRegistration)
                    }
                    Active | Reserved => {
                        IdentityCreationNextStep::Execute(IssueIdentityBindingChallenge)
                    }
                    DidPublished | PcrAccepted | AccountBound
                        if !keep_set.contains(&PreparedRegistrationRequest) =>
                    {
                        IdentityCreationNextStep::Collect(PreparedRegistrationRequest)
                    }
                    DidPublished | PcrAccepted | AccountBound => {
                        IdentityCreationNextStep::Execute(SubmitRegistration)
                    }
                    Completed => unreachable!("completed state was handled before artifacts"),
                }
            }
        }
        AbandonProvisionalIdentity => {
            if !keep_set.contains(&FreshAccountHandoff) {
                IdentityCreationNextStep::Authenticate
            } else {
                IdentityCreationNextStep::Execute(ConfirmAbandonment)
            }
        }
    };

    Ok(IdentityCreationReconciliation {
        goal,
        keep_artifacts: keep,
        discard_artifacts: discard,
        missing_artifacts: missing,
        next_step,
    })
}

pub fn account_handoff_disposition(
    outcome: &AccountHandoffOutcome,
) -> Result<AccountHandoffDisposition> {
    outcome.validate()?;
    Ok(match &outcome.binding {
        AccountHandoffBinding::IdentityCreationActive {
            identity_creation_lease,
        } => AccountHandoffDisposition::IdentityCreationActive(Box::new(
            identity_creation_lease.clone(),
        )),
        AccountHandoffBinding::IdentityCreationBusy {
            retry_after_ms,
            expires_at,
        } => AccountHandoffDisposition::IdentityCreationBusy {
            retry_after_ms: *retry_after_ms,
            expires_at: *expires_at,
        },
        AccountHandoffBinding::Bound { principal_id, did } => AccountHandoffDisposition::Bound {
            principal_id: principal_id.clone(),
            did: did.clone(),
        },
    })
}

/// Build and holder-sign the one-shot OIDC code exchange for an account
/// handoff. The signing callback must use the same key as the request DPoP JWK.
pub fn oidc_account_handoff_request(
    input: OidcAccountHandoffInput,
    sign: impl FnOnce(&[u8]) -> Result<String>,
) -> Result<AccountHandoffRequestBody> {
    let unsigned = UnsignedAccountHandoffRequestBody::new(
        input.request_id,
        UnsignedAccountHandoffAuthenticationProof {
            // The authorization transaction nonce is the protocol challenge
            // for this code-exchange transcript.
            challenge: input.nonce.clone(),
            audience_id: input.audience_id,
            issuer_uri: input.issuer_uri,
            client_id: input.client_id,
            redirect_uri: input.redirect_uri,
            state: input.state,
            nonce: input.nonce,
            authorization_code: input.authorization_code,
            code_verifier: input.code_verifier,
        },
    )?;
    let signature =
        Base64UrlString::new(sign(&unsigned.canonical_signing_bytes()?)?).map_err(|error| {
            crate::Error::Protocol(format!("invalid account handoff signature: {error}"))
        })?;
    Ok(unsigned.attach_signature(signature)?)
}

pub fn identity_binding_challenge_request(
    request_id: RequestId,
    lease: &IdentityCreationLease,
    principal_registration_anchor: PrincipalRegistrationAnchor,
    creation_events: &PcrGenesisUnit,
    initial_session: &InitialSessionGrantIntent,
) -> Result<IdentityBindingChallengeRequestBody> {
    let reserved = ReservedIdentityCreation::from_anchor(principal_registration_anchor.clone())?;
    if let Some(existing) = lease.reserved_identity.as_ref()
        && existing != &reserved
    {
        return Err(protocol(
            "identity-creation lease is already reserved for a different registration anchor",
        ));
    }
    creation_events.validate_ordered_envelopes()?;
    initial_session.validate()?;
    let create = creation_events.create();
    let authorize = creation_events.founding_authorize();
    let did = principal_registration_anchor.did().clone();
    let request = IdentityBindingChallengeRequestBody {
        request_id,
        identity_creation_lease_id: lease.identity_creation_lease_id.clone(),
        lease_fence: lease.fence,
        did,
        principal_registration_anchor,
        pcr_realm_id: create.realm_id.clone(),
        realm_create_payload_digest: Hash::new(arkret_canonical::canonical_sha256(
            &create.payload,
        )?)?,
        founding_authorize_payload_digest: Hash::new(arkret_canonical::canonical_sha256(
            &authorize.payload,
        )?)?,
        initial_session_request_digest: initial_session.canonical_request_digest()?,
    };
    request.canonical_request_digest()?;
    Ok(request)
}

/// Authenticated host context frozen with the challenge request, never UI state.
#[derive(Clone, Debug)]
pub struct IdentityCreationBindingContext {
    pub account_subject: Hash,
    pub dpop_jkt: String,
    pub audience_id: DidCoreId,
    pub origin: arkret_wire::WebOrigin,
    pub trust_domain: arkret_wire::TrustDomainId,
}

/// Reconstruct the closed proof from the frozen request and authenticated context.
/// The response contributes only fresh challenge material and its lifetime.
pub fn identity_creation_register_request(
    challenge: &IdentityBindingChallengeOutcome,
    frozen_request: &IdentityBindingChallengeRequestBody,
    context: &IdentityCreationBindingContext,
    creation_events: PcrGenesisUnit,
    initial_session: InitialSessionGrantIntent,
    root_seed: &[u8; 32],
    display_name: Option<String>,
) -> Result<AccountRegisterRequestBody> {
    frozen_request.canonical_request_digest()?;
    let principal_registration_anchor = &frozen_request.principal_registration_anchor;
    let validated =
        arkret_identity::validate_principal_registration_anchor(principal_registration_anchor)
            .map_err(|error| protocol(error.to_string()))?;
    let did_operation = match principal_registration_anchor {
        PrincipalRegistrationAnchor::WebvhRegistration {
            registration_did_operation,
            ..
        } => registration_did_operation.as_ref(),
    };
    if challenge.request_id != frozen_request.request_id
        || challenge.purpose != IdentityBindingPurpose::AccountBindingAndPcrGenesis
        || challenge.challenge_id.is_empty()
        || challenge.challenge.len() < 22
        || challenge.expires_at <= challenge.issued_at
        || challenge.expires_at - challenge.issued_at > chrono::Duration::seconds(300)
        || initial_session.audience_id != context.audience_id
        || initial_session.session_public_key.thumbprint_sha256()? != context.dpop_jkt
        || frozen_request.initial_session_request_digest
            != initial_session.canonical_request_digest()?
        || frozen_request.pcr_realm_id != creation_events.create().realm_id
        || frozen_request.realm_create_payload_digest
            != Hash::new(arkret_canonical::canonical_sha256(
                &creation_events.create().payload,
            )?)?
        || frozen_request.founding_authorize_payload_digest
            != Hash::new(arkret_canonical::canonical_sha256(
                &creation_events.founding_authorize().payload,
            )?)?
    {
        return Err(protocol(
            "identity-binding challenge or submission does not match its frozen context",
        ));
    }
    let registration_did_evidence_draft =
        arkret_signatures::webvh::sign_registration_did_evidence_draft(
            did_operation,
            challenge.issued_at,
            root_seed,
        )
        .map_err(|error| protocol(error.to_string()))?;
    let unsigned_control_proof =
        UnsignedIdentityCreationControlProof::new(UnsignedIdentityCreationControlProofBody {
            proof_kind: IdentityCreationControlProofKind::DidWebvhInceptionUpdateKey,
            challenge_id: challenge.challenge_id.clone(),
            challenge: challenge.challenge.clone(),
            purpose: challenge.purpose,
            account_subject: context.account_subject.clone(),
            principal_id: validated.principal_id.clone(),
            did: validated.did.clone(),
            registration_anchor_digest: validated.registration_anchor_digest,
            did_version_id: validated.did_version_id,
            control_key_digest: validated.control_key_digest,
            pcr_realm_id: frozen_request.pcr_realm_id.clone(),
            realm_create_payload_digest: frozen_request.realm_create_payload_digest.clone(),
            founding_authorize_payload_digest: frozen_request
                .founding_authorize_payload_digest
                .clone(),
            initial_session_request_digest: frozen_request.initial_session_request_digest.clone(),
            genesis_unit_kinds: arkret_models_identity::PCR_GENESIS_UNIT_KINDS,
            identity_creation_lease_id: frozen_request.identity_creation_lease_id.clone(),
            lease_fence: frozen_request.lease_fence,
            dpop_jkt: context.dpop_jkt.clone(),
            audience_id: context.audience_id.clone(),
            origin: context.origin.clone(),
            trust_domain: context.trust_domain.clone(),
            issued_at: challenge.issued_at,
            expires_at: challenge.expires_at,
            verification_key_multibase: validated.root_public_key_multibase,
        })?;
    let control_proof = arkret_signatures::webvh::sign_identity_creation_control_proof(
        unsigned_control_proof,
        root_seed,
    )
    .map_err(|error| protocol(error.to_string()))?;
    let request = AccountRegisterRequestBody {
        principal_id: validated.principal_id,
        did: validated.did.clone(),
        display_name,
        device_id: None,
        proof: None,
        identity_creation: Some(IdentityCreationRegistration {
            identity_creation_lease_id: frozen_request.identity_creation_lease_id.clone(),
            lease_fence: frozen_request.lease_fence,
            did: validated.did.clone(),
            principal_registration_anchor: principal_registration_anchor.clone(),
            registration_did_evidence_draft,
            control_proof,
            pcr_genesis_unit: creation_events,
            initial_session,
        }),
        policy_evidence: None,
    };
    request.validate()?;
    Ok(request)
}

/// Validate the only successful identity-creation terminal: the account is
/// bound, PCR genesis has a verified receipt, and the first grant is Standard.
pub fn validate_identity_creation_outcome(
    outcome: &AccountRegisterOutcome,
    request: &AccountRegisterRequestBody,
) -> Result<()> {
    outcome.validate_against_request(request)?;
    let registration = request
        .identity_creation
        .as_ref()
        .ok_or_else(|| protocol("identity-creation outcome requires identity_creation request"))?;
    let receipt = &outcome.binding_receipt;
    receipt.validate_shape()?;
    if receipt.account_subject != registration.control_proof.account_subject
        || receipt.principal_id != request.principal_id
        || receipt.did != request.did
        || receipt.identity_creation_lease_id.as_deref()
            != Some(registration.identity_creation_lease_id.as_str())
        || receipt.lease_fence != Some(registration.lease_fence)
        || receipt.registration_anchor_digest
            != registration.control_proof.registration_anchor_digest
    {
        return Err(protocol(
            "account binding receipt does not match the accepted identity-creation request",
        ));
    }
    Ok(())
}

fn protocol(message: impl Into<String>) -> Error {
    Error::Protocol(message.into())
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use super::*;

    fn webvh_anchor() -> PrincipalRegistrationAnchor {
        let next_root_public_key_multibase = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
            ed25519_dalek::SigningKey::from_bytes(&[8; 32])
                .verifying_key()
                .as_bytes(),
        );
        let endpoint = url::Url::parse("https://registration.example/").unwrap();
        let inception = arkret_signatures::webvh::prepare_principal_inception(
            &arkret_signatures::webvh::PrincipalInceptionInput {
                provider_endpoint: &endpoint,
                principal_endpoint: &endpoint,
                local_id: "lease-fixture",
                also_known_as: &[],
                version_time: arkret_canonical::normalize_timestamp_canonical(Utc::now()),
                root_seed: &[7; 32],
                next_root_public_key_multibase: &next_root_public_key_multibase,
                witness_policy: None,
            },
        )
        .unwrap();
        PrincipalRegistrationAnchor::WebvhRegistration {
            registration_did_operation: Box::new(inception.submit_body),
            log_entries: vec![serde_json::from_value(inception.log_entry.clone()).unwrap()],
            witness_records: Vec::new(),
            normalized_did_document: serde_json::from_value(inception.log_entry["state"].clone())
                .unwrap(),
        }
    }

    fn lease(state: IdentityCreationLeaseState) -> IdentityCreationLease {
        let reserved_identity = state
            .has_reserved_identity()
            .then(|| ReservedIdentityCreation::from_anchor(webvh_anchor()).unwrap());
        IdentityCreationLease {
            identity_creation_lease_id: "lease-fixture".to_owned(),
            fence: 1,
            state,
            expires_at: Utc::now() + chrono::Duration::minutes(15),
            reserved_identity,
        }
    }

    fn did(value: &str) -> Did {
        Did::new(value.to_owned()).unwrap()
    }

    fn core_id(value: &str) -> DidCoreId {
        arkret_wire::project_did_to_core_id(&did(value)).unwrap()
    }

    fn device(value: &str) -> DeviceId {
        DeviceId::new(value.to_owned()).unwrap()
    }

    fn returning_candidate(
        principal: &str,
        device_value: &str,
        signer_ref: &str,
    ) -> ReturningDeviceCandidate {
        ReturningDeviceCandidate {
            principal_id: core_id(principal),
            device_id: device(device_value),
            signer_ref: signer_ref.to_owned(),
        }
    }

    #[test]
    fn local_evidence_normalization_admits_only_one_matching_signer() {
        let alice_did = did("did:webvh:z6mkfixture:alice.example");
        let alice_id = core_id(alice_did.as_str());
        let bob_device = returning_candidate(
            "did:webvh:z6mkbobfixture:bob.example",
            "ak:device:01904100-0000-7000-8000-000000000031",
            "secure:bob-device",
        );
        let alice_device = returning_candidate(
            alice_did.as_str(),
            "ak:device:01904100-0000-7000-8000-000000000030",
            "secure:alice-device",
        );
        let normalized = normalize_local_evidence(
            &alice_id,
            LocalEvidenceHydration::Ready,
            [bob_device.clone(), alice_device.clone()],
        );

        assert_eq!(
            normalized.evidence,
            NormalizedLocalEvidence::ReturningDevice(alice_device)
        );
        assert_eq!(normalized.quarantined_candidates, vec![bob_device]);
    }

    #[test]
    fn local_evidence_loading_and_ambiguity_never_become_no_device() {
        let alice_did = did("did:webvh:z6mkfixture:alice.example");
        let alice_id = core_id(alice_did.as_str());
        let first = returning_candidate(
            alice_did.as_str(),
            "ak:device:01904100-0000-7000-8000-000000000030",
            "secure:alice-device-a",
        );
        let second = returning_candidate(
            alice_did.as_str(),
            "ak:device:01904100-0000-7000-8000-000000000032",
            "secure:alice-device-b",
        );

        assert_eq!(
            normalize_local_evidence(
                &alice_id,
                LocalEvidenceHydration::Loading,
                std::iter::empty(),
            )
            .evidence,
            NormalizedLocalEvidence::Unavailable(
                LocalEvidenceUnavailableReason::HydrationInProgress
            )
        );
        assert_eq!(
            normalize_local_evidence(&alice_id, LocalEvidenceHydration::Ready, [first, second])
                .evidence,
            NormalizedLocalEvidence::Unavailable(
                LocalEvidenceUnavailableReason::AmbiguousReturningDevices
            )
        );
    }

    #[test]
    fn bound_session_route_keeps_device_setup_and_diagnostics_distinct() {
        let did = did("did:webvh:z6mkfixture:alice.example");
        let principal_id = core_id(did.as_str());
        let disposition = AccountHandoffDisposition::Bound {
            principal_id: principal_id.clone(),
            did: did.clone(),
        };
        let no_device = normalize_local_evidence(
            &principal_id,
            LocalEvidenceHydration::Ready,
            std::iter::empty(),
        );
        assert_eq!(
            route_bound_session(&disposition, no_device).unwrap(),
            BoundSessionRoute::DeviceSetupRequired
        );

        let unavailable = normalize_local_evidence(
            &principal_id,
            LocalEvidenceHydration::Failed {
                reason: "secure store unavailable".to_owned(),
            },
            std::iter::empty(),
        );
        assert_eq!(
            route_bound_session(&disposition, unavailable).unwrap(),
            BoundSessionRoute::Diagnostics(LocalEvidenceUnavailableReason::StorageFailure {
                reason: "secure store unavailable".to_owned(),
            })
        );
    }

    #[test]
    fn registration_checkpoint_classification_is_exhaustive_over_its_facts() {
        use RegistrationCheckpointDisposition as Disposition;

        for continues in [false, true] {
            for lease_matches in [false, true] {
                for lease_expired in [false, true] {
                    for terminal in [false, true] {
                        let facts = RegistrationCheckpointFacts {
                            continues_current_transaction: continues,
                            lease_matches,
                            lease_expired,
                            identity_creation_terminal: terminal,
                        };
                        let expected = if !continues {
                            Disposition::Quarantine
                        } else if terminal || lease_expired || !lease_matches {
                            Disposition::DiscardStale
                        } else {
                            Disposition::ContinuesIdentityCreation
                        };
                        assert_eq!(
                            classify_registration_checkpoint(facts),
                            expected,
                            "{facts:?}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn only_a_live_current_transaction_checkpoint_owns_the_authentication() {
        use RegistrationCheckpointDisposition as Disposition;

        let live = RegistrationCheckpointFacts {
            continues_current_transaction: true,
            lease_matches: true,
            lease_expired: false,
            identity_creation_terminal: false,
        };
        assert_eq!(
            classify_registration_checkpoint(live),
            Disposition::ContinuesIdentityCreation
        );

        // A foreign account's draft is retained, never deleted, and never
        // allowed to speak for this transaction.
        assert_eq!(
            classify_registration_checkpoint(RegistrationCheckpointFacts {
                continues_current_transaction: false,
                ..live
            }),
            Disposition::Quarantine
        );
        // Terminal, expired and fenced-out drafts are all erasable local
        // temporaries of this same transaction.
        for stale in [
            RegistrationCheckpointFacts {
                identity_creation_terminal: true,
                ..live
            },
            RegistrationCheckpointFacts {
                lease_expired: true,
                ..live
            },
            RegistrationCheckpointFacts {
                lease_matches: false,
                ..live
            },
        ] {
            assert_eq!(
                classify_registration_checkpoint(stale),
                Disposition::DiscardStale,
                "{stale:?}"
            );
        }
    }

    #[test]
    fn bound_completion_resume_classification_is_exhaustive_over_material_states() {
        use BoundCompletionCheckpointStage as Stage;
        use BoundCompletionHandoffState as Handoff;
        use BoundCompletionMaterialState as Material;
        use BoundCompletionResumeDisposition as Disposition;

        let states = [Material::Present, Material::Absent, Material::ReadError];
        let recovery_policy_states = [
            Material::Present,
            Material::Absent,
            Material::ReadError,
            Material::NotRequired,
        ];
        for handoff in [
            Handoff::ActiveBound,
            Handoff::MissingOrExpired,
            Handoff::ReadError,
        ] {
            for stage in [Stage::Accepted, Stage::RecoveryMaterialComplete] {
                for recovery_policy in recovery_policy_states {
                    for device_id in states {
                        for signing_seed in states {
                            for grant_binding_key in states {
                                for session_grant in states {
                                    for recovery_evidence in states {
                                        for hpke_private_key in states {
                                            let facts = BoundCompletionResumeFacts {
                                                handoff,
                                                checkpoint_stage: stage,
                                                recovery_policy,
                                                device_id,
                                                signing_seed,
                                                grant_binding_key,
                                                session_grant,
                                                recovery_evidence,
                                                hpke_private_key,
                                                authority_matches: true,
                                                device_slot_matches: true,
                                                grant_matches_account: true,
                                                grant_is_live: true,
                                                grant_binding_matches_handoff: true,
                                            };
                                            let classified =
                                                classify_bound_completion_resume(facts);
                                            let required_material_unavailable = handoff
                                                == Handoff::ReadError
                                                || [
                                                    device_id,
                                                    signing_seed,
                                                    grant_binding_key,
                                                    session_grant,
                                                    recovery_evidence,
                                                ]
                                                .contains(&Material::ReadError);
                                            if required_material_unavailable {
                                                assert!(classified.is_err(), "{facts:?}");
                                                continue;
                                            }
                                            let expected = if stage
                                                == Stage::RecoveryMaterialComplete
                                                && recovery_evidence == Material::Absent
                                            {
                                                Disposition::Contradiction {
                                                    reason: BoundCompletionContradiction::CompletedStageMissingEvidence,
                                                }
                                            } else if handoff == Handoff::MissingOrExpired {
                                                Disposition::ReauthRequired
                                            } else if signing_seed == Material::Absent
                                                && matches!(
                                                    recovery_policy,
                                                    Material::ReadError | Material::NotRequired
                                                )
                                            {
                                                assert!(classified.is_err(), "{facts:?}");
                                                continue;
                                            } else if signing_seed == Material::Absent {
                                                if recovery_policy == Material::Present {
                                                    Disposition::RecoverWithPolicy
                                                } else {
                                                    Disposition::StrandedIdentity
                                                }
                                            } else if device_id == Material::Present
                                                && grant_binding_key == Material::Present
                                                && session_grant == Material::Present
                                            {
                                                Disposition::RestoreRuntime
                                            } else {
                                                Disposition::ReissueGrant
                                            };
                                            assert_eq!(classified.unwrap(), expected, "{facts:?}");
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn bound_completion_resume_routes_contradictions_and_stale_grants_without_guessing() {
        let live = BoundCompletionResumeFacts {
            handoff: BoundCompletionHandoffState::ActiveBound,
            checkpoint_stage: BoundCompletionCheckpointStage::Accepted,
            recovery_policy: BoundCompletionMaterialState::NotRequired,
            device_id: BoundCompletionMaterialState::Present,
            signing_seed: BoundCompletionMaterialState::Present,
            grant_binding_key: BoundCompletionMaterialState::Present,
            session_grant: BoundCompletionMaterialState::Present,
            recovery_evidence: BoundCompletionMaterialState::Absent,
            hpke_private_key: BoundCompletionMaterialState::Absent,
            authority_matches: true,
            device_slot_matches: true,
            grant_matches_account: true,
            grant_is_live: true,
            grant_binding_matches_handoff: true,
        };
        assert_eq!(
            classify_bound_completion_resume(live).unwrap(),
            BoundCompletionResumeDisposition::RestoreRuntime
        );
        for reissue in [
            BoundCompletionResumeFacts {
                session_grant: BoundCompletionMaterialState::Absent,
                ..live
            },
            BoundCompletionResumeFacts {
                grant_is_live: false,
                ..live
            },
            BoundCompletionResumeFacts {
                grant_binding_matches_handoff: false,
                ..live
            },
        ] {
            assert_eq!(
                classify_bound_completion_resume(reissue).unwrap(),
                BoundCompletionResumeDisposition::ReissueGrant
            );
        }
        for (facts, reason) in [
            (
                BoundCompletionResumeFacts {
                    authority_matches: false,
                    ..live
                },
                BoundCompletionContradiction::AuthorityMismatch,
            ),
            (
                BoundCompletionResumeFacts {
                    device_slot_matches: false,
                    ..live
                },
                BoundCompletionContradiction::DeviceSlotConflict,
            ),
        ] {
            assert_eq!(
                classify_bound_completion_resume(facts).unwrap(),
                BoundCompletionResumeDisposition::Contradiction { reason }
            );
        }
        for hpke_private_key in [
            BoundCompletionMaterialState::Present,
            BoundCompletionMaterialState::Absent,
            BoundCompletionMaterialState::ReadError,
        ] {
            assert_eq!(
                classify_bound_completion_resume(BoundCompletionResumeFacts {
                    hpke_private_key,
                    ..live
                })
                .unwrap(),
                BoundCompletionResumeDisposition::RestoreRuntime,
                "HPKE custody is diagnostic-only for onboarding completion"
            );
        }
    }

    #[test]
    fn oidc_handoff_digest_and_signature_are_built_in_canonical_order() {
        let request = oidc_account_handoff_request(
            OidcAccountHandoffInput {
                request_id: RequestId::new(
                    "ak:request:01964137-0000-7000-8000-000000000001".to_owned(),
                )
                .unwrap(),
                audience_id: DidCoreId::new("ak:did_core:webvh:z6mkfixture:service.example")
                    .unwrap(),
                issuer_uri: "https://auth.example".to_owned(),
                client_id: "inkson".to_owned(),
                redirect_uri: "https://app.example/auth/callback".to_owned(),
                state: "state".to_owned(),
                nonce: "nonce".to_owned(),
                authorization_code: "code".to_owned(),
                code_verifier: "verifier".to_owned(),
            },
            |bytes| Ok(arkret_canonical::base64url_encode(bytes)),
        )
        .unwrap();

        assert_eq!(request.proof.challenge, "nonce");
        assert!(
            request
                .proof
                .request_canonical_digest
                .as_str()
                .starts_with("sha256:")
        );
        assert!(!request.proof.signature.is_empty());
    }

    #[test]
    fn canonical_handoff_disposition_rejects_open_allowlist() {
        let mut outcome = AccountHandoffOutcome {
            request_id: RequestId::new(
                "ak:request:01964137-0000-7000-8000-000000000001".to_owned(),
            )
            .unwrap(),
            account_handle: arkret_models_identity::Handle::parse("alice:example.com").unwrap(),
            account_subject: Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
            preferred_locale: None,
            account_handoff_grant: "g".repeat(32),
            expires_at: Utc::now(),
            allowed_operations: arkret_models_identity::ACCOUNT_HANDOFF_ALLOWED_OPERATIONS,
            binding: AccountHandoffBinding::Bound {
                principal_id: core_id("did:webvh:z6mkfixture:alice.example"),
                did: did("did:webvh:z6mkfixture:alice.example"),
            },
        };
        assert!(matches!(
            account_handoff_disposition(&outcome).unwrap(),
            AccountHandoffDisposition::Bound { .. }
        ));
        outcome.allowed_operations.swap(0, 1);
        assert!(account_handoff_disposition(&outcome).is_err());
    }

    #[test]
    fn reconciliation_discards_foreign_and_invalid_local_artifacts() {
        use IdentityCreationLocalArtifactKind::{
            PreparedRegistrationRequest, RegistrationCheckpoint,
        };
        let plan = reconcile_identity_creation(
            &lease(IdentityCreationLeaseState::Reserved),
            IdentityCreationGoal::CompleteIdentity,
            IdentityCreationRecoveryKeyState::GeneratedLocallyValidatedDurable,
            [RegistrationCheckpoint, PreparedRegistrationRequest],
            [PreparedRegistrationRequest],
        )
        .unwrap();

        assert_eq!(plan.keep_artifacts, vec![PreparedRegistrationRequest]);
        assert!(plan.discard_artifacts.contains(&RegistrationCheckpoint));
        assert!(
            !plan
                .discard_artifacts
                .contains(&PreparedRegistrationRequest)
        );
        assert_eq!(
            plan.next_step,
            IdentityCreationNextStep::Collect(RegistrationCheckpoint)
        );
    }

    #[test]
    fn reserved_completion_reuses_valid_material_and_skips_collection() {
        use IdentityCreationLocalArtifactKind::RegistrationCheckpoint;
        let plan = reconcile_identity_creation(
            &lease(IdentityCreationLeaseState::Reserved),
            IdentityCreationGoal::CompleteIdentity,
            IdentityCreationRecoveryKeyState::ExistingValidatedDurable,
            [RegistrationCheckpoint],
            [RegistrationCheckpoint],
        )
        .unwrap();

        assert_eq!(
            plan.next_step,
            IdentityCreationNextStep::Execute(
                IdentityCreationCommandKind::IssueIdentityBindingChallenge
            )
        );
        assert!(plan.missing_artifacts.is_empty());
    }

    #[test]
    fn reserved_completion_reuses_prepared_request_after_reauthentication() {
        use IdentityCreationLocalArtifactKind::{
            PreparedRegistrationRequest, RegistrationCheckpoint,
        };
        for prepared_is_valid in [true, false] {
            let valid = if prepared_is_valid {
                vec![RegistrationCheckpoint, PreparedRegistrationRequest]
            } else {
                vec![RegistrationCheckpoint]
            };
            let plan = reconcile_identity_creation(
                &lease(IdentityCreationLeaseState::Reserved),
                IdentityCreationGoal::CompleteIdentity,
                IdentityCreationRecoveryKeyState::ExistingValidatedDurable,
                [RegistrationCheckpoint, PreparedRegistrationRequest],
                valid,
            )
            .unwrap();
            assert_eq!(
                plan.next_step,
                IdentityCreationNextStep::Execute(if prepared_is_valid {
                    IdentityCreationCommandKind::SubmitRegistration
                } else {
                    IdentityCreationCommandKind::IssueIdentityBindingChallenge
                })
            );
            assert_eq!(
                plan.keep_artifacts.contains(&PreparedRegistrationRequest),
                prepared_is_valid
            );
            assert_eq!(
                plan.discard_artifacts
                    .contains(&PreparedRegistrationRequest),
                !prepared_is_valid
            );
            assert!(plan.missing_artifacts.is_empty());
        }
    }

    #[test]
    fn abandonment_requires_fresh_authentication_without_a_challenge_artifact() {
        use IdentityCreationLocalArtifactKind::FreshAccountHandoff;
        let lease = lease(IdentityCreationLeaseState::Reserved);
        let plan = reconcile_identity_creation(
            &lease,
            IdentityCreationGoal::AbandonProvisionalIdentity,
            IdentityCreationRecoveryKeyState::Unavailable,
            [],
            [],
        )
        .unwrap();
        assert_eq!(plan.next_step, IdentityCreationNextStep::Authenticate);
        let plan = reconcile_identity_creation(
            &lease,
            IdentityCreationGoal::AbandonProvisionalIdentity,
            IdentityCreationRecoveryKeyState::Unavailable,
            [FreshAccountHandoff],
            [FreshAccountHandoff],
        )
        .unwrap();
        assert_eq!(
            plan.next_step,
            IdentityCreationNextStep::Execute(IdentityCreationCommandKind::ConfirmAbandonment)
        );
    }

    #[test]
    fn pcr_acceptance_closes_the_abandonment_goal() {
        let result = reconcile_identity_creation(
            &lease(IdentityCreationLeaseState::PcrAccepted),
            IdentityCreationGoal::AbandonProvisionalIdentity,
            IdentityCreationRecoveryKeyState::Unavailable,
            [],
            [],
        );
        assert!(result.is_err());
    }

    #[test]
    fn completed_server_state_is_terminal_without_local_artifacts() {
        let plan = reconcile_identity_creation(
            &lease(IdentityCreationLeaseState::Completed),
            IdentityCreationGoal::CompleteIdentity,
            IdentityCreationRecoveryKeyState::Unavailable,
            [],
            [],
        )
        .unwrap();

        assert_eq!(plan.next_step, IdentityCreationNextStep::Complete);
        assert!(plan.missing_artifacts.is_empty());
    }

    #[test]
    fn recovery_key_state_distinguishes_fresh_resume_and_existing_entry() {
        let fresh = reconcile_identity_creation(
            &lease(IdentityCreationLeaseState::Active),
            IdentityCreationGoal::CompleteIdentity,
            IdentityCreationRecoveryKeyState::Unavailable,
            [],
            [],
        )
        .unwrap();
        assert_eq!(
            fresh.next_step,
            IdentityCreationNextStep::GenerateRecoveryKey
        );

        let recovered = reconcile_identity_creation(
            &lease(IdentityCreationLeaseState::Reserved),
            IdentityCreationGoal::CompleteIdentity,
            IdentityCreationRecoveryKeyState::RecoveredPendingConfirmation,
            [],
            [],
        )
        .unwrap();
        assert_eq!(
            recovered.next_step,
            IdentityCreationNextStep::ConfirmRecoveryKey
        );

        let missing = reconcile_identity_creation(
            &lease(IdentityCreationLeaseState::Reserved),
            IdentityCreationGoal::CompleteIdentity,
            IdentityCreationRecoveryKeyState::Unavailable,
            [],
            [],
        )
        .unwrap();
        assert_eq!(
            missing.next_step,
            IdentityCreationNextStep::EnterExistingRecoveryKey
        );
    }
}
