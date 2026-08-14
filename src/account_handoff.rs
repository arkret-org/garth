//! Runtime-neutral account-first onboarding request orchestration.
//!
//! Hosts own navigation, durable public checkpoints and custody prompts. This
//! module owns the canonical request sequence and delegates all protocol
//! cryptography and DTO validation to the Arkret SDK.

use crate::protocol::{
    AccountBindingReceipt, AccountHandoffBinding, AccountHandoffOutcome, AccountHandoffRequestBody,
    AccountRegisterOutcome, AccountRegisterRequestBody, Base64UrlString, DidCoreId, DidFullId,
    DidOperationSubmitRequestBody, Hash, IdentityBindingChallengeOutcome,
    IdentityBindingChallengeRequestBody, IdentityBindingPurpose, IdentityCreationCommandKind,
    IdentityCreationGoal, IdentityCreationLease, IdentityCreationLeaseState,
    IdentityCreationLocalArtifactKind, IdentityCreationRecoveryKeyState,
    IdentityCreationRegistration, InitialSessionGrantIntent, PcrGenesisUnit, RequestId, Result,
    UnsignedAccountHandoffAuthenticationProof, UnsignedAccountHandoffRequestBody,
    UnsignedIdentityCreationControlProof, UnsignedIdentityCreationControlProofBody,
};
use std::collections::BTreeSet;

#[derive(Clone, Debug)]
pub struct OidcAccountHandoffInput {
    pub request_id: RequestId,
    pub audience: crate::protocol::DidCoreId,
    pub issuer: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub state: String,
    pub nonce: String,
    pub authorization_code: String,
    pub code_verifier: String,
}

#[derive(Clone, Debug, PartialEq)]
pub enum AccountHandoffDisposition {
    IdentityCreationActive(IdentityCreationLease),
    IdentityCreationBusy {
        retry_after_ms: u64,
        expires_at: chrono::DateTime<chrono::Utc>,
    },
    Bound {
        principal_id: DidCoreId,
        full_id: DidFullId,
    },
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
    let keep = stored
        .intersection(&valid)
        .copied()
        .collect::<BTreeSet<_>>()
        .intersection(&required)
        .copied()
        .collect::<Vec<_>>();
    let keep_set = keep.iter().copied().collect::<BTreeSet<_>>();
    let discard = stored.difference(&keep_set).copied().collect::<Vec<_>>();
    let missing = required.difference(&keep_set).copied().collect::<Vec<_>>();

    use IdentityCreationCommandKind::{
        ConfirmAbandonment, IssueAbandonmentChallenge, IssueIdentityBindingChallenge,
        SubmitRegistration,
    };
    use IdentityCreationGoal::{AbandonProvisionalIdentity, CompleteIdentity};
    use IdentityCreationLeaseState::{
        AccountBound, Active, Completed, DidPublished, PcrAccepted, Reserved,
    };
    use IdentityCreationLocalArtifactKind::{
        AbandonmentChallenge, FreshAccountHandoff, PreparedRegistrationRequest,
        RegistrationCheckpoint,
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
            if !keep_set.contains(&AbandonmentChallenge) {
                IdentityCreationNextStep::Execute(IssueAbandonmentChallenge)
            } else if !keep_set.contains(&FreshAccountHandoff) {
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
        } => AccountHandoffDisposition::IdentityCreationActive(identity_creation_lease.clone()),
        AccountHandoffBinding::IdentityCreationBusy {
            retry_after_ms,
            expires_at,
        } => AccountHandoffDisposition::IdentityCreationBusy {
            retry_after_ms: *retry_after_ms,
            expires_at: *expires_at,
        },
        AccountHandoffBinding::Bound {
            principal_id,
            full_id,
        } => AccountHandoffDisposition::Bound {
            principal_id: principal_id.clone(),
            full_id: full_id.clone(),
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
            audience: input.audience,
            issuer: input.issuer,
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
    did_operation: DidOperationSubmitRequestBody,
    pcr_genesis_unit: &PcrGenesisUnit,
    initial_session: &InitialSessionGrantIntent,
) -> Result<IdentityBindingChallengeRequestBody> {
    let reserved =
        crate::protocol::ReservedIdentityCreation::from_operation(did_operation.clone())?;
    if let Some(existing) = lease.reserved_identity.as_ref()
        && existing != &reserved
    {
        return Err(protocol(
            "identity-creation lease is already reserved for a different operation",
        ));
    }
    pcr_genesis_unit.validate_ordered_envelopes()?;
    initial_session.validate()?;
    let create = pcr_genesis_unit.create();
    let authorize = pcr_genesis_unit.founding_authorize();
    let full_id = did_operation.did.clone();
    let request = IdentityBindingChallengeRequestBody {
        request_id,
        identity_creation_lease_id: lease.identity_creation_lease_id.clone(),
        lease_fence: lease.fence,
        full_id,
        did_operation,
        pcr_realm_id: create.realm_id.clone(),
        realm_create_payload_digest: Hash::new(crate::protocol::canonical::canonical_sha256(
            &create.payload,
        )?)?,
        founding_authorize_payload_digest: Hash::new(
            crate::protocol::canonical::canonical_sha256(&authorize.payload)?,
        )?,
        initial_session_request_digest: initial_session.canonical_request_digest()?,
    };
    request.canonical_request_digest()?;
    Ok(request)
}

/// Build the canonical identity-creation register request and sign its control
/// proof with the cold inception root. The seed is borrowed and never retained.
pub fn identity_creation_register_request(
    challenge: &IdentityBindingChallengeOutcome,
    expected_account_subject: &Hash,
    did_operation: DidOperationSubmitRequestBody,
    pcr_genesis_unit: PcrGenesisUnit,
    initial_session: InitialSessionGrantIntent,
    root_seed: &[u8; 32],
    display_name: Option<String>,
) -> Result<AccountRegisterRequestBody> {
    let validated =
        crate::protocol::signatures::webvh::validate_principal_inception_operation(&did_operation)
            .map_err(|error| protocol(error.to_string()))?;
    if &challenge.account_subject != expected_account_subject
        || challenge.principal_id != validated.principal_id
        || challenge.full_id != did_operation.did
        || challenge.operation_digest != validated.operation_digest
        || challenge.did_version_id != validated.did_version_id
        || challenge.log_head_digest != validated.log_head_digest
        || challenge.control_key_digest != validated.control_key_digest
        || challenge.purpose != IdentityBindingPurpose::AccountBindingAndPcrGenesis
    {
        return Err(protocol(
            "identity-binding challenge does not match the inception operation",
        ));
    }
    let registration_did_evidence_draft =
        crate::protocol::signatures::webvh::sign_registration_did_evidence_draft(
            &did_operation,
            challenge.issued_at,
            root_seed,
        )
        .map_err(|error| protocol(error.to_string()))?;
    let unsigned_control_proof =
        UnsignedIdentityCreationControlProof::new(UnsignedIdentityCreationControlProofBody {
            challenge_id: challenge.challenge_id.clone(),
            challenge: challenge.challenge.clone(),
            purpose: challenge.purpose,
            account_subject: challenge.account_subject.clone(),
            principal_id: challenge.principal_id.clone(),
            full_id: challenge.full_id.clone(),
            operation_digest: challenge.operation_digest.clone(),
            did_version_id: challenge.did_version_id.clone(),
            log_head_digest: challenge.log_head_digest.clone(),
            control_key_digest: challenge.control_key_digest.clone(),
            pcr_realm_id: challenge.pcr_realm_id.clone(),
            realm_create_payload_digest: challenge.realm_create_payload_digest.clone(),
            founding_authorize_payload_digest: challenge.founding_authorize_payload_digest.clone(),
            initial_session_request_digest: challenge.initial_session_request_digest.clone(),
            genesis_unit_kinds: challenge.genesis_unit_kinds,
            identity_creation_lease_id: challenge.identity_creation_lease_id.clone(),
            lease_fence: challenge.lease_fence,
            dpop_jkt: challenge.dpop_jkt.clone(),
            audience: challenge.audience.clone(),
            origin: challenge.origin.clone(),
            trust_domain: challenge.trust_domain.clone(),
            issued_at: challenge.issued_at,
            expires_at: challenge.expires_at,
            verification_key_multibase: validated.root_public_key_multibase,
        })?;
    let control_proof = crate::protocol::signatures::webvh::sign_identity_creation_control_proof(
        unsigned_control_proof,
        root_seed,
    )
    .map_err(|error| protocol(error.to_string()))?;
    let request = AccountRegisterRequestBody {
        principal_id: challenge.principal_id.clone(),
        full_id: challenge.full_id.clone(),
        display_name,
        device_id: None,
        proof: None,
        identity_creation: Some(IdentityCreationRegistration {
            identity_creation_lease_id: challenge.identity_creation_lease_id.clone(),
            lease_fence: challenge.lease_fence,
            full_id: challenge.full_id.clone(),
            did_operation,
            registration_did_evidence_draft,
            control_proof,
            pcr_genesis_unit,
            initial_session,
        }),
        policy_evidence: None,
    };
    request.validate()?;
    Ok(request)
}

pub fn validate_binding_receipt(
    receipt: &AccountBindingReceipt,
    challenge: &IdentityBindingChallengeOutcome,
) -> Result<()> {
    receipt.validate_shape()?;
    if receipt.account_subject != challenge.account_subject
        || receipt.principal_id != challenge.principal_id
        || receipt.full_id != challenge.full_id
        || receipt.identity_creation_lease_id.as_deref()
            != Some(challenge.identity_creation_lease_id.as_str())
        || receipt.lease_fence != Some(challenge.lease_fence)
        || receipt.operation_digest != challenge.operation_digest
        || receipt.head_event_digest != challenge.log_head_digest
    {
        return Err(protocol(
            "account binding receipt does not match the identity-creation reservation",
        ));
    }
    Ok(())
}

/// Verify an Account Authority receipt against the complete method-native DID
/// history effective at the receipt timestamp. The explicit error variants
/// let hosts distinguish retryable resolver unavailability from a fork,
/// revoked/unauthorized key, or invalid signature.
pub fn verify_binding_receipt_at_issuance(
    receipt: &AccountBindingReceipt,
    resolver: &dyn arkret_identity::AuthorityDidHistoryResolver,
) -> std::result::Result<
    arkret_identity::VerifiedAccountBindingReceipt,
    arkret_identity::AuthorityHistoryVerificationError,
> {
    arkret_identity::verify_account_binding_receipt_at_issuance(receipt, resolver)
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
        || receipt.full_id != request.full_id
        || receipt.identity_creation_lease_id.as_deref()
            != Some(registration.identity_creation_lease_id.as_str())
        || receipt.lease_fence != Some(registration.lease_fence)
        || receipt.operation_digest != registration.control_proof.operation_digest
        || receipt.head_event_digest != registration.control_proof.log_head_digest
    {
        return Err(protocol(
            "account binding receipt does not match the accepted identity-creation request",
        ));
    }
    Ok(())
}

fn protocol(message: impl Into<String>) -> crate::protocol::Error {
    crate::protocol::Error::Protocol(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn lease(state: IdentityCreationLeaseState) -> IdentityCreationLease {
        let reserved_identity = state.has_reserved_identity().then(|| {
            let full_id = did("did:webvh:z6mkfixture:alice.example");
            crate::protocol::ReservedIdentityCreation {
                principal_id: core_id(full_id.as_str()),
                full_id: full_id.clone(),
                operation_digest: Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
                did_operation: crate::protocol::DidOperationSubmitRequestBody {
                    did: full_id,
                    did_method: arkret_models_identity::DidMethodName::Webvh,
                    seq: None,
                    prev_event_digest: None,
                    operation: std::collections::BTreeMap::new(),
                },
            }
        });
        IdentityCreationLease {
            identity_creation_lease_id: "lease-fixture".to_owned(),
            fence: 1,
            state,
            expires_at: Utc::now() + chrono::Duration::minutes(15),
            reserved_identity,
        }
    }

    fn did(value: &str) -> DidFullId {
        DidFullId::new(value.to_owned()).unwrap()
    }

    fn core_id(value: &str) -> DidCoreId {
        crate::protocol::project_full_id_to_core_id(&did(value)).unwrap()
    }

    #[test]
    fn oidc_handoff_digest_and_signature_are_built_in_canonical_order() {
        let request = oidc_account_handoff_request(
            OidcAccountHandoffInput {
                request_id: RequestId::new(
                    "ak:request:01964137-0000-7000-8000-000000000001".to_owned(),
                )
                .unwrap(),
                audience: crate::protocol::DidCoreId::new(
                    "ak:did_core:webvh:z6mkfixture:service.example",
                )
                .unwrap(),
                issuer: "https://auth.example".to_owned(),
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
            account_handle: crate::protocol::Handle::parse("alice:example.com").unwrap(),
            account_subject: Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
            preferred_locale: None,
            account_handoff_grant: "g".repeat(32),
            expires_at: Utc::now(),
            allowed_operations: crate::protocol::ACCOUNT_HANDOFF_ALLOWED_OPERATIONS,
            binding: AccountHandoffBinding::Bound {
                principal_id: core_id("did:webvh:z6mkfixture:alice.example"),
                full_id: did("did:webvh:z6mkfixture:alice.example"),
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
            AbandonmentChallenge, PreparedRegistrationRequest, RegistrationCheckpoint,
        };
        let plan = reconcile_identity_creation(
            &lease(IdentityCreationLeaseState::Reserved),
            IdentityCreationGoal::CompleteIdentity,
            IdentityCreationRecoveryKeyState::GeneratedLocallyValidatedDurable,
            [
                RegistrationCheckpoint,
                PreparedRegistrationRequest,
                AbandonmentChallenge,
            ],
            [PreparedRegistrationRequest],
        )
        .unwrap();

        assert!(plan.keep_artifacts.is_empty());
        assert!(plan.discard_artifacts.contains(&RegistrationCheckpoint));
        assert!(
            plan.discard_artifacts
                .contains(&PreparedRegistrationRequest)
        );
        assert!(plan.discard_artifacts.contains(&AbandonmentChallenge));
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
    fn abandonment_requires_challenge_then_fresh_authentication() {
        use IdentityCreationLocalArtifactKind::{AbandonmentChallenge, FreshAccountHandoff};
        let lease = lease(IdentityCreationLeaseState::DidPublished);
        let issue = reconcile_identity_creation(
            &lease,
            IdentityCreationGoal::AbandonProvisionalIdentity,
            IdentityCreationRecoveryKeyState::Unavailable,
            [],
            [],
        )
        .unwrap();
        assert_eq!(
            issue.next_step,
            IdentityCreationNextStep::Execute(
                IdentityCreationCommandKind::IssueAbandonmentChallenge
            )
        );

        let authenticate = reconcile_identity_creation(
            &lease,
            IdentityCreationGoal::AbandonProvisionalIdentity,
            IdentityCreationRecoveryKeyState::Unavailable,
            [AbandonmentChallenge],
            [AbandonmentChallenge],
        )
        .unwrap();
        assert_eq!(
            authenticate.next_step,
            IdentityCreationNextStep::Authenticate
        );

        let confirm = reconcile_identity_creation(
            &lease,
            IdentityCreationGoal::AbandonProvisionalIdentity,
            IdentityCreationRecoveryKeyState::Unavailable,
            [AbandonmentChallenge, FreshAccountHandoff],
            [AbandonmentChallenge, FreshAccountHandoff],
        )
        .unwrap();
        assert_eq!(
            confirm.next_step,
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
