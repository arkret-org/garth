//! Runtime-neutral account-first onboarding request orchestration.
//!
//! Hosts own navigation, durable public checkpoints and custody prompts. This
//! module owns the canonical request sequence and delegates all protocol
//! cryptography and DTO validation to the Arkret SDK.

use crate::protocol::{
    AccountBindingReceipt, AccountHandoffBinding, AccountHandoffOutcome, AccountHandoffRequestBody,
    AccountRegisterOutcome, AccountRegisterRequestBody, Base64UrlString, Did,
    DidOperationSubmitRequestBody, Hash, IdentityBindingChallengeOutcome,
    IdentityBindingChallengeRequestBody, IdentityBindingPurpose, IdentityCreationLease,
    IdentityCreationRegistration, InitialSessionGrantRequest, PcrGenesisUnit, RequestId, Result,
    UnsignedAccountHandoffAuthenticationProof, UnsignedAccountHandoffRequestBody,
    UnsignedIdentityCreationControlProof, UnsignedIdentityCreationControlProofBody,
};

#[derive(Clone, Debug)]
pub struct OidcAccountHandoffInput {
    pub request_id: RequestId,
    pub audience: Did,
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
    IdentityCreationBusy { retry_after_ms: u64 },
    Bound { principal_id: Did },
}

pub fn account_handoff_disposition(
    outcome: &AccountHandoffOutcome,
) -> Result<AccountHandoffDisposition> {
    outcome.validate()?;
    Ok(match &outcome.binding {
        AccountHandoffBinding::IdentityCreationActive {
            identity_creation_lease,
        } => AccountHandoffDisposition::IdentityCreationActive(identity_creation_lease.clone()),
        AccountHandoffBinding::IdentityCreationBusy { retry_after_ms } => {
            AccountHandoffDisposition::IdentityCreationBusy {
                retry_after_ms: *retry_after_ms,
            }
        }
        AccountHandoffBinding::Bound { principal_id } => AccountHandoffDisposition::Bound {
            principal_id: principal_id.clone(),
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
    initial_session: &InitialSessionGrantRequest,
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
    let request = IdentityBindingChallengeRequestBody {
        request_id,
        identity_creation_lease_id: lease.lease_id.clone(),
        lease_fence: lease.fence,
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
    did_operation: DidOperationSubmitRequestBody,
    pcr_genesis_unit: PcrGenesisUnit,
    initial_session: InitialSessionGrantRequest,
    root_seed: &[u8; 32],
    display_name: Option<String>,
) -> Result<AccountRegisterRequestBody> {
    let validated =
        crate::protocol::signatures::webvh::validate_principal_inception_operation(&did_operation)
            .map_err(|error| protocol(error.to_string()))?;
    if challenge.principal_id != validated.principal_id
        || challenge.operation_digest != validated.operation_digest
        || challenge.purpose != IdentityBindingPurpose::AccountBindingAndPcrGenesis
    {
        return Err(protocol(
            "identity-binding challenge does not match the inception operation",
        ));
    }
    let unsigned_control_proof =
        UnsignedIdentityCreationControlProof::new(UnsignedIdentityCreationControlProofBody {
            challenge_id: challenge.challenge_id.clone(),
            challenge: challenge.challenge.clone(),
            purpose: challenge.purpose,
            principal_id: challenge.principal_id.clone(),
            operation_digest: challenge.operation_digest.clone(),
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
        display_name,
        device_id: None,
        proof: None,
        identity_creation: Some(IdentityCreationRegistration {
            identity_creation_lease_id: challenge.identity_creation_lease_id.clone(),
            lease_fence: challenge.lease_fence,
            did_operation,
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
    if receipt.identity_creation_lease_id != challenge.identity_creation_lease_id
        || receipt.lease_fence != challenge.lease_fence
        || receipt.operation_digest != challenge.operation_digest
    {
        return Err(protocol(
            "account binding receipt does not match the identity-creation reservation",
        ));
    }
    Ok(())
}

/// Validate the only successful identity-creation terminal: the account is
/// bound, PCR genesis has a verified receipt, and the first grant is Standard.
pub fn validate_identity_creation_outcome(
    outcome: &AccountRegisterOutcome,
    request: &AccountRegisterRequestBody,
) -> Result<()> {
    outcome.validate_against_request(request)?;
    Ok(())
}

fn protocol(message: impl Into<String>) -> crate::protocol::Error {
    crate::protocol::Error::Protocol(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn did(value: &str) -> Did {
        Did::new(value.to_owned()).unwrap()
    }

    #[test]
    fn oidc_handoff_digest_and_signature_are_built_in_canonical_order() {
        let request = oidc_account_handoff_request(
            OidcAccountHandoffInput {
                request_id: RequestId::new(
                    "ak:request:01964137-0000-7000-8000-000000000001".to_owned(),
                )
                .unwrap(),
                audience: did("did:webvh:z6mkfixture:service.example"),
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
            preferred_locale: None,
            account_handoff_grant: "g".repeat(32),
            expires_at: Utc::now(),
            allowed_operations: crate::protocol::ACCOUNT_HANDOFF_ALLOWED_OPERATIONS,
            binding: AccountHandoffBinding::Bound {
                principal_id: did("did:webvh:z6mkfixture:alice.example"),
            },
        };
        assert!(matches!(
            account_handoff_disposition(&outcome).unwrap(),
            AccountHandoffDisposition::Bound { .. }
        ));
        outcome.allowed_operations.swap(0, 1);
        assert!(account_handoff_disposition(&outcome).is_err());
    }
}
