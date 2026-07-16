//! Runtime-neutral account-first onboarding request orchestration.
//!
//! Hosts own navigation, durable public checkpoints and custody prompts. This
//! module owns the canonical request sequence and delegates all protocol
//! cryptography and DTO validation to the Arkret SDK.

use arkret::{
    AccountBindingReceipt, AccountHandoffAuthenticationProof,
    AccountHandoffAuthenticationProofKind, AccountHandoffBinding, AccountHandoffOutcome,
    AccountHandoffRequestBody, AccountRegisterRequestBody, DeviceId, Did,
    DidOperationSubmitRequestBody, Hash, IdentityBindingChallengeOutcome,
    IdentityBindingChallengeRequestBody, IdentityBindingPurpose, IdentityCreationControlProof,
    IdentityCreationControlProofKind, IdentityCreationLease, IdentityCreationRegistration,
    RequestId, Result, SessionGrantRequestBody,
};
use chrono::{DateTime, Utc};

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
    let placeholder = Hash::new(format!("sha256:{}", "0".repeat(64)))?;
    let mut request = AccountHandoffRequestBody {
        request_id: input.request_id,
        proof: AccountHandoffAuthenticationProof {
            proof_kind: AccountHandoffAuthenticationProofKind::OidcCodeExchange,
            // The authorization transaction nonce is the protocol challenge
            // for this code-exchange transcript.
            challenge: input.nonce.clone(),
            request_canonical_digest: placeholder,
            audience: input.audience,
            issuer: input.issuer,
            client_id: input.client_id,
            redirect_uri: input.redirect_uri,
            state: input.state,
            nonce: input.nonce,
            authorization_code: input.authorization_code,
            code_verifier: input.code_verifier,
            signature: String::new(),
        },
    };
    request.proof.request_canonical_digest = request.canonical_request_digest()?;
    request.proof.signature = sign(&request.proof.canonical_signing_bytes()?)?;
    Ok(request)
}

pub fn identity_binding_challenge_request(
    request_id: RequestId,
    lease: &IdentityCreationLease,
    did_operation: DidOperationSubmitRequestBody,
) -> Result<IdentityBindingChallengeRequestBody> {
    let reserved = arkret::ReservedIdentityCreation::from_operation(did_operation.clone())?;
    if let Some(existing) = lease.reserved_identity.as_ref()
        && existing != &reserved
    {
        return Err(protocol(
            "identity-creation lease is already reserved for a different operation",
        ));
    }
    Ok(IdentityBindingChallengeRequestBody {
        request_id,
        lease_id: lease.lease_id.clone(),
        lease_fence: lease.fence,
        did_operation,
    })
}

/// Build the canonical identity-creation register request and sign its control
/// proof with the cold inception root. The seed is borrowed and never retained.
pub fn identity_creation_register_request(
    challenge: &IdentityBindingChallengeOutcome,
    did_operation: DidOperationSubmitRequestBody,
    root_seed: &[u8; 32],
    display_name: Option<String>,
    device_id: Option<DeviceId>,
) -> Result<AccountRegisterRequestBody> {
    let validated =
        arkret::signatures::webvh::validate_principal_inception_operation(&did_operation)
            .map_err(|error| protocol(error.to_string()))?;
    if challenge.principal_id != validated.principal_id
        || challenge.operation_digest != validated.operation_digest
        || challenge.purpose != IdentityBindingPurpose::AccountBinding
    {
        return Err(protocol(
            "identity-binding challenge does not match the inception operation",
        ));
    }
    let mut control_proof = IdentityCreationControlProof {
        proof_kind: IdentityCreationControlProofKind::DidWebvhInceptionUpdateKey,
        challenge_id: challenge.challenge_id.clone(),
        challenge: challenge.challenge.clone(),
        purpose: challenge.purpose,
        principal_id: challenge.principal_id.clone(),
        operation_digest: challenge.operation_digest.clone(),
        lease_id: challenge.lease_id.clone(),
        lease_fence: challenge.lease_fence,
        dpop_jkt: challenge.dpop_jkt.clone(),
        audience: challenge.audience.clone(),
        origin: challenge.origin.clone(),
        trust_domain: challenge.trust_domain.clone(),
        issued_at: challenge.issued_at,
        expires_at: challenge.expires_at,
        verification_key_multibase: validated.root_public_key_multibase,
        signature: String::new(),
    };
    arkret::signatures::webvh::sign_identity_creation_control_proof(&mut control_proof, root_seed)
        .map_err(|error| protocol(error.to_string()))?;
    Ok(AccountRegisterRequestBody {
        principal_id: challenge.principal_id.clone(),
        display_name,
        device_id,
        proof: None,
        identity_creation: Some(IdentityCreationRegistration {
            lease_id: challenge.lease_id.clone(),
            lease_fence: challenge.lease_fence,
            did_operation,
            control_proof,
        }),
        policy_evidence: None,
    })
}

pub fn validate_binding_receipt(
    receipt: &AccountBindingReceipt,
    challenge: &IdentityBindingChallengeOutcome,
) -> Result<()> {
    if receipt.lease_id != challenge.lease_id
        || receipt.lease_fence != challenge.lease_fence
        || receipt.operation_digest != challenge.operation_digest
    {
        return Err(protocol(
            "account binding receipt does not match the identity-creation reservation",
        ));
    }
    Ok(())
}

/// Build and holder-sign the session request immediately following a verified
/// binding. The signing callback must use the handoff holder / DPoP key.
pub fn pre_registration_session_grant_request(
    principal_id: Did,
    device_id: Option<DeviceId>,
    requested_scope: Vec<String>,
    account_handoff_grant: &str,
    audience: Did,
    expires_at: DateTime<Utc>,
    sign: impl FnOnce(&[u8]) -> Result<String>,
) -> Result<SessionGrantRequestBody> {
    let mut request = arkret::session_grant::pre_registration_handoff_session_grant_request(
        principal_id,
        device_id,
        requested_scope,
        account_handoff_grant,
        audience,
        expires_at,
    )?;
    request.proof.signature = sign(&request.proof.canonical_signing_bytes()?)?;
    Ok(request)
}

fn protocol(message: impl Into<String>) -> arkret::Error {
    arkret::Error::Protocol(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

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
            |bytes| Ok(format!("signed:{}", bytes.len())),
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
        assert!(request.proof.signature.starts_with("signed:"));
    }

    #[test]
    fn canonical_handoff_disposition_rejects_open_allowlist() {
        let mut outcome = AccountHandoffOutcome {
            request_id: RequestId::new(
                "ak:request:01964137-0000-7000-8000-000000000001".to_owned(),
            )
            .unwrap(),
            account_handoff_grant: "g".repeat(32),
            expires_at: Utc::now(),
            allowed_operations: arkret::ACCOUNT_HANDOFF_ALLOWED_OPERATIONS,
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
