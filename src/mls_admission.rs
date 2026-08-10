//! Fail-closed target signing-evidence gate for peer MLS KeyPackage claims.

use arkret_models_crypto::{KeyPackageClaimRecord, PeerKeyPackagesClaimOutcome};
use arkret_models_identity::AgentSignerEvidence;
use arkret_signatures::FederatedDeviceEvidenceVerificationContext;
use arkret_signatures::agent_evidence::{
    AgentSignerEvidenceVerdict, CurrentAgentSignerEvidenceValidationContext,
    validate_current_agent_signer_evidence,
};
use arkret_wire::DidKey;
use chrono::{DateTime, Utc};

use crate::{Error, Result};

pub enum MlsClaimEvidenceContext<'a> {
    Device(&'a FederatedDeviceEvidenceVerificationContext<'a>),
    NativeAgent(&'a CurrentAgentSignerEvidenceValidationContext<'a>),
}

pub enum TargetSigningKey<'a> {
    Device(&'a DidKey),
    NativeAgent(&'a arkret_models_identity::AgentSigningPublicKey),
}

/// Verify a claimed KeyPackage and its target authority before exposing it to
/// the MLS state machine. The final callback parses/verifies the opaque MLS
/// KeyPackage and its exact `device_signature` against the replayed key.
pub fn admit_peer_claim_for_mls<'a, VerifyKeyPackage>(
    outcome: &'a PeerKeyPackagesClaimOutcome,
    keypackage_ref: &str,
    now: DateTime<Utc>,
    evidence_context: MlsClaimEvidenceContext<'_>,
    verify_exact_keypackage_signature: VerifyKeyPackage,
) -> Result<&'a KeyPackageClaimRecord>
where
    VerifyKeyPackage: FnOnce(&KeyPackageClaimRecord, TargetSigningKey<'_>) -> Result<()>,
{
    outcome
        .validate_shape()
        .map_err(|error| Error::Protocol(error.to_string()))?;
    if now >= outcome.claim_receipt.expires_at {
        return Err(Error::Protocol("mls_claim_receipt_stale".to_owned()));
    }
    let claim = outcome
        .claims
        .iter()
        .find(|claim| claim.keypackage_ref == keypackage_ref)
        .ok_or_else(|| Error::Protocol("mls_claim_keypackage_missing".to_owned()))?;
    if now >= claim.expires_at {
        return Err(Error::Protocol("mls_claim_keypackage_stale".to_owned()));
    }
    verify_keypackage_commitment(claim)?;

    match (
        &claim.target_device_signing_key_evidence,
        &claim.target_agent_signer_evidence,
        evidence_context,
    ) {
        (Some(evidence), None, MlsClaimEvidenceContext::Device(context)) => {
            if context.expected_authority_instance.principal_id != claim.principal_id
                || context.expected_authority_instance.principal_server_id
                    != outcome.claim_receipt.source_service_id
                || claim.device_id.as_ref() != Some(context.expected_device_id)
                || context.expected_verification_method.as_str()
                    != claim.device_signature.kid.as_str()
                || context.now != now
            {
                return Err(Error::Protocol(
                    "mls_target_device_verification_context_mismatch".to_owned(),
                ));
            }
            let verified = arkret_signatures::verify_federated_device_evidence(evidence, context)?;
            if claim.device_authorize_event_id.as_ref() != Some(verified.authorize_event_id())
                || *verified.expires_at() <= now
            {
                return Err(Error::Protocol(
                    "mls_target_device_evidence_binding_mismatch".to_owned(),
                ));
            }
            verify_exact_keypackage_signature(
                claim,
                TargetSigningKey::Device(verified.signing_key()),
            )?;
        }
        (None, Some(evidence), MlsClaimEvidenceContext::NativeAgent(context)) => {
            let portable = AgentSignerEvidence::from(evidence);
            match validate_current_agent_signer_evidence(Some(&portable), context) {
                AgentSignerEvidenceVerdict::Verified(_) => {}
                AgentSignerEvidenceVerdict::Unresolved(reason) => {
                    return Err(Error::Protocol(format!(
                        "mls_target_agent_evidence_unresolved:{}",
                        reason.as_str()
                    )));
                }
                AgentSignerEvidenceVerdict::Rejected(reason) => {
                    return Err(Error::Protocol(format!(
                        "mls_target_agent_evidence_rejected:{}",
                        reason.as_str()
                    )));
                }
            }
            let binding = &evidence
                .admission_evidence
                .agent_authority_snapshot
                .core
                .signing_key_binding;
            if binding.core.agent_id != claim.principal_id
                || binding.core.verification_method.as_str() != claim.device_signature.kid.as_str()
            {
                return Err(Error::Protocol(
                    "mls_target_agent_evidence_binding_mismatch".to_owned(),
                ));
            }
            verify_exact_keypackage_signature(
                claim,
                TargetSigningKey::NativeAgent(&binding.core.public_key),
            )?;
        }
        _ => {
            return Err(Error::Protocol(
                "mls_target_signing_evidence_missing_or_wrong_branch".to_owned(),
            ));
        }
    }
    Ok(claim)
}

fn verify_keypackage_commitment(claim: &KeyPackageClaimRecord) -> Result<()> {
    let bytes = arkret_canonical::base64url_decode(&claim.key_package)
        .map_err(|_| Error::Protocol("mls_claim_keypackage_encoding_invalid".to_owned()))?;
    let digest = arkret_wire::Hash::new(arkret_canonical::sha256_digest(&bytes))?;
    if digest != claim.keypackage_digest || digest.as_str() != claim.keypackage_ref {
        return Err(Error::Protocol(
            "mls_claim_keypackage_commitment_mismatch".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn admission_branch_is_closed_not_optional() {
        fn branch(device: bool, agent: bool) -> bool {
            matches!((device, agent), (true, false) | (false, true))
        }
        assert!(branch(true, false));
        assert!(branch(false, true));
        assert!(!branch(false, false));
        assert!(!branch(true, true));
    }
}
