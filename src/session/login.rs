use crate::protocol::session_grant::{
    agent_key_proof_session_grant_request, did_proof_session_grant_request,
    holder_proof_session_grant_request, oidc_session_grant_request,
};
use crate::protocol::{
    AgentRequestedScopeDisclosure, DeviceId, DidCoreId, DidUrl, NonEmptyString, Result,
    SessionGrantAgentScopeRequest, SessionGrantAppletDelegation, SessionGrantDpopBindingProof,
    SessionGrantRequestBody, UnsignedSessionGrantRequestBody,
};
use chrono::{DateTime, Utc};

pub use crate::protocol::session_grant::SessionGrantProofFields as SessionProofFields;

#[derive(Clone, Debug)]
pub struct AgentKeyProofLogin {
    pub principal_id: DidCoreId,
    pub device_id: DeviceId,
    pub requested_scope: Vec<String>,
    pub agent_key_authorization_ref: String,
    pub agent_scope_request: SessionGrantAgentScopeRequest,
    pub requested_scope_disclosure: Option<AgentRequestedScopeDisclosure>,
    pub dpop_binding_proof: SessionGrantDpopBindingProof,
    pub verification_method: DidUrl,
    pub challenge: String,
    pub nonce: String,
    pub audience: DidCoreId,
    pub expires_at: DateTime<Utc>,
    pub signature: String,
}

impl AgentKeyProofLogin {
    pub fn into_session_grant_request(self) -> Result<SessionGrantRequestBody> {
        Ok(agent_key_proof_session_grant_request(
            self.principal_id,
            self.device_id,
            self.requested_scope,
            self.agent_key_authorization_ref,
            self.agent_scope_request,
            self.requested_scope_disclosure,
            self.dpop_binding_proof,
            self.verification_method,
            self.challenge,
            self.nonce,
            self.audience,
            self.expires_at,
            self.signature,
        )?)
    }
}

#[derive(Clone, Debug)]
pub struct HolderProofLogin {
    pub principal_id: DidCoreId,
    pub device_id: Option<DeviceId>,
    pub requested_scope: Vec<String>,
    pub dpop_binding_proof: Option<SessionGrantDpopBindingProof>,
    pub applet_delegation: Option<SessionGrantAppletDelegation>,
    pub proof: SessionProofFields,
}

impl HolderProofLogin {
    pub fn into_session_grant_request(self) -> SessionGrantRequestBody {
        holder_proof_session_grant_request(
            self.principal_id,
            self.device_id,
            self.requested_scope,
            self.dpop_binding_proof,
            self.applet_delegation,
            self.proof,
        )
    }
}

#[derive(Clone, Debug)]
pub struct DidProofLogin {
    pub principal_id: DidCoreId,
    pub device_id: DeviceId,
    pub requested_scope: Vec<String>,
    pub dpop_binding_proof: Option<SessionGrantDpopBindingProof>,
    pub applet_delegation: Option<SessionGrantAppletDelegation>,
    pub proof: SessionProofFields,
}

impl DidProofLogin {
    pub fn into_session_grant_request(self) -> SessionGrantRequestBody {
        did_proof_session_grant_request(
            self.principal_id,
            self.device_id,
            self.requested_scope,
            self.dpop_binding_proof,
            self.applet_delegation,
            self.proof,
        )
    }
}

#[derive(Clone, Debug)]
pub struct OidcLogin {
    pub principal_id: DidCoreId,
    pub device_id: Option<DeviceId>,
    pub requested_scope: Vec<String>,
    pub challenge: String,
    pub audience: DidCoreId,
    pub issuer: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub state: String,
    pub nonce: String,
    pub authorization_code: String,
    pub code_verifier: String,
}

impl OidcLogin {
    pub fn into_unsigned_session_grant_request(self) -> Result<UnsignedSessionGrantRequestBody> {
        Ok(oidc_session_grant_request(
            self.principal_id,
            self.device_id,
            self.requested_scope,
            self.challenge,
            self.audience,
            self.issuer,
            self.client_id,
            self.redirect_uri,
            self.state,
            self.nonce,
            self.authorization_code,
            self.code_verifier,
        )?)
    }

    pub fn sign(self, sign: impl FnOnce(&[u8]) -> Result<String>) -> Result<SignedOidcLogin> {
        let unsigned = self.into_unsigned_session_grant_request()?;
        let signature =
            NonEmptyString::new(sign(&unsigned.canonical_signing_bytes()?)?).map_err(|error| {
                crate::Error::Protocol(format!("invalid session grant signature: {error}"))
            })?;
        Ok(SignedOidcLogin {
            request: unsigned.attach_signature(signature)?,
        })
    }
}

#[derive(Clone, Debug)]
pub struct SignedOidcLogin {
    request: SessionGrantRequestBody,
}

impl SignedOidcLogin {
    pub fn into_session_grant_request(self) -> SessionGrantRequestBody {
        self.request
    }
}

#[derive(Clone, Debug)]
pub enum LoginKind {
    AgentKeyProof(AgentKeyProofLogin),
    HolderProof(HolderProofLogin),
    Oidc(SignedOidcLogin),
    DidProof(DidProofLogin),
}

impl LoginKind {
    pub fn into_session_grant_request(self) -> Result<SessionGrantRequestBody> {
        match self {
            Self::AgentKeyProof(login) => login.into_session_grant_request(),
            Self::HolderProof(login) => Ok(login.into_session_grant_request()),
            Self::Oidc(login) => Ok(login.into_session_grant_request()),
            Self::DidProof(login) => Ok(login.into_session_grant_request()),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::protocol::{Hash, RealmId, SessionGrantProofKind};

    use super::*;

    fn did() -> DidCoreId {
        DidCoreId::new("ak:did_core:webvh:z6mkfixture:alice.example").unwrap()
    }

    fn device_id() -> DeviceId {
        DeviceId::new("ak:device:01904100-0000-7000-8000-000000000001").unwrap()
    }

    fn digest() -> Hash {
        Hash::new("sha256:0000000000000000000000000000000000000000000000000000000000000000")
            .unwrap()
    }

    fn expires_at() -> DateTime<Utc> {
        "2026-07-08T10:05:00.000Z".parse().unwrap()
    }

    fn agent_key_authorization_ref() -> String {
        crate::protocol::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [2; 32])
            .to_string()
    }

    fn proof_fields() -> SessionProofFields {
        SessionProofFields {
            challenge: "session-grant-challenge-0001".to_owned(),
            request_canonical_digest: digest(),
            audience: DidCoreId::new("ak:did_core:webvh:z6mkfixture:service.example").unwrap(),
            expires_at: Some(expires_at()),
            signature: "proof-signature".to_owned(),
            verification_method: Some(
                DidUrl::new("did:webvh:z6mkfixture:alice.example#device-1").unwrap(),
            ),
        }
    }

    #[test]
    fn did_proof_login_builds_session_grant_request() {
        let request = LoginKind::DidProof(DidProofLogin {
            principal_id: did(),
            device_id: device_id(),
            requested_scope: vec!["ak.self.events.stream.subscribe".to_owned()],
            dpop_binding_proof: None,
            applet_delegation: None,
            proof: proof_fields(),
        })
        .into_session_grant_request()
        .unwrap();

        assert_eq!(request.principal_id, did());
        assert_eq!(request.device_id, Some(device_id()));
        assert_eq!(
            request.proof.proof_kind,
            SessionGrantProofKind::DidBoundSignature
        );
        assert_eq!(request.proof.signature, "proof-signature");
        assert!(request.agent_key_authorization_ref.is_none());
    }

    #[test]
    fn holder_proof_login_builds_paired_device_request() {
        let request = LoginKind::HolderProof(HolderProofLogin {
            principal_id: did(),
            device_id: Some(device_id()),
            requested_scope: vec!["ak.self.account.read.viewer".to_owned()],
            dpop_binding_proof: Some(SessionGrantDpopBindingProof {
                proof_jwt: "holder-dpop-proof".to_owned(),
            }),
            applet_delegation: None,
            proof: proof_fields(),
        })
        .into_session_grant_request()
        .unwrap();

        assert_eq!(
            request.proof.proof_kind,
            SessionGrantProofKind::PairedDeviceProof
        );
        assert_eq!(request.principal_id, did());
        assert_eq!(request.device_id, Some(device_id()));
        assert_eq!(
            request.dpop_binding_proof.as_ref().unwrap().proof_jwt,
            "holder-dpop-proof"
        );
    }

    #[test]
    fn oidc_login_builds_code_exchange_request() {
        let request = LoginKind::Oidc(
            OidcLogin {
                principal_id: did(),
                device_id: Some(device_id()),
                requested_scope: Vec::new(),
                challenge: "oidc-challenge".to_owned(),
                audience: DidCoreId::new("ak:did_core:webvh:z6mkfixture:service.example").unwrap(),
                issuer: "https://issuer.example".to_owned(),
                client_id: "client-1".to_owned(),
                redirect_uri: "https://app.example/callback".to_owned(),
                state: "state-1".to_owned(),
                nonce: "nonce-1".to_owned(),
                authorization_code: "code-1".to_owned(),
                code_verifier: "verifier-1".to_owned(),
            }
            .sign(|bytes| Ok(arkret_canonical::base64url_encode(bytes)))
            .unwrap(),
        )
        .into_session_grant_request()
        .unwrap();

        assert_eq!(
            request.proof.proof_kind,
            SessionGrantProofKind::OidcCodeExchange
        );
        assert_eq!(
            request.proof.issuer.as_deref(),
            Some("https://issuer.example")
        );
        assert_eq!(request.proof.authorization_code.as_deref(), Some("code-1"));
        assert!(!request.proof.signature.is_empty());
    }

    #[test]
    fn agent_key_proof_login_builds_bound_request() {
        let request = LoginKind::AgentKeyProof(AgentKeyProofLogin {
            principal_id: did(),
            device_id: device_id(),
            requested_scope: vec!["ak.self.events.stream.subscribe".to_owned()],
            agent_key_authorization_ref: agent_key_authorization_ref(),
            agent_scope_request: SessionGrantAgentScopeRequest {
                realm_ids: vec![
                    RealmId::new("ak:realm:AfF-hFqRoMbajXkPapH-xaq0xwK-UKt2ph2zTs9JZRAO").unwrap(),
                ],
                strand_ids: Vec::new(),
                track_names: Vec::new(),
            },
            requested_scope_disclosure: None,
            dpop_binding_proof: SessionGrantDpopBindingProof {
                proof_jwt: "dpop-proof".to_owned(),
            },
            verification_method: DidUrl::new("did:webvh:z6mkfixture:agent.example#runtime-key-1")
                .unwrap(),
            challenge: "agent-challenge".to_owned(),
            nonce: "agent-nonce".to_owned(),
            audience: DidCoreId::new("ak:did_core:webvh:z6mkfixture:service.example").unwrap(),
            expires_at: expires_at(),
            signature: "agent-signature".to_owned(),
        })
        .into_session_grant_request()
        .unwrap();

        assert_eq!(
            request.proof.proof_kind,
            SessionGrantProofKind::AgentKeyProof
        );
        assert_eq!(
            request.agent_key_authorization_ref.as_deref(),
            Some(agent_key_authorization_ref().as_str())
        );
        assert_eq!(request.device_id, Some(device_id()));
        assert_eq!(
            request.dpop_binding_proof.as_ref().unwrap().proof_jwt,
            "dpop-proof"
        );
        assert_eq!(request.proof.signature, "agent-signature");
        assert_ne!(request.proof.request_canonical_digest, digest());
    }
}
