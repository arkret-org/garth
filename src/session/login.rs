use chrono::{DateTime, Utc};
use cokret::{
    DeviceId, Did, Hash, Result, SessionGrantAppletDelegation, SessionGrantDpopBindingProof,
    SessionGrantProofKind, SessionGrantRequestBody, SessionGrantRequestProof,
};
use serde_json::Value;

#[derive(Clone, Debug)]
pub struct SessionProofFields {
    pub challenge: String,
    pub request_canonical_digest: Hash,
    pub audience: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub signature: String,
    pub verification_method: Option<String>,
}

impl SessionProofFields {
    pub fn into_request_proof(self, proof_kind: SessionGrantProofKind) -> SessionGrantRequestProof {
        SessionGrantRequestProof {
            proof_kind,
            challenge: self.challenge,
            request_canonical_digest: self.request_canonical_digest,
            audience: self.audience,
            expires_at: self.expires_at,
            signature: self.signature,
            verification_method: self.verification_method,
            issuer: None,
            client_id: None,
            redirect_uri: None,
            state: None,
            nonce: None,
            authorization_code: None,
            code_verifier: None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct AgentKeyProofLogin {
    pub principal_id: Did,
    pub requested_scope: Vec<String>,
    pub agent_key_authorization_ref: String,
    pub agent_scope_request: Value,
    pub dpop_binding_proof: SessionGrantDpopBindingProof,
    pub verification_method: String,
    pub challenge: String,
    pub nonce: String,
    pub audience: String,
    pub expires_at: DateTime<Utc>,
    pub signature: String,
}

impl AgentKeyProofLogin {
    pub fn into_session_grant_request(self) -> Result<SessionGrantRequestBody> {
        cokret::agent::agent_key_proof_session_grant_request(
            self.principal_id,
            self.requested_scope,
            self.agent_key_authorization_ref,
            self.agent_scope_request,
            self.dpop_binding_proof,
            self.verification_method,
            self.challenge,
            self.nonce,
            self.audience,
            self.expires_at,
            self.signature,
        )
    }
}

#[derive(Clone, Debug)]
pub struct HolderProofLogin {
    pub principal_id: Did,
    pub device_id: Option<DeviceId>,
    pub requested_scope: Vec<String>,
    pub dpop_binding_proof: Option<SessionGrantDpopBindingProof>,
    pub applet_delegation: Option<SessionGrantAppletDelegation>,
    pub proof: SessionProofFields,
}

impl HolderProofLogin {
    pub fn into_session_grant_request(self) -> SessionGrantRequestBody {
        SessionGrantRequestBody {
            principal_id: Some(self.principal_id),
            device_id: self.device_id,
            requested_scope: self.requested_scope,
            agent_key_authorization_ref: None,
            agent_scope_request: Value::Null,
            dpop_binding_proof: self.dpop_binding_proof,
            applet_delegation: self.applet_delegation,
            proof: self
                .proof
                .into_request_proof(SessionGrantProofKind::PairedDeviceProof),
        }
    }
}

#[derive(Clone, Debug)]
pub struct DidProofLogin {
    pub principal_id: Did,
    pub device_id: DeviceId,
    pub requested_scope: Vec<String>,
    pub dpop_binding_proof: Option<SessionGrantDpopBindingProof>,
    pub applet_delegation: Option<SessionGrantAppletDelegation>,
    pub proof: SessionProofFields,
}

impl DidProofLogin {
    pub fn into_session_grant_request(self) -> SessionGrantRequestBody {
        SessionGrantRequestBody {
            principal_id: Some(self.principal_id),
            device_id: Some(self.device_id),
            requested_scope: self.requested_scope,
            agent_key_authorization_ref: None,
            agent_scope_request: Value::Null,
            dpop_binding_proof: self.dpop_binding_proof,
            applet_delegation: self.applet_delegation,
            proof: self
                .proof
                .into_request_proof(SessionGrantProofKind::DidBoundSignature),
        }
    }
}

#[derive(Clone, Debug)]
pub struct OidcLogin {
    pub principal_id: Option<Did>,
    pub device_id: Option<DeviceId>,
    pub requested_scope: Vec<String>,
    pub challenge: String,
    pub request_canonical_digest: Hash,
    pub audience: String,
    pub issuer: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub state: String,
    pub nonce: String,
    pub authorization_code: String,
    pub code_verifier: String,
}

impl OidcLogin {
    pub fn into_session_grant_request(self) -> SessionGrantRequestBody {
        SessionGrantRequestBody {
            principal_id: self.principal_id,
            device_id: self.device_id,
            requested_scope: self.requested_scope,
            agent_key_authorization_ref: None,
            agent_scope_request: Value::Null,
            dpop_binding_proof: None,
            applet_delegation: None,
            proof: SessionGrantRequestProof {
                proof_kind: SessionGrantProofKind::OidcCodeExchange,
                challenge: self.challenge,
                request_canonical_digest: self.request_canonical_digest,
                audience: self.audience,
                expires_at: None,
                signature: String::new(),
                verification_method: None,
                issuer: Some(self.issuer),
                client_id: Some(self.client_id),
                redirect_uri: Some(self.redirect_uri),
                state: Some(self.state),
                nonce: Some(self.nonce),
                authorization_code: Some(self.authorization_code),
                code_verifier: Some(self.code_verifier),
            },
        }
    }
}

#[derive(Clone, Debug)]
pub enum LoginKind {
    AgentKeyProof(AgentKeyProofLogin),
    HolderProof(HolderProofLogin),
    Oidc(OidcLogin),
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
    use serde_json::json;

    use super::*;

    fn did() -> Did {
        Did::new("did:webvh:z6mkfixture:alice.example").unwrap()
    }

    fn device_id() -> DeviceId {
        DeviceId::new("ck:device:01904100-0000-7000-8000-000000000001").unwrap()
    }

    fn digest() -> Hash {
        Hash::new("sha256:0000000000000000000000000000000000000000000000000000000000000000")
            .unwrap()
    }

    fn expires_at() -> DateTime<Utc> {
        "2026-07-08T10:05:00Z".parse().unwrap()
    }

    fn proof_fields() -> SessionProofFields {
        SessionProofFields {
            challenge: "session-grant-challenge-0001".to_owned(),
            request_canonical_digest: digest(),
            audience: "did:webvh:z6mkfixture:service.example".to_owned(),
            expires_at: Some(expires_at()),
            signature: "proof-signature".to_owned(),
            verification_method: Some("did:webvh:z6mkfixture:alice.example#device-1".to_owned()),
        }
    }

    #[test]
    fn did_proof_login_builds_session_grant_request() {
        let request = LoginKind::DidProof(DidProofLogin {
            principal_id: did(),
            device_id: device_id(),
            requested_scope: vec!["ck.self.events.stream.subscribe".to_owned()],
            dpop_binding_proof: None,
            applet_delegation: None,
            proof: proof_fields(),
        })
        .into_session_grant_request()
        .unwrap();

        assert_eq!(request.principal_id, Some(did()));
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
            requested_scope: vec!["ck.self.account.query.viewer".to_owned()],
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
        assert_eq!(request.principal_id, Some(did()));
        assert_eq!(request.device_id, Some(device_id()));
        assert_eq!(
            request.dpop_binding_proof.as_ref().unwrap().proof_jwt,
            "holder-dpop-proof"
        );
    }

    #[test]
    fn oidc_login_builds_code_exchange_request() {
        let request = LoginKind::Oidc(OidcLogin {
            principal_id: None,
            device_id: Some(device_id()),
            requested_scope: Vec::new(),
            challenge: "oidc-challenge".to_owned(),
            request_canonical_digest: digest(),
            audience: "did:webvh:z6mkfixture:service.example".to_owned(),
            issuer: "https://issuer.example".to_owned(),
            client_id: "client-1".to_owned(),
            redirect_uri: "https://app.example/callback".to_owned(),
            state: "state-1".to_owned(),
            nonce: "nonce-1".to_owned(),
            authorization_code: "code-1".to_owned(),
            code_verifier: "verifier-1".to_owned(),
        })
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
        assert!(request.proof.signature.is_empty());
    }

    #[test]
    fn agent_key_proof_login_reuses_sdk_request_builder() {
        let request = LoginKind::AgentKeyProof(AgentKeyProofLogin {
            principal_id: did(),
            requested_scope: vec!["ck.self.events.stream.subscribe".to_owned()],
            agent_key_authorization_ref: "ck:event:01904100-0000-7000-8000-000000000002".to_owned(),
            agent_scope_request: json!({"kind": "realm"}),
            dpop_binding_proof: SessionGrantDpopBindingProof {
                proof_jwt: "dpop-proof".to_owned(),
            },
            verification_method: "did:webvh:z6mkfixture:agent.example#runtime-key-1".to_owned(),
            challenge: "agent-challenge".to_owned(),
            nonce: "agent-nonce".to_owned(),
            audience: "did:webvh:z6mkfixture:service.example".to_owned(),
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
            Some("ck:event:01904100-0000-7000-8000-000000000002")
        );
        assert_eq!(
            request.dpop_binding_proof.as_ref().unwrap().proof_jwt,
            "dpop-proof"
        );
        assert_eq!(request.proof.signature, "agent-signature");
        assert_ne!(request.proof.request_canonical_digest, digest());
    }
}
