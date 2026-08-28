use crate::protocol::session_grant::agent_key_proof_session_grant_request;
use crate::protocol::{
    AgentRequestedScopeDisclosure, DeviceId, DidCoreId, DidUrl, Result,
    SessionGrantAgentScopeRequest, SessionGrantDpopBindingProof, SessionGrantRequestBody,
};
use chrono::{DateTime, Utc};

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
    pub audience_id: DidCoreId,
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
            self.audience_id,
            self.expires_at,
            self.signature,
        )?)
    }
}

#[derive(Clone, Debug)]
pub enum LoginKind {
    AgentKeyProof(AgentKeyProofLogin),
}

impl LoginKind {
    pub fn into_session_grant_request(self) -> Result<SessionGrantRequestBody> {
        match self {
            Self::AgentKeyProof(login) => login.into_session_grant_request(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::protocol::RealmId;

    use super::*;

    fn principal_id() -> DidCoreId {
        DidCoreId::new("ak:did_core:webvh:z6mkfixture:alice.example").unwrap()
    }

    fn device_id() -> DeviceId {
        DeviceId::new("ak:device:01904100-0000-7000-8000-000000000001").unwrap()
    }

    fn expires_at() -> DateTime<Utc> {
        "2026-07-08T10:05:00.000Z".parse().unwrap()
    }

    fn agent_key_authorization_ref() -> String {
        crate::protocol::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [2; 32])
            .to_string()
    }

    #[test]
    fn agent_key_proof_login_builds_bound_request() {
        let request = LoginKind::AgentKeyProof(AgentKeyProofLogin {
            principal_id: principal_id(),
            device_id: device_id(),
            requested_scope: vec!["ak.self.events.stream.subscribe.v1".to_owned()],
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
            audience_id: DidCoreId::new("ak:did_core:webvh:z6mkfixture:service.example").unwrap(),
            expires_at: expires_at(),
            signature: "agent-signature".to_owned(),
        })
        .into_session_grant_request()
        .unwrap();

        let SessionGrantRequestBody::Agent(request) = request else {
            panic!("agent login must build the Agent branch");
        };
        assert_eq!(
            request.agent_key_authorization_ref,
            agent_key_authorization_ref()
        );
        assert_eq!(request.device_id, device_id());
        assert_eq!(request.dpop_binding_proof.proof_jwt, "dpop-proof");
        assert_eq!(request.proof.signature, "agent-signature");
        assert_eq!(
            request.proof.audience_id.as_str(),
            "ak:did_core:webvh:z6mkfixture:service.example"
        );
    }
}
