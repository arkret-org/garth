use arkret_auth::session_grant::agent_key_proof_session_grant_request;
use arkret_models_collaboration::agent_scope::AgentRequestedScopeDisclosure;
use arkret_models_collaboration::session_grants::{
    SessionGrantAgentScopeRequest, SessionGrantDpopBindingProof, SessionGrantRequestBody,
};
use arkret_wire::{DidCoreId, DidUrl, EventId};
use chrono::{DateTime, Utc};

use crate::Result;

#[derive(Clone, Debug)]
pub struct AgentKeyProofLogin {
    pub principal_id: DidCoreId,
    pub requested_scope: Vec<String>,
    pub agent_key_authorization_ref: EventId,
    pub agent_scope_request: SessionGrantAgentScopeRequest,
    pub requested_scope_disclosure: Option<AgentRequestedScopeDisclosure>,
    pub dpop_binding_proof: SessionGrantDpopBindingProof,
    pub verification_method: DidUrl,
    pub challenge: String,
    pub audience_id: DidCoreId,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub signature: String,
}

impl AgentKeyProofLogin {
    pub fn into_session_grant_request(self) -> Result<SessionGrantRequestBody> {
        Ok(agent_key_proof_session_grant_request(
            self.principal_id,
            self.requested_scope,
            self.agent_key_authorization_ref,
            self.agent_scope_request,
            self.requested_scope_disclosure,
            self.dpop_binding_proof,
            self.verification_method,
            self.challenge,
            self.audience_id,
            self.issued_at,
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
    use arkret_wire::RealmId;

    use super::*;

    fn principal_id() -> DidCoreId {
        DidCoreId::new("ak:did_core:webvh:z6mkfixture:alice.example").unwrap()
    }

    fn expires_at() -> DateTime<Utc> {
        "2026-07-08T10:05:00.000Z".parse().unwrap()
    }

    fn agent_key_authorization_ref() -> EventId {
        arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [2; 32])
    }

    #[test]
    fn agent_key_proof_login_builds_bound_request() {
        let request = LoginKind::AgentKeyProof(AgentKeyProofLogin {
            principal_id: principal_id(),
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
            challenge: "AAECAwQFBgcICQoLDA0ODw".to_owned(),
            audience_id: DidCoreId::new("ak:did_core:webvh:z6mkfixture:service.example").unwrap(),
            issued_at: expires_at() - chrono::Duration::minutes(5),
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
        assert_eq!(request.dpop_binding_proof.proof_jwt, "dpop-proof");
        assert_eq!(request.proof.signature, "agent-signature");
        assert_eq!(
            request.proof.audience_id.as_str(),
            "ak:did_core:webvh:z6mkfixture:service.example"
        );
    }
}
