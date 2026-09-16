use arkret_auth::session_grant::agent_key_proof_session_grant_request;
use arkret_models_collaboration::agent_scope::AgentRequestedScopeDisclosure;
use arkret_models_collaboration::session_grants::{
    SessionGrantAgentScopeRequest, SessionGrantDpopBindingProof, SessionGrantRequestBody,
};
use arkret_wire::{DeviceId, DidCoreId, DidUrl};
use chrono::{DateTime, Utc};

use crate::Result;

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
    pub audience_id: DidCoreId,
    pub issued_at: DateTime<Utc>,
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
