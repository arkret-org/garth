pub mod dpop;
pub mod engine;
pub mod login;
pub mod refresh;

pub use engine::{
    BoxSessionFuture, REFRESH_SUCCESS_COOLDOWN_SECS, SessionEngine, SessionGrantState,
    SessionGrantTransport, SessionRefreshOptions,
};
pub use login::{
    AgentKeyProofLogin, DidProofLogin, HolderProofLogin, LoginKind, OidcLogin, SessionProofFields,
};
pub use refresh::{
    GRANT_ROTATION_SKEW_SECS, POLL_INTERVAL_SECS, REFRESH_SKEW_SECS, RefreshDecision,
    SessionGrantRefreshState, grant_due_for_rotation, grant_is_dead, refresh_decision,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionHandle {
    pub access_token: String,
}
