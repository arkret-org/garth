pub mod dpop;
pub mod engine;
pub mod login;
mod provider;
pub mod refresh;
mod store;

pub use engine::{
    BoxSessionFuture, REFRESH_SUCCESS_COOLDOWN_SECS, SessionEngine, SessionGrantState,
    SessionGrantTransport, SessionRefreshOptions,
};
pub use login::{
    AgentKeyProofLogin, DidProofLogin, HolderProofLogin, LoginKind, OidcLogin, SessionProofFields,
    SignedOidcLogin,
};
pub use provider::{AuthenticatedTransportFactory, SessionTransportProvider};
pub use refresh::{
    GRANT_ROTATION_SKEW_SECS, POLL_INTERVAL_SECS, REFRESH_SKEW_SECS, RefreshDecision,
    SessionGrantRefreshState, grant_due_for_rotation, grant_is_dead, refresh_decision,
};
pub use store::{NoopSessionGrantStore, SecureSessionGrantStore, SessionGrantStore};

#[derive(Clone, PartialEq, Eq, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct SessionHandle {
    pub access_token: String,
}

impl std::fmt::Debug for SessionHandle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SessionHandle")
            .field("access_token", &"[REDACTED]")
            .finish()
    }
}
