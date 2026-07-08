pub mod dpop;
pub mod engine;
pub mod login;
pub mod refresh;

pub use engine::{
    BoxSessionFuture, SessionEngine, SessionGrantState, SessionGrantTransport,
    SessionRefreshOptions,
};
pub use login::{
    AgentKeyProofLogin, DidProofLogin, HolderProofLogin, LoginKind, OidcLogin, SessionProofFields,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionHandle {
    pub access_token: String,
}
