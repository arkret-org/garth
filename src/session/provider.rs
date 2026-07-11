use std::sync::{Arc, Mutex, PoisonError};

use arkret_core::{GrantId, Result};
use chrono::Utc;

use super::{SessionEngine, SessionGrantState, SessionGrantTransport, SessionRefreshOptions};
use crate::TransportProvider;

type TransportCache<T> = Arc<Mutex<Option<(GrantId, T)>>>;

pub trait AuthenticatedTransportFactory: Clone + 'static {
    type Transport: Clone;

    fn build(&self, state: &SessionGrantState) -> Result<Self::Transport>;

    /// Mint per-refresh inputs (notably short-lived signed proofs). The
    /// default keeps static options for simple clients and tests.
    fn refresh_options(
        &self,
        _state: &SessionGrantState,
        fallback: &SessionRefreshOptions,
    ) -> Result<SessionRefreshOptions> {
        Ok(fallback.clone())
    }
}

#[derive(Clone, Debug)]
pub struct SessionTransportProvider<T, F>
where
    F: AuthenticatedTransportFactory,
{
    session: SessionEngine<T>,
    factory: F,
    refresh_options: SessionRefreshOptions,
    cached: TransportCache<F::Transport>,
}

impl<T, F> SessionTransportProvider<T, F>
where
    T: SessionGrantTransport,
    F: AuthenticatedTransportFactory,
{
    pub fn new(
        session: SessionEngine<T>,
        factory: F,
        refresh_options: SessionRefreshOptions,
    ) -> Self {
        Self {
            session,
            factory,
            refresh_options,
            cached: Arc::new(Mutex::new(None)),
        }
    }

    pub fn session(&self) -> &SessionEngine<T> {
        &self.session
    }

    pub fn clear_cached_transport(&self) {
        *self.cache_lock() = None;
    }

    pub async fn refresh_after_unauthorized(&self) -> Result<bool> {
        let previous_state = self
            .session
            .current_state()
            .ok_or_else(|| arkret_core::Error::Protocol("no active session grant".to_owned()))?;
        let previous_grant_id = Some(previous_state.grant_id.clone());
        let refresh_options = self
            .factory
            .refresh_options(&previous_state, &self.refresh_options)?;
        self.session
            .refresh_after_unauthorized(refresh_options, Utc::now())
            .await?;
        let refreshed_grant_id = self.session.current_state().map(|state| state.grant_id);
        if refreshed_grant_id == previous_grant_id {
            // The shared refresh cooldown can legitimately return the current
            // grant. Do not tell the orchestrator to reconnect forever with
            // the same credential after the server has rejected it.
            return Ok(false);
        }
        self.clear_cached_transport();
        Ok(true)
    }

    async fn provide_authenticated(&self) -> Result<F::Transport> {
        let current = self
            .session
            .current_state()
            .ok_or_else(|| arkret_core::Error::Protocol("no active session grant".to_owned()))?;
        let refresh_options = self
            .factory
            .refresh_options(&current, &self.refresh_options)?;
        self.session
            .refresh_if_due(refresh_options, Utc::now())
            .await?;
        let state = self
            .session
            .current_state()
            .ok_or_else(|| arkret_core::Error::Protocol("no active session grant".to_owned()))?;
        if let Some((grant_id, transport)) = self.cache_lock().as_ref()
            && grant_id == &state.grant_id
        {
            return Ok(transport.clone());
        }
        let transport = self.factory.build(&state)?;
        *self.cache_lock() = Some((state.grant_id, transport.clone()));
        Ok(transport)
    }

    fn cache_lock(&self) -> std::sync::MutexGuard<'_, Option<(GrantId, F::Transport)>> {
        self.cached.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl<T, F> TransportProvider for SessionTransportProvider<T, F>
where
    T: SessionGrantTransport,
    F: AuthenticatedTransportFactory,
{
    type Transport = F::Transport;

    fn provide(&self) -> impl std::future::Future<Output = Result<Self::Transport>> + '_ {
        self.provide_authenticated()
    }

    fn recover_unauthorized(&self) -> impl std::future::Future<Output = Result<bool>> + '_ {
        async move { self.refresh_after_unauthorized().await }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    use arkret_core::{
        DeviceId, Did, Error, Hash, SessionGrantOutcome, SessionGrantProofKind,
        SessionGrantRefreshOutcome, SessionGrantRefreshProof, SessionGrantRefreshRequestBody,
        SessionGrantRequestBody,
    };
    use chrono::Duration;

    use super::*;
    use crate::session::BoxSessionFuture;

    #[derive(Clone)]
    struct RefreshTransport {
        outcomes: Arc<Mutex<VecDeque<Result<SessionGrantRefreshOutcome>>>>,
        calls: Arc<Mutex<usize>>,
    }

    impl SessionGrantTransport for RefreshTransport {
        fn issue_session_grant<'a>(
            &'a self,
            _request: SessionGrantRequestBody,
        ) -> BoxSessionFuture<'a, SessionGrantOutcome> {
            Box::pin(async { Err(Error::Protocol("unexpected issue".to_owned())) })
        }

        fn refresh_session_grant<'a>(
            &'a self,
            _request: SessionGrantRefreshRequestBody,
        ) -> BoxSessionFuture<'a, SessionGrantRefreshOutcome> {
            *self.calls.lock().unwrap() += 1;
            let outcome = self.outcomes.lock().unwrap().pop_front().unwrap();
            Box::pin(async move { outcome })
        }
    }

    #[derive(Clone)]
    struct TokenFactory {
        calls: Arc<Mutex<usize>>,
    }

    impl AuthenticatedTransportFactory for TokenFactory {
        type Transport = String;

        fn build(&self, state: &SessionGrantState) -> Result<Self::Transport> {
            *self.calls.lock().unwrap() += 1;
            Ok(state.grant_jwt.clone())
        }
    }

    fn grant_id(n: u64) -> GrantId {
        GrantId::new(format!("ak:grant:01904100-0000-7000-8000-{n:012}")).unwrap()
    }

    fn state() -> SessionGrantState {
        SessionGrantState {
            principal_id: Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
            device_id: Some(
                DeviceId::new("ak:device:01904100-0000-7000-8000-000000000001").unwrap(),
            ),
            grant_id: grant_id(1),
            grant_jwt: "grant-1".to_owned(),
            expires_at: Utc::now() + Duration::hours(2),
            audience: "did:webvh:z6mkfixture:service.example".to_owned(),
            granted_scope: vec!["ak.self.events.stream.subscribe".to_owned()],
            session_public_key: Some("session-public-key".to_owned()),
            dpop_jkt: Some("jkt-1".to_owned()),
        }
    }

    fn refresh_outcome() -> SessionGrantRefreshOutcome {
        SessionGrantRefreshOutcome {
            grant_id: grant_id(2),
            grant_jwt: "grant-2".to_owned(),
            session_public_key: "session-public-key".to_owned(),
            expires_at: Utc::now() + Duration::hours(1),
            audience: "did:webvh:z6mkfixture:service.example".to_owned(),
            scopes: vec!["ak.self.events.stream.subscribe".to_owned()],
            dpop_jkt: "jkt-1".to_owned(),
            previous_grant_id: grant_id(1),
        }
    }

    #[allow(clippy::type_complexity)]
    fn provider() -> (
        SessionTransportProvider<RefreshTransport, TokenFactory>,
        Arc<Mutex<usize>>,
        Arc<Mutex<usize>>,
    ) {
        let refresh_calls = Arc::new(Mutex::new(0));
        let factory_calls = Arc::new(Mutex::new(0));
        let transport = RefreshTransport {
            outcomes: Arc::new(Mutex::new(VecDeque::from([Ok(refresh_outcome())]))),
            calls: refresh_calls.clone(),
        };
        let factory = TokenFactory {
            calls: factory_calls.clone(),
        };
        (
            SessionTransportProvider::new(
                SessionEngine::with_state(transport, state()),
                factory,
                SessionRefreshOptions {
                    audience: Some("did:webvh:z6mkfixture:service.example".to_owned()),
                    device_id: Some(
                        DeviceId::new("ak:device:01904100-0000-7000-8000-000000000001").unwrap(),
                    ),
                    proof: Some(SessionGrantRefreshProof {
                        proof_kind: Some(SessionGrantProofKind::DidBoundSignature),
                        challenge: Some("refresh-challenge".to_owned()),
                        request_canonical_digest: Some(
                            Hash::new("sha256:0000000000000000000000000000000000000000000000000000000000000000").unwrap(),
                        ),
                        audience: Some("did:webvh:z6mkfixture:service.example".to_owned()),
                        issued_at: Some(Utc::now()),
                        expires_at: Some(Utc::now() + Duration::minutes(5)),
                        signature: Some("refresh-proof-signature".to_owned()),
                        verification_method: Some(
                            "did:webvh:z6mkfixture:alice.example#device-1".to_owned(),
                        ),
                    }),
                    expected_dpop_jkt: Some("jkt-1".to_owned()),
                },
            ),
            refresh_calls,
            factory_calls,
        )
    }

    #[tokio::test]
    async fn provide_builds_once_per_grant() {
        let (provider, refresh_calls, factory_calls) = provider();

        assert_eq!(provider.provide().await.unwrap(), "grant-1");
        assert_eq!(provider.provide().await.unwrap(), "grant-1");
        assert_eq!(*refresh_calls.lock().unwrap(), 0);
        assert_eq!(*factory_calls.lock().unwrap(), 1);
    }

    #[tokio::test]
    async fn unauthorized_refresh_rebuilds_authenticated_transport() {
        let (provider, refresh_calls, factory_calls) = provider();
        assert_eq!(provider.provide().await.unwrap(), "grant-1");

        assert!(provider.recover_unauthorized().await.unwrap());
        assert_eq!(provider.provide().await.unwrap(), "grant-2");
        assert_eq!(*refresh_calls.lock().unwrap(), 1);
        assert_eq!(*factory_calls.lock().unwrap(), 2);
    }
}
