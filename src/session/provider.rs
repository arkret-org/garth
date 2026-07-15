use std::sync::{Arc, Mutex, PoisonError};

use arkret_core::{GrantId, Result};

use super::{
    NoopSessionGrantStore, SessionEngine, SessionGrantState, SessionGrantStore,
    SessionGrantTransport, SessionRefreshOptions,
};
use crate::{HostClock, TransportProvider};

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
pub struct SessionTransportProvider<T, F, S = NoopSessionGrantStore, E = crate::SystemClock>
where
    F: AuthenticatedTransportFactory,
    S: SessionGrantStore,
    E: HostClock,
{
    session: SessionEngine<T>,
    factory: F,
    refresh_options: SessionRefreshOptions,
    state_store: S,
    persisted_grant_id: Arc<Mutex<Option<GrantId>>>,
    cached: TransportCache<F::Transport>,
    clock: E,
}

impl<T, F> SessionTransportProvider<T, F, NoopSessionGrantStore, crate::SystemClock>
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
            persisted_grant_id: Arc::new(Mutex::new(
                session.current_state().map(|state| state.grant_id.clone()),
            )),
            session,
            factory,
            refresh_options,
            state_store: NoopSessionGrantStore,
            cached: Arc::new(Mutex::new(None)),
            clock: crate::SystemClock,
        }
    }
}

impl<T, F, S> SessionTransportProvider<T, F, S, crate::SystemClock>
where
    T: SessionGrantTransport,
    F: AuthenticatedTransportFactory,
    S: SessionGrantStore,
{
    pub async fn with_store(
        session: SessionEngine<T>,
        factory: F,
        refresh_options: SessionRefreshOptions,
        state_store: S,
    ) -> Result<Self> {
        let provider = Self {
            session,
            factory,
            refresh_options,
            state_store,
            persisted_grant_id: Arc::new(Mutex::new(None)),
            cached: Arc::new(Mutex::new(None)),
            clock: crate::SystemClock,
        };
        provider.persist_current_state().await?;
        Ok(provider)
    }

    pub fn restore(
        transport: T,
        factory: F,
        refresh_options: SessionRefreshOptions,
        state_store: S,
    ) -> Result<Self> {
        let restored = state_store.load()?;
        let persisted_grant_id = restored.as_ref().map(|state| state.grant_id.clone());
        let session = match restored {
            Some(state) => SessionEngine::with_state(transport, state),
            None => SessionEngine::new(transport),
        };
        Ok(Self {
            session,
            factory,
            refresh_options,
            state_store,
            persisted_grant_id: Arc::new(Mutex::new(persisted_grant_id)),
            cached: Arc::new(Mutex::new(None)),
            clock: crate::SystemClock,
        })
    }
}

impl<T, F, S, E> SessionTransportProvider<T, F, S, E>
where
    T: SessionGrantTransport,
    F: AuthenticatedTransportFactory,
    S: SessionGrantStore,
    E: HostClock,
{
    pub fn with_clock<E2: HostClock>(self, clock: E2) -> SessionTransportProvider<T, F, S, E2> {
        SessionTransportProvider {
            session: self.session,
            factory: self.factory,
            refresh_options: self.refresh_options,
            state_store: self.state_store,
            persisted_grant_id: self.persisted_grant_id,
            cached: self.cached,
            clock,
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
            .refresh_after_unauthorized(refresh_options, self.clock.now())
            .await?;
        let refreshed_grant_id = self
            .session
            .current_state()
            .map(|state| state.grant_id.clone());
        if refreshed_grant_id == previous_grant_id {
            // The shared refresh cooldown can legitimately return the current
            // grant. Do not tell the orchestrator to reconnect forever with
            // the same credential after the server has rejected it.
            if self.session.refresh_in_flight() {
                self.clear_cached_transport();
                return Ok(true);
            }
            return Ok(false);
        }
        self.persist_current_state().await?;
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
            .refresh_if_due(refresh_options, self.clock.now())
            .await?;
        let state = self
            .session
            .current_state()
            .ok_or_else(|| arkret_core::Error::Protocol("no active session grant".to_owned()))?;
        self.persist_state_if_needed(&state).await?;
        if let Some((grant_id, transport)) = self.cache_lock().as_ref()
            && grant_id == &state.grant_id
        {
            return Ok(transport.clone());
        }
        let transport = self.factory.build(&state)?;
        *self.cache_lock() = Some((state.grant_id.clone(), transport.clone()));
        Ok(transport)
    }

    fn cache_lock(&self) -> std::sync::MutexGuard<'_, Option<(GrantId, F::Transport)>> {
        self.cached.lock().unwrap_or_else(PoisonError::into_inner)
    }

    async fn persist_current_state(&self) -> Result<()> {
        let state = self
            .session
            .current_state()
            .ok_or_else(|| arkret_core::Error::Protocol("no active session grant".to_owned()))?;
        self.persist_state_if_needed(&state).await
    }

    async fn persist_state_if_needed(&self, state: &SessionGrantState) -> Result<()> {
        if self
            .persisted_grant_id
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            == Some(&state.grant_id)
        {
            return Ok(());
        }
        self.state_store.save(state).await?;
        *self
            .persisted_grant_id
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(state.grant_id.clone());
        Ok(())
    }
}

impl<T, F, S, E> TransportProvider for SessionTransportProvider<T, F, S, E>
where
    T: SessionGrantTransport,
    F: AuthenticatedTransportFactory,
    S: SessionGrantStore,
    E: HostClock,
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
    use chrono::{Duration, Utc};

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
            audience: Did::new("did:webvh:z6mkfixture:service.example").unwrap(),
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
            audience: Did::new("did:webvh:z6mkfixture:service.example").unwrap(),
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
                    audience: Some(
                        Did::new("did:webvh:z6mkfixture:service.example").unwrap(),
                    ),
                    device_id: Some(
                        DeviceId::new("ak:device:01904100-0000-7000-8000-000000000001").unwrap(),
                    ),
                    proof: Some(SessionGrantRefreshProof {
                        proof_kind: Some(SessionGrantProofKind::DidBoundSignature),
                        challenge: Some("refresh-challenge".to_owned()),
                        request_canonical_digest: Some(
                            Hash::new("sha256:0000000000000000000000000000000000000000000000000000000000000000").unwrap(),
                        ),
                        audience: Some(
                            Did::new("did:webvh:z6mkfixture:service.example").unwrap(),
                        ),
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

    #[tokio::test]
    async fn secure_store_restores_and_tracks_rotated_grant() {
        use crate::{MemorySecureKeyStore, SecureSessionGrantStore};

        let secure = MemorySecureKeyStore::new();
        let store = SecureSessionGrantStore::new(secure, "session/account-1");
        let refresh_calls = Arc::new(Mutex::new(0));
        let transport = RefreshTransport {
            outcomes: Arc::new(Mutex::new(VecDeque::from([Ok(refresh_outcome())]))),
            calls: refresh_calls.clone(),
        };
        let factory = TokenFactory {
            calls: Arc::new(Mutex::new(0)),
        };
        let options = SessionRefreshOptions {
            audience: Some(Did::new("did:webvh:z6mkfixture:service.example").unwrap()),
            device_id: state().device_id.clone(),
            proof: Some(SessionGrantRefreshProof {
                proof_kind: Some(SessionGrantProofKind::DidBoundSignature),
                challenge: Some("refresh-challenge".to_owned()),
                request_canonical_digest: Some(
                    Hash::new(
                        "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                    )
                    .unwrap(),
                ),
                audience: Some(Did::new("did:webvh:z6mkfixture:service.example").unwrap()),
                issued_at: Some(Utc::now()),
                expires_at: Some(Utc::now() + chrono::Duration::minutes(5)),
                signature: Some("refresh-proof-signature".to_owned()),
                verification_method: Some(
                    "did:webvh:z6mkfixture:alice.example#device-1".to_owned(),
                ),
            }),
            expected_dpop_jkt: Some("jkt-1".to_owned()),
        };
        let provider = SessionTransportProvider::with_store(
            SessionEngine::with_state(transport.clone(), state()),
            factory.clone(),
            options.clone(),
            store.clone(),
        )
        .await
        .unwrap();

        let restored = SessionTransportProvider::restore(
            transport,
            factory.clone(),
            options.clone(),
            store.clone(),
        )
        .unwrap();
        assert_eq!(restored.provide().await.unwrap(), "grant-1");
        assert!(provider.refresh_after_unauthorized().await.unwrap());
        assert_eq!(*refresh_calls.lock().unwrap(), 1);

        let after_rotation = SessionTransportProvider::restore(
            RefreshTransport {
                outcomes: Arc::new(Mutex::new(VecDeque::new())),
                calls: Arc::new(Mutex::new(0)),
            },
            factory,
            options,
            store,
        )
        .unwrap();
        assert_eq!(after_rotation.provide().await.unwrap(), "grant-2");
    }

    #[tokio::test]
    async fn two_provider_instances_share_one_forced_refresh_exchange() {
        let (first, refresh_calls, _) = provider();
        let second = first.clone();

        let (first_result, second_result) = tokio::join!(
            first.refresh_after_unauthorized(),
            second.refresh_after_unauthorized()
        );

        assert!(first_result.unwrap() || second_result.unwrap());
        assert_eq!(*refresh_calls.lock().unwrap(), 1);
        assert_eq!(
            first.session().current_state().unwrap().grant_id,
            grant_id(2)
        );
        assert_eq!(
            second.session().current_state().unwrap().grant_id,
            grant_id(2)
        );
    }
}
