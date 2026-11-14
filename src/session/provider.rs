use std::sync::{Arc, Mutex, PoisonError};

#[cfg(test)]
use arkret_wire::SessionGrantRef;

use super::{
    NoopSessionGrantStore, SessionEngine, SessionGrantState, SessionGrantStore,
    SessionGrantTransport, SessionRefreshOptions,
};
use crate::{Error, HostClock, Result, TransportProvider};

type TransportCache<T> = Arc<Mutex<Option<(SessionGrantState, T)>>>;

pub trait AuthenticatedTransportFactory: Clone + crate::MaybeSendSync + 'static {
    type Transport: Clone + crate::MaybeSend;

    fn build(&self, state: &SessionGrantState) -> Result<Self::Transport>;

    /// Recheck the factory's live host identity without issuing network IO.
    fn validate_own_station_session(
        &self,
        state: &SessionGrantState,
        _binding: &arkret_models_discovery::StationConnectionBinding,
    ) -> Result<()> {
        self.build(state).map(|_| ())
    }

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

struct ProviderOwnStationSource<T, F, E> {
    session: SessionEngine<T>,
    binding: arkret_models_discovery::StationConnectionBinding,
    factory: F,
    clock: E,
}

impl<
    T: SessionGrantTransport + crate::MaybeSendSync,
    F: AuthenticatedTransportFactory,
    E: HostClock,
> arkret_http_client::own_station_results::OwnStationSessionSource
    for ProviderOwnStationSource<T, F, E>
{
    fn snapshot(
        &self,
    ) -> arkret_http_client::Result<
        arkret_http_client::own_station_results::OwnStationSessionSnapshot,
    > {
        let checked = || -> Result<_> {
            let before = self
                .session
                .own_station_snapshot_at(&self.binding, self.clock.now())?;
            let state = self
                .session
                .current_state()
                .ok_or_else(|| Error::Protocol("no active own Station session".into()))?;
            self.factory
                .validate_own_station_session(&state, &self.binding)?;
            let after = self
                .session
                .own_station_snapshot_at(&self.binding, self.clock.now())?;
            if before != after {
                return Err(Error::Protocol(
                    "own Station session changed during host identity validation".into(),
                ));
            }
            Ok(after)
        };
        checked().map_err(|error| arkret_http_client::Error::Protocol(error.to_string()))
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
    persisted_state: Arc<Mutex<Option<SessionGrantState>>>,
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
            persisted_state: Arc::new(Mutex::new(session.current_state())),
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
            persisted_state: Arc::new(Mutex::new(None)),
            cached: Arc::new(Mutex::new(None)),
            clock: crate::SystemClock,
        };
        let state = provider
            .session
            .current_state()
            .ok_or_else(|| Error::Protocol("no initial session grant".into()))?;
        provider.state_store.save(&state).await?;
        *provider
            .persisted_state
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(state);
        Ok(provider)
    }

    pub fn restore(
        transport: T,
        factory: F,
        refresh_options: SessionRefreshOptions,
        state_store: S,
    ) -> Result<Self> {
        let restored = state_store.load()?;
        let persisted_state = restored.clone();
        let session = match restored {
            Some(state) => SessionEngine::with_state(transport, state),
            None => SessionEngine::new(transport),
        };
        Ok(Self {
            session,
            factory,
            refresh_options,
            state_store,
            persisted_state: Arc::new(Mutex::new(persisted_state)),
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
            persisted_state: self.persisted_state,
            cached: self.cached,
            clock,
        }
    }

    pub fn session(&self) -> &SessionEngine<T> {
        &self.session
    }

    /// Access the host's factory without changing this provider's frozen grant.
    pub fn factory(&self) -> &F {
        &self.factory
    }

    /// Bind a factory-built authenticated client to this provider's live grant.
    /// The source remains shared with every login, rotation and invalidation.
    pub fn own_station_result_client(
        &self,
        client: arkret_http_client::Client,
        binding: arkret_models_discovery::StationConnectionBinding,
    ) -> Result<arkret_http_client::own_station_results::OwnStationStateClient>
    where
        T: Clone + crate::MaybeSendSync + 'static,
    {
        let source = Arc::new(ProviderOwnStationSource {
            session: self.session.clone(),
            binding: binding.clone(),
            factory: self.factory.clone(),
            clock: self.clock.clone(),
        });
        arkret_http_client::own_station_results::OwnStationStateClient::new(client, binding, source)
            .map_err(Error::from)
    }

    pub fn clear_cached_transport(&self) {
        *self.cache_lock() = None;
    }

    /// Return the transport most recently built for the current grant.
    ///
    /// This is the synchronous bridge for host APIs that cannot await
    /// [`TransportProvider::provide`]. It never builds or refreshes a client;
    /// callers must first establish the provider through `provide`, and treat
    /// `None` as a signal to use an asynchronous provider-aware path.
    pub fn cached_transport(&self) -> Option<F::Transport> {
        let current_state = self.session.current_state();
        self.cache_lock()
            .as_ref()
            .filter(|(state, _)| Some(state) == current_state.as_ref())
            .map(|(_, transport)| transport.clone())
    }

    /// Clear the live grant, its durable representation, and any client built
    /// from it. Hosts call this only after a structured terminal grant error.
    pub fn invalidate(&self) -> Result<()> {
        self.session.clear_state();
        self.state_store.clear()?;
        *self
            .persisted_state
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = None;
        self.clear_cached_transport();
        Ok(())
    }

    pub async fn refresh_after_unauthorized(&self) -> Result<bool> {
        let Some(previous_state) = self.session.current_state() else {
            return Ok(false);
        };
        let previous_session_grant_id = Some(previous_state.grant_ref.clone());
        let refresh_options = self.options_for(&previous_state)?;
        self.session
            .refresh_after_unauthorized_with_store(
                refresh_options,
                self.clock.clone(),
                &self.state_store,
            )
            .await?;
        let refreshed_grant_id = self
            .session
            .current_state()
            .map(|state| state.grant_ref.clone());
        if refreshed_grant_id == previous_session_grant_id {
            // Another runner may already have rotated the shared session while
            // this request was still in flight with the previous transport.
            // The SessionEngine cooldown then legitimately returns the current
            // state unchanged. Treat that as a transport-rebuild recovery, not
            // as a terminal inability to refresh; otherwise a late 401 from a
            // sibling runner spuriously signs the user out even though the
            // provider already holds a usable grant.
            self.clear_cached_transport();
            return Ok(true);
        }
        self.persist_current_state().await?;
        self.clear_cached_transport();
        Ok(true)
    }

    /// Force an issuer round-trip before a security-sensitive action.
    ///
    /// Unlike normal `provide`, this does not trust local expiry metadata or
    /// the post-success cooldown. The issuer therefore re-evaluates current
    /// principal lifecycle, runtime-key authorization, and scopes before the
    /// returned transport can be used.
    /// An overlapping refresh fails locally; its unconfirmed predecessor must
    /// never satisfy this stronger requirement.
    pub async fn refresh_for_sensitive_action(&self) -> Result<F::Transport> {
        let previous_state = self
            .session
            .current_state()
            .ok_or_else(|| Error::Protocol("no active session grant".to_owned()))?;
        let refresh_options = self.options_for(&previous_state)?;
        let refreshed = self
            .session
            .refresh_for_sensitive_action_with_store(
                refresh_options,
                self.clock.clone(),
                &self.state_store,
            )
            .await?;
        let state = self
            .session
            .current_state()
            .ok_or(Error::OwnStationSessionChanged)?;
        if state.pending_refresh.is_some()
            || state.handle() != refreshed
            || state.expires_at <= self.clock.now()
        {
            return Err(Error::OwnStationSessionChanged);
        }
        self.persist_state_if_needed(&state).await?;
        if self.session.current_state().as_ref() != Some(&state) {
            return Err(Error::OwnStationSessionChanged);
        }
        let transport = self.factory.build(&state)?;
        if self.session.current_state().as_ref() != Some(&state)
            || state.expires_at <= self.clock.now()
        {
            return Err(Error::OwnStationSessionChanged);
        }
        self.clear_cached_transport();
        *self.cache_lock() = Some((state, transport.clone()));
        Ok(transport)
    }

    fn options_for(&self, state: &SessionGrantState) -> Result<SessionRefreshOptions> {
        if let Some(pending) = &state.pending_refresh {
            return Ok(SessionRefreshOptions {
                request: Some(pending.request.clone()),
                expected_dpop_jkt: Some(pending.expected_dpop_jkt.clone()),
            });
        }
        self.factory.refresh_options(state, &self.refresh_options)
    }

    async fn provide_authenticated(&self) -> Result<F::Transport> {
        let current = self
            .session
            .current_state()
            .ok_or_else(|| Error::Protocol("no active session grant".to_owned()))?;
        let refresh_options = self.options_for(&current)?;
        self.session
            .refresh_if_due_with_store(refresh_options, self.clock.clone(), &self.state_store)
            .await?;
        let state = self
            .session
            .current_state()
            .ok_or_else(|| Error::Protocol("no active session grant".to_owned()))?;
        self.persist_state_if_needed(&state).await?;
        if let Some((cached_state, transport)) = self.cache_lock().as_ref()
            && cached_state == &state
        {
            return Ok(transport.clone());
        }
        let transport = self.factory.build(&state)?;
        *self.cache_lock() = Some((state.clone(), transport.clone()));
        Ok(transport)
    }

    fn cache_lock(&self) -> std::sync::MutexGuard<'_, Option<(SessionGrantState, F::Transport)>> {
        self.cached.lock().unwrap_or_else(PoisonError::into_inner)
    }

    async fn persist_current_state(&self) -> Result<()> {
        let state = self
            .session
            .current_state()
            .ok_or_else(|| Error::Protocol("no active session grant".to_owned()))?;
        self.persist_state_if_needed(&state).await
    }

    async fn persist_state_if_needed(&self, state: &SessionGrantState) -> Result<()> {
        if self
            .persisted_state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            == Some(state)
        {
            return Ok(());
        }
        if self.state_store.persistence_required() {
            let mut durable = self
                .state_store
                .load()?
                .ok_or(Error::OwnStationSessionChanged)?;
            // Some host records persist the actual private holder and restore
            // its JKT without duplicating the optional public-JWK display value.
            if durable.session_public_key.is_none() {
                durable.session_public_key = state.session_public_key.clone();
            }
            if &durable != state {
                return Err(Error::OwnStationSessionChanged);
            }
        }
        // The engine has already installed a successor through atomic CAS.
        // Verification must never repair a changed durable slot by blind write.
        *self
            .persisted_state
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(state.clone());
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

    use arkret_models_collaboration::session_grant_bodies::{
        AgentSessionGrantRefreshRequestBody, AgentSessionRefreshProofContext,
        UnsignedAgentSessionRefreshProof,
    };
    use arkret_models_collaboration::session_grants::{
        SessionGrantRefreshRequestBody, SessionGrantRequestBody, SessionGrantResponseBody,
    };
    use arkret_wire::{AccountId, Base64UrlString, DidCoreId, DidUrl, Hash};
    use chrono::{Duration, Utc};

    use super::*;
    use crate::session::BoxSessionFuture;

    #[derive(Clone)]
    struct RefreshTransport {
        outcomes: Arc<Mutex<VecDeque<Result<SessionGrantResponseBody>>>>,
        calls: Arc<Mutex<usize>>,
    }

    impl SessionGrantTransport for RefreshTransport {
        fn issue_session_grant<'a>(
            &'a self,
            _request: SessionGrantRequestBody,
        ) -> BoxSessionFuture<'a, SessionGrantResponseBody> {
            Box::pin(async { Err(Error::Protocol("unexpected issue".to_owned())) })
        }

        fn refresh_session_grant<'a>(
            &'a self,
            _request: SessionGrantRefreshRequestBody,
        ) -> BoxSessionFuture<'a, SessionGrantResponseBody> {
            *self.calls.lock().unwrap() += 1;
            let outcome = self.outcomes.lock().unwrap().pop_front().unwrap();
            Box::pin(async move { outcome })
        }
    }

    #[derive(Clone)]
    struct TokenFactory {
        calls: Arc<Mutex<usize>>,
    }

    #[derive(Clone)]
    struct GatedRefreshTransport {
        started: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Notify>,
        outcome: Arc<Mutex<Option<Result<SessionGrantResponseBody>>>>,
        requests: Arc<Mutex<Vec<SessionGrantRefreshRequestBody>>>,
    }

    impl SessionGrantTransport for GatedRefreshTransport {
        fn issue_session_grant<'a>(
            &'a self,
            _request: SessionGrantRequestBody,
        ) -> BoxSessionFuture<'a, SessionGrantResponseBody> {
            Box::pin(async { Err(Error::Protocol("unexpected issue".into())) })
        }

        fn refresh_session_grant<'a>(
            &'a self,
            request: SessionGrantRefreshRequestBody,
        ) -> BoxSessionFuture<'a, SessionGrantResponseBody> {
            self.requests.lock().unwrap().push(request);
            Box::pin(async move {
                self.started.notify_one();
                self.release.notified().await;
                self.outcome.lock().unwrap().take().unwrap()
            })
        }
    }

    type GatedProvider = SessionTransportProvider<
        GatedRefreshTransport,
        TokenFactory,
        crate::SecureSessionGrantStore<crate::MemorySecureKeyStore>,
        FixedClock,
    >;

    #[derive(Clone)]
    struct FixedClock(chrono::DateTime<Utc>);

    impl HostClock for FixedClock {
        fn now(&self) -> chrono::DateTime<Utc> {
            self.0
        }
    }

    async fn gated_provider(rejected: bool) -> (GatedProvider, GatedRefreshTransport) {
        let transport = GatedRefreshTransport {
            started: Arc::new(tokio::sync::Notify::new()),
            release: Arc::new(tokio::sync::Notify::new()),
            outcome: Arc::new(Mutex::new(Some(if rejected {
                Err(Error::Protocol("issuer refused current authority".into()))
            } else {
                Ok(refresh_outcome())
            }))),
            requests: Arc::new(Mutex::new(Vec::new())),
        };
        let provider = SessionTransportProvider::with_store(
            SessionEngine::with_state(transport.clone(), state()),
            TokenFactory {
                calls: Arc::new(Mutex::new(0)),
            },
            refresh_options(),
            crate::SecureSessionGrantStore::new(
                crate::MemorySecureKeyStore::new(),
                "session/sensitive-refresh",
            ),
        )
        .await
        .unwrap()
        .with_clock(FixedClock(Utc::now()));
        (provider, transport)
    }

    async fn wait_for_refresh(transport: &GatedRefreshTransport) {
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            transport.started.notified(),
        )
        .await
        .expect("valid sensitive refresh reaches the issuer");
    }

    impl AuthenticatedTransportFactory for TokenFactory {
        type Transport = String;

        fn build(&self, state: &SessionGrantState) -> Result<Self::Transport> {
            *self.calls.lock().unwrap() += 1;
            Ok(state.session_grant.as_str().to_owned())
        }

        fn refresh_options(
            &self,
            state: &SessionGrantState,
            fallback: &SessionRefreshOptions,
        ) -> Result<SessionRefreshOptions> {
            let mut options = fallback.clone();
            if let Some(SessionGrantRefreshRequestBody::Agent(request)) = &mut options.request {
                request.session_grant = state.session_grant.clone();
                request.agent_session_refresh_proof.request_canonical_digest = arkret_models_collaboration::session_grant_bodies::agent_session_refresh_request_digest(
                    &request.session_grant,&request.principal_id,&request.agent_key_authorization_ref,&state.audience_id,&request.agent_session_refresh_proof.verification_method,
                )?;
            }
            Ok(options)
        }
    }

    fn grant_ref(n: u64) -> SessionGrantRef {
        SessionGrantRef::new(
            DidCoreId::new("ak:did_core:webvh:z6mkfixture:service.example").unwrap(),
            arkret_wire::SessionGrantId::new(format!(
                "ak:session_grant:01904100-0000-7000-8000-{n:012x}"
            ))
            .unwrap(),
        )
    }

    /// The single grant-binding public JWK every provider fixture speaks for.
    /// Per `sync/api-conventions.md` §3.3 the grant's `cnf.jkt` is this key's
    /// RFC 7638 thumbprint and `session_public_key` is this very JWK, so
    /// fixtures derive both from one key rather than from stand-in constants.
    fn session_public_jwk() -> arkret_models_identity::CanonicalSessionPublicJwk {
        arkret_models_identity::CanonicalSessionPublicJwk::new(
            r#"{"crv":"Ed25519","kty":"OKP","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#,
        )
        .unwrap()
    }

    fn session_dpop_jkt() -> String {
        session_public_jwk()
            .thumbprint_sha256()
            .expect("fixture session JWK has a thumbprint")
    }

    fn state() -> SessionGrantState {
        let expires =
            arkret_canonical::normalize_timestamp_canonical(Utc::now()) + Duration::hours(2);
        SessionGrantState {
            account_id: AccountId::new(
                DidCoreId::new("ak:did_core:webvh:z6mkfixture:alice.example").unwrap(),
                DidCoreId::new("ak:did_core:webvh:z6mkfixture:service.example").unwrap(),
            ),
            // The refresh options below exercise the Agent branch, whose
            // holder is the principal alone and never carries a Device.
            device_id: None,
            grant_ref: grant_ref(1),
            session_grant: super::super::engine::tests::opaque_secret(
                "grant-1",
                grant_ref(1),
                expires,
            ),
            expires_at: expires,
            audience_id: DidCoreId::new("ak:did_core:webvh:z6mkfixture:service.example").unwrap(),
            granted_scope: vec!["ak.self.committed_event.stream.subscribe.v1".to_owned()],
            session_public_key: Some(session_public_jwk().into_string()),
            dpop_jkt: Some(session_dpop_jkt()),
            pending_refresh: None,
        }
    }

    fn state_secret(n: u64) -> String {
        super::super::engine::tests::opaque_secret(&format!("grant-{n}"), grant_ref(n), Utc::now())
            .into_string()
    }

    #[test]
    fn own_station_live_provider_rejects_aba_new_instance_and_expired_grant() {
        let transport = RefreshTransport {
            outcomes: Arc::new(Mutex::new(VecDeque::new())),
            calls: Arc::new(Mutex::new(0)),
        };
        let state = state();
        let binding = arkret_models_discovery::StationConnectionBinding {
            service_id: state.audience_id.clone(),
            base_url: "https://service.example/".into(),
            trust_domain: arkret_wire::TrustDomainId::new("ak:trust_domain:service.example")
                .unwrap(),
            authentication_metadata: arkret_models_discovery::AuthenticationMetadata::minimal(),
        };
        let engine = SessionEngine::with_state(transport.clone(), state.clone());
        let first = engine
            .own_station_snapshot_at(&binding, Utc::now())
            .unwrap();
        engine.clear_state();
        engine.replace_state(Some(state.clone()));
        assert_ne!(
            first,
            engine
                .own_station_snapshot_at(&binding, Utc::now())
                .unwrap()
        );
        let new_engine = SessionEngine::with_state(transport, state.clone());
        assert_ne!(
            first,
            new_engine
                .own_station_snapshot_at(&binding, Utc::now())
                .unwrap()
        );
        assert!(
            new_engine
                .own_station_snapshot_at(&binding, state.expires_at)
                .is_err()
        );
        let factory = TokenFactory {
            calls: Arc::new(Mutex::new(0)),
        };
        let source = ProviderOwnStationSource {
            session: engine,
            binding,
            factory: factory.clone(),
            clock: crate::SystemClock,
        };
        arkret_http_client::own_station_results::OwnStationSessionSource::snapshot(&source)
            .unwrap();
        assert_eq!(
            *factory.calls.lock().unwrap(),
            1,
            "snapshot rechecks the factory host identity"
        );
    }

    fn refresh_outcome() -> SessionGrantResponseBody {
        let expires =
            arkret_canonical::normalize_timestamp_canonical(Utc::now()) + Duration::hours(1);
        SessionGrantResponseBody {
            issuer_id: grant_ref(2).issuer_id,
            session_grant_id: grant_ref(2).id,
            account_id: AccountId::new(
                DidCoreId::new("ak:did_core:webvh:z6mkfixture:alice.example").unwrap(),
                DidCoreId::new("ak:did_core:webvh:z6mkfixture:service.example").unwrap(),
            ),
            device_id: None,
            session_grant: super::super::engine::tests::opaque_secret(
                "grant-2",
                grant_ref(2),
                expires,
            ),
            session_public_key: session_public_jwk(),
            expires_at: expires,
            audience_id: DidCoreId::new("ak:did_core:webvh:z6mkfixture:service.example").unwrap(),
            granted_scope: vec!["ak.self.committed_event.stream.subscribe.v1".to_owned()],
            previous_session_grant_id: Some(grant_ref(1).id),
        }
    }

    fn refresh_options() -> SessionRefreshOptions {
        let audience = DidCoreId::new("ak:did_core:webvh:z6mkfixture:service.example").unwrap();
        let issued_at = arkret_canonical::normalize_timestamp_canonical(Utc::now());
        let proof = UnsignedAgentSessionRefreshProof {
            context: AgentSessionRefreshProofContext::V1,
            request_canonical_digest: Hash::new(
                "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            )
            .unwrap(),
            audience_id: audience.clone(),
            issued_at,
            expires_at: issued_at + Duration::minutes(5),
            verification_method: DidUrl::new("did:webvh:z6mkfixture:agent.example#runtime-key-1")
                .unwrap(),
        }
        .attach_signature(
            Base64UrlString::new(arkret_canonical::base64url_encode([0_u8; 64])).unwrap(),
        )
        .unwrap();
        SessionRefreshOptions {
            request: Some(SessionGrantRefreshRequestBody::Agent(
                AgentSessionGrantRefreshRequestBody {
                    session_grant: state().session_grant.clone(),
                    audience_id: Some(audience),
                    principal_id: DidCoreId::new("ak:did_core:webvh:z6mkfixture:alice.example")
                        .unwrap(),
                    agent_key_authorization_ref: arkret_wire::EventId::from_digest(
                        arkret_canonical::DigestSuite::Sha256,
                        [2; 32],
                    ),
                    agent_session_refresh_proof: proof,
                },
            )),
            expected_dpop_jkt: Some(session_dpop_jkt()),
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
                refresh_options(),
            ),
            refresh_calls,
            factory_calls,
        )
    }

    #[tokio::test]
    async fn provide_builds_once_per_grant() {
        let (provider, refresh_calls, factory_calls) = provider();

        assert_eq!(provider.provide().await.unwrap(), state_secret(1));
        assert_eq!(provider.provide().await.unwrap(), state_secret(1));
        assert_eq!(*refresh_calls.lock().unwrap(), 0);
        assert_eq!(*factory_calls.lock().unwrap(), 1);
    }

    #[tokio::test]
    async fn unauthorized_refresh_rebuilds_authenticated_transport() {
        let (provider, refresh_calls, factory_calls) = provider();
        assert_eq!(provider.provide().await.unwrap(), state_secret(1));

        assert!(provider.recover_unauthorized().await.unwrap());
        assert_eq!(provider.provide().await.unwrap(), state_secret(2));
        assert_eq!(*refresh_calls.lock().unwrap(), 1);
        assert_eq!(*factory_calls.lock().unwrap(), 2);
    }

    #[tokio::test]
    async fn sensitive_action_forces_issuer_refresh_while_grant_is_locally_fresh() {
        let (provider, refresh_calls, factory_calls) = provider();
        assert_eq!(provider.provide().await.unwrap(), state_secret(1));

        assert_eq!(
            provider.refresh_for_sensitive_action().await.unwrap(),
            state_secret(2)
        );
        assert_eq!(*refresh_calls.lock().unwrap(), 1);
        assert_eq!(*factory_calls.lock().unwrap(), 2);
    }

    #[tokio::test]
    async fn sensitive_refresh_never_uses_an_unconfirmed_in_flight_predecessor() {
        for rejected in [false, true] {
            let (provider, transport) = gated_provider(rejected).await;
            assert_eq!(provider.provide().await.unwrap(), state_secret(1));
            let first = {
                let provider = provider.clone();
                tokio::spawn(async move { provider.refresh_for_sensitive_action().await })
            };
            wait_for_refresh(&transport).await;
            let builds = *provider.factory.calls.lock().unwrap();
            assert!(provider.refresh_for_sensitive_action().await.is_err());
            assert_eq!(*provider.factory.calls.lock().unwrap(), builds);
            assert_eq!(transport.requests.lock().unwrap().len(), 1);
            // Ordinary traffic remains live while the stronger operation fails closed.
            assert_eq!(provider.provide().await.unwrap(), state_secret(1));
            // An in-flight 401 recovery must not turn the same pending request
            // into proof that an issuer has already approved a sensitive call.
            assert!(provider.refresh_after_unauthorized().await.unwrap());
            assert!(provider.refresh_for_sensitive_action().await.is_err());

            transport.release.notify_one();
            let result = tokio::time::timeout(std::time::Duration::from_secs(5), first)
                .await
                .unwrap()
                .unwrap();
            let durable = provider.state_store.load().unwrap().unwrap();
            if rejected {
                assert!(result.is_err());
                assert_eq!(durable.grant_ref, grant_ref(1));
                assert!(durable.pending_refresh.is_some());
            } else {
                assert_eq!(result.unwrap(), state_secret(2));
                assert_eq!(durable.grant_ref, grant_ref(2));
                assert!(durable.pending_refresh.is_none());
                // A late 401 from the old transport rebuilds the committed
                // successor inside cooldown without issuing another rotation.
                assert!(provider.refresh_after_unauthorized().await.unwrap());
                assert_eq!(provider.provide().await.unwrap(), state_secret(2));
                assert_eq!(transport.requests.lock().unwrap().len(), 1);
            }
        }
    }

    #[tokio::test]
    async fn cancelled_sensitive_refresh_releases_gate_and_replays_exact_durable_request() {
        let (provider, transport) = gated_provider(false).await;
        let cancelled = {
            let provider = provider.clone();
            tokio::spawn(async move { provider.refresh_for_sensitive_action().await })
        };
        wait_for_refresh(&transport).await;
        assert!(provider.refresh_for_sensitive_action().await.is_err());
        let pending = provider.state_store.load().unwrap().unwrap();
        assert!(pending.pending_refresh.is_some());
        cancelled.abort();
        assert!(cancelled.await.unwrap_err().is_cancelled());

        let retry = {
            let provider = provider.clone();
            tokio::spawn(async move { provider.refresh_for_sensitive_action().await })
        };
        wait_for_refresh(&transport).await;
        assert!(provider.refresh_for_sensitive_action().await.is_err());
        assert_eq!(provider.state_store.load().unwrap().unwrap(), pending);
        {
            let requests = transport.requests.lock().unwrap();
            assert_eq!(requests.len(), 2);
            assert_eq!(
                arkret_canonical::canonical_json_bytes(&requests[0]).unwrap(),
                arkret_canonical::canonical_json_bytes(&requests[1]).unwrap(),
            );
        }
        transport.release.notify_one();
        assert_eq!(
            tokio::time::timeout(std::time::Duration::from_secs(5), retry)
                .await
                .unwrap()
                .unwrap()
                .unwrap(),
            state_secret(2),
        );
        let durable = provider.state_store.load().unwrap().unwrap();
        assert_eq!(durable.grant_ref, grant_ref(2));
        assert!(durable.pending_refresh.is_none());
    }

    #[tokio::test]
    async fn sensitive_refresh_cannot_overwrite_a_new_durable_login() {
        let (provider, transport) = gated_provider(false).await;
        let pending = {
            let provider = provider.clone();
            tokio::spawn(async move { provider.refresh_for_sensitive_action().await })
        };
        wait_for_refresh(&transport).await;
        let mut newer = state();
        newer.grant_ref = grant_ref(99);
        newer.session_grant = super::super::engine::tests::opaque_secret(
            "new-login",
            grant_ref(99),
            newer.expires_at,
        );
        provider.state_store.save(&newer).await.unwrap();
        transport.release.notify_one();
        assert!(matches!(
            tokio::time::timeout(std::time::Duration::from_secs(5), pending)
                .await
                .unwrap()
                .unwrap(),
            Err(Error::OwnStationSessionChanged),
        ));
        assert_eq!(provider.state_store.load().unwrap().unwrap(), newer);
        assert_eq!(*provider.factory.calls.lock().unwrap(), 0);
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
        let options = refresh_options();
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
        assert_eq!(restored.provide().await.unwrap(), state_secret(1));
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
        assert_eq!(after_rotation.provide().await.unwrap(), state_secret(2));
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
            first.session().current_state().unwrap().grant_ref,
            grant_ref(2)
        );
        assert_eq!(
            second.session().current_state().unwrap().grant_ref,
            grant_ref(2)
        );
    }

    #[tokio::test]
    async fn late_sibling_unauthorized_rebuilds_after_shared_rotation() {
        let (first, refresh_calls, factory_calls) = provider();
        let second = first.clone();

        assert_eq!(second.provide().await.unwrap(), state_secret(1));
        assert!(first.refresh_after_unauthorized().await.unwrap());
        assert_eq!(*refresh_calls.lock().unwrap(), 1);

        // This models a request that left with grant-1 before the first runner
        // rotated and returned its 401 afterwards, inside the shared cooldown.
        assert!(second.refresh_after_unauthorized().await.unwrap());
        assert_eq!(*refresh_calls.lock().unwrap(), 1);
        assert_eq!(second.provide().await.unwrap(), state_secret(2));
        assert_eq!(*factory_calls.lock().unwrap(), 2);
    }
}
