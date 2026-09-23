use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use arkret_models_collaboration::session_grants::{
    SessionGrantOutcome, SessionGrantRefreshRequestBody, SessionGrantRequestBody,
};
use arkret_wire::{AccountId, DeviceId, DidCoreId, SessionGrantId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::SessionHandle;
use super::login::LoginKind;
use super::refresh::{RefreshDecision, SessionGrantRefreshState, refresh_decision};
use crate::{Error, Result};

#[cfg(not(target_arch = "wasm32"))]
pub type BoxSessionFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

#[cfg(target_arch = "wasm32")]
pub type BoxSessionFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + 'a>>;

pub trait SessionGrantTransport: crate::MaybeSendSync {
    fn issue_session_grant<'a>(
        &'a self,
        request: SessionGrantRequestBody,
    ) -> BoxSessionFuture<'a, SessionGrantOutcome>;

    fn refresh_session_grant<'a>(
        &'a self,
        request: SessionGrantRefreshRequestBody,
    ) -> BoxSessionFuture<'a, SessionGrantOutcome>;
}

impl SessionGrantTransport for arkret_http_client::Client {
    fn issue_session_grant<'a>(
        &'a self,
        request: SessionGrantRequestBody,
    ) -> BoxSessionFuture<'a, SessionGrantOutcome> {
        Box::pin(async move {
            self.auth_issue_session_grant(&request)
                .await
                .map_err(Error::from)
        })
    }

    fn refresh_session_grant<'a>(
        &'a self,
        request: SessionGrantRefreshRequestBody,
    ) -> BoxSessionFuture<'a, SessionGrantOutcome> {
        Box::pin(async move {
            self.auth_refresh_session_grant(&request)
                .await
                .map_err(Error::from)
        })
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SessionGrantState {
    #[zeroize(skip)]
    pub account_id: AccountId,
    #[zeroize(skip)]
    pub device_id: Option<DeviceId>,
    #[zeroize(skip)]
    pub grant_id: SessionGrantId,
    pub grant_jwt: String,
    #[zeroize(skip)]
    pub expires_at: DateTime<Utc>,
    #[zeroize(skip)]
    pub audience_id: DidCoreId,
    #[zeroize(skip)]
    pub granted_scope: Vec<String>,
    /// The session public key reported by the Account Authority when the grant
    /// was issued/rotated. It is retained by secure persistence and restored
    /// with the grant, but is not consumed by the refresh decision itself.
    #[zeroize(skip)]
    pub session_public_key: Option<String>,
    #[zeroize(skip)]
    pub dpop_jkt: Option<String>,
}

impl fmt::Debug for SessionGrantState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionGrantState")
            .field("account_id", &self.account_id)
            .field("device_id", &self.device_id)
            .field("grant_id", &self.grant_id)
            .field("grant_jwt", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .field("audience_id", &self.audience_id)
            .field("granted_scope", &self.granted_scope)
            .field("session_public_key", &self.session_public_key)
            .field("dpop_jkt", &self.dpop_jkt)
            .finish()
    }
}

impl SessionGrantState {
    pub fn handle(&self) -> SessionHandle {
        SessionHandle {
            access_token: self.grant_jwt.clone(),
        }
    }

    pub fn from_initial_registration_outcome(
        request: &arkret_models_identity::InitialSessionGrantIntent,
        outcome: SessionGrantOutcome,
        now: DateTime<Utc>,
    ) -> Result<Self> {
        if outcome.session_grant.trim().is_empty() || outcome.expires_at <= now {
            return Err(protocol(
                "initial Standard session grant is empty or expired",
            ));
        }
        if outcome.device_id.as_ref() != Some(&request.device_id)
            || outcome.session_public_key != request.session_public_key
            || outcome.audience_id != request.audience_id
            || outcome.account_id.station_id != request.audience_id
            || outcome.granted_scope
                != arkret_models_identity::standard_initial_session_grant_scope()
        {
            return Err(protocol(
                "initial Standard session grant does not match registration request",
            ));
        }
        Ok(Self {
            account_id: outcome.account_id,
            device_id: outcome.device_id,
            grant_id: outcome.session_grant_id,
            grant_jwt: outcome.session_grant,
            expires_at: outcome.expires_at,
            audience_id: outcome.audience_id,
            granted_scope: outcome.granted_scope,
            session_public_key: Some(outcome.session_public_key.into_string()),
            dpop_jkt: Some(request.session_public_key.thumbprint_sha256()?),
        })
    }

    fn refresh_state(&self) -> SessionGrantRefreshState {
        SessionGrantRefreshState {
            grant_expires_at: Some(self.expires_at),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct SessionRefreshOptions {
    /// Fully closed human or Agent refresh branch authored by the caller.
    /// Keeping the branch together prevents impossible cross-products such as
    /// a human device proof paired with Agent fields.
    pub request: Option<SessionGrantRefreshRequestBody>,
    pub expected_dpop_jkt: Option<String>,
}

/// Cooldown after a successful refresh during which `refresh_if_due` returns
/// the current handle instead of hitting the transport again. Guards against a
/// refresh treadmill when issued grants are short-lived enough to be
/// immediately `Due` again (many independent callers would otherwise each fire
/// a rotation).
pub const REFRESH_SUCCESS_COOLDOWN_SECS: i64 = 3;

/// Refresh coordination shared by all clones of a [`SessionEngine`]:
/// single-flight (only one transport refresh at a time) plus the
/// last-success timestamp backing the cooldown.
#[derive(Debug, Default)]
struct RefreshGate {
    in_flight: bool,
    last_success_at: Option<DateTime<Utc>>,
}

/// Clears the in-flight flag when the winning refresh finishes — including
/// when its future is dropped mid-await, so a cancelled refresh can never
/// wedge the gate shut.
struct RefreshInFlightGuard(Arc<Mutex<RefreshGate>>);

impl Drop for RefreshInFlightGuard {
    fn drop(&mut self) {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .in_flight = false;
    }
}

#[derive(Clone, Debug)]
pub struct SessionEngine<T> {
    transport: T,
    state: Arc<Mutex<Option<SessionGrantState>>>,
    refresh_gate: Arc<Mutex<RefreshGate>>,
}

impl<T> SessionEngine<T>
where
    T: SessionGrantTransport,
{
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            state: Arc::new(Mutex::new(None)),
            refresh_gate: Arc::new(Mutex::new(RefreshGate::default())),
        }
    }

    pub fn with_state(transport: T, state: SessionGrantState) -> Self {
        Self {
            transport,
            state: Arc::new(Mutex::new(Some(state))),
            refresh_gate: Arc::new(Mutex::new(RefreshGate::default())),
        }
    }

    // The state mutex only guards a plain `Option<SessionGrantState>` and every
    // critical section is panic-free, so it can never actually be poisoned.
    // Recover the guard rather than `unwrap()`-panicking, keeping the engine free
    // of a panic surface (and consistent with the store layer, which also maps
    // lock failures to a value rather than aborting).
    fn state_lock(&self) -> MutexGuard<'_, Option<SessionGrantState>> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn gate_lock(&self) -> MutexGuard<'_, RefreshGate> {
        self.refresh_gate
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn within_refresh_cooldown(&self, now: DateTime<Utc>) -> bool {
        match self.gate_lock().last_success_at {
            Some(at) => now.signed_duration_since(at).num_seconds() < REFRESH_SUCCESS_COOLDOWN_SECS,
            None => false,
        }
    }

    pub fn current_state(&self) -> Option<SessionGrantState> {
        self.state_lock().clone()
    }

    pub fn current_handle(&self) -> Option<SessionHandle> {
        self.current_state().map(|state| state.handle())
    }

    pub fn replace_state(&self, state: Option<SessionGrantState>) {
        *self.state_lock() = state;
    }

    pub fn clear_state(&self) {
        self.replace_state(None);
    }

    pub fn refresh_decision(&self, now: DateTime<Utc>) -> RefreshDecision {
        let state = self.state_lock();
        let refresh_state = state.as_ref().map(SessionGrantState::refresh_state);
        refresh_decision(refresh_state.as_ref(), now)
    }

    pub async fn login(&self, login: LoginKind, now: DateTime<Utc>) -> Result<SessionHandle> {
        let request = login.into_session_grant_request()?;
        self.login_request(request, now).await
    }

    /// Issue a session from an already-authored canonical request.
    ///
    /// Some protocol transitions, such as exchanging an authenticated account
    /// handoff after OIDC, are authored by `arkret-auth` rather than one of the
    /// convenience [`LoginKind`] builders. They still pass through the same
    /// response validation and state installation as every other login.
    pub async fn login_request(
        &self,
        request: SessionGrantRequestBody,
        now: DateTime<Utc>,
    ) -> Result<SessionHandle> {
        let outcome = self.transport.issue_session_grant(request.clone()).await?;
        let state = state_from_issue_outcome(&request, outcome, now)?;
        let handle = state.handle();
        *self.state_lock() = Some(state);
        Ok(handle)
    }

    pub async fn refresh_if_due(
        &self,
        options: SessionRefreshOptions,
        now: DateTime<Utc>,
    ) -> Result<SessionHandle> {
        match self.refresh_decision(now) {
            RefreshDecision::Fresh => self.current_handle().ok_or_else(no_active_grant),
            RefreshDecision::Due => {
                // A refresh just succeeded (possibly by another caller): the
                // grant is as fresh as it gets, do not fire another rotation.
                if self.within_refresh_cooldown(now) {
                    return self.current_handle().ok_or_else(no_active_grant);
                }
                self.refresh_once(options, now).await
            }
            RefreshDecision::NoGrant => Err(no_active_grant()),
            RefreshDecision::GrantExpired => Err(protocol("session grant is expired")),
        }
    }

    /// Refresh after a server has rejected the current credential. Unlike
    /// [`Self::refresh_if_due`], this does not trust local expiry metadata, but
    /// it still honors the shared success cooldown and single-flight gate.
    pub async fn refresh_after_unauthorized(
        &self,
        options: SessionRefreshOptions,
        now: DateTime<Utc>,
    ) -> Result<SessionHandle> {
        if self.within_refresh_cooldown(now) {
            return self.current_handle().ok_or_else(no_active_grant);
        }
        self.refresh_once(options, now).await
    }

    pub async fn refresh_once(
        &self,
        options: SessionRefreshOptions,
        now: DateTime<Utc>,
    ) -> Result<SessionHandle> {
        // Single-flight: the grant JWT is consumed by rotation, so a second
        // concurrent refresh would race the winner with an already-spent JWT.
        // Losers return the still-valid current handle; the winner installs
        // the rotated grant into the shared state for everyone.
        let _in_flight = {
            let mut gate = self.gate_lock();
            if gate.in_flight {
                drop(gate);
                return self.current_handle().ok_or_else(no_active_grant);
            }
            gate.in_flight = true;
            RefreshInFlightGuard(Arc::clone(&self.refresh_gate))
        };

        let current = self.current_state().ok_or_else(no_active_grant)?;
        if refresh_decision(Some(&current.refresh_state()), now) == RefreshDecision::GrantExpired {
            return Err(protocol("session grant is expired"));
        }

        let (request, expected_dpop_jkt) = refresh_request(&current, options)?;
        let outcome = self
            .transport
            .refresh_session_grant(request.clone())
            .await?;
        let state =
            state_from_refresh_outcome(&current, &request, &expected_dpop_jkt, outcome, now)?;
        let handle = state.handle();
        *self.state_lock() = Some(state);
        self.gate_lock().last_success_at = Some(now);
        Ok(handle)
    }
}

fn refresh_request(
    current: &SessionGrantState,
    options: SessionRefreshOptions,
) -> Result<(SessionGrantRefreshRequestBody, String)> {
    let request = required(options.request, "session refresh request is required")?;
    let expected_dpop_jkt = required(
        options.expected_dpop_jkt,
        "session refresh DPoP key thumbprint is required",
    )?;

    if current.grant_jwt.trim().is_empty() {
        return Err(protocol("active session grant JWT is empty"));
    }
    let (grant_jwt, audience) = match &request {
        SessionGrantRefreshRequestBody::Human(request) => {
            if current.device_id.as_ref() != Some(&request.device_id) {
                return Err(protocol("session refresh device changed"));
            }
            (request.grant_jwt.as_str(), request.audience_id.as_ref())
        }
        SessionGrantRefreshRequestBody::Agent(request) => {
            if current.device_id.is_some()
                || request.principal_id != current.account_id.principal_id
            {
                return Err(protocol("session refresh Agent holder changed"));
            }
            (request.grant_jwt.as_str(), request.audience_id.as_ref())
        }
    };
    if grant_jwt != current.grant_jwt {
        return Err(protocol("session refresh predecessor JWT changed"));
    }
    if audience != Some(&current.audience_id) {
        return Err(protocol("session refresh audience changed"));
    }
    if let Some(current_dpop_jkt) = current.dpop_jkt.as_deref()
        && current_dpop_jkt != expected_dpop_jkt
    {
        return Err(protocol("session refresh DPoP key changed"));
    }

    request
        .validate()
        .map_err(|error| protocol(error.to_string()))?;
    Ok((request, expected_dpop_jkt))
}

fn state_from_issue_outcome(
    request: &SessionGrantRequestBody,
    outcome: SessionGrantOutcome,
    now: DateTime<Utc>,
) -> Result<SessionGrantState> {
    if outcome.session_grant.trim().is_empty() {
        return Err(protocol("issued session grant JWT is empty"));
    }
    if outcome.expires_at <= now {
        return Err(protocol("issued session grant is expired"));
    }
    let (principal_id, device_id, request_audience) = match request {
        SessionGrantRequestBody::Human(request) => (
            &request.principal_id,
            Some(&request.device_id),
            &request.audience_id,
        ),
        SessionGrantRequestBody::Recovery(request) => (
            &request.principal_id,
            Some(&request.device_id),
            &request.audience_id,
        ),
        SessionGrantRequestBody::Agent(request) => {
            (&request.principal_id, None, &request.proof.audience_id)
        }
    };
    if &outcome.account_id.principal_id != principal_id {
        return Err(protocol("issued session grant principal changed"));
    }
    if outcome.device_id.as_ref() != device_id {
        return Err(protocol("issued session grant device changed"));
    }
    let audience = outcome.audience_id;
    if &audience != request_audience {
        return Err(protocol("issued session grant audience changed"));
    }
    if outcome.account_id.station_id != audience {
        return Err(protocol("issued session grant Station changed"));
    }
    let grant_id = outcome.session_grant_id;
    let dpop_jkt = outcome.session_public_key.thumbprint_sha256()?;
    let session_public_key = outcome.session_public_key.into_string();

    Ok(SessionGrantState {
        account_id: outcome.account_id,
        device_id: outcome.device_id,
        grant_id,
        grant_jwt: outcome.session_grant,
        expires_at: outcome.expires_at,
        audience_id: audience,
        granted_scope: outcome.granted_scope,
        session_public_key: Some(session_public_key),
        dpop_jkt: Some(dpop_jkt),
    })
}

fn state_from_refresh_outcome(
    current: &SessionGrantState,
    request: &SessionGrantRefreshRequestBody,
    expected_dpop_jkt: &str,
    outcome: SessionGrantOutcome,
    now: DateTime<Utc>,
) -> Result<SessionGrantState> {
    if outcome.session_grant.trim().is_empty() {
        return Err(protocol("refreshed session grant JWT is empty"));
    }
    if outcome.expires_at <= now {
        return Err(protocol("refreshed session grant is expired"));
    }
    if outcome.audience_id != current.audience_id {
        return Err(protocol("refreshed session grant audience changed"));
    }
    if outcome.previous_session_grant_id.as_ref() != Some(&current.grant_id) {
        return Err(protocol("refreshed session grant chain changed"));
    }
    if outcome.account_id != current.account_id {
        return Err(protocol("refreshed session grant AccountId changed"));
    }
    // `sync/service-http-binding.md` requires the refresh successor to keep
    // subject/scope/audience/cnf.jkt, and neither refresh request branch carries
    // a requested scope, so any delta - widening or narrowing - is an unrequested
    // server-side rewrite. A runtime that needs a different scope obtains a new
    // session instead (`agent_session_scope_refresh_required`).
    if outcome.granted_scope != current.granted_scope {
        return Err(protocol("refreshed session grant scope changed"));
    }
    if outcome.session_grant_id == current.grant_id {
        return Err(protocol("refreshed session grant id was replayed"));
    }
    let outcome_dpop_jkt = outcome.session_public_key.thumbprint_sha256()?;
    if outcome_dpop_jkt != expected_dpop_jkt {
        return Err(protocol("refreshed session grant DPoP key changed"));
    }
    let request_audience = match request {
        SessionGrantRefreshRequestBody::Human(request) => {
            if current.device_id.as_ref() != Some(&request.device_id) {
                return Err(protocol(
                    "refreshed session grant device mismatched request",
                ));
            }
            request.audience_id.as_ref()
        }
        SessionGrantRefreshRequestBody::Agent(request) => {
            if current.device_id.is_some()
                || request.principal_id != current.account_id.principal_id
            {
                return Err(protocol(
                    "refreshed session grant Agent holder mismatched request",
                ));
            }
            request.audience_id.as_ref()
        }
    };
    if request_audience != Some(&outcome.audience_id) {
        return Err(protocol(
            "refreshed session grant audience mismatched request",
        ));
    }
    // Human successors echo their bound device; Agent successors omit one.
    if outcome.device_id.as_ref() != current.device_id.as_ref() {
        return Err(protocol("refreshed session grant device changed"));
    }

    Ok(SessionGrantState {
        account_id: outcome.account_id,
        device_id: outcome.device_id,
        grant_id: outcome.session_grant_id,
        grant_jwt: outcome.session_grant,
        expires_at: outcome.expires_at,
        audience_id: outcome.audience_id,
        granted_scope: outcome.granted_scope,
        session_public_key: Some(outcome.session_public_key.into_string()),
        dpop_jkt: Some(outcome_dpop_jkt),
    })
}

fn required<T>(value: Option<T>, message: &str) -> Result<T> {
    value.ok_or_else(|| protocol(message))
}

fn no_active_grant() -> Error {
    protocol("no active session grant")
}

fn protocol(message: impl Into<String>) -> Error {
    Error::Protocol(message.into())
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    use arkret_models_collaboration::session_grant_bodies::{
        AgentSessionGrantRefreshRequest, AgentSessionRefreshProofContext,
        UnsignedAgentSessionRefreshProof,
    };
    use arkret_models_collaboration::session_grants::{
        SessionGrantAgentScopeRequest, SessionGrantDpopBindingProof,
    };
    use arkret_wire::{Base64UrlString, DidUrl, Hash, RealmId};
    use chrono::Duration;

    use super::*;
    use crate::session::AgentKeyProofLogin;

    #[derive(Clone, Default)]
    struct MockSessionTransport {
        issue_requests: Arc<Mutex<Vec<SessionGrantRequestBody>>>,
        refresh_requests: Arc<Mutex<Vec<SessionGrantRefreshRequestBody>>>,
        issue_responses: Arc<Mutex<VecDeque<Result<SessionGrantOutcome>>>>,
        refresh_responses: Arc<Mutex<VecDeque<Result<SessionGrantOutcome>>>>,
    }

    impl MockSessionTransport {
        fn with_issue_responses(responses: Vec<Result<SessionGrantOutcome>>) -> Self {
            Self {
                issue_responses: Arc::new(Mutex::new(VecDeque::from(responses))),
                ..Self::default()
            }
        }

        fn with_refresh_responses(responses: Vec<Result<SessionGrantOutcome>>) -> Self {
            Self {
                refresh_responses: Arc::new(Mutex::new(VecDeque::from(responses))),
                ..Self::default()
            }
        }

        fn issue_requests(&self) -> Vec<SessionGrantRequestBody> {
            self.issue_requests.lock().unwrap().clone()
        }

        fn refresh_requests(&self) -> Vec<SessionGrantRefreshRequestBody> {
            self.refresh_requests.lock().unwrap().clone()
        }
    }

    impl SessionGrantTransport for MockSessionTransport {
        fn issue_session_grant<'a>(
            &'a self,
            request: SessionGrantRequestBody,
        ) -> BoxSessionFuture<'a, SessionGrantOutcome> {
            self.issue_requests.lock().unwrap().push(request);
            let response = self.issue_responses.lock().unwrap().pop_front().unwrap();
            Box::pin(async move { response })
        }

        fn refresh_session_grant<'a>(
            &'a self,
            request: SessionGrantRefreshRequestBody,
        ) -> BoxSessionFuture<'a, SessionGrantOutcome> {
            self.refresh_requests.lock().unwrap().push(request);
            let response = self.refresh_responses.lock().unwrap().pop_front().unwrap();
            Box::pin(async move { response })
        }
    }

    fn now() -> DateTime<Utc> {
        "2026-07-08T00:00:00.000Z".parse().unwrap()
    }

    fn agent_key_authorization_ref() -> arkret_wire::EventId {
        arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [2; 32])
    }

    fn principal_id() -> DidCoreId {
        DidCoreId::new("ak:did_core:webvh:z6mkfixture:alice.example").unwrap()
    }

    fn other_principal_id() -> DidCoreId {
        DidCoreId::new("ak:did_core:webvh:z6mkfixture:bob.example").unwrap()
    }

    fn device_id() -> DeviceId {
        DeviceId::new("ak:device:01904100-0000-7000-8000-000000000001").unwrap()
    }

    fn other_device_id() -> DeviceId {
        DeviceId::new("ak:device:01904100-0000-7000-8000-000000000002").unwrap()
    }

    fn grant_id(n: u64) -> SessionGrantId {
        let mut digest = [0_u8; 32];
        digest[24..].copy_from_slice(&n.to_be_bytes());
        SessionGrantId::from_issuance_digest(digest)
    }

    fn digest() -> Hash {
        Hash::new("sha256:0000000000000000000000000000000000000000000000000000000000000000")
            .unwrap()
    }

    fn audience() -> DidCoreId {
        DidCoreId::new("ak:did_core:webvh:z6mkfixture:service.example").unwrap()
    }

    /// The single grant-binding public JWK every session fixture speaks for.
    /// Per `sync/api-conventions.md` §3.3 the grant's `cnf.jkt` is this key's
    /// RFC 7638 thumbprint and `session_public_key` is this very JWK, so
    /// fixtures derive both from one key instead of asserting stand-in
    /// constants that no production path could ever produce.
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

    fn agent_login() -> LoginKind {
        LoginKind::AgentKeyProof(AgentKeyProofLogin {
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
                proof_jwt: "agent-dpop-proof".to_owned(),
            },
            verification_method: DidUrl::new("did:webvh:z6mkfixture:agent.example#runtime-key-1")
                .unwrap(),
            challenge: "AAECAwQFBgcICQoLDA0ODw".to_owned(),
            audience_id: audience(),
            issued_at: now(),
            expires_at: now() + Duration::minutes(5),
            signature: "agent-signature".to_owned(),
        })
    }

    fn issue_outcome(
        token: &str,
        grant: SessionGrantId,
        principal_id: DidCoreId,
        device_id: Option<DeviceId>,
    ) -> SessionGrantOutcome {
        SessionGrantOutcome {
            account_id: AccountId::new(principal_id, audience()),
            device_id,
            session_grant: token.to_owned(),
            expires_at: now() + Duration::hours(1),
            session_grant_id: grant,
            session_public_key: session_public_jwk(),
            audience_id: audience(),
            granted_scope: vec!["ak.self.events.stream.subscribe.v1".to_owned()],
            previous_session_grant_id: None,
        }
    }

    fn active_state() -> SessionGrantState {
        SessionGrantState {
            account_id: AccountId::new(principal_id(), audience()),
            device_id: None,
            grant_id: grant_id(1),
            grant_jwt: "grant-1".to_owned(),
            expires_at: now() + Duration::minutes(20),
            audience_id: audience(),
            granted_scope: vec!["ak.self.events.stream.subscribe.v1".to_owned()],
            session_public_key: Some(session_public_jwk().into_string()),
            dpop_jkt: Some(session_dpop_jkt()),
        }
    }

    #[test]
    fn session_credentials_are_redacted_from_debug_output() {
        let state = active_state();
        let state_debug = format!("{state:?}");
        assert!(state_debug.contains("[REDACTED]"));
        assert!(!state_debug.contains(&state.grant_jwt));

        let handle = state.handle();
        let handle_debug = format!("{handle:?}");
        assert!(handle_debug.contains("[REDACTED]"));
        assert!(!handle_debug.contains(&handle.access_token));
    }

    fn refresh_options_for(grant_jwt: &str) -> SessionRefreshOptions {
        let proof = UnsignedAgentSessionRefreshProof {
            context: AgentSessionRefreshProofContext::V1,
            request_canonical_digest: digest(),
            audience_id: audience(),
            issued_at: now(),
            expires_at: now() + Duration::minutes(5),
            verification_method: DidUrl::new("did:webvh:z6mkfixture:agent.example#runtime-key-1")
                .unwrap(),
        }
        .attach_signature(
            Base64UrlString::new(arkret_canonical::base64url_encode([0_u8; 64])).unwrap(),
        )
        .unwrap();
        SessionRefreshOptions {
            request: Some(SessionGrantRefreshRequestBody::Agent(
                AgentSessionGrantRefreshRequest {
                    grant_jwt: grant_jwt.to_owned(),
                    audience_id: Some(audience()),
                    principal_id: principal_id(),
                    agent_key_authorization_ref: agent_key_authorization_ref(),
                    agent_session_refresh_proof: proof,
                },
            )),
            expected_dpop_jkt: Some(session_dpop_jkt()),
        }
    }

    fn refresh_options() -> SessionRefreshOptions {
        refresh_options_for("grant-1")
    }

    fn refresh_outcome(token: &str, grant: SessionGrantId) -> SessionGrantOutcome {
        SessionGrantOutcome {
            session_grant_id: grant,
            account_id: AccountId::new(principal_id(), audience()),
            device_id: None,
            session_grant: token.to_owned(),
            session_public_key: session_public_jwk(),
            expires_at: now() + Duration::hours(1),
            audience_id: audience(),
            granted_scope: vec!["ak.self.events.stream.subscribe.v1".to_owned()],
            previous_session_grant_id: Some(grant_id(1)),
        }
    }

    #[tokio::test]
    async fn engine_exchanges_closed_agent_login() {
        let transport = MockSessionTransport::with_issue_responses(vec![Ok(issue_outcome(
            "grant-agent",
            grant_id(10),
            principal_id(),
            None,
        ))]);
        let engine = SessionEngine::new(transport.clone());

        let handle = engine.login(agent_login(), now()).await.unwrap();

        assert_eq!(handle.access_token, "grant-agent");
        let requests = transport.issue_requests();
        assert_eq!(requests.len(), 1);
        assert!(matches!(requests[0], SessionGrantRequestBody::Agent(_)));
    }

    #[test]
    fn recovery_issue_keeps_device_binding() {
        let wire = serde_json::json!({
            "credential_class": "recovery_session",
            "request_id": "ak:request:01970000-0000-7000-8000-000000000021",
            "principal_id": principal_id(),
            "device_id": device_id(),
            "audience_id": audience(),
        });
        let request: SessionGrantRequestBody = serde_json::from_value(wire.clone()).unwrap();
        assert!(matches!(request, SessionGrantRequestBody::Recovery(_)));
        let state = state_from_issue_outcome(
            &request,
            issue_outcome(
                "grant-recovery",
                grant_id(11),
                principal_id(),
                Some(device_id()),
            ),
            now(),
        )
        .unwrap();
        assert_eq!(state.device_id, Some(device_id()));
    }

    #[test]
    fn retired_pairwise_issue_wire_has_no_branch() {
        let request_id = "ak:request:01970000-0000-7000-8000-000000000021";
        let account_id = AccountId::new(principal_id(), audience());
        let digest = format!("sha256:{}", "0".repeat(64));
        let signature = arkret_canonical::base64url_encode([0u8; 64]);
        let accepted = serde_json::json!({
            "context": "ak.session_grant_accepted_device_possession_proof.v1",
            "purpose": "session_grant_issue",
            "request_id": request_id,
            "account_subject": digest,
            "account_handoff_grant_digest": digest,
            "account_id": account_id,
            "device_id": device_id(),
            "audience_id": audience(),
            "holder_jkt": "A".repeat(43),
            "session_intent_digest": digest,
            "issued_at": "2026-07-08T00:00:00.000Z",
            "expires_at": "2026-07-08T00:05:00.000Z",
            "verification_method": "did:webvh:z6mkfixture:agent.example#runtime-key-1",
            "signature": signature,
        });
        let pairwise = serde_json::json!({
            "request_id": request_id,
            "principal_id": principal_id(),
            "device_id": device_id(),
            "audience_id": audience(),
            "accepted_device_possession_proof": accepted,
            "pairwise_endpoint_possession_proof": {
                "context": "ak.session_grant_pairwise_endpoint_possession_proof.v1",
                "request_id": request_id,
                "account_id": account_id,
                "realm_id": "ak:realm:AfF-hFqRoMbajXkPapH-xaq0xwK-UKt2ph2zTs9JZRAO",
                "actor_id": arkret_wire::ActorId::account(account_id),
                "audience_id": audience(),
                "holder_jkt": "A".repeat(43),
                "session_intent_digest": digest,
                "issued_at": "2026-07-08T00:00:00.000Z",
                "expires_at": "2026-07-08T00:05:00.000Z",
                "verification_method": "did:webvh:z6mkfixture:agent.example#runtime-key-1",
                "signature": signature,
            }
        });
        assert!(serde_json::from_value::<SessionGrantRequestBody>(pairwise).is_err());
    }

    #[tokio::test]
    async fn authored_request_uses_the_same_issue_validation_path() {
        let transport = MockSessionTransport::with_issue_responses(vec![Ok(issue_outcome(
            "grant-authored",
            grant_id(14),
            principal_id(),
            None,
        ))]);
        let engine = SessionEngine::new(transport.clone());
        let request = agent_login().into_session_grant_request().unwrap();

        let handle = engine.login_request(request, now()).await.unwrap();

        assert_eq!(handle.access_token, "grant-authored");
        assert_eq!(transport.issue_requests().len(), 1);
        assert_eq!(engine.current_state().unwrap().grant_id, grant_id(14));
    }

    #[tokio::test]
    async fn engine_rejects_unsafe_issue_outcomes_without_state() {
        let cases = vec![
            issue_outcome("", grant_id(20), principal_id(), None),
            SessionGrantOutcome {
                expires_at: now() - Duration::seconds(1),
                ..issue_outcome("grant-expired", grant_id(21), principal_id(), None)
            },
            issue_outcome(
                "grant-wrong-principal",
                grant_id(22),
                other_principal_id(),
                None,
            ),
            issue_outcome(
                "grant-wrong-device",
                grant_id(23),
                principal_id(),
                Some(other_device_id()),
            ),
        ];

        for outcome in cases {
            let transport = MockSessionTransport::with_issue_responses(vec![Ok(outcome)]);
            let engine = SessionEngine::new(transport);

            let result = engine.login(agent_login(), now()).await;

            assert!(result.is_err());
            assert!(engine.current_state().is_none());
        }
    }

    #[tokio::test]
    async fn refresh_no_grant_or_expired_grant_does_not_call_transport() {
        let transport = MockSessionTransport::default();
        let engine = SessionEngine::new(transport.clone());

        assert!(engine.refresh_once(refresh_options(), now()).await.is_err());
        assert!(transport.refresh_requests().is_empty());

        let mut expired = active_state();
        expired.expires_at = now() - Duration::seconds(1);
        let engine = SessionEngine::with_state(transport.clone(), expired);

        assert!(engine.refresh_once(refresh_options(), now()).await.is_err());
        assert!(transport.refresh_requests().is_empty());
    }

    #[tokio::test]
    async fn refresh_rejects_missing_required_inputs_without_transport() {
        let cases = vec![
            SessionRefreshOptions {
                request: None,
                ..refresh_options()
            },
            SessionRefreshOptions {
                expected_dpop_jkt: None,
                ..refresh_options()
            },
        ];

        for options in cases {
            let transport = MockSessionTransport::default();
            let engine = SessionEngine::with_state(transport.clone(), active_state());

            let result = engine.refresh_once(options, now()).await;

            assert!(result.is_err());
            assert!(transport.refresh_requests().is_empty());
        }
    }

    #[tokio::test]
    async fn refresh_sends_old_grant_and_replaces_state() {
        let transport = MockSessionTransport::with_refresh_responses(vec![Ok(refresh_outcome(
            "grant-2",
            grant_id(2),
        ))]);
        let engine = SessionEngine::with_state(transport.clone(), active_state());

        let handle = engine.refresh_once(refresh_options(), now()).await.unwrap();

        assert_eq!(handle.access_token, "grant-2");
        let requests = transport.refresh_requests();
        assert_eq!(requests.len(), 1);
        let SessionGrantRefreshRequestBody::Agent(request) = &requests[0] else {
            panic!("test authors the Agent refresh branch");
        };
        assert_eq!(request.grant_jwt, "grant-1");
        assert_eq!(request.audience_id.as_ref(), Some(&audience()));
        let state = engine.current_state().unwrap();
        assert_eq!(state.grant_id, grant_id(2));
        assert_eq!(state.dpop_jkt, Some(session_dpop_jkt()));
    }

    #[tokio::test]
    async fn refresh_rejects_changed_outcomes_without_replacing_state() {
        let mut wrong_audience = refresh_outcome("grant-wrong-audience", grant_id(30));
        wrong_audience.audience_id =
            DidCoreId::new("ak:did_core:webvh:z6mkfixture:other-service.example").unwrap();

        let mut wrong_previous = refresh_outcome("grant-wrong-previous", grant_id(31));
        wrong_previous.previous_session_grant_id = Some(grant_id(99));

        let replayed = refresh_outcome("grant-replayed", grant_id(1));

        let mut expired = refresh_outcome("grant-expired", grant_id(32));
        expired.expires_at = now() - Duration::seconds(1);

        let mut wrong_dpop = refresh_outcome("grant-wrong-dpop", grant_id(33));
        wrong_dpop.session_public_key = arkret_models_identity::CanonicalSessionPublicJwk::new(
            r#"{"crv":"Ed25519","kty":"OKP","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE"}"#,
        )
        .unwrap();

        let mut widened_scope = refresh_outcome("grant-widened-scope", grant_id(34));
        widened_scope.granted_scope = vec![
            "ak.self.events.stream.subscribe.v1".to_owned(),
            "ak.self.events.command.submit.v1".to_owned(),
        ];

        let mut narrowed_scope = refresh_outcome("grant-narrowed-scope", grant_id(35));
        narrowed_scope.granted_scope = Vec::new();

        let mut substituted_scope = refresh_outcome("grant-substituted-scope", grant_id(36));
        substituted_scope.granted_scope = vec!["ak.self.events.command.submit.v1".to_owned()];

        let mut wrong_device = refresh_outcome("grant-wrong-device", grant_id(37));
        wrong_device.device_id = Some(other_device_id());

        for (outcome, expected_error) in [
            (wrong_audience, "refreshed session grant audience changed"),
            (wrong_previous, "refreshed session grant chain changed"),
            (replayed, "refreshed session grant id was replayed"),
            (expired, "refreshed session grant is expired"),
            (wrong_dpop, "refreshed session grant DPoP key changed"),
            (widened_scope, "refreshed session grant scope changed"),
            (narrowed_scope, "refreshed session grant scope changed"),
            (substituted_scope, "refreshed session grant scope changed"),
            (wrong_device, "refreshed session grant device changed"),
        ] {
            let transport = MockSessionTransport::with_refresh_responses(vec![Ok(outcome)]);
            let engine = SessionEngine::with_state(transport, active_state());

            let error = engine
                .refresh_once(refresh_options(), now())
                .await
                .expect_err("a changed successor is rejected");

            assert!(
                error.to_string().contains(expected_error),
                "expected `{expected_error}`, got `{error}`"
            );
            assert_eq!(engine.current_state().unwrap().grant_jwt, "grant-1");
        }
    }

    #[tokio::test]
    async fn refresh_transport_errors_do_not_replace_state() {
        for label in ["revoked", "paused", "expired"] {
            let transport = MockSessionTransport::with_refresh_responses(vec![Err(
                Error::Protocol(label.to_owned()),
            )]);
            let engine = SessionEngine::with_state(transport.clone(), active_state());

            let result = engine.refresh_once(refresh_options(), now()).await;

            assert!(result.is_err());
            assert_eq!(engine.current_state().unwrap().grant_jwt, "grant-1");
            assert_eq!(transport.refresh_requests().len(), 1);
        }
    }

    /// Refresh transport whose future stays pending until released, so a test
    /// can hold a refresh in flight while a second caller races it.
    struct GatedRefreshTransport {
        started: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Notify>,
        refresh_calls: Arc<Mutex<usize>>,
        outcome: SessionGrantOutcome,
    }

    impl SessionGrantTransport for GatedRefreshTransport {
        fn issue_session_grant<'a>(
            &'a self,
            _request: SessionGrantRequestBody,
        ) -> BoxSessionFuture<'a, SessionGrantOutcome> {
            Box::pin(async move { Err(Error::Protocol("issue not expected".to_owned())) })
        }

        fn refresh_session_grant<'a>(
            &'a self,
            _request: SessionGrantRefreshRequestBody,
        ) -> BoxSessionFuture<'a, SessionGrantOutcome> {
            *self.refresh_calls.lock().unwrap() += 1;
            let started = Arc::clone(&self.started);
            let release = Arc::clone(&self.release);
            let outcome = self.outcome.clone();
            Box::pin(async move {
                started.notify_one();
                release.notified().await;
                Ok(outcome)
            })
        }
    }

    #[tokio::test]
    async fn concurrent_refresh_is_single_flight() {
        let started = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let refresh_calls = Arc::new(Mutex::new(0usize));
        let transport = GatedRefreshTransport {
            started: Arc::clone(&started),
            release: Arc::clone(&release),
            refresh_calls: Arc::clone(&refresh_calls),
            outcome: refresh_outcome("grant-2", grant_id(2)),
        };
        let engine = Arc::new(SessionEngine::with_state(transport, active_state()));

        let winner = {
            let engine = Arc::clone(&engine);
            tokio::spawn(async move { engine.refresh_once(refresh_options(), now()).await })
        };
        // Wait until the winner's transport call is in flight...
        started.notified().await;
        // ...then race a second refresh: it must NOT fire a transport call and
        // returns the still-valid current handle instead.
        let loser = engine.refresh_once(refresh_options(), now()).await.unwrap();
        assert_eq!(loser.access_token, "grant-1");
        assert_eq!(*refresh_calls.lock().unwrap(), 1);

        release.notify_one();
        let winner = winner.await.unwrap().unwrap();
        assert_eq!(winner.access_token, "grant-2");
        assert_eq!(*refresh_calls.lock().unwrap(), 1);
        // The winner installed the rotated grant for everyone.
        assert_eq!(engine.current_state().unwrap().grant_jwt, "grant-2");
    }

    #[tokio::test]
    async fn cancelled_refresh_releases_single_flight_without_replacing_state() {
        let started = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let refresh_calls = Arc::new(Mutex::new(0usize));
        let transport = GatedRefreshTransport {
            started: Arc::clone(&started),
            release: Arc::clone(&release),
            refresh_calls: Arc::clone(&refresh_calls),
            outcome: refresh_outcome("grant-2", grant_id(2)),
        };
        let engine = Arc::new(SessionEngine::with_state(transport, active_state()));

        let cancelled = {
            let engine = Arc::clone(&engine);
            tokio::spawn(async move { engine.refresh_once(refresh_options(), now()).await })
        };
        started.notified().await;
        cancelled.abort();
        assert!(cancelled.await.unwrap_err().is_cancelled());
        assert_eq!(engine.current_state().unwrap().grant_jwt, "grant-1");

        let retry = {
            let engine = Arc::clone(&engine);
            tokio::spawn(async move { engine.refresh_once(refresh_options(), now()).await })
        };
        started.notified().await;
        release.notify_one();
        assert_eq!(retry.await.unwrap().unwrap().access_token, "grant-2");
        assert_eq!(*refresh_calls.lock().unwrap(), 2);
    }

    #[tokio::test]
    async fn refresh_if_due_honors_success_cooldown() {
        // A rotated grant that is still short-lived enough to be immediately
        // `Due` again (the refresh-treadmill shape).
        let mut short_lived = refresh_outcome("grant-2", grant_id(2));
        short_lived.expires_at = now() + Duration::seconds(30);
        let mut after_cooldown = refresh_outcome("grant-3", grant_id(3));
        after_cooldown.previous_session_grant_id = Some(grant_id(2));
        after_cooldown.expires_at = now() + Duration::seconds(30);
        let transport =
            MockSessionTransport::with_refresh_responses(vec![Ok(short_lived), Ok(after_cooldown)]);
        let mut due_state = active_state();
        due_state.expires_at = now() + Duration::seconds(30);
        let engine = SessionEngine::with_state(transport.clone(), due_state);

        // First call rotates.
        let handle = engine
            .refresh_if_due(refresh_options(), now())
            .await
            .unwrap();
        assert_eq!(handle.access_token, "grant-2");
        assert_eq!(transport.refresh_requests().len(), 1);

        // Still Due, but within the cooldown: no second transport call.
        let handle = engine
            .refresh_if_due(refresh_options(), now() + Duration::seconds(1))
            .await
            .unwrap();
        assert_eq!(handle.access_token, "grant-2");
        assert_eq!(transport.refresh_requests().len(), 1);

        // Past the cooldown the due refresh fires again.
        let handle = engine
            .refresh_if_due(
                refresh_options_for("grant-2"),
                now() + Duration::seconds(REFRESH_SUCCESS_COOLDOWN_SECS),
            )
            .await
            .unwrap();
        assert_eq!(handle.access_token, "grant-3");
        assert_eq!(transport.refresh_requests().len(), 2);
    }
}
