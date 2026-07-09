use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use chrono::{DateTime, Utc};
use arkret_core::{
    DeviceId, Did, Error, GrantId, Result, SessionGrantOutcome, SessionGrantRefreshOutcome,
    SessionGrantRefreshProof, SessionGrantRefreshRequestBody, SessionGrantRequestBody,
};

use super::SessionHandle;
use super::login::LoginKind;
use super::refresh::{RefreshDecision, SessionGrantRefreshState, refresh_decision};

#[cfg(not(target_arch = "wasm32"))]
pub type BoxSessionFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

#[cfg(target_arch = "wasm32")]
pub type BoxSessionFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + 'a>>;

pub trait SessionGrantTransport {
    fn issue_session_grant<'a>(
        &'a self,
        request: SessionGrantRequestBody,
    ) -> BoxSessionFuture<'a, SessionGrantOutcome>;

    fn refresh_session_grant<'a>(
        &'a self,
        request: SessionGrantRefreshRequestBody,
    ) -> BoxSessionFuture<'a, SessionGrantRefreshOutcome>;
}

impl SessionGrantTransport for arkret_http_client::Client {
    fn issue_session_grant<'a>(
        &'a self,
        request: SessionGrantRequestBody,
    ) -> BoxSessionFuture<'a, SessionGrantOutcome> {
        Box::pin(async move { self.auth_issue_session_grant(&request).await })
    }

    fn refresh_session_grant<'a>(
        &'a self,
        request: SessionGrantRefreshRequestBody,
    ) -> BoxSessionFuture<'a, SessionGrantRefreshOutcome> {
        Box::pin(async move { self.auth_refresh_session_grant(&request).await })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionGrantState {
    pub principal_id: Did,
    pub device_id: Option<DeviceId>,
    pub grant_id: GrantId,
    pub grant_jwt: String,
    pub expires_at: DateTime<Utc>,
    pub audience: String,
    pub granted_scope: Vec<String>,
    pub session_public_key: String,
    pub dpop_jkt: Option<String>,
}

impl SessionGrantState {
    pub fn handle(&self) -> SessionHandle {
        SessionHandle {
            access_token: self.grant_jwt.clone(),
        }
    }

    fn refresh_state(&self) -> SessionGrantRefreshState {
        SessionGrantRefreshState {
            grant_expires_at: Some(self.expires_at),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct SessionRefreshOptions {
    pub audience: Option<String>,
    pub device_id: Option<DeviceId>,
    pub proof: Option<SessionGrantRefreshProof>,
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

    pub fn refresh_decision(&self, now: DateTime<Utc>) -> RefreshDecision {
        let state = self.state_lock();
        let refresh_state = state.as_ref().map(SessionGrantState::refresh_state);
        refresh_decision(refresh_state.as_ref(), now)
    }

    pub async fn login(&self, login: LoginKind, now: DateTime<Utc>) -> Result<SessionHandle> {
        let request = login.into_session_grant_request()?;
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
    let audience = required(options.audience, "session refresh audience is required")?;
    let device_id = required(options.device_id, "session refresh device_id is required")?;
    let proof = required(options.proof, "session refresh proof is required")?;
    let expected_dpop_jkt = required(
        options.expected_dpop_jkt,
        "session refresh DPoP key thumbprint is required",
    )?;

    if current.grant_jwt.trim().is_empty() {
        return Err(protocol("active session grant JWT is empty"));
    }
    if current.audience != audience {
        return Err(protocol("session refresh audience changed"));
    }
    if current.device_id.as_ref() != Some(&device_id) {
        return Err(protocol("session refresh device changed"));
    }
    if let Some(current_dpop_jkt) = current.dpop_jkt.as_deref() {
        if current_dpop_jkt != expected_dpop_jkt {
            return Err(protocol("session refresh DPoP key changed"));
        }
    }

    Ok((
        SessionGrantRefreshRequestBody {
            grant_jwt: current.grant_jwt.clone(),
            audience: Some(audience),
            device_id: Some(device_id),
            proof: Some(proof),
        },
        expected_dpop_jkt,
    ))
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
    if let Some(expected_principal) = request.principal_id.as_ref() {
        if &outcome.principal_id != expected_principal {
            return Err(protocol("issued session grant principal changed"));
        }
    }
    if request.device_id.as_ref() != outcome.device_id.as_ref() {
        return Err(protocol("issued session grant device changed"));
    }
    let audience = required(outcome.audience, "issued session grant audience is missing")?;
    if audience != request.proof.audience {
        return Err(protocol("issued session grant audience changed"));
    }
    let grant_id = required(outcome.grant_id, "issued session grant id is missing")?;
    let session_public_key = required(
        outcome.session_public_key,
        "issued session grant public key is missing",
    )?;
    if session_public_key.trim().is_empty() {
        return Err(protocol("issued session grant public key is empty"));
    }

    Ok(SessionGrantState {
        principal_id: outcome.principal_id,
        device_id: outcome.device_id,
        grant_id,
        grant_jwt: outcome.session_grant,
        expires_at: outcome.expires_at,
        audience,
        granted_scope: outcome.granted_scope,
        session_public_key,
        dpop_jkt: None,
    })
}

fn state_from_refresh_outcome(
    current: &SessionGrantState,
    request: &SessionGrantRefreshRequestBody,
    expected_dpop_jkt: &str,
    outcome: SessionGrantRefreshOutcome,
    now: DateTime<Utc>,
) -> Result<SessionGrantState> {
    if outcome.grant_jwt.trim().is_empty() {
        return Err(protocol("refreshed session grant JWT is empty"));
    }
    if outcome.expires_at <= now {
        return Err(protocol("refreshed session grant is expired"));
    }
    if outcome.audience != current.audience {
        return Err(protocol("refreshed session grant audience changed"));
    }
    if outcome.previous_grant_id != current.grant_id {
        return Err(protocol("refreshed session grant chain changed"));
    }
    if outcome.grant_id == current.grant_id {
        return Err(protocol("refreshed session grant id was replayed"));
    }
    if outcome.session_public_key.trim().is_empty() {
        return Err(protocol("refreshed session grant public key is empty"));
    }
    if outcome.dpop_jkt != expected_dpop_jkt {
        return Err(protocol("refreshed session grant DPoP key changed"));
    }
    if request.audience.as_deref() != Some(outcome.audience.as_str()) {
        return Err(protocol(
            "refreshed session grant audience mismatched request",
        ));
    }
    if request.device_id.as_ref() != current.device_id.as_ref() {
        return Err(protocol(
            "refreshed session grant device mismatched request",
        ));
    }

    Ok(SessionGrantState {
        principal_id: current.principal_id.clone(),
        device_id: current.device_id.clone(),
        grant_id: outcome.grant_id,
        grant_jwt: outcome.grant_jwt,
        expires_at: outcome.expires_at,
        audience: outcome.audience,
        granted_scope: outcome.scopes,
        session_public_key: outcome.session_public_key,
        dpop_jkt: Some(outcome.dpop_jkt),
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

    use chrono::Duration;
    use arkret_core::{
        Hash, SessionGrantDpopBindingProof, SessionGrantProofKind, SessionGrantScopeDetails,
    };
    use serde_json::json;

    use super::*;
    use crate::session::{
        AgentKeyProofLogin, DidProofLogin, HolderProofLogin, OidcLogin, SessionProofFields,
    };

    #[derive(Clone, Default)]
    struct MockSessionTransport {
        issue_requests: Arc<Mutex<Vec<SessionGrantRequestBody>>>,
        refresh_requests: Arc<Mutex<Vec<SessionGrantRefreshRequestBody>>>,
        issue_responses: Arc<Mutex<VecDeque<Result<SessionGrantOutcome>>>>,
        refresh_responses: Arc<Mutex<VecDeque<Result<SessionGrantRefreshOutcome>>>>,
    }

    impl MockSessionTransport {
        fn with_issue_responses(responses: Vec<Result<SessionGrantOutcome>>) -> Self {
            Self {
                issue_responses: Arc::new(Mutex::new(VecDeque::from(responses))),
                ..Self::default()
            }
        }

        fn with_refresh_responses(responses: Vec<Result<SessionGrantRefreshOutcome>>) -> Self {
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
        ) -> BoxSessionFuture<'a, SessionGrantRefreshOutcome> {
            self.refresh_requests.lock().unwrap().push(request);
            let response = self.refresh_responses.lock().unwrap().pop_front().unwrap();
            Box::pin(async move { response })
        }
    }

    fn now() -> DateTime<Utc> {
        "2026-07-08T00:00:00Z".parse().unwrap()
    }

    fn did() -> Did {
        Did::new("did:webvh:z6mkfixture:alice.example").unwrap()
    }

    fn other_did() -> Did {
        Did::new("did:webvh:z6mkfixture:bob.example").unwrap()
    }

    fn device_id() -> DeviceId {
        DeviceId::new("ak:device:01904100-0000-7000-8000-000000000001").unwrap()
    }

    fn other_device_id() -> DeviceId {
        DeviceId::new("ak:device:01904100-0000-7000-8000-000000000002").unwrap()
    }

    fn grant_id(n: u64) -> GrantId {
        GrantId::new(format!("ak:grant:01904100-0000-7000-8000-{n:012}")).unwrap()
    }

    fn digest() -> Hash {
        Hash::new("sha256:0000000000000000000000000000000000000000000000000000000000000000")
            .unwrap()
    }

    fn audience() -> String {
        "did:webvh:z6mkfixture:service.example".to_owned()
    }

    fn proof_fields() -> SessionProofFields {
        SessionProofFields {
            challenge: "session-grant-challenge-0001".to_owned(),
            request_canonical_digest: digest(),
            audience: audience(),
            expires_at: Some(now() + Duration::minutes(5)),
            signature: "proof-signature".to_owned(),
            verification_method: Some("did:webvh:z6mkfixture:alice.example#device-1".to_owned()),
        }
    }

    fn did_login() -> LoginKind {
        LoginKind::DidProof(DidProofLogin {
            principal_id: did(),
            device_id: device_id(),
            requested_scope: vec!["ck.self.events.stream.subscribe".to_owned()],
            dpop_binding_proof: Some(SessionGrantDpopBindingProof {
                proof_jwt: "dpop-proof".to_owned(),
            }),
            applet_delegation: None,
            proof: proof_fields(),
        })
    }

    fn holder_login() -> LoginKind {
        LoginKind::HolderProof(HolderProofLogin {
            principal_id: did(),
            device_id: Some(device_id()),
            requested_scope: vec!["ck.self.account.query.viewer".to_owned()],
            dpop_binding_proof: Some(SessionGrantDpopBindingProof {
                proof_jwt: "holder-dpop-proof".to_owned(),
            }),
            applet_delegation: None,
            proof: proof_fields(),
        })
    }

    fn oidc_login() -> LoginKind {
        LoginKind::Oidc(OidcLogin {
            principal_id: None,
            device_id: Some(device_id()),
            requested_scope: Vec::new(),
            challenge: "oidc-challenge".to_owned(),
            request_canonical_digest: digest(),
            audience: audience(),
            issuer: "https://issuer.example".to_owned(),
            client_id: "client-1".to_owned(),
            redirect_uri: "https://app.example/callback".to_owned(),
            state: "state-1".to_owned(),
            nonce: "nonce-1".to_owned(),
            authorization_code: "code-1".to_owned(),
            code_verifier: "verifier-1".to_owned(),
        })
    }

    fn agent_login() -> LoginKind {
        LoginKind::AgentKeyProof(AgentKeyProofLogin {
            principal_id: did(),
            requested_scope: vec!["ck.self.events.stream.subscribe".to_owned()],
            agent_key_authorization_ref: "ak:event:01904100-0000-7000-8000-000000000002".to_owned(),
            agent_scope_request: json!({"kind": "realm"}),
            dpop_binding_proof: SessionGrantDpopBindingProof {
                proof_jwt: "agent-dpop-proof".to_owned(),
            },
            verification_method: "did:webvh:z6mkfixture:agent.example#runtime-key-1".to_owned(),
            challenge: "agent-challenge".to_owned(),
            nonce: "agent-nonce".to_owned(),
            audience: audience(),
            expires_at: now() + Duration::minutes(5),
            signature: "agent-signature".to_owned(),
        })
    }

    fn issue_outcome(
        token: &str,
        grant: GrantId,
        principal_id: Did,
        device_id: Option<DeviceId>,
    ) -> SessionGrantOutcome {
        SessionGrantOutcome {
            principal_id,
            device_id,
            session_grant: token.to_owned(),
            expires_at: now() + Duration::hours(1),
            grant_id: Some(grant),
            session_public_key: Some("session-public-key".to_owned()),
            audience: Some(audience()),
            granted_scope: vec!["ck.self.events.stream.subscribe".to_owned()],
            scope_details: None::<SessionGrantScopeDetails>,
        }
    }

    fn active_state() -> SessionGrantState {
        SessionGrantState {
            principal_id: did(),
            device_id: Some(device_id()),
            grant_id: grant_id(1),
            grant_jwt: "grant-1".to_owned(),
            expires_at: now() + Duration::minutes(20),
            audience: audience(),
            granted_scope: vec!["ck.self.events.stream.subscribe".to_owned()],
            session_public_key: "session-public-key".to_owned(),
            dpop_jkt: Some("jkt-1".to_owned()),
        }
    }

    fn refresh_proof() -> SessionGrantRefreshProof {
        SessionGrantRefreshProof {
            proof_kind: Some(SessionGrantProofKind::DidBoundSignature),
            challenge: Some("refresh-challenge".to_owned()),
            request_canonical_digest: Some(digest()),
            audience: Some(audience()),
            issued_at: Some(now()),
            expires_at: Some(now() + Duration::minutes(5)),
            signature: Some("refresh-proof-signature".to_owned()),
            verification_method: Some("did:webvh:z6mkfixture:alice.example#device-1".to_owned()),
        }
    }

    fn refresh_options() -> SessionRefreshOptions {
        SessionRefreshOptions {
            audience: Some(audience()),
            device_id: Some(device_id()),
            proof: Some(refresh_proof()),
            expected_dpop_jkt: Some("jkt-1".to_owned()),
        }
    }

    fn refresh_outcome(token: &str, grant: GrantId) -> SessionGrantRefreshOutcome {
        SessionGrantRefreshOutcome {
            grant_id: grant,
            grant_jwt: token.to_owned(),
            session_public_key: "session-public-key".to_owned(),
            expires_at: now() + Duration::hours(1),
            audience: audience(),
            scopes: vec!["ck.self.events.stream.subscribe".to_owned()],
            dpop_jkt: "jkt-1".to_owned(),
            previous_grant_id: grant_id(1),
        }
    }

    #[tokio::test]
    async fn engine_exchanges_all_login_kinds() {
        let transport = MockSessionTransport::with_issue_responses(vec![
            Ok(issue_outcome("grant-agent", grant_id(10), did(), None)),
            Ok(issue_outcome(
                "grant-holder",
                grant_id(11),
                did(),
                Some(device_id()),
            )),
            Ok(issue_outcome(
                "grant-oidc",
                grant_id(12),
                did(),
                Some(device_id()),
            )),
            Ok(issue_outcome(
                "grant-did",
                grant_id(13),
                did(),
                Some(device_id()),
            )),
        ]);
        let engine = SessionEngine::new(transport.clone());

        engine.login(agent_login(), now()).await.unwrap();
        engine.login(holder_login(), now()).await.unwrap();
        engine.login(oidc_login(), now()).await.unwrap();
        let handle = engine.login(did_login(), now()).await.unwrap();

        assert_eq!(handle.access_token, "grant-did");
        let requests = transport.issue_requests();
        assert_eq!(requests.len(), 4);
        assert_eq!(
            requests[0].proof.proof_kind,
            SessionGrantProofKind::AgentKeyProof
        );
        assert_eq!(
            requests[1].proof.proof_kind,
            SessionGrantProofKind::PairedDeviceProof
        );
        assert_eq!(
            requests[2].proof.proof_kind,
            SessionGrantProofKind::OidcCodeExchange
        );
        assert_eq!(
            requests[3].proof.proof_kind,
            SessionGrantProofKind::DidBoundSignature
        );
    }

    #[tokio::test]
    async fn engine_rejects_unsafe_issue_outcomes_without_state() {
        let cases = vec![
            issue_outcome("", grant_id(20), did(), Some(device_id())),
            SessionGrantOutcome {
                expires_at: now() - Duration::seconds(1),
                ..issue_outcome("grant-expired", grant_id(21), did(), Some(device_id()))
            },
            issue_outcome(
                "grant-wrong-principal",
                grant_id(22),
                other_did(),
                Some(device_id()),
            ),
            issue_outcome(
                "grant-wrong-device",
                grant_id(23),
                did(),
                Some(other_device_id()),
            ),
        ];

        for outcome in cases {
            let transport = MockSessionTransport::with_issue_responses(vec![Ok(outcome)]);
            let engine = SessionEngine::new(transport);

            let result = engine.login(did_login(), now()).await;

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
                audience: None,
                ..refresh_options()
            },
            SessionRefreshOptions {
                device_id: None,
                ..refresh_options()
            },
            SessionRefreshOptions {
                proof: None,
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
        assert_eq!(requests[0].grant_jwt, "grant-1");
        assert_eq!(requests[0].audience.as_deref(), Some(audience().as_str()));
        let state = engine.current_state().unwrap();
        assert_eq!(state.grant_id, grant_id(2));
        assert_eq!(state.dpop_jkt.as_deref(), Some("jkt-1"));
    }

    #[tokio::test]
    async fn refresh_rejects_changed_outcomes_without_replacing_state() {
        let mut wrong_audience = refresh_outcome("grant-wrong-audience", grant_id(30));
        wrong_audience.audience = "did:webvh:z6mkfixture:other-service.example".to_owned();

        let mut wrong_previous = refresh_outcome("grant-wrong-previous", grant_id(31));
        wrong_previous.previous_grant_id = grant_id(99);

        let replayed = refresh_outcome("grant-replayed", grant_id(1));

        let mut expired = refresh_outcome("grant-expired", grant_id(32));
        expired.expires_at = now() - Duration::seconds(1);

        let mut wrong_dpop = refresh_outcome("grant-wrong-dpop", grant_id(33));
        wrong_dpop.dpop_jkt = "jkt-other".to_owned();

        for outcome in [
            wrong_audience,
            wrong_previous,
            replayed,
            expired,
            wrong_dpop,
        ] {
            let transport = MockSessionTransport::with_refresh_responses(vec![Ok(outcome)]);
            let engine = SessionEngine::with_state(transport, active_state());

            let result = engine.refresh_once(refresh_options(), now()).await;

            assert!(result.is_err());
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
        outcome: SessionGrantRefreshOutcome,
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
        ) -> BoxSessionFuture<'a, SessionGrantRefreshOutcome> {
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
    async fn refresh_if_due_honors_success_cooldown() {
        // A rotated grant that is still short-lived enough to be immediately
        // `Due` again (the refresh-treadmill shape).
        let mut short_lived = refresh_outcome("grant-2", grant_id(2));
        short_lived.expires_at = now() + Duration::minutes(10);
        let mut after_cooldown = refresh_outcome("grant-3", grant_id(3));
        after_cooldown.previous_grant_id = grant_id(2);
        after_cooldown.expires_at = now() + Duration::minutes(10);
        let transport =
            MockSessionTransport::with_refresh_responses(vec![Ok(short_lived), Ok(after_cooldown)]);
        let engine = SessionEngine::with_state(transport.clone(), active_state());

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
                refresh_options(),
                now() + Duration::seconds(REFRESH_SUCCESS_COOLDOWN_SECS),
            )
            .await
            .unwrap();
        assert_eq!(handle.access_token, "grant-3");
        assert_eq!(transport.refresh_requests().len(), 2);
    }
}
