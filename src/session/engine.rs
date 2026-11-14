use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use arkret_models_collaboration::session_grants::{
    SessionGrantRefreshRequestBody, SessionGrantRequestBody, SessionGrantResponseBody,
};
#[cfg(test)]
use arkret_wire::SessionGrantId;
use arkret_wire::{AccountId, DeviceId, DidCoreId, SessionGrantRef, SessionGrantSecret};
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
    ) -> BoxSessionFuture<'a, SessionGrantResponseBody>;

    fn refresh_session_grant<'a>(
        &'a self,
        request: SessionGrantRefreshRequestBody,
    ) -> BoxSessionFuture<'a, SessionGrantResponseBody>;
}

impl SessionGrantTransport for arkret_http_client::Client {
    fn issue_session_grant<'a>(
        &'a self,
        request: SessionGrantRequestBody,
    ) -> BoxSessionFuture<'a, SessionGrantResponseBody> {
        Box::pin(async move {
            self.auth_issue_session_grant(&request)
                .await
                .map_err(Error::from)
        })
    }

    fn refresh_session_grant<'a>(
        &'a self,
        request: SessionGrantRefreshRequestBody,
    ) -> BoxSessionFuture<'a, SessionGrantResponseBody> {
        Box::pin(async move {
            self.auth_refresh_session_grant(&request)
                .await
                .map_err(Error::from)
        })
    }
}

/// Host-local exact refresh intent. It is stored inside the same secure
/// SessionGrant record, whose full reference and secret bind its predecessor.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingSessionGrantRefresh {
    pub request: SessionGrantRefreshRequestBody,
    pub expected_dpop_jkt: String,
}
impl PartialEq for PendingSessionGrantRefresh {
    fn eq(&self, other: &Self) -> bool {
        self.expected_dpop_jkt == other.expected_dpop_jkt
            && match (&self.request, &other.request) {
                (
                    SessionGrantRefreshRequestBody::Human(a),
                    SessionGrantRefreshRequestBody::Human(b),
                ) => {
                    a.session_grant == b.session_grant
                        && a.device_id == b.device_id
                        && a.audience_id == b.audience_id
                        && a.accepted_device_possession_proof == b.accepted_device_possession_proof
                }
                (
                    SessionGrantRefreshRequestBody::Agent(a),
                    SessionGrantRefreshRequestBody::Agent(b),
                ) => {
                    a.session_grant == b.session_grant
                        && a.principal_id == b.principal_id
                        && a.audience_id == b.audience_id
                        && a.agent_key_authorization_ref == b.agent_key_authorization_ref
                        && a.agent_session_refresh_proof == b.agent_session_refresh_proof
                }
                _ => false,
            }
    }
}
impl Eq for PendingSessionGrantRefresh {}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct SessionGrantState {
    #[zeroize(skip)]
    pub account_id: AccountId,
    #[zeroize(skip)]
    pub device_id: Option<DeviceId>,
    #[zeroize(skip)]
    pub grant_ref: SessionGrantRef,
    pub session_grant: SessionGrantSecret,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[zeroize(skip)]
    pub pending_refresh: Option<PendingSessionGrantRefresh>,
}

impl fmt::Debug for SessionGrantState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionGrantState")
            .field("account_id", &self.account_id)
            .field("device_id", &self.device_id)
            .field("grant_ref", &self.grant_ref)
            .field("session_grant", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .field("audience_id", &self.audience_id)
            .field("granted_scope", &self.granted_scope)
            .field("session_public_key", &self.session_public_key)
            .field("dpop_jkt", &self.dpop_jkt)
            .finish()
    }
}

impl SessionGrantState {
    /// Opaque credentials carry no client-readable participation observation.
    /// A host may independently load the registered current projection; the
    /// absence of this optional hint never replaces a server authority gate.
    pub fn agent_participation_observation(
        &self,
        _now: DateTime<Utc>,
    ) -> Result<Option<arkret_models_collaboration::governance::agent_participation::AgentParticipationObservation>>{
        Ok(None)
    }
    pub fn handle(&self) -> SessionHandle {
        SessionHandle {
            access_token: self.session_grant.as_str().to_owned(),
        }
    }

    pub fn from_initial_registration_outcome(
        request: &arkret_models_identity::InitialSessionGrantIntent,
        outcome: SessionGrantResponseBody,
        now: DateTime<Utc>,
    ) -> Result<Self> {
        if outcome.expires_at <= now {
            return Err(protocol(
                "initial Standard session grant is empty or expired",
            ));
        }
        if outcome.issuer_id != request.audience_id
            || outcome.device_id.as_ref() != Some(&request.device_id)
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
        let grant_ref = outcome.grant_ref();
        Ok(Self {
            account_id: outcome.account_id,
            device_id: outcome.device_id,
            grant_ref,
            session_grant: outcome.session_grant,
            expires_at: outcome.expires_at,
            audience_id: outcome.audience_id,
            granted_scope: outcome.granted_scope,
            session_public_key: Some(outcome.session_public_key.into_string()),
            dpop_jkt: Some(request.session_public_key.thumbprint_sha256()?),
            pending_refresh: None,
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
    state: Arc<Mutex<(Option<SessionGrantState>, u64)>>,
    refresh_gate: Arc<Mutex<RefreshGate>>,
    own_station_identity: arkret_http_client::own_station_results::OwnStationSessionIdentity,
}

impl<T> SessionEngine<T>
where
    T: SessionGrantTransport,
{
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            state: Arc::new(Mutex::new((None, 0))),
            refresh_gate: Arc::new(Mutex::new(RefreshGate::default())),
            own_station_identity: Default::default(),
        }
    }

    pub fn with_state(transport: T, state: SessionGrantState) -> Self {
        Self {
            transport,
            state: Arc::new(Mutex::new((Some(state), 0))),
            refresh_gate: Arc::new(Mutex::new(RefreshGate::default())),
            own_station_identity: Default::default(),
        }
    }

    // The state mutex only guards a plain `Option<SessionGrantState>` and every
    // critical section is panic-free, so it can never actually be poisoned.
    // Recover the guard rather than `unwrap()`-panicking, keeping the engine free
    // of a panic surface (and consistent with the store layer, which also maps
    // lock failures to a value rather than aborting).
    fn state_lock(&self) -> MutexGuard<'_, (Option<SessionGrantState>, u64)> {
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
        self.state_lock().0.clone()
    }

    /// Capture grant and local replacement epoch under the same lock.
    pub fn own_station_snapshot(
        &self,
        binding: &arkret_models_discovery::StationConnectionBinding,
    ) -> Result<arkret_http_client::own_station_results::OwnStationSessionSnapshot> {
        self.own_station_snapshot_at(binding, Utc::now())
    }
    pub fn own_station_snapshot_at(
        &self,
        binding: &arkret_models_discovery::StationConnectionBinding,
        now: DateTime<Utc>,
    ) -> Result<arkret_http_client::own_station_results::OwnStationSessionSnapshot> {
        let live = self.state_lock();
        let state = live.0.as_ref().ok_or_else(no_active_grant)?;
        if state.expires_at <= now {
            return Err(protocol("own Station session grant is expired"));
        }
        arkret_http_client::own_station_results::OwnStationSessionSnapshot::new(
            binding.clone(),
            state.account_id.clone(),
            state.audience_id.clone(),
            state.grant_ref.clone(),
            live.1,
            state.session_grant.as_str().to_owned(),
        )
        .map(|snapshot| snapshot.with_provider_identity(self.own_station_identity.clone()))
        .map_err(Error::from)
    }

    pub fn current_handle(&self) -> Option<SessionHandle> {
        self.current_state().map(|state| state.handle())
    }

    pub fn replace_state(&self, state: Option<SessionGrantState>) {
        let mut live = self.state_lock();
        if live.1 == u64::MAX {
            live.0 = None;
            return;
        }
        live.1 += 1;
        live.0 = state;
    }

    pub fn clear_state(&self) {
        self.replace_state(None);
    }

    pub fn refresh_decision(&self, now: DateTime<Utc>) -> RefreshDecision {
        let state = self.state_lock();
        let refresh_state = state.0.as_ref().map(SessionGrantState::refresh_state);
        refresh_decision(refresh_state.as_ref(), now)
    }

    pub async fn login(
        &self,
        login: LoginKind,
        clock: impl crate::HostClock,
    ) -> Result<SessionHandle> {
        let request = login.into_session_grant_request()?;
        self.login_request(request, clock).await
    }

    /// Issue a session from an already-authored canonical request.
    ///
    /// Some protocol transitions, such as exchanging an authenticated account
    /// handoff after OIDC, are authored by `arkret-auth` rather than one of the
    /// convenience [`LoginKind`] builders. They still pass through the same
    /// response validation and state installation as every other login.
    /// Sample the host clock after transport completion: an issuer can set
    /// `not_before` later than the time when this request was sent.
    pub async fn login_request(
        &self,
        request: SessionGrantRequestBody,
        clock: impl crate::HostClock,
    ) -> Result<SessionHandle> {
        let outcome = self.transport.issue_session_grant(request.clone()).await?;
        let now = clock.now();
        let state = state_from_issue_outcome(&request, outcome, now)?;
        if let SessionGrantRequestBody::Agent(agent) = &request {
            if let Some(observation) = state.agent_participation_observation(now)?
                && (observation.agent_key_authorization_ref != agent.agent_key_authorization_ref
                    || observation.verification_method != agent.proof.verification_method)
            {
                return Err(protocol(
                    "Agent observation differs from requested runtime authorization",
                ));
            }
        }
        let handle = state.handle();
        self.replace_state(Some(state));
        Ok(handle)
    }

    pub async fn refresh_if_due(
        &self,
        options: SessionRefreshOptions,
        clock: impl crate::HostClock,
    ) -> Result<SessionHandle> {
        self.refresh_if_due_with_store(options, clock, &super::NoopSessionGrantStore)
            .await
    }
    pub(super) async fn refresh_if_due_with_store<S: super::SessionGrantStore>(
        &self,
        options: SessionRefreshOptions,
        clock: impl crate::HostClock,
        store: &S,
    ) -> Result<SessionHandle> {
        if self
            .current_state()
            .is_some_and(|state| state.pending_refresh.is_some())
        {
            return self.refresh_once_with_store(options, clock, store).await;
        }
        let now = clock.now();
        match self.refresh_decision(now) {
            RefreshDecision::Fresh => self.current_handle().ok_or_else(no_active_grant),
            RefreshDecision::Due => {
                if self.within_refresh_cooldown(now) {
                    return self.current_handle().ok_or_else(no_active_grant);
                }
                self.refresh_once_with_store(options, clock, store).await
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
        clock: impl crate::HostClock,
    ) -> Result<SessionHandle> {
        self.refresh_after_unauthorized_with_store(options, clock, &super::NoopSessionGrantStore)
            .await
    }
    pub(super) async fn refresh_after_unauthorized_with_store<S: super::SessionGrantStore>(
        &self,
        options: SessionRefreshOptions,
        clock: impl crate::HostClock,
        store: &S,
    ) -> Result<SessionHandle> {
        let now = clock.now();
        if self
            .current_state()
            .is_some_and(|state| state.pending_refresh.is_none())
            && self.within_refresh_cooldown(now)
        {
            return self.current_handle().ok_or_else(no_active_grant);
        }
        self.refresh_once_with_store(options, clock, store).await
    }

    fn retire_refresh_context(&self, current: &SessionGrantState, epoch: u64) {
        let mut live = self.state_lock();
        if live.1 == epoch && live.0.as_ref() == Some(current) {
            live.0 = None;
            live.1 = live.1.saturating_add(1);
        }
    }

    pub async fn refresh_once(
        &self,
        options: SessionRefreshOptions,
        clock: impl crate::HostClock,
    ) -> Result<SessionHandle> {
        self.refresh_once_with_store(options, clock, &super::NoopSessionGrantStore)
            .await
    }
    pub(super) async fn refresh_once_with_store<S: super::SessionGrantStore>(
        &self,
        options: SessionRefreshOptions,
        clock: impl crate::HostClock,
        store: &S,
    ) -> Result<SessionHandle> {
        self.refresh_once_with_store_mode(options, clock, store, false)
            .await
    }

    pub(super) async fn refresh_for_sensitive_action_with_store<S: super::SessionGrantStore>(
        &self,
        options: SessionRefreshOptions,
        clock: impl crate::HostClock,
        store: &S,
    ) -> Result<SessionHandle> {
        self.refresh_once_with_store_mode(options, clock, store, true)
            .await
    }

    async fn refresh_once_with_store_mode<S: super::SessionGrantStore>(
        &self,
        options: SessionRefreshOptions,
        clock: impl crate::HostClock,
        store: &S,
        require_issuer_result: bool,
    ) -> Result<SessionHandle> {
        // Single-flight keeps concurrent callers on the same immutable refresh
        // request and issuer-ledger predecessor rather than racing rotations.
        // Losers return the still-valid current handle; the winner installs
        // the rotated grant into the shared state for everyone.
        let _in_flight = {
            let mut gate = self.gate_lock();
            if gate.in_flight {
                if require_issuer_result {
                    return Err(protocol("session refresh is already in flight"));
                }
                drop(gate);
                let current = self.current_state().ok_or_else(no_active_grant)?;
                if current.expires_at <= clock.now() {
                    return Err(protocol("expired predecessor replay is already in flight"));
                }
                return Ok(current.handle());
            }
            gate.in_flight = true;
            RefreshInFlightGuard(Arc::clone(&self.refresh_gate))
        };

        let (mut current, current_epoch) = {
            let live = self.state_lock();
            (live.0.clone().ok_or_else(no_active_grant)?, live.1)
        };
        let now = clock.now();
        let pending = if let Some(pending) = &current.pending_refresh {
            // A previous network send may already have committed at the issuer.
            // Preserve its exact body even after the predecessor/proof expires.
            refresh_request(
                &current,
                SessionRefreshOptions {
                    request: Some(pending.request.clone()),
                    expected_dpop_jkt: Some(pending.expected_dpop_jkt.clone()),
                },
            )?;
            pending.clone()
        } else {
            if current.expires_at <= now {
                return Err(protocol("session grant is expired"));
            }
            let (request, expected_dpop_jkt) = refresh_request(&current, options)?;
            PendingSessionGrantRefresh {
                request,
                expected_dpop_jkt,
            }
        };
        let predecessor = current.clone();
        current.pending_refresh = Some(pending.clone());
        {
            let mut live = self.state_lock();
            if live.1 != current_epoch
                || live.0.as_ref().is_none_or(|state| {
                    state.grant_ref != current.grant_ref
                        || state.session_grant != current.session_grant
                })
            {
                return Err(protocol("session changed before refresh preparation"));
            }
            live.0 = Some(current.clone());
        }
        // Durability precedes the first network byte. Cancellation or response
        // loss leaves this exact request recoverable under the existing key.
        match store.compare_exchange(&predecessor, &current).await {
            Ok(true) => {}
            Ok(false) => {
                self.retire_refresh_context(&current, current_epoch);
                return Err(Error::OwnStationSessionChanged);
            }
            Err(error) => {
                self.retire_refresh_context(&current, current_epoch);
                return Err(error);
            }
        }
        {
            let live = self.state_lock();
            if live.1 != current_epoch || live.0.as_ref() != Some(&current) {
                return Err(protocol("session changed before refresh dispatch"));
            }
        }
        let request = pending.request;
        let expected_dpop_jkt = pending.expected_dpop_jkt;
        // Validate the outgoing observation while its credential is valid.
        // The old credential may expire during a successful rotation.
        let previous_observation = if current.device_id.is_none() {
            current.agent_participation_observation(now)?
        } else {
            None
        };
        let outcome = self
            .transport
            .refresh_session_grant(request.clone())
            .await?;
        let now = clock.now();
        let state =
            state_from_refresh_outcome(&current, &request, &expected_dpop_jkt, outcome, now)?;
        if let (Some(previous_observation), Some(next_observation)) = (
            previous_observation,
            state.agent_participation_observation(now)?,
        ) {
            previous_observation
                .validate_successor(&next_observation)
                .map_err(protocol)?;
        }
        {
            let live = self.state_lock();
            if live.1 != current_epoch || live.0.as_ref() != Some(&current) {
                return Err(protocol(
                    "late session refresh cannot replace another active session",
                ));
            }
            if live.1 == u64::MAX {
                return Err(protocol("session replacement epoch is exhausted"));
            }
        }
        // Successor and cleared pending intent form one durable replacement.
        // The old state remains published until this write succeeds.
        match store.compare_exchange(&current, &state).await {
            Ok(true) => {}
            Ok(false) => {
                self.retire_refresh_context(&current, current_epoch);
                return Err(Error::OwnStationSessionChanged);
            }
            Err(error) => {
                self.retire_refresh_context(&current, current_epoch);
                return Err(error);
            }
        }
        let handle = state.handle();
        let mut installed = self.state_lock();
        if installed.1 != current_epoch || installed.0.as_ref() != Some(&current) {
            return Err(protocol(
                "late session refresh cannot replace another active session",
            ));
        }
        if installed.1 == u64::MAX {
            installed.0 = None;
            return Err(protocol("session replacement epoch is exhausted"));
        }
        installed.1 += 1;
        installed.0 = Some(state);
        drop(installed);
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

    let (session_grant, audience) = match &request {
        SessionGrantRefreshRequestBody::Human(request) => {
            if current.device_id.as_ref() != Some(&request.device_id)
                || request
                    .accepted_device_possession_proof
                    .predecessor_session_grant_ref
                    != current.grant_ref
            {
                return Err(protocol(
                    "session refresh device or issuer-qualified predecessor changed",
                ));
            }
            (&request.session_grant, request.audience_id.as_ref())
        }
        SessionGrantRefreshRequestBody::Agent(request) => {
            if current.device_id.is_some()
                || request.principal_id != current.account_id.principal_id
            {
                return Err(protocol("session refresh Agent holder changed"));
            }
            (&request.session_grant, request.audience_id.as_ref())
        }
    };
    if session_grant != &current.session_grant {
        return Err(protocol("session refresh exact predecessor changed"));
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
    outcome: SessionGrantResponseBody,
    now: DateTime<Utc>,
) -> Result<SessionGrantState> {
    request
        .validate()
        .map_err(|error| protocol(error.to_string()))?;
    if outcome.expires_at <= now {
        return Err(protocol("issued session grant is expired"));
    }
    if outcome.granted_scope.is_empty()
        || outcome
            .granted_scope
            .iter()
            .any(|value| value.trim().is_empty())
        || outcome
            .granted_scope
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
    {
        return Err(protocol(
            "issued session grant scope is incomplete or noncanonical",
        ));
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
    let audience = outcome.audience_id.clone();
    if &audience != request_audience || outcome.issuer_id != *request_audience {
        return Err(protocol("issued session grant audience changed"));
    }
    if outcome.account_id.station_id != audience {
        return Err(protocol("issued session grant Station changed"));
    }
    let grant_ref = outcome.grant_ref();
    let dpop_jkt = outcome.session_public_key.thumbprint_sha256()?;
    match request {
        SessionGrantRequestBody::Human(request) => {
            if dpop_jkt != request.accepted_device_possession_proof.holder_jkt {
                return Err(protocol(
                    "issued session grant holder differs from the signed request",
                ));
            }
        }
        SessionGrantRequestBody::Agent(request) => {
            // The caller's signed intent covers this complete DPoP proof. Read
            // its public holder commitment, not metadata from the opaque secret.
            // The issuer owns proof signature/freshness and current authority;
            // an exact late issue replay must not rerun that admission here.
            let mut parts = request.dpop_binding_proof.proof_jwt.split('.');
            let (Some(protected), Some(_), Some(_), None) =
                (parts.next(), parts.next(), parts.next(), parts.next())
            else {
                return Err(protocol(
                    "Agent request has no compact DPoP holder commitment",
                ));
            };
            let header = arkret_canonical::parse_json_rejecting_duplicate_keys(
                &arkret_canonical::base64url_decode(protected)
                    .map_err(|error| protocol(error.to_string()))?,
            )
            .map_err(|error| protocol(error.to_string()))?;
            if header["typ"] != "dpop+jwt" || header["alg"] != "Ed25519" {
                return Err(protocol(
                    "Agent request has an unsupported DPoP holder commitment",
                ));
            }
            let holder = arkret_models_identity::CanonicalSessionPublicJwk::new(
                serde_json::to_string(&header["jwk"])
                    .map_err(|error| protocol(error.to_string()))?,
            )?;
            if outcome.session_public_key != holder {
                return Err(protocol(
                    "issued session grant holder differs from the signed request",
                ));
            }
            if outcome
                .granted_scope
                .iter()
                .any(|scope| !request.requested_scope.contains(scope))
            {
                return Err(protocol(
                    "issued Agent scope exceeds the signed request ceiling",
                ));
            }
        }
        // Recovery carries no holder JWK in this body; its dedicated handoff
        // transport and recovery flow bind the actual candidate key.
        SessionGrantRequestBody::Recovery(_) => {}
    }
    if outcome.previous_session_grant_id.is_some() {
        return Err(protocol(
            "fresh session grant unexpectedly names a predecessor",
        ));
    }
    let session_public_key = outcome.session_public_key.into_string();

    Ok(SessionGrantState {
        account_id: outcome.account_id,
        device_id: outcome.device_id,
        grant_ref,
        session_grant: outcome.session_grant,
        expires_at: outcome.expires_at,
        audience_id: audience,
        granted_scope: outcome.granted_scope,
        session_public_key: Some(session_public_key),
        dpop_jkt: Some(dpop_jkt),
        pending_refresh: None,
    })
}

fn state_from_refresh_outcome(
    current: &SessionGrantState,
    request: &SessionGrantRefreshRequestBody,
    expected_dpop_jkt: &str,
    outcome: SessionGrantResponseBody,
    now: DateTime<Utc>,
) -> Result<SessionGrantState> {
    if outcome.expires_at <= now {
        return Err(protocol("refreshed session grant is expired"));
    }
    if outcome.audience_id != current.audience_id {
        return Err(protocol("refreshed session grant audience changed"));
    }
    if outcome.issuer_id != current.grant_ref.issuer_id
        || outcome.previous_session_grant_id.as_ref() != Some(&current.grant_ref.id)
    {
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
    if outcome.session_grant_id == current.grant_ref.id
        || outcome.session_grant == current.session_grant
    {
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

    let grant_ref = outcome.grant_ref();
    Ok(SessionGrantState {
        account_id: outcome.account_id,
        device_id: outcome.device_id,
        grant_ref,
        session_grant: outcome.session_grant,
        expires_at: outcome.expires_at,
        audience_id: outcome.audience_id,
        granted_scope: outcome.granted_scope,
        session_public_key: Some(outcome.session_public_key.into_string()),
        dpop_jkt: Some(outcome_dpop_jkt),
        pending_refresh: None,
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
pub(super) mod tests {
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    use arkret_models_collaboration::session_grant_bodies::{
        AgentSessionGrantRefreshRequestBody, AgentSessionRefreshProofContext,
        UnsignedAgentSessionRefreshProof,
    };
    use arkret_models_collaboration::session_grants::{
        RequestedAgentSessionGrantScope, SessionGrantDpopBindingProof,
    };
    use arkret_wire::{Base64UrlString, DidUrl, RealmId};
    use chrono::Duration;

    use super::*;
    use crate::session::AgentKeyProofLogin;

    #[derive(Clone)]
    struct FixedClock(DateTime<Utc>);

    impl crate::HostClock for FixedClock {
        fn now(&self) -> DateTime<Utc> {
            self.0
        }
    }

    #[derive(Clone)]
    struct AdvancingClock(Arc<Mutex<DateTime<Utc>>>);

    impl crate::HostClock for AdvancingClock {
        fn now(&self) -> DateTime<Utc> {
            *self.0.lock().unwrap()
        }
    }

    #[derive(Clone)]
    struct AdvancingTransport {
        inner: MockSessionTransport,
        clock: AdvancingClock,
        response_at: DateTime<Utc>,
    }

    impl SessionGrantTransport for AdvancingTransport {
        fn issue_session_grant<'a>(
            &'a self,
            request: SessionGrantRequestBody,
        ) -> BoxSessionFuture<'a, SessionGrantResponseBody> {
            Box::pin(async move {
                *self.clock.0.lock().unwrap() = self.response_at;
                self.inner.issue_session_grant(request).await
            })
        }

        fn refresh_session_grant<'a>(
            &'a self,
            request: SessionGrantRefreshRequestBody,
        ) -> BoxSessionFuture<'a, SessionGrantResponseBody> {
            Box::pin(async move {
                *self.clock.0.lock().unwrap() = self.response_at;
                self.inner.refresh_session_grant(request).await
            })
        }
    }

    #[derive(Clone, Default)]
    struct MockSessionTransport {
        issue_requests: Arc<Mutex<Vec<SessionGrantRequestBody>>>,
        refresh_requests: Arc<Mutex<Vec<SessionGrantRefreshRequestBody>>>,
        issue_responses: Arc<Mutex<VecDeque<Result<SessionGrantResponseBody>>>>,
        refresh_responses: Arc<Mutex<VecDeque<Result<SessionGrantResponseBody>>>>,
    }

    impl MockSessionTransport {
        fn with_issue_responses(responses: Vec<Result<SessionGrantResponseBody>>) -> Self {
            Self {
                issue_responses: Arc::new(Mutex::new(VecDeque::from(responses))),
                ..Self::default()
            }
        }

        fn with_refresh_responses(responses: Vec<Result<SessionGrantResponseBody>>) -> Self {
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
        ) -> BoxSessionFuture<'a, SessionGrantResponseBody> {
            self.issue_requests.lock().unwrap().push(request);
            let response = self.issue_responses.lock().unwrap().pop_front().unwrap();
            Box::pin(async move { response })
        }

        fn refresh_session_grant<'a>(
            &'a self,
            request: SessionGrantRefreshRequestBody,
        ) -> BoxSessionFuture<'a, SessionGrantResponseBody> {
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

    fn grant_ref(n: u64) -> SessionGrantRef {
        SessionGrantRef::new(
            audience(),
            SessionGrantId::new(format!("ak:session_grant:01904100-0000-7000-8000-{n:012x}"))
                .unwrap(),
        )
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
            serde_json::to_string(&arkret_signatures::JsonWebKey::from_ed25519_verifying_key(
                &ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]).verifying_key(),
            ))
            .unwrap(),
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
            requested_scope: vec!["ak.self.committed_event.stream.subscribe.v1".to_owned()],
            agent_key_authorization_ref: agent_key_authorization_ref(),
            agent_scope_request: RequestedAgentSessionGrantScope {
                realm_ids: vec![
                    RealmId::new("ak:realm:AfF-hFqRoMbajXkPapH-xaq0xwK-UKt2ph2zTs9JZRAO").unwrap(),
                ],
                strand_ids: Vec::new(),
                track_names: Vec::new(),
            },
            requested_scope_disclosure: None,
            dpop_binding_proof: SessionGrantDpopBindingProof {
                proof_jwt: arkret_signatures::dpop::build_dpop_proof(
                    &arkret_signatures::dpop::DpopProofRequest::new(
                        "POST",
                        "https://authority.example/_arkret/gate/account/session-grants",
                    )
                    .issued_at(now()),
                    &ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]),
                )
                .unwrap()
                .proof_jwt,
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

    fn human_issue_request() -> SessionGrantRequestBody {
        use ed25519_dalek::Signer as _;
        let request_id =
            arkret_wire::RequestId::new("ak:request:01970000-0000-7000-8000-000000000021").unwrap();
        let digest = arkret_wire::Hash::new(
            arkret_canonical::canonical_sha256(&"returning-session-handoff").unwrap(),
        )
        .unwrap();
        let unsigned = arkret_wire::UnsignedAcceptedDeviceIssuePossessionProof {
            context: arkret_wire::AcceptedDevicePossessionProofContext::V1,
            purpose: arkret_wire::AcceptedDeviceIssuePossessionPurpose::SessionGrantIssue,
            request_id: request_id.clone(),
            account_subject: digest.clone(),
            account_handoff_grant_digest: digest,
            account_id: AccountId::new(principal_id(), audience()),
            device_id: device_id(),
            audience_id: audience(),
            holder_jkt: session_dpop_jkt(),
            session_intent_digest:
                arkret_models_collaboration::session_grants::human_session_grant_intent_digest(
                    &request_id,
                    &principal_id(),
                    &device_id(),
                    &audience(),
                    &session_dpop_jkt(),
                )
                .unwrap(),
            issued_at: now(),
            expires_at: now() + Duration::minutes(5),
            verification_method: DidUrl::new("did:webvh:z6mkfixture:alice.example#accepted-device")
                .unwrap(),
        };
        let signature = ed25519_dalek::SigningKey::from_bytes(&[0x55; 32])
            .sign(&unsigned.canonical_signing_bytes().unwrap());
        let proof = unsigned
            .attach_signature(
                Base64UrlString::new(arkret_canonical::base64url_encode(signature.to_bytes()))
                    .unwrap(),
            )
            .unwrap();
        arkret_auth::session_grant::human_session_grant_request(
            request_id,
            principal_id(),
            device_id(),
            audience(),
            proof,
        )
        .unwrap()
    }

    pub(crate) fn opaque_secret(
        label: &str,
        grant: SessionGrantRef,
        _expires: DateTime<Utc>,
    ) -> SessionGrantSecret {
        SessionGrantSecret::from_bytes(arkret_canonical::sha256_bytes(
            &arkret_canonical::canonical_json_bytes(&serde_json::json!([label, grant])).unwrap(),
        ))
    }
    fn issue_outcome(
        token: &str,
        grant: SessionGrantRef,
        principal_id: DidCoreId,
        device_id: Option<DeviceId>,
    ) -> SessionGrantResponseBody {
        SessionGrantResponseBody {
            account_id: AccountId::new(principal_id, audience()),
            device_id: device_id.clone(),
            issuer_id: audience(),
            session_grant: opaque_secret(token, grant.clone(), now() + Duration::hours(1)),
            expires_at: now() + Duration::hours(1),
            session_grant_id: grant.id.clone(),
            session_public_key: session_public_jwk(),
            audience_id: audience(),
            granted_scope: vec!["ak.self.committed_event.stream.subscribe.v1".to_owned()],
            previous_session_grant_id: None,
        }
    }

    fn active_state() -> SessionGrantState {
        SessionGrantState {
            account_id: AccountId::new(principal_id(), audience()),
            device_id: None,
            grant_ref: grant_ref(1),
            session_grant: opaque_secret("grant-1", grant_ref(1), now() + Duration::minutes(20)),
            expires_at: now() + Duration::minutes(20),
            audience_id: audience(),
            granted_scope: vec!["ak.self.committed_event.stream.subscribe.v1".to_owned()],
            session_public_key: Some(session_public_jwk().into_string()),
            dpop_jkt: Some(session_dpop_jkt()),
            pending_refresh: None,
        }
    }

    #[test]
    fn session_credentials_are_redacted_from_debug_output() {
        let state = active_state();
        let state_debug = format!("{state:?}");
        assert!(state_debug.contains("[REDACTED]"));
        assert!(!state_debug.contains(state.session_grant.as_str()));

        let handle = state.handle();
        let handle_debug = format!("{handle:?}");
        assert!(handle_debug.contains("[REDACTED]"));
        assert!(!handle_debug.contains(&handle.access_token));
    }

    fn refresh_options_for(session_grant: &SessionGrantSecret) -> SessionRefreshOptions {
        let proof = UnsignedAgentSessionRefreshProof {
            context: AgentSessionRefreshProofContext::V1,
            request_canonical_digest: arkret_models_collaboration::session_grant_bodies::agent_session_refresh_request_digest(
                session_grant,&principal_id(),&agent_key_authorization_ref(),&audience(),&DidUrl::new("did:webvh:z6mkfixture:agent.example#runtime-key-1").unwrap(),
            ).unwrap(),
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
                AgentSessionGrantRefreshRequestBody {
                    session_grant: session_grant.clone(),
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
        refresh_options_for(&active_state().session_grant)
    }

    fn refresh_outcome(token: &str, grant: SessionGrantRef) -> SessionGrantResponseBody {
        SessionGrantResponseBody {
            issuer_id: audience(),
            session_grant_id: grant.id.clone(),
            account_id: AccountId::new(principal_id(), audience()),
            device_id: None,
            session_grant: opaque_secret(token, grant, now() + Duration::hours(1)),
            session_public_key: session_public_jwk(),
            expires_at: now() + Duration::hours(1),
            audience_id: audience(),
            granted_scope: vec!["ak.self.committed_event.stream.subscribe.v1".to_owned()],
            previous_session_grant_id: Some(grant_ref(1).id),
        }
    }

    #[tokio::test]
    async fn engine_exchanges_closed_agent_login() {
        let transport = MockSessionTransport::with_issue_responses(vec![Ok(issue_outcome(
            "grant-agent",
            grant_ref(10),
            principal_id(),
            None,
        ))]);
        let engine = SessionEngine::new(transport.clone());

        let handle = engine
            .login(agent_login(), FixedClock(now()))
            .await
            .unwrap();

        assert_eq!(
            handle.access_token,
            opaque_secret("grant-agent", grant_ref(10), now() + Duration::hours(1)).as_str()
        );
        let requests = transport.issue_requests();
        assert_eq!(requests.len(), 1);
        assert!(matches!(requests[0], SessionGrantRequestBody::Agent(_)));
    }

    #[tokio::test]
    async fn initial_receipt_cannot_substitute_the_signed_holder_or_expand_agent_scope() {
        use ed25519_dalek::Signer as _;
        let mut agent = agent_login().into_session_grant_request().unwrap();
        let SessionGrantRequestBody::Agent(body) = &mut agent else {
            unreachable!()
        };
        body.proof.signature = arkret_canonical::base64url_encode(
            ed25519_dalek::SigningKey::from_bytes(&[0x42; 32])
                .sign(&body.proof.canonical_signing_bytes().unwrap())
                .to_bytes(),
        );
        let wrong_holder = arkret_models_identity::CanonicalSessionPublicJwk::new(
            serde_json::to_string(&arkret_signatures::JsonWebKey::from_ed25519_verifying_key(
                &ed25519_dalek::SigningKey::from_bytes(&[0x43; 32]).verifying_key(),
            ))
            .unwrap(),
        )
        .unwrap();
        for (request, device) in [
            (agent.clone(), None),
            (human_issue_request(), Some(device_id())),
        ] {
            let valid = issue_outcome("bound-holder", grant_ref(91), principal_id(), device);
            let transport = MockSessionTransport::with_issue_responses(vec![Ok(valid.clone())]);
            let engine = SessionEngine::new(transport);
            engine
                .login_request(request.clone(), FixedClock(now()))
                .await
                .unwrap();
            assert_eq!(
                engine.current_state().unwrap().dpop_jkt.as_deref(),
                Some(session_dpop_jkt().as_str())
            );
            let mut invalid = valid;
            invalid.session_public_key = wrong_holder.clone();
            let transport = MockSessionTransport::with_issue_responses(vec![Ok(invalid)]);
            let engine = SessionEngine::new(transport);
            assert!(
                engine
                    .login_request(request, FixedClock(now()))
                    .await
                    .is_err()
            );
            assert!(engine.current_state().is_none());
        }
        let mut expanded = issue_outcome("expanded-agent", grant_ref(92), principal_id(), None);
        expanded
            .granted_scope
            .push("ak.self.events.command.submit.v1".to_owned());
        let engine = SessionEngine::new(MockSessionTransport::with_issue_responses(vec![Ok(
            expanded,
        )]));
        assert!(
            engine
                .login_request(agent, FixedClock(now()))
                .await
                .is_err()
        );
        assert!(engine.current_state().is_none());
    }

    #[tokio::test]
    async fn opaque_login_and_rotation_check_expiry_after_transport_completion() {
        let response_at = now() + Duration::minutes(21);
        for (expires, accepted) in [
            (response_at + Duration::hours(1), true),
            (response_at, false),
        ] {
            let clock = AdvancingClock(Arc::new(Mutex::new(now())));
            let mut outcome = issue_outcome("grant-agent", grant_ref(10), principal_id(), None);
            outcome.expires_at = expires;
            let login = SessionEngine::new(AdvancingTransport {
                inner: MockSessionTransport::with_issue_responses(vec![Ok(outcome)]),
                clock: clock.clone(),
                response_at,
            });
            assert_eq!(login.login(agent_login(), clock).await.is_ok(), accepted);
            let clock = AdvancingClock(Arc::new(Mutex::new(now())));
            let mut outcome = refresh_outcome("grant-2", grant_ref(2));
            outcome.expires_at = expires;
            let engine = SessionEngine::with_state(
                AdvancingTransport {
                    inner: MockSessionTransport::with_refresh_responses(vec![Ok(outcome)]),
                    clock: clock.clone(),
                    response_at,
                },
                active_state(),
            );
            assert_eq!(
                engine.refresh_once(refresh_options(), clock).await.is_ok(),
                accepted
            );
            assert_eq!(
                engine.current_state().unwrap().grant_ref,
                grant_ref(if accepted { 2 } else { 1 })
            );
        }
    }

    #[tokio::test]
    async fn durable_pending_replays_exact_body_after_response_loss_and_cold_expiry() {
        use crate::{MemorySecureKeyStore, SecureSessionGrantStore, SessionGrantStore};
        let store =
            SecureSessionGrantStore::new(MemorySecureKeyStore::new(), "session/exact-replay");
        store.save(&active_state()).await.unwrap();
        let transport = MockSessionTransport::with_refresh_responses(vec![Err(protocol(
            "response lost after issuer commit",
        ))]);
        let engine = SessionEngine::with_state(transport.clone(), active_state());
        assert!(
            engine
                .refresh_once_with_store(refresh_options(), FixedClock(now()), &store)
                .await
                .is_err()
        );
        let before =
            arkret_canonical::canonical_json_bytes(&transport.refresh_requests()[0]).unwrap();
        let restored = store.load().unwrap().unwrap();
        assert!(restored.pending_refresh.is_some());
        assert_eq!(restored.grant_ref, grant_ref(1));
        drop(engine);
        let transport = MockSessionTransport::with_refresh_responses(vec![Ok(refresh_outcome(
            "grant-2",
            grant_ref(2),
        ))]);
        let replay = SessionEngine::with_state(transport.clone(), restored);
        replay
            .refresh_once_with_store(
                SessionRefreshOptions::default(),
                FixedClock(now() + Duration::minutes(21)),
                &store,
            )
            .await
            .unwrap();
        assert_eq!(
            before,
            arkret_canonical::canonical_json_bytes(&transport.refresh_requests()[0]).unwrap(),
            "cold retry must not author a fresh proof/body"
        );
        let durable = store.load().unwrap().unwrap();
        assert_eq!(durable.grant_ref, grant_ref(2));
        assert!(durable.pending_refresh.is_none());
        assert_eq!(replay.current_state().unwrap(), durable);
    }

    #[derive(Clone)]
    struct FailingRefreshStore {
        inner: crate::SecureSessionGrantStore<crate::MemorySecureKeyStore>,
        fail_successor: bool,
    }
    impl super::super::SessionGrantStore for FailingRefreshStore {
        fn load(&self) -> Result<Option<SessionGrantState>> {
            self.inner.load()
        }
        fn save<'a>(
            &'a self,
            state: &'a SessionGrantState,
        ) -> impl std::future::Future<Output = Result<()>> + crate::MaybeSend + 'a {
            async move {
                if state.pending_refresh.is_some() != self.fail_successor {
                    return Err(protocol("durable write failed"));
                }
                self.inner.save(state).await
            }
        }
        fn compare_exchange<'a>(
            &'a self,
            expected: &'a SessionGrantState,
            next: &'a SessionGrantState,
        ) -> impl std::future::Future<Output = Result<bool>> + crate::MaybeSend + 'a {
            async move {
                if next.pending_refresh.is_some() != self.fail_successor {
                    return Err(protocol("durable write failed"));
                }
                self.inner.compare_exchange(expected, next).await
            }
        }
        fn clear(&self) -> Result<()> {
            self.inner.clear()
        }
    }

    #[tokio::test]
    async fn refresh_dispatch_and_successor_publication_wait_for_durability() {
        use crate::SessionGrantStore;
        for fail_successor in [false, true] {
            let store = FailingRefreshStore {
                inner: crate::SecureSessionGrantStore::new(
                    crate::MemorySecureKeyStore::new(),
                    "session/failure",
                ),
                fail_successor,
            };
            store.inner.save(&active_state()).await.unwrap();
            let transport = MockSessionTransport::with_refresh_responses(vec![Ok(
                refresh_outcome("grant-2", grant_ref(2)),
            )]);
            let engine = SessionEngine::with_state(transport.clone(), active_state());
            assert!(
                engine
                    .refresh_once_with_store(refresh_options(), FixedClock(now()), &store)
                    .await
                    .is_err()
            );
            assert_eq!(
                transport.refresh_requests().len(),
                usize::from(fail_successor)
            );
            assert!(
                engine.current_state().is_none(),
                "an uncertain persistence outcome retires this local context"
            );
            if fail_successor {
                assert!(store.load().unwrap().unwrap().pending_refresh.is_some());
            } else {
                assert!(store.load().unwrap().unwrap().pending_refresh.is_none());
            }
        }
    }

    #[tokio::test]
    async fn fresh_refresh_cannot_start_after_expiry_without_a_pending_exact_request() {
        let transport = MockSessionTransport::with_refresh_responses(Vec::new());
        let engine = SessionEngine::with_state(transport.clone(), active_state());
        assert!(
            engine
                .refresh_once(refresh_options(), FixedClock(now() + Duration::minutes(21)))
                .await
                .is_err()
        );
        assert!(transport.refresh_requests().is_empty());
    }

    #[test]
    fn opaque_state_has_no_claims_or_mandatory_participation_hint() {
        let state = active_state();
        assert!(
            state
                .agent_participation_observation(now())
                .unwrap()
                .is_none()
        );
        let mut wire = serde_json::to_value(&state).unwrap();
        wire["session_grant"] = serde_json::json!("header.payload.signature");
        assert!(serde_json::from_value::<SessionGrantState>(wire).is_err());
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
                grant_ref(11),
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
            grant_ref(14),
            principal_id(),
            None,
        ))]);
        let engine = SessionEngine::new(transport.clone());
        let request = agent_login().into_session_grant_request().unwrap();

        let handle = engine
            .login_request(request, FixedClock(now()))
            .await
            .unwrap();

        assert_eq!(
            handle.access_token,
            opaque_secret("grant-authored", grant_ref(14), now() + Duration::hours(1)).as_str()
        );
        assert_eq!(transport.issue_requests().len(), 1);
        assert_eq!(engine.current_state().unwrap().grant_ref, grant_ref(14));
    }

    #[tokio::test]
    async fn engine_rejects_unsafe_issue_outcomes_without_state() {
        let cases = vec![
            SessionGrantResponseBody {
                granted_scope: Vec::new(),
                ..issue_outcome("grant-empty-scope", grant_ref(20), principal_id(), None)
            },
            SessionGrantResponseBody {
                expires_at: now() - Duration::seconds(1),
                ..issue_outcome("grant-expired", grant_ref(21), principal_id(), None)
            },
            issue_outcome(
                "grant-wrong-principal",
                grant_ref(22),
                other_principal_id(),
                None,
            ),
            issue_outcome(
                "grant-wrong-device",
                grant_ref(23),
                principal_id(),
                Some(other_device_id()),
            ),
        ];

        for outcome in cases {
            let transport = MockSessionTransport::with_issue_responses(vec![Ok(outcome)]);
            let engine = SessionEngine::new(transport);

            let result = engine.login(agent_login(), FixedClock(now())).await;

            assert!(result.is_err());
            assert!(engine.current_state().is_none());
        }
    }

    #[tokio::test]
    async fn refresh_no_grant_or_expired_grant_does_not_call_transport() {
        let transport = MockSessionTransport::default();
        let engine = SessionEngine::new(transport.clone());

        assert!(
            engine
                .refresh_once(refresh_options(), FixedClock(now()))
                .await
                .is_err()
        );
        assert!(transport.refresh_requests().is_empty());

        let mut expired = active_state();
        expired.expires_at = now() - Duration::seconds(1);
        let engine = SessionEngine::with_state(transport.clone(), expired);

        assert!(
            engine
                .refresh_once(refresh_options(), FixedClock(now()))
                .await
                .is_err()
        );
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

            let result = engine.refresh_once(options, FixedClock(now())).await;

            assert!(result.is_err());
            assert!(transport.refresh_requests().is_empty());
        }
    }

    #[tokio::test]
    async fn refresh_sends_old_grant_and_replaces_state() {
        let transport = MockSessionTransport::with_refresh_responses(vec![Ok(refresh_outcome(
            "grant-2",
            grant_ref(2),
        ))]);
        let engine = SessionEngine::with_state(transport.clone(), active_state());

        let handle = engine
            .refresh_once(refresh_options(), FixedClock(now()))
            .await
            .unwrap();

        assert_eq!(
            handle.access_token,
            opaque_secret("grant-2", grant_ref(2), now() + Duration::hours(1)).as_str()
        );
        let requests = transport.refresh_requests();
        assert_eq!(requests.len(), 1);
        let SessionGrantRefreshRequestBody::Agent(request) = &requests[0] else {
            panic!("test authors the Agent refresh branch");
        };
        assert_eq!(request.session_grant, active_state().session_grant);
        assert_eq!(request.audience_id.as_ref(), Some(&audience()));
        let state = engine.current_state().unwrap();
        assert_eq!(state.grant_ref, grant_ref(2));
        assert_eq!(state.dpop_jkt, Some(session_dpop_jkt()));
    }

    #[tokio::test]
    async fn refresh_rejects_changed_outcomes_without_replacing_state() {
        let mut wrong_issuer = refresh_outcome("grant-wrong-issuer", grant_ref(2));
        wrong_issuer.issuer_id = DidCoreId::new("ak:did_core:web:other-issuer.example").unwrap();
        let mut wrong_audience = refresh_outcome("grant-wrong-audience", grant_ref(30));
        wrong_audience.audience_id =
            DidCoreId::new("ak:did_core:webvh:z6mkfixture:other-service.example").unwrap();

        let mut wrong_previous = refresh_outcome("grant-wrong-previous", grant_ref(31));
        wrong_previous.previous_session_grant_id = Some(grant_ref(99).id);

        let replayed = refresh_outcome("grant-replayed", grant_ref(1));

        let mut expired = refresh_outcome("grant-expired", grant_ref(32));
        expired.expires_at = now() - Duration::seconds(1);

        let mut wrong_dpop = refresh_outcome("grant-wrong-dpop", grant_ref(33));
        wrong_dpop.session_public_key = arkret_models_identity::CanonicalSessionPublicJwk::new(
            r#"{"crv":"Ed25519","kty":"OKP","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE"}"#,
        )
        .unwrap();

        let mut widened_scope = refresh_outcome("grant-widened-scope", grant_ref(34));
        widened_scope.granted_scope = vec![
            "ak.self.committed_event.stream.subscribe.v1".to_owned(),
            "ak.self.events.command.submit.v1".to_owned(),
        ];

        let mut narrowed_scope = refresh_outcome("grant-narrowed-scope", grant_ref(35));
        narrowed_scope.granted_scope = Vec::new();

        let mut substituted_scope = refresh_outcome("grant-substituted-scope", grant_ref(36));
        substituted_scope.granted_scope = vec!["ak.self.events.command.submit.v1".to_owned()];

        let mut wrong_device = refresh_outcome("grant-wrong-device", grant_ref(37));
        wrong_device.device_id = Some(other_device_id());

        for (outcome, expected_error) in [
            (wrong_issuer, "refreshed session grant chain changed"),
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
                .refresh_once(refresh_options(), FixedClock(now()))
                .await
                .expect_err("a changed successor is rejected");

            assert!(
                error.to_string().contains(expected_error),
                "expected `{expected_error}`, got `{error}`"
            );
            assert_eq!(
                engine.current_state().unwrap().session_grant,
                active_state().session_grant
            );
        }
    }

    #[tokio::test]
    async fn refresh_transport_errors_do_not_replace_state() {
        for label in ["revoked", "paused", "expired"] {
            let transport = MockSessionTransport::with_refresh_responses(vec![Err(
                Error::Protocol(label.to_owned()),
            )]);
            let engine = SessionEngine::with_state(transport.clone(), active_state());

            let result = engine
                .refresh_once(refresh_options(), FixedClock(now()))
                .await;

            assert!(result.is_err());
            assert_eq!(
                engine.current_state().unwrap().session_grant,
                active_state().session_grant
            );
            assert_eq!(transport.refresh_requests().len(), 1);
        }
    }

    /// Refresh transport whose future stays pending until released, so a test
    /// can hold a refresh in flight while a second caller races it.
    struct GatedRefreshTransport {
        started: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Notify>,
        refresh_calls: Arc<Mutex<usize>>,
        outcome: SessionGrantResponseBody,
    }

    impl SessionGrantTransport for GatedRefreshTransport {
        fn issue_session_grant<'a>(
            &'a self,
            _request: SessionGrantRequestBody,
        ) -> BoxSessionFuture<'a, SessionGrantResponseBody> {
            Box::pin(async move { Err(Error::Protocol("issue not expected".to_owned())) })
        }

        fn refresh_session_grant<'a>(
            &'a self,
            _request: SessionGrantRefreshRequestBody,
        ) -> BoxSessionFuture<'a, SessionGrantResponseBody> {
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
            outcome: refresh_outcome("grant-2", grant_ref(2)),
        };
        let engine = Arc::new(SessionEngine::with_state(transport, active_state()));

        let winner = {
            let engine = Arc::clone(&engine);
            tokio::spawn(async move {
                engine
                    .refresh_once(refresh_options(), FixedClock(now()))
                    .await
            })
        };
        // Wait until the winner's transport call is in flight...
        tokio::time::timeout(std::time::Duration::from_secs(15), started.notified())
            .await
            .expect("the valid refresh request reaches transport");
        // ...then race a second refresh: it must NOT fire a transport call and
        // returns the still-valid current handle instead.
        let loser = engine
            .refresh_once(refresh_options(), FixedClock(now()))
            .await
            .unwrap();
        assert_eq!(loser.access_token, active_state().session_grant.as_str());
        assert_eq!(*refresh_calls.lock().unwrap(), 1);

        release.notify_one();
        let winner = winner.await.unwrap().unwrap();
        assert_eq!(
            winner.access_token,
            opaque_secret("grant-2", grant_ref(2), now() + Duration::hours(1)).as_str()
        );
        assert_eq!(*refresh_calls.lock().unwrap(), 1);
        // The winner installed the rotated grant for everyone.
        assert_eq!(
            engine.current_state().unwrap().session_grant,
            opaque_secret("grant-2", grant_ref(2), now() + Duration::hours(1))
        );
    }

    #[tokio::test]
    async fn a_late_refresh_cannot_overwrite_a_new_durable_login() {
        use crate::{MemorySecureKeyStore, SecureSessionGrantStore, SessionGrantStore};
        let store = SecureSessionGrantStore::new(MemorySecureKeyStore::new(), "session/race");
        store.save(&active_state()).await.unwrap();
        let started = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let transport = GatedRefreshTransport {
            started: started.clone(),
            release: release.clone(),
            refresh_calls: Arc::new(Mutex::new(0)),
            outcome: refresh_outcome("grant-2", grant_ref(2)),
        };
        let engine = Arc::new(SessionEngine::with_state(transport, active_state()));
        let task = {
            let engine = engine.clone();
            let store = store.clone();
            tokio::spawn(async move {
                engine
                    .refresh_once_with_store(refresh_options(), FixedClock(now()), &store)
                    .await
            })
        };
        started.notified().await;
        let mut newer = active_state();
        newer.grant_ref = grant_ref(99);
        newer.session_grant = opaque_secret("new-login", grant_ref(99), newer.expires_at);
        store.save(&newer).await.unwrap();
        release.notify_one();
        assert!(matches!(
            task.await.unwrap(),
            Err(Error::OwnStationSessionChanged)
        ));
        assert_eq!(store.load().unwrap().unwrap(), newer);
        assert!(engine.current_state().is_none());
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
            outcome: refresh_outcome("grant-2", grant_ref(2)),
        };
        let engine = Arc::new(SessionEngine::with_state(transport, active_state()));

        let cancelled = {
            let engine = Arc::clone(&engine);
            tokio::spawn(async move {
                engine
                    .refresh_once(refresh_options(), FixedClock(now()))
                    .await
            })
        };
        tokio::time::timeout(std::time::Duration::from_secs(15), started.notified())
            .await
            .expect("the valid refresh request reaches transport");
        cancelled.abort();
        assert!(cancelled.await.unwrap_err().is_cancelled());
        assert_eq!(
            engine.current_state().unwrap().session_grant,
            active_state().session_grant
        );

        let retry = {
            let engine = Arc::clone(&engine);
            tokio::spawn(async move {
                engine
                    .refresh_once(refresh_options(), FixedClock(now()))
                    .await
            })
        };
        tokio::time::timeout(std::time::Duration::from_secs(15), started.notified())
            .await
            .expect("the retried refresh request reaches transport");
        release.notify_one();
        assert_eq!(
            retry.await.unwrap().unwrap().access_token,
            opaque_secret("grant-2", grant_ref(2), now() + Duration::hours(1)).as_str()
        );
        assert_eq!(*refresh_calls.lock().unwrap(), 2);
    }

    #[tokio::test]
    async fn refresh_if_due_honors_success_cooldown() {
        // A rotated grant that is still short-lived enough to be immediately
        // `Due` again (the refresh-treadmill shape).
        let mut short_lived = refresh_outcome("grant-2", grant_ref(2));
        short_lived.expires_at = now() + Duration::seconds(30);
        short_lived.session_grant = opaque_secret("grant-2", grant_ref(2), short_lived.expires_at);
        let mut after_cooldown = refresh_outcome("grant-3", grant_ref(3));
        after_cooldown.previous_session_grant_id = Some(grant_ref(2).id);
        after_cooldown.expires_at = now() + Duration::seconds(30);
        after_cooldown.session_grant =
            opaque_secret("grant-3", grant_ref(3), after_cooldown.expires_at);
        let transport =
            MockSessionTransport::with_refresh_responses(vec![Ok(short_lived), Ok(after_cooldown)]);
        let mut due_state = active_state();
        due_state.expires_at = now() + Duration::seconds(30);
        due_state.session_grant = opaque_secret("grant-1", grant_ref(1), due_state.expires_at);
        let engine = SessionEngine::with_state(transport.clone(), due_state);

        // First call rotates.
        let handle = engine
            .refresh_if_due(
                refresh_options_for(&opaque_secret(
                    "grant-1",
                    grant_ref(1),
                    now() + Duration::seconds(30),
                )),
                FixedClock(now()),
            )
            .await
            .unwrap();
        assert_eq!(
            handle.access_token,
            opaque_secret("grant-2", grant_ref(2), now() + Duration::seconds(30)).as_str()
        );
        assert_eq!(transport.refresh_requests().len(), 1);

        // Still Due, but within the cooldown: no second transport call.
        let handle = engine
            .refresh_if_due(refresh_options(), FixedClock(now() + Duration::seconds(1)))
            .await
            .unwrap();
        assert_eq!(
            handle.access_token,
            opaque_secret("grant-2", grant_ref(2), now() + Duration::seconds(30)).as_str()
        );
        assert_eq!(transport.refresh_requests().len(), 1);

        // Past the cooldown the due refresh fires again.
        let handle = engine
            .refresh_if_due(
                refresh_options_for(&opaque_secret(
                    "grant-2",
                    grant_ref(2),
                    now() + Duration::seconds(30),
                )),
                FixedClock(now() + Duration::seconds(REFRESH_SUCCESS_COOLDOWN_SECS)),
            )
            .await
            .unwrap();
        assert_eq!(
            handle.access_token,
            opaque_secret("grant-3", grant_ref(3), now() + Duration::seconds(30)).as_str()
        );
        assert_eq!(transport.refresh_requests().len(), 2);
    }
}
