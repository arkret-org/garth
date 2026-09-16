use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use arkret_models_collaboration::session_grants::{
    SessionGrantOutcome, SessionGrantRefreshRequestBody, SessionGrantRequestBody,
};
use arkret_models_identity::InitialSessionGrantIntent;
use arkret_wire::{AccountId, DeviceId, DidCoreId, SessionGrantId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::login::LoginKind;
use super::store::SessionGrantStore;
use super::{SessionHandle, refresh_decision};
use crate::{Error, Result};

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
    ) -> BoxSessionFuture<'a, SessionGrantOutcome>;
}

impl SessionGrantTransport for arkret_http_client::Client {
    fn issue_session_grant<'a>(
        &'a self,
        request: SessionGrantRequestBody,
    ) -> BoxSessionFuture<'a, SessionGrantOutcome> {
        Box::pin(async move { Ok(self.auth_issue_session_grant(&request).await?) })
    }

    fn refresh_session_grant<'a>(
        &'a self,
        request: SessionGrantRefreshRequestBody,
    ) -> BoxSessionFuture<'a, SessionGrantOutcome> {
        Box::pin(async move { Ok(self.auth_refresh_session_grant(&request).await?) })
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
        request: &InitialSessionGrantIntent,
        outcome: SessionGrantOutcome,
        now: DateTime<Utc>,
    ) -> Result<Self> {
        let state = Self::from_outcome(outcome, now)?;
        if state.device_id.as_ref() != Some(&request.device_id)
            || state.audience_id != request.audience_id
            || state.account_id.station_id != request.audience_id
        {
            return Err(Error::Protocol(
                "initial session grant does not match registration intent".to_owned(),
            ));
        }
        Ok(state)
    }

    fn from_outcome(outcome: SessionGrantOutcome, now: DateTime<Utc>) -> Result<Self> {
        if outcome.session_grant.trim().is_empty() || outcome.expires_at <= now {
            return Err(Error::Protocol(
                "session grant is empty or already expired".to_owned(),
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
            dpop_jkt: None,
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct SessionRefreshOptions {
    pub request: Option<SessionGrantRefreshRequestBody>,
}

#[derive(Clone, Debug)]
pub struct SessionEngine<T, S> {
    transport: T,
    store: S,
    state: Arc<Mutex<Option<SessionGrantState>>>,
}

impl<T, S> SessionEngine<T, S>
where
    T: SessionGrantTransport,
    S: SessionGrantStore,
{
    pub fn new(transport: T, store: S) -> Result<Self> {
        let state = store.load()?;
        Ok(Self {
            transport,
            store,
            state: Arc::new(Mutex::new(state)),
        })
    }

    pub fn current(&self) -> Option<SessionGrantState> {
        self.state.lock().unwrap().clone()
    }

    pub async fn issue(&self, login: LoginKind, now: DateTime<Utc>) -> Result<SessionHandle> {
        let request = login.into_session_grant_request()?;
        let outcome = self.transport.issue_session_grant(request).await?;
        let state = SessionGrantState::from_outcome(outcome, now)?;
        self.store.save(&state).await?;
        *self.state.lock().unwrap() = Some(state.clone());
        Ok(state.handle())
    }

    pub async fn refresh_if_due(
        &self,
        options: SessionRefreshOptions,
        now: DateTime<Utc>,
    ) -> Result<Option<SessionHandle>> {
        let current = self.current();
        let refresh_state = current
            .as_ref()
            .map(|state| super::SessionGrantRefreshState {
                grant_expires_at: Some(state.expires_at),
            });
        let decision = refresh_decision(refresh_state.as_ref(), now);
        if matches!(decision, super::RefreshDecision::Fresh) {
            return Ok(current.map(|state| state.handle()));
        }
        let request = options.request.ok_or_else(|| {
            Error::Protocol(
                "session refresh is due but no bound refresh request was supplied".to_owned(),
            )
        })?;
        let outcome = self.transport.refresh_session_grant(request).await?;
        let state = SessionGrantState::from_outcome(outcome, now)?;
        if let Some(previous) = current
            && state.account_id != previous.account_id
        {
            return Err(Error::Protocol(
                "refreshed session grant changed the bound account".to_owned(),
            ));
        }
        self.store.save(&state).await?;
        *self.state.lock().unwrap() = Some(state.clone());
        Ok(Some(state.handle()))
    }

    pub fn clear(&self) -> Result<()> {
        self.store.clear()?;
        *self.state.lock().unwrap() = None;
        Ok(())
    }
}
