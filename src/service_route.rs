//! Service routes derive exclusively from independently verified DID method state.
use crate::{Error, Result};
use arkret_models_identity::{
    AuthenticatedServiceResolution, ServiceMethodState, ServiceRouteCacheEntry,
};
use arkret_wire::DidCoreId;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteForkQuarantine {
    pub reason: String,
    pub quarantined_at: DateTime<Utc>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceRouteDurableSnapshot {
    pub service_id: DidCoreId,
    pub service_kind: String,
    pub method_state: Option<ServiceMethodState>,
    pub quarantine: Option<RouteForkQuarantine>,
}
pub trait ServiceRouteStateStore {
    fn load_route_state(
        &self,
        service_id: &DidCoreId,
        service_kind: &str,
    ) -> Result<Option<ServiceRouteDurableSnapshot>>;
    fn save_route_state(&mut self, snapshot: &ServiceRouteDurableSnapshot) -> Result<()>;
}
#[derive(Clone, Debug, Default)]
pub struct MemoryServiceRouteStateStore {
    states: BTreeMap<(DidCoreId, String), ServiceRouteDurableSnapshot>,
}
impl ServiceRouteStateStore for MemoryServiceRouteStateStore {
    fn load_route_state(
        &self,
        id: &DidCoreId,
        kind: &str,
    ) -> Result<Option<ServiceRouteDurableSnapshot>> {
        Ok(self.states.get(&(id.clone(), kind.to_owned())).cloned())
    }
    fn save_route_state(&mut self, state: &ServiceRouteDurableSnapshot) -> Result<()> {
        self.states.insert(
            (state.service_id.clone(), state.service_kind.clone()),
            state.clone(),
        );
        Ok(())
    }
}
#[derive(Clone, Debug)]
pub struct ServiceRouteCandidate {
    pub resolution: AuthenticatedServiceResolution,
    /// Independently fetched through the DID method transport; never copied from the carrier.
    pub current_resolution: arkret_identity::ResolvedDid,
    pub verified_at: DateTime<Utc>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceDescribeBinding {
    pub service_id: DidCoreId,
    pub service_kind: String,
    pub base_url: String,
}
pub trait ServiceRouteSource {
    fn current_resolution(
        &mut self,
        id: &DidCoreId,
        kind: &str,
    ) -> Result<Option<ServiceRouteCandidate>>;
    fn describe(&mut self, base_url: &str) -> Result<ServiceDescribeBinding>;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteCandidateSource {
    FreshCache,
    CurrentResolution,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteResolution {
    source: RouteCandidateSource,
    route: ServiceRouteCacheEntry,
    authenticated_resolution: AuthenticatedServiceResolution,
}
impl RouteResolution {
    pub const fn source(&self) -> RouteCandidateSource {
        self.source
    }
    pub const fn route(&self) -> &ServiceRouteCacheEntry {
        &self.route
    }
    pub const fn authenticated_resolution(&self) -> &AuthenticatedServiceResolution {
        &self.authenticated_resolution
    }
}
pub struct ServiceRouteEvaluator<S> {
    store: S,
    cache: BTreeMap<(DidCoreId, String), RouteResolution>,
    cache_ttl: Duration,
}
impl<S: ServiceRouteStateStore> ServiceRouteEvaluator<S> {
    pub fn new(store: S, cache_ttl: Duration) -> Result<Self> {
        if cache_ttl <= Duration::zero() || cache_ttl > Duration::minutes(5) {
            return Err(Error::Protocol("service_route_cache_ttl_invalid".into()));
        }
        Ok(Self {
            store,
            cache: BTreeMap::new(),
            cache_ttl,
        })
    }
    pub fn store(&self) -> &S {
        &self.store
    }
    pub fn resolve<R: ServiceRouteSource>(
        &mut self,
        id: &DidCoreId,
        kind: &str,
        now: DateTime<Utc>,
        source: &mut R,
    ) -> Result<RouteResolution> {
        let key = (id.clone(), kind.to_owned());
        let mut durable =
            self.store
                .load_route_state(id, kind)?
                .unwrap_or(ServiceRouteDurableSnapshot {
                    service_id: id.clone(),
                    service_kind: kind.to_owned(),
                    method_state: None,
                    quarantine: None,
                });
        if durable.service_id != *id || durable.service_kind != kind {
            return Err(Error::Protocol(
                "service_route_state_identity_mismatch".into(),
            ));
        }
        if durable.quarantine.is_some() {
            return Err(Error::Protocol("service_route_fork_quarantined".into()));
        }
        if let Some(cached) = self.cache.get(&key) {
            if cached.route.is_routable_at(now)
                && durable.method_state.as_ref().is_some_and(|state| {
                    state.method_history_head == cached.route.method_history_head
                        && state.version_id == cached.route.version_id
                        && state.did == cached.route.did
                })
            {
                let mut result = cached.clone();
                result.source = RouteCandidateSource::FreshCache;
                return Ok(result);
            }
        }
        self.cache.remove(&key);
        let candidate = source
            .current_resolution(id, kind)?
            .ok_or_else(|| Error::Protocol("service_route_unresolved".into()))?;
        if candidate.verified_at > now || now >= candidate.verified_at + self.cache_ttl {
            return Err(Error::Protocol(
                "service_route_current_evidence_expired".into(),
            ));
        }
        let projection = arkret_identity::verify_current_service_resolution(
            &candidate.resolution,
            id,
            kind,
            &candidate.current_resolution,
            now,
        )
        .map_err(|e| Error::Protocol(e.to_string()))?;
        if let Some(state) = &durable.method_state {
            if let Err(error) =
                arkret_identity::verify_service_resolution_floor(&candidate.resolution, state)
            {
                durable.quarantine = Some(RouteForkQuarantine {
                    reason: error.to_string(),
                    quarantined_at: now,
                });
                self.store.save_route_state(&durable)?;
                return Err(Error::Protocol(error.to_string()));
            }
        }
        let describe = source.describe(&projection.base_url)?;
        if describe.service_id != *id
            || describe.service_kind != kind
            || describe.base_url != projection.base_url
        {
            return Err(Error::Protocol(
                "service_route_describe_reverse_binding_mismatch".into(),
            ));
        }
        let route = ServiceRouteCacheEntry {
            service_id: id.clone(),
            service_kind: kind.to_owned(),
            did: projection.did.clone(),
            method_history_head: projection.method_history_head.clone(),
            version_id: projection.version_id.clone(),
            base_url: projection.base_url,
            verified_at: candidate.verified_at,
            cache_expires_at: candidate.verified_at + self.cache_ttl,
        };
        durable.method_state = Some(ServiceMethodState {
            service_id: id.clone(),
            service_kind: kind.to_owned(),
            did: projection.did,
            method_history_head: projection.method_history_head,
            version_id: projection.version_id,
            verified_at: candidate.verified_at,
        });
        self.store.save_route_state(&durable)?;
        let result = RouteResolution {
            source: RouteCandidateSource::CurrentResolution,
            route,
            authenticated_resolution: candidate.resolution,
        };
        self.cache.insert(key, result.clone());
        Ok(result)
    }
}
