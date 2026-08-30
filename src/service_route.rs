//! Single shared evaluator and cache owner for service route resolution.

use std::collections::BTreeMap;

use arkret_models_identity::{
    AuthenticatedServiceResolution, ServiceResolutionLastSeenFloor, ServiceRouteCacheEntry,
    ServiceRouteHandoverNotice, ServiceRouteHandoverState, ServiceRouteNoticeState,
};
use arkret_wire::{DidCoreId, Hash};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::{Error, Result};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteForkQuarantine {
    pub service_id: DidCoreId,
    pub service_kind: String,
    pub expected_sequence: u64,
    pub expected_digest: Hash,
    pub observed_sequence: u64,
    pub observed_digest: Hash,
    pub reason: String,
    pub quarantined_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceRouteDurableSnapshot {
    pub service_id: DidCoreId,
    pub service_kind: String,
    pub floor: Option<ServiceResolutionLastSeenFloor>,
    pub notice: Option<ServiceRouteNoticeState>,
    pub quarantine: Option<RouteForkQuarantine>,
}

impl ServiceRouteDurableSnapshot {
    fn empty(service_id: DidCoreId, service_kind: String) -> Self {
        Self {
            service_id,
            service_kind,
            floor: None,
            notice: None,
            quarantine: None,
        }
    }
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
        service_id: &DidCoreId,
        service_kind: &str,
    ) -> Result<Option<ServiceRouteDurableSnapshot>> {
        Ok(self
            .states
            .get(&(service_id.clone(), service_kind.to_owned()))
            .cloned())
    }

    fn save_route_state(&mut self, snapshot: &ServiceRouteDurableSnapshot) -> Result<()> {
        self.states.insert(
            (snapshot.service_id.clone(), snapshot.service_kind.clone()),
            snapshot.clone(),
        );
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct ServiceRouteCandidate {
    pub resolution: AuthenticatedServiceResolution,
}

#[derive(Clone, Debug)]
pub struct ServiceRouteNoticeCandidate {
    /// Fresh, independently authenticated record whose DID document verifies
    /// the notice. This cannot be a transport assertion.
    pub authority_resolution: AuthenticatedServiceResolution,
    pub notice: ServiceRouteHandoverNotice,
    pub successor: Option<ServiceRouteCandidate>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceDescribeBinding {
    pub service_id: DidCoreId,
    pub service_kind: String,
    pub base_url: String,
    pub describe_digest: Hash,
}

pub trait ServiceRouteSource {
    /// Run the registered DID-method adapter and witness/freshness policy over
    /// the exact history evidence and normalized document in this resolution.
    fn verify_method_history(
        &mut self,
        resolution: &AuthenticatedServiceResolution,
        now: DateTime<Utc>,
    ) -> Result<()>;

    fn current_record(
        &mut self,
        service_id: &DidCoreId,
        service_kind: &str,
    ) -> Result<Option<ServiceRouteCandidate>>;

    fn active_notice(
        &mut self,
        service_id: &DidCoreId,
        service_kind: &str,
    ) -> Result<Option<ServiceRouteNoticeCandidate>>;

    fn realm_peer_mirror(
        &mut self,
        service_id: &DidCoreId,
        service_kind: &str,
        floor: Option<&ServiceResolutionLastSeenFloor>,
    ) -> Result<Option<ServiceRouteCandidate>>;

    fn external_mirror(
        &mut self,
        service_id: &DidCoreId,
        service_kind: &str,
        floor: Option<&ServiceResolutionLastSeenFloor>,
    ) -> Result<Option<ServiceRouteCandidate>>;

    fn describe(&mut self, base_url: &str) -> Result<ServiceDescribeBinding>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteCandidateSource {
    FreshCache,
    CurrentRecord,
    ActiveNotice,
    RealmPeerMirror,
    ExternalMirror,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteResolution {
    source: RouteCandidateSource,
    route: ServiceRouteCacheEntry,
    authenticated_resolution: AuthenticatedServiceResolution,
}

impl RouteResolution {
    #[must_use]
    pub const fn source(&self) -> RouteCandidateSource {
        self.source
    }

    #[must_use]
    pub const fn route(&self) -> &ServiceRouteCacheEntry {
        &self.route
    }

    /// Exact authenticated record, method-history evidence and normalized DID
    /// document accepted by this evaluator. Keeping this material behind the
    /// evaluator-produced token prevents consumers from supplying an
    /// unverified DID or an unrelated DID document as service authority.
    #[must_use]
    pub const fn authenticated_resolution(&self) -> &AuthenticatedServiceResolution {
        &self.authenticated_resolution
    }
}

#[derive(Clone, Debug)]
struct CachedRouteResolution {
    route: ServiceRouteCacheEntry,
    authenticated_resolution: AuthenticatedServiceResolution,
}

pub struct ServiceRouteEvaluator<S> {
    store: S,
    cache: BTreeMap<(DidCoreId, String), CachedRouteResolution>,
    cache_ttl: Duration,
    external_mirror_enabled: bool,
}

impl<S> ServiceRouteEvaluator<S>
where
    S: ServiceRouteStateStore,
{
    pub fn new(store: S, cache_ttl: Duration) -> Result<Self> {
        if cache_ttl <= Duration::zero() {
            return Err(Error::Protocol(
                "service_route_cache_ttl_invalid".to_owned(),
            ));
        }
        Ok(Self {
            store,
            cache: BTreeMap::new(),
            cache_ttl,
            external_mirror_enabled: false,
        })
    }

    #[must_use]
    pub fn with_external_mirror(mut self, enabled: bool) -> Self {
        self.external_mirror_enabled = enabled;
        self
    }

    pub fn store(&self) -> &S {
        &self.store
    }

    /// Resolve in the normative order. Invalid signed material is terminal and
    /// never downgraded to a later source; unavailable sources return `None`.
    pub fn resolve<R: ServiceRouteSource>(
        &mut self,
        service_id: &DidCoreId,
        service_kind: &str,
        now: DateTime<Utc>,
        source: &mut R,
    ) -> Result<RouteResolution> {
        let key = (service_id.clone(), service_kind.to_owned());
        let mut durable = self
            .store
            .load_route_state(service_id, service_kind)?
            .unwrap_or_else(|| {
                ServiceRouteDurableSnapshot::empty(service_id.clone(), service_kind.to_owned())
            });
        validate_snapshot_identity(&durable, service_id, service_kind)?;
        if durable.quarantine.is_some() {
            return Err(Error::Protocol("service_route_fork_quarantined".to_owned()));
        }
        if let Some(cached) = self.cache.get(&key)
            && cached.route.is_routable_at(now)
            && cache_matches_floor(&cached.route, durable.floor.as_ref())
        {
            return Ok(RouteResolution {
                source: RouteCandidateSource::FreshCache,
                route: cached.route.clone(),
                authenticated_resolution: cached.authenticated_resolution.clone(),
            });
        }
        self.cache.remove(&key);

        if let Some(candidate) = source.current_record(service_id, service_kind)? {
            return self.accept_candidate(
                &mut durable,
                candidate,
                RouteCandidateSource::CurrentRecord,
                true,
                now,
                source,
            );
        }

        if let Some(notice_candidate) = source.active_notice(service_id, service_kind)?
            && let Some(candidate) = self.verify_notice_candidate(
                &mut durable,
                notice_candidate,
                service_id,
                service_kind,
                now,
                source,
            )?
        {
            return self.accept_candidate(
                &mut durable,
                candidate,
                RouteCandidateSource::ActiveNotice,
                false,
                now,
                source,
            );
        }

        if let Some(candidate) =
            source.realm_peer_mirror(service_id, service_kind, durable.floor.as_ref())?
        {
            return self.accept_candidate(
                &mut durable,
                candidate,
                RouteCandidateSource::RealmPeerMirror,
                false,
                now,
                source,
            );
        }

        if self.external_mirror_enabled
            && let Some(candidate) =
                source.external_mirror(service_id, service_kind, durable.floor.as_ref())?
        {
            return self.accept_candidate(
                &mut durable,
                candidate,
                RouteCandidateSource::ExternalMirror,
                false,
                now,
                source,
            );
        }
        Err(Error::Protocol("service_route_unresolved".to_owned()))
    }

    fn verify_notice_candidate<R: ServiceRouteSource>(
        &mut self,
        durable: &mut ServiceRouteDurableSnapshot,
        candidate: ServiceRouteNoticeCandidate,
        service_id: &DidCoreId,
        service_kind: &str,
        now: DateTime<Utc>,
        source: &mut R,
    ) -> Result<Option<ServiceRouteCandidate>> {
        source.verify_method_history(&candidate.authority_resolution, now)?;
        arkret_signatures::service_resolution::verify_authenticated_service_resolution(
            &candidate.authority_resolution,
            service_id,
            now,
        )?;
        let authority_record = &candidate.authority_resolution.service_resolution_record;
        let authority_digest = record_digest(authority_record)?;
        if durable.floor.is_none() {
            return Err(Error::Protocol(
                "service_route_notice_requires_durable_floor".to_owned(),
            ));
        }
        let authority_is_floor = durable.floor.as_ref().is_some_and(|floor| {
            floor.record_sequence == authority_record.record.record_sequence
                && floor.record_digest == authority_digest
        });
        if authority_record.record.service_kind != service_kind
            || candidate.notice.notice.service_kind != service_kind
            || !authority_is_floor
            || candidate.notice.notice.from_record_sequence
                != authority_record.record.record_sequence
            || candidate.notice.notice.from_record_digest != authority_digest
        {
            return self.quarantine(
                durable,
                authority_record.record.record_sequence,
                authority_digest,
                "service_route_notice_authority_mismatch",
                now,
            );
        }
        arkret_signatures::service_resolution::verify_service_route_handover_notice(
            &candidate.notice,
            &candidate.authority_resolution.normalized_did_document,
            service_id,
            now,
        )?;
        let notice_digest = Hash::new(arkret_canonical::canonical_sha256(&candidate.notice)?)?;
        if validate_notice_chain(durable.notice.as_ref(), &candidate.notice, &notice_digest)
            .is_err()
        {
            return self.quarantine(
                durable,
                authority_record.record.record_sequence,
                authority_digest,
                "service_route_notice_gap_or_fork",
                now,
            );
        }
        durable.notice = Some(ServiceRouteNoticeState {
            service_id: service_id.clone(),
            service_kind: service_kind.to_owned(),
            handover_id: candidate.notice.notice.handover_id.clone(),
            notice_revision: candidate.notice.notice.notice_revision,
            notice_digest,
            state: candidate.notice.notice.state,
            from_record_sequence: candidate.notice.notice.from_record_sequence,
            from_record_digest: candidate.notice.notice.from_record_digest.clone(),
            expires_at: candidate.notice.notice.expires_at,
            verified_at: now,
        });
        self.store.save_route_state(durable)?;
        if candidate.notice.notice.state == ServiceRouteHandoverState::Cancelled {
            return Ok(None);
        }
        let not_before = candidate
            .notice
            .notice
            .not_before
            .expect("scheduled notice shape was verified");
        if now < not_before {
            return Ok(None);
        }
        let successor = candidate
            .successor
            .ok_or_else(|| Error::Protocol("service_route_notice_successor_missing".to_owned()))?;
        let record = &successor.resolution.service_resolution_record.record;
        if candidate.notice.notice.candidate_base_url.as_deref() != Some(record.base_url.as_str())
            || candidate.notice.notice.candidate_record_url.as_deref()
                != Some(record.current_record_url.as_str())
        {
            return Err(Error::Protocol(
                "service_route_notice_candidate_binding_mismatch".to_owned(),
            ));
        }
        Ok(Some(successor))
    }

    #[allow(clippy::too_many_arguments)]
    fn accept_candidate<R: ServiceRouteSource>(
        &mut self,
        durable: &mut ServiceRouteDurableSnapshot,
        candidate: ServiceRouteCandidate,
        candidate_source: RouteCandidateSource,
        allow_initial_anchor: bool,
        now: DateTime<Utc>,
        source: &mut R,
    ) -> Result<RouteResolution> {
        let record = &candidate.resolution.service_resolution_record;
        validate_candidate_identity(
            &durable.service_id,
            &durable.service_kind,
            &record.record.service_id,
            &record.record.service_kind,
        )?;
        source.verify_method_history(&candidate.resolution, now)?;
        arkret_signatures::service_resolution::verify_authenticated_service_resolution(
            &candidate.resolution,
            &durable.service_id,
            now,
        )?;
        let digest = record_digest(record)?;
        match durable.floor.as_ref() {
            Some(floor)
                if record.record.record_sequence == floor.record_sequence
                    && digest == floor.record_digest => {}
            Some(floor)
                if record.record.record_sequence == floor.record_sequence + 1
                    && record.record.previous_record_digest.as_ref()
                        == Some(&floor.record_digest) => {}
            Some(_) => {
                return self.quarantine(
                    durable,
                    record.record.record_sequence,
                    digest,
                    "service_route_gap_or_fork",
                    now,
                );
            }
            None if allow_initial_anchor => {}
            None => {
                return Err(Error::Protocol(
                    "service_route_mirror_requires_durable_floor".to_owned(),
                ));
            }
        }
        let describe = source.describe(&record.record.base_url)?;
        if describe.service_id != durable.service_id
            || describe.service_kind != durable.service_kind
            || describe.base_url != record.record.base_url
            || describe.describe_digest != record.record.describe_digest
        {
            return Err(Error::Protocol(
                "service_route_describe_reverse_binding_mismatch".to_owned(),
            ));
        }
        let cache_expires_at = (now + self.cache_ttl)
            .min(record.record.refresh_after)
            .min(record.record.expires_at);
        let route = ServiceRouteCacheEntry {
            service_id: durable.service_id.clone(),
            service_kind: durable.service_kind.clone(),
            did: record.record.did.clone(),
            method_history_head: record.record.method_history_head.clone(),
            version_id: record.record.version_id.clone(),
            record_sequence: record.record.record_sequence,
            record_digest: digest.clone(),
            base_url: record.record.base_url.clone(),
            current_record_url: record.record.current_record_url.clone(),
            describe_digest: record.record.describe_digest.clone(),
            verified_at: now,
            refresh_after: record.record.refresh_after,
            expires_at: record.record.expires_at,
            cached_at: now,
            cache_expires_at,
        };
        durable.floor = Some(ServiceResolutionLastSeenFloor {
            service_id: durable.service_id.clone(),
            service_kind: durable.service_kind.clone(),
            record_sequence: record.record.record_sequence,
            record_digest: digest,
            verified_at: now,
        });
        self.store.save_route_state(durable)?;
        let authenticated_resolution = candidate.resolution;
        self.cache.insert(
            (durable.service_id.clone(), durable.service_kind.clone()),
            CachedRouteResolution {
                route: route.clone(),
                authenticated_resolution: authenticated_resolution.clone(),
            },
        );
        Ok(RouteResolution {
            source: candidate_source,
            route,
            authenticated_resolution,
        })
    }

    fn quarantine<T>(
        &mut self,
        durable: &mut ServiceRouteDurableSnapshot,
        observed_sequence: u64,
        observed_digest: Hash,
        reason: &str,
        now: DateTime<Utc>,
    ) -> Result<T> {
        let floor = durable
            .floor
            .as_ref()
            .ok_or_else(|| Error::Protocol("service_route_quarantine_without_floor".to_owned()))?;
        durable.quarantine = Some(RouteForkQuarantine {
            service_id: durable.service_id.clone(),
            service_kind: durable.service_kind.clone(),
            expected_sequence: floor.record_sequence,
            expected_digest: floor.record_digest.clone(),
            observed_sequence,
            observed_digest,
            reason: reason.to_owned(),
            quarantined_at: now,
        });
        self.store.save_route_state(durable)?;
        Err(Error::Protocol(reason.to_owned()))
    }
}

fn validate_snapshot_identity(
    snapshot: &ServiceRouteDurableSnapshot,
    service_id: &DidCoreId,
    service_kind: &str,
) -> Result<()> {
    let floor_mismatch = snapshot
        .floor
        .as_ref()
        .is_some_and(|floor| &floor.service_id != service_id || floor.service_kind != service_kind);
    let notice_mismatch = snapshot.notice.as_ref().is_some_and(|notice| {
        &notice.service_id != service_id || notice.service_kind != service_kind
    });
    let quarantine_mismatch = snapshot.quarantine.as_ref().is_some_and(|quarantine| {
        &quarantine.service_id != service_id || quarantine.service_kind != service_kind
    });
    if &snapshot.service_id != service_id
        || snapshot.service_kind != service_kind
        || floor_mismatch
        || notice_mismatch
        || quarantine_mismatch
    {
        return Err(Error::Protocol(
            "service_route_snapshot_identity_mismatch".to_owned(),
        ));
    }
    Ok(())
}

fn validate_candidate_identity(
    expected_service_id: &DidCoreId,
    expected_service_kind: &str,
    observed_service_id: &DidCoreId,
    observed_service_kind: &str,
) -> Result<()> {
    if observed_service_id != expected_service_id {
        return Err(Error::Protocol(
            "service_route_service_id_mismatch".to_owned(),
        ));
    }
    if observed_service_kind != expected_service_kind {
        return Err(Error::Protocol(
            "service_route_service_kind_mismatch".to_owned(),
        ));
    }
    Ok(())
}

fn cache_matches_floor(
    cache: &ServiceRouteCacheEntry,
    floor: Option<&ServiceResolutionLastSeenFloor>,
) -> bool {
    floor.is_some_and(|floor| {
        cache.service_id == floor.service_id
            && cache.service_kind == floor.service_kind
            && cache.record_sequence == floor.record_sequence
            && cache.record_digest == floor.record_digest
    })
}

fn record_digest(record: &arkret_models_identity::ServiceResolutionRecord) -> Result<Hash> {
    Ok(Hash::new(arkret_canonical::canonical_sha256(record)?)?)
}

fn validate_notice_chain(
    previous: Option<&ServiceRouteNoticeState>,
    notice: &ServiceRouteHandoverNotice,
    digest: &Hash,
) -> Result<()> {
    let Some(previous) = previous else {
        if notice.notice.notice_revision != 0 {
            return Err(Error::Protocol(
                "service_route_notice_history_missing".to_owned(),
            ));
        }
        return Ok(());
    };
    if notice.notice.handover_id != previous.handover_id
        || notice.notice.notice_revision != previous.notice_revision + 1
        || notice.notice.previous_notice_digest.as_ref() != Some(&previous.notice_digest)
        || digest == &previous.notice_digest
    {
        return Err(Error::Protocol(
            "service_route_notice_gap_or_fork".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    use arkret_models_identity::{
        DidDocument, ResolutionDidBindingEvidenceKind, ResolutionDidBindingEvidenceReceipt,
        ResolutionMethodEvidenceBoundary, ResolutionMethodHistoryEvidence,
        ServiceResolutionRecordCore,
    };
    use arkret_wire::{Did, DidUrl};
    use chrono::TimeZone as _;
    use ed25519_dalek::SigningKey;

    use super::*;

    fn hash(byte: char) -> Hash {
        Hash::new(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
    }

    fn route_fixture(service_kind: &str) -> AuthenticatedServiceResolution {
        let signing_key = SigningKey::from_bytes(&[31_u8; 32]);
        let did = Did::new("did:web:media.example").unwrap();
        let service_id = arkret_wire::project_did_to_core_id(&did).unwrap();
        let method = DidUrl::new(format!("{did}#signing-1")).unwrap();
        let document = DidDocument {
            id: did.clone(),
            verification_methods: BTreeMap::from([(
                method.to_string(),
                arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                    signing_key.verifying_key().as_bytes(),
                ),
            )]),
            also_known_as: Vec::new(),
            updated_at: None,
            raw_properties: BTreeMap::from([(
                "assertionMethod".to_owned(),
                serde_json::json!([method]),
            )]),
        };
        let issued_at = Utc.with_ymd_and_hms(2026, 8, 11, 1, 0, 0).unwrap();
        let record = arkret_signatures::service_resolution::sign_service_resolution_record(
            ServiceResolutionRecordCore {
                service_id,
                service_kind: service_kind.to_owned(),
                did,
                method_history_head: "did-web-document-sha256:fixture".to_owned(),
                version_id: "did-web-document-sha256:fixture".to_owned(),
                resolution_event_ref: format!("did-web-document-sha256:{}", "1".repeat(64)),
                record_sequence: 0,
                previous_record_digest: None,
                current_record_url: "https://media.example/_arkret/open/services/ak%3Adid_core%3Aweb%3Amedia.example/resolution".to_owned(),
                base_url: "https://media.example/".to_owned(),
                describe_digest: hash('2'),
                issued_at,
                refresh_after: issued_at + Duration::minutes(5),
                expires_at: issued_at + Duration::minutes(10),
            },
            method,
            &signing_key,
        )
        .unwrap();
        let document_digest =
            Hash::new(arkret_canonical::canonical_sha256(&document).unwrap()).unwrap();
        AuthenticatedServiceResolution {
            service_resolution_record: record,
            method_history_evidence: ResolutionMethodHistoryEvidence::DidWebDocument {
                adapter_version: "did:web:1".to_owned(),
                boundary: ResolutionMethodEvidenceBoundary {
                    from_method_history_head: "did-web-document-sha256:fixture".to_owned(),
                    from_version_id: "did-web-document-sha256:fixture".to_owned(),
                    to_method_history_head: "did-web-document-sha256:fixture".to_owned(),
                    to_version_id: "did-web-document-sha256:fixture".to_owned(),
                },
                evidence: ResolutionDidBindingEvidenceReceipt {
                    kind: ResolutionDidBindingEvidenceKind::AkDidBindingEvidenceV1,
                    method: "web".to_owned(),
                    document_digest,
                    method_proofs: Vec::new(),
                },
            },
            normalized_did_document: document,
        }
    }

    struct FixtureSource {
        candidate: Option<ServiceRouteCandidate>,
        calls: Vec<&'static str>,
    }

    impl ServiceRouteSource for FixtureSource {
        fn verify_method_history(
            &mut self,
            _: &AuthenticatedServiceResolution,
            _: DateTime<Utc>,
        ) -> Result<()> {
            Ok(())
        }

        fn current_record(
            &mut self,
            _: &DidCoreId,
            _: &str,
        ) -> Result<Option<ServiceRouteCandidate>> {
            self.calls.push("current");
            Ok(self.candidate.take())
        }

        fn active_notice(
            &mut self,
            _: &DidCoreId,
            _: &str,
        ) -> Result<Option<ServiceRouteNoticeCandidate>> {
            self.calls.push("notice");
            Ok(None)
        }

        fn realm_peer_mirror(
            &mut self,
            _: &DidCoreId,
            _: &str,
            _: Option<&ServiceResolutionLastSeenFloor>,
        ) -> Result<Option<ServiceRouteCandidate>> {
            self.calls.push("realm");
            Ok(None)
        }

        fn external_mirror(
            &mut self,
            _: &DidCoreId,
            _: &str,
            _: Option<&ServiceResolutionLastSeenFloor>,
        ) -> Result<Option<ServiceRouteCandidate>> {
            self.calls.push("external");
            Ok(None)
        }

        fn describe(&mut self, base_url: &str) -> Result<ServiceDescribeBinding> {
            let resolution = route_fixture("media_service");
            Ok(ServiceDescribeBinding {
                service_id: resolution.service_resolution_record.record.service_id,
                service_kind: "media_service".to_owned(),
                base_url: base_url.to_owned(),
                describe_digest: hash('2'),
            })
        }
    }

    #[test]
    fn evaluator_token_preserves_exact_authenticated_material_in_fresh_cache() {
        let resolution = route_fixture("media_service");
        let service_id = resolution
            .service_resolution_record
            .record
            .service_id
            .clone();
        let now = resolution.service_resolution_record.record.issued_at;
        let mut source = FixtureSource {
            candidate: Some(ServiceRouteCandidate { resolution }),
            calls: Vec::new(),
        };
        let mut evaluator = ServiceRouteEvaluator::new(
            MemoryServiceRouteStateStore::default(),
            Duration::minutes(1),
        )
        .unwrap();
        let first = evaluator
            .resolve(&service_id, "media_service", now, &mut source)
            .unwrap();
        assert_eq!(first.source(), RouteCandidateSource::CurrentRecord);
        assert_eq!(
            first.authenticated_resolution().normalized_did_document.id,
            first.route().did
        );

        source.calls.clear();
        let cached = evaluator
            .resolve(&service_id, "media_service", now, &mut source)
            .unwrap();
        assert_eq!(cached.source(), RouteCandidateSource::FreshCache);
        assert_eq!(
            cached.authenticated_resolution(),
            first.authenticated_resolution()
        );
        assert!(source.calls.is_empty());
    }

    #[test]
    fn fresh_cache_must_equal_the_durable_floor() {
        let service_id = DidCoreId::new("ak:did_core:web:service.example").unwrap();
        let now = Utc::now();
        let floor = ServiceResolutionLastSeenFloor {
            service_id: service_id.clone(),
            service_kind: "station".to_owned(),
            record_sequence: 4,
            record_digest: hash('1'),
            verified_at: now,
        };
        let cache = ServiceRouteCacheEntry {
            service_id,
            service_kind: "station".to_owned(),
            did: arkret_wire::Did::new("did:web:service.example").unwrap(),
            method_history_head: "head".to_owned(),
            version_id: "version".to_owned(),
            record_sequence: 3,
            record_digest: hash('1'),
            base_url: "https://service.example/".to_owned(),
            current_record_url: "https://service.example/current".to_owned(),
            describe_digest: hash('2'),
            verified_at: now,
            refresh_after: now + Duration::minutes(1),
            expires_at: now + Duration::minutes(2),
            cached_at: now,
            cache_expires_at: now + Duration::minutes(1),
        };
        assert!(!cache_matches_floor(&cache, Some(&floor)));
    }

    #[test]
    fn restart_store_preserves_floor_and_quarantine() {
        let service_id = DidCoreId::new("ak:did_core:web:service.example").unwrap();
        let now = Utc::now();
        let snapshot = ServiceRouteDurableSnapshot {
            service_id: service_id.clone(),
            service_kind: "station".to_owned(),
            floor: Some(ServiceResolutionLastSeenFloor {
                service_id: service_id.clone(),
                service_kind: "station".to_owned(),
                record_sequence: 7,
                record_digest: hash('7'),
                verified_at: now,
            }),
            notice: None,
            quarantine: Some(RouteForkQuarantine {
                service_id: service_id.clone(),
                service_kind: "station".to_owned(),
                expected_sequence: 7,
                expected_digest: hash('7'),
                observed_sequence: 7,
                observed_digest: hash('8'),
                reason: "fork".to_owned(),
                quarantined_at: now,
            }),
        };
        let mut store = MemoryServiceRouteStateStore::default();
        store.save_route_state(&snapshot).unwrap();
        assert_eq!(
            store.load_route_state(&service_id, "station").unwrap(),
            Some(snapshot)
        );
    }

    struct EmptySource {
        calls: RefCell<Vec<&'static str>>,
    }

    impl ServiceRouteSource for EmptySource {
        fn verify_method_history(
            &mut self,
            _: &AuthenticatedServiceResolution,
            _: DateTime<Utc>,
        ) -> Result<()> {
            unreachable!()
        }

        fn current_record(
            &mut self,
            _: &DidCoreId,
            _: &str,
        ) -> Result<Option<ServiceRouteCandidate>> {
            self.calls.borrow_mut().push("current");
            Ok(None)
        }

        fn active_notice(
            &mut self,
            _: &DidCoreId,
            _: &str,
        ) -> Result<Option<ServiceRouteNoticeCandidate>> {
            self.calls.borrow_mut().push("notice");
            Ok(None)
        }

        fn realm_peer_mirror(
            &mut self,
            _: &DidCoreId,
            _: &str,
            _: Option<&ServiceResolutionLastSeenFloor>,
        ) -> Result<Option<ServiceRouteCandidate>> {
            self.calls.borrow_mut().push("realm");
            Ok(None)
        }

        fn external_mirror(
            &mut self,
            _: &DidCoreId,
            _: &str,
            _: Option<&ServiceResolutionLastSeenFloor>,
        ) -> Result<Option<ServiceRouteCandidate>> {
            self.calls.borrow_mut().push("external");
            Ok(None)
        }

        fn describe(&mut self, _: &str) -> Result<ServiceDescribeBinding> {
            unreachable!()
        }
    }

    #[test]
    fn evaluator_queries_route_sources_in_normative_order() {
        let service_id = DidCoreId::new("ak:did_core:web:service.example").unwrap();
        let mut evaluator = ServiceRouteEvaluator::new(
            MemoryServiceRouteStateStore::default(),
            Duration::minutes(1),
        )
        .unwrap()
        .with_external_mirror(true);
        let mut source = EmptySource {
            calls: RefCell::new(Vec::new()),
        };
        assert!(
            evaluator
                .resolve(&service_id, "station", Utc::now(), &mut source)
                .is_err()
        );
        assert_eq!(
            source.calls.into_inner(),
            vec!["current", "notice", "realm", "external"]
        );
    }

    #[test]
    fn route_candidates_must_keep_the_expected_service_id() {
        let expected = DidCoreId::new("ak:did_core:web:service.example").unwrap();
        let replacement = DidCoreId::new("ak:did_core:web:replacement.example").unwrap();
        assert!(validate_candidate_identity(&expected, "station", &expected, "station").is_ok());
        let error =
            validate_candidate_identity(&expected, "station", &replacement, "station").unwrap_err();
        assert!(error.to_string().contains("service_id_mismatch"));
    }
}
