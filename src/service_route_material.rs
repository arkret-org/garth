//! Materialize complete DID evidence and independently fetched current state.
use std::collections::BTreeMap;

use arkret_models_discovery::ServiceDescribe;
use arkret_models_identity::AuthenticatedServiceResolution;
use arkret_wire::DidCoreId;
use chrono::{DateTime, Utc};

use crate::service_route::{ServiceDescribeBinding, ServiceRouteCandidate, ServiceRouteSource};
use crate::{Error, Result};

pub fn authenticate_fetched_resolution(
    resolution: AuthenticatedServiceResolution,
    current_resolution: arkret_identity::ResolvedDid,
    now: DateTime<Utc>,
) -> Result<ServiceRouteCandidate> {
    arkret_identity::verify_current_service_resolution(
        &resolution,
        &resolution.service_id,
        &resolution.service_kind,
        &current_resolution,
        now,
    )
    .map_err(|e| Error::Protocol(e.to_string()))?;
    Ok(ServiceRouteCandidate {
        resolution,
        current_resolution,
        verified_at: now,
    })
}
pub fn describe_route_binding(
    resolution: &AuthenticatedServiceResolution,
    description: &ServiceDescribe,
    _now: DateTime<Utc>,
) -> Result<ServiceDescribeBinding> {
    let projection = resolution.projection()?;
    description
        .validate_route_projection(&projection)
        .map_err(|error| Error::Protocol(error.to_string()))?;
    Ok(ServiceDescribeBinding {
        service_id: projection.service_id,
        service_kind: projection.service_kind,
        base_url: projection.base_url,
    })
}
#[derive(Debug, Default)]
pub struct PrefetchedRouteSource {
    current: Option<ServiceRouteCandidate>,
    describes: BTreeMap<String, ServiceDescribeBinding>,
}
impl PrefetchedRouteSource {
    pub fn new(current: Option<ServiceRouteCandidate>) -> Self {
        Self {
            current,
            describes: BTreeMap::new(),
        }
    }
    pub fn insert_describe(&mut self, describe: ServiceDescribeBinding) {
        self.describes.insert(describe.base_url.clone(), describe);
    }
}
impl ServiceRouteSource for PrefetchedRouteSource {
    fn current_resolution(
        &mut self,
        id: &DidCoreId,
        kind: &str,
    ) -> Result<Option<ServiceRouteCandidate>> {
        let candidate = self.current.take();
        if candidate
            .as_ref()
            .is_some_and(|c| c.resolution.service_id != *id || c.resolution.service_kind != kind)
        {
            return Err(Error::Protocol(
                "service_route_prefetched_candidate_identity_mismatch".into(),
            ));
        }
        Ok(candidate)
    }
    fn describe(&mut self, base: &str) -> Result<ServiceDescribeBinding> {
        self.describes
            .get(base)
            .cloned()
            .ok_or_else(|| Error::Protocol("service_route_describe_not_prefetched".into()))
    }
}

/// Current-document fixtures explicitly model the no-history did:web policy.
#[cfg(any(test, feature = "route-material-test-support"))]
pub mod test_fixture {
    use arkret_models_discovery::TransportBinding;
    use arkret_models_identity::{DidDocument, ResolutionCommitment};
    use arkret_wire::{Did, ServiceKind, TrustDomainId};
    use ed25519_dalek::SigningKey;

    use super::*;
    pub struct CurrentRouteFixture {
        pub service_id: DidCoreId,
        pub resolution: AuthenticatedServiceResolution,
        pub document: DidDocument,
        pub describe: ServiceDescribe,
        pub signing_key: SigningKey,
    }
    pub fn current_web_route_fixture(host: &str, kind: &str, key_seed: u8) -> CurrentRouteFixture {
        let signing_key = SigningKey::from_bytes(&[key_seed; 32]);
        let did = Did::new(format!("did:web:{host}")).unwrap();
        let service_id = arkret_wire::project_did_to_core_id(&did).unwrap();
        let method = format!("{did}#signing-1");
        let base = format!("https://{host}/");
        let document = DidDocument {
            id: did.clone(),
            verification_methods: BTreeMap::from([(
                method.clone(),
                arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                    signing_key.verifying_key().as_bytes(),
                ),
            )]),
            also_known_as: vec![],
            updated_at: None,
            raw_properties: BTreeMap::from([
                ("assertionMethod".into(), serde_json::json!([method])),
                (
                    "service".into(),
                    serde_json::json!([{"id":format!("{did}#arkret"),"type":"ArkretService","serviceKind":kind,"serviceEndpoint":base}]),
                ),
            ]),
        };
        let resolution = arkret_identity::build_authenticated_did_web_service_resolution(
            service_id.clone(),
            kind.into(),
            document.clone(),
            Utc::now(),
        )
        .unwrap();
        let projection = resolution.projection().unwrap();
        let commitment = ResolutionCommitment {
            did: did.clone(),
            method_history_head: projection.method_history_head,
            version_id: projection.version_id,
        };
        let registered = ServiceKind::ALL
            .iter()
            .copied()
            .find(|k| k.as_str() == kind)
            .unwrap();
        let mut describe = ServiceDescribe::development(
            did,
            TrustDomainId::new(format!("ak:trust_domain:{host}")).unwrap(),
            registered,
            vec![format!("ak.operation_bundle.{kind}.describe.v1")],
            vec![TransportBinding::HttpJson {
                base_url: base,
                extension_profile_required: (),
            }],
        );
        describe.service_resolution = commitment;
        CurrentRouteFixture {
            service_id,
            resolution,
            document,
            describe,
            signing_key,
        }
    }
}
#[cfg(test)]
mod tests {
    use chrono::Duration;
    use test_fixture::current_web_route_fixture;

    use super::*;
    use crate::{MemoryServiceRouteStateStore, ServiceRouteEvaluator};
    #[test]
    fn refresh_after_many_cache_periods_and_restart_needs_no_address_history() {
        let fixture = current_web_route_fixture("media.example", "media_service", 31);
        let now = Utc::now();
        let mut evaluator = ServiceRouteEvaluator::new(
            MemoryServiceRouteStateStore::default(),
            Duration::minutes(1),
        )
        .unwrap();
        for at in [now, now + Duration::hours(1), now + Duration::days(2)] {
            let candidate = authenticate_fetched_resolution(
                fixture.resolution.clone(),
                arkret_identity::ResolvedDid::proofless(fixture.document.clone()),
                at,
            )
            .unwrap();
            let mut source = PrefetchedRouteSource::new(Some(candidate));
            source.insert_describe(
                describe_route_binding(&fixture.resolution, &fixture.describe, at).unwrap(),
            );
            assert_eq!(
                evaluator
                    .resolve(&fixture.service_id, "media_service", at, &mut source)
                    .unwrap()
                    .route()
                    .base_url(),
                "https://media.example/"
            );
            evaluator = ServiceRouteEvaluator::new(evaluator.store().clone(), Duration::minutes(1))
                .unwrap();
        }
    }
    #[test]
    fn mismatched_current_document_and_ambiguous_endpoints_fail_closed() {
        let fixture = current_web_route_fixture("media.example", "media_service", 31);
        let mut changed = fixture.document.clone();
        changed
            .raw_properties
            .insert("service".into(), serde_json::json!([]));
        assert!(
            authenticate_fetched_resolution(
                fixture.resolution.clone(),
                arkret_identity::ResolvedDid::proofless(changed),
                Utc::now()
            )
            .is_err()
        );
        let mut bad = fixture.resolution;
        let endpoints = bad
            .normalized_did_document
            .raw_properties
            .get_mut("service")
            .unwrap()
            .as_array_mut()
            .unwrap();
        endpoints.push(endpoints[0].clone());
        assert!(bad.projection().is_err());
    }
    #[test]
    fn did_web_cannot_supply_historical_signer_evidence() {
        let fixture = current_web_route_fixture("media.example", "media_service", 31);
        assert!(
            arkret_identity::verify_authenticated_service_resolution_history(
                &fixture.resolution,
                &fixture.service_id,
                Utc::now()
            )
            .is_err()
        );
    }
    #[test]
    fn expired_prefetch_cannot_extend_current_state_freshness() {
        let fixture = current_web_route_fixture("media.example", "media_service", 31);
        let now = Utc::now();
        let candidate = authenticate_fetched_resolution(
            fixture.resolution.clone(),
            arkret_identity::ResolvedDid::proofless(fixture.document.clone()),
            now,
        )
        .unwrap();
        let mut source = PrefetchedRouteSource::new(Some(candidate));
        source.insert_describe(
            describe_route_binding(&fixture.resolution, &fixture.describe, now).unwrap(),
        );
        let mut evaluator = ServiceRouteEvaluator::new(
            MemoryServiceRouteStateStore::default(),
            Duration::minutes(1),
        )
        .unwrap();
        assert!(
            evaluator
                .resolve(
                    &fixture.service_id,
                    "media_service",
                    now + Duration::minutes(1),
                    &mut source
                )
                .is_err()
        );
    }

    #[test]
    fn did_web_endpoint_change_preserves_identity_and_uses_current_document() {
        let fixture = current_web_route_fixture("media.example", "media_service", 31);
        let now = Utc::now();
        let mut evaluator = ServiceRouteEvaluator::new(
            MemoryServiceRouteStateStore::default(),
            Duration::minutes(1),
        )
        .unwrap();
        let mut document = fixture.document.clone();
        for (at, base) in [
            (now, "https://media.example/"),
            (now + Duration::hours(1), "https://replacement.example/"),
        ] {
            document.raw_properties.get_mut("service").unwrap()[0]["serviceEndpoint"] =
                serde_json::json!(base);
            let resolution = arkret_identity::build_authenticated_did_web_service_resolution(
                fixture.service_id.clone(),
                "media_service".into(),
                document.clone(),
                at,
            )
            .unwrap();
            let projection = resolution.projection().unwrap();
            let mut description = fixture.describe.clone();
            description.service_resolution = arkret_models_identity::ResolutionCommitment {
                did: projection.did,
                method_history_head: projection.method_history_head,
                version_id: projection.version_id,
            };
            description.transport_bindings =
                vec![arkret_models_discovery::TransportBinding::HttpJson {
                    base_url: base.into(),
                    extension_profile_required: (),
                }];
            let candidate = authenticate_fetched_resolution(
                resolution.clone(),
                arkret_identity::ResolvedDid::proofless(document.clone()),
                at,
            )
            .unwrap();
            let mut source = PrefetchedRouteSource::new(Some(candidate));
            source.insert_describe(describe_route_binding(&resolution, &description, at).unwrap());
            assert_eq!(
                evaluator
                    .resolve(&fixture.service_id, "media_service", at, &mut source)
                    .unwrap()
                    .route()
                    .base_url(),
                base
            );
        }
    }
}
