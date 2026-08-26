//! Client-side materialization of [`crate::service_route::ServiceRouteEvaluator`]
//! inputs from host-fetched route bytes.
//!
//! `service-surface.md` §2.6: a URL or record obtained from a realm cell,
//! carrier, mirror or local config is only an untrusted candidate. The host
//! fetches the raw bytes (signed `ServiceResolutionRecord`, the target's DID
//! document, the role-scoped `ServiceDescribe`) over its own SSRF-guarded
//! transport; this module turns those bytes into the verified, typed inputs
//! the evaluator consumes:
//!
//! - [`authenticate_fetched_record`] — rebuild the method-adapter evidence
//!   from the normalized DID document, validate the record's route binding
//!   (canonical base URL, derived `current_record_url`, describe projection
//!   digest) and verify the target-signed proof.
//! - [`describe_route_binding`] — validate the two-hop `ServiceDescribe`
//!   confirmation against the signed record and produce the
//!   [`ServiceDescribeBinding`] the evaluator's reverse-binding check needs.
//! - [`PrefetchedRouteSource`] — a [`ServiceRouteSource`] over material the
//!   host prefetched asynchronously, so the synchronous evaluator can run its
//!   durable-floor / fail-closed / quarantine decision over it.
//!
//! Method adapters: `did:web` and `did:key` are materialized here (synthetic
//! single-version histories per the active adapter rows). `did:webvh` route
//! materialization requires the verified log head and is not yet available in
//! this client materializer — it fails closed rather than degrading to an
//! unverified document.

use std::collections::BTreeMap;

use arkret_models_discovery::ServiceDescribe;
use arkret_models_identity::service_identity::CanonicalServiceUrl;
use arkret_models_identity::{
    AuthenticatedServiceResolution, DidDocument, ResolutionCommitment,
    ResolutionDidBindingEvidenceKind, ResolutionDidBindingEvidenceReceipt,
    ResolutionMethodEvidenceBoundary, ResolutionMethodHistoryEvidence, ServiceResolutionRecord,
    canonical_service_current_record_path, route_binding_describe_digest,
};
use arkret_wire::{BindingKind, DidCoreId, Hash, ServiceKind};
use chrono::{DateTime, Utc};

use crate::service_route::{
    ServiceDescribeBinding, ServiceRouteCandidate, ServiceRouteNoticeCandidate, ServiceRouteSource,
};
use crate::{Error, Result};

fn canonical_document_digest(document: &DidDocument) -> Result<Hash> {
    Ok(Hash::new(arkret_canonical::canonical_sha256(document)?)?)
}

fn digest_hex(digest: &Hash) -> Result<&str> {
    digest
        .as_str()
        .strip_prefix("sha256:")
        .ok_or_else(|| Error::Protocol("canonical digest lost its sha256 prefix".to_owned()))
}

/// Validate the signed record's own route binding: canonical HTTPS base URL,
/// mechanically derived `current_record_url`, and a `describe_digest` that is
/// the canonical projection digest over the record's own coordinates.
pub fn validate_route_binding(record: &ServiceResolutionRecord) -> Result<()> {
    let base = CanonicalServiceUrl::canonicalize(&record.record.base_url)
        .map_err(|error| Error::Protocol(error.to_string()))?;
    if base.to_string() != record.record.base_url {
        return Err(Error::Protocol(
            "service_route_base_url_not_canonical".to_owned(),
        ));
    }
    let expected_record_url = format!(
        "{}{}",
        base,
        canonical_service_current_record_path(&record.record.service_id).trim_start_matches('/')
    );
    if record.record.current_record_url != expected_record_url {
        return Err(Error::Protocol(
            "service_route_current_record_url_not_derived_from_base".to_owned(),
        ));
    }
    let digest = route_binding_describe_digest(
        &record.record.service_id,
        &record.record.service_kind,
        &ResolutionCommitment {
            full_id: record.record.full_id.clone(),
            method_history_head: record.record.method_history_head.clone(),
            version_id: record.record.version_id.clone(),
        },
        &record.record.base_url,
    )?;
    if digest != record.record.describe_digest {
        return Err(Error::Protocol(
            "service_route_describe_binding_digest_mismatch".to_owned(),
        ));
    }
    Ok(())
}

/// Re-run the active method adapter's coordinate derivation over the exact
/// normalized document carried by `resolution` and require the signed record
/// to commit those coordinates. This is the client half of
/// [`ServiceRouteSource::verify_method_history`].
pub fn verify_client_method_evidence(
    resolution: &AuthenticatedServiceResolution,
    now: DateTime<Utc>,
) -> Result<()> {
    let record = &resolution.service_resolution_record.record;
    if now >= record.expires_at {
        return Err(Error::Protocol("service_route_record_expired".to_owned()));
    }
    if resolution.normalized_did_document.id != record.full_id {
        return Err(Error::Protocol(
            "service_route_document_identity_mismatch".to_owned(),
        ));
    }
    let boundary = resolution.method_history_evidence.boundary();
    if boundary.from_method_history_head != record.method_history_head
        || boundary.to_method_history_head != record.method_history_head
        || boundary.from_version_id != record.version_id
        || boundary.to_version_id != record.version_id
    {
        return Err(Error::Protocol(
            "service_route_evidence_boundary_mismatch".to_owned(),
        ));
    }
    let document_digest = canonical_document_digest(&resolution.normalized_did_document)?;
    if resolution
        .method_history_evidence
        .evidence()
        .document_digest
        != document_digest
    {
        return Err(Error::Protocol(
            "service_route_evidence_document_digest_mismatch".to_owned(),
        ));
    }
    match record.full_id.method() {
        "web" => {
            if !matches!(
                resolution.method_history_evidence,
                ResolutionMethodHistoryEvidence::DidWebDocument { .. }
            ) {
                return Err(Error::Protocol(
                    "service_route_evidence_kind_mismatch".to_owned(),
                ));
            }
            validate_synthetic_method_coordinates(
                record,
                &document_digest,
                "synthetic-jcs-sha256:",
                "did-web-document-sha256:",
            )
        }
        "key" => {
            if !matches!(
                resolution.method_history_evidence,
                ResolutionMethodHistoryEvidence::DidKeyExpansion { .. }
            ) {
                return Err(Error::Protocol(
                    "service_route_evidence_kind_mismatch".to_owned(),
                ));
            }
            let full_id_digest = Hash::new(arkret_canonical::sha256_digest(
                record.full_id.as_str().as_bytes(),
            ))?;
            validate_synthetic_method_coordinates(
                record,
                &full_id_digest,
                "synthetic-full-id-sha256:",
                "did-key-full-id-sha256:",
            )
        }
        _ => Err(Error::Protocol(
            "service_route_method_adapter_unavailable".to_owned(),
        )),
    }
}

fn validate_synthetic_method_coordinates(
    record: &arkret_models_identity::ServiceResolutionRecordCore,
    digest: &Hash,
    version_prefix: &str,
    event_prefix: &str,
) -> Result<()> {
    let hex = digest_hex(digest)?;
    if record.method_history_head != digest.as_str()
        || record.version_id != format!("{version_prefix}{hex}")
        || record.resolution_event_ref != format!("{event_prefix}{hex}")
    {
        return Err(Error::Protocol(
            "service_route_method_coordinates_mismatch".to_owned(),
        ));
    }
    Ok(())
}

fn evidence_boundary(
    record: &arkret_models_identity::ServiceResolutionRecordCore,
) -> ResolutionMethodEvidenceBoundary {
    ResolutionMethodEvidenceBoundary {
        from_method_history_head: record.method_history_head.clone(),
        from_version_id: record.version_id.clone(),
        to_method_history_head: record.method_history_head.clone(),
        to_version_id: record.version_id.clone(),
    }
}

/// Turn a host-fetched signed record plus the target's normalized DID document
/// into a verified [`AuthenticatedServiceResolution`].
///
/// `document` MUST be the exact DID document the host fetched for
/// `record.full_id` through its own method-scoped, SSRF-guarded transport
/// (for `did:web`: the validated `did.json`; for `did:key`: the deterministic
/// expansion). Everything is re-derived and re-verified here — a mismatched or
/// stale record fails closed.
pub fn authenticate_fetched_record(
    record: ServiceResolutionRecord,
    document: DidDocument,
    now: DateTime<Utc>,
) -> Result<AuthenticatedServiceResolution> {
    validate_route_binding(&record)?;
    let document_digest = canonical_document_digest(&document)?;
    let evidence_receipt = |method: &str| ResolutionDidBindingEvidenceReceipt {
        kind: ResolutionDidBindingEvidenceKind::AkDidBindingEvidenceV1,
        method: method.to_owned(),
        document_digest: document_digest.clone(),
        method_proofs: Vec::new(),
    };
    let method_history_evidence = match record.record.full_id.method() {
        "web" => ResolutionMethodHistoryEvidence::DidWebDocument {
            adapter_version: "did:web:1".to_owned(),
            boundary: evidence_boundary(&record.record),
            evidence: evidence_receipt("web"),
        },
        "key" => ResolutionMethodHistoryEvidence::DidKeyExpansion {
            adapter_version: "did:key:1".to_owned(),
            boundary: evidence_boundary(&record.record),
            evidence: evidence_receipt("key"),
        },
        _ => {
            return Err(Error::Protocol(
                "service_route_method_adapter_unavailable".to_owned(),
            ));
        }
    };
    let expected_service_id = record.record.service_id.clone();
    let resolution = AuthenticatedServiceResolution {
        service_resolution_record: record,
        method_history_evidence,
        normalized_did_document: document,
    };
    verify_client_method_evidence(&resolution, now)?;
    arkret_signatures::service_resolution::verify_authenticated_service_resolution(
        &resolution,
        &expected_service_id,
        now,
    )
    .map_err(|error| Error::Protocol(error.to_string()))?;
    Ok(resolution)
}

/// Validate the two-hop `ServiceDescribe` confirmation against the signed
/// record and produce the evaluator's reverse-binding input.
pub fn describe_route_binding(
    record: &ServiceResolutionRecord,
    description: &ServiceDescribe,
    now: DateTime<Utc>,
) -> Result<ServiceDescribeBinding> {
    if now >= record.record.expires_at {
        return Err(Error::Protocol("service_route_record_expired".to_owned()));
    }
    description
        .validate()
        .map_err(|error| Error::Protocol(error.to_string()))?;
    let registered_kind = ServiceKind::ALL
        .iter()
        .copied()
        .find(|kind| {
            kind.as_str() == record.record.service_kind && kind.valid_in("service_describe")
        })
        .ok_or_else(|| Error::Protocol("service_route_kind_has_no_describe_surface".to_owned()))?;
    if description.protocol_version != arkret_wire::PROTOCOL_VERSION
        || description.service_id != record.record.service_id
        || description.service_kind != registered_kind
        || description.service_resolution.full_id != record.record.full_id
        || description.service_resolution.method_history_head != record.record.method_history_head
        || description.service_resolution.version_id != record.record.version_id
    {
        return Err(Error::Protocol(
            "service_route_describe_commitment_mismatch".to_owned(),
        ));
    }
    let mut http_json_bindings = description
        .supported_bindings
        .iter()
        .filter(|binding| binding.kind == BindingKind::HttpJson);
    let binding = http_json_bindings.next().ok_or_else(|| {
        Error::Protocol("service_route_describe_missing_http_json_binding".to_owned())
    })?;
    if http_json_bindings.next().is_some() {
        return Err(Error::Protocol(
            "service_route_describe_ambiguous_http_json_binding".to_owned(),
        ));
    }
    let advertised_base_raw = binding.base_url.as_deref().ok_or_else(|| {
        Error::Protocol("service_route_describe_http_json_binding_without_base".to_owned())
    })?;
    let advertised_base = CanonicalServiceUrl::canonicalize(advertised_base_raw)
        .map_err(|error| Error::Protocol(error.to_string()))?;
    if advertised_base.as_str() != advertised_base_raw
        || advertised_base.as_str() != record.record.base_url
    {
        return Err(Error::Protocol(
            "service_route_describe_base_mismatch".to_owned(),
        ));
    }
    let digest = route_binding_describe_digest(
        &description.service_id,
        registered_kind.as_str(),
        &description.service_resolution,
        advertised_base.as_str(),
    )?;
    if digest != record.record.describe_digest {
        return Err(Error::Protocol(
            "service_route_describe_binding_digest_mismatch".to_owned(),
        ));
    }
    Ok(ServiceDescribeBinding {
        service_id: description.service_id.clone(),
        service_kind: registered_kind.as_str().to_owned(),
        base_url: advertised_base.to_string(),
        describe_digest: digest,
    })
}

/// [`ServiceRouteSource`] over host-prefetched material.
///
/// The host performs its asynchronous, SSRF-guarded fetches first
/// (record + DID document + describe), materializes them through
/// [`authenticate_fetched_record`] / [`describe_route_binding`], and hands the
/// results to this source so the synchronous evaluator can apply its durable
/// floor / quarantine / fail-closed decision. Notices and mirrors have no
/// client distribution channel yet and honestly return `None` — the evaluator
/// then fails closed (`service_route_unresolved`) instead of inventing a
/// route.
#[derive(Debug, Default)]
pub struct PrefetchedRouteSource {
    current: Option<ServiceRouteCandidate>,
    describes: BTreeMap<String, ServiceDescribeBinding>,
}

impl PrefetchedRouteSource {
    #[must_use]
    pub fn new(current: Option<ServiceRouteCandidate>) -> Self {
        Self {
            current,
            describes: BTreeMap::new(),
        }
    }

    /// Register the verified describe confirmation for one base URL.
    pub fn insert_describe(&mut self, describe: ServiceDescribeBinding) {
        self.describes.insert(describe.base_url.clone(), describe);
    }
}

impl ServiceRouteSource for PrefetchedRouteSource {
    fn verify_method_history(
        &mut self,
        resolution: &AuthenticatedServiceResolution,
        now: DateTime<Utc>,
    ) -> Result<()> {
        verify_client_method_evidence(resolution, now)
    }

    fn current_record(
        &mut self,
        service_id: &DidCoreId,
        service_kind: &str,
    ) -> Result<Option<ServiceRouteCandidate>> {
        let Some(candidate) = self.current.take() else {
            return Ok(None);
        };
        let record = &candidate.resolution.service_resolution_record.record;
        if &record.service_id != service_id || record.service_kind != service_kind {
            return Err(Error::Protocol(
                "service_route_prefetched_candidate_identity_mismatch".to_owned(),
            ));
        }
        Ok(Some(candidate))
    }

    fn active_notice(
        &mut self,
        _service_id: &DidCoreId,
        _service_kind: &str,
    ) -> Result<Option<ServiceRouteNoticeCandidate>> {
        Ok(None)
    }

    fn realm_peer_mirror(
        &mut self,
        _service_id: &DidCoreId,
        _service_kind: &str,
        _floor: Option<&arkret_models_identity::ServiceResolutionLastSeenFloor>,
    ) -> Result<Option<ServiceRouteCandidate>> {
        Ok(None)
    }

    fn external_mirror(
        &mut self,
        _service_id: &DidCoreId,
        _service_kind: &str,
        _floor: Option<&arkret_models_identity::ServiceResolutionLastSeenFloor>,
    ) -> Result<Option<ServiceRouteCandidate>> {
        Ok(None)
    }

    fn describe(&mut self, base_url: &str) -> Result<ServiceDescribeBinding> {
        self.describes
            .get(base_url)
            .cloned()
            .ok_or_else(|| Error::Protocol("service_route_describe_not_prefetched".to_owned()))
    }
}

/// Build the full fixture set for one signed `did:web` service route:
/// signed record with correct synthetic method coordinates, normalized DID
/// document, and the matching `ServiceDescribe`. Test-support only — the
/// signing key is deterministic.
#[cfg(any(test, feature = "route-material-test-support"))]
pub mod test_fixture {
    use arkret_models_discovery::SupportedBinding;
    use arkret_wire::{DidFullId, DidUrl, TrustDomainId};
    use chrono::Duration;
    use ed25519_dalek::SigningKey;

    use super::*;

    pub struct SignedRouteFixture {
        pub service_id: DidCoreId,
        pub record: ServiceResolutionRecord,
        pub document: DidDocument,
        pub describe: ServiceDescribe,
        pub signing_key: SigningKey,
    }

    /// Deterministic signed `did:web` route fixture for `host` at
    /// `record_sequence` with the given `previous_record_digest`.
    pub fn signed_web_route_fixture(
        host: &str,
        service_kind: &str,
        issued_at: DateTime<Utc>,
        record_sequence: u64,
        previous_record_digest: Option<Hash>,
        key_seed: u8,
    ) -> SignedRouteFixture {
        let signing_key = SigningKey::from_bytes(&[key_seed; 32]);
        let full_id = DidFullId::new(format!("did:web:{host}")).unwrap();
        let service_id = arkret_wire::project_full_id_to_core_id(&full_id).unwrap();
        let method = DidUrl::new(format!("{full_id}#signing-1")).unwrap();
        let document = DidDocument {
            id: full_id.clone(),
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
        let document_digest = canonical_document_digest(&document).unwrap();
        let hex = digest_hex(&document_digest).unwrap().to_owned();
        let base_url = format!("https://{host}/");
        let commitment = ResolutionCommitment {
            full_id: full_id.clone(),
            method_history_head: document_digest.as_str().to_owned(),
            version_id: format!("synthetic-jcs-sha256:{hex}"),
        };
        let describe_digest =
            route_binding_describe_digest(&service_id, service_kind, &commitment, &base_url)
                .unwrap();
        let record = arkret_signatures::service_resolution::sign_service_resolution_record(
            arkret_models_identity::ServiceResolutionRecordCore {
                service_id: service_id.clone(),
                service_kind: service_kind.to_owned(),
                full_id: full_id.clone(),
                method_history_head: commitment.method_history_head.clone(),
                version_id: commitment.version_id.clone(),
                resolution_event_ref: format!("did-web-document-sha256:{hex}"),
                record_sequence,
                previous_record_digest,
                current_record_url: format!(
                    "{}{}",
                    base_url,
                    canonical_service_current_record_path(&service_id).trim_start_matches('/')
                ),
                base_url: base_url.clone(),
                describe_digest,
                issued_at,
                refresh_after: issued_at + Duration::minutes(5),
                expires_at: issued_at + Duration::minutes(10),
            },
            method,
            &signing_key,
        )
        .unwrap();
        let registered_kind = ServiceKind::ALL
            .iter()
            .copied()
            .find(|kind| kind.as_str() == service_kind)
            .expect("fixture service kind must be registered");
        let mut describe = ServiceDescribe::development(
            full_id,
            TrustDomainId::new(format!("ak:trust_domain:{host}")).unwrap(),
            registered_kind,
        );
        describe.service_resolution = commitment;
        describe.supported_bindings =
            vec![SupportedBinding::new(BindingKind::HttpJson).with_base_url(base_url)];
        SignedRouteFixture {
            service_id,
            record,
            document,
            describe,
            signing_key,
        }
    }
}

#[cfg(test)]
mod tests {
    use arkret_wire::DidFullId;
    use chrono::{Duration, TimeZone as _};

    use super::test_fixture::signed_web_route_fixture;
    use super::*;
    use crate::service_route::{
        MemoryServiceRouteStateStore, RouteCandidateSource, ServiceRouteEvaluator,
        ServiceRouteStateStore as _,
    };

    fn now_fixture() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 20, 1, 0, 0).unwrap()
    }

    fn evaluator() -> ServiceRouteEvaluator<MemoryServiceRouteStateStore> {
        ServiceRouteEvaluator::new(
            MemoryServiceRouteStateStore::default(),
            Duration::minutes(1),
        )
        .unwrap()
    }

    fn source_for(
        fixture: &super::test_fixture::SignedRouteFixture,
        now: DateTime<Utc>,
    ) -> PrefetchedRouteSource {
        let resolution =
            authenticate_fetched_record(fixture.record.clone(), fixture.document.clone(), now)
                .unwrap();
        let mut source = PrefetchedRouteSource::new(Some(ServiceRouteCandidate { resolution }));
        source.insert_describe(
            describe_route_binding(&fixture.record, &fixture.describe, now).unwrap(),
        );
        source
    }

    #[test]
    fn fetched_record_materializes_and_resolves_through_the_evaluator() {
        let now = now_fixture();
        let fixture = signed_web_route_fixture("media.example", "media_service", now, 0, None, 31);
        let mut evaluator = evaluator();
        let mut source = source_for(&fixture, now);
        let resolved = evaluator
            .resolve(&fixture.service_id, "media_service", now, &mut source)
            .unwrap();
        assert_eq!(resolved.source(), RouteCandidateSource::CurrentRecord);
        assert_eq!(resolved.route().base_url, "https://media.example/");
        assert_eq!(resolved.route().record_sequence, 0);
        // The durable floor advanced atomically before the route was returned.
        let snapshot = evaluator
            .store()
            .load_route_state(&fixture.service_id, "media_service")
            .unwrap()
            .unwrap();
        assert_eq!(snapshot.floor.unwrap().record_sequence, 0);
        assert!(snapshot.quarantine.is_none());
    }

    #[test]
    fn tampered_document_fails_authentication() {
        let now = now_fixture();
        let fixture = signed_web_route_fixture("media.example", "media_service", now, 0, None, 31);
        let mut document = fixture.document.clone();
        document
            .raw_properties
            .insert("attacker".to_owned(), serde_json::json!(true));
        // Coordinates no longer derive from the (modified) document.
        assert!(authenticate_fetched_record(fixture.record, document, now).is_err());
    }

    #[test]
    fn describe_binding_rejects_base_url_mismatch() {
        let now = now_fixture();
        let fixture = signed_web_route_fixture("media.example", "media_service", now, 0, None, 31);
        let mut describe = fixture.describe.clone();
        describe.supported_bindings[0].base_url = Some("https://other.example/".to_owned());
        assert!(describe_route_binding(&fixture.record, &describe, now).is_err());
        assert!(describe_route_binding(&fixture.record, &fixture.describe, now).is_ok());
    }

    #[test]
    fn lower_sequence_after_accepted_floor_is_quarantined_fail_closed() {
        let now = now_fixture();
        let seq1_prev =
            signed_web_route_fixture("media.example", "media_service", now, 0, None, 31);
        let prev_digest =
            Hash::new(arkret_canonical::canonical_sha256(&seq1_prev.record).unwrap()).unwrap();
        let seq1 = signed_web_route_fixture(
            "media.example",
            "media_service",
            now,
            1,
            Some(prev_digest),
            31,
        );
        let mut evaluator = evaluator();
        // Anchor at sequence 1.
        let mut source = source_for(&seq1, now);
        evaluator
            .resolve(&seq1.service_id, "media_service", now, &mut source)
            .unwrap();
        // Offer the older sequence-0 record again after cache expiry: gap/fork
        // handling MUST quarantine, not roll back.
        let later = now + Duration::minutes(2);
        // A rollback offer must be freshly-signed to even reach the floor
        // check, so re-issue sequence 0 at a later timestamp.
        let stale = signed_web_route_fixture("media.example", "media_service", later, 0, None, 31);
        let mut rollback_source = source_for(&stale, later);
        let error = evaluator
            .resolve(
                &stale.service_id,
                "media_service",
                later,
                &mut rollback_source,
            )
            .unwrap_err();
        assert!(error.to_string().contains("service_route_gap_or_fork"));
        let snapshot = evaluator
            .store()
            .load_route_state(&stale.service_id, "media_service")
            .unwrap()
            .unwrap();
        assert!(snapshot.quarantine.is_some(), "fork must be quarantined");
        assert_eq!(
            snapshot.floor.unwrap().record_sequence,
            1,
            "floor must not be lowered"
        );
        // Once quarantined, every further resolve fails closed.
        let mut retry_source = source_for(&seq1, later);
        let error = evaluator
            .resolve(&seq1.service_id, "media_service", later, &mut retry_source)
            .unwrap_err();
        assert!(error.to_string().contains("service_route_fork_quarantined"));
    }

    #[test]
    fn same_sequence_different_digest_is_a_fork() {
        let now = now_fixture();
        let original = signed_web_route_fixture("media.example", "media_service", now, 0, None, 31);
        let mut evaluator = evaluator();
        let mut source = source_for(&original, now);
        evaluator
            .resolve(&original.service_id, "media_service", now, &mut source)
            .unwrap();
        // Same core, same sequence, later issue time -> different digest.
        let later = now + Duration::minutes(2);
        let fork = signed_web_route_fixture("media.example", "media_service", later, 0, None, 31);
        let mut fork_source = source_for(&fork, later);
        let error = evaluator
            .resolve(&fork.service_id, "media_service", later, &mut fork_source)
            .unwrap_err();
        assert!(error.to_string().contains("service_route_gap_or_fork"));
    }

    #[test]
    fn sequence_skip_is_rejected() {
        let now = now_fixture();
        let seq0 = signed_web_route_fixture("media.example", "media_service", now, 0, None, 31);
        let mut evaluator = evaluator();
        let mut source = source_for(&seq0, now);
        evaluator
            .resolve(&seq0.service_id, "media_service", now, &mut source)
            .unwrap();
        // Sequence 2 with a fabricated predecessor digest: skip -> fail closed.
        let later = now + Duration::minutes(2);
        let skipped = signed_web_route_fixture(
            "media.example",
            "media_service",
            later,
            2,
            Some(Hash::new(format!("sha256:{}", "9".repeat(64))).unwrap()),
            31,
        );
        let mut skip_source = source_for(&skipped, later);
        let error = evaluator
            .resolve(
                &skipped.service_id,
                "media_service",
                later,
                &mut skip_source,
            )
            .unwrap_err();
        assert!(error.to_string().contains("service_route_gap_or_fork"));
    }

    #[test]
    fn continuous_successor_advances_the_floor() {
        let now = now_fixture();
        let seq0 = signed_web_route_fixture("media.example", "media_service", now, 0, None, 31);
        let prev_digest =
            Hash::new(arkret_canonical::canonical_sha256(&seq0.record).unwrap()).unwrap();
        let mut evaluator = evaluator();
        let mut source = source_for(&seq0, now);
        evaluator
            .resolve(&seq0.service_id, "media_service", now, &mut source)
            .unwrap();
        let later = now + Duration::minutes(2);
        let seq1 = signed_web_route_fixture(
            "media.example",
            "media_service",
            later,
            1,
            Some(prev_digest),
            31,
        );
        let mut successor_source = source_for(&seq1, later);
        let resolved = evaluator
            .resolve(
                &seq1.service_id,
                "media_service",
                later,
                &mut successor_source,
            )
            .unwrap();
        assert_eq!(resolved.route().record_sequence, 1);
        let snapshot = evaluator
            .store()
            .load_route_state(&seq1.service_id, "media_service")
            .unwrap()
            .unwrap();
        assert_eq!(snapshot.floor.unwrap().record_sequence, 1);
    }

    #[test]
    fn missing_describe_prefetch_fails_closed() {
        let now = now_fixture();
        let fixture = signed_web_route_fixture("media.example", "media_service", now, 0, None, 31);
        let resolution =
            authenticate_fetched_record(fixture.record.clone(), fixture.document.clone(), now)
                .unwrap();
        let mut source = PrefetchedRouteSource::new(Some(ServiceRouteCandidate { resolution }));
        let mut evaluator = evaluator();
        let error = evaluator
            .resolve(&fixture.service_id, "media_service", now, &mut source)
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("service_route_describe_not_prefetched")
        );
    }

    #[test]
    fn webvh_record_has_no_client_adapter_yet_and_fails_closed() {
        let now = now_fixture();
        let fixture = signed_web_route_fixture("media.example", "media_service", now, 0, None, 31);
        // Retarget the record to a webvh full id with a consistent route
        // binding, so the failure is attributable to the missing adapter and
        // not to an earlier binding mismatch.
        let full_id = DidFullId::new("did:webvh:QmExampleScidValue123456:media.example").unwrap();
        let service_id = arkret_wire::project_full_id_to_core_id(&full_id).unwrap();
        let mut record = fixture.record.clone();
        record.record.full_id = full_id.clone();
        record.record.service_id = service_id.clone();
        record.record.current_record_url = format!(
            "https://media.example/{}",
            canonical_service_current_record_path(&service_id).trim_start_matches('/')
        );
        record.record.describe_digest = route_binding_describe_digest(
            &service_id,
            "media_service",
            &ResolutionCommitment {
                full_id,
                method_history_head: record.record.method_history_head.clone(),
                version_id: record.record.version_id.clone(),
            },
            &record.record.base_url,
        )
        .unwrap();
        assert!(
            authenticate_fetched_record(record, fixture.document, now)
                .unwrap_err()
                .to_string()
                .contains("service_route_method_adapter_unavailable")
        );
    }
}
