//! Historical Station keys for a Realm authority bundle, scan page, and
//! exact signed Snapshot.
//!
//! A current DID document cannot authenticate an old Commit or an older
//! tenure's Snapshot. Each signature is resolved against complete
//! method-native history at its own acceptance or signing coordinate; mutable
//! did:web has no historical key source and fails closed. Neither the current
//! route record alone nor a connection pin is a substitute.

use std::collections::BTreeMap;

use arkret_http_client::Client;
use arkret_identity::{
    DidVerificationRelationship, RealmAuthorityKeyMap, authenticated_service_document_at,
    resolve_verification_method_key_from_document, validate_verification_method_relationship,
};
use arkret_models_identity::AuthenticatedServiceResolution;
use arkret_signatures::PublicKeyMaterial;
use arkret_wire::{
    DetachedObjectSignature, DidCoreId, RealmAuthorityBundle, RealmCommit, RealmStateSnapshot,
    StreamScanResponseBody,
};
use chrono::{DateTime, Utc};

use crate::{Error, Result};

struct SignedStationMethod {
    signature: DetachedObjectSignature,
    accepted_at: DateTime<Utc>,
}

fn protocol(error: impl std::fmt::Display) -> Error {
    Error::Protocol(error.to_string())
}

fn signed_methods(
    bundle: &RealmAuthorityBundle,
    scan: Option<&StreamScanResponseBody>,
    snapshot: Option<&RealmStateSnapshot>,
) -> Result<Vec<SignedStationMethod>> {
    let mut methods = vec![SignedStationMethod {
        signature: bundle.genesis_commit.signature.clone(),
        accepted_at: bundle.genesis_commit.committed_at,
    }];
    for transition in &bundle.authority_transitions {
        methods.push(SignedStationMethod {
            signature: transition.change_commit.signature.clone(),
            accepted_at: transition.change_commit.committed_at,
        });
        for signature in [
            &transition.handoff.old_authority_signature,
            &transition.handoff.new_authority_acceptance_signature,
        ] {
            methods.push(SignedStationMethod {
                signature: signature.clone(),
                accepted_at: signature
                    .created_at
                    .max(transition.change_commit.committed_at),
            });
        }
    }
    methods.push(SignedStationMethod {
        signature: bundle.current_assertion.signature.clone(),
        accepted_at: bundle.bundle_issued_at,
    });
    if let Some(scan) = scan {
        methods.extend(scan.committed_events.iter().map(|item| {
            let commit = item.commit();
            SignedStationMethod {
                signature: commit.signature.clone(),
                accepted_at: commit.committed_at,
            }
        }));
    }
    // A Snapshot is resolved at its own signing time, the moment its tenure's
    // Station key had to be valid; the verifier separately proves that the
    // signer governed the Snapshot's generation.
    if let Some(snapshot) = snapshot {
        methods.push(SignedStationMethod {
            signature: snapshot.signature.clone(),
            accepted_at: snapshot.signature.created_at,
        });
    }
    if let Some(snapshot) = snapshot {
        let commits =
            arkret_models_collaboration::events_payloads::call::call_current_source_commits(
                &snapshot.current_state_entries,
            )
            .map_err(protocol)?;
        methods.extend(commits.into_iter().map(|commit| SignedStationMethod {
            signature: commit.signature,
            accepted_at: commit.committed_at,
        }));
    }
    Ok(methods)
}

pub(crate) fn station_id_for_signature(signature: &DetachedObjectSignature) -> Result<DidCoreId> {
    let did = arkret_identity::verification_method_did(signature.verification_method.as_str())
        .map_err(protocol)?;
    arkret_wire::project_did_to_core_id(&did).map_err(protocol)
}

fn historical_key_for_signature(
    resolution: &AuthenticatedServiceResolution,
    signature: &DetachedObjectSignature,
    accepted_at: DateTime<Utc>,
) -> Result<PublicKeyMaterial> {
    let service_id = station_id_for_signature(signature)?;
    if resolution.service_id != service_id || resolution.service_kind != "station" {
        return Err(Error::Protocol(
            "historical Station resolution identity or kind mismatch".to_owned(),
        ));
    }
    let document = authenticated_service_document_at(resolution, &service_id, accepted_at)
        .map_err(protocol)?;
    let method = &signature.verification_method;
    let controller = arkret_identity::verification_method_did(method.as_str()).map_err(protocol)?;
    validate_verification_method_relationship(
        &document,
        method,
        &controller,
        DidVerificationRelationship::AssertionMethod,
    )
    .map_err(protocol)?;
    Ok(
        resolve_verification_method_key_from_document(&document, method.as_str())
            .map_err(protocol)?
            .public_key,
    )
}

/// List every Station whose signed historical material the verifier needs.
/// The caller fetches complete authenticated service resolutions for these
/// exact ids; absent material remains an error, never a current-key fallback.
pub fn required_historical_station_ids(
    bundle: &RealmAuthorityBundle,
    scan: Option<&StreamScanResponseBody>,
    snapshot: Option<&RealmStateSnapshot>,
) -> Result<Vec<DidCoreId>> {
    let mut ids = signed_methods(bundle, scan, snapshot)?
        .iter()
        .map(|entry| station_id_for_signature(&entry.signature))
        .collect::<Result<Vec<_>>>()?;
    ids.sort();
    ids.dedup();
    Ok(ids)
}

/// Build the exact-method directory consumed by the replica's cryptographic
/// gates. Resolutions must already be complete method-native carriers; each
/// is verified at the signature's historical coordinate.
pub fn historical_station_key_directory(
    bundle: &RealmAuthorityBundle,
    scan: Option<&StreamScanResponseBody>,
    snapshot: Option<&RealmStateSnapshot>,
    resolutions: &BTreeMap<DidCoreId, AuthenticatedServiceResolution>,
) -> Result<RealmAuthorityKeyMap> {
    key_directory_for_methods(signed_methods(bundle, scan, snapshot)?, resolutions)
}

fn key_directory_for_methods(
    methods: Vec<SignedStationMethod>,
    resolutions: &BTreeMap<DidCoreId, AuthenticatedServiceResolution>,
) -> Result<RealmAuthorityKeyMap> {
    let mut keys = RealmAuthorityKeyMap::new();
    let mut latest = BTreeMap::new();
    for entry in methods {
        let service_id = station_id_for_signature(&entry.signature)?;
        let resolution = resolutions.get(&service_id).ok_or_else(|| {
            Error::Protocol(format!(
                "missing historical Station resolution {service_id}"
            ))
        })?;
        let method = &entry.signature.verification_method;
        let material =
            historical_key_for_signature(resolution, &entry.signature, entry.accepted_at)?;
        if let Some(previous) = keys.insert_at(method, entry.signature.created_at, material.clone())
            && previous != material
        {
            return Err(protocol(
                "historical Station signature coordinate has conflicting key material",
            ));
        }
        if latest
            .get(method)
            .is_none_or(|previous| *previous <= entry.accepted_at)
        {
            keys.insert(method, material);
            latest.insert(method.clone(), entry.accepted_at);
        }
    }
    if keys.is_empty() {
        return Err(Error::Protocol(
            "authority bundle has no Station signing key".to_owned(),
        ));
    }
    Ok(keys)
}

/// Fetch missing Station resolutions through the SDK method adapter and
/// build the historical directory. The bundle's current route
/// record supplies only the current Station; every prior generation needs
/// its own complete history.
pub async fn fetch_historical_station_key_directory(
    http: &Client,
    bundle: &RealmAuthorityBundle,
    scan: Option<&StreamScanResponseBody>,
    snapshot: Option<&RealmStateSnapshot>,
) -> Result<RealmAuthorityKeyMap> {
    fetch_keys_for_methods(http, bundle, signed_methods(bundle, scan, snapshot)?).await
}

/// Include accepted receipts at their own historical signing coordinates.
pub async fn fetch_historical_station_keys_for_commits(
    http: &Client,
    bundle: &RealmAuthorityBundle,
    commits: &[&RealmCommit],
) -> Result<RealmAuthorityKeyMap> {
    let mut methods = signed_methods(bundle, None, None)?;
    methods.extend(commits.iter().map(|commit| SignedStationMethod {
        signature: commit.signature.clone(),
        accepted_at: commit.committed_at,
    }));
    fetch_keys_for_methods(http, bundle, methods).await
}

async fn fetch_keys_for_methods(
    http: &Client,
    bundle: &RealmAuthorityBundle,
    methods: Vec<SignedStationMethod>,
) -> Result<RealmAuthorityKeyMap> {
    fetch_keys_for_methods_with_resolver(bundle, methods, |did| async move {
        http.resolve_service_from_did(&did, arkret_wire::ServiceKind::Station)
            .await
            .map_err(Error::from)
    })
    .await
}

async fn fetch_keys_for_methods_with_resolver<F, Fut>(
    bundle: &RealmAuthorityBundle,
    methods: Vec<SignedStationMethod>,
    mut resolve: F,
) -> Result<RealmAuthorityKeyMap>
where
    F: FnMut(arkret_wire::Did) -> Fut,
    Fut: std::future::Future<Output = Result<AuthenticatedServiceResolution>>,
{
    let current: AuthenticatedServiceResolution =
        serde_json::from_value(bundle.current_route_record.clone()).map_err(|error| {
            Error::Protocol(format!(
                "current authority route is not a typed service resolution: {error}"
            ))
        })?;
    if current.service_id != bundle.current_service_id {
        return Err(Error::Protocol(
            "current authority route belongs to another Station".to_owned(),
        ));
    }
    let mut resolutions = BTreeMap::from([(current.service_id.clone(), current)]);
    let mut ids = methods
        .iter()
        .map(|entry| station_id_for_signature(&entry.signature))
        .collect::<Result<Vec<_>>>()?;
    ids.sort();
    ids.dedup();
    for service_id in ids {
        if resolutions.contains_key(&service_id) {
            continue;
        }
        let signature = &methods
            .iter()
            .find(|entry| {
                station_id_for_signature(&entry.signature).ok().as_ref() == Some(&service_id)
            })
            .ok_or_else(|| protocol("historical Station has no signed DID locator"))?
            .signature;
        let did = arkret_identity::verification_method_did(signature.verification_method.as_str())
            .map_err(protocol)?;
        let resolution = resolve(did).await?;
        resolutions.insert(service_id, resolution);
    }
    key_directory_for_methods(methods, &resolutions)
}

#[cfg(test)]
mod tests {
    use arkret_signatures::webvh::{
        ServiceInceptionInput, prepare_service_inception_with_did_key_seed,
    };
    use arkret_wire::{
        Base64UrlString, DetachedSignatureAlgorithm, DetachedSignatureContext, Did, DidUrl, Hash,
    };
    use chrono::{Duration, TimeZone as _};
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng as _;
    use url::Url;

    use super::*;

    #[test]
    fn complete_webvh_history_selects_the_station_key_at_acceptance() {
        let inception_at = Utc.with_ymd_and_hms(2026, 5, 1, 0, 0, 0).unwrap();
        let mut rng = ChaCha20Rng::seed_from_u64(73);
        let signing_seed = [41_u8; 32];
        let prepared = prepare_service_inception_with_did_key_seed(
            &mut rng,
            &ServiceInceptionInput {
                principal_endpoint: &Url::parse("https://station.example/").unwrap(),
                local_id: "service",
                also_known_as: &[],
                version_created_at: inception_at,
                did_key_fragment: Some("realm-authority"),
            },
            &signing_seed,
        )
        .unwrap();
        let did = Did::new(prepared.did.clone()).unwrap();
        let service_id = arkret_wire::project_did_to_core_id(&did).unwrap();
        let document = serde_json::from_value(prepared.log_entry["state"].clone()).unwrap();
        let resolution = arkret_identity::build_authenticated_webvh_service_resolution(
            service_id,
            "station".to_owned(),
            document,
            vec![prepared.log_entry.clone()],
            vec![],
            inception_at + Duration::seconds(30),
        )
        .unwrap();
        let signature = DetachedObjectSignature {
            context: DetachedSignatureContext::RealmCommit,
            signature_algorithm: DetachedSignatureAlgorithm::Ed25519,
            verification_method: DidUrl::new(prepared.did_key_id.clone()).unwrap(),
            signed_digest: Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
            created_at: inception_at + Duration::seconds(10),
            signature: Base64UrlString::new("AA").unwrap(),
        };
        let key =
            historical_key_for_signature(&resolution, &signature, signature.created_at).unwrap();
        assert_eq!(
            key,
            PublicKeyMaterial::Ed25519Multibase {
                value: prepared.did_public_key_multibase.clone(),
            }
        );
        assert!(
            historical_key_for_signature(
                &resolution,
                &signature,
                inception_at - Duration::seconds(1)
            )
            .is_err()
        );
        let mut wrong_method = signature;
        wrong_method.verification_method =
            DidUrl::new(format!("{}#unknown", did.as_str())).unwrap();
        assert!(
            historical_key_for_signature(
                &resolution,
                &wrong_method,
                inception_at + Duration::seconds(10)
            )
            .is_err()
        );
    }

    struct PreparedStation {
        method: DidUrl,
        service_id: DidCoreId,
        resolution: AuthenticatedServiceResolution,
        key: PublicKeyMaterial,
    }

    fn webvh_station(host: &str, seed: u8, inception_at: DateTime<Utc>) -> PreparedStation {
        let mut rng = ChaCha20Rng::seed_from_u64(u64::from(seed));
        let prepared = prepare_service_inception_with_did_key_seed(
            &mut rng,
            &ServiceInceptionInput {
                principal_endpoint: &Url::parse(&format!("https://{host}/")).unwrap(),
                local_id: "service",
                also_known_as: &[],
                version_created_at: inception_at,
                did_key_fragment: Some("notary-key"),
            },
            &[seed; 32],
        )
        .unwrap();
        let did = Did::new(prepared.did.clone()).unwrap();
        let service_id = arkret_wire::project_did_to_core_id(&did).unwrap();
        let resolution = arkret_identity::build_authenticated_webvh_service_resolution(
            service_id.clone(),
            "station".to_owned(),
            serde_json::from_value(prepared.log_entry["state"].clone()).unwrap(),
            vec![prepared.log_entry.clone()],
            vec![],
            inception_at + Duration::seconds(30),
        )
        .unwrap();
        PreparedStation {
            method: DidUrl::new(prepared.did_key_id.clone()).unwrap(),
            service_id,
            resolution,
            key: PublicKeyMaterial::Ed25519Multibase {
                value: prepared.did_public_key_multibase.clone(),
            },
        }
    }

    fn signature_by(
        context: DetachedSignatureContext,
        station: &PreparedStation,
        created_at: DateTime<Utc>,
    ) -> DetachedObjectSignature {
        let mut signature = crate::test_fixtures::detached_signature(context);
        signature.verification_method = station.method.clone();
        signature.created_at = created_at;
        signature
    }

    fn bundle_signed_by(station: &PreparedStation, at: DateTime<Utc>) -> RealmAuthorityBundle {
        let stream_ref = crate::test_fixtures::realm_stream();
        let genesis_event = crate::test_fixtures::event(
            1,
            arkret_wire::EventKind::RealmCreate,
            serde_json::json!({}),
        );
        let mut genesis_commit =
            crate::test_fixtures::commit(2, &genesis_event, stream_ref.clone(), 0);
        genesis_commit.committed_at = at;
        genesis_commit.signature = signature_by(DetachedSignatureContext::RealmCommit, station, at);
        let head = arkret_wire::CommitStreamHead {
            stream_ref,
            stream_position: 0,
            commit_id: genesis_commit.commit_id.clone(),
        };
        let nonce = Base64UrlString::new("AAAAAAAAAAAAAAAAAAAAAA").unwrap();
        RealmAuthorityBundle {
            realm_id: crate::test_fixtures::realm_id(),
            genesis_event,
            genesis_commit,
            authority_transitions: vec![],
            current_generation: 0,
            current_service_id: station.service_id.clone(),
            current_route_record: serde_json::to_value(&station.resolution).unwrap(),
            realm_stream_head: head.clone(),
            bundle_issued_at: at,
            current_assertion: arkret_wire::RealmAuthorityCurrentAssertion {
                realm_id: crate::test_fixtures::realm_id(),
                current_generation: 0,
                current_service_id: station.service_id.clone(),
                last_handoff_ref: None,
                realm_stream_head: head,
                nonce,
                expires_at: at + Duration::minutes(5),
                signature: signature_by(
                    DetachedSignatureContext::RealmAuthorityCurrentAssertion,
                    station,
                    at,
                ),
            },
        }
    }

    fn snapshot_signed_by(station: &PreparedStation, at: DateTime<Utc>) -> RealmStateSnapshot {
        let stream_ref = crate::test_fixtures::realm_stream();
        RealmStateSnapshot {
            purpose: arkret_wire::RealmSnapshotPurpose::FullRecovery,
            history_basis: None,
            snapshot_id: arkret_wire::RealmSnapshotId::from_digest([4; 32]),
            realm_id: crate::test_fixtures::realm_id(),
            governance_generation: 0,
            visible_stream_heads: vec![arkret_wire::CommitStreamHead {
                stream_ref: stream_ref.clone(),
                stream_position: 0,
                commit_id: arkret_wire::RealmCommitId::from_digest([2; 32]),
            }],
            current_state_entries: Vec::new(),
            retention_and_history_floor: arkret_wire::RetentionAndHistoryFloor {
                history_access: arkret_wire::HistoryAccess::AllHistoryForCurrentMembers,
                stream_floors: vec![arkret_wire::StreamHistoryFloor {
                    stream_ref,
                    oldest_position: 0,
                }],
            },
            created_at: at,
            signature: signature_by(DetachedSignatureContext::RealmSnapshot, station, at),
        }
    }

    #[test]
    fn snapshot_signer_is_resolved_from_its_own_history_at_signing_time() {
        let inception_at = Utc.with_ymd_and_hms(2026, 5, 1, 0, 0, 0).unwrap();
        let current = webvh_station("station-a.example", 61, inception_at);
        let other = webvh_station("station-b.example", 62, inception_at);
        let at = inception_at + Duration::seconds(10);
        let bundle = bundle_signed_by(&current, at);
        let snapshot = snapshot_signed_by(&other, at);

        assert_eq!(
            required_historical_station_ids(&bundle, None, None).unwrap(),
            vec![current.service_id.clone()]
        );
        let mut expected = vec![current.service_id.clone(), other.service_id.clone()];
        expected.sort();
        assert_eq!(
            required_historical_station_ids(&bundle, None, Some(&snapshot)).unwrap(),
            expected
        );

        let only_current =
            BTreeMap::from([(current.service_id.clone(), current.resolution.clone())]);
        let without_snapshot =
            historical_station_key_directory(&bundle, None, None, &only_current).unwrap();
        assert!(
            arkret_identity::RealmAuthorityKeyDirectory::public_key(
                &without_snapshot,
                &other.method
            )
            .is_none()
        );
        assert!(
            historical_station_key_directory(&bundle, None, Some(&snapshot), &only_current)
                .is_err()
        );

        let both = BTreeMap::from([
            (current.service_id.clone(), current.resolution.clone()),
            (other.service_id.clone(), other.resolution.clone()),
        ]);
        let keys = historical_station_key_directory(&bundle, None, Some(&snapshot), &both).unwrap();
        assert_eq!(
            arkret_identity::RealmAuthorityKeyDirectory::public_key(&keys, &other.method),
            Some(other.key.clone())
        );

        let before_inception = snapshot_signed_by(&other, inception_at - Duration::seconds(1));
        assert!(
            historical_station_key_directory(&bundle, None, Some(&before_inception), &both)
                .is_err()
        );
    }

    #[cfg(feature = "native")]
    #[tokio::test]
    async fn historical_resolution_outage_keeps_its_retryable_transport_class() {
        let at = Utc.with_ymd_and_hms(2026, 5, 1, 0, 0, 0).unwrap();
        let current = webvh_station("station-a.example", 61, at);
        let old = webvh_station("station-b.example", 62, at);
        let bundle = bundle_signed_by(&current, at + Duration::seconds(10));
        let snapshot = snapshot_signed_by(&old, at + Duration::seconds(10));
        let old_did = arkret_identity::verification_method_did(old.method.as_str()).unwrap();
        let mut calls = 0;
        let error = fetch_keys_for_methods_with_resolver(
            &bundle,
            signed_methods(&bundle, None, Some(&snapshot)).unwrap(),
            |did| {
                calls += 1;
                assert_eq!(did, old_did);
                std::future::ready(Err(Error::Http("service DID returned 503".to_owned())))
            },
        )
        .await
        .unwrap_err();
        assert_eq!(calls, 1);
        assert!(
            crate::run::is_retryable(&error),
            "a historical evidence outage must preserve retryability: {error}"
        );
    }

    #[test]
    fn mutable_did_web_document_cannot_supply_a_historical_station_key() {
        let at = Utc.with_ymd_and_hms(2026, 5, 1, 0, 0, 0).unwrap();
        let did = Did::new("did:web:station.example").unwrap();
        let method = DidUrl::new("did:web:station.example#authority").unwrap();
        let document = serde_json::from_value(serde_json::json!({
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": did,
            "verificationMethod": [{
                "id": method,
                "controller": did,
                "type": "Multikey",
                "publicKeyMultibase": arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                    ed25519_dalek::SigningKey::from_bytes(&[47; 32]).verifying_key().as_bytes()
                )
            }],
            "assertionMethod": [method],
            "service": [{
                "id": "did:web:station.example#station",
                "type": "ArkretService",
                "serviceEndpoint": "https://station.example/",
                "serviceKind": "station"
            }]
        }))
        .unwrap();
        let service_id = arkret_wire::project_did_to_core_id(&did).unwrap();
        let resolution = arkret_identity::build_authenticated_did_web_service_resolution(
            service_id,
            "station".to_owned(),
            document,
            at,
        )
        .unwrap();
        let signature = DetachedObjectSignature {
            context: DetachedSignatureContext::RealmSnapshot,
            signature_algorithm: DetachedSignatureAlgorithm::Ed25519,
            verification_method: method,
            signed_digest: Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
            created_at: at,
            signature: Base64UrlString::new("AA").unwrap(),
        };
        assert!(historical_key_for_signature(&resolution, &signature, at).is_err());
    }
}
