//! Exact by-ref read of the signed Realm Snapshot named by a stream window.
//!
//! Availability comes only from the Station's advertised operation bundle,
//! and refusals are classified by their registered error code. The returned
//! object is shape-checked only: it becomes a verified predecessor solely
//! through [`crate::RealmReplica::install_verified_floor_predecessor`] with a
//! fresh nonce-bound authority bundle and a historical Station key directory
//! (see [`crate::historical_station_keys`]).

#[cfg(test)]
use arkret_identity::VerifiedSubmission;
use arkret_models_discovery::ServiceDescribe;
use arkret_wire::{
    BindingKind, ErrorCode, Problem, RealmId, RealmSnapshotId, RealmStateSnapshot, ServiceKind,
    ServiceOperationId,
};

use crate::{AuthorityClient, AuthorityTransport, Error, Result};

/// Registered refusal of `ak.self.realm_state_snapshot.read.by_ref.v1`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExactSnapshotRefusal {
    /// The Station does not advertise
    /// `ak.operation_bundle.station.snapshot_exact_read.v1` over HTTP JSON.
    NotAdvertised,
    /// `realm_state_snapshot_unavailable`: the original signed bytes are
    /// absent or no longer safely disclosable to this caller.
    Unavailable,
    /// `realm_state_snapshot_authority_unverified`.
    AuthorityUnverified,
    /// `capability_denied`: the universal surface for every authorization
    /// failure of this read (the Realm or reference is not the caller's).
    CapabilityDenied,
}

impl ExactSnapshotRefusal {
    /// Classify a problem only when its registered code and HTTP status agree.
    /// Any other response stays a generic API error.
    pub fn from_problem(status: u16, problem: &Problem) -> Option<Self> {
        let code = problem.error_code()?;
        if code.http_status() != status {
            return None;
        }
        match code {
            ErrorCode::RealmStateSnapshotUnavailable => Some(Self::Unavailable),
            ErrorCode::RealmStateSnapshotAuthorityUnverified => Some(Self::AuthorityUnverified),
            ErrorCode::CapabilityDenied => Some(Self::CapabilityDenied),
            _ => None,
        }
    }
}

/// Whether this Station advertises the exact by-ref read over HTTP JSON.
pub fn exact_snapshot_read_advertised(describe: &ServiceDescribe) -> bool {
    describe.service_kind == ServiceKind::Station
        && describe
            .select_transport_binding(
                ServiceOperationId::SelfRealmStateSnapshotReadByRefV1,
                &[BindingKind::HttpJson],
            )
            .is_some()
}

impl<T: AuthorityTransport> AuthorityClient<T> {
    /// Read the original signed Snapshot for `snapshot_ref` from the caller's
    /// own Station. No current `/head`, cache, or re-signed object may stand
    /// in for it; every refusal fails the window closed.
    pub async fn exact_snapshot(
        &self,
        describe: &ServiceDescribe,
        realm_id: &RealmId,
        snapshot_ref: &RealmSnapshotId,
    ) -> Result<RealmStateSnapshot> {
        if !exact_snapshot_read_advertised(describe) {
            return Err(Error::ExactSnapshotRefused(
                ExactSnapshotRefusal::NotAdvertised,
            ));
        }
        let snapshot = self
            .transport()
            .exact_snapshot(realm_id, snapshot_ref)
            .await
            .map_err(|error| match error {
                Error::Api { status, error } => ExactSnapshotRefusal::from_problem(status, &error)
                    .map_or(Error::Api { status, error }, Error::ExactSnapshotRefused),
                other => other,
            })?;
        if &snapshot.realm_id != realm_id || &snapshot.snapshot_id != snapshot_ref {
            return Err(Error::Protocol(
                "exact Realm snapshot answered for another Realm or reference".to_owned(),
            ));
        }
        Ok(snapshot)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use arkret_http_client::ClientRequestOptions;
    use arkret_models_collaboration::authority_commit::AuthorityHandoffRequest;
    use arkret_models_discovery::TransportBinding;
    use arkret_wire::{
        AuthorityBundleRequest, AuthoritySubmitOutcome, AuthoritySubmitRequest, CommitStreamHead,
        DetachedSignatureContext, Did, RealmAuthorityBundle, RealmAuthorityHandoff, RealmCommitId,
        StreamScanOutcome, StreamScanRequest, TrustDomainId,
    };

    use super::*;

    enum Scripted {
        Snapshot(Box<RealmStateSnapshot>),
        Problem(&'static str, u16),
    }

    struct ByRefTransport {
        script: Scripted,
        calls: AtomicUsize,
    }

    impl AuthorityTransport for ByRefTransport {
        async fn submit(
            &self,
            _request: &VerifiedSubmission<AuthoritySubmitRequest>,
            _options: &ClientRequestOptions,
        ) -> Result<AuthoritySubmitOutcome> {
            unreachable!("by-ref reads never submit")
        }

        async fn scan(&self, _request: &StreamScanRequest) -> Result<StreamScanOutcome> {
            unreachable!("by-ref reads never scan")
        }

        async fn authority_bundle(
            &self,
            _request: &AuthorityBundleRequest,
        ) -> Result<RealmAuthorityBundle> {
            unreachable!("by-ref reads never resolve authority")
        }

        async fn install_handoff(
            &self,
            _request: &AuthorityHandoffRequest,
            _options: &ClientRequestOptions,
        ) -> Result<RealmAuthorityHandoff> {
            unreachable!("by-ref reads never install a handoff")
        }

        async fn exact_snapshot(
            &self,
            _realm_id: &RealmId,
            _snapshot_id: &RealmSnapshotId,
        ) -> Result<RealmStateSnapshot> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            match &self.script {
                Scripted::Snapshot(snapshot) => Ok((**snapshot).clone()),
                Scripted::Problem(code, status) => Err(Error::Api {
                    status: *status,
                    error: Box::new(Problem::new(*code, *status, "refused")),
                }),
            }
        }
    }

    fn client(script: Scripted) -> AuthorityClient<ByRefTransport> {
        AuthorityClient::new(ByRefTransport {
            script,
            calls: AtomicUsize::new(0),
        })
    }

    fn snapshot(snapshot_id: RealmSnapshotId) -> RealmStateSnapshot {
        let stream_ref = crate::test_fixtures::realm_stream();
        RealmStateSnapshot {
            snapshot_id,
            realm_id: crate::test_fixtures::realm_id(),
            governance_generation: 0,
            visible_stream_heads: vec![CommitStreamHead {
                stream_ref: stream_ref.clone(),
                stream_position: 0,
                commit_id: RealmCommitId::from_digest([3; 32]),
            }],
            current_state_entries: Vec::new(),
            retention_and_history_floor: arkret_wire::RetentionAndHistoryFloor {
                history_access: arkret_wire::HistoryAccess::AllHistoryForCurrentMembers,
                stream_floors: vec![arkret_wire::StreamHistoryFloor {
                    stream_ref,
                    oldest_position: 0,
                }],
            },
            created_at: crate::test_fixtures::at(0),
            signature: crate::test_fixtures::detached_signature(
                DetachedSignatureContext::RealmSnapshot,
            ),
        }
    }

    const ADVERTISED: &[&str] = &[
        "ak.operation_bundle.station.http_core_current.v1",
        "ak.operation_bundle.station.snapshot_exact_read.v1",
    ];

    #[tokio::test]
    async fn by_ref_read_is_gated_classified_and_bound_to_the_request() {
        let realm_id = crate::test_fixtures::realm_id();
        let snapshot_ref = RealmSnapshotId::from_digest([7; 32]);
        let advertised = station_describe(ADVERTISED);

        let unadvertised = client(Scripted::Snapshot(Box::new(snapshot(snapshot_ref.clone()))));
        let error = unadvertised
            .exact_snapshot(
                &station_describe(&["ak.operation_bundle.station.http_core_current.v1"]),
                &realm_id,
                &snapshot_ref,
            )
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            Error::ExactSnapshotRefused(ExactSnapshotRefusal::NotAdvertised)
        ));
        assert_eq!(unadvertised.transport().calls.load(Ordering::SeqCst), 0);

        for (code, status, expected) in [
            (
                "realm_state_snapshot_unavailable",
                503,
                ExactSnapshotRefusal::Unavailable,
            ),
            (
                "capability_denied",
                403,
                ExactSnapshotRefusal::CapabilityDenied,
            ),
        ] {
            let error = client(Scripted::Problem(code, status))
                .exact_snapshot(&advertised, &realm_id, &snapshot_ref)
                .await
                .unwrap_err();
            assert!(
                matches!(error, Error::ExactSnapshotRefused(refusal) if refusal == expected),
                "{code}: {error}"
            );
        }
        let unregistered = client(Scripted::Problem("internal_error", 500))
            .exact_snapshot(&advertised, &realm_id, &snapshot_ref)
            .await
            .unwrap_err();
        assert!(matches!(unregistered, Error::Api { status: 500, .. }));

        let substituted = client(Scripted::Snapshot(Box::new(snapshot(
            RealmSnapshotId::from_digest([8; 32]),
        ))))
        .exact_snapshot(&advertised, &realm_id, &snapshot_ref)
        .await
        .unwrap_err();
        assert!(matches!(substituted, Error::Protocol(_)));

        let exact = client(Scripted::Snapshot(Box::new(snapshot(snapshot_ref.clone()))))
            .exact_snapshot(&advertised, &realm_id, &snapshot_ref)
            .await
            .unwrap();
        assert_eq!(exact.snapshot_id, snapshot_ref);
    }

    fn station_describe(bundles: &[&str]) -> ServiceDescribe {
        ServiceDescribe::development(
            Did::new("did:web:station.example".to_owned()).unwrap(),
            TrustDomainId::new("ak:trust_domain:example.net").unwrap(),
            ServiceKind::Station,
            bundles.iter().map(|id| (*id).to_owned()).collect(),
            vec![TransportBinding::HttpJson {
                base_url: "https://station.example/".to_owned(),
                extension_profile_required: (),
            }],
        )
    }

    #[test]
    fn only_the_advertised_exact_read_bundle_enables_by_ref() {
        assert!(exact_snapshot_read_advertised(&station_describe(&[
            "ak.operation_bundle.station.http_core_current.v1",
            "ak.operation_bundle.station.snapshot_exact_read.v1",
        ])));
        assert!(!exact_snapshot_read_advertised(&station_describe(&[
            "ak.operation_bundle.station.http_core_current.v1",
        ])));
    }

    #[test]
    fn refusals_are_classified_only_by_registered_code_and_status() {
        let cases = [
            (
                "realm_state_snapshot_unavailable",
                503,
                Some(ExactSnapshotRefusal::Unavailable),
            ),
            (
                "realm_state_snapshot_authority_unverified",
                403,
                Some(ExactSnapshotRefusal::AuthorityUnverified),
            ),
            // The operation registers no `not_found`.
            ("not_found", 404, None),
            (
                "capability_denied",
                403,
                Some(ExactSnapshotRefusal::CapabilityDenied),
            ),
            ("realm_state_snapshot_unavailable", 404, None),
            ("internal_error", 500, None),
            ("snapshot_gone", 410, None),
        ];
        for (code, status, expected) in cases {
            let problem = Problem::new(code, status, "refused");
            assert_eq!(
                ExactSnapshotRefusal::from_problem(status, &problem),
                expected,
                "{code}/{status}"
            );
        }
    }
}
