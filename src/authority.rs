//! Current governance-authority transport and submission state.

use std::future::Future;

use arkret_http_client::{Client, ClientRequestOptions};
use arkret_identity::{
    RealmAuthorityFreshness, RealmAuthorityKeyDirectory, verify_realm_authority_bundle,
};
use arkret_models_collaboration::authority_commit::{
    DirectConversationFoundingUnitSubmission, OrdinaryRealmBootstrapUnitSubmission,
    SelfAuthoritySubmitOutcome, SelfAuthoritySubmitRequest,
};
use arkret_wire::{
    AuthorityBundleRequest, AuthorityCommitStatus, AuthorityHandoffRequest,
    AuthorityRejectionStatus, AuthoritySubmitOutcome, AuthoritySubmitRequest, EventId,
    RealmAuthorityBundle, RealmAuthorityHandoff, RealmCommit, RealmId, RealmSnapshotId,
    RealmStateSnapshot, StreamScanOutcome, StreamScanRequest,
};
use serde::{Deserialize, Serialize};

use crate::{Error, MaybeSend, MaybeSendSync, Result};

/// Runtime-neutral boundary over the current authority operations and the
/// exact by-ref read of a Snapshot that anchors a verified stream window.
pub trait AuthorityTransport: MaybeSendSync {
    fn submit<'a>(
        &'a self,
        request: &'a AuthoritySubmitRequest,
        options: &'a ClientRequestOptions,
    ) -> impl Future<Output = Result<AuthoritySubmitOutcome>> + MaybeSend + 'a;

    fn submit_self<'a>(
        &'a self,
        request: &'a SelfAuthoritySubmitRequest,
        options: &'a ClientRequestOptions,
    ) -> impl Future<Output = Result<SelfAuthoritySubmitOutcome>> + MaybeSend + 'a {
        async move {
            let request = match request {
                SelfAuthoritySubmitRequest::Event(value) => {
                    AuthoritySubmitRequest::Event(value.clone())
                }
                SelfAuthoritySubmitRequest::MlsCommit(value) => {
                    AuthoritySubmitRequest::MlsCommit(value.clone())
                }
                _ => {
                    return Err(Error::Protocol(
                        "transport does not implement atomic self submission".to_owned(),
                    ));
                }
            };
            self.submit(&request, options)
                .await
                .map(SelfAuthoritySubmitOutcome::Ordinary)
        }
    }

    fn scan<'a>(
        &'a self,
        request: &'a StreamScanRequest,
    ) -> impl Future<Output = Result<StreamScanOutcome>> + MaybeSend + 'a;

    fn authority_bundle<'a>(
        &'a self,
        request: &'a AuthorityBundleRequest,
    ) -> impl Future<Output = Result<RealmAuthorityBundle>> + MaybeSend + 'a;

    fn install_handoff<'a>(
        &'a self,
        request: &'a AuthorityHandoffRequest,
        options: &'a ClientRequestOptions,
    ) -> impl Future<Output = Result<RealmAuthorityHandoff>> + MaybeSend + 'a;

    /// `ak.self.realm_state_snapshot.read.by_ref.v1`. Registered refusals
    /// stay [`Error::Api`] here; [`AuthorityClient::exact_snapshot`]
    /// classifies them.
    fn exact_snapshot<'a>(
        &'a self,
        realm_id: &'a RealmId,
        snapshot_id: &'a RealmSnapshotId,
    ) -> impl Future<Output = Result<RealmStateSnapshot>> + MaybeSend + 'a;
}

impl AuthorityTransport for Client {
    async fn submit(
        &self,
        request: &AuthoritySubmitRequest,
        options: &ClientRequestOptions,
    ) -> Result<AuthoritySubmitOutcome> {
        let request = match request {
            AuthoritySubmitRequest::Event(value) => {
                SelfAuthoritySubmitRequest::Event(value.clone())
            }
            AuthoritySubmitRequest::MlsCommit(value) => {
                SelfAuthoritySubmitRequest::MlsCommit(value.clone())
            }
        };
        match AuthorityTransport::submit_self(self, &request, options).await? {
            SelfAuthoritySubmitOutcome::Ordinary(outcome) => Ok(outcome),
            _ => Err(crate::Error::Protocol(
                "ordinary queued submission returned an aggregate outcome".to_owned(),
            )),
        }
    }

    async fn submit_self(
        &self,
        request: &SelfAuthoritySubmitRequest,
        options: &ClientRequestOptions,
    ) -> Result<SelfAuthoritySubmitOutcome> {
        let outcome = self.submit_to_realm_authority(request, options).await?;
        let items = accepted_items(request, &outcome)?;
        if !items.is_empty() {
            let mut nonce = [0_u8; 32];
            getrandom::fill(&mut nonce).map_err(|error| Error::Protocol(error.to_string()))?;
            let nonce =
                arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(nonce))
                    .map_err(|error| Error::Protocol(error.to_owned()))?;
            let authority_request = AuthorityBundleRequest {
                realm_id: items[0].commit.realm_id.clone(),
                nonce: nonce.clone(),
            };
            let bundle = AuthorityClient::new(self.clone())
                .resolve_authority(&authority_request)
                .await?;
            let commits = items.iter().map(|item| &item.commit).collect::<Vec<_>>();
            let keys = crate::historical_station_keys::fetch_historical_station_keys_for_commits(
                self, &bundle, &commits,
            )
            .await?;
            verify_accepted_items(
                &items,
                &bundle,
                &RealmAuthorityFreshness::new(chrono::Utc::now(), nonce),
                &keys,
            )?;
        }
        Ok(outcome)
    }

    async fn scan(&self, request: &StreamScanRequest) -> Result<StreamScanOutcome> {
        Ok(self.scan_commit_stream(request).await?)
    }

    async fn authority_bundle(
        &self,
        request: &AuthorityBundleRequest,
    ) -> Result<RealmAuthorityBundle> {
        Ok(self.realm_authority_bundle(request).await?)
    }

    async fn install_handoff(
        &self,
        request: &AuthorityHandoffRequest,
        options: &ClientRequestOptions,
    ) -> Result<RealmAuthorityHandoff> {
        Ok(self
            .install_realm_authority_handoff(request, options)
            .await?)
    }

    async fn exact_snapshot(
        &self,
        realm_id: &RealmId,
        snapshot_id: &RealmSnapshotId,
    ) -> Result<RealmStateSnapshot> {
        Ok(self
            .realm_state_snapshot_by_ref(realm_id, snapshot_id)
            .await?)
    }
}

fn accepted_items(
    request: &SelfAuthoritySubmitRequest,
    outcome: &SelfAuthoritySubmitOutcome,
) -> Result<Vec<arkret_wire::CommittedEventFullView>> {
    outcome.validate_for_request(request)?;
    let pair =
        |event: &arkret_wire::Event, commit: &RealmCommit| arkret_wire::CommittedEventFullView {
            event: event.clone(),
            commit: commit.clone(),
        };
    let items = match (request, outcome) {
        (_, SelfAuthoritySubmitOutcome::Ordinary(AuthoritySubmitOutcome::Rejected { .. })) => {
            vec![]
        }
        (
            SelfAuthoritySubmitRequest::Event(value),
            SelfAuthoritySubmitOutcome::Ordinary(AuthoritySubmitOutcome::Accepted {
                commit, ..
            }),
        ) => vec![pair(&value.event, commit)],
        (
            SelfAuthoritySubmitRequest::MlsCommit(value),
            SelfAuthoritySubmitOutcome::Ordinary(AuthoritySubmitOutcome::Accepted {
                commit, ..
            }),
        ) => vec![pair(&value.commit_event, commit)],
        (
            SelfAuthoritySubmitRequest::OrdinaryRealmBootstrap(value),
            SelfAuthoritySubmitOutcome::OrdinaryRealmBootstrap(accepted),
        ) => value
            .events
            .iter()
            .zip(&accepted.commits)
            .map(|(event, commit)| pair(&event.event, commit))
            .collect(),
        (
            SelfAuthoritySubmitRequest::DirectConversationFounding(value),
            SelfAuthoritySubmitOutcome::DirectConversationFounding(accepted),
        ) => value
            .events
            .iter()
            .zip(&accepted.commits)
            .map(|(event, commit)| pair(&event.event, commit))
            .collect(),
        (
            SelfAuthoritySubmitRequest::MembershipCompensation(value),
            SelfAuthoritySubmitOutcome::MembershipCompensation(accepted),
        ) => vec![pair(&value.event_submission.event, &accepted.commit)],
        _ => {
            return Err(Error::Protocol(
                "acceptance branch does not bind its frozen request".to_owned(),
            ));
        }
    };
    Ok(items)
}

fn verify_accepted_items(
    items: &[arkret_wire::CommittedEventFullView],
    bundle: &RealmAuthorityBundle,
    freshness: &RealmAuthorityFreshness,
    keys: &dyn RealmAuthorityKeyDirectory,
) -> Result<()> {
    let authority = verify_realm_authority_bundle(bundle, freshness, keys)
        .map_err(|error| Error::Protocol(error.to_string()))?;
    for item in items {
        authority
            .verify_committed_item(item, keys)
            .map_err(|error| Error::Protocol(error.to_string()))?;
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum SubmissionState {
    Queued,
    Committed {
        status: AuthorityCommitStatus,
        commit: Box<RealmCommit>,
    },
    UnitCommitted {
        outcome: Box<SelfAuthoritySubmitOutcome>,
    },
    Rejected {
        status: AuthorityRejectionStatus,
        reason_code: String,
    },
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct QueuedSubmission {
    pub request: SelfAuthoritySubmitRequest,
    pub event_id: EventId,
    pub state: SubmissionState,
}

impl<'de> Deserialize<'de> for QueuedSubmission {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error as _;
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Raw {
            request: SelfAuthoritySubmitRequest,
            event_id: EventId,
            state: SubmissionState,
        }
        let raw = Raw::deserialize(deserializer)?;
        let mut queued = Self::from_self(raw.request).map_err(D::Error::custom)?;
        if queued.event_id != raw.event_id {
            return Err(D::Error::custom(
                "queued identity does not bind the frozen request",
            ));
        }
        match raw.state {
            SubmissionState::Queued => {}
            SubmissionState::Committed { status, commit } => queued
                .apply_outcome(AuthoritySubmitOutcome::Accepted {
                    status,
                    commit: *commit,
                })
                .map_err(D::Error::custom)?,
            SubmissionState::Rejected {
                status,
                reason_code,
            } => queued
                .apply_outcome(AuthoritySubmitOutcome::Rejected {
                    status,
                    reason_code,
                })
                .map_err(D::Error::custom)?,
            SubmissionState::UnitCommitted { outcome } => queued
                .apply_self_outcome(*outcome)
                .map_err(D::Error::custom)?,
        }
        Ok(queued)
    }
}

impl QueuedSubmission {
    pub fn new(request: AuthoritySubmitRequest) -> Result<Self> {
        let request = match request {
            AuthoritySubmitRequest::Event(value) => SelfAuthoritySubmitRequest::Event(value),
            AuthoritySubmitRequest::MlsCommit(value) => {
                SelfAuthoritySubmitRequest::MlsCommit(value)
            }
        };
        Self::from_self(request)
    }

    pub fn realm_bootstrap(unit: OrdinaryRealmBootstrapUnitSubmission) -> Result<Self> {
        Self::from_self(SelfAuthoritySubmitRequest::OrdinaryRealmBootstrap(unit))
    }

    pub fn direct_conversation_founding(
        unit: DirectConversationFoundingUnitSubmission,
    ) -> Result<Self> {
        Self::from_self(SelfAuthoritySubmitRequest::DirectConversationFounding(unit))
    }

    fn from_self(request: SelfAuthoritySubmitRequest) -> Result<Self> {
        request.validate()?;
        let event_id = match &request {
            SelfAuthoritySubmitRequest::Event(value) => value.event.event_id.clone(),
            SelfAuthoritySubmitRequest::MlsCommit(value) => value.commit_event.event_id.clone(),
            SelfAuthoritySubmitRequest::OrdinaryRealmBootstrap(value) => {
                value.events[0].event.event_id.clone()
            }
            SelfAuthoritySubmitRequest::DirectConversationFounding(value) => {
                value.events[0].event.event_id.clone()
            }
            _ => {
                return Err(Error::Protocol(
                    "unsupported queued self submission unit".to_owned(),
                ));
            }
        };
        Ok(Self {
            request,
            event_id,
            state: SubmissionState::Queued,
        })
    }

    pub fn validate_queued_request(&self) -> Result<()> {
        let validated = Self::from_self(self.request.clone())?;
        if validated.event_id != self.event_id {
            return Err(Error::Protocol(
                "queued identity does not bind the frozen request".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn primary_event(&self) -> &arkret_wire::Event {
        match &self.request {
            SelfAuthoritySubmitRequest::Event(value) => &value.event,
            SelfAuthoritySubmitRequest::MlsCommit(value) => &value.commit_event,
            SelfAuthoritySubmitRequest::OrdinaryRealmBootstrap(value) => &value.events[0].event,
            SelfAuthoritySubmitRequest::DirectConversationFounding(value) => &value.events[0].event,
            _ => unreachable!("validated queued submission branch"),
        }
    }

    pub fn apply_self_outcome(&mut self, outcome: SelfAuthoritySubmitOutcome) -> Result<()> {
        outcome.validate_for_request(&self.request)?;
        if let (
            SelfAuthoritySubmitRequest::OrdinaryRealmBootstrap(unit),
            SelfAuthoritySubmitOutcome::OrdinaryRealmBootstrap(accepted),
        ) = (&self.request, &outcome)
        {
            for (submission, commit) in unit.events.iter().zip(&accepted.commits) {
                arkret_wire::CommittedEventFullView {
                    event: submission.event.clone(),
                    commit: commit.clone(),
                }
                .validate_shape()?;
            }
        }
        match outcome {
            SelfAuthoritySubmitOutcome::Ordinary(value) => self.apply_outcome(value),
            value @ (SelfAuthoritySubmitOutcome::OrdinaryRealmBootstrap(_)
            | SelfAuthoritySubmitOutcome::DirectConversationFounding(_)) => {
                self.state = SubmissionState::UnitCommitted {
                    outcome: Box::new(value),
                };
                Ok(())
            }
            _ => Err(Error::Protocol(
                "unsupported queued aggregate outcome".to_owned(),
            )),
        }
    }

    pub fn apply_outcome(&mut self, outcome: AuthoritySubmitOutcome) -> Result<()> {
        let ordinary = match &self.request {
            SelfAuthoritySubmitRequest::Event(value) => {
                AuthoritySubmitRequest::Event(value.clone())
            }
            SelfAuthoritySubmitRequest::MlsCommit(value) => {
                AuthoritySubmitRequest::MlsCommit(value.clone())
            }
            _ => {
                return Err(Error::Protocol(
                    "aggregate unit requires its complete outcome".to_owned(),
                ));
            }
        };
        outcome.validate_for_request(&ordinary)?;
        self.state = match outcome {
            AuthoritySubmitOutcome::Accepted { status, commit } => SubmissionState::Committed {
                status,
                commit: Box::new(commit),
            },
            AuthoritySubmitOutcome::Rejected {
                status,
                reason_code,
            } => SubmissionState::Rejected {
                status,
                reason_code,
            },
        };
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct AuthorityClient<T> {
    transport: T,
}

impl<T> AuthorityClient<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }
}

impl<T: AuthorityTransport> AuthorityClient<T> {
    pub async fn submit(
        &self,
        queued: &mut QueuedSubmission,
        options: &ClientRequestOptions,
    ) -> Result<()> {
        queued.validate_queued_request()?;
        let options = match &queued.request {
            SelfAuthoritySubmitRequest::OrdinaryRealmBootstrap(unit) => options
                .clone()
                .idempotency_key(unit.idempotency_key.as_uuid().to_string()),
            SelfAuthoritySubmitRequest::DirectConversationFounding(unit) => options
                .clone()
                .idempotency_key(unit.idempotency_key.as_uuid().to_string()),
            _ => options.clone(),
        };
        let outcome = self
            .transport
            .submit_self(&queued.request, &options)
            .await?;
        queued.apply_self_outcome(outcome)
    }

    /// Fetch a shape-checked but unverified scan page. Consumers MUST pass it
    /// through [`crate::RealmReplica::apply_verified_scan`] before projection.
    pub async fn scan(&self, request: &StreamScanRequest) -> Result<StreamScanOutcome> {
        request.validate()?;
        let outcome = self.transport.scan(request).await?;
        outcome.validate_for_request(request)?;
        Ok(outcome)
    }

    /// Fetch a shape-checked bundle only. Use
    /// [`Self::resolve_verified_authority`] before any authority decision.
    pub async fn resolve_authority(
        &self,
        request: &AuthorityBundleRequest,
    ) -> Result<RealmAuthorityBundle> {
        request.validate()?;
        let bundle = self.transport.authority_bundle(request).await?;
        bundle.validate_for_request(request, chrono::Utc::now())?;
        Ok(bundle)
    }

    /// Fetch a nonce-bound bundle and verify its complete authority chain,
    /// current route, signatures, and caller-supplied freshness before it can
    /// be installed in a replica or used to authenticate scan rows.
    pub async fn resolve_verified_authority(
        &self,
        request: &AuthorityBundleRequest,
        freshness: &RealmAuthorityFreshness,
        keys: &dyn RealmAuthorityKeyDirectory,
    ) -> Result<RealmAuthorityBundle> {
        if freshness.expected_nonce != request.nonce {
            return Err(Error::Protocol(
                "authority freshness does not bind the issued request nonce".to_owned(),
            ));
        }
        let bundle = self.resolve_authority(request).await?;
        verify_realm_authority_bundle(&bundle, freshness, keys)
            .map_err(|error| Error::Protocol(error.to_string()))?;
        Ok(bundle)
    }

    pub async fn install_handoff(
        &self,
        request: &AuthorityHandoffRequest,
        options: &ClientRequestOptions,
    ) -> Result<RealmAuthorityHandoff> {
        request.validate_shape()?;
        let installed = self.transport.install_handoff(request, options).await?;
        installed.validate_shape()?;
        if installed != request.handoff {
            return Err(crate::Error::Protocol(
                "authority handoff response changed the installed handoff".to_owned(),
            ));
        }
        Ok(installed)
    }
}

#[cfg(test)]
mod acceptance_proof_tests {
    use arkret_identity::RealmAuthorityKeyMap;
    use arkret_signatures::PublicKeyMaterial;
    use arkret_signatures::detached_object::sign_detached_object;
    use arkret_wire::{
        CommitStreamHead, DetachedSignatureContext, Did, DidUrl, EventKind,
        RealmAuthorityCurrentAssertion, RealmCommitAuthorityRef, ScopeRef, project_did_to_core_id,
    };
    use chrono::{Duration, Utc};
    use ed25519_dalek::SigningKey;

    use super::*;

    #[test]
    fn receipts_require_signed_authority_and_exact_frozen_events() {
        let route = crate::service_route_material::test_fixture::current_web_route_fixture(
            "station-a.example",
            "station",
            0xA1,
        );
        let now = Utc::now();
        let realm_id = crate::test_fixtures::realm_id();
        let stream_ref = crate::test_fixtures::realm_stream();
        let method = DidUrl::new("did:web:station-a.example#signing-1").unwrap();
        let station =
            project_did_to_core_id(&Did::new("did:web:station-a.example").unwrap()).unwrap();
        let keys = RealmAuthorityKeyMap::new().with_key(
            &method,
            PublicKeyMaterial::Ed25519Raw {
                bytes: route.signing_key.verifying_key().to_bytes().to_vec(),
            },
        );
        let scope = ScopeRef::Realm {
            realm_id: realm_id.clone(),
        };
        let genesis = arkret_wire::test_support::raw_event_at(
            EventKind::RealmCreate.as_str(),
            scope.clone(),
            arkret_wire::DidCoreId::new("ak:did_core:web:founder.example").unwrap(),
            station.clone(),
            serde_json::json!({}),
            now - Duration::seconds(2),
        )
        .unwrap();
        let ordinary = arkret_wire::test_support::raw_event_at(
            EventKind::MessageCreate.as_str(),
            scope,
            arkret_wire::DidCoreId::new("ak:did_core:web:founder.example").unwrap(),
            station.clone(),
            serde_json::json!({}),
            now - Duration::seconds(1),
        )
        .unwrap();
        let seal = |mut commit: RealmCommit, key: &SigningKey| {
            let unsigned =
                arkret_canonical::canonical::unsigned_value(&commit, &["signature"]).unwrap();
            commit.signature = sign_detached_object(
                &unsigned,
                DetachedSignatureContext::RealmCommit,
                method.clone(),
                now,
                key,
            )
            .unwrap();
            commit
        };
        let mut genesis_commit = crate::test_fixtures::commit(1, &genesis, stream_ref.clone(), 0);
        genesis_commit.authority_ref =
            RealmCommitAuthorityRef::GenesisOrChangeEvent(genesis.event_id.clone());
        let genesis_commit = seal(genesis_commit, &route.signing_key);
        let mut ordinary_commit = crate::test_fixtures::commit(2, &ordinary, stream_ref.clone(), 1);
        ordinary_commit.authority_ref =
            RealmCommitAuthorityRef::GenesisOrChangeEvent(genesis.event_id.clone());
        let ordinary_commit = seal(ordinary_commit, &route.signing_key);
        let head = CommitStreamHead {
            stream_ref: stream_ref.clone(),
            stream_position: 1,
            commit_id: ordinary_commit.commit_id.clone(),
        };
        let nonce = arkret_wire::Base64UrlString::new("BBBBBBBBBBBBBBBBBBBBBB").unwrap();
        let mut assertion = RealmAuthorityCurrentAssertion {
            realm_id: realm_id.clone(),
            current_generation: 0,
            current_service_id: station.clone(),
            last_handoff_ref: None,
            realm_stream_head: head.clone(),
            nonce: nonce.clone(),
            expires_at: now + Duration::minutes(5),
            signature: crate::test_fixtures::detached_signature(
                DetachedSignatureContext::RealmAuthorityCurrentAssertion,
            ),
        };
        let unsigned =
            arkret_canonical::canonical::unsigned_value(&assertion, &["signature"]).unwrap();
        assertion.signature = sign_detached_object(
            &unsigned,
            DetachedSignatureContext::RealmAuthorityCurrentAssertion,
            method.clone(),
            now,
            &route.signing_key,
        )
        .unwrap();
        let bundle = RealmAuthorityBundle {
            realm_id: realm_id.clone(),
            genesis_event: genesis.clone(),
            genesis_commit: genesis_commit.clone(),
            authority_transitions: vec![],
            current_generation: 0,
            current_service_id: station,
            current_route_record: serde_json::to_value(&route.resolution).unwrap(),
            realm_stream_head: head,
            bundle_issued_at: now,
            current_assertion: assertion,
        };

        let item = arkret_wire::CommittedEventFullView {
            event: ordinary,
            commit: ordinary_commit,
        };
        let freshness = RealmAuthorityFreshness::new(now, nonce);
        verify_accepted_items(&[item.clone()], &bundle, &freshness, &keys).unwrap();
        let mut forged = item.clone();
        forged.commit.signature.sig =
            arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode([0_u8; 64]))
                .unwrap();
        assert!(verify_accepted_items(&[forged.clone()], &bundle, &freshness, &keys).is_err());
        assert!(
            verify_accepted_items(&[item.clone(), forged], &bundle, &freshness, &keys).is_err()
        );
        let mut wrong_event = item.clone();
        wrong_event.event = genesis;
        assert!(verify_accepted_items(&[wrong_event], &bundle, &freshness, &keys).is_err());
        let mut future_generation = item.clone();
        future_generation.commit.governance_generation = 1;
        assert!(verify_accepted_items(&[future_generation], &bundle, &freshness, &keys).is_err());
        let mut replay = freshness;
        replay.expected_nonce =
            arkret_wire::Base64UrlString::new("CCCCCCCCCCCCCCCCCCCCCC").unwrap();
        assert!(verify_accepted_items(&[item], &bundle, &replay, &keys).is_err());
    }
}
