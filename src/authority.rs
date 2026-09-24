//! Current governance-authority transport and submission state.

use std::future::Future;

use arkret_http_client::{Client, ClientRequestOptions};
use arkret_identity::{
    RealmAuthorityFreshness, RealmAuthorityKeyDirectory, verify_realm_authority_bundle,
};
use arkret_models_collaboration::authority_commit::{
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
        match self.submit_to_realm_authority(&request, options).await? {
            SelfAuthoritySubmitOutcome::Ordinary(outcome) => Ok(outcome),
            _ => Err(crate::Error::Protocol(
                "ordinary queued submission returned an aggregate outcome".to_owned(),
            )),
        }
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

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum SubmissionState {
    Queued,
    Committed {
        status: AuthorityCommitStatus,
        commit: Box<RealmCommit>,
    },
    Rejected {
        status: AuthorityRejectionStatus,
        reason_code: String,
    },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct QueuedSubmission {
    pub request: AuthoritySubmitRequest,
    pub event_id: EventId,
    pub state: SubmissionState,
}

impl QueuedSubmission {
    pub fn new(request: AuthoritySubmitRequest) -> Result<Self> {
        request.validate()?;
        let event_id = match &request {
            AuthoritySubmitRequest::Event(value) => value.event.event_id.clone(),
            AuthoritySubmitRequest::MlsCommit(value) => value.commit_event.event_id.clone(),
        };
        Ok(Self {
            request,
            event_id,
            state: SubmissionState::Queued,
        })
    }

    pub fn apply_outcome(&mut self, outcome: AuthoritySubmitOutcome) -> Result<()> {
        outcome.validate_for_request(&self.request)?;
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
        let outcome = self.transport.submit(&queued.request, options).await?;
        queued.apply_outcome(outcome)
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
