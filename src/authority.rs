//! Current governance-authority transport and submission state.

use std::future::Future;

use arkret_http_client::{Client, ClientRequestOptions};
use arkret_models_collaboration::authority_commit::{
    SelfAuthoritySubmitOutcome, SelfAuthoritySubmitRequest,
};
use arkret_wire::{
    AuthorityBundleRequest, AuthorityCommitStatus, AuthorityHandoffRequest,
    AuthorityRejectionStatus, AuthoritySubmitOutcome, AuthoritySubmitRequest,
    CommittedEventResolveOutcome, CommittedEventResolveRequest, EventId, RealmAuthorityBundle,
    RealmAuthorityHandoff, RealmCommit, StreamScanOutcome, StreamScanRequest,
};
use serde::{Deserialize, Serialize};

use crate::{MaybeSend, MaybeSendSync, Result};

/// Runtime-neutral boundary over the five current authority operations.
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

    fn resolve<'a>(
        &'a self,
        request: &'a CommittedEventResolveRequest,
    ) -> impl Future<Output = Result<CommittedEventResolveOutcome>> + MaybeSend + 'a;

    fn authority_bundle<'a>(
        &'a self,
        request: &'a AuthorityBundleRequest,
    ) -> impl Future<Output = Result<RealmAuthorityBundle>> + MaybeSend + 'a;

    fn install_handoff<'a>(
        &'a self,
        request: &'a AuthorityHandoffRequest,
        options: &'a ClientRequestOptions,
    ) -> impl Future<Output = Result<RealmAuthorityHandoff>> + MaybeSend + 'a;
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

    async fn resolve(
        &self,
        request: &CommittedEventResolveRequest,
    ) -> Result<CommittedEventResolveOutcome> {
        Ok(self.resolve_committed_events(request).await?)
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

    pub async fn scan(&self, request: &StreamScanRequest) -> Result<StreamScanOutcome> {
        request.validate()?;
        let outcome = self.transport.scan(request).await?;
        outcome.validate_for_request(request)?;
        Ok(outcome)
    }

    pub async fn resolve(
        &self,
        request: &CommittedEventResolveRequest,
    ) -> Result<CommittedEventResolveOutcome> {
        request.validate()?;
        let outcome = self.transport.resolve(request).await?;
        outcome.validate_for_request(request)?;
        Ok(outcome)
    }

    pub async fn resolve_authority(
        &self,
        request: &AuthorityBundleRequest,
    ) -> Result<RealmAuthorityBundle> {
        request.validate()?;
        let bundle = self.transport.authority_bundle(request).await?;
        bundle.validate_for_request(request, chrono::Utc::now())?;
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
