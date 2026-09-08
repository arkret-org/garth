//! Shared `#[cfg(test)]` helpers for the subscription engine and loop driver.
//!
//! `RecordingExecutor`, `sync_response` and `queued_transport` were previously
//! duplicated verbatim across `driver.rs` and `mod.rs`; they live here so both
//! test modules share a single definition.

use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::Executor;
use crate::protocol::{
    AccountSubscribeBatch, AccountSubscribeFrame, AccountSubscribeFrameKind, Result,
    SyncRequestBody,
};

#[derive(Clone, Debug, Default)]
pub(crate) struct RecordingExecutor {
    sleeps: Arc<Mutex<Vec<Duration>>>,
}

impl RecordingExecutor {
    pub(crate) fn sleeps(&self) -> Vec<Duration> {
        self.sleeps.lock().unwrap().clone()
    }
}

impl Executor for RecordingExecutor {
    fn sleep(&self, dur: Duration) -> impl Future<Output = ()> + '_ {
        async move {
            self.sleeps.lock().unwrap().push(dur);
        }
    }
}

pub(crate) fn sync_response(cursor: &str) -> AccountSubscribeBatch {
    AccountSubscribeBatch {
        cursor: cursor.to_owned(),
        frames: vec![AccountSubscribeFrame {
            kind: AccountSubscribeFrameKind::Delta,
            cursor: Some(cursor.to_owned()),
            realms: None,
            to_device: None,
            device_lists: None,
            account_data: None,
            notifications: None,
            agent_signer_evidence_bundle: None,
            partial: None,
            priority: None,
            reconnect_after_ms: None,
        }],
    }
}

pub(crate) fn queued_transport(
    responses: Arc<Mutex<VecDeque<Result<AccountSubscribeBatch>>>>,
) -> impl Fn(
    SyncRequestBody,
    arkret_http_client::ClientRequestOptions,
) -> Pin<Box<dyn Future<Output = Result<AccountSubscribeBatch>> + Send>> {
    move |_request, _options| {
        let responses = Arc::clone(&responses);
        Box::pin(async move {
            responses
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| Ok(sync_response("fallback")))
        })
    }
}

/// Subscription fixtures exercise accepted-envelope projection, not admission verification.
pub(crate) fn structural_only_accepted_event(event: arkret_wire::Event) -> arkret_wire::Event {
    let accepted_at = event.created_at;
    let signer = arkret_test_kit::StructuralOnlyPayloadSigner::new(
        arkret_wire::Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
        arkret_wire::DidUrl::new("did:webvh:z6mkfixture:alice.example#device-1").unwrap(),
    );
    arkret_test_kit::structural_only_admitted_event(
        event,
        &signer,
        arkret_test_kit::StructuralOnlyAdmissionFixture {
            verification_method: arkret_wire::DidUrl::new("did:web:principal.example#admission-1")
                .unwrap(),
            producer_signing_key_did: arkret_wire::DidKey::new("did:key:z6MkhFixtureDeviceKey")
                .unwrap(),
            signer_resolution_evidence_ref: arkret_wire::SignerEvidenceRef::new(format!(
                "ak:signer_evidence:sha256:{}",
                "11".repeat(32)
            ))
            .unwrap(),
            accepted_at,
        },
        arkret_canonical::DigestSuite::Sha256,
    )
    .expect("structural-only accepted fixture builds")
    .expect_structural_only()
}
