use std::collections::BTreeMap;
use std::future::Future;
use std::sync::{Arc, Mutex};

use arkret_models_collaboration::history_key::{
    HistoryGovernanceTraversalIntent, HistoryGovernanceTraversalRetention, HistoryKeyRequest,
    HistoryKeyRequestCreateOutcome, HistoryKeyRequestListOutcome, HistoryKeyRequestListQuery,
    HistoryKeyResponseAckOutcome, HistoryKeyResponseAckRequest, HistoryKeyResponseListOutcome,
    HistoryKeyResponseListQuery, HistoryKeyResponseSendOutcome, HistoryKeyResponseSendRequest,
    HistoryKeySourceRelay, HistoryRequestId, HistoryResponseAckEntry,
    HistoryResponseChunkDescriptor, HistoryResponseId, HistoryResponsePageEntry,
    HistoryResponseRecordStatus, SelfHistoryTraversalAccess, response_capability_commitment,
};
use arkret_state::mls_governance_proof::MlsGovernanceVerificationCheckpoint;
use arkret_wire::{Hash, SealBasis};
use serde::{Deserialize, Serialize};

use crate::store::{SecretClass, SecretDurability, SecureKeyStore};
use crate::{Error, MaybeSend, MaybeSendSync, PutSecretOptions, Result};

const HISTORY_RESPONSE_CAPABILITY_PREFIX: &str = "arkret/history-response-capability/v1/";
const HISTORY_RUNTIME_CAS_RETRY_LIMIT: usize = 16;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableHistoryRequest {
    pub request: HistoryKeyRequest,
    pub request_digest: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepted: Option<HistoryKeyRequestCreateOutcome>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_capability_secret_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_stream: Option<DurableHistoryResponseStream>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified_traversal_basis: Option<SealBasis>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableHistoryResponseStream {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acknowledged_through_cursor: Option<String>,
    pub acknowledged_through_sequence: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_page: Option<HistoryKeyResponseListOutcome>,
    pub pending_dispositions: BTreeMap<u64, HistoryResponseAckEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_ack: Option<HistoryKeyResponseAckRequest>,
    #[serde(default)]
    pub verified_manifests: BTreeMap<String, DurableVerifiedHistoryManifest>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableVerifiedHistoryManifest {
    pub response_id: HistoryResponseId,
    pub source_actor_id: arkret_wire::DidCoreId,
    pub source_sender_domain: String,
    pub manifest_digest: Hash,
    pub manifest_admission_digest: Hash,
    pub chunks: Vec<HistoryResponseChunkDescriptor>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DurableHistoryResponseAttempt {
    Direct {
        request: HistoryKeyResponseSendRequest,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        receipt: Option<HistoryKeyResponseSendOutcome>,
    },
    Relay {
        relay: HistoryKeySourceRelay,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        receipt: Option<HistoryKeyResponseSendOutcome>,
    },
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryRuntimeSnapshot {
    pub requests: BTreeMap<String, DurableHistoryRequest>,
    pub response_attempts: BTreeMap<String, DurableHistoryResponseAttempt>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VersionedHistoryRuntimeSnapshot {
    pub revision: u64,
    pub snapshot: HistoryRuntimeSnapshot,
}

pub trait HistoryRuntimeStore: Clone + MaybeSendSync + 'static {
    fn load_history_runtime(&self) -> Result<VersionedHistoryRuntimeSnapshot>;

    fn compare_and_swap_history_runtime<'a>(
        &'a self,
        expected_revision: u64,
        snapshot: &'a HistoryRuntimeSnapshot,
    ) -> impl Future<Output = Result<bool>> + MaybeSend + 'a;
}

#[derive(Clone, Default)]
pub struct MemoryHistoryRuntimeStore {
    snapshot: Arc<Mutex<VersionedHistoryRuntimeSnapshot>>,
}

impl MemoryHistoryRuntimeStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl HistoryRuntimeStore for MemoryHistoryRuntimeStore {
    fn load_history_runtime(&self) -> Result<VersionedHistoryRuntimeSnapshot> {
        self.snapshot
            .lock()
            .map_err(|_| Error::Protocol("history runtime store lock poisoned".to_owned()))
            .map(|snapshot| snapshot.clone())
    }

    fn compare_and_swap_history_runtime<'a>(
        &'a self,
        expected_revision: u64,
        snapshot: &'a HistoryRuntimeSnapshot,
    ) -> impl Future<Output = Result<bool>> + MaybeSend + 'a {
        async move {
            let mut current = self
                .snapshot
                .lock()
                .map_err(|_| Error::Protocol("history runtime store lock poisoned".to_owned()))?;
            if current.revision != expected_revision {
                return Ok(false);
            }
            current.revision = current
                .revision
                .checked_add(1)
                .ok_or_else(|| Error::Protocol("history runtime revision overflow".to_owned()))?;
            current.snapshot = snapshot.clone();
            Ok(true)
        }
    }
}

pub trait HistoryRuntimeTransport: MaybeSendSync {
    fn create_request<'a>(
        &'a self,
        request: &'a HistoryKeyRequest,
    ) -> impl Future<Output = Result<HistoryKeyRequestCreateOutcome>> + MaybeSend + 'a;

    fn list_requests<'a>(
        &'a self,
        query: &'a HistoryKeyRequestListQuery,
    ) -> impl Future<Output = Result<HistoryKeyRequestListOutcome>> + MaybeSend + 'a;

    fn send_response<'a>(
        &'a self,
        request: &'a HistoryKeyResponseSendRequest,
    ) -> impl Future<Output = Result<HistoryKeyResponseSendOutcome>> + MaybeSend + 'a;

    fn relay_response<'a>(
        &'a self,
        relay: &'a HistoryKeySourceRelay,
    ) -> impl Future<Output = Result<HistoryKeyResponseSendOutcome>> + MaybeSend + 'a;

    fn list_responses<'a>(
        &'a self,
        capability_b64u: &'a str,
        query: &'a HistoryKeyResponseListQuery,
    ) -> impl Future<Output = Result<HistoryKeyResponseListOutcome>> + MaybeSend + 'a;

    fn acknowledge_responses<'a>(
        &'a self,
        capability_b64u: &'a str,
        request: &'a HistoryKeyResponseAckRequest,
    ) -> impl Future<Output = Result<HistoryKeyResponseAckOutcome>> + MaybeSend + 'a;
}

impl HistoryRuntimeTransport for arkret_http_client::Client {
    fn create_request<'a>(
        &'a self,
        request: &'a HistoryKeyRequest,
    ) -> impl Future<Output = Result<HistoryKeyRequestCreateOutcome>> + MaybeSend + 'a {
        async move { Ok(self.history_key_request_create(request).await?) }
    }

    fn list_requests<'a>(
        &'a self,
        query: &'a HistoryKeyRequestListQuery,
    ) -> impl Future<Output = Result<HistoryKeyRequestListOutcome>> + MaybeSend + 'a {
        async move { Ok(self.history_key_request_list(query).await?) }
    }

    fn send_response<'a>(
        &'a self,
        request: &'a HistoryKeyResponseSendRequest,
    ) -> impl Future<Output = Result<HistoryKeyResponseSendOutcome>> + MaybeSend + 'a {
        async move { Ok(self.history_key_response_send(request).await?) }
    }

    fn relay_response<'a>(
        &'a self,
        relay: &'a HistoryKeySourceRelay,
    ) -> impl Future<Output = Result<HistoryKeyResponseSendOutcome>> + MaybeSend + 'a {
        async move { Ok(self.peer_history_key_response_relay(relay).await?) }
    }

    fn list_responses<'a>(
        &'a self,
        capability_b64u: &'a str,
        query: &'a HistoryKeyResponseListQuery,
    ) -> impl Future<Output = Result<HistoryKeyResponseListOutcome>> + MaybeSend + 'a {
        async move {
            Ok(self
                .history_key_response_list(capability_b64u, query)
                .await?)
        }
    }

    fn acknowledge_responses<'a>(
        &'a self,
        capability_b64u: &'a str,
        request: &'a HistoryKeyResponseAckRequest,
    ) -> impl Future<Output = Result<HistoryKeyResponseAckOutcome>> + MaybeSend + 'a {
        async move {
            Ok(self
                .history_key_response_ack(capability_b64u, request)
                .await?)
        }
    }
}

pub trait HistoryResponseCapabilityOpener: MaybeSendSync {
    fn open_response_capability<'a>(
        &'a self,
        outcome: &'a HistoryKeyRequestCreateOutcome,
    ) -> impl Future<Output = Result<String>> + MaybeSend + 'a;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedHistoryTraversal {
    pub checkpoint: MlsGovernanceVerificationCheckpoint,
}

pub trait ReceiptBoundHistoryTraversal: MaybeSendSync {
    fn acquire_and_verify<'a>(
        &'a self,
        retention: &'a HistoryGovernanceTraversalRetention,
        access: &'a SelfHistoryTraversalAccess,
    ) -> impl Future<Output = Result<VerifiedHistoryTraversal>> + MaybeSend + 'a;
}

pub struct HistoryRuntime<S> {
    store: S,
}

impl<S> HistoryRuntime<S>
where
    S: HistoryRuntimeStore,
{
    pub fn new(store: S) -> Self {
        Self { store }
    }

    pub fn store(&self) -> &S {
        &self.store
    }

    async fn mutate<R>(
        &self,
        mut mutation: impl FnMut(&mut HistoryRuntimeSnapshot) -> Result<R>,
    ) -> Result<R> {
        for _ in 0..HISTORY_RUNTIME_CAS_RETRY_LIMIT {
            let current = self.store.load_history_runtime()?;
            let mut next = current.snapshot;
            let result = mutation(&mut next)?;
            if self
                .store
                .compare_and_swap_history_runtime(current.revision, &next)
                .await?
            {
                return Ok(result);
            }
        }
        Err(Error::Protocol(
            "history runtime store remained concurrently modified".to_owned(),
        ))
    }

    pub async fn create_or_resume_request<T, O>(
        &self,
        transport: &T,
        opener: &O,
        secure_store: &dyn SecureKeyStore,
        request: HistoryKeyRequest,
    ) -> Result<HistoryKeyRequestCreateOutcome>
    where
        T: HistoryRuntimeTransport,
        O: HistoryResponseCapabilityOpener,
    {
        request.validate()?;
        let request_digest = request.request_digest()?;
        let request_key = request.request_id.as_str().to_owned();
        let existing_accepted = self
            .mutate(|snapshot| match snapshot.requests.get(&request_key) {
                Some(existing) if existing.request != request => {
                    Err(Error::IdempotencyConflict(request_key.clone()))
                }
                Some(existing) => Ok(existing.accepted.clone()),
                None => {
                    snapshot.requests.insert(
                        request_key.clone(),
                        DurableHistoryRequest {
                            request: request.clone(),
                            request_digest: request_digest.clone(),
                            accepted: None,
                            response_capability_secret_ref: None,
                            response_stream: None,
                            verified_traversal_basis: None,
                        },
                    );
                    Ok(None)
                }
            })
            .await?;

        let accepted = match existing_accepted {
            Some(accepted) => accepted,
            None => {
                let received = transport.create_request(&request).await?;
                validate_accepted_request(&request, &request_digest, &received)?;
                self.mutate(|snapshot| {
                    let state = request_state_mut(snapshot, &request.request_id)?;
                    if state.request != request {
                        return Err(Error::IdempotencyConflict(request_key.clone()));
                    }
                    match &state.accepted {
                        Some(existing) if existing != &received => {
                            Err(Error::IdempotencyConflict(request_key.clone()))
                        }
                        Some(existing) => Ok(existing.clone()),
                        None => {
                            state.accepted = Some(received.clone());
                            Ok(received.clone())
                        }
                    }
                })
                .await?
            }
        };

        let capability_missing = self
            .store
            .load_history_runtime()?
            .snapshot
            .requests
            .get(&request_key)
            .ok_or_else(|| Error::Protocol("history request disappeared".to_owned()))?
            .response_capability_secret_ref
            .is_none();
        if capability_missing {
            let capability = opener.open_response_capability(&accepted).await?;
            validate_opened_response_capability(&accepted, &capability)?;
            let capability_ref =
                history_response_capability_secret_ref(&accepted.request.request_id);
            secure_store
                .put_secret(
                    &capability_ref,
                    capability.as_bytes(),
                    PutSecretOptions {
                        durability: SecretDurability::DurableBeforeReturn,
                        class: SecretClass::MlsSecret,
                    },
                )
                .await?;
            self.mutate(|snapshot| {
                let state = request_state_mut(snapshot, &request.request_id)?;
                if state.accepted.as_ref() != Some(&accepted) {
                    return Err(Error::IdempotencyConflict(request_key.clone()));
                }
                if let Some(existing_ref) = &state.response_capability_secret_ref {
                    if existing_ref != &capability_ref {
                        return Err(Error::IdempotencyConflict(request_key.clone()));
                    }
                    return Ok(());
                }
                state.response_capability_secret_ref = Some(capability_ref.clone());
                state.response_stream = Some(DurableHistoryResponseStream {
                    acknowledged_through_cursor: None,
                    acknowledged_through_sequence: None,
                    pending_page: None,
                    pending_dispositions: BTreeMap::new(),
                    pending_ack: None,
                    verified_manifests: BTreeMap::new(),
                });
                Ok(())
            })
            .await?;
        }
        Ok(accepted)
    }

    pub async fn list_requests<T>(
        &self,
        transport: &T,
        query: &HistoryKeyRequestListQuery,
    ) -> Result<HistoryKeyRequestListOutcome>
    where
        T: HistoryRuntimeTransport,
    {
        query.validate()?;
        let outcome = transport.list_requests(query).await?;
        outcome.validate()?;
        Ok(outcome)
    }

    pub async fn send_response_exact<T>(
        &self,
        transport: &T,
        request: HistoryKeyResponseSendRequest,
    ) -> Result<HistoryKeyResponseSendOutcome>
    where
        T: HistoryRuntimeTransport,
    {
        request.validate()?;
        let key = request.response_id.as_str().to_owned();
        let stored_receipt = self
            .mutate(|snapshot| match snapshot.response_attempts.get(&key) {
                Some(DurableHistoryResponseAttempt::Direct {
                    request: existing,
                    receipt,
                }) if existing == &request => Ok(receipt.clone()),
                Some(_) => Err(Error::IdempotencyConflict(key.clone())),
                None => {
                    snapshot.response_attempts.insert(
                        key.clone(),
                        DurableHistoryResponseAttempt::Direct {
                            request: request.clone(),
                            receipt: None,
                        },
                    );
                    Ok(None)
                }
            })
            .await?;
        if let Some(receipt) = stored_receipt {
            return Ok(receipt);
        }
        let receipt = transport.send_response(&request).await?;
        receipt.validate()?;
        if receipt.response_id != request.response_id {
            return Err(Error::Protocol(
                "history response receipt changed response_id".to_owned(),
            ));
        }
        self.mutate(|snapshot| {
            let Some(DurableHistoryResponseAttempt::Direct {
                request: existing,
                receipt: stored,
            }) = snapshot.response_attempts.get_mut(&key)
            else {
                return Err(Error::IdempotencyConflict(key.clone()));
            };
            if existing != &request {
                return Err(Error::IdempotencyConflict(key.clone()));
            }
            match stored {
                Some(existing) if existing != &receipt => {
                    Err(Error::IdempotencyConflict(key.clone()))
                }
                Some(existing) => Ok(existing.clone()),
                None => {
                    *stored = Some(receipt.clone());
                    Ok(receipt.clone())
                }
            }
        })
        .await
    }

    pub async fn relay_response_exact<T>(
        &self,
        transport: &T,
        relay: HistoryKeySourceRelay,
    ) -> Result<HistoryKeyResponseSendOutcome>
    where
        T: HistoryRuntimeTransport,
    {
        relay.validate()?;
        let key = relay.response.response_id.as_str().to_owned();
        let stored_receipt = self
            .mutate(|snapshot| match snapshot.response_attempts.get(&key) {
                Some(DurableHistoryResponseAttempt::Relay {
                    relay: existing,
                    receipt,
                }) if existing == &relay => Ok(receipt.clone()),
                Some(_) => Err(Error::IdempotencyConflict(key.clone())),
                None => {
                    snapshot.response_attempts.insert(
                        key.clone(),
                        DurableHistoryResponseAttempt::Relay {
                            relay: relay.clone(),
                            receipt: None,
                        },
                    );
                    Ok(None)
                }
            })
            .await?;
        if let Some(receipt) = stored_receipt {
            return Ok(receipt);
        }
        let receipt = transport.relay_response(&relay).await?;
        receipt.validate()?;
        if receipt.response_id != relay.response.response_id {
            return Err(Error::Protocol(
                "history relay receipt changed response_id".to_owned(),
            ));
        }
        self.mutate(|snapshot| {
            let Some(DurableHistoryResponseAttempt::Relay {
                relay: existing,
                receipt: stored,
            }) = snapshot.response_attempts.get_mut(&key)
            else {
                return Err(Error::IdempotencyConflict(key.clone()));
            };
            if existing != &relay {
                return Err(Error::IdempotencyConflict(key.clone()));
            }
            match stored {
                Some(existing) if existing != &receipt => {
                    Err(Error::IdempotencyConflict(key.clone()))
                }
                Some(existing) => Ok(existing.clone()),
                None => {
                    *stored = Some(receipt.clone());
                    Ok(receipt.clone())
                }
            }
        })
        .await
    }

    pub async fn acquire_response_page<T>(
        &self,
        transport: &T,
        secure_store: &dyn SecureKeyStore,
        request_id: &HistoryRequestId,
        limit: Option<u8>,
    ) -> Result<HistoryKeyResponseListOutcome>
    where
        T: HistoryRuntimeTransport,
    {
        let snapshot = self.store.load_history_runtime()?.snapshot;
        let state = snapshot.requests.get(request_id.as_str()).ok_or_else(|| {
            Error::Protocol(format!("history request is not durable: {request_id}"))
        })?;
        let response_stream = state.response_stream.as_ref().ok_or_else(|| {
            Error::Protocol("history request response stream is not initialized".to_owned())
        })?;
        if let Some(page) = &response_stream.pending_page {
            return Ok(page.clone());
        }
        let capability_ref = state
            .response_capability_secret_ref
            .as_deref()
            .ok_or_else(|| {
                Error::Protocol("history response stream capability is missing".to_owned())
            })?;
        let capability = secure_store.get_secret(capability_ref)?.ok_or_else(|| {
            Error::Protocol("history response stream capability bytes are missing".to_owned())
        })?;
        let query = HistoryKeyResponseListQuery {
            after: response_stream.acknowledged_through_cursor.clone(),
            limit,
        };
        query.validate()?;
        let page = transport.list_responses(&capability, &query).await?;
        page.validate()?;
        self.mutate(|snapshot| {
            let state = request_state_mut(snapshot, request_id)?;
            let response_stream = state.response_stream.as_mut().ok_or_else(|| {
                Error::Protocol("history request response stream is not initialized".to_owned())
            })?;
            if let Some(existing) = &response_stream.pending_page {
                return Ok(existing.clone());
            }
            validate_page_after_high_water(response_stream, &page)?;
            response_stream.pending_page = Some(page.clone());
            response_stream.pending_dispositions.clear();
            response_stream.pending_ack = None;
            Ok(page.clone())
        })
        .await
    }

    pub async fn record_response_disposition(
        &self,
        request_id: &HistoryRequestId,
        disposition: HistoryResponseAckEntry,
    ) -> Result<()> {
        self.mutate(|snapshot| {
            let state = request_state_mut(snapshot, request_id)?;
            let response_stream = state.response_stream.as_mut().ok_or_else(|| {
                Error::Protocol("history request response stream is not initialized".to_owned())
            })?;
            let page = response_stream.pending_page.as_ref().ok_or_else(|| {
                Error::Protocol("history response stream has no pending page".to_owned())
            })?;
            validate_disposition_for_page(page, &disposition)?;
            if let Some(existing) = response_stream
                .pending_dispositions
                .get(&disposition.sequence())
                && existing != &disposition
            {
                return Err(Error::IdempotencyConflict(format!(
                    "history-response-stream-disposition:{}",
                    disposition.sequence()
                )));
            }
            response_stream
                .pending_dispositions
                .insert(disposition.sequence(), disposition.clone());
            Ok(())
        })
        .await
    }

    pub fn durable_request(&self, request_id: &HistoryRequestId) -> Result<DurableHistoryRequest> {
        Ok(self
            .store
            .load_history_runtime()?
            .snapshot
            .requests
            .get(request_id.as_str())
            .cloned()
            .ok_or_else(|| {
                Error::Protocol(format!("history request is not durable: {request_id}"))
            })?)
    }

    /// Return the canonical ids of all durably accepted requests whose
    /// response_stream can be polled. Ordering is deterministic by request id.
    pub fn accepted_request_ids(&self) -> Result<Vec<HistoryRequestId>> {
        Ok(self
            .store
            .load_history_runtime()?
            .snapshot
            .requests
            .values()
            .filter(|request| request.accepted.is_some() && request.response_stream.is_some())
            .map(|request| request.request.request_id.clone())
            .collect())
    }

    pub fn verified_manifest(
        &self,
        request_id: &HistoryRequestId,
        manifest_digest: &Hash,
    ) -> Result<Option<DurableVerifiedHistoryManifest>> {
        let request = self.durable_request(request_id)?;
        let response_stream = request.response_stream.ok_or_else(|| {
            Error::Protocol("history request response stream is not initialized".to_owned())
        })?;
        Ok(response_stream
            .verified_manifests
            .get(manifest_digest.as_str())
            .cloned())
    }

    pub async fn install_verified_manifest(
        &self,
        request_id: &HistoryRequestId,
        manifest: DurableVerifiedHistoryManifest,
    ) -> Result<()> {
        self.mutate(|snapshot| {
            let state = request_state_mut(snapshot, request_id)?;
            let response_stream = state.response_stream.as_mut().ok_or_else(|| {
                Error::Protocol("history request response stream is not initialized".to_owned())
            })?;
            match response_stream
                .verified_manifests
                .get(manifest.manifest_digest.as_str())
            {
                Some(existing) if existing != &manifest => Err(Error::IdempotencyConflict(
                    format!("history-manifest:{}", manifest.manifest_digest),
                )),
                Some(_) => Ok(()),
                None => {
                    response_stream
                        .verified_manifests
                        .insert(manifest.manifest_digest.to_string(), manifest.clone());
                    Ok(())
                }
            }
        })
        .await
    }

    pub async fn acknowledge_ready_page<T>(
        &self,
        transport: &T,
        secure_store: &dyn SecureKeyStore,
        request_id: &HistoryRequestId,
    ) -> Result<HistoryKeyResponseAckOutcome>
    where
        T: HistoryRuntimeTransport,
    {
        let (capability_ref, ack) = {
            self.mutate(|snapshot| {
                let state = request_state_mut(snapshot, request_id)?;
                let capability_ref =
                    state
                        .response_capability_secret_ref
                        .clone()
                        .ok_or_else(|| {
                            Error::Protocol(
                                "history response stream capability is missing".to_owned(),
                            )
                        })?;
                let response_stream = state.response_stream.as_mut().ok_or_else(|| {
                    Error::Protocol("history request response stream is not initialized".to_owned())
                })?;
                let ack = match &response_stream.pending_ack {
                    Some(ack) => ack.clone(),
                    None => build_ack_for_pending_page(response_stream)?,
                };
                response_stream.pending_ack = Some(ack.clone());
                Ok((capability_ref, ack))
            })
            .await?
        };
        let capability = secure_store.get_secret(&capability_ref)?.ok_or_else(|| {
            Error::Protocol("history response stream capability bytes are missing".to_owned())
        })?;

        let outcome = transport.acknowledge_responses(&capability, &ack).await?;
        outcome.validate()?;
        if outcome.acked_through_cursor != ack.high_water_cursor {
            return Err(Error::Protocol(
                "history ACK outcome changed the high-water cursor".to_owned(),
            ));
        }
        let high_sequence = ack
            .ack_entries
            .last()
            .expect("validated ACK contains entries")
            .sequence();
        self.mutate(|snapshot| {
            let state = request_state_mut(snapshot, request_id)?;
            let response_stream = state.response_stream.as_mut().ok_or_else(|| {
                Error::Protocol("history request response stream is not initialized".to_owned())
            })?;
            if !advance_ack_high_water(response_stream, &ack.high_water_cursor, high_sequence)? {
                return Ok(());
            }
            if response_stream.pending_ack.as_ref() != Some(&ack) {
                return Err(Error::IdempotencyConflict(format!(
                    "history-response-stream-ack:{}",
                    request_id.as_str()
                )));
            }
            response_stream.pending_page = None;
            response_stream.pending_dispositions.clear();
            response_stream.pending_ack = None;
            Ok(())
        })
        .await?;
        Ok(outcome)
    }

    pub async fn acquire_receipt_bound_traversal<A>(
        &self,
        acquirer: &A,
        request_id: &HistoryRequestId,
    ) -> Result<VerifiedHistoryTraversal>
    where
        A: ReceiptBoundHistoryTraversal,
    {
        let snapshot = self.store.load_history_runtime()?.snapshot;
        let (retention, target_basis, realm_id, receipt_digest) = {
            let state = snapshot.requests.get(request_id.as_str()).ok_or_else(|| {
                Error::Protocol(format!("history request is not durable: {request_id}"))
            })?;
            let accepted = state
                .accepted
                .as_ref()
                .ok_or_else(|| Error::Protocol("history request is not accepted".to_owned()))?;
            validate_receipt_bound_traversal(&state.request, &state.request_digest, accepted)?;
            (
                accepted.request_receipt.history_traversal_retention.clone(),
                traversal_target_basis(
                    &accepted
                        .request_receipt
                        .history_traversal_retention
                        .traversal_intent,
                )
                .clone(),
                scope_realm_id(&state.request.effective_scope),
                accepted.request_receipt.request_receipt_digest()?,
            )
        };
        let access = SelfHistoryTraversalAccess::RequestReceipt {
            request_receipt_digest: receipt_digest,
        };
        let verified = acquirer.acquire_and_verify(&retention, &access).await?;
        verified.checkpoint.validate_checkpoint()?;
        if verified.checkpoint.basis != target_basis || verified.checkpoint.realm_id != realm_id {
            return Err(Error::Protocol(
                "verified history traversal checkpoint does not match receipt target".to_owned(),
            ));
        }
        let trusted_current_basis = traversal_trusted_current_basis(&retention.traversal_intent);
        let trusted_history_base_basis =
            traversal_trusted_history_base_basis(&retention.traversal_intent);
        if !checkpoint_contains_basis(&verified.checkpoint, trusted_current_basis)
            || !checkpoint_contains_basis(&verified.checkpoint, trusted_history_base_basis)
        {
            return Err(Error::Protocol(
                "verified history traversal target does not dominate both signed bases".to_owned(),
            ));
        }
        self.mutate(|snapshot| {
            let state = request_state_mut(snapshot, request_id)?;
            let accepted = state
                .accepted
                .as_ref()
                .ok_or_else(|| Error::Protocol("history request is not accepted".to_owned()))?;
            validate_receipt_bound_traversal(&state.request, &state.request_digest, accepted)?;
            let current_target = traversal_target_basis(
                &accepted
                    .request_receipt
                    .history_traversal_retention
                    .traversal_intent,
            );
            if current_target != &verified.checkpoint.basis {
                return Err(Error::IdempotencyConflict(format!(
                    "history-traversal:{}",
                    request_id.as_str()
                )));
            }
            state.verified_traversal_basis = Some(verified.checkpoint.basis.clone());
            Ok(())
        })
        .await?;
        Ok(verified)
    }
}

fn validate_accepted_request(
    request: &HistoryKeyRequest,
    request_digest: &Hash,
    accepted: &HistoryKeyRequestCreateOutcome,
) -> Result<()> {
    accepted.validate()?;
    if accepted.request != *request || accepted.request_receipt.request_digest != *request_digest {
        return Err(Error::Protocol(
            "history create outcome does not bind the exact request".to_owned(),
        ));
    }
    validate_receipt_bound_traversal(request, request_digest, accepted)
}

fn validate_opened_response_capability(
    accepted: &HistoryKeyRequestCreateOutcome,
    capability_b64u: &str,
) -> Result<()> {
    let receipt = &accepted.request_receipt;
    if accepted
        .sealed_history_response_capability
        .sealed_response_capability_digest()?
        != receipt.sealed_response_capability_digest
        || response_capability_commitment(capability_b64u)?
            != receipt.response_capability_commitment
    {
        return Err(Error::Protocol(
            "opened history response stream capability does not match request receipt".to_owned(),
        ));
    }
    Ok(())
}

fn validate_receipt_bound_traversal(
    request: &HistoryKeyRequest,
    request_digest: &Hash,
    accepted: &HistoryKeyRequestCreateOutcome,
) -> Result<()> {
    let receipt = &accepted.request_receipt;
    receipt.history_traversal_retention.validate_digest()?;
    let HistoryGovernanceTraversalIntent::MemberHistoryDelivery {
        effective_scope,
        mls_group_id,
        trusted_history_base_basis,
        trusted_current_basis,
        target_basis,
        request_digest: intent_request_digest,
        requested_ranges,
        authorization_incarnation,
        retention,
        ..
    } = &receipt.history_traversal_retention.traversal_intent
    else {
        return Err(Error::Protocol(
            "history request receipt used a non-member traversal intent".to_owned(),
        ));
    };
    validate_release_target_basis(trusted_current_basis, target_basis)?;
    if effective_scope != &request.effective_scope
        || mls_group_id != &request.effective_scope.canonical_mls_group_id()?
        || trusted_history_base_basis != &request.trusted_history_base_basis
        || trusted_current_basis != &request.trusted_current_basis
        || intent_request_digest != request_digest
        || requested_ranges != &request.requested_ranges
        || authorization_incarnation != &request.requester_authorization_incarnation
        || retention.expires_at != request.expires_at
        || receipt.expires_at != request.expires_at
    {
        return Err(Error::Protocol(
            "history traversal retention does not bind the exact accepted request".to_owned(),
        ));
    }
    Ok(())
}

fn validate_release_target_basis(
    trusted_current_basis: &SealBasis,
    target_basis: &SealBasis,
) -> Result<()> {
    trusted_current_basis.validate_protocol_bounds()?;
    target_basis.validate_protocol_bounds()?;
    Ok(())
}

fn traversal_target_basis(intent: &HistoryGovernanceTraversalIntent) -> &SealBasis {
    match intent {
        HistoryGovernanceTraversalIntent::MemberHistoryDelivery { target_basis, .. }
        | HistoryGovernanceTraversalIntent::OrganizationRecoveryArchive { target_basis, .. } => {
            target_basis
        }
    }
}

fn traversal_trusted_history_base_basis(intent: &HistoryGovernanceTraversalIntent) -> &SealBasis {
    match intent {
        HistoryGovernanceTraversalIntent::MemberHistoryDelivery {
            trusted_history_base_basis,
            ..
        }
        | HistoryGovernanceTraversalIntent::OrganizationRecoveryArchive {
            trusted_history_base_basis,
            ..
        } => trusted_history_base_basis,
    }
}

fn traversal_trusted_current_basis(intent: &HistoryGovernanceTraversalIntent) -> &SealBasis {
    match intent {
        HistoryGovernanceTraversalIntent::MemberHistoryDelivery {
            trusted_current_basis,
            ..
        }
        | HistoryGovernanceTraversalIntent::OrganizationRecoveryArchive {
            trusted_current_basis,
            ..
        } => trusted_current_basis,
    }
}

fn checkpoint_contains_basis(
    checkpoint: &MlsGovernanceVerificationCheckpoint,
    basis: &SealBasis,
) -> bool {
    seal_ids_contain_basis(checkpoint.accepted_seals.iter().map(|seal| &seal.id), basis)
}

fn seal_ids_contain_basis<'a>(
    seal_ids: impl IntoIterator<Item = &'a arkret_wire::SealId>,
    basis: &SealBasis,
) -> bool {
    let accepted = seal_ids
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();
    basis.leaves.iter().all(|leaf| accepted.contains(leaf))
}

fn scope_realm_id(scope: &arkret_wire::HistoryEffectiveScope) -> arkret_wire::RealmId {
    match scope {
        arkret_wire::HistoryEffectiveScope::Realm { realm_id }
        | arkret_wire::HistoryEffectiveScope::Circle { realm_id, .. } => realm_id.clone(),
    }
}

fn history_response_capability_secret_ref(request_id: &HistoryRequestId) -> String {
    format!(
        "{HISTORY_RESPONSE_CAPABILITY_PREFIX}{}",
        request_id.as_str()
    )
}

fn request_state_mut<'a>(
    snapshot: &'a mut HistoryRuntimeSnapshot,
    request_id: &HistoryRequestId,
) -> Result<&'a mut DurableHistoryRequest> {
    snapshot
        .requests
        .get_mut(request_id.as_str())
        .ok_or_else(|| Error::Protocol(format!("history request is not durable: {request_id}")))
}

fn validate_page_after_high_water(
    response_stream: &DurableHistoryResponseStream,
    page: &HistoryKeyResponseListOutcome,
) -> Result<()> {
    if let (Some(high), Some(first)) = (
        response_stream.acknowledged_through_sequence,
        page.ack_entries.first(),
    ) && first.sequence() <= high
    {
        return Err(Error::Protocol(
            "history response stream page did not advance beyond acknowledged high-water"
                .to_owned(),
        ));
    }
    Ok(())
}

fn validate_disposition_for_page(
    page: &HistoryKeyResponseListOutcome,
    disposition: &HistoryResponseAckEntry,
) -> Result<()> {
    let entry = page
        .ack_entries
        .iter()
        .find(|entry| entry.sequence() == disposition.sequence())
        .ok_or_else(|| {
            Error::Protocol(
                "history response stream disposition is outside pending page".to_owned(),
            )
        })?;
    match (entry, disposition) {
        (
            HistoryResponsePageEntry::Record { record },
            HistoryResponseAckEntry::Record {
                response_id,
                record_digest,
                ..
            },
        ) if response_id == &record.source_record.response_id
            && record_digest == &record.record_digest =>
        {
            Ok(())
        }
        (
            HistoryResponsePageEntry::Lost { lost_record },
            HistoryResponseAckEntry::Lost {
                response_id,
                lost_record_digest,
                ..
            },
        ) if response_id == &lost_record.response_id
            && lost_record_digest == &lost_record.lost_record_digest()? =>
        {
            Ok(())
        }
        _ => Err(Error::Protocol(
            "history response stream disposition does not bind the exact page entry".to_owned(),
        )),
    }
}

fn build_ack_for_pending_page(
    response_stream: &DurableHistoryResponseStream,
) -> Result<HistoryKeyResponseAckRequest> {
    let page = response_stream
        .pending_page
        .as_ref()
        .ok_or_else(|| Error::Protocol("history response stream has no pending page".to_owned()))?;
    if page.ack_entries.is_empty() {
        return Err(Error::Protocol(
            "empty history response stream page has nothing to acknowledge".to_owned(),
        ));
    }
    let mut ack_entries = Vec::with_capacity(page.ack_entries.len());
    for page_entry in &page.ack_entries {
        let disposition = response_stream
            .pending_dispositions
            .get(&page_entry.sequence())
            .ok_or_else(|| {
                Error::Protocol(
                    "history response stream page is not fully processed before ACK".to_owned(),
                )
            })?
            .clone();
        validate_disposition_for_page(page, &disposition)?;
        ack_entries.push(disposition);
    }
    let high_water_cursor = match page.ack_entries.last().expect("page is non-empty") {
        HistoryResponsePageEntry::Record { record } => record.cursor.clone(),
        HistoryResponsePageEntry::Lost { lost_record } => lost_record.cursor.clone(),
    };
    let request = HistoryKeyResponseAckRequest {
        ack_token: page.ack_token.clone(),
        high_water_cursor,
        ack_entries,
    };
    request.validate()?;
    Ok(request)
}

fn advance_ack_high_water(
    response_stream: &mut DurableHistoryResponseStream,
    cursor: &str,
    sequence: u64,
) -> Result<bool> {
    if let Some(current) = response_stream.acknowledged_through_sequence {
        if current > sequence {
            return Ok(false);
        }
        if current == sequence {
            if response_stream.acknowledged_through_cursor.as_deref() != Some(cursor) {
                return Err(Error::Protocol(
                    "history ACK sequence is bound to two cursors".to_owned(),
                ));
            }
            return Ok(false);
        }
    }
    response_stream.acknowledged_through_cursor = Some(cursor.to_owned());
    response_stream.acknowledged_through_sequence = Some(sequence);
    Ok(true)
}

pub fn cryptographically_rejected_disposition(
    entry: &HistoryResponsePageEntry,
) -> Result<HistoryResponseAckEntry> {
    match entry {
        HistoryResponsePageEntry::Record { record } => Ok(HistoryResponseAckEntry::Record {
            sequence: record.sequence,
            response_id: record.source_record.response_id.clone(),
            record_digest: record.record_digest.clone(),
            status: HistoryResponseRecordStatus::CryptographicallyRejected,
        }),
        HistoryResponsePageEntry::Lost { lost_record } => Ok(HistoryResponseAckEntry::Lost {
            sequence: lost_record.sequence,
            response_id: lost_record.response_id.clone(),
            lost_record_digest: lost_record.lost_record_digest()?,
            status: arkret_models_collaboration::history_key::HistoryResponseLostStatus::Value,
        }),
    }
}

#[cfg(test)]
mod tests {
    use arkret_wire::SealId;

    use super::*;

    fn basis(fill: char) -> SealBasis {
        SealBasis {
            leaves: vec![
                SealId::new(format!("ak:seal:sha256:{}", fill.to_string().repeat(64))).unwrap(),
            ],
        }
    }

    fn response_stream() -> DurableHistoryResponseStream {
        DurableHistoryResponseStream {
            acknowledged_through_cursor: None,
            acknowledged_through_sequence: None,
            pending_page: None,
            pending_dispositions: BTreeMap::new(),
            pending_ack: None,
            verified_manifests: BTreeMap::new(),
        }
    }

    #[test]
    fn response_capability_secret_ref_uses_indexeddb_only_prefix() {
        let request_id = HistoryRequestId::new(
            "ak:history_request:01964137-0000-7000-8000-000000000001".to_owned(),
        )
        .unwrap();
        assert_eq!(
            history_response_capability_secret_ref(&request_id),
            "arkret/history-response-capability/v1/ak:history_request:01964137-0000-7000-8000-000000000001"
        );
    }

    #[test]
    fn release_target_may_be_newer_than_the_signed_current_basis() {
        let trusted_current = basis('a');
        let release_target = basis('b');
        assert_ne!(trusted_current, release_target);
        validate_release_target_basis(&trusted_current, &release_target).unwrap();
    }

    #[test]
    fn verified_target_closure_must_contain_every_trusted_current_leaf() {
        let trusted_current = SealBasis {
            leaves: vec![basis('a').leaves[0].clone(), basis('b').leaves[0].clone()],
        };
        let only_one = [trusted_current.leaves[0].clone()];
        assert!(!seal_ids_contain_basis(only_one.iter(), &trusted_current));
        assert!(seal_ids_contain_basis(
            trusted_current.leaves.iter(),
            &trusted_current,
        ));
    }

    #[test]
    fn verified_target_closure_must_also_contain_history_base() {
        let trusted_history_base = basis('a');
        let target_seals = [basis('b').leaves[0].clone()];
        assert!(!seal_ids_contain_basis(
            target_seals.iter(),
            &trusted_history_base,
        ));
    }

    #[test]
    fn ack_high_water_never_rolls_back() {
        let mut response_stream = response_stream();
        assert!(advance_ack_high_water(&mut response_stream, "cursor-10", 10).unwrap());
        assert!(!advance_ack_high_water(&mut response_stream, "cursor-9", 9).unwrap());
        assert_eq!(response_stream.acknowledged_through_sequence, Some(10));
        assert_eq!(
            response_stream.acknowledged_through_cursor.as_deref(),
            Some("cursor-10")
        );
        assert!(advance_ack_high_water(&mut response_stream, "other-cursor", 10).is_err());
    }

    #[tokio::test]
    async fn stale_store_revision_cannot_overwrite_a_committed_snapshot() {
        let store = MemoryHistoryRuntimeStore::new();
        let first = store.load_history_runtime().unwrap();
        let stale = store.load_history_runtime().unwrap();
        assert!(
            store
                .compare_and_swap_history_runtime(first.revision, &first.snapshot)
                .await
                .unwrap()
        );
        assert!(
            !store
                .compare_and_swap_history_runtime(stale.revision, &stale.snapshot)
                .await
                .unwrap()
        );
        assert_eq!(store.load_history_runtime().unwrap().revision, 1);
    }
}
