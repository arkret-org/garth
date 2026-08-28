//! Crash-safe source outbox for private-history response attempts.
//!
//! A complete manifest and every named chunk are persisted as
//! content-addressed canonical blobs before the attempt marker becomes
//! visible. Network replay can therefore only start from a complete bundle,
//! and every retry reconstructs the exact signed objects from those bytes.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::sync::{Arc, Mutex};

use arkret_models_collaboration::history_key::{
    HistoryKeyResponseContent, HistoryKeyResponseSendReceipt, HistoryKeyResponseSendRequest,
    HistoryKeySourceRelay, HistoryRequestId, HistoryResponseId,
};
use arkret_wire::Hash;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::history_runtime::HistoryRuntimeTransport;
use crate::{Error, MaybeSend, MaybeSendSync, Result};

const HISTORY_OUTBOX_BLOB_PREFIX: &str = "arkret/history-source-outbox/v1/";
const HISTORY_OUTBOX_CAS_RETRY_LIMIT: usize = 16;
pub const MAX_HISTORY_SOURCE_RECORD_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_HISTORY_ATTEMPT_STAGED_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_UNFINISHED_HISTORY_ATTEMPTS_PER_REQUEST_SOURCE: usize = 4;
pub const MAX_UNFINISHED_HISTORY_ATTEMPTS_PER_REQUEST: usize = 8;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "route", rename_all = "snake_case", deny_unknown_fields)]
pub enum HistorySourceOutboundRecord {
    Direct {
        request: Box<HistoryKeyResponseSendRequest>,
    },
    Relay {
        relay: Box<HistoryKeySourceRelay>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistorySourceRoute {
    Direct,
    Relay,
}

impl HistorySourceOutboundRecord {
    pub fn route(&self) -> HistorySourceRoute {
        match self {
            Self::Direct { .. } => HistorySourceRoute::Direct,
            Self::Relay { .. } => HistorySourceRoute::Relay,
        }
    }

    pub fn response(&self) -> &HistoryKeyResponseSendRequest {
        match self {
            Self::Direct { request } => request,
            Self::Relay { relay } => &relay.response,
        }
    }

    fn validate(&self) -> Result<()> {
        match self {
            Self::Direct { request } => Ok(request.validate()?),
            Self::Relay { relay } => Ok(relay.validate()?),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistorySourceAttemptBundle {
    pub request_id: HistoryRequestId,
    pub manifest_admission_digest: Hash,
    pub manifest: HistorySourceOutboundRecord,
    pub chunks: Vec<HistorySourceOutboundRecord>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistorySourceAttemptIdentity {
    pub request_id: HistoryRequestId,
    pub source_sender_domain: String,
    pub manifest_response_id: HistoryResponseId,
    pub manifest_digest: Hash,
}

impl HistorySourceAttemptIdentity {
    pub fn storage_key(&self) -> Result<String> {
        Ok(arkret_canonical::canonical::canonical_sha256(self)?)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistorySourceAttemptStatus {
    Unfinished,
    Completed,
    Expired,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableStagedHistoryRecord {
    pub response_id: HistoryResponseId,
    pub chunk_index: Option<u64>,
    pub route: HistorySourceRoute,
    pub blob_digest: Hash,
    pub canonical_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableHistorySourceAttempt {
    pub identity: HistorySourceAttemptIdentity,
    pub manifest_admission_digest: Hash,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub staged_bytes: u64,
    pub records: Vec<DurableStagedHistoryRecord>,
    pub receipts: BTreeMap<String, HistoryKeyResponseSendReceipt>,
    pub status: HistorySourceAttemptStatus,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistorySourceOutboxSnapshot {
    pub attempts: BTreeMap<String, DurableHistorySourceAttempt>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VersionedHistorySourceOutboxSnapshot {
    pub revision: u64,
    pub snapshot: HistorySourceOutboxSnapshot,
}

pub trait HistorySourceOutboxStore: Clone + MaybeSendSync + 'static {
    fn load_history_source_outbox(&self) -> Result<VersionedHistorySourceOutboxSnapshot>;

    fn compare_and_swap_history_source_outbox<'a>(
        &'a self,
        expected_revision: u64,
        snapshot: &'a HistorySourceOutboxSnapshot,
    ) -> impl Future<Output = Result<bool>> + MaybeSend + 'a;
}

#[derive(Clone, Default)]
pub struct MemoryHistorySourceOutboxStore {
    snapshot: Arc<Mutex<VersionedHistorySourceOutboxSnapshot>>,
}

impl MemoryHistorySourceOutboxStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl HistorySourceOutboxStore for MemoryHistorySourceOutboxStore {
    fn load_history_source_outbox(&self) -> Result<VersionedHistorySourceOutboxSnapshot> {
        self.snapshot
            .lock()
            .map_err(|_| Error::Protocol("history source outbox lock poisoned".to_owned()))
            .map(|snapshot| snapshot.clone())
    }

    fn compare_and_swap_history_source_outbox<'a>(
        &'a self,
        expected_revision: u64,
        snapshot: &'a HistorySourceOutboxSnapshot,
    ) -> impl Future<Output = Result<bool>> + MaybeSend + 'a {
        async move {
            let mut current = self
                .snapshot
                .lock()
                .map_err(|_| Error::Protocol("history source outbox lock poisoned".to_owned()))?;
            if current.revision != expected_revision {
                return Ok(false);
            }
            current.revision = current.revision.checked_add(1).ok_or_else(|| {
                Error::Protocol("history source outbox revision overflow".to_owned())
            })?;
            current.snapshot = snapshot.clone();
            Ok(true)
        }
    }
}

pub trait HistorySourceBlobStore: MaybeSendSync {
    fn put_history_blob<'a>(
        &'a self,
        key: &'a str,
        bytes: &'a [u8],
    ) -> impl Future<Output = Result<()>> + MaybeSend + 'a;

    fn get_history_blob(&self, key: &str) -> Result<Option<Vec<u8>>>;
    fn delete_history_blob(&self, key: &str) -> Result<()>;
    fn list_history_blob_keys(&self) -> Result<Vec<String>>;
}

#[derive(Clone, Default)]
pub struct MemoryHistorySourceBlobStore {
    blobs: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
}

impl MemoryHistorySourceBlobStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl HistorySourceBlobStore for MemoryHistorySourceBlobStore {
    fn put_history_blob<'a>(
        &'a self,
        key: &'a str,
        bytes: &'a [u8],
    ) -> impl Future<Output = Result<()>> + MaybeSend + 'a {
        async move {
            let mut blobs = self.blobs.lock().map_err(|_| {
                Error::Protocol("history source blob store lock poisoned".to_owned())
            })?;
            match blobs.get(key) {
                Some(existing) if existing != bytes => {
                    Err(Error::IdempotencyConflict(key.to_owned()))
                }
                Some(_) => Ok(()),
                None => {
                    blobs.insert(key.to_owned(), bytes.to_vec());
                    Ok(())
                }
            }
        }
    }

    fn get_history_blob(&self, key: &str) -> Result<Option<Vec<u8>>> {
        Ok(self
            .blobs
            .lock()
            .map_err(|_| Error::Protocol("history source blob store lock poisoned".to_owned()))?
            .get(key)
            .cloned())
    }

    fn delete_history_blob(&self, key: &str) -> Result<()> {
        self.blobs
            .lock()
            .map_err(|_| Error::Protocol("history source blob store lock poisoned".to_owned()))?
            .remove(key);
        Ok(())
    }

    fn list_history_blob_keys(&self) -> Result<Vec<String>> {
        Ok(self
            .blobs
            .lock()
            .map_err(|_| Error::Protocol("history source blob store lock poisoned".to_owned()))?
            .keys()
            .cloned()
            .collect())
    }
}

pub struct HistorySourceOutbox<S> {
    store: S,
}

impl<S> HistorySourceOutbox<S>
where
    S: HistorySourceOutboxStore,
{
    pub fn new(store: S) -> Self {
        Self { store }
    }

    pub fn store(&self) -> &S {
        &self.store
    }

    async fn mutate<R>(
        &self,
        mut mutation: impl FnMut(&mut HistorySourceOutboxSnapshot) -> Result<R>,
    ) -> Result<R> {
        for _ in 0..HISTORY_OUTBOX_CAS_RETRY_LIMIT {
            let current = self.store.load_history_source_outbox()?;
            let mut next = current.snapshot;
            let result = mutation(&mut next)?;
            if self
                .store
                .compare_and_swap_history_source_outbox(current.revision, &next)
                .await?
            {
                return Ok(result);
            }
        }
        Err(Error::Protocol(
            "history source outbox remained concurrently modified".to_owned(),
        ))
    }

    /// Persist every canonical blob before atomically publishing the ready
    /// marker represented by the durable attempt row.
    pub async fn stage_attempt<B>(
        &self,
        blobs: &B,
        bundle: HistorySourceAttemptBundle,
    ) -> Result<HistorySourceAttemptIdentity>
    where
        B: HistorySourceBlobStore,
    {
        let prepared = prepare_attempt(bundle)?;
        for (record, bytes) in &prepared.blobs {
            blobs
                .put_history_blob(&history_blob_key(&record.blob_digest), bytes)
                .await?;
        }
        let attempt = prepared.attempt;
        let identity = attempt.identity.clone();
        let attempt_key = identity.storage_key()?;
        self.mutate(|snapshot| {
            if let Some(existing) = snapshot.attempts.get(&attempt_key) {
                return if same_staged_attempt(existing, &attempt) {
                    Ok(identity.clone())
                } else {
                    Err(Error::IdempotencyConflict(attempt_key.clone()))
                };
            }
            enforce_unfinished_attempt_limits(snapshot, &identity)?;
            snapshot
                .attempts
                .insert(attempt_key.clone(), attempt.clone());
            Ok(identity.clone())
        })
        .await
    }

    pub fn attempt(
        &self,
        identity: &HistorySourceAttemptIdentity,
    ) -> Result<Option<DurableHistorySourceAttempt>> {
        Ok(self
            .store
            .load_history_source_outbox()?
            .snapshot
            .attempts
            .get(&identity.storage_key()?)
            .cloned())
    }

    /// Return every durable attempt for one request/source partition. Hosts
    /// use this to keep source discovery single-flight across poll ticks and
    /// restarts without deriving a second set of signed response ids.
    pub fn attempts_for_request_source(
        &self,
        request_id: &HistoryRequestId,
        source_sender_domain: &str,
    ) -> Result<Vec<DurableHistorySourceAttempt>> {
        Ok(self
            .store
            .load_history_source_outbox()?
            .snapshot
            .attempts
            .values()
            .filter(|attempt| {
                &attempt.identity.request_id == request_id
                    && attempt.identity.source_sender_domain == source_sender_domain
            })
            .cloned()
            .collect())
    }

    /// Snapshot every durable ready-marker identity in canonical storage-key
    /// order. Hosts use this after startup and on retry ticks; the records
    /// themselves are always reconstructed from their immutable blobs.
    pub fn ready_attempt_identities(
        &self,
        route: HistorySourceRoute,
    ) -> Result<Vec<HistorySourceAttemptIdentity>> {
        Ok(self
            .store
            .load_history_source_outbox()?
            .snapshot
            .attempts
            .values()
            .filter(|attempt| {
                attempt
                    .records
                    .first()
                    .is_some_and(|record| record.route == route)
            })
            .map(|attempt| attempt.identity.clone())
            .collect())
    }

    /// Replay the complete ready attempt. Each accepted receipt is made
    /// durable before the next record is sent, so restart resumes at the first
    /// missing receipt and never reconstructs or resigns bytes.
    pub async fn replay_attempt<T, B>(
        &self,
        transport: &T,
        blobs: &B,
        identity: &HistorySourceAttemptIdentity,
        now: DateTime<Utc>,
    ) -> Result<DurableHistorySourceAttempt>
    where
        T: HistoryRuntimeTransport,
        B: HistorySourceBlobStore,
    {
        let attempt_key = identity.storage_key()?;
        let mut attempt = self
            .attempt(identity)?
            .ok_or_else(|| Error::Protocol("history source attempt is not ready".to_owned()))?;
        if attempt.status != HistorySourceAttemptStatus::Unfinished {
            return Ok(attempt);
        }
        if now >= attempt.expires_at {
            return self
                .mutate(|snapshot| {
                    let attempt = snapshot.attempts.get_mut(&attempt_key).ok_or_else(|| {
                        Error::Protocol("history source attempt disappeared".to_owned())
                    })?;
                    attempt.status = HistorySourceAttemptStatus::Expired;
                    Ok(attempt.clone())
                })
                .await;
        }

        for staged in attempt.records.clone() {
            if attempt.receipts.contains_key(staged.response_id.as_str()) {
                continue;
            }
            let bytes = load_exact_record(blobs, &staged)?;
            let record: HistorySourceOutboundRecord = serde_json::from_slice(&bytes)?;
            record.validate()?;
            if record.response().response_id != staged.response_id
                || arkret_canonical::canonical::canonical_json_bytes(&record)? != bytes
            {
                return Err(Error::Protocol(
                    "staged history source record is not its canonical signed object".to_owned(),
                ));
            }
            let receipt = match &record {
                HistorySourceOutboundRecord::Direct { request } => {
                    transport.send_response(request).await?
                }
                HistorySourceOutboundRecord::Relay { relay } => {
                    transport.relay_response(relay).await?
                }
            };
            receipt.validate()?;
            if receipt.response_id != staged.response_id
                || receipt.manifest_admission_digest != attempt.manifest_admission_digest
            {
                return Err(Error::Protocol(
                    "history source receipt changed the attempt binding".to_owned(),
                ));
            }
            attempt = self
                .mutate(|snapshot| {
                    let current = snapshot.attempts.get_mut(&attempt_key).ok_or_else(|| {
                        Error::Protocol("history source attempt disappeared".to_owned())
                    })?;
                    match current.receipts.get(staged.response_id.as_str()) {
                        Some(existing) if existing != &receipt => {
                            Err(Error::IdempotencyConflict(staged.response_id.to_string()))
                        }
                        Some(_) => Ok(current.clone()),
                        None => {
                            current
                                .receipts
                                .insert(staged.response_id.to_string(), receipt.clone());
                            Ok(current.clone())
                        }
                    }
                })
                .await?;
        }

        self.mutate(|snapshot| {
            let current = snapshot
                .attempts
                .get_mut(&attempt_key)
                .ok_or_else(|| Error::Protocol("history source attempt disappeared".to_owned()))?;
            if current.receipts.len() != current.records.len() {
                return Err(Error::Protocol(
                    "history source attempt lacks a durable receipt for a named record".to_owned(),
                ));
            }
            current.status = HistorySourceAttemptStatus::Completed;
            Ok(current.clone())
        })
        .await
    }
}

fn same_staged_attempt(
    existing: &DurableHistorySourceAttempt,
    staged: &DurableHistorySourceAttempt,
) -> bool {
    existing.identity == staged.identity
        && existing.manifest_admission_digest == staged.manifest_admission_digest
        && existing.expires_at == staged.expires_at
        && existing.staged_bytes == staged.staged_bytes
        && existing.records == staged.records
}

struct PreparedAttempt {
    attempt: DurableHistorySourceAttempt,
    blobs: Vec<(DurableStagedHistoryRecord, Vec<u8>)>,
}

fn prepare_attempt(bundle: HistorySourceAttemptBundle) -> Result<PreparedAttempt> {
    bundle.manifest.validate()?;
    let attempt_route = bundle.manifest.route();
    let manifest_request = bundle.manifest.response();
    let HistoryKeyResponseContent::Manifest(manifest) = &manifest_request.content else {
        return Err(Error::Protocol(
            "history source attempt starts without a manifest".to_owned(),
        ));
    };
    manifest.validate()?;
    let manifest_digest = manifest_request.manifest_digest()?;
    if bundle.chunks.len() != manifest.chunks.len() {
        return Err(Error::Protocol(
            "history source attempt is not a complete manifest bundle".to_owned(),
        ));
    }
    let manifest_descriptors = manifest.chunks.clone();
    let manifest_binding = manifest_request.clone();
    let expires_at = manifest_request.expires_at;
    let identity = HistorySourceAttemptIdentity {
        request_id: bundle.request_id,
        source_sender_domain: manifest_request.source_sender_domain.clone(),
        manifest_response_id: manifest_request.response_id.clone(),
        manifest_digest: manifest_digest.clone(),
    };
    let mut outbound = Vec::with_capacity(1 + bundle.chunks.len());
    outbound.push((bundle.manifest, None));
    for (descriptor, record) in manifest_descriptors.iter().zip(bundle.chunks) {
        record.validate()?;
        if record.route() != attempt_route {
            return Err(Error::Protocol(
                "history source attempt mixes self-send and peer-relay routes".to_owned(),
            ));
        }
        let response = record.response();
        let HistoryKeyResponseContent::Chunk(chunk) = &response.content else {
            return Err(Error::Protocol(
                "history source attempt contains a second manifest".to_owned(),
            ));
        };
        if response.response_id != descriptor.chunk_response_id
            || chunk.chunk_index != descriptor.chunk_index
            || chunk.manifest_digest != manifest_digest
            || chunk.manifest_admission_digest != bundle.manifest_admission_digest
            || !same_attempt_binding(&manifest_binding, response)
        {
            return Err(Error::Protocol(
                "history source chunk differs from its manifest attempt binding".to_owned(),
            ));
        }
        let chunk_index = chunk.chunk_index;
        outbound.push((record, Some(chunk_index)));
    }

    let mut staged_bytes = 0_usize;
    let mut response_ids = BTreeSet::new();
    let mut blobs = Vec::with_capacity(outbound.len());
    for (record, chunk_index) in outbound {
        let response_id = record.response().response_id.clone();
        if !response_ids.insert(response_id.clone()) {
            return Err(Error::Protocol(
                "history source attempt repeats a response_id".to_owned(),
            ));
        }
        let bytes = arkret_canonical::canonical::canonical_json_bytes(&record)?;
        if bytes.len() > MAX_HISTORY_SOURCE_RECORD_BYTES {
            return Err(Error::Protocol(
                "history source record exceeds 2 MiB".to_owned(),
            ));
        }
        staged_bytes = staged_bytes.checked_add(bytes.len()).ok_or_else(|| {
            Error::Protocol("history source staged byte count overflow".to_owned())
        })?;
        if staged_bytes > MAX_HISTORY_ATTEMPT_STAGED_BYTES {
            return Err(Error::Protocol(
                "history source attempt exceeds 64 MiB".to_owned(),
            ));
        }
        let staged = DurableStagedHistoryRecord {
            response_id,
            chunk_index,
            route: record.route(),
            blob_digest: Hash::new(arkret_wire::canonical::sha256_digest(&bytes))?,
            canonical_bytes: u64::try_from(bytes.len()).map_err(|_| {
                Error::Protocol("history source record length overflows".to_owned())
            })?,
        };
        blobs.push((staged, bytes));
    }
    let records = blobs.iter().map(|(record, _)| record.clone()).collect();
    Ok(PreparedAttempt {
        attempt: DurableHistorySourceAttempt {
            identity,
            manifest_admission_digest: bundle.manifest_admission_digest,
            expires_at,
            staged_bytes: staged_bytes as u64,
            records,
            receipts: BTreeMap::new(),
            status: HistorySourceAttemptStatus::Unfinished,
        },
        blobs,
    })
}

fn same_attempt_binding(
    manifest: &HistoryKeyResponseSendRequest,
    record: &HistoryKeyResponseSendRequest,
) -> bool {
    manifest.effective_scope == record.effective_scope
        && manifest.source_actor_id == record.source_actor_id
        && manifest.source_sender_domain == record.source_sender_domain
        && manifest.request_digest == record.request_digest
        && manifest.request_receipt_digest == record.request_receipt_digest
        && manifest.expires_at == record.expires_at
}

fn enforce_unfinished_attempt_limits(
    snapshot: &HistorySourceOutboxSnapshot,
    identity: &HistorySourceAttemptIdentity,
) -> Result<()> {
    let unfinished = snapshot
        .attempts
        .values()
        .filter(|attempt| attempt.status == HistorySourceAttemptStatus::Unfinished)
        .filter(|attempt| attempt.identity.request_id == identity.request_id);
    let mut request_count = 0;
    let mut request_source_count = 0;
    for attempt in unfinished {
        request_count += 1;
        if attempt.identity.source_sender_domain == identity.source_sender_domain {
            request_source_count += 1;
        }
    }
    if request_source_count >= MAX_UNFINISHED_HISTORY_ATTEMPTS_PER_REQUEST_SOURCE
        || request_count >= MAX_UNFINISHED_HISTORY_ATTEMPTS_PER_REQUEST
    {
        return Err(Error::Protocol(
            "history source unfinished attempt quota exceeded".to_owned(),
        ));
    }
    Ok(())
}

fn history_blob_key(digest: &Hash) -> String {
    format!("{HISTORY_OUTBOX_BLOB_PREFIX}{digest}")
}

fn load_exact_record<B: HistorySourceBlobStore>(
    blobs: &B,
    staged: &DurableStagedHistoryRecord,
) -> Result<Vec<u8>> {
    let bytes = blobs
        .get_history_blob(&history_blob_key(&staged.blob_digest))?
        .ok_or_else(|| Error::Protocol("ready history source blob is missing".to_owned()))?;
    if bytes.len() as u64 != staged.canonical_bytes
        || Hash::new(arkret_wire::canonical::sha256_digest(&bytes))? != staged.blob_digest
    {
        return Err(Error::Protocol(
            "ready history source blob digest mismatch".to_owned(),
        ));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use arkret_models_collaboration::history_key::{
        EpochRange, HistoryKeyRequest, HistoryKeyRequestCreateOutcome,
        HistoryKeyRequestListOutcome, HistoryKeyRequestListQuery, HistoryKeyResponseAckOutcome,
        HistoryKeyResponseAckRequest, HistoryKeyResponseListOutcome, HistoryKeyResponseListQuery,
        HistoryKeyResponseSendReceipt, HistoryResponseChunkDescriptor, HistoryResponseManifest,
        HistoryResponseManifestKind, SealedHistoryChunk, SealedHistoryChunkKind,
    };
    use arkret_wire::{
        DidCoreId, DidUrl, HistoryEffectiveScope, PayloadProof, RealmId, SignerEvidenceRef,
    };

    use super::*;

    fn digest(fill: char) -> Hash {
        Hash::new(format!("sha256:{}", fill.to_string().repeat(64))).unwrap()
    }

    fn response_id(suffix: u8) -> HistoryResponseId {
        HistoryResponseId::new(format!(
            "ak:history_response:019c0000-0000-7000-8000-{suffix:012}"
        ))
        .unwrap()
    }

    fn signed_response(
        response_id: HistoryResponseId,
        content: HistoryKeyResponseContent,
        expires_at: DateTime<Utc>,
    ) -> HistoryKeyResponseSendRequest {
        let evidence_digest = digest('a');
        let evidence_ref =
            SignerEvidenceRef::new(format!("ak:signer_evidence:{evidence_digest}")).unwrap();
        HistoryKeyResponseSendRequest::build_signed_proof(
            DidUrl::new("did:key:z6MkHistorySource#response-key").unwrap(),
            expires_at - chrono::Duration::minutes(1),
            |source_proof| HistoryKeyResponseSendRequest {
                response_id: response_id.clone(),
                effective_scope: HistoryEffectiveScope::Realm {
                    realm_id: RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19")
                        .unwrap(),
                },
                source_actor_id: DidCoreId::new("ak:did_core:key:z6MkHistorySource").unwrap(),
                source_sender_domain: "history.example".to_owned(),
                source_signer_evidence_ref: evidence_ref.clone(),
                source_signer_evidence_digest: evidence_digest.clone(),
                request_digest: digest('b'),
                request_receipt_digest: digest('c'),
                expires_at,
                content: content.clone(),
                source_proof,
            },
            |_| Ok("test-source-signature".to_owned()),
        )
        .unwrap()
    }

    fn attempt_bundle() -> HistorySourceAttemptBundle {
        let expires_at = DateTime::parse_from_rfc3339("2026-08-28T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let chunk_response_id = response_id(2);
        let manifest = signed_response(
            response_id(1),
            HistoryKeyResponseContent::Manifest(HistoryResponseManifest {
                kind: HistoryResponseManifestKind::Value,
                chunks: vec![HistoryResponseChunkDescriptor {
                    chunk_response_id: chunk_response_id.clone(),
                    chunk_index: 0,
                    covered_epoch_range: EpochRange {
                        from_epoch: 0,
                        to_epoch: 1,
                    },
                }],
            }),
            expires_at,
        );
        let manifest_digest = manifest.manifest_digest().unwrap();
        let manifest_admission_digest = digest('d');
        let chunk = signed_response(
            chunk_response_id,
            HistoryKeyResponseContent::Chunk(SealedHistoryChunk {
                kind: SealedHistoryChunkKind::Value,
                manifest_digest,
                manifest_admission_digest: manifest_admission_digest.clone(),
                chunk_index: 0,
                enc: "AQ".to_owned(),
                ciphertext: "Ag".to_owned(),
            }),
            expires_at,
        );
        HistorySourceAttemptBundle {
            request_id: HistoryRequestId::new(
                "ak:history_request:01964137-0000-7000-8000-000000000001",
            )
            .unwrap(),
            manifest_admission_digest,
            manifest: HistorySourceOutboundRecord::Direct {
                request: Box::new(manifest),
            },
            chunks: vec![HistorySourceOutboundRecord::Direct {
                request: Box::new(chunk),
            }],
        }
    }

    fn placeholder_proof(created_at: DateTime<Utc>) -> PayloadProof {
        PayloadProof {
            kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
            verification_method: DidUrl::new("did:key:z6MkHistoryService#notary-key").unwrap(),
            payload_digest: digest('0'),
            created_at,
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: String::new(),
        }
    }

    fn receipt(
        request: &HistoryKeyResponseSendRequest,
        manifest_admission_digest: &Hash,
        sequence: u64,
    ) -> HistoryKeyResponseSendReceipt {
        let accepted_at = request.expires_at - chrono::Duration::hours(1);
        let temporary = HistoryKeyResponseSendReceipt {
            response_id: request.response_id.clone(),
            source_record_digest: digest('e'),
            record_digest: digest('f'),
            sequence,
            accepted_at,
            manifest_admission_digest: manifest_admission_digest.clone(),
            release_attestation_digest: None,
            receipt_digest: digest('0'),
            service_proof: placeholder_proof(accepted_at),
        };
        let receipt_digest = temporary.send_receipt_digest().unwrap();
        HistoryKeyResponseSendReceipt::build_signed_proof(
            DidUrl::new("did:key:z6MkHistoryService#notary-key").unwrap(),
            accepted_at,
            |service_proof| HistoryKeyResponseSendReceipt {
                receipt_digest: receipt_digest.clone(),
                service_proof,
                ..temporary.clone()
            },
            |_| Ok("test-service-signature".to_owned()),
        )
        .unwrap()
    }

    #[derive(Clone)]
    struct RecordingTransport {
        admission_digest: Hash,
        sent: Arc<Mutex<Vec<HistoryResponseId>>>,
    }

    impl RecordingTransport {
        fn new(admission_digest: Hash) -> Self {
            Self {
                admission_digest,
                sent: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn sent(&self) -> Vec<HistoryResponseId> {
            self.sent.lock().unwrap().clone()
        }
    }

    impl HistoryRuntimeTransport for RecordingTransport {
        fn create_request<'a>(
            &'a self,
            _request: &'a HistoryKeyRequest,
        ) -> impl Future<Output = Result<HistoryKeyRequestCreateOutcome>> + MaybeSend + 'a {
            async { unreachable!("not used by source outbox") }
        }

        fn list_requests<'a>(
            &'a self,
            _query: &'a HistoryKeyRequestListQuery,
        ) -> impl Future<Output = Result<HistoryKeyRequestListOutcome>> + MaybeSend + 'a {
            async { unreachable!("not used by source outbox") }
        }

        fn send_response<'a>(
            &'a self,
            request: &'a HistoryKeyResponseSendRequest,
        ) -> impl Future<Output = Result<HistoryKeyResponseSendReceipt>> + MaybeSend + 'a {
            async move {
                let mut sent = self.sent.lock().unwrap();
                sent.push(request.response_id.clone());
                Ok(receipt(request, &self.admission_digest, sent.len() as u64))
            }
        }

        fn relay_response<'a>(
            &'a self,
            _relay: &'a HistoryKeySourceRelay,
        ) -> impl Future<Output = Result<HistoryKeyResponseSendReceipt>> + MaybeSend + 'a {
            async { unreachable!("test attempt uses direct routing") }
        }

        fn list_responses<'a>(
            &'a self,
            _capability_b64u: &'a str,
            _query: &'a HistoryKeyResponseListQuery,
        ) -> impl Future<Output = Result<HistoryKeyResponseListOutcome>> + MaybeSend + 'a {
            async { unreachable!("not used by source outbox") }
        }

        fn acknowledge_responses<'a>(
            &'a self,
            _capability_b64u: &'a str,
            _request: &'a HistoryKeyResponseAckRequest,
        ) -> impl Future<Output = Result<HistoryKeyResponseAckOutcome>> + MaybeSend + 'a {
            async { unreachable!("not used by source outbox") }
        }
    }

    #[derive(Clone, Default)]
    struct FailingBlobStore {
        inner: MemoryHistorySourceBlobStore,
        puts: Arc<AtomicUsize>,
        fail_at: Arc<AtomicUsize>,
    }

    impl FailingBlobStore {
        fn fail_at(&self, put_number: usize) {
            self.fail_at.store(put_number, Ordering::SeqCst);
        }
    }

    impl HistorySourceBlobStore for FailingBlobStore {
        fn put_history_blob<'a>(
            &'a self,
            key: &'a str,
            bytes: &'a [u8],
        ) -> impl Future<Output = Result<()>> + MaybeSend + 'a {
            async move {
                let put = self.puts.fetch_add(1, Ordering::SeqCst) + 1;
                if put == self.fail_at.load(Ordering::SeqCst) {
                    return Err(Error::Protocol("injected blob write failure".to_owned()));
                }
                self.inner.put_history_blob(key, bytes).await
            }
        }

        fn get_history_blob(&self, key: &str) -> Result<Option<Vec<u8>>> {
            self.inner.get_history_blob(key)
        }

        fn delete_history_blob(&self, key: &str) -> Result<()> {
            self.inner.delete_history_blob(key)
        }

        fn list_history_blob_keys(&self) -> Result<Vec<String>> {
            self.inner.list_history_blob_keys()
        }
    }

    #[tokio::test]
    async fn crash_before_ready_marker_never_exposes_partial_attempt() {
        let outbox = HistorySourceOutbox::new(MemoryHistorySourceOutboxStore::new());
        let blobs = FailingBlobStore::default();
        blobs.fail_at(2);
        assert!(
            outbox
                .stage_attempt(&blobs, attempt_bundle())
                .await
                .is_err()
        );
        assert!(
            outbox
                .store()
                .load_history_source_outbox()
                .unwrap()
                .snapshot
                .attempts
                .is_empty()
        );

        blobs.fail_at(usize::MAX);
        let identity = outbox
            .stage_attempt(&blobs, attempt_bundle())
            .await
            .unwrap();
        assert!(outbox.attempt(&identity).unwrap().is_some());
    }

    #[tokio::test]
    async fn exact_replay_resumes_after_missing_blob_and_completed_is_network_silent() {
        let outbox = HistorySourceOutbox::new(MemoryHistorySourceOutboxStore::new());
        let blobs = MemoryHistorySourceBlobStore::new();
        let bundle = attempt_bundle();
        let transport = RecordingTransport::new(bundle.manifest_admission_digest.clone());
        let identity = outbox.stage_attempt(&blobs, bundle.clone()).await.unwrap();
        let attempt = outbox.attempt(&identity).unwrap().unwrap();
        let chunk_blob_key = history_blob_key(&attempt.records[1].blob_digest);
        blobs.delete_history_blob(&chunk_blob_key).unwrap();

        let now = DateTime::parse_from_rfc3339("2026-08-27T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        assert!(
            outbox
                .replay_attempt(&transport, &blobs, &identity, now)
                .await
                .is_err()
        );
        assert_eq!(transport.sent(), vec![response_id(1)]);

        outbox.stage_attempt(&blobs, bundle).await.unwrap();
        let completed = outbox
            .replay_attempt(&transport, &blobs, &identity, now)
            .await
            .unwrap();
        assert_eq!(completed.status, HistorySourceAttemptStatus::Completed);
        assert_eq!(transport.sent(), vec![response_id(1), response_id(2)]);

        outbox
            .replay_attempt(&transport, &blobs, &identity, now)
            .await
            .unwrap();
        assert_eq!(transport.sent(), vec![response_id(1), response_id(2)]);
    }

    #[tokio::test]
    async fn same_identity_cannot_change_staged_chunk_bytes() {
        let outbox = HistorySourceOutbox::new(MemoryHistorySourceOutboxStore::new());
        let blobs = MemoryHistorySourceBlobStore::new();
        let bundle = attempt_bundle();
        outbox.stage_attempt(&blobs, bundle.clone()).await.unwrap();

        let mut changed = bundle;
        let HistorySourceOutboundRecord::Direct { request } = &mut changed.chunks[0] else {
            unreachable!()
        };
        let HistoryKeyResponseContent::Chunk(chunk) = &mut request.content else {
            unreachable!()
        };
        chunk.ciphertext = "Aw".to_owned();
        assert!(outbox.stage_attempt(&blobs, changed).await.is_err());
    }

    #[tokio::test]
    async fn ready_attempt_discovery_is_route_partitioned() {
        let outbox = HistorySourceOutbox::new(MemoryHistorySourceOutboxStore::new());
        let blobs = MemoryHistorySourceBlobStore::new();
        let identity = outbox
            .stage_attempt(&blobs, attempt_bundle())
            .await
            .unwrap();

        assert_eq!(
            outbox
                .ready_attempt_identities(HistorySourceRoute::Direct)
                .unwrap(),
            vec![identity]
        );
        assert!(
            outbox
                .ready_attempt_identities(HistorySourceRoute::Relay)
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn expired_attempt_never_reaches_transport() {
        let outbox = HistorySourceOutbox::new(MemoryHistorySourceOutboxStore::new());
        let blobs = MemoryHistorySourceBlobStore::new();
        let bundle = attempt_bundle();
        let transport = RecordingTransport::new(bundle.manifest_admission_digest.clone());
        let identity = outbox.stage_attempt(&blobs, bundle).await.unwrap();
        let after_expiry = DateTime::parse_from_rfc3339("2026-08-29T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let expired = outbox
            .replay_attempt(&transport, &blobs, &identity, after_expiry)
            .await
            .unwrap();
        assert_eq!(expired.status, HistorySourceAttemptStatus::Expired);
        assert!(transport.sent().is_empty());
    }
}
