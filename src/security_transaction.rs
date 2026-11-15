//! Durable coordination for current security transactions.
//!
//! The service resource is the authoritative progress record. Garth stores
//! only canonical public requests and an opaque reference to separately held
//! secret material. A completed PCR recovery is accepted only when its two
//! Events occupy consecutive coordinates in the same PCR Realm stream.

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::{Arc, Mutex};

use arkret_identity::VerifiedSubmission;
pub use arkret_models_crypto::{
    ClientStepAttestation, RecoveryReceipt, RecoveryTransactionCompletion,
    RecoveryTransactionCreateRequestBody, RecoveryUnit, SecurityRotationTransaction,
    SecurityTransaction, SecurityTransactionContinueRequestBody,
    SecurityTransactionCreateRequestBody, SecurityTransactionTerminalOutcome,
};
use arkret_wire::{CommitStreamRef, CommittedEventRef, RealmId, TransactionId};
use serde::{Deserialize, Serialize};

use crate::{Error, MaybeSend, MaybeSendSync, Result};

/// Host transport for the three current transaction operations.
pub trait SecurityTransactionTransport: MaybeSendSync {
    fn create<'a>(
        &'a self,
        request: &'a VerifiedSubmission<SecurityTransactionCreateRequestBody>,
    ) -> impl Future<Output = Result<SecurityTransaction>> + MaybeSend + 'a;

    fn get<'a>(
        &'a self,
        transaction_id: &'a TransactionId,
    ) -> impl Future<Output = Result<SecurityTransaction>> + MaybeSend + 'a;

    fn continue_transaction<'a>(
        &'a self,
        transaction_id: &'a TransactionId,
        request: &'a SecurityTransactionContinueRequestBody,
    ) -> impl Future<Output = Result<SecurityTransaction>> + MaybeSend + 'a;
}

/// One continuation retained byte-for-byte until the service observes it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingSecurityTransactionContinue {
    pub expected_accepted_step_count: u64,
    pub canonical_request: Vec<u8>,
}

/// Exact signed local Recovery receipt retained before single submission.
///
/// Keeping the canonical bytes makes recovery-grant issuance restart-safe
/// without requiring the client to fetch C or retaining any secret material.
/// It is local evidence; only the original Station can attest acceptance.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DurableCompletedRecoveryReceipt {
    canonical_receipt: Vec<u8>,
}

impl DurableCompletedRecoveryReceipt {
    fn from_receipt(receipt: &RecoveryReceipt) -> Result<Self> {
        receipt.validate()?;
        Ok(Self {
            canonical_receipt: arkret_canonical::canonical_json_bytes(receipt)?,
        })
    }

    pub fn receipt(&self) -> Result<RecoveryReceipt> {
        let receipt: RecoveryReceipt = serde_json::from_slice(&self.canonical_receipt)?;
        receipt.validate()?;
        if arkret_canonical::canonical_json_bytes(&receipt)? != self.canonical_receipt {
            return Err(Error::Protocol(
                "stored completed recovery receipt is not canonical".to_owned(),
            ));
        }
        Ok(receipt)
    }
}

/// Public durable state for one transaction.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DurableSecurityTransaction {
    pub transaction_id: TransactionId,
    pub canonical_create_request: Vec<u8>,
    /// Opaque host-owned secret-store reference; never plaintext secret bytes.
    pub staged_secret_ref: Option<String>,
    pub pending_continue: Option<PendingSecurityTransactionContinue>,
    /// Exact first AA completion request, containing no bearer secret.
    pub pending_recovery_completion: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_recovery_receipt: Option<DurableCompletedRecoveryReceipt>,
    pub last_observed_resource: Option<SecurityTransaction>,
}

impl DurableSecurityTransaction {
    /// Return the exact signed receipt retained for a completed recovery.
    pub fn completed_recovery_receipt(&self) -> Result<Option<RecoveryReceipt>> {
        let Some(stored) = &self.completed_recovery_receipt else {
            return Ok(None);
        };
        let receipt = stored.receipt()?;
        if receipt.transaction_id != self.transaction_id {
            return Err(Error::Protocol(
                "stored completed recovery receipt changed transaction_id".to_owned(),
            ));
        }
        Ok(Some(receipt))
    }
}

pub trait SecurityTransactionStore: Clone + MaybeSendSync + 'static {
    fn load(&self, transaction_id: &TransactionId) -> Result<Option<DurableSecurityTransaction>>;
    fn save<'a>(
        &'a self,
        state: &'a DurableSecurityTransaction,
    ) -> impl Future<Output = Result<()>> + MaybeSend + 'a;
    fn load_committed<'a>(
        &'a self,
        transaction_id: &'a TransactionId,
    ) -> impl Future<Output = Result<Option<DurableSecurityTransaction>>> + MaybeSend + 'a;
    /// Shared-backend atomic compare/replace, resolving after durable commit.
    fn compare_exchange<'a>(
        &'a self,
        expected: Option<&'a DurableSecurityTransaction>,
        next: &'a DurableSecurityTransaction,
    ) -> impl Future<Output = Result<bool>> + MaybeSend + 'a;
    /// Idempotently discard one host-owned secret after a terminal resource
    /// has been saved. A crash may require repeating this cleanup.
    fn clear_staged_secret(&self, reference: &str) -> Result<()>;
    fn remove(&self, transaction_id: &TransactionId) -> Result<()>;
}

#[derive(Clone, Debug, Default)]
pub struct MemorySecurityTransactionStore {
    states: Arc<Mutex<BTreeMap<TransactionId, DurableSecurityTransaction>>>,
    cleared_secret_refs: Arc<Mutex<Vec<String>>>,
}

impl MemorySecurityTransactionStore {
    pub fn cleared_secret_refs(&self) -> Vec<String> {
        self.cleared_secret_refs.lock().unwrap().clone()
    }
}

impl SecurityTransactionStore for MemorySecurityTransactionStore {
    fn load(&self, transaction_id: &TransactionId) -> Result<Option<DurableSecurityTransaction>> {
        Ok(self.states.lock().unwrap().get(transaction_id).cloned())
    }

    async fn save(&self, state: &DurableSecurityTransaction) -> Result<()> {
        self.states
            .lock()
            .unwrap()
            .insert(state.transaction_id.clone(), state.clone());
        Ok(())
    }

    async fn load_committed(
        &self,
        id: &TransactionId,
    ) -> Result<Option<DurableSecurityTransaction>> {
        self.load(id)
    }
    async fn compare_exchange(
        &self,
        expected: Option<&DurableSecurityTransaction>,
        next: &DurableSecurityTransaction,
    ) -> Result<bool> {
        let mut states = self.states.lock().unwrap();
        if states.get(&next.transaction_id) != expected {
            return Ok(false);
        }
        states.insert(next.transaction_id.clone(), next.clone());
        Ok(true)
    }

    fn clear_staged_secret(&self, reference: &str) -> Result<()> {
        let mut cleared = self.cleared_secret_refs.lock().unwrap();
        if !cleared.iter().any(|existing| existing == reference) {
            cleared.push(reference.to_owned());
        }
        Ok(())
    }

    fn remove(&self, transaction_id: &TransactionId) -> Result<()> {
        self.states.lock().unwrap().remove(transaction_id);
        Ok(())
    }
}

/// Enforce the atomic PCR recovery completion boundary exposed to clients.
pub fn validate_recovery_commit_boundary(
    realm_id: &RealmId,
    reanchor_ref: &CommittedEventRef,
    device_authorization_ref: &CommittedEventRef,
) -> Result<()> {
    let expected_stream = CommitStreamRef::Realm {
        realm_id: realm_id.clone(),
    };
    if reanchor_ref.stream_ref != expected_stream
        || device_authorization_ref.stream_ref != expected_stream
        || device_authorization_ref.stream_position
            != reanchor_ref.stream_position.checked_add(1).ok_or_else(|| {
                Error::Protocol("PCR recovery commit position overflow".to_owned())
            })?
        || reanchor_ref.commit_id == device_authorization_ref.commit_id
        || reanchor_ref.event_id == device_authorization_ref.event_id
    {
        return Err(Error::Protocol(
            "PCR recovery completion requires distinct consecutive commits in its Realm stream"
                .to_owned(),
        ));
    }
    Ok(())
}

fn validate_recovery_receipt_digest(
    receipt: &RecoveryReceipt,
    accepted_digest: &arkret_wire::Hash,
) -> Result<()> {
    let bytes = arkret_canonical::canonical_json_bytes(receipt)?;
    let digest = arkret_wire::Hash::new(arkret_canonical::sha256_digest(&bytes))?;
    if &digest != accepted_digest {
        return Err(Error::Protocol(
            "completed recovery accepted a different terminal receipt".to_owned(),
        ));
    }
    Ok(())
}

fn resource_is_terminal(resource: &SecurityTransaction) -> bool {
    match resource {
        SecurityTransaction::Recovery(_) => true,
        SecurityTransaction::SecurityRotation(rotation) => rotation.terminal_outcome.is_some(),
    }
}

fn validate_observed_resource(
    local: &DurableSecurityTransaction,
    resource: &SecurityTransaction,
) -> Result<()> {
    resource.validate_structural()?;
    if resource.transaction_id() != &local.transaction_id {
        return Err(Error::Protocol(
            "security transaction changed its identity".into(),
        ));
    }
    let request: SecurityTransactionCreateRequestBody =
        serde_json::from_slice(&local.canonical_create_request)?;
    if arkret_canonical::canonical_json_bytes(&request)? != local.canonical_create_request {
        return Err(Error::Protocol(
            "stored create request is not canonical".into(),
        ));
    }
    match (&request, resource) {
        (
            SecurityTransactionCreateRequestBody::Recovery(request),
            SecurityTransaction::Recovery(completed),
        ) => {
            completed.validate_for_request(request)?;
            let realm = &request.recovery_receipt.recovery_unit.events[0]
                .event
                .realm_id;
            validate_recovery_commit_boundary(
                realm,
                &completed.completion_attestation.reanchor_event_ref,
                &completed
                    .completion_attestation
                    .device_authorization_event_ref,
            )?;
            validate_recovery_receipt_digest(
                &request.recovery_receipt,
                &completed.completion_attestation.terminal_receipt_digest,
            )?;
            if local.pending_continue.is_some() {
                return Err(Error::Protocol(
                    "Recovery cannot have a pending continuation".into(),
                ));
            }
        }
        (
            SecurityTransactionCreateRequestBody::SecurityRotation(request),
            SecurityTransaction::SecurityRotation(rotation),
        ) => {
            let expected = arkret_wire::Hash::new(arkret_canonical::sha256_digest(
                &local.canonical_create_request,
            ))?;
            if rotation.request_digest != expected
                || rotation.account_id != request.account_id
                || rotation.authorizing_device_id != request.authorizing_device_id
                || rotation.expires_at != request.expires_at
                || arkret_canonical::canonical_json_bytes(&rotation.prepared_plan)?
                    != arkret_canonical::canonical_json_bytes(&request.prepared_plan)?
            {
                return Err(Error::Protocol(
                    "Rotation changed its canonical create request or frozen plan".into(),
                ));
            }
        }
        _ => {
            return Err(Error::Protocol(
                "security transaction changed its closed branch".into(),
            ));
        }
    }
    Ok(())
}

fn retain_completed_recovery_receipt(
    local: &mut DurableSecurityTransaction,
    receipt: &RecoveryReceipt,
) -> Result<()> {
    if receipt.transaction_id != local.transaction_id {
        return Err(Error::Protocol(
            "signed R belongs to another durable transaction".into(),
        ));
    }
    let stored = DurableCompletedRecoveryReceipt::from_receipt(receipt)?;
    if local
        .completed_recovery_receipt
        .as_ref()
        .is_some_and(|existing| existing != &stored)
    {
        return Err(Error::Protocol(
            "completed recovery receipt idempotency conflict".to_owned(),
        ));
    }
    local.completed_recovery_receipt = Some(stored);
    Ok(())
}

async fn persist_observation<S: SecurityTransactionStore>(
    store: &S,
    local: &mut DurableSecurityTransaction,
    terminal: bool,
) -> Result<()> {
    // Merge only the observation into the committed record. Concurrent
    // completion/continuation intent fields are never restored from a stale
    // handle, and a cleaned secret reference is never resurrected.
    loop {
        let current = store.load_committed(&local.transaction_id).await?;
        let mut next = local.clone();
        if let Some(current) = &current {
            if current.canonical_create_request != local.canonical_create_request {
                return Err(Error::Protocol(
                    "observation changed the frozen create identity".into(),
                ));
            }
            next.pending_recovery_completion = current.pending_recovery_completion.clone();
            if current.staged_secret_ref.is_none() {
                next.staged_secret_ref = None;
            }
            if let Some(pending) = &current.pending_continue {
                let accepted = match next.last_observed_resource.as_ref() {
                    Some(SecurityTransaction::SecurityRotation(r)) => r.accepted_steps.len(),
                    _ => 0,
                };
                if usize::try_from(pending.expected_accepted_step_count)
                    .ok()
                    .is_none_or(|count| count >= accepted)
                {
                    next.pending_continue = Some(pending.clone());
                }
            }
            if let Some(previous) = current.last_observed_resource.as_ref() {
                if resource_is_terminal(previous)
                    && next.last_observed_resource.as_ref() != Some(previous)
                {
                    return Err(Error::Protocol("terminal observation is immutable".into()));
                }
                if let (
                    SecurityTransaction::SecurityRotation(previous),
                    Some(SecurityTransaction::SecurityRotation(observed)),
                ) = (previous, next.last_observed_resource.as_ref())
                    && observed.accepted_steps.len() < previous.accepted_steps.len()
                {
                    next.last_observed_resource =
                        Some(SecurityTransaction::SecurityRotation(previous.clone()));
                }
            }
        }
        if store.compare_exchange(current.as_ref(), &next).await? {
            *local = next;
            break;
        }
    }
    if terminal && let Some(reference) = local.staged_secret_ref.clone() {
        store.clear_staged_secret(&reference)?;
        loop {
            let current = store
                .load_committed(&local.transaction_id)
                .await?
                .ok_or_else(|| {
                    Error::Protocol("terminal record disappeared before cleanup".into())
                })?;
            let mut next = current.clone();
            next.staged_secret_ref = None;
            if store.compare_exchange(Some(&current), &next).await? {
                *local = next;
                break;
            }
        }
    }
    Ok(())
}

#[derive(Clone, Debug)]
pub struct SecurityTransactionEngine<T, S> {
    transport: T,
    store: S,
}

impl<T, S> SecurityTransactionEngine<T, S>
where
    T: SecurityTransactionTransport,
    S: SecurityTransactionStore,
{
    pub fn new(transport: T, store: S) -> Self {
        Self { transport, store }
    }

    pub fn local_state(
        &self,
        transaction_id: &TransactionId,
    ) -> Result<Option<DurableSecurityTransaction>> {
        self.store.load(transaction_id)
    }

    async fn observe(
        &self,
        local: &mut DurableSecurityTransaction,
        resource: SecurityTransaction,
    ) -> Result<SecurityTransaction> {
        validate_observed_resource(local, &resource)?;
        let terminal = resource_is_terminal(&resource);
        if let SecurityTransaction::Recovery(completed) = &resource {
            retain_completed_recovery_receipt(local, &completed.recovery_receipt)?;
        }
        local.last_observed_resource = Some(resource.clone());
        persist_observation(&self.store, local, terminal).await?;
        Ok(resource)
    }

    pub async fn freeze_create(
        &self,
        request: &VerifiedSubmission<SecurityTransactionCreateRequestBody>,
        staged_secret_ref: Option<String>,
    ) -> Result<DurableSecurityTransaction> {
        request.validate()?;
        if staged_secret_ref.as_deref().is_some_and(str::is_empty) {
            return Err(Error::Protocol(
                "staged security-transaction reference must not be empty".to_owned(),
            ));
        }
        let canonical_request = arkret_canonical::canonical_json_bytes(request)?;
        let transaction_id = request.transaction_id();
        let local = loop {
            match self.store.load_committed(transaction_id).await? {
                Some(existing) => {
                    if existing.canonical_create_request != canonical_request
                        || existing.staged_secret_ref != staged_secret_ref
                    {
                        return Err(Error::Protocol(
                            "security transaction idempotency conflict".to_owned(),
                        ));
                    }
                    break existing;
                }
                None => {
                    let mut state = DurableSecurityTransaction {
                        transaction_id: transaction_id.clone(),
                        canonical_create_request: canonical_request.clone(),
                        staged_secret_ref: staged_secret_ref.clone(),
                        pending_continue: None,
                        pending_recovery_completion: None,
                        completed_recovery_receipt: None,
                        last_observed_resource: None,
                    };
                    if let SecurityTransactionCreateRequestBody::Recovery(recovery) = &**request {
                        // Freeze signed R before the first network effect. It is
                        // sufficient input to AA completion after response loss;
                        // it never claims the Station has accepted the native unit.
                        retain_completed_recovery_receipt(&mut state, &recovery.recovery_receipt)?;
                    }
                    if self.store.compare_exchange(None, &state).await? {
                        break state;
                    }
                }
            }
        };
        Ok(local)
    }

    pub async fn create_or_resume(
        &self,
        request: &VerifiedSubmission<SecurityTransactionCreateRequestBody>,
        staged_secret_ref: Option<String>,
    ) -> Result<SecurityTransaction> {
        let mut local = self.freeze_create(request, staged_secret_ref).await?;
        let transaction_id = request.transaction_id();
        let resource = match local.last_observed_resource.as_ref() {
            Some(completed @ SecurityTransaction::Recovery(_)) => completed.clone(),
            Some(SecurityTransaction::SecurityRotation(_)) => {
                self.transport.get(transaction_id).await?
            }
            None => self.transport.create(request).await?,
        };
        self.observe(&mut local, resource).await
    }

    /// Freeze the fresh completion intent before its first AA effect. An
    /// accepted outcome is replayed with this same business body and fresh
    /// transport authentication, never a newly signed proof/window.
    pub async fn freeze_recovery_completion_request(
        &self,
        request: &arkret_models_identity::RecoveryCompletionGrantRequestBody,
    ) -> Result<arkret_models_identity::RecoveryCompletionGrantRequestBody> {
        request.validate_structural()?;
        loop {
            let current = self
                .store
                .load_committed(&request.terminal_receipt.transaction_id)
                .await?
                .ok_or_else(|| Error::Protocol("Recovery has no frozen create request".into()))?;
            let create: SecurityTransactionCreateRequestBody =
                serde_json::from_slice(&current.canonical_create_request)?;
            let SecurityTransactionCreateRequestBody::Recovery(create) = create else {
                return Err(Error::Protocol(
                    "completion belongs to another branch".into(),
                ));
            };
            if create.recovery_receipt != request.terminal_receipt {
                return Err(Error::Protocol("completion changed frozen R".into()));
            }
            if let Some(bytes) = &current.pending_recovery_completion {
                let original: arkret_models_identity::RecoveryCompletionGrantRequestBody =
                    serde_json::from_slice(bytes)?;
                original.validate_structural()?;
                if arkret_canonical::canonical_json_bytes(&original)? != *bytes
                    || original.terminal_receipt != request.terminal_receipt
                    || original.initial_session != request.initial_session
                {
                    return Err(Error::Protocol(
                        "completion changed persisted R/holder intent".into(),
                    ));
                }
                return Ok(original);
            }
            let mut next = current.clone();
            next.pending_recovery_completion =
                Some(arkret_canonical::canonical_json_bytes(request)?);
            if self.store.compare_exchange(Some(&current), &next).await? {
                return Ok(request.clone());
            }
        }
    }

    /// Only the completion operation's authenticated, lock-linearized expiry
    /// rejection authorizes retiring a never-accepted PoP attempt. R and the
    /// initial holder intent remain immutable. 404/503/local time are not proof.
    pub async fn renew_recovery_completion_request(
        &self,
        rejected: &arkret_models_identity::RecoveryCompletionGrantRequestBody,
        fresh: &arkret_models_identity::RecoveryCompletionGrantRequestBody,
        http_status: u16,
        problem: &arkret_wire::Problem,
    ) -> Result<arkret_models_identity::RecoveryCompletionGrantRequestBody> {
        if http_status != 401
            || problem.status != 401
            || problem.code() != arkret_wire::ErrorCode::REAUTHENTICATION_REQUIRED
            || problem.problem_type != "https://arkret.org/problems/reauthentication_required"
            || problem
                .extensions
                .get("reason_code")
                .and_then(serde_json::Value::as_str)
                != Some(arkret_wire::ReasonCode::PROOF_INVALID)
        {
            return Err(Error::Protocol(
                "completion attempt has no definitive issuer expiry rejection".into(),
            ));
        }
        rejected.validate_structural()?;
        fresh.validate_structural()?;
        if rejected.terminal_receipt != fresh.terminal_receipt
            || rejected.initial_session != fresh.initial_session
            || fresh.accepted_device_possession_proof.expires_at
                <= rejected.accepted_device_possession_proof.expires_at
        {
            return Err(Error::Protocol(
                "completion renewal changed R/holder or did not advance the PoP window".into(),
            ));
        }
        let rejected_bytes = arkret_canonical::canonical_json_bytes(rejected)?;
        loop {
            let current = self
                .store
                .load_committed(&rejected.terminal_receipt.transaction_id)
                .await?
                .ok_or_else(|| Error::Protocol("Recovery record disappeared".into()))?;
            let Some(bytes) = current.pending_recovery_completion.as_ref() else {
                return Err(Error::Protocol(
                    "completion has no persisted first attempt".into(),
                ));
            };
            if *bytes != rejected_bytes {
                let winner: arkret_models_identity::RecoveryCompletionGrantRequestBody =
                    serde_json::from_slice(bytes)?;
                winner.validate_structural()?;
                if winner.terminal_receipt != fresh.terminal_receipt
                    || winner.initial_session != fresh.initial_session
                {
                    return Err(Error::Protocol(
                        "completion renewal lost to another intent".into(),
                    ));
                }
                return Ok(winner);
            }
            let mut next = current.clone();
            next.pending_recovery_completion = Some(arkret_canonical::canonical_json_bytes(fresh)?);
            if self.store.compare_exchange(Some(&current), &next).await? {
                return Ok(fresh.clone());
            }
        }
    }

    pub async fn refresh(&self, transaction_id: &TransactionId) -> Result<SecurityTransaction> {
        let mut local = self.store.load(transaction_id)?.ok_or_else(|| {
            Error::Protocol("security transaction has no local public plan".to_owned())
        })?;
        let resource = self.transport.get(transaction_id).await?;
        self.observe(&mut local, resource).await
    }

    pub async fn continue_transaction(
        &self,
        transaction_id: &TransactionId,
        request: &SecurityTransactionContinueRequestBody,
    ) -> Result<SecurityTransaction> {
        let mut local = self.store.load(transaction_id)?.ok_or_else(|| {
            Error::Protocol("security transaction has no local public plan".to_owned())
        })?;
        let observed = local.last_observed_resource.as_ref().ok_or_else(|| {
            Error::Protocol("security transaction has no observed service resource".to_owned())
        })?;
        request.validate_for_transaction(observed)?;
        let canonical_request = arkret_canonical::canonical_json_bytes(request)?;
        let pending = PendingSecurityTransactionContinue {
            expected_accepted_step_count: request.expected_accepted_step_count,
            canonical_request,
        };
        loop {
            let current = self
                .store
                .load_committed(transaction_id)
                .await?
                .ok_or_else(|| Error::Protocol("Rotation record disappeared".into()))?;
            if current.canonical_create_request != local.canonical_create_request
                || current
                    .pending_continue
                    .as_ref()
                    .is_some_and(|existing| existing != &pending)
            {
                return Err(Error::Protocol(
                    "Rotation continuation idempotency conflict".into(),
                ));
            }
            let current_observed = current
                .last_observed_resource
                .as_ref()
                .ok_or_else(|| Error::Protocol("Rotation has no observed resource".into()))?;
            request.validate_for_transaction(current_observed)?;
            let mut next = current.clone();
            next.pending_continue = Some(pending.clone());
            if self.store.compare_exchange(Some(&current), &next).await? {
                local = next;
                break;
            }
        }

        let resource = self
            .transport
            .continue_transaction(transaction_id, request)
            .await?;
        validate_observed_resource(&local, &resource)?;
        local.pending_continue = None;
        self.observe(&mut local, resource).await
    }

    pub async fn retry_pending(
        &self,
        transaction_id: &TransactionId,
    ) -> Result<Option<SecurityTransaction>> {
        let mut local = self.store.load(transaction_id)?.ok_or_else(|| {
            Error::Protocol("security transaction has no local public plan".to_owned())
        })?;
        if let Some(resource) = local.last_observed_resource.clone()
            && resource_is_terminal(&resource)
            && local.staged_secret_ref.is_some()
            && local.pending_continue.is_none()
        {
            validate_observed_resource(&local, &resource)?;
            persist_observation(&self.store, &mut local, true).await?;
            return Ok(Some(resource));
        }
        let Some(pending) = local.pending_continue else {
            return Ok(None);
        };
        let request: SecurityTransactionContinueRequestBody =
            serde_json::from_slice(&pending.canonical_request)?;
        if request.expected_accepted_step_count != pending.expected_accepted_step_count
            || arkret_canonical::canonical_json_bytes(&request)? != pending.canonical_request
        {
            return Err(Error::Protocol(
                "stored security transaction continuation is not canonical".to_owned(),
            ));
        }
        self.continue_transaction(transaction_id, &request)
            .await
            .map(Some)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use arkret_wire::{EventId, RealmCommitId};
    use serde_json::json;

    use super::*;

    fn realm(seed: u8) -> RealmId {
        RealmId::from_event_id(&EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [seed; 32],
        ))
    }

    fn committed_ref(realm_id: RealmId, seed: u8, position: u64) -> CommittedEventRef {
        CommittedEventRef {
            event_id: EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [seed; 32]),
            commit_id: RealmCommitId::from_digest([seed.wrapping_add(1); 32]),
            stream_ref: CommitStreamRef::Realm { realm_id },
            stream_position: position,
        }
    }

    fn durable_state() -> DurableSecurityTransaction {
        DurableSecurityTransaction {
            transaction_id: completed_recovery_receipt().transaction_id,
            canonical_create_request: br#"{"kind":"recovery"}"#.to_vec(),
            staged_secret_ref: Some("secure/recovery/1".to_owned()),
            pending_recovery_completion: None,
            pending_continue: Some(PendingSecurityTransactionContinue {
                expected_accepted_step_count: 0,
                canonical_request: br#"{"expected_accepted_step_count":0}"#.to_vec(),
            }),
            completed_recovery_receipt: None,
            last_observed_resource: None,
        }
    }

    #[derive(Clone, Default)]
    struct FailSaveStore {
        memory: MemorySecurityTransactionStore,
        save_count: Arc<AtomicUsize>,
        fail_on_save: Arc<AtomicUsize>,
    }

    impl SecurityTransactionStore for FailSaveStore {
        fn load(
            &self,
            transaction_id: &TransactionId,
        ) -> Result<Option<DurableSecurityTransaction>> {
            self.memory.load(transaction_id)
        }

        async fn save(&self, state: &DurableSecurityTransaction) -> Result<()> {
            let save_number = self.save_count.fetch_add(1, Ordering::SeqCst) + 1;
            if save_number == self.fail_on_save.load(Ordering::SeqCst) {
                return Err(Error::Protocol("injected durable save failure".to_owned()));
            }
            self.memory.save(state).await
        }

        async fn load_committed(
            &self,
            id: &TransactionId,
        ) -> Result<Option<DurableSecurityTransaction>> {
            self.memory.load_committed(id).await
        }
        async fn compare_exchange(
            &self,
            expected: Option<&DurableSecurityTransaction>,
            next: &DurableSecurityTransaction,
        ) -> Result<bool> {
            let number = self.save_count.fetch_add(1, Ordering::SeqCst) + 1;
            if number == self.fail_on_save.load(Ordering::SeqCst) {
                return Err(Error::Protocol("injected durable save failure".into()));
            }
            self.memory.compare_exchange(expected, next).await
        }

        fn clear_staged_secret(&self, reference: &str) -> Result<()> {
            self.memory.clear_staged_secret(reference)
        }

        fn remove(&self, transaction_id: &TransactionId) -> Result<()> {
            self.memory.remove(transaction_id)
        }
    }

    #[tokio::test]
    async fn terminal_save_failure_keeps_staged_secret_for_recovery() {
        let store = FailSaveStore::default();
        let mut state = durable_state();
        store.fail_on_save.store(1, Ordering::SeqCst);

        assert!(persist_observation(&store, &mut state, true).await.is_err());
        assert_eq!(
            state.staged_secret_ref.as_deref(),
            Some("secure/recovery/1")
        );
        assert!(store.memory.cleared_secret_refs().is_empty());

        persist_observation(&store, &mut state, true).await.unwrap();
        assert!(state.staged_secret_ref.is_none());
        assert_eq!(store.memory.cleared_secret_refs(), ["secure/recovery/1"]);
        assert!(
            store
                .load(&state.transaction_id)
                .unwrap()
                .unwrap()
                .staged_secret_ref
                .is_none()
        );
    }

    #[tokio::test]
    async fn cleanup_save_failure_retries_from_durable_terminal_reference() {
        let store = FailSaveStore::default();
        let mut state = durable_state();
        store.fail_on_save.store(2, Ordering::SeqCst);

        assert!(persist_observation(&store, &mut state, true).await.is_err());
        let mut restored = store.load(&state.transaction_id).unwrap().unwrap();
        assert_eq!(
            restored.staged_secret_ref.as_deref(),
            Some("secure/recovery/1")
        );
        assert_eq!(store.memory.cleared_secret_refs(), ["secure/recovery/1"]);

        persist_observation(&store, &mut restored, true)
            .await
            .unwrap();
        assert_eq!(store.memory.cleared_secret_refs(), ["secure/recovery/1"]);
        assert!(
            store
                .load(&state.transaction_id)
                .unwrap()
                .unwrap()
                .staged_secret_ref
                .is_none()
        );
    }

    fn completed_recovery_receipt() -> RecoveryReceipt {
        let fixture = arkret_schema_conformance::spec_json_artifact(
            "fixtures/security-transaction-resilience-fixture.json",
        )
        .unwrap();
        serde_json::from_value(fixture["single_submit_recovery_kat"]["receipt"].clone()).unwrap()
    }

    fn completion_request() -> arkret_models_identity::RecoveryCompletionGrantRequestBody {
        let fixture = arkret_schema_conformance::spec_json_artifact(
            "fixtures/security-transaction-resilience-fixture.json",
        )
        .unwrap();
        serde_json::from_value(fixture["single_submit_recovery_kat"]["completion_request"].clone())
            .unwrap()
    }
    fn fresh_completion(
        original: &arkret_models_identity::RecoveryCompletionGrantRequestBody,
    ) -> arkret_models_identity::RecoveryCompletionGrantRequestBody {
        use ed25519_dalek::Signer as _;
        let mut proof = original.accepted_device_possession_proof.clone();
        proof.issued_at += chrono::Duration::seconds(301);
        proof.expires_at += chrono::Duration::seconds(301);
        proof.request_id =
            arkret_wire::RequestId::new("ak:request:019ba000-0000-7000-8000-000000000009").unwrap();
        let seed = std::array::from_fn(|index| u8::try_from(index + 1).unwrap());
        proof.signature = arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
            ed25519_dalek::SigningKey::from_bytes(&seed)
                .sign(&proof.canonical_signing_bytes().unwrap())
                .to_bytes(),
        ))
        .unwrap();
        arkret_models_identity::RecoveryCompletionGrantRequestBody::new(
            original.terminal_receipt.clone(),
            original.initial_session.clone(),
            proof,
        )
        .unwrap()
    }
    async fn seeded_recovery(
        store: &MemorySecurityTransactionStore,
        request: &arkret_models_identity::RecoveryCompletionGrantRequestBody,
    ) -> DurableSecurityTransaction {
        let create = SecurityTransactionCreateRequestBody::Recovery(
            RecoveryTransactionCreateRequestBody::new(request.terminal_receipt.clone()).unwrap(),
        );
        let state = DurableSecurityTransaction {
            transaction_id: request.terminal_receipt.transaction_id.clone(),
            canonical_create_request: arkret_canonical::canonical_json_bytes(&create).unwrap(),
            staged_secret_ref: None,
            pending_continue: None,
            pending_recovery_completion: None,
            completed_recovery_receipt: None,
            last_observed_resource: None,
        };
        assert!(store.compare_exchange(None, &state).await.unwrap());
        state
    }
    #[derive(Clone)]
    struct NoNetwork;
    impl SecurityTransactionTransport for NoNetwork {
        async fn create(
            &self,
            _: &VerifiedSubmission<SecurityTransactionCreateRequestBody>,
        ) -> Result<SecurityTransaction> {
            panic!("no network before durable completion freeze")
        }
        async fn get(&self, _: &TransactionId) -> Result<SecurityTransaction> {
            panic!("completion does not require a client C fetch")
        }
        async fn continue_transaction(
            &self,
            _: &TransactionId,
            _: &SecurityTransactionContinueRequestBody,
        ) -> Result<SecurityTransaction> {
            panic!("Recovery has no continue")
        }
    }
    #[tokio::test]
    async fn completion_freeze_reuses_first_body_and_renewal_requires_exact_expiry_discriminator() {
        let store = MemorySecurityTransactionStore::default();
        let original = completion_request();
        let fresh = fresh_completion(&original);
        seeded_recovery(&store, &original).await;
        let engine = SecurityTransactionEngine::new(NoNetwork, store.clone());
        assert_eq!(
            arkret_canonical::canonical_json_bytes(
                &engine
                    .freeze_recovery_completion_request(&original)
                    .await
                    .unwrap()
            )
            .unwrap(),
            arkret_canonical::canonical_json_bytes(&original).unwrap()
        );
        assert_eq!(
            arkret_canonical::canonical_json_bytes(
                &engine
                    .freeze_recovery_completion_request(&fresh)
                    .await
                    .unwrap()
            )
            .unwrap(),
            arkret_canonical::canonical_json_bytes(&original).unwrap()
        );
        let mut rejection = arkret_wire::Problem::from_code(
            arkret_wire::ErrorCode::REAUTHENTICATION_REQUIRED,
            "fresh proof required",
        );
        rejection.status = 401;
        // Neither a broad authentication failure, local expiry nor a missing
        // native result proves this particular intent can no longer accept.
        assert!(
            engine
                .renew_recovery_completion_request(&original, &fresh, 401, &rejection)
                .await
                .is_err()
        );
        rejection.extensions.insert(
            "reason_code".into(),
            json!(arkret_wire::ReasonCode::PROOF_INVALID),
        );
        assert!(
            engine
                .renew_recovery_completion_request(&original, &fresh, 503, &rejection)
                .await
                .is_err()
        );
        let mut bad_type = rejection.clone();
        bad_type.problem_type = "https://other.example/reauthentication_required".into();
        assert!(
            engine
                .renew_recovery_completion_request(&original, &fresh, 401, &bad_type)
                .await
                .is_err()
        );
        assert_eq!(
            arkret_canonical::canonical_json_bytes(
                &engine
                    .renew_recovery_completion_request(&original, &fresh, 401, &rejection)
                    .await
                    .unwrap()
            )
            .unwrap(),
            arkret_canonical::canonical_json_bytes(&fresh).unwrap()
        );
        let stored = store
            .load_committed(&original.terminal_receipt.transaction_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            stored.pending_recovery_completion,
            Some(arkret_canonical::canonical_json_bytes(&fresh).unwrap())
        );
        let create: SecurityTransactionCreateRequestBody =
            serde_json::from_slice(&stored.canonical_create_request).unwrap();
        assert_eq!(
            create,
            SecurityTransactionCreateRequestBody::Recovery(
                RecoveryTransactionCreateRequestBody::new(original.terminal_receipt).unwrap()
            )
        );
    }
    #[tokio::test]
    async fn stale_observation_cannot_overwrite_completion_body_or_resurrect_cleaned_material() {
        let store = MemorySecurityTransactionStore::default();
        let request = completion_request();
        let mut stale = seeded_recovery(&store, &request).await;
        let engine = SecurityTransactionEngine::new(NoNetwork, store.clone());
        engine
            .freeze_recovery_completion_request(&request)
            .await
            .unwrap();
        let fixture = arkret_schema_conformance::spec_json_artifact(
            "fixtures/security-transaction-resilience-fixture.json",
        )
        .unwrap();
        let completed: SecurityTransaction = serde_json::from_value(
            fixture["single_submit_recovery_kat"]["expected_outcome"].clone(),
        )
        .unwrap();
        validate_observed_resource(&stale, &completed).unwrap();
        stale.last_observed_resource = Some(completed);
        persist_observation(&store, &mut stale, true).await.unwrap();
        assert_eq!(
            stale.pending_recovery_completion,
            Some(arkret_canonical::canonical_json_bytes(&request).unwrap())
        );
        let mut losing = stale.clone();
        losing.pending_recovery_completion = None;
        assert!(!store.compare_exchange(Some(&losing), &stale).await.unwrap());
    }

    #[test]
    fn completed_recovery_binds_the_exact_receipt_not_its_outer_artifact() {
        let receipt = completed_recovery_receipt();
        let digest = |value: &serde_json::Value| {
            arkret_wire::Hash::new(arkret_canonical::sha256_digest(
                arkret_canonical::canonical_json_bytes(value).unwrap(),
            ))
            .unwrap()
        };
        let receipt_digest = digest(&serde_json::to_value(&receipt).unwrap());
        validate_recovery_receipt_digest(&receipt, &receipt_digest).unwrap();
        let artifact_digest = digest(&json!({"recovery_receipt": receipt}));
        assert_ne!(receipt_digest, artifact_digest);
        assert!(validate_recovery_receipt_digest(&receipt, &artifact_digest).is_err());
        let mut altered = receipt;
        altered.welcome_count += 1;
        assert!(validate_recovery_receipt_digest(&altered, &receipt_digest).is_err());
    }

    #[test]
    fn recovery_boundary_accepts_consecutive_realm_commits() {
        let realm_id = realm(1);
        let first = committed_ref(realm_id.clone(), 2, 8);
        let second = committed_ref(realm_id.clone(), 4, 9);
        validate_recovery_commit_boundary(&realm_id, &first, &second).unwrap();
    }

    #[test]
    fn recovery_boundary_rejects_a_gap() {
        let realm_id = realm(1);
        let first = committed_ref(realm_id.clone(), 2, 8);
        let second = committed_ref(realm_id.clone(), 4, 10);
        assert!(validate_recovery_commit_boundary(&realm_id, &first, &second).is_err());
    }

    #[test]
    fn recovery_boundary_rejects_another_realm() {
        let realm_id = realm(1);
        let first = committed_ref(realm_id.clone(), 2, 8);
        let second = committed_ref(realm(9), 4, 9);
        assert!(validate_recovery_commit_boundary(&realm_id, &first, &second).is_err());
    }

    #[test]
    fn recovery_boundary_rejects_non_realm_streams() {
        let realm_id = realm(1);
        let first = committed_ref(realm_id.clone(), 2, 8);
        let mut second = committed_ref(realm_id.clone(), 4, 9);
        second.stream_ref = CommitStreamRef::Sidecar {
            realm_id: realm_id.clone(),
            sidecar_id: arkret_wire::SidecarId::from_event_id(&EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                [7; 32],
            )),
        };
        assert!(validate_recovery_commit_boundary(&realm_id, &first, &second).is_err());
    }

    #[tokio::test]
    async fn memory_store_preserves_exact_pending_request_bytes() {
        let store = MemorySecurityTransactionStore::default();
        let state = durable_state();
        store.save(&state).await.unwrap();
        let restored = store.load(&state.transaction_id).unwrap().unwrap();
        assert_eq!(
            restored.pending_continue.unwrap().canonical_request,
            br#"{"expected_accepted_step_count":0}"#
        );
    }

    #[tokio::test]
    async fn memory_store_tracks_secret_clear_and_removal_independently() {
        let store = MemorySecurityTransactionStore::default();
        let state = durable_state();
        store.save(&state).await.unwrap();
        store.clear_staged_secret("secure/recovery/1").unwrap();
        assert_eq!(store.cleared_secret_refs(), ["secure/recovery/1"]);
        store.remove(&state.transaction_id).unwrap();
        assert!(store.load(&state.transaction_id).unwrap().is_none());
    }

    #[test]
    fn completed_recovery_receipt_survives_restart_byte_identically() {
        let receipt = completed_recovery_receipt();
        receipt.validate().unwrap();
        let mut state = durable_state();
        let stored = DurableCompletedRecoveryReceipt::from_receipt(&receipt).unwrap();
        let exact_bytes = stored.canonical_receipt.clone();
        state.completed_recovery_receipt = Some(stored);

        let persisted = serde_json::to_vec(&state).unwrap();
        let restored: DurableSecurityTransaction = serde_json::from_slice(&persisted).unwrap();

        assert_eq!(
            restored
                .completed_recovery_receipt
                .as_ref()
                .unwrap()
                .canonical_receipt,
            exact_bytes
        );
        assert_eq!(
            restored.completed_recovery_receipt().unwrap(),
            Some(receipt)
        );
    }

    #[test]
    fn completed_recovery_receipt_rejects_noncanonical_persisted_bytes() {
        let receipt = completed_recovery_receipt();
        let mut state = durable_state();
        state.completed_recovery_receipt = Some(DurableCompletedRecoveryReceipt {
            canonical_receipt: serde_json::to_vec_pretty(&receipt).unwrap(),
        });

        assert!(state.completed_recovery_receipt().is_err());
    }

    #[test]
    fn completed_recovery_receipt_exact_replay_is_idempotent() {
        let receipt = completed_recovery_receipt();
        let mut state = durable_state();

        retain_completed_recovery_receipt(&mut state, &receipt).unwrap();
        let first = state.completed_recovery_receipt.clone().unwrap();
        retain_completed_recovery_receipt(&mut state, &receipt).unwrap();

        assert_eq!(state.completed_recovery_receipt.unwrap(), first);
    }

    #[test]
    fn completed_recovery_receipt_conflicting_replay_is_rejected() {
        let receipt = completed_recovery_receipt();
        let mut conflicting = receipt.clone();
        conflicting.signature_proof.signature =
            serde_json::from_value(serde_json::Value::String("AQ".to_owned())).unwrap();
        let mut state = durable_state();

        retain_completed_recovery_receipt(&mut state, &receipt).unwrap();

        assert!(retain_completed_recovery_receipt(&mut state, &conflicting).is_err());
    }
}
