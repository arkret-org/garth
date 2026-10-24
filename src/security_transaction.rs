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
use arkret_models_crypto::ClientStepAttestationArtifact;
pub use arkret_models_crypto::{
    ClientStepAttestation, PcrPolicyRecoveryPlan, RecoveryReceipt, RecoveryTerminalCommit,
    RecoveryTransactionCreateRequestBody, SecurityTransaction,
    SecurityTransactionContinueRequestBody, SecurityTransactionCreateRequestBody,
    SecurityTransactionPreparedPlan, SecurityTransactionTerminalOutcome,
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

/// The exact canonical terminal receipt retained after a recovery completes.
///
/// Keeping the canonical bytes makes recovery-grant issuance restart-safe
/// without retaining a broader continuation request or any secret material.
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
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DurableSecurityTransaction {
    pub transaction_id: TransactionId,
    pub canonical_create_request: Vec<u8>,
    /// Opaque host-owned secret-store reference; never plaintext secret bytes.
    pub staged_secret_ref: Option<String>,
    pub pending_continue: Option<PendingSecurityTransactionContinue>,
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

fn validate_observed_resource(
    local: &DurableSecurityTransaction,
    resource: &SecurityTransaction,
) -> Result<()> {
    resource.validate_structural()?;
    if resource.transaction_id != local.transaction_id {
        return Err(Error::Protocol(
            "security transaction response changed transaction_id".to_owned(),
        ));
    }
    let expected_request_digest = arkret_wire::Hash::new(arkret_canonical::sha256_digest(
        &local.canonical_create_request,
    ))?;
    if resource.request_digest != expected_request_digest {
        return Err(Error::Protocol(
            "security transaction response changed the canonical create request".to_owned(),
        ));
    }

    if let Some(SecurityTransactionTerminalOutcome::Completed {
        completion_attestation: Some(attestation),
        ..
    }) = &resource.terminal_outcome
    {
        let plan = resource.recovery_plan().ok_or_else(|| {
            Error::Protocol(
                "only a PCR recovery may carry a recovery completion attestation".to_owned(),
            )
        })?;
        validate_recovery_commit_boundary(
            &plan.reanchor_commit_intent.realm_id,
            &attestation.reanchor_event_ref,
            &attestation.device_authorization_event_ref,
        )?;
    }
    Ok(())
}

fn retain_completed_recovery_receipt(
    local: &mut DurableSecurityTransaction,
    receipt: &RecoveryReceipt,
) -> Result<()> {
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
    // The terminal resource must survive a crash before the only local secret
    // reference can be discarded. A failed cleanup leaves the reference in
    // durable state so a later observation can retry it.
    store.save(local).await?;
    if terminal && let Some(reference) = local.staged_secret_ref.as_ref() {
        store.clear_staged_secret(reference)?;
        local.staged_secret_ref = None;
        store.save(local).await?;
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
        let terminal = resource.terminal_outcome.is_some();
        local.last_observed_resource = Some(resource.clone());
        persist_observation(&self.store, local, terminal).await?;
        Ok(resource)
    }

    pub async fn create_or_resume(
        &self,
        request: &VerifiedSubmission<SecurityTransactionCreateRequestBody>,
        staged_secret_ref: Option<String>,
    ) -> Result<SecurityTransaction> {
        request.validate()?;
        if staged_secret_ref.as_deref().is_some_and(str::is_empty) {
            return Err(Error::Protocol(
                "staged security-transaction reference must not be empty".to_owned(),
            ));
        }
        let canonical_request = arkret_canonical::canonical_json_bytes(request)?;
        let transaction_id = request.transaction_id();
        let mut local = match self.store.load(transaction_id)? {
            Some(existing) => {
                if existing.canonical_create_request != canonical_request
                    || existing.staged_secret_ref != staged_secret_ref
                {
                    return Err(Error::Protocol(
                        "security transaction idempotency conflict".to_owned(),
                    ));
                }
                existing
            }
            None => {
                let state = DurableSecurityTransaction {
                    transaction_id: transaction_id.clone(),
                    canonical_create_request: canonical_request,
                    staged_secret_ref,
                    pending_continue: None,
                    completed_recovery_receipt: None,
                    last_observed_resource: None,
                };
                self.store.save(&state).await?;
                state
            }
        };
        let resource = if local.last_observed_resource.is_some() {
            self.transport.get(transaction_id).await?
        } else {
            self.transport.create(request).await?
        };
        self.observe(&mut local, resource).await
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
        if local
            .pending_continue
            .as_ref()
            .is_some_and(|existing| existing != &pending)
        {
            return Err(Error::Protocol(
                "security transaction continuation idempotency conflict".to_owned(),
            ));
        }
        local.pending_continue = Some(pending);
        self.store.save(&local).await?;

        let resource = self
            .transport
            .continue_transaction(transaction_id, request)
            .await?;
        validate_observed_resource(&local, &resource)?;
        if matches!(
            resource.terminal_outcome,
            Some(SecurityTransactionTerminalOutcome::Completed { .. })
        ) && resource.recovery_plan().is_some()
        {
            let ClientStepAttestationArtifact::Recovery(artifact) =
                &request.client_attestation.artifact
            else {
                return Err(Error::Protocol(
                    "completed recovery omitted its terminal receipt".to_owned(),
                ));
            };
            let Some(SecurityTransactionTerminalOutcome::Completed {
                completion_attestation: Some(completion_attestation),
                ..
            }) = &resource.terminal_outcome
            else {
                return Err(Error::Protocol(
                    "completed recovery omitted its completion attestation".to_owned(),
                ));
            };
            validate_recovery_receipt_digest(
                &artifact.recovery_receipt,
                &completion_attestation.terminal_receipt_digest,
            )?;
            retain_completed_recovery_receipt(&mut local, &artifact.recovery_receipt)?;
        }
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
            && resource.terminal_outcome.is_some()
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
            transaction_id: TransactionId::new(
                "ak:transaction:0196419b-0000-7000-8000-000000000001",
            )
            .unwrap(),
            canonical_create_request: br#"{"kind":"recovery"}"#.to_vec(),
            staged_secret_ref: Some("secure/recovery/1".to_owned()),
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
        serde_json::from_value(json!({
            "schema": "ak.schema.recovery_receipt.v1",
            "receipt_id": "ak:receipt:0196419b-0000-7000-8000-000000000002",
            "transaction_id": "ak:transaction:0196419b-0000-7000-8000-000000000001",
            "transaction_request_digest": format!("sha256:{}", "1".repeat(64)),
            "prepared_plan_digest": format!("sha256:{}", "2".repeat(64)),
            "account_id": {
                "principal_id": "ak:did_core:webvh:z6mkfixtureprincipalexample",
                "station_id": "ak:did_core:webvh:z6mkfixtureserviceexample"
            },
            "recovery_session_id": "ak:recovery_session:0196419b-0000-7000-8000-000000000003",
            "policy_id": "ak:policy:0196419b-0000-7000-8000-000000000004",
            "policy_version": 1,
            "trust_domain": "ak:trust_domain:fixture.example",
            "new_device_id": "ak:device:0196419b-0000-7000-8000-000000000005",
            "identity_model": "pcr_policy",
            "recovery_authority_kind": "pcr_policy",
            "previous_model_generation_ref": 7,
            "new_model_generation_ref": 8,
            "authorization_event_id": "ak:event:AWKDhmQTc5zyfilaLwPF3xnhoZAjxSha7Z-6grioN9aW",
            "reanchor_event_id": "ak:event:AR8bu-n-kOOB3nRUvYuIEglCX5B-JpFaNTex9gxs_cWY",
            "proof_summary": {
                "kind": "recovery_unlock",
                "proof_digest": format!("sha256:{}", "3".repeat(64))
            },
            "unlocked_backups": [],
            "welcome_count": 0,
            "outcome": "completed",
            "started_at": "2026-09-19T10:00:00.000Z",
            "completed_at": "2026-09-19T10:00:01.000Z",
            "signature_proof": {
                "verification_method": "did:web:alice.example#device-1",
                "signature_algorithm": "Ed25519",
                "signature": "AA"
            }
        }))
        .unwrap()
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
