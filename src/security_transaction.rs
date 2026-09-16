//! Durable coordination for current security transactions.
//!
//! The service resource is the authoritative progress record. Garth stores
//! only canonical public requests and an opaque reference to separately held
//! secret material. A completed PCR recovery is accepted only when its two
//! Events occupy consecutive coordinates in the same PCR Realm stream.

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::{Arc, Mutex};

pub use arkret_models_crypto::{
    ClientStepAttestation, PcrPolicyRecoveryPlan, RecoveryTerminalCommit,
    RecoveryTransactionCreateRequest, SecurityTransaction, SecurityTransactionContinueRequest,
    SecurityTransactionCreateRequest, SecurityTransactionPreparedPlan,
    SecurityTransactionTerminalOutcome,
};
use arkret_wire::{CommitStreamRef, CommittedEventRef, RealmId, TransactionId};
use serde::{Deserialize, Serialize};

use crate::{Error, MaybeSend, MaybeSendSync, Result};

/// Host transport for the three current transaction operations.
pub trait SecurityTransactionTransport: MaybeSendSync {
    fn create<'a>(
        &'a self,
        request: &'a SecurityTransactionCreateRequest,
    ) -> impl Future<Output = Result<SecurityTransaction>> + MaybeSend + 'a;

    fn get<'a>(
        &'a self,
        transaction_id: &'a TransactionId,
    ) -> impl Future<Output = Result<SecurityTransaction>> + MaybeSend + 'a;

    fn continue_transaction<'a>(
        &'a self,
        transaction_id: &'a TransactionId,
        request: &'a SecurityTransactionContinueRequest,
    ) -> impl Future<Output = Result<SecurityTransaction>> + MaybeSend + 'a;
}

/// One continuation retained byte-for-byte until the service observes it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingSecurityTransactionContinue {
    pub expected_accepted_step_count: u64,
    pub canonical_request: Vec<u8>,
}

/// Public durable state for one transaction.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DurableSecurityTransaction {
    pub transaction_id: TransactionId,
    pub canonical_create_request: Vec<u8>,
    /// Opaque host-owned secret-store reference; never plaintext secret bytes.
    pub staged_secret_ref: Option<String>,
    pub pending_continue: Option<PendingSecurityTransactionContinue>,
    pub last_observed_resource: Option<SecurityTransaction>,
}

pub trait SecurityTransactionStore: Clone + MaybeSendSync + 'static {
    fn load(&self, transaction_id: &TransactionId) -> Result<Option<DurableSecurityTransaction>>;
    fn save<'a>(
        &'a self,
        state: &'a DurableSecurityTransaction,
    ) -> impl Future<Output = Result<()>> + MaybeSend + 'a;
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
        self.cleared_secret_refs
            .lock()
            .unwrap()
            .push(reference.to_owned());
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
    }) = &resource.terminal_result
    {
        let plan = resource.recovery_plan().ok_or_else(|| {
            Error::Protocol(
                "only a PCR recovery may carry a recovery completion attestation".to_owned(),
            )
        })?;
        validate_recovery_commit_boundary(
            &plan.reanchor_commit_intent.realm_id,
            &attestation.reanchor_ref,
            &attestation.device_authorization_ref,
        )?;
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
        if resource.terminal_result.is_some()
            && let Some(reference) = local.staged_secret_ref.take()
        {
            self.store.clear_staged_secret(&reference)?;
        }
        local.last_observed_resource = Some(resource.clone());
        self.store.save(local).await?;
        Ok(resource)
    }

    pub async fn create_or_resume(
        &self,
        request: &SecurityTransactionCreateRequest,
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
        request: &SecurityTransactionContinueRequest,
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
        local.pending_continue = None;
        self.observe(&mut local, resource).await
    }

    pub async fn retry_pending(
        &self,
        transaction_id: &TransactionId,
    ) -> Result<Option<SecurityTransaction>> {
        let local = self.store.load(transaction_id)?.ok_or_else(|| {
            Error::Protocol("security transaction has no local public plan".to_owned())
        })?;
        let Some(pending) = local.pending_continue else {
            return Ok(None);
        };
        let request: SecurityTransactionContinueRequest =
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
    use arkret_wire::{EventId, RealmCommitId};

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
            last_observed_resource: None,
        }
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
}
