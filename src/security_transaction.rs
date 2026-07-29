//! Durable client coordination for Arkret security transactions.
//!
//! The server resource is the only authoritative progress record. This module
//! persists only public, byte-identical requests plus an opaque reference to
//! separately encrypted staged material. Recovery secrets never enter this
//! state.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use arkret_models_crypto::TypedSecurityTransactionContinueRequest;
use arkret_models_crypto::{BackupSeriesEraseOutcome, BackupSeriesEraseRequestBody};
use arkret_wire::{
    Hash, SecurityTransaction, SecurityTransactionCreateRequest, SecurityTransactionState,
    SecurityTransactionStep, TransactionId,
};
use serde::{Deserialize, Serialize};

use crate::{Error, MaybeSendSync, Result};

#[cfg(not(target_arch = "wasm32"))]
pub type BoxSecurityTransactionFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

#[cfg(target_arch = "wasm32")]
pub type BoxSecurityTransactionFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + 'a>>;

pub trait SecurityTransactionTransport: MaybeSendSync {
    fn create_security_transaction<'a>(
        &'a self,
        request: &'a SecurityTransactionCreateRequest,
    ) -> BoxSecurityTransactionFuture<'a, SecurityTransaction>;

    fn get_security_transaction<'a>(
        &'a self,
        transaction_id: &'a TransactionId,
    ) -> BoxSecurityTransactionFuture<'a, SecurityTransaction>;

    fn continue_security_transaction<'a>(
        &'a self,
        transaction_id: &'a TransactionId,
        request: &'a TypedSecurityTransactionContinueRequest,
    ) -> BoxSecurityTransactionFuture<'a, SecurityTransaction>;

    fn erase_backup_series<'a>(
        &'a self,
        request: &'a BackupSeriesEraseRequestBody,
    ) -> BoxSecurityTransactionFuture<'a, BackupSeriesEraseOutcome>;
}

impl SecurityTransactionTransport for arkret_http_client::Client {
    fn create_security_transaction<'a>(
        &'a self,
        request: &'a SecurityTransactionCreateRequest,
    ) -> BoxSecurityTransactionFuture<'a, SecurityTransaction> {
        Box::pin(async move {
            self.create_security_transaction(request)
                .await
                .map_err(Error::from)
        })
    }

    fn get_security_transaction<'a>(
        &'a self,
        transaction_id: &'a TransactionId,
    ) -> BoxSecurityTransactionFuture<'a, SecurityTransaction> {
        Box::pin(async move {
            self.get_security_transaction(transaction_id)
                .await
                .map_err(Error::from)
        })
    }

    fn continue_security_transaction<'a>(
        &'a self,
        transaction_id: &'a TransactionId,
        request: &'a TypedSecurityTransactionContinueRequest,
    ) -> BoxSecurityTransactionFuture<'a, SecurityTransaction> {
        Box::pin(async move {
            self.continue_security_transaction(transaction_id, request)
                .await
                .map_err(Error::from)
        })
    }

    fn erase_backup_series<'a>(
        &'a self,
        request: &'a BackupSeriesEraseRequestBody,
    ) -> BoxSecurityTransactionFuture<'a, BackupSeriesEraseOutcome> {
        Box::pin(async move { self.erase_backup_series(request).await.map_err(Error::from) })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingSecurityTransactionContinue {
    pub step: SecurityTransactionStep,
    pub canonical_request: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DurableSecurityTransaction {
    pub transaction_id: TransactionId,
    pub canonical_create_request: Vec<u8>,
    /// Reference into a host-owned encrypted store. Never plaintext material.
    pub staged_secret_ref: Option<String>,
    pub pending_continue: Option<PendingSecurityTransactionContinue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_erase_request: Option<Vec<u8>>,
    /// Cached UI projection only; GET remains authoritative.
    pub last_observed_resource: Option<SecurityTransaction>,
}

impl DurableSecurityTransaction {
    pub fn create_request_digest(&self) -> Result<Hash> {
        Hash::new(arkret_canonical::sha256_digest(
            &self.canonical_create_request,
        ))
        .map_err(Error::from)
    }

    pub fn progress(&self) -> SecurityTransactionProgress {
        self.last_observed_resource.as_ref().map_or(
            SecurityTransactionProgress {
                transaction_id: self.transaction_id.clone(),
                state: None,
                next_required_step: None,
                accepted_step_count: 0,
                terminal: false,
            },
            |resource| SecurityTransactionProgress {
                transaction_id: resource.transaction_id.clone(),
                state: Some(resource.state),
                next_required_step: resource.next_required_step,
                accepted_step_count: resource.accepted_steps.len(),
                terminal: resource.state.is_terminal(),
            },
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecurityTransactionProgress {
    pub transaction_id: TransactionId,
    pub state: Option<SecurityTransactionState>,
    pub next_required_step: Option<SecurityTransactionStep>,
    pub accepted_step_count: usize,
    pub terminal: bool,
}

pub trait SecurityTransactionStore: Clone + MaybeSendSync + 'static {
    fn load(&self, transaction_id: &TransactionId) -> Result<Option<DurableSecurityTransaction>>;
    fn save<'a>(
        &'a self,
        state: &'a DurableSecurityTransaction,
    ) -> impl Future<Output = Result<()>> + crate::MaybeSend + 'a;
    fn remove(&self, transaction_id: &TransactionId) -> Result<()>;
}

#[derive(Clone, Default)]
pub struct MemorySecurityTransactionStore {
    transactions: Arc<Mutex<BTreeMap<String, DurableSecurityTransaction>>>,
}

impl SecurityTransactionStore for MemorySecurityTransactionStore {
    fn load(&self, transaction_id: &TransactionId) -> Result<Option<DurableSecurityTransaction>> {
        Ok(self
            .transactions
            .lock()
            .map_err(|_| Error::Protocol("security transaction store lock poisoned".to_owned()))?
            .get(transaction_id.as_str())
            .cloned())
    }

    fn save<'a>(
        &'a self,
        state: &'a DurableSecurityTransaction,
    ) -> impl Future<Output = Result<()>> + crate::MaybeSend + 'a {
        async move {
            self.transactions
                .lock()
                .map_err(|_| {
                    Error::Protocol("security transaction store lock poisoned".to_owned())
                })?
                .insert(state.transaction_id.as_str().to_owned(), state.clone());
            Ok(())
        }
    }

    fn remove(&self, transaction_id: &TransactionId) -> Result<()> {
        self.transactions
            .lock()
            .map_err(|_| Error::Protocol("security transaction store lock poisoned".to_owned()))?
            .remove(transaction_id.as_str());
        Ok(())
    }
}

#[derive(Clone)]
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

    pub async fn create_or_resume(
        &self,
        request: &SecurityTransactionCreateRequest,
        staged_secret_ref: Option<String>,
    ) -> Result<SecurityTransaction> {
        validate_staged_secret_ref(staged_secret_ref.as_deref())?;
        let transaction_id = create_request_transaction_id(request);
        let canonical_request = arkret_canonical::canonical_json_bytes(request)?;
        let mut local = match self.store.load(transaction_id)? {
            Some(existing) => {
                if existing.canonical_create_request != canonical_request
                    || existing.staged_secret_ref != staged_secret_ref
                {
                    return Err(Error::IdempotencyConflict(
                        transaction_id.as_str().to_owned(),
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
                    pending_erase_request: None,
                    last_observed_resource: None,
                };
                self.store.save(&state).await?;
                state
            }
        };
        let resource = if local.last_observed_resource.is_some() {
            self.transport
                .get_security_transaction(transaction_id)
                .await?
        } else {
            self.transport.create_security_transaction(request).await?
        };
        validate_resource_binding(&local, &resource)?;
        local.last_observed_resource = Some(resource.clone());
        self.store.save(&local).await?;
        Ok(resource)
    }

    pub async fn refresh(&self, transaction_id: &TransactionId) -> Result<SecurityTransaction> {
        let mut local = self.store.load(transaction_id)?.ok_or_else(|| {
            Error::Protocol(format!(
                "security transaction {} has no local public plan",
                transaction_id.as_str()
            ))
        })?;
        let resource = self
            .transport
            .get_security_transaction(transaction_id)
            .await?;
        validate_resource_binding(&local, &resource)?;
        local.last_observed_resource = Some(resource.clone());
        self.store.save(&local).await?;
        Ok(resource)
    }

    pub async fn continue_transaction(
        &self,
        transaction_id: &TransactionId,
        request: &TypedSecurityTransactionContinueRequest,
    ) -> Result<SecurityTransaction> {
        let mut local = self.store.load(transaction_id)?.ok_or_else(|| {
            Error::Protocol(format!(
                "security transaction {} has no local public plan",
                transaction_id.as_str()
            ))
        })?;
        let canonical_request = arkret_canonical::canonical_json_bytes(request)?;
        let pending = PendingSecurityTransactionContinue {
            step: request.expected_next_step,
            canonical_request: canonical_request.clone(),
        };
        if local
            .pending_continue
            .as_ref()
            .is_some_and(|existing| existing != &pending)
        {
            return Err(Error::IdempotencyConflict(format!(
                "{}:{:?}",
                transaction_id.as_str(),
                request.expected_next_step
            )));
        }
        local.pending_continue = Some(pending);
        self.store.save(&local).await?;

        let resource = self
            .transport
            .continue_security_transaction(transaction_id, request)
            .await?;
        validate_resource_binding(&local, &resource)?;
        local.pending_continue = None;
        local.last_observed_resource = Some(resource.clone());
        self.store.save(&local).await?;
        Ok(resource)
    }

    pub async fn retry_pending(
        &self,
        transaction_id: &TransactionId,
    ) -> Result<Option<SecurityTransaction>> {
        let local = self.store.load(transaction_id)?.ok_or_else(|| {
            Error::Protocol(format!(
                "security transaction {} has no local public plan",
                transaction_id.as_str()
            ))
        })?;
        let Some(pending) = local.pending_continue else {
            return Ok(None);
        };
        let request: TypedSecurityTransactionContinueRequest = serde_json::from_value(
            arkret_canonical::parse_canonical_json(&pending.canonical_request)?,
        )
        .map_err(|error| {
            Error::Protocol(format!(
                "stored security transaction continuation is invalid: {error}"
            ))
        })?;
        if request.expected_next_step != pending.step {
            return Err(Error::Protocol(
                "stored security transaction continuation changed its step".to_owned(),
            ));
        }
        self.continue_transaction(transaction_id, &request)
            .await
            .map(Some)
    }

    pub async fn erase_backup_series(
        &self,
        transaction_id: &TransactionId,
        request: &BackupSeriesEraseRequestBody,
    ) -> Result<BackupSeriesEraseOutcome> {
        let mut local = self.store.load(transaction_id)?.ok_or_else(|| {
            Error::Protocol(format!(
                "security transaction {} has no local public plan",
                transaction_id.as_str()
            ))
        })?;
        if &request.transaction_id != transaction_id {
            return Err(Error::Protocol(
                "backup-series erase request belongs to a different transaction".to_owned(),
            ));
        }
        let canonical = arkret_canonical::canonical_json_bytes(request)?;
        if local
            .pending_erase_request
            .as_ref()
            .is_some_and(|existing| existing != &canonical)
        {
            return Err(Error::IdempotencyConflict(format!(
                "{}:erase_old_material",
                transaction_id.as_str()
            )));
        }
        local.pending_erase_request = Some(canonical);
        self.store.save(&local).await?;
        let outcome = self.transport.erase_backup_series(request).await?;
        outcome.validate_for_request(request).map_err(Error::from)?;
        if outcome.status == arkret_models_crypto::BackupSeriesEraseStatus::Complete {
            local.pending_erase_request = None;
            local.last_observed_resource = Some(
                self.transport
                    .get_security_transaction(transaction_id)
                    .await?,
            );
            self.store.save(&local).await?;
        }
        Ok(outcome)
    }

    pub async fn retry_pending_erase(
        &self,
        transaction_id: &TransactionId,
    ) -> Result<Option<BackupSeriesEraseOutcome>> {
        let local = self.store.load(transaction_id)?.ok_or_else(|| {
            Error::Protocol(format!(
                "security transaction {} has no local public plan",
                transaction_id.as_str()
            ))
        })?;
        let Some(canonical) = local.pending_erase_request else {
            return Ok(None);
        };
        let request: BackupSeriesEraseRequestBody = serde_json::from_value(
            arkret_canonical::parse_canonical_json(&canonical)?,
        )
        .map_err(|error| {
            Error::Protocol(format!(
                "stored backup-series erase request is invalid: {error}"
            ))
        })?;
        self.erase_backup_series(transaction_id, &request)
            .await
            .map(Some)
    }
}

fn validate_staged_secret_ref(reference: Option<&str>) -> Result<()> {
    let Some(reference) = reference else {
        return Ok(());
    };
    if !reference.starts_with("secure-store://")
        || reference.len() > 512
        || reference.chars().any(char::is_whitespace)
        || reference.contains('?')
        || reference.contains('#')
    {
        return Err(Error::Protocol(
            "staged_secret_ref must be an opaque secure-store reference without query or fragment"
                .to_owned(),
        ));
    }
    Ok(())
}

fn create_request_transaction_id(request: &SecurityTransactionCreateRequest) -> &TransactionId {
    match request {
        SecurityTransactionCreateRequest::Recovery(request) => &request.transaction_id,
        SecurityTransactionCreateRequest::SecurityRotation(request) => &request.transaction_id,
    }
}

fn validate_resource_binding(
    local: &DurableSecurityTransaction,
    resource: &SecurityTransaction,
) -> Result<()> {
    resource.validate_structural().map_err(Error::from)?;
    if resource.transaction_id != local.transaction_id
        || resource.request_digest != local.create_request_digest()?
    {
        return Err(Error::Protocol(
            "security transaction resource changed the durable create binding".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn transaction_id() -> TransactionId {
        TransactionId::new("ak:transaction:01904100-0000-7000-8000-abcdefabcdef").unwrap()
    }

    #[tokio::test]
    async fn memory_store_round_trips_only_public_coordination_state() {
        let store = MemorySecurityTransactionStore::default();
        let state = DurableSecurityTransaction {
            transaction_id: transaction_id(),
            canonical_create_request: br#"{"public_plan":true}"#.to_vec(),
            staged_secret_ref: Some("secure-store://recovery/staged-1".to_owned()),
            pending_continue: None,
            pending_erase_request: None,
            last_observed_resource: None,
        };
        store.save(&state).await.unwrap();
        let loaded = store.load(&state.transaction_id).unwrap().unwrap();
        assert_eq!(loaded.canonical_create_request, br#"{"public_plan":true}"#);
        assert_eq!(
            loaded.staged_secret_ref.as_deref(),
            Some("secure-store://recovery/staged-1")
        );
        assert!(
            !serde_json::to_vec(&loaded)
                .unwrap()
                .windows("recovery secret".len())
                .any(|window| window == b"recovery secret")
        );
    }

    #[test]
    fn progress_without_server_resource_does_not_infer_completion() {
        let state = DurableSecurityTransaction {
            transaction_id: transaction_id(),
            canonical_create_request: Vec::new(),
            staged_secret_ref: None,
            pending_continue: None,
            pending_erase_request: None,
            last_observed_resource: None,
        };
        let progress = state.progress();
        assert_eq!(progress.state, None);
        assert_eq!(progress.next_required_step, None);
        assert_eq!(progress.accepted_step_count, 0);
        assert!(!progress.terminal);
    }

    #[test]
    fn staged_secret_reference_cannot_embed_secret_material() {
        assert!(validate_staged_secret_ref(Some("secure-store://recovery/staged-1")).is_ok());
        for invalid in [
            "recovery phrase words",
            "secure-store://recovery/staged-1?mnemonic=secret",
            "secure-store://recovery/staged-1#private-key",
        ] {
            assert!(validate_staged_secret_ref(Some(invalid)).is_err());
        }
    }
}
