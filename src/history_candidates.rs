//! Durable client adapter for the SDK history-only store.
//!
//! Every admission, quota and eviction decision belongs to
//! `arkret_state::history_store`, the single implementation of
//! `history-visibility.md` section 7 and the `history_store` section of the
//! scalability registry. This module owns only what the SDK deliberately does
//! not: the secret bytes in the secure key store, and the write ordering that
//! keeps those bytes and the ledger consistent across a crash.

use arkret_canonical::canonical::canonical_sha256;
use arkret_models_collaboration::history_key::HistoryCandidateOriginAttribution;
use arkret_state::history_store::{HistoryMaterialLedger, ResidentHistoryMaterial};
use arkret_wire::{
    EventCandidateBinding, EventCandidateBindingKey, Hash, HistoryCandidateMaterialKey,
    HistoryCandidateMaterialRecord, HistoryEffectiveScope,
};
use chrono::{DateTime, Utc};
use std::collections::BTreeSet;

use crate::store::{SecretClass, SecretDurability, SecureKeyStore};
use crate::{Error, PutSecretOptions, Result};

const HISTORY_CANDIDATE_SECRET_PREFIX: &str = "arkret/history-candidate/v1/";

pub trait HistoryCandidateStateStore {
    fn load_history_candidate_state(&self) -> Result<HistoryMaterialLedger>;

    fn save_history_candidate_state(&mut self, ledger: &HistoryMaterialLedger) -> Result<()>;
}

#[derive(Clone, Debug, Default)]
pub struct MemoryHistoryCandidateStateStore {
    ledger: HistoryMaterialLedger,
}

impl MemoryHistoryCandidateStateStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl HistoryCandidateStateStore for MemoryHistoryCandidateStateStore {
    fn load_history_candidate_state(&self) -> Result<HistoryMaterialLedger> {
        Ok(self.ledger.clone())
    }

    fn save_history_candidate_state(&mut self, ledger: &HistoryMaterialLedger) -> Result<()> {
        self.ledger = ledger.clone();
        Ok(())
    }
}

pub struct HistoryCandidateEngine<S> {
    store: S,
}

impl<S> HistoryCandidateEngine<S>
where
    S: HistoryCandidateStateStore,
{
    pub fn new(store: S) -> Self {
        Self { store }
    }

    pub fn store(&self) -> &S {
        &self.store
    }

    pub fn store_mut(&mut self) -> &mut S {
        &mut self.store
    }

    pub fn into_store(self) -> S {
        self.store
    }

    pub fn event_binding(
        &self,
        event_binding_key: &EventCandidateBindingKey,
        candidate_digest: &Hash,
    ) -> Result<Option<EventCandidateBinding>> {
        Ok(self
            .store
            .load_history_candidate_state()?
            .event_binding(event_binding_key, candidate_digest)
            .cloned())
    }

    /// Durably admit one externally received history secret as an
    /// `external_candidate`.
    ///
    /// Returns whether the candidate is resident afterwards. Bytes are written
    /// before the ledger and evicted after it, so a crash can leave orphan
    /// bytes (harmless, overwritten by the identical refetch) but never a
    /// resident row without bytes.
    pub async fn receive_external_candidate(
        &mut self,
        secure_store: &dyn SecureKeyStore,
        secret: &[u8],
        attribution: HistoryCandidateOriginAttribution,
        now: DateTime<Utc>,
    ) -> Result<bool> {
        self.reconcile_candidate_secrets(secure_store)?;
        let material_key = attribution.material_key().clone();
        material_key.validate()?;
        let actual_digest = Hash::new(arkret_wire::canonical::sha256_digest(secret))?;
        if actual_digest != material_key.candidate_digest {
            return Err(Error::Protocol(
                "history candidate digest does not match exact secret bytes".to_owned(),
            ));
        }
        let secret_key = history_candidate_secret_key(&material_key)?;
        if let Some(stored) = secure_store.get_secret_bytes(&secret_key)?
            && stored.as_slice() != secret
        {
            return Err(Error::Protocol(
                "history candidate digest collision or secure-store mismatch".to_owned(),
            ));
        }

        let mut ledger = self.store.load_history_candidate_state()?;
        let plan = ledger.admit_received_candidate(&attribution, now)?;
        if let Some(stored) = &plan.store {
            secure_store
                .put_secret(
                    &history_candidate_secret_key(stored)?,
                    secret,
                    PutSecretOptions {
                        durability: SecretDurability::DurableBeforeReturn,
                        class: SecretClass::MlsSecret,
                    },
                )
                .await?;
        }
        self.store.save_history_candidate_state(&ledger)?;
        for evicted in &plan.evict {
            secure_store.delete_secret(&history_candidate_secret_key(evicted)?)?;
        }
        Ok(plan.resident)
    }

    /// Remove bytes left by a crash after the durable secret write but before
    /// the ledger commit. A ledger row is the only ready marker for candidate
    /// material; unreferenced bytes are never treated as candidates.
    pub fn reconcile_candidate_secrets(&self, secure_store: &dyn SecureKeyStore) -> Result<usize> {
        let referenced = self
            .store
            .load_history_candidate_state()?
            .resident
            .iter()
            .map(|resident| history_candidate_secret_key(&resident.material_key))
            .collect::<Result<BTreeSet<_>>>()?;
        let mut removed = 0;
        for key in secure_store.list_secret_keys(Some(HISTORY_CANDIDATE_SECRET_PREFIX))? {
            if !referenced.contains(&key) {
                secure_store.delete_secret(&key)?;
                removed += 1;
            }
        }
        Ok(removed)
    }

    pub fn record_event_binding(
        &mut self,
        binding: EventCandidateBinding,
        now: DateTime<Utc>,
    ) -> Result<()> {
        let mut ledger = self.store.load_history_candidate_state()?;
        ledger.record_event_binding(&binding, now)?;
        self.store.save_history_candidate_state(&ledger)
    }

    /// Resident received candidates for one epoch, in the SDK's deterministic
    /// try order, with their exact bytes reattached.
    pub fn candidates_for_epoch(
        &self,
        secure_store: &dyn SecureKeyStore,
        effective_scope: &HistoryEffectiveScope,
        mls_group_id: &str,
        epoch: u64,
    ) -> Result<Vec<HistoryCandidateMaterialRecord>> {
        self.store
            .load_history_candidate_state()?
            .resident_for_epoch(effective_scope, mls_group_id, epoch)
            .into_iter()
            .map(|resident| self.reattach_secret(secure_store, resident))
            .collect()
    }

    fn reattach_secret(
        &self,
        secure_store: &dyn SecureKeyStore,
        resident: &ResidentHistoryMaterial,
    ) -> Result<HistoryCandidateMaterialRecord> {
        let secret = secure_store
            .get_secret_bytes(&history_candidate_secret_key(&resident.material_key)?)?
            .ok_or_else(|| {
                Error::Protocol("resident history candidate bytes are missing".to_owned())
            })?;
        let actual_digest = Hash::new(arkret_wire::canonical::sha256_digest(secret.as_slice()))?;
        if actual_digest != resident.material_key.candidate_digest {
            return Err(Error::Protocol(
                "resident history candidate digest does not match exact secret bytes".to_owned(),
            ));
        }
        let record = HistoryCandidateMaterialRecord {
            material_key: resident.material_key.clone(),
            secret_b64u: arkret_wire::base64url::base64url_encode(secret.as_slice()),
            material_received_sequence: resident.material_received_sequence,
        };
        record.validate()?;
        Ok(record)
    }
}

fn history_candidate_secret_key(material_key: &HistoryCandidateMaterialKey) -> Result<String> {
    material_key.validate()?;
    Ok(format!(
        "{HISTORY_CANDIDATE_SECRET_PREFIX}{}",
        canonical_sha256(material_key)?
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use arkret_models_collaboration::history_key::{
        HistoryResponseId, ResponseSenderOriginRef, ResponseSenderQuotaDomain,
    };
    use arkret_wire::{
        EventCandidateBindingOutcome, EventId, HISTORY_STORE_LIMITS, HistoryEffectiveScope, RealmId,
    };

    fn hash(byte: char) -> Hash {
        Hash::new(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
    }

    fn scope() -> HistoryEffectiveScope {
        HistoryEffectiveScope::Realm {
            realm_id: RealmId::new("ak:realm:AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
                .unwrap(),
        }
    }

    fn attribution(secret: &[u8], now: DateTime<Utc>) -> HistoryCandidateOriginAttribution {
        let effective_scope = scope();
        HistoryCandidateOriginAttribution::ResponseSender {
            material_key: HistoryCandidateMaterialKey {
                mls_group_id: effective_scope.canonical_mls_group_id().unwrap(),
                effective_scope,
                epoch: 4,
                candidate_digest: Hash::new(arkret_wire::canonical::sha256_digest(secret)).unwrap(),
            },
            origin_quota_domain: ResponseSenderQuotaDomain {
                source_sender_domain: "ak:device:sender".to_owned(),
            },
            origin_ref: ResponseSenderOriginRef {
                response_id: HistoryResponseId::new(
                    "ak:history_response:019a0000-0000-7000-8000-000000000001",
                )
                .unwrap(),
                source_record_digest: hash('1'),
            },
            first_observed_at: now,
            expires_at: now
                + chrono::Duration::seconds(HISTORY_STORE_LIMITS.origin_attribution_ttl_seconds),
        }
    }

    #[tokio::test]
    async fn candidate_store_is_event_local_and_does_not_promote_epoch_winner() {
        let secret_store = crate::MemorySecureKeyStore::new();
        let mut engine = HistoryCandidateEngine::new(MemoryHistoryCandidateStateStore::new());
        let now = Utc::now();
        let secret = [7_u8; 32];
        let attribution = attribution(&secret, now);
        let key = attribution.material_key().clone();
        let digest = key.candidate_digest.clone();
        assert!(
            engine
                .receive_external_candidate(&secret_store, &secret, attribution, now)
                .await
                .unwrap()
        );
        let binding_key = EventCandidateBindingKey {
            effective_scope: key.effective_scope.clone(),
            mls_group_id: key.mls_group_id.clone(),
            epoch: key.epoch,
            event_id: EventId::new("ak:event:AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
                .unwrap(),
            event_digest: hash('2'),
            verified_sender_domain: "ak:device:sender".to_owned(),
        };
        engine
            .record_event_binding(
                EventCandidateBinding::new(
                    binding_key.clone(),
                    digest.clone(),
                    EventCandidateBindingOutcome::Failure,
                    now,
                )
                .unwrap(),
                now,
            )
            .unwrap();
        assert_eq!(
            engine
                .event_binding(&binding_key, &digest)
                .unwrap()
                .unwrap()
                .outcome,
            EventCandidateBindingOutcome::Failure
        );
        assert_eq!(
            engine
                .candidates_for_epoch(
                    &secret_store,
                    &key.effective_scope,
                    &key.mls_group_id,
                    key.epoch,
                )
                .unwrap()
                .len(),
            1
        );
    }

    struct FailFirstSaveStore {
        ledger: HistoryMaterialLedger,
        fail_first_save: bool,
    }

    impl HistoryCandidateStateStore for FailFirstSaveStore {
        fn load_history_candidate_state(&self) -> Result<HistoryMaterialLedger> {
            Ok(self.ledger.clone())
        }

        fn save_history_candidate_state(&mut self, ledger: &HistoryMaterialLedger) -> Result<()> {
            if self.fail_first_save {
                self.fail_first_save = false;
                return Err(Error::Protocol("injected ledger commit failure".to_owned()));
            }
            self.ledger = ledger.clone();
            Ok(())
        }
    }

    #[tokio::test]
    async fn retry_reconciles_secret_written_before_failed_ledger_commit() {
        let secret_store = crate::MemorySecureKeyStore::new();
        let mut engine = HistoryCandidateEngine::new(FailFirstSaveStore {
            ledger: HistoryMaterialLedger::default(),
            fail_first_save: true,
        });
        let now = Utc::now();
        let secret = [9_u8; 32];
        let attribution = attribution(&secret, now);

        assert!(
            engine
                .receive_external_candidate(&secret_store, &secret, attribution.clone(), now)
                .await
                .is_err()
        );
        assert_eq!(
            secret_store
                .list_secret_keys(Some(HISTORY_CANDIDATE_SECRET_PREFIX))
                .unwrap()
                .len(),
            1
        );
        assert!(
            engine
                .receive_external_candidate(&secret_store, &secret, attribution, now)
                .await
                .unwrap()
        );
        assert_eq!(engine.store().ledger.resident.len(), 1);
        assert_eq!(
            secret_store
                .list_secret_keys(Some(HISTORY_CANDIDATE_SECRET_PREFIX))
                .unwrap()
                .len(),
            1
        );
    }
}
