//! Runtime-neutral consumption boundary for portable history backup.
//!
//! Packing is deliberately limited by the SDK helper's
//! `LocalAuthoritativeHistorySecret` input. Restore always passes through the
//! candidate engine, so imported material can never become local authority.

use arkret_models_crypto::KeyBackupPlaintext;
use arkret_wire::DidCoreId;
use chrono::{DateTime, Utc};

use crate::Result;
use crate::history_candidates::{HistoryCandidateEngine, HistoryCandidateStateStore};
use crate::store::SecureKeyStore;

pub use arkret_state::history_backup::pack_local_authoritative_history_backup;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HistoryBackupRestoreOutcome {
    pub restored_records: usize,
    pub resident_candidates: usize,
}

/// Restore the SDK's closed `mls_history` plaintext and durably admit every
/// unpacked secret as an `external_candidate` with portable-backup provenance.
pub async fn restore_history_backup_into_candidates<S>(
    engine: &mut HistoryCandidateEngine<S>,
    secure_store: &dyn SecureKeyStore,
    plaintext: &KeyBackupPlaintext,
    producer_actor_id: &DidCoreId,
    kdf_nh: usize,
    first_observed_at: DateTime<Utc>,
) -> Result<HistoryBackupRestoreOutcome>
where
    S: HistoryCandidateStateStore,
{
    let restored = arkret_state::history_backup::restore_history_backup_candidates(
        plaintext,
        producer_actor_id,
        kdf_nh,
        first_observed_at,
    )?;
    let restored_records = restored.len();
    let mut resident_candidates = 0;
    for candidate in restored {
        if engine
            .receive_external_candidate(
                secure_store,
                &candidate.secret,
                candidate.attribution,
                first_observed_at,
            )
            .await?
        {
            resident_candidates += 1;
        }
    }
    Ok(HistoryBackupRestoreOutcome {
        restored_records,
        resident_candidates,
    })
}

#[cfg(test)]
mod tests {
    use arkret_models_collaboration::history_key::HistoryCandidateOriginAttribution;
    use arkret_models_crypto::KeyBackupPlaintext;
    use arkret_wire::base64url::base64url_encode;
    use arkret_wire::{
        BackupId, BackupSeriesId, EventId, Hash, HistoryEffectiveScope,
        LocalAuthoritativeHistorySecret, RealmId,
    };

    use super::*;
    use crate::{MemoryHistoryCandidateStateStore, MemorySecureKeyStore};

    const KDF_NH: usize = 32;

    fn scope() -> HistoryEffectiveScope {
        HistoryEffectiveScope::Realm {
            realm_id: RealmId::new("ak:realm:AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
                .unwrap(),
        }
    }

    fn local_secret(epoch: u64) -> LocalAuthoritativeHistorySecret {
        let effective_scope = scope();
        LocalAuthoritativeHistorySecret {
            mls_group_id: effective_scope.canonical_mls_group_id().unwrap(),
            effective_scope,
            epoch,
            mls_ciphersuite: "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519".to_owned(),
            local_state_ref: "arkret/mls-state/v1/realm/7".to_owned(),
            transition_ref: EventId::new("ak:event:AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
                .unwrap(),
            transition_event_digest: Hash::new(arkret_wire::canonical::sha256_digest([1; 4]))
                .unwrap(),
            mls_transition_digest: Hash::new(arkret_wire::canonical::sha256_digest([2; 8]))
                .unwrap(),
            secret_b64u: base64url_encode([epoch as u8; KDF_NH]),
        }
    }

    #[tokio::test]
    async fn restored_backup_enters_only_the_external_candidate_ledger() {
        let keybag = pack_local_authoritative_history_backup(
            &scope(),
            &[local_secret(7), local_secret(8)],
            KDF_NH,
        )
        .unwrap();
        let plaintext = KeyBackupPlaintext {
            schema: KeyBackupPlaintext::SCHEMA.to_owned(),
            backup_id: BackupId::new("ak:backup:01964137-0000-7000-8000-000000000000").unwrap(),
            series_id: BackupSeriesId::new("ak:backup_series:01964137-0000-7000-8000-000000000001")
                .unwrap(),
            series_seq: 3,
            keybag,
            extra: Default::default(),
        };
        let producer = DidCoreId::new("ak:did_core:web:acme.example:users:alice").unwrap();
        let now = Utc::now();
        let secure_store = MemorySecureKeyStore::new();
        let mut engine = HistoryCandidateEngine::new(MemoryHistoryCandidateStateStore::new());

        let outcome = restore_history_backup_into_candidates(
            &mut engine,
            &secure_store,
            &plaintext,
            &producer,
            KDF_NH,
            now,
        )
        .await
        .unwrap();
        assert_eq!(outcome.restored_records, 2);
        assert_eq!(outcome.resident_candidates, 2);
        let ledger = engine.store().load_history_candidate_state().unwrap();
        assert_eq!(ledger.resident.len(), 2);
        assert_eq!(ledger.origins.len(), 2);
        assert!(ledger.origins.iter().all(|origin| matches!(
            origin,
            HistoryCandidateOriginAttribution::PortableBackup { .. }
        )));
    }
}
