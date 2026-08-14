//! Durable crypto store traits and an in-memory implementation.
//!
//! The SDK keeps this layer independent from OpenMLS internals. Applications can
//! serialize provider-specific MLS state into `MlsGroupStateRecord` while using
//! the typed Arkret envelopes for KeyPackages, Welcomes and Commits.

use std::collections::BTreeMap;

pub use arkret_models_crypto::{MlsCommitSource, MlsGroupStateSink};
use arkret_wire::WireError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::protocol::{
    DeviceId, DeviceVerificationState, DidCoreId, Error, MlsCommitEnvelope, MlsKeyPackageRecord,
    MlsWelcomeEnvelope, Result,
};

pub const CRYPTO_STORE_BACKUP_VERSION: &str = "arkret.crypto_store.backup.v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CryptoStoreBackupEnvelope {
    pub version: String,
    pub key_version: u64,
    pub exported_at: DateTime<Utc>,
    pub payload_json: String,
    pub payload_digest: String,
}

impl CryptoStoreBackupEnvelope {
    pub fn new(key_version: u64, payload_json: String, exported_at: DateTime<Utc>) -> Result<Self> {
        let payload_digest = crate::protocol::canonical::sha256_digest(payload_json.as_bytes());
        Ok(Self {
            version: CRYPTO_STORE_BACKUP_VERSION.to_owned(),
            key_version,
            exported_at,
            payload_json,
            payload_digest,
        })
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != CRYPTO_STORE_BACKUP_VERSION {
            return Err(Error::Protocol(
                "unsupported crypto store backup version".to_owned(),
            ));
        }
        if self.payload_digest
            != crate::protocol::canonical::sha256_digest(self.payload_json.as_bytes())
        {
            return Err(Error::Protocol(
                "crypto store backup digest mismatch".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MlsRecoveryAction {
    UseLocalState,
    ApplyCommits { from_epoch: u64, to_epoch: u64 },
    ConsumeWelcome,
    RequestEpochRecovery { missing_from_epoch: u64 },
}

/// Local processing state for an exact Welcome envelope.
///
/// Receipt, admission, and successful MLS consumption are deliberately
/// separate. Merely observing an old Welcome must never authorize a join or
/// make recovery choose it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MlsWelcomeState {
    Received,
    Accepted,
    Consumed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MlsRecoveryPlan {
    pub group_id: String,
    pub action: MlsRecoveryAction,
}

// `MlsGroupStateRecord` moved to `arkret_models_crypto::mls_records` so the MLS
// behavior layer can consume it without the SDK crypto store. Re-exported here
// to keep the `crate::MlsGroupStateRecord` path and the `crate::protocol::` surface
// stable.
pub use arkret_models_crypto::MlsGroupStateRecord;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MlsEpochSecretRecord {
    pub group_id: String,
    pub epoch: u64,
    pub secret_ref: String,
    pub encrypted_secret: Vec<u8>,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredDeviceVerification {
    pub principal_id: DidCoreId,
    pub device_id: DeviceId,
    pub state: DeviceVerificationState,
    pub updated_at: DateTime<Utc>,
}

// `put_mls_group_state` / `commits_for_group` moved to the narrow
// `arkret_models_crypto::{MlsGroupStateSink, MlsCommitSource}` ports so the MLS
// behavior layer can persist / read those records without depending on the
// umbrella crate — and so binding them here does not drag OpenMLS into ordinary
// build. `CryptoStore` re-declares them as supertraits: any `impl CryptoStore`
// still satisfies both ports, and existing `&mut impl CryptoStore` call sites
// coerce unchanged. Direct callers of the two moved methods now need the port
// trait in scope.
pub trait CryptoStore: Send + Sync + MlsGroupStateSink + MlsCommitSource {
    fn mls_group_state(&self, group_id: &str) -> Option<&MlsGroupStateRecord>;
    fn put_key_package(&mut self, record: MlsKeyPackageRecord) -> Result<()>;
    fn key_package(
        &self,
        principal_id: &DidCoreId,
        device_id: &DeviceId,
    ) -> Option<&MlsKeyPackageRecord>;
    fn key_packages_for_device(
        &self,
        principal_id: &DidCoreId,
        device_id: &DeviceId,
    ) -> Vec<&MlsKeyPackageRecord>;
    fn put_welcome(&mut self, record: MlsWelcomeEnvelope) -> Result<()>;
    fn welcomes_for_device(
        &self,
        principal_id: &DidCoreId,
        device_id: &DeviceId,
    ) -> Vec<&MlsWelcomeEnvelope>;
    fn mark_welcome_accepted(&mut self, welcome_hash: &crate::protocol::Hash) -> Result<()>;
    fn mark_welcome_consumed(&mut self, welcome_hash: &crate::protocol::Hash) -> Result<()>;
    fn welcome_state(&self, welcome_hash: &crate::protocol::Hash) -> Option<MlsWelcomeState>;
    fn put_commit(&mut self, record: MlsCommitEnvelope) -> Result<()>;
    fn put_epoch_secret(&mut self, record: MlsEpochSecretRecord) -> Result<()>;
    fn epoch_secret(&self, group_id: &str, epoch: u64) -> Option<&MlsEpochSecretRecord>;
    fn put_device_verification(&mut self, record: StoredDeviceVerification) -> Result<()>;
    fn device_verification(
        &self,
        principal_id: &DidCoreId,
        device_id: &DeviceId,
    ) -> Option<&StoredDeviceVerification>;
    fn plan_mls_recovery(
        &self,
        group_id: &str,
        local_epoch: Option<u64>,
        required_epoch: u64,
        principal_id: &DidCoreId,
        device_id: &DeviceId,
    ) -> MlsRecoveryPlan;
    fn export_backup_json(&self) -> Result<String>;
    fn import_backup_json(&mut self, backup: &str) -> Result<()>;
    fn export_backup_envelope(&self, key_version: u64) -> Result<CryptoStoreBackupEnvelope> {
        CryptoStoreBackupEnvelope::new(key_version, self.export_backup_json()?, Utc::now())
    }
    fn import_backup_envelope(&mut self, envelope: &CryptoStoreBackupEnvelope) -> Result<()> {
        envelope.validate()?;
        self.import_backup_json(&envelope.payload_json)
    }
}

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct MemoryCryptoStore {
    group_states: BTreeMap<String, MlsGroupStateRecord>,
    key_packages: BTreeMap<crate::protocol::Hash, MlsKeyPackageRecord>,
    welcomes: Vec<MlsWelcomeEnvelope>,
    welcome_states: BTreeMap<crate::protocol::Hash, MlsWelcomeState>,
    commits: BTreeMap<String, Vec<MlsCommitEnvelope>>,
    epoch_secrets: BTreeMap<(String, u64), MlsEpochSecretRecord>,
    device_verifications: BTreeMap<(DidCoreId, DeviceId), StoredDeviceVerification>,
}

// The store aggregates MLS group snapshots, key packages and sealed epoch
// secrets: Debug renders entry counts only so no secret bytes can reach logs.
impl std::fmt::Debug for MemoryCryptoStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoryCryptoStore")
            .field("group_states", &self.group_states.len())
            .field("key_packages", &self.key_packages.len())
            .field("welcomes", &self.welcomes.len())
            .field("commits", &self.commits.len())
            .field("epoch_secrets", &self.epoch_secrets.len())
            .field("device_verifications", &self.device_verifications.len())
            .finish()
    }
}

impl MemoryCryptoStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl MlsGroupStateSink for MemoryCryptoStore {
    fn put_mls_group_state(
        &mut self,
        record: MlsGroupStateRecord,
    ) -> std::result::Result<(), WireError> {
        if let Some(existing) = self.group_states.get(&record.group_id)
            && record.epoch < existing.epoch
        {
            return Err(WireError::Protocol(
                "MLS group state rollback protection rejected older epoch".to_owned(),
            ));
        }
        self.group_states.insert(record.group_id.clone(), record);
        Ok(())
    }
}

impl MlsCommitSource for MemoryCryptoStore {
    fn commits_for_group(&self, group_id: &str) -> Vec<&MlsCommitEnvelope> {
        self.commits
            .get(group_id)
            .map(|commits| commits.iter().collect())
            .unwrap_or_default()
    }
}

impl CryptoStore for MemoryCryptoStore {
    fn mls_group_state(&self, group_id: &str) -> Option<&MlsGroupStateRecord> {
        self.group_states.get(group_id)
    }

    fn put_key_package(&mut self, record: MlsKeyPackageRecord) -> Result<()> {
        let key = record.keypackage_ref.clone();
        match self.key_packages.get(&key) {
            Some(existing)
                if crate::protocol::canonical::canonical_sha256(existing)?
                    == crate::protocol::canonical::canonical_sha256(&record)? =>
            {
                Ok(())
            }
            Some(_) => Err(Error::IdempotencyConflict(
                record.keypackage_ref.to_string(),
            )),
            None => {
                self.key_packages.insert(key, record);
                Ok(())
            }
        }
    }

    fn key_package(
        &self,
        principal_id: &DidCoreId,
        device_id: &DeviceId,
    ) -> Option<&MlsKeyPackageRecord> {
        self.key_packages_for_device(principal_id, device_id)
            .into_iter()
            .find(|record| record.is_usable())
    }

    fn key_packages_for_device(
        &self,
        principal_id: &DidCoreId,
        device_id: &DeviceId,
    ) -> Vec<&MlsKeyPackageRecord> {
        self.key_packages
            .values()
            .filter(|record| {
                matches!(
                    &record.endpoint,
                    crate::protocol::MlsEndpointIdentity::HumanDevice {
                        principal_id: owner,
                        device_id: owner_device,
                    } if owner == principal_id && owner_device == device_id
                )
            })
            .collect()
    }

    fn put_welcome(&mut self, record: MlsWelcomeEnvelope) -> Result<()> {
        if record.group_id.is_empty() {
            return Err(Error::Protocol("MLS welcome group_id is empty".to_owned()));
        }
        if let Some(existing) = self.welcomes.iter().find(|welcome| {
            welcome.group_id == record.group_id
                && welcome.epoch == record.epoch
                && welcome.recipient == record.recipient
        }) {
            return if existing.welcome_hash == record.welcome_hash {
                Ok(())
            } else {
                Err(Error::IdempotencyConflict(format!(
                    "welcome:{}:{}:{}",
                    record.group_id,
                    record.epoch,
                    record.recipient.actor_id()
                )))
            };
        }
        self.welcome_states
            .insert(record.welcome_hash.clone(), MlsWelcomeState::Received);
        self.welcomes.push(record);
        Ok(())
    }

    fn welcomes_for_device(
        &self,
        principal_id: &DidCoreId,
        device_id: &DeviceId,
    ) -> Vec<&MlsWelcomeEnvelope> {
        self.welcomes
            .iter()
            .filter(|welcome| {
                matches!(
                    &welcome.recipient,
                    crate::protocol::MlsEndpointIdentity::HumanDevice {
                        principal_id: owner,
                        device_id: owner_device,
                    } if owner == principal_id && owner_device == device_id
                )
            })
            .collect()
    }

    fn mark_welcome_accepted(&mut self, welcome_hash: &crate::protocol::Hash) -> Result<()> {
        let state = self
            .welcome_states
            .get_mut(welcome_hash)
            .ok_or_else(|| Error::Protocol(format!("MLS welcome not found: {welcome_hash}")))?;
        match state {
            MlsWelcomeState::Received | MlsWelcomeState::Accepted => {
                *state = MlsWelcomeState::Accepted;
                Ok(())
            }
            MlsWelcomeState::Consumed => Ok(()),
        }
    }

    fn mark_welcome_consumed(&mut self, welcome_hash: &crate::protocol::Hash) -> Result<()> {
        let state = self
            .welcome_states
            .get_mut(welcome_hash)
            .ok_or_else(|| Error::Protocol(format!("MLS welcome not found: {welcome_hash}")))?;
        match state {
            MlsWelcomeState::Accepted | MlsWelcomeState::Consumed => {
                *state = MlsWelcomeState::Consumed;
                Ok(())
            }
            MlsWelcomeState::Received => Err(Error::Protocol(
                "MLS welcome must be accepted before consumption".to_owned(),
            )),
        }
    }

    fn welcome_state(&self, welcome_hash: &crate::protocol::Hash) -> Option<MlsWelcomeState> {
        self.welcome_states.get(welcome_hash).copied()
    }

    fn put_commit(&mut self, record: MlsCommitEnvelope) -> Result<()> {
        if record.group_id.is_empty() {
            return Err(Error::Protocol("MLS commit group_id is empty".to_owned()));
        }
        let commits = self.commits.entry(record.group_id.clone()).or_default();
        if commits
            .iter()
            .any(|commit| commit.commit_digest == record.commit_digest)
        {
            return Ok(());
        }
        if commits.iter().any(|commit| commit.epoch == record.epoch) {
            return Err(Error::IdempotencyConflict(format!(
                "commit:{}:{}",
                record.group_id, record.epoch
            )));
        }
        commits.push(record);
        Ok(())
    }

    fn put_epoch_secret(&mut self, record: MlsEpochSecretRecord) -> Result<()> {
        self.epoch_secrets
            .insert((record.group_id.clone(), record.epoch), record);
        Ok(())
    }

    fn epoch_secret(&self, group_id: &str, epoch: u64) -> Option<&MlsEpochSecretRecord> {
        self.epoch_secrets.get(&(group_id.to_owned(), epoch))
    }

    fn put_device_verification(&mut self, record: StoredDeviceVerification) -> Result<()> {
        self.device_verifications.insert(
            (record.principal_id.clone(), record.device_id.clone()),
            record,
        );
        Ok(())
    }

    fn device_verification(
        &self,
        principal_id: &DidCoreId,
        device_id: &DeviceId,
    ) -> Option<&StoredDeviceVerification> {
        self.device_verifications
            .get(&(principal_id.clone(), device_id.clone()))
    }

    fn plan_mls_recovery(
        &self,
        group_id: &str,
        local_epoch: Option<u64>,
        required_epoch: u64,
        principal_id: &DidCoreId,
        device_id: &DeviceId,
    ) -> MlsRecoveryPlan {
        let action = match local_epoch {
            Some(epoch) if epoch >= required_epoch => MlsRecoveryAction::UseLocalState,
            Some(epoch)
                if (epoch.saturating_add(1)..=required_epoch).all(|next_epoch| {
                    self.commits_for_group(group_id)
                        .iter()
                        .any(|commit| commit.epoch == next_epoch)
                }) =>
            {
                MlsRecoveryAction::ApplyCommits {
                    from_epoch: epoch.saturating_add(1),
                    to_epoch: required_epoch,
                }
            }
            _ if self
                .welcomes_for_device(principal_id, device_id)
                .into_iter()
                .any(|welcome| {
                    welcome.group_id == group_id
                        && welcome.epoch == required_epoch
                        && self.welcome_state(&welcome.welcome_hash)
                            == Some(MlsWelcomeState::Accepted)
                }) =>
            {
                MlsRecoveryAction::ConsumeWelcome
            }
            Some(epoch) => MlsRecoveryAction::RequestEpochRecovery {
                missing_from_epoch: epoch.saturating_add(1),
            },
            None => MlsRecoveryAction::RequestEpochRecovery {
                missing_from_epoch: required_epoch,
            },
        };
        MlsRecoveryPlan {
            group_id: group_id.to_owned(),
            action,
        }
    }

    fn export_backup_json(&self) -> Result<String> {
        serde_json::to_string(self).map_err(Into::into)
    }

    fn import_backup_json(&mut self, backup: &str) -> Result<()> {
        *self = serde_json::from_str(backup)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::Hash;

    fn did(name: &str) -> DidCoreId {
        DidCoreId::new(format!("ak:did_core:webvh:z6mkfixture:{name}.example")).unwrap()
    }

    fn device(id: &str) -> DeviceId {
        let mut acc = 0xcbf29ce484222325u64;
        for byte in id.bytes() {
            acc = (acc ^ u64::from(byte)).wrapping_mul(0x100000001b3);
        }
        DeviceId::new(format!(
            "ak:device:01904100-0000-7000-8000-{:012x}",
            acc & 0x0000_ffff_ffff_ffff
        ))
        .unwrap()
    }

    #[test]
    fn memory_crypto_store_roundtrips_mls_records_and_verification() {
        let alice = did("alice");
        let device_id = device("phone");
        let mut store = MemoryCryptoStore::new();

        store
            .put_mls_group_state(MlsGroupStateRecord {
                group_id: "group1".to_owned(),
                principal_id: alice.clone(),
                device_id: device_id.clone(),
                epoch: 3,
                serialized_state: b"state".to_vec(),
                updated_at: Utc::now(),
            })
            .unwrap();
        assert_eq!(store.mls_group_state("group1").unwrap().epoch, 3);

        store
            .put_key_package(MlsKeyPackageRecord {
                keypackage_id: format!("ak:mls:kp:{}", uuid::Uuid::now_v7()),
                endpoint: crate::protocol::MlsEndpointIdentity::human_device(
                    alice.clone(),
                    device_id.clone(),
                ),
                keypackage: "kp".to_owned(),
                keypackage_ref: Hash::new(
                    "sha256:1111111111111111111111111111111111111111111111111111111111111111",
                )
                .unwrap(),
                cipher_suites: vec!["suite".to_owned()],
                capabilities: Vec::new(),
                state: crate::protocol::MlsKeyPackageState::Published,
                claim_id: None,
                created_at: Utc::now(),
                expires_at: None,
                device_signature: None,
                last_resort: false,
            })
            .unwrap();
        assert!(store.key_package(&alice, &device_id).is_some());

        store
            .put_device_verification(StoredDeviceVerification {
                principal_id: alice.clone(),
                device_id: device_id.clone(),
                state: DeviceVerificationState::Verified,
                updated_at: Utc::now(),
            })
            .unwrap();
        assert_eq!(
            store.device_verification(&alice, &device_id).unwrap().state,
            DeviceVerificationState::Verified
        );
    }

    #[test]
    fn crypto_store_rejects_group_state_rollback() {
        let alice = did("alice");
        let device_id = device("phone");
        let mut store = MemoryCryptoStore::new();
        store
            .put_mls_group_state(MlsGroupStateRecord {
                group_id: "group1".to_owned(),
                principal_id: alice.clone(),
                device_id: device_id.clone(),
                epoch: 5,
                serialized_state: b"newer".to_vec(),
                updated_at: Utc::now(),
            })
            .unwrap();
        assert!(
            store
                .put_mls_group_state(MlsGroupStateRecord {
                    group_id: "group1".to_owned(),
                    principal_id: alice,
                    device_id,
                    epoch: 4,
                    serialized_state: b"older".to_vec(),
                    updated_at: Utc::now(),
                })
                .is_err()
        );
        assert_eq!(store.mls_group_state("group1").unwrap().epoch, 5);
    }

    #[test]
    fn memory_crypto_store_plans_recovery_and_restores_backup() {
        let alice = did("alice");
        let device_id = device("phone");
        let mut store = MemoryCryptoStore::new();
        store
            .put_welcome(MlsWelcomeEnvelope {
                group_id: "group1".to_owned(),
                epoch: 1,
                recipient: crate::protocol::MlsEndpointIdentity::human_device(
                    alice.clone(),
                    device_id.clone(),
                ),
                welcome: "welcome".to_owned(),
                welcome_hash: Hash::new(
                    "sha256:2222222222222222222222222222222222222222222222222222222222222222",
                )
                .unwrap(),
                ratchet_tree: None,
            })
            .unwrap();

        let welcome_hash = store.welcomes_for_device(&alice, &device_id)[0]
            .welcome_hash
            .clone();
        let before_acceptance = store.plan_mls_recovery("group1", None, 1, &alice, &device_id);
        assert!(matches!(
            before_acceptance.action,
            MlsRecoveryAction::RequestEpochRecovery { .. }
        ));
        store.mark_welcome_accepted(&welcome_hash).unwrap();

        let plan = store.plan_mls_recovery("group1", None, 1, &alice, &device_id);
        assert!(matches!(plan.action, MlsRecoveryAction::ConsumeWelcome));

        let backup = store.export_backup_json().unwrap();
        let mut restored = MemoryCryptoStore::new();
        restored.import_backup_json(&backup).unwrap();
        assert_eq!(restored.welcomes_for_device(&alice, &device_id).len(), 1);
    }

    #[test]
    fn memory_crypto_store_deduplicates_welcomes_and_commits() {
        let alice = did("alice");
        let device_id = device("phone");
        let mut store = MemoryCryptoStore::new();
        let welcome = MlsWelcomeEnvelope {
            group_id: "group1".to_owned(),
            epoch: 1,
            recipient: crate::protocol::MlsEndpointIdentity::human_device(
                alice.clone(),
                device_id.clone(),
            ),
            welcome: "welcome".to_owned(),
            welcome_hash: Hash::new(
                "sha256:2222222222222222222222222222222222222222222222222222222222222222",
            )
            .unwrap(),
            ratchet_tree: None,
        };

        store.put_welcome(welcome.clone()).unwrap();
        store.put_welcome(welcome.clone()).unwrap();
        assert_eq!(store.welcomes_for_device(&alice, &device_id).len(), 1);
        assert!(store.mark_welcome_consumed(&welcome.welcome_hash).is_err());
        store.mark_welcome_accepted(&welcome.welcome_hash).unwrap();
        store.mark_welcome_consumed(&welcome.welcome_hash).unwrap();
        store.mark_welcome_consumed(&welcome.welcome_hash).unwrap();
        assert_eq!(
            store.welcome_state(&welcome.welcome_hash),
            Some(MlsWelcomeState::Consumed)
        );

        let mut conflicting_welcome = welcome;
        conflicting_welcome.welcome_hash =
            Hash::new("sha256:3333333333333333333333333333333333333333333333333333333333333333")
                .unwrap();
        assert!(matches!(
            store.put_welcome(conflicting_welcome),
            Err(Error::IdempotencyConflict(_))
        ));

        let commit = MlsCommitEnvelope {
            group_id: "group1".to_owned(),
            epoch: 2,
            commit: "commit".to_owned(),
            commit_digest: Hash::new(
                "sha256:4444444444444444444444444444444444444444444444444444444444444444",
            )
            .unwrap(),
            ratchet_tree: None,
        };
        store.put_commit(commit.clone()).unwrap();
        store.put_commit(commit.clone()).unwrap();
        assert_eq!(store.commits_for_group("group1").len(), 1);

        let mut conflicting_commit = commit;
        conflicting_commit.commit_digest =
            Hash::new("sha256:5555555555555555555555555555555555555555555555555555555555555555")
                .unwrap();
        assert!(matches!(
            store.put_commit(conflicting_commit),
            Err(Error::IdempotencyConflict(_))
        ));
    }
}
