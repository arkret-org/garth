use cokret::{
    CryptoStore, CryptoStoreBackupEnvelope, MemoryCryptoStore, MlsEpochSecretRecord,
    MlsGroupStateRecord, MlsRecoveryPlan, StoredDeviceVerification,
};
use cokret_core::{
    DeviceId, Did, MlsCommitEnvelope, MlsKeyPackageRecord, MlsWelcomeEnvelope, Result,
};

use super::SecureKeyStore;

#[derive(Clone, Debug)]
pub struct SecureCryptoStoreAdapter<S> {
    inner: MemoryCryptoStore,
    secure_store: S,
    storage_key: String,
}

impl<S> SecureCryptoStoreAdapter<S>
where
    S: SecureKeyStore,
{
    pub fn new(secure_store: S, storage_key: impl Into<String>) -> Result<Self> {
        let storage_key = storage_key.into();
        let mut inner = MemoryCryptoStore::new();
        if let Some(backup_json) = secure_store.get_secret(&storage_key)? {
            inner.import_backup_json(&backup_json)?;
        }
        Ok(Self {
            inner,
            secure_store,
            storage_key,
        })
    }

    pub fn memory(secure_store: S, storage_key: impl Into<String>) -> Self {
        Self {
            inner: MemoryCryptoStore::new(),
            secure_store,
            storage_key: storage_key.into(),
        }
    }

    pub fn inner(&self) -> &MemoryCryptoStore {
        &self.inner
    }

    fn persist(&self) -> Result<()> {
        let backup_json = self.inner.export_backup_json()?;
        self.secure_store
            .store_secret_bytes(&self.storage_key, backup_json.as_bytes())?;
        Ok(())
    }
}

impl<S> CryptoStore for SecureCryptoStoreAdapter<S>
where
    S: SecureKeyStore,
{
    fn put_mls_group_state(&mut self, record: MlsGroupStateRecord) -> Result<()> {
        self.inner.put_mls_group_state(record)?;
        self.persist()
    }

    fn mls_group_state(&self, group_id: &str) -> Option<&MlsGroupStateRecord> {
        self.inner.mls_group_state(group_id)
    }

    fn put_key_package(&mut self, record: MlsKeyPackageRecord) -> Result<()> {
        self.inner.put_key_package(record)?;
        self.persist()
    }

    fn key_package(
        &self,
        principal_id: &Did,
        device_id: &DeviceId,
    ) -> Option<&MlsKeyPackageRecord> {
        self.inner.key_package(principal_id, device_id)
    }

    fn put_welcome(&mut self, record: MlsWelcomeEnvelope) -> Result<()> {
        self.inner.put_welcome(record)?;
        self.persist()
    }

    fn welcomes_for_device(
        &self,
        principal_id: &Did,
        device_id: &DeviceId,
    ) -> Vec<&MlsWelcomeEnvelope> {
        self.inner.welcomes_for_device(principal_id, device_id)
    }

    fn put_commit(&mut self, record: MlsCommitEnvelope) -> Result<()> {
        self.inner.put_commit(record)?;
        self.persist()
    }

    fn commits_for_group(&self, group_id: &str) -> Vec<&MlsCommitEnvelope> {
        self.inner.commits_for_group(group_id)
    }

    fn put_epoch_secret(&mut self, record: MlsEpochSecretRecord) -> Result<()> {
        self.inner.put_epoch_secret(record)?;
        self.persist()
    }

    fn epoch_secret(&self, group_id: &str, epoch: u64) -> Option<&MlsEpochSecretRecord> {
        self.inner.epoch_secret(group_id, epoch)
    }

    fn put_device_verification(&mut self, record: StoredDeviceVerification) -> Result<()> {
        self.inner.put_device_verification(record)?;
        self.persist()
    }

    fn device_verification(
        &self,
        principal_id: &Did,
        device_id: &DeviceId,
    ) -> Option<&StoredDeviceVerification> {
        self.inner.device_verification(principal_id, device_id)
    }

    fn plan_mls_recovery(
        &self,
        group_id: &str,
        local_epoch: Option<u64>,
        required_epoch: u64,
        principal_id: &Did,
        device_id: &DeviceId,
    ) -> MlsRecoveryPlan {
        self.inner.plan_mls_recovery(
            group_id,
            local_epoch,
            required_epoch,
            principal_id,
            device_id,
        )
    }

    fn export_backup_json(&self) -> Result<String> {
        self.inner.export_backup_json()
    }

    fn import_backup_json(&mut self, backup: &str) -> Result<()> {
        self.inner.import_backup_json(backup)?;
        self.persist()
    }

    fn export_backup_envelope(&self, key_version: u64) -> Result<CryptoStoreBackupEnvelope> {
        self.inner.export_backup_envelope(key_version)
    }

    fn import_backup_envelope(&mut self, envelope: &CryptoStoreBackupEnvelope) -> Result<()> {
        self.inner.import_backup_envelope(envelope)?;
        self.persist()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MemorySecureKeyStore, SecureKeyStore};

    #[test]
    fn persists_imported_backup_json_to_secure_store() {
        let secure = MemorySecureKeyStore::new();
        let source = MemoryCryptoStore::new();
        let backup = source.export_backup_json().unwrap();
        let mut adapter = SecureCryptoStoreAdapter::memory(secure.clone(), "mls.crypto");

        adapter.import_backup_json(&backup).unwrap();

        assert_eq!(
            secure.get_secret("mls.crypto").unwrap().as_deref(),
            Some(backup.as_str())
        );
        let restored = SecureCryptoStoreAdapter::new(secure, "mls.crypto").unwrap();
        assert_eq!(restored.export_backup_json().unwrap(), backup);
    }
}
