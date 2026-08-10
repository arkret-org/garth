use crate::crypto_state_store::{
    CryptoStore, CryptoStoreBackupEnvelope, MemoryCryptoStore, MlsCommitSource,
    MlsEpochSecretRecord, MlsGroupStateRecord, MlsGroupStateSink, MlsRecoveryPlan, MlsWelcomeState,
    StoredDeviceVerification,
};
use crate::protocol::{
    DeviceId, DidCoreId, Hash, MlsCommitEnvelope, MlsKeyPackageRecord, MlsWelcomeEnvelope, Result,
};
use arkret_wire::WireError;
use zeroize::Zeroizing;

use super::{PutSecretOptions, SecretClass, SecretDurability, SecureKeyStore};

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
        if let Some(encoded) = secure_store.get_secret_bytes(&storage_key)? {
            let envelope =
                serde_json::from_slice::<CryptoStoreBackupEnvelope>(&encoded).map_err(|error| {
                    crate::protocol::Error::Protocol(format!("decode MLS backup: {error}"))
                })?;
            inner.import_backup_envelope(&envelope)?;
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
        let envelope = self.inner.export_backup_envelope(1)?;
        let encoded = Zeroizing::new(serde_json::to_vec(&envelope).map_err(|error| {
            crate::protocol::Error::Protocol(format!("encode MLS backup envelope: {error}"))
        })?);
        self.secure_store.put_secret_sync(
            &self.storage_key,
            &encoded,
            PutSecretOptions {
                durability: SecretDurability::DurableBeforeReturn,
                class: SecretClass::MlsSecret,
            },
        )?;
        Ok(())
    }
}

// The SDK `CryptoStore` trait is unconditionally `Send + Sync`, so this bridge
// must require its wrapped `SecureKeyStore` to actually be `Send + Sync` (on
// native this is implied by `SecureKeyStore`; on wasm the relaxed store trait no
// longer implies it, and a `!Send` store cannot back an SDK crypto store).
impl<S> MlsGroupStateSink for SecureCryptoStoreAdapter<S>
where
    S: SecureKeyStore + Send + Sync,
{
    fn put_mls_group_state(
        &mut self,
        record: MlsGroupStateRecord,
    ) -> std::result::Result<(), WireError> {
        self.inner.put_mls_group_state(record)?;
        self.persist()
            .map_err(|error| WireError::Protocol(error.to_string()))
    }
}

impl<S> MlsCommitSource for SecureCryptoStoreAdapter<S>
where
    S: SecureKeyStore + Send + Sync,
{
    fn commits_for_group(&self, group_id: &str) -> Vec<&MlsCommitEnvelope> {
        self.inner.commits_for_group(group_id)
    }
}

impl<S> CryptoStore for SecureCryptoStoreAdapter<S>
where
    S: SecureKeyStore + Send + Sync,
{
    fn mls_group_state(&self, group_id: &str) -> Option<&MlsGroupStateRecord> {
        self.inner.mls_group_state(group_id)
    }

    fn put_key_package(&mut self, record: MlsKeyPackageRecord) -> Result<()> {
        self.inner.put_key_package(record)?;
        self.persist()
    }

    fn key_package(
        &self,
        principal_id: &DidCoreId,
        device_id: &DeviceId,
    ) -> Option<&MlsKeyPackageRecord> {
        self.inner.key_package(principal_id, device_id)
    }

    fn key_packages_for_device(
        &self,
        principal_id: &DidCoreId,
        device_id: &DeviceId,
    ) -> Vec<&MlsKeyPackageRecord> {
        self.inner.key_packages_for_device(principal_id, device_id)
    }

    fn put_welcome(&mut self, record: MlsWelcomeEnvelope) -> Result<()> {
        self.inner.put_welcome(record)?;
        self.persist()
    }

    fn welcomes_for_device(
        &self,
        principal_id: &DidCoreId,
        device_id: &DeviceId,
    ) -> Vec<&MlsWelcomeEnvelope> {
        self.inner.welcomes_for_device(principal_id, device_id)
    }

    fn mark_welcome_accepted(&mut self, welcome_hash: &Hash) -> Result<()> {
        self.inner.mark_welcome_accepted(welcome_hash)?;
        self.persist()
    }

    fn mark_welcome_consumed(&mut self, welcome_hash: &Hash) -> Result<()> {
        self.inner.mark_welcome_consumed(welcome_hash)?;
        self.persist()
    }

    fn welcome_state(&self, welcome_hash: &Hash) -> Option<MlsWelcomeState> {
        self.inner.welcome_state(welcome_hash)
    }

    fn put_commit(&mut self, record: MlsCommitEnvelope) -> Result<()> {
        self.inner.put_commit(record)?;
        self.persist()
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
        principal_id: &DidCoreId,
        device_id: &DeviceId,
    ) -> Option<&StoredDeviceVerification> {
        self.inner.device_verification(principal_id, device_id)
    }

    fn plan_mls_recovery(
        &self,
        group_id: &str,
        local_epoch: Option<u64>,
        required_epoch: u64,
        principal_id: &DidCoreId,
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
    fn persists_validated_backup_envelope_to_secure_store() {
        let secure = MemorySecureKeyStore::new();
        let source = MemoryCryptoStore::new();
        let backup = source.export_backup_json().unwrap();
        let mut adapter = SecureCryptoStoreAdapter::memory(secure.clone(), "mls.crypto");

        adapter.import_backup_json(&backup).unwrap();

        let encoded = secure
            .get_secret_bytes("mls.crypto")
            .unwrap()
            .expect("backup persisted");
        let envelope: CryptoStoreBackupEnvelope = serde_json::from_slice(&encoded).unwrap();
        envelope.validate().unwrap();
        let restored = SecureCryptoStoreAdapter::new(secure, "mls.crypto").unwrap();
        assert_eq!(restored.export_backup_json().unwrap(), backup);
    }
}
