//! Durable KeyPackage inventory for one endpoint.
//!
//! KeyPackages ride their own dedicated ledger rather than a Realm commit
//! stream, so what a client owns here is narrow: the endpoint-bound local
//! record of what it published, persisted in the host's secure store, and the
//! deficit that record implies. The maintenance thresholds themselves are the
//! SDK's, so every client replenishes on the same rule.

use arkret_models_crypto::{LocalMlsKeyPackageInventory, MlsEndpointIdentity};
use arkret_wire::{AccountId, DeviceId};
use chrono::{DateTime, Utc};
use zeroize::Zeroizing;

use crate::{
    Error, PutSecretOptions, Result, SecretClass, SecretDurability, SecureKeyStore,
    SecureKeyStoreError, account_id_storage_digest, device_storage_digest,
};

/// Low-water mark for usable single-use KeyPackages on one endpoint. A client
/// replenishes once its published inventory drops below this.
pub const KEY_PACKAGE_LOW_WATER: usize = 20;

/// Endpoint-scoped secure storage for the published KeyPackage inventory.
#[derive(Clone, Debug)]
pub struct MlsKeyPackageInventoryStore<S> {
    secure_store: S,
    namespace: String,
}

impl<S: SecureKeyStore> MlsKeyPackageInventoryStore<S> {
    pub fn new(secure_store: S, namespace: impl Into<String>) -> Self {
        Self {
            secure_store,
            namespace: namespace.into(),
        }
    }

    fn storage_key(&self, account_id: &AccountId, device_id: &DeviceId) -> Result<String> {
        let account = account_id_storage_digest(account_id).map_err(Error::from)?;
        Ok(format!(
            "{}/keypackages/{account}.{}",
            self.namespace,
            device_storage_digest(device_id)
        ))
    }

    /// Load the inventory, returning an empty one bound to this endpoint when
    /// nothing is stored yet. An inventory stored for a different endpoint is
    /// refused instead of being silently adopted.
    pub fn load(
        &self,
        account_id: &AccountId,
        device_id: &DeviceId,
    ) -> Result<LocalMlsKeyPackageInventory> {
        let expected =
            MlsEndpointIdentity::human_device(account_id.principal_id.clone(), device_id.clone());
        let key = self.storage_key(account_id, device_id)?;
        let Some(bytes) = self
            .secure_store
            .get_secret_bytes(&key)
            .map_err(Error::from)?
        else {
            return Ok(LocalMlsKeyPackageInventory {
                endpoint: expected,
                entries: std::collections::BTreeMap::new(),
            });
        };
        let inventory: LocalMlsKeyPackageInventory = serde_json::from_slice(bytes.as_slice())?;
        if inventory.endpoint != expected {
            return Err(Error::Protocol(
                "stored KeyPackage inventory belongs to another endpoint".to_owned(),
            ));
        }
        Ok(inventory)
    }

    pub async fn save(
        &self,
        account_id: &AccountId,
        device_id: &DeviceId,
        inventory: &LocalMlsKeyPackageInventory,
    ) -> Result<()> {
        let expected =
            MlsEndpointIdentity::human_device(account_id.principal_id.clone(), device_id.clone());
        if inventory.endpoint != expected {
            return Err(Error::Protocol(
                "a KeyPackage inventory may only be stored for its own endpoint".to_owned(),
            ));
        }
        let key = self.storage_key(account_id, device_id)?;
        let bytes = Zeroizing::new(serde_json::to_vec(inventory)?);
        self.secure_store
            .put_secret(
                &key,
                &bytes,
                PutSecretOptions {
                    durability: SecretDurability::DurableBeforeReturn,
                    class: SecretClass::MlsSecret,
                },
            )
            .await
            .map_err(Error::from)
    }

    pub async fn remove(&self, account_id: &AccountId, device_id: &DeviceId) -> Result<()> {
        let key = self.storage_key(account_id, device_id)?;
        match self.secure_store.delete_secret_durable(&key).await {
            Ok(()) | Err(SecureKeyStoreError::NotFound) => Ok(()),
            Err(error) => Err(Error::from(error)),
        }
    }
}

/// How many fresh single-use KeyPackages this endpoint should publish now.
pub fn key_package_deficit(
    inventory: &LocalMlsKeyPackageInventory,
    now: DateTime<Utc>,
    low_water: usize,
) -> usize {
    inventory.maintenance_deficit(now, low_water)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use arkret_models_crypto::{LocalMlsKeyPackageInventoryEntry, MlsKeyPackageState};
    use arkret_wire::{DidCoreId, Hash};
    use chrono::Duration;

    use super::*;
    use crate::test_fixtures::{at, device_id};
    use crate::{MemorySecureKeyStore, SecureKeyStoreResult};

    fn account_id() -> AccountId {
        AccountId::new(
            DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        )
    }

    fn entry(
        id: &str,
        state: MlsKeyPackageState,
        expires_at: DateTime<Utc>,
    ) -> (String, LocalMlsKeyPackageInventoryEntry) {
        (
            id.to_owned(),
            LocalMlsKeyPackageInventoryEntry {
                keypackage_id: id.to_owned(),
                keypackage_ref: Hash::new(format!("sha256:{}", "d".repeat(64))).unwrap(),
                state,
                has_private_state: true,
                created_at: at(0),
                expires_at,
                last_resort: false,
            },
        )
    }

    fn inventory(
        entries: Vec<(String, LocalMlsKeyPackageInventoryEntry)>,
    ) -> LocalMlsKeyPackageInventory {
        LocalMlsKeyPackageInventory {
            endpoint: MlsEndpointIdentity::human_device(
                account_id().principal_id.clone(),
                device_id(),
            ),
            entries: BTreeMap::from_iter(entries),
        }
    }

    #[tokio::test]
    async fn an_inventory_round_trips_through_the_secure_store() {
        let store = MlsKeyPackageInventoryStore::new(MemorySecureKeyStore::new(), "mls-test");
        let expected = inventory(vec![entry(
            "kp-1",
            MlsKeyPackageState::Published,
            at(0) + Duration::days(7),
        )]);
        store
            .save(&account_id(), &device_id(), &expected)
            .await
            .unwrap();
        assert_eq!(store.load(&account_id(), &device_id()).unwrap(), expected);
        store.remove(&account_id(), &device_id()).await.unwrap();
        assert!(
            store
                .load(&account_id(), &device_id())
                .unwrap()
                .entries
                .is_empty()
        );
    }

    #[tokio::test]
    async fn an_inventory_for_another_endpoint_is_never_stored() {
        let store = MlsKeyPackageInventoryStore::new(MemorySecureKeyStore::new(), "mls-test");
        let mut other = inventory(Vec::new());
        other.endpoint = MlsEndpointIdentity::human_device(
            DidCoreId::new("ak:did_core:web:mallory.example").unwrap(),
            device_id(),
        );
        assert!(
            store
                .save(&account_id(), &device_id(), &other)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn a_foreign_stored_inventory_is_refused_on_load() -> SecureKeyStoreResult<()> {
        let secure = MemorySecureKeyStore::new();
        let store = MlsKeyPackageInventoryStore::new(secure.clone(), "mls-test");
        let mut other = inventory(Vec::new());
        other.endpoint = MlsEndpointIdentity::human_device(
            DidCoreId::new("ak:did_core:web:mallory.example").unwrap(),
            device_id(),
        );
        let key = store.storage_key(&account_id(), &device_id()).unwrap();
        secure.store_secret_bytes(&key, &serde_json::to_vec(&other).unwrap())?;
        assert!(store.load(&account_id(), &device_id()).is_err());
        Ok(())
    }

    #[test]
    fn expired_and_consumed_packages_do_not_count_toward_the_low_water_mark() {
        let now = at(0) + Duration::days(1);
        let inventory = inventory(vec![
            entry(
                "kp-1",
                MlsKeyPackageState::Published,
                now + Duration::days(7),
            ),
            entry(
                "kp-2",
                MlsKeyPackageState::Published,
                now - Duration::days(1),
            ),
            entry(
                "kp-3",
                MlsKeyPackageState::Consumed,
                now + Duration::days(7),
            ),
        ]);
        assert_eq!(key_package_deficit(&inventory, now, 3), 2);
        assert_eq!(key_package_deficit(&inventory, now, 1), 0);
    }
}
