use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::str;
use std::sync::{Arc, Mutex, PoisonError};

use cokret_core::{Error, KeyStore};
use thiserror::Error;
use zeroize::Zeroizing;

pub type SecretBytes = Zeroizing<Vec<u8>>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecretDurability {
    CachedOk,
    DurableBeforeReturn,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecretClass {
    General,
    Seed,
    SessionCredential,
    MlsSecret,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PutSecretOptions {
    pub durability: SecretDurability,
    pub class: SecretClass,
}

impl Default for PutSecretOptions {
    fn default() -> Self {
        Self {
            durability: SecretDurability::CachedOk,
            class: SecretClass::General,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecureKeyStoreBackendInfo {
    pub name: &'static str,
    pub hardware_backed: bool,
    pub exportable: bool,
}

#[derive(Debug, Error)]
pub enum SecureKeyStoreError {
    #[error("secret not found")]
    NotFound,
    #[error("secure key store backend error: {0}")]
    Backend(String),
    #[error("secure key store backend `{0}` is not supported")]
    Unsupported(&'static str),
}

impl From<SecureKeyStoreError> for Error {
    fn from(value: SecureKeyStoreError) -> Self {
        Error::Protocol(value.to_string())
    }
}

pub type SecureKeyStoreResult<T> = Result<T, SecureKeyStoreError>;

pub trait SecureKeyStore: Send + Sync + 'static {
    fn store_secret_bytes(&self, key: &str, value: &[u8]) -> SecureKeyStoreResult<()>;

    fn store_secret_bytes_durable<'a>(
        &'a self,
        key: &'a str,
        value: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = SecureKeyStoreResult<()>> + 'a>> {
        let result = self.store_secret_bytes(key, value);
        Box::pin(async move { result })
    }

    fn put_secret<'a>(
        &'a self,
        key: &'a str,
        value: &'a [u8],
        options: PutSecretOptions,
    ) -> Pin<Box<dyn Future<Output = SecureKeyStoreResult<()>> + 'a>> {
        match options.durability {
            SecretDurability::CachedOk => {
                let result = self.store_secret_bytes(key, value);
                Box::pin(async move { result })
            }
            SecretDurability::DurableBeforeReturn => self.store_secret_bytes_durable(key, value),
        }
    }

    fn get_secret_bytes(&self, key: &str) -> SecureKeyStoreResult<Option<SecretBytes>>;
    fn delete_secret(&self, key: &str) -> SecureKeyStoreResult<()>;
    fn list_secret_keys(&self, prefix: Option<&str>) -> SecureKeyStoreResult<Vec<String>>;
    fn backend_info(&self) -> SecureKeyStoreBackendInfo;

    fn store_secret(&self, key: &str, value: &str) -> SecureKeyStoreResult<()> {
        self.store_secret_bytes(key, value.as_bytes())
    }

    fn store_secret_durable<'a>(
        &'a self,
        key: &'a str,
        value: &'a str,
    ) -> Pin<Box<dyn Future<Output = SecureKeyStoreResult<()>> + 'a>> {
        self.store_secret_bytes_durable(key, value.as_bytes())
    }

    fn get_secret(&self, key: &str) -> SecureKeyStoreResult<Option<String>> {
        self.get_secret_bytes(key)?
            .map(|bytes| {
                str::from_utf8(bytes.as_slice())
                    .map(str::to_owned)
                    .map_err(|err| SecureKeyStoreError::Backend(format!("utf8 secret: {err}")))
            })
            .transpose()
    }

    fn backend_name(&self) -> &'static str {
        self.backend_info().name
    }
}

#[derive(Clone, Debug, Default)]
pub struct MemorySecureKeyStore {
    inner: Arc<Mutex<BTreeMap<String, SecretBytes>>>,
}

impl MemorySecureKeyStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn with_map<T>(
        &self,
        f: impl FnOnce(&mut BTreeMap<String, SecretBytes>) -> T,
    ) -> SecureKeyStoreResult<T> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|err: PoisonError<_>| SecureKeyStoreError::Backend(format!("lock: {err}")))?;
        Ok(f(&mut guard))
    }
}

impl SecureKeyStore for MemorySecureKeyStore {
    fn store_secret_bytes(&self, key: &str, value: &[u8]) -> SecureKeyStoreResult<()> {
        self.with_map(|map| {
            map.insert(key.to_owned(), SecretBytes::new(value.to_vec()));
        })
    }

    fn get_secret_bytes(&self, key: &str) -> SecureKeyStoreResult<Option<SecretBytes>> {
        self.with_map(|map| map.get(key).cloned())
    }

    fn delete_secret(&self, key: &str) -> SecureKeyStoreResult<()> {
        self.with_map(|map| {
            map.remove(key);
        })
    }

    fn list_secret_keys(&self, prefix: Option<&str>) -> SecureKeyStoreResult<Vec<String>> {
        self.with_map(|map| {
            map.keys()
                .filter(|key| prefix.is_none_or(|prefix| key.starts_with(prefix)))
                .cloned()
                .collect()
        })
    }

    fn backend_info(&self) -> SecureKeyStoreBackendInfo {
        SecureKeyStoreBackendInfo {
            name: "memory",
            hardware_backed: false,
            exportable: true,
        }
    }
}

#[derive(Clone, Debug)]
pub struct SdkKeyStoreAdapter<S> {
    inner: S,
}

impl<S> SdkKeyStoreAdapter<S> {
    pub fn new(inner: S) -> Self {
        Self { inner }
    }

    pub fn inner(&self) -> &S {
        &self.inner
    }
}

impl<S> KeyStore for SdkKeyStoreAdapter<S>
where
    S: SecureKeyStore,
{
    fn load(&self, id: &str) -> cokret_core::Result<cokret_core::KeyBytes> {
        self.inner
            .get_secret_bytes(id)?
            .ok_or_else(|| SecureKeyStoreError::NotFound.into())
    }

    fn store(&self, id: &str, key: &[u8]) -> cokret_core::Result<()> {
        self.inner.store_secret_bytes(id, key).map_err(Error::from)
    }

    fn list(&self) -> cokret_core::Result<Vec<String>> {
        self.inner.list_secret_keys(None).map_err(Error::from)
    }

    fn delete(&self, id: &str) -> cokret_core::Result<()> {
        self.inner.delete_secret(id).map_err(Error::from)
    }
}

#[derive(Clone, Debug)]
pub struct SdkKeyStoreSecureAdapter<K> {
    inner: K,
}

impl<K> SdkKeyStoreSecureAdapter<K> {
    pub fn new(inner: K) -> Self {
        Self { inner }
    }

    pub fn inner(&self) -> &K {
        &self.inner
    }
}

impl<K> SecureKeyStore for SdkKeyStoreSecureAdapter<K>
where
    K: KeyStore + Send + Sync + 'static,
{
    fn store_secret_bytes(&self, key: &str, value: &[u8]) -> SecureKeyStoreResult<()> {
        self.inner
            .store(key, value)
            .map_err(|err| SecureKeyStoreError::Backend(err.to_string()))
    }

    fn get_secret_bytes(&self, key: &str) -> SecureKeyStoreResult<Option<SecretBytes>> {
        match self.inner.load(key) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(err) if err.to_string().contains("key not found") => Ok(None),
            Err(err) => Err(SecureKeyStoreError::Backend(err.to_string())),
        }
    }

    fn delete_secret(&self, key: &str) -> SecureKeyStoreResult<()> {
        self.inner
            .delete(key)
            .map_err(|err| SecureKeyStoreError::Backend(err.to_string()))
    }

    fn list_secret_keys(&self, prefix: Option<&str>) -> SecureKeyStoreResult<Vec<String>> {
        self.inner
            .list()
            .map(|keys| {
                keys.into_iter()
                    .filter(|key| prefix.is_none_or(|prefix| key.starts_with(prefix)))
                    .collect()
            })
            .map_err(|err| SecureKeyStoreError::Backend(err.to_string()))
    }

    fn backend_info(&self) -> SecureKeyStoreBackendInfo {
        SecureKeyStoreBackendInfo {
            name: "sdk_key_store",
            hardware_backed: false,
            exportable: true,
        }
    }
}
