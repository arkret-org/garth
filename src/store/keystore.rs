use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::str;
use std::sync::{Arc, Mutex, PoisonError};

use arkret_core::{Error, KeyStore, KeyStoreError};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::MaybeSendSync;

pub type SecretBytes = Zeroizing<Vec<u8>>;

/// Durability expectation a caller attaches to a secret write.
///
/// NOTE: this is an *advisory* value consumed by concrete [`SecureKeyStore`]
/// implementations. The blanket default implementation of
/// [`SecureKeyStore::store_secret_bytes_durable`] does NOT perform any
/// flush/fsync/commit — it merely wraps the synchronous write — so
/// [`SecretDurability::DurableBeforeReturn`] behaves identically to
/// [`SecretDurability::CachedOk`] unless the host backend overrides
/// `store_secret_bytes_durable` to provide real crash durability. Hosts that
/// need "persisted before return" guarantees for critical keys MUST override it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecretDurability {
    CachedOk,
    DurableBeforeReturn,
}

/// Sensitivity class a caller attaches to a secret so a capable host backend can
/// route high-value material (seeds, MLS secrets) to stronger storage
/// (hardware-backed / non-exportable).
///
/// NOTE: this is an *advisory hint* only. The blanket [`SecureKeyStore`]
/// implementation of [`SecureKeyStore::put_secret`] branches solely on
/// [`SecretDurability`] and IGNORES `class`; [`MemorySecureKeyStore`] and
/// [`SdkKeyStoreSecureAdapter`] likewise store every class identically. A host
/// that hands a [`SecretClass::Seed`]/[`SecretClass::MlsSecret`] to a store
/// without a hardware backend gets NO extra protection from this crate — it is
/// the host backend's responsibility to act on `class` (e.g. by implementing
/// `put_secret`). Do not rely on `class` alone for tiered hardening.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecretClass {
    General,
    Seed,
    SessionCredential,
    MlsSecret,
}

/// Options for a secret write. Both fields are advisory hints for the concrete
/// [`SecureKeyStore`] backend — see [`SecretDurability`] and [`SecretClass`] for
/// the exact (non-)guarantees provided by the blanket/default implementations.
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

pub trait SecureKeyStore: MaybeSendSync + 'static {
    fn store_secret_bytes(&self, key: &str, value: &[u8]) -> SecureKeyStoreResult<()>;

    /// Persist a secret with crash durability.
    ///
    /// The default implementation provides NO real durability: it simply wraps
    /// the synchronous [`Self::store_secret_bytes`] result in a ready future
    /// with no flush/fsync/commit. Hosts that genuinely need "persisted before
    /// return" (e.g. for recovery seeds) MUST override this to talk to a durable
    /// backend; otherwise `DurableBeforeReturn` is indistinguishable from
    /// `CachedOk`.
    fn store_secret_bytes_durable<'a>(
        &'a self,
        key: &'a str,
        value: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = SecureKeyStoreResult<()>> + 'a>> {
        let result = self.store_secret_bytes(key, value);
        Box::pin(async move { result })
    }

    /// Write a secret honoring [`PutSecretOptions`].
    ///
    /// The default implementation branches only on
    /// [`PutSecretOptions::durability`] and IGNORES
    /// [`PutSecretOptions::class`] — the class is an advisory hint that only a
    /// capability-aware host backend can act on. Override this method to apply
    /// class-based hardening (e.g. route [`SecretClass::Seed`] to a hardware
    /// backend). See [`SecretClass`] / [`SecretDurability`] for the full caveat.
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

    /// Total entries currently held — only useful for diagnostics / tests.
    /// Production code should never iterate the store contents.
    pub fn len(&self) -> usize {
        self.inner.lock().map(|guard| guard.len()).unwrap_or(0)
    }

    /// True when no secrets are stored.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
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

// The SDK `KeyStore` trait is unconditionally `Send + Sync`, so this bridge must
// require its wrapped `SecureKeyStore` to actually be `Send + Sync` (implied on
// native; a real constraint on wasm where `SecureKeyStore` no longer forces it).
impl<S> KeyStore for SdkKeyStoreAdapter<S>
where
    S: SecureKeyStore + Send + Sync,
{
    fn load(&self, id: &str) -> arkret_core::Result<arkret_core::KeyBytes> {
        let bytes = self.inner.get_secret_bytes(id).map_err(|err| match err {
            SecureKeyStoreError::NotFound => Error::from(KeyStoreError::not_found(id)),
            other => Error::from(other),
        })?;
        bytes.ok_or_else(|| KeyStoreError::not_found(id).into())
    }

    fn store(&self, id: &str, key: &[u8]) -> arkret_core::Result<()> {
        self.inner.store_secret_bytes(id, key).map_err(Error::from)
    }

    fn list(&self) -> arkret_core::Result<Vec<String>> {
        self.inner.list_secret_keys(None).map_err(Error::from)
    }

    fn delete(&self, id: &str) -> arkret_core::Result<()> {
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
            Err(err) if err.is_key_store_not_found() => Ok(None),
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

    // The wrapped `KeyStore` trait exposes no capability query, so these flags
    // are a deliberately CONSERVATIVE placeholder rather than a reflection of the
    // real backend: `hardware_backed: false` / `exportable: true` describe the
    // worst case. A host that needs accurate capability routing (e.g. to detect
    // a hardware backend behind the `KeyStore`) should implement `SecureKeyStore`
    // directly instead of relying on this adapter's reported info.
    fn backend_info(&self) -> SecureKeyStoreBackendInfo {
        SecureKeyStoreBackendInfo {
            name: "sdk_key_store",
            hardware_backed: false,
            exportable: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Debug)]
    struct MissingKeyStore;

    impl KeyStore for MissingKeyStore {
        fn load(&self, id: &str) -> arkret_core::Result<arkret_core::KeyBytes> {
            Err(KeyStoreError::not_found(id).into())
        }

        fn store(&self, _id: &str, _key: &[u8]) -> arkret_core::Result<()> {
            Ok(())
        }

        fn list(&self) -> arkret_core::Result<Vec<String>> {
            Ok(Vec::new())
        }

        fn delete(&self, _id: &str) -> arkret_core::Result<()> {
            Ok(())
        }
    }

    #[derive(Clone, Debug)]
    struct BackendTextKeyStore;

    impl KeyStore for BackendTextKeyStore {
        fn load(&self, _id: &str) -> arkret_core::Result<arkret_core::KeyBytes> {
            Err(Error::Protocol(
                "backend text mentions key not found but is not typed".to_owned(),
            ))
        }

        fn store(&self, _id: &str, _key: &[u8]) -> arkret_core::Result<()> {
            Ok(())
        }

        fn list(&self) -> arkret_core::Result<Vec<String>> {
            Ok(Vec::new())
        }

        fn delete(&self, _id: &str) -> arkret_core::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn secure_adapter_maps_typed_key_store_not_found_to_none() {
        let adapter = SdkKeyStoreSecureAdapter::new(MissingKeyStore);
        let value = adapter.get_secret_bytes("missing").unwrap();
        assert!(value.is_none());
    }

    #[test]
    fn secure_adapter_does_not_classify_backend_text_as_not_found() {
        let adapter = SdkKeyStoreSecureAdapter::new(BackendTextKeyStore);
        let err = adapter.get_secret_bytes("missing").unwrap_err();
        assert!(matches!(err, SecureKeyStoreError::Backend(_)));
    }

    #[test]
    fn key_store_adapter_preserves_secure_store_not_found_as_typed_sdk_error() {
        let adapter = SdkKeyStoreAdapter::new(MemorySecureKeyStore::new());
        let err = adapter.load("missing").unwrap_err();
        assert!(err.is_key_store_not_found());
    }
}
