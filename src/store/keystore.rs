use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::str;
use std::sync::{Arc, Mutex, PoisonError};

use arkret_keystore::{KeyBytes, KeyStore, KeyStoreError};
use thiserror::Error;

use crate::{Error as GarthError, MaybeSendSync};

/// Character-safe storage namespace for an account authority pair.
///
/// Secret-store keys are flat strings, so the authority pair has to collapse
/// into one path-safe component. Canonicalizing the `AccountId` first means the
/// namespace is stable across serialization order, and hashing it keeps the
/// user's DID out of the raw key material a host backend may log or index.
pub fn account_id_storage_digest(
    authority: &arkret_wire::AccountId,
) -> Result<String, SecureKeyStoreError> {
    authority
        .validate()
        .map_err(|error| SecureKeyStoreError::Backend(format!("invalid AccountId: {error}")))?;
    let canonical = arkret_canonical::canonical_json_bytes(authority).map_err(|error| {
        SecureKeyStoreError::Backend(format!("canonicalize AccountId storage namespace: {error}"))
    })?;
    Ok(arkret_canonical::sha256_base64url(canonical))
}

/// Character-safe storage suffix for a device coordinate below an authority.
pub fn device_storage_digest(device_id: &arkret_wire::DeviceId) -> String {
    arkret_canonical::sha256_base64url(device_id.as_str().as_bytes())
}

#[cfg(not(target_arch = "wasm32"))]
type BoxSecureStoreFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
#[cfg(target_arch = "wasm32")]
type BoxSecureStoreFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

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

impl From<SecureKeyStoreError> for GarthError {
    fn from(value: SecureKeyStoreError) -> Self {
        GarthError::Protocol(value.to_string())
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
    ) -> BoxSecureStoreFuture<'a, SecureKeyStoreResult<()>> {
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
    ) -> BoxSecureStoreFuture<'a, SecureKeyStoreResult<()>> {
        match options.durability {
            SecretDurability::CachedOk => {
                let result = self.store_secret_bytes(key, value);
                Box::pin(async move { result })
            }
            SecretDurability::DurableBeforeReturn => self.store_secret_bytes_durable(key, value),
        }
    }

    fn get_secret_bytes(&self, key: &str) -> SecureKeyStoreResult<Option<KeyBytes>>;

    /// Read the committed backend value rather than an instance-local cache.
    /// Backends without this capability must fail instead of emulating a read.
    fn read_secret_bytes_durable<'a>(
        &'a self,
        _key: &'a str,
    ) -> BoxSecureStoreFuture<'a, SecureKeyStoreResult<Option<KeyBytes>>> {
        Box::pin(async { Err(SecureKeyStoreError::Unsupported("committed secret read")) })
    }

    /// Compare and replace under one backend transaction shared by all handles.
    /// `None` expects an absent entry. `false` leaves the winner unchanged.
    /// Success resolves only after durable commit; a process mutex is insufficient.
    fn compare_exchange_secret_bytes_durable<'a>(
        &'a self,
        _key: &'a str,
        _expected: Option<&'a [u8]>,
        _replacement: &'a [u8],
    ) -> BoxSecureStoreFuture<'a, SecureKeyStoreResult<bool>> {
        Box::pin(async {
            Err(SecureKeyStoreError::Unsupported(
                "atomic secret compare exchange",
            ))
        })
    }

    fn delete_secret(&self, key: &str) -> SecureKeyStoreResult<()>;
    /// Wait for removal from persistent storage. Async backends must override
    /// this; synchronous keyrings and in-memory stores complete immediately.
    fn delete_secret_durable<'a>(
        &'a self,
        key: &'a str,
    ) -> BoxSecureStoreFuture<'a, SecureKeyStoreResult<()>> {
        let result = self.delete_secret(key);
        Box::pin(async move { result })
    }
    fn list_secret_keys(&self, prefix: Option<&str>) -> SecureKeyStoreResult<Vec<String>>;
    fn backend_info(&self) -> SecureKeyStoreBackendInfo;

    fn store_secret(&self, key: &str, value: &str) -> SecureKeyStoreResult<()> {
        self.store_secret_bytes(key, value.as_bytes())
    }

    fn store_secret_durable<'a>(
        &'a self,
        key: &'a str,
        value: &'a str,
    ) -> BoxSecureStoreFuture<'a, SecureKeyStoreResult<()>> {
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
    inner: Arc<Mutex<BTreeMap<String, KeyBytes>>>,
}

impl MemorySecureKeyStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn with_map<T>(
        &self,
        f: impl FnOnce(&mut BTreeMap<String, KeyBytes>) -> T,
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
            map.insert(key.to_owned(), KeyBytes::new(value.to_vec()));
        })
    }

    fn get_secret_bytes(&self, key: &str) -> SecureKeyStoreResult<Option<KeyBytes>> {
        self.with_map(|map| map.get(key).cloned())
    }

    fn read_secret_bytes_durable<'a>(
        &'a self,
        key: &'a str,
    ) -> BoxSecureStoreFuture<'a, SecureKeyStoreResult<Option<KeyBytes>>> {
        Box::pin(async move { self.get_secret_bytes(key) })
    }

    fn compare_exchange_secret_bytes_durable<'a>(
        &'a self,
        key: &'a str,
        expected: Option<&'a [u8]>,
        replacement: &'a [u8],
    ) -> BoxSecureStoreFuture<'a, SecureKeyStoreResult<bool>> {
        Box::pin(async move {
            self.with_map(|map| {
                if map.get(key).map(KeyBytes::as_slice) != expected {
                    return false;
                }
                map.insert(key.to_owned(), KeyBytes::new(replacement.to_vec()));
                true
            })
        })
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
    fn load(&self, id: &str) -> Result<KeyBytes, KeyStoreError> {
        let bytes = self.inner.get_secret_bytes(id).map_err(|err| match err {
            SecureKeyStoreError::NotFound => KeyStoreError::not_found(id),
            other => KeyStoreError::backend(other.to_string()),
        })?;
        bytes.ok_or_else(|| KeyStoreError::not_found(id))
    }

    fn store(&self, id: &str, key: &[u8]) -> Result<(), KeyStoreError> {
        self.inner
            .store_secret_bytes(id, key)
            .map_err(|err| KeyStoreError::backend(err.to_string()))
    }

    fn list(&self) -> Result<Vec<String>, KeyStoreError> {
        self.inner
            .list_secret_keys(None)
            .map_err(|err| KeyStoreError::backend(err.to_string()))
    }

    fn delete(&self, id: &str) -> Result<(), KeyStoreError> {
        self.inner
            .delete_secret(id)
            .map_err(|err| KeyStoreError::backend(err.to_string()))
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

    fn get_secret_bytes(&self, key: &str) -> SecureKeyStoreResult<Option<KeyBytes>> {
        match self.inner.load(key) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(err) if err.is_not_found() => Ok(None),
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

    #[tokio::test]
    async fn unsupported_backends_cannot_emulate_atomic_secret_updates() {
        let store = SdkKeyStoreSecureAdapter::new(MissingKeyStore);
        assert!(matches!(
            store.read_secret_bytes_durable("queue").await,
            Err(SecureKeyStoreError::Unsupported(_))
        ));
        assert!(matches!(
            store
                .compare_exchange_secret_bytes_durable("queue", None, b"first")
                .await,
            Err(SecureKeyStoreError::Unsupported(_))
        ));
    }

    #[tokio::test]
    async fn secret_compare_exchange_preserves_the_winner_across_handles() {
        let first = MemorySecureKeyStore::new();
        let second = first.clone();
        assert!(
            first
                .compare_exchange_secret_bytes_durable("queue", None, b"first")
                .await
                .unwrap()
        );
        assert!(
            !second
                .compare_exchange_secret_bytes_durable("queue", None, b"stale")
                .await
                .unwrap()
        );
        assert!(
            !second
                .compare_exchange_secret_bytes_durable("queue", Some(b"wrong"), b"stale")
                .await
                .unwrap()
        );
        assert_eq!(
            second
                .read_secret_bytes_durable("queue")
                .await
                .unwrap()
                .unwrap()
                .as_slice(),
            b"first"
        );
        assert!(
            second
                .compare_exchange_secret_bytes_durable("queue", Some(b"first"), b"next")
                .await
                .unwrap()
        );
    }

    #[derive(Clone, Debug)]
    struct MissingKeyStore;

    impl KeyStore for MissingKeyStore {
        fn load(&self, id: &str) -> Result<KeyBytes, KeyStoreError> {
            Err(KeyStoreError::not_found(id))
        }

        fn store(&self, _id: &str, _key: &[u8]) -> Result<(), KeyStoreError> {
            Ok(())
        }

        fn list(&self) -> Result<Vec<String>, KeyStoreError> {
            Ok(Vec::new())
        }

        fn delete(&self, _id: &str) -> Result<(), KeyStoreError> {
            Ok(())
        }
    }

    #[derive(Clone, Debug)]
    struct BackendTextKeyStore;

    impl KeyStore for BackendTextKeyStore {
        fn load(&self, _id: &str) -> Result<KeyBytes, KeyStoreError> {
            Err(KeyStoreError::backend(
                "backend text mentions key not found but is not typed",
            ))
        }

        fn store(&self, _id: &str, _key: &[u8]) -> Result<(), KeyStoreError> {
            Ok(())
        }

        fn list(&self) -> Result<Vec<String>, KeyStoreError> {
            Ok(Vec::new())
        }

        fn delete(&self, _id: &str) -> Result<(), KeyStoreError> {
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
        assert!(err.is_not_found());
    }
}
