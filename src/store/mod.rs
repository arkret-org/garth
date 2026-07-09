mod crypto_store;
#[cfg(all(feature = "native", not(target_arch = "wasm32")))]
mod file;
mod keystore;
mod memory;
mod seen_window;

use std::future::Future;

use arkret_core::{DeviceId, Did, EventId, RealmId, Result};
pub use crypto_store::SecureCryptoStoreAdapter;
#[cfg(all(feature = "native", not(target_arch = "wasm32")))]
pub use file::FileStore;
pub use keystore::{
    MemorySecureKeyStore, PutSecretOptions, SdkKeyStoreAdapter, SdkKeyStoreSecureAdapter,
    SecretBytes, SecretClass, SecretDurability, SecureKeyStore, SecureKeyStoreBackendInfo,
    SecureKeyStoreError,
};
pub use memory::MemoryStore;

pub type OpaqueCursor = String;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CursorScope {
    Account {
        service_did: Option<Did>,
        actor_id: Did,
        device_id: DeviceId,
    },
    RealmEvents {
        service_did: Option<Did>,
        realm_id: RealmId,
    },
}

pub trait CursorStore: Clone + Send + Sync + 'static {
    fn load(&self, scope: CursorScope) -> impl Future<Output = Result<Option<OpaqueCursor>>> + '_;
    fn save(
        &self,
        scope: CursorScope,
        cursor: OpaqueCursor,
    ) -> impl Future<Output = Result<()>> + '_;
    fn clear(&self, scope: CursorScope) -> impl Future<Output = Result<()>> + '_;
}

pub trait EventCacheStore: Clone + Send + Sync + 'static {
    fn seen(&self, event_id: EventId) -> impl Future<Output = Result<bool>> + '_;
    fn remember(&self, event_id: EventId) -> impl Future<Output = Result<()>> + '_;
}
