mod crypto_store;
mod keystore;
mod memory;

use std::future::Future;

use cokret_core::{DeviceId, Did, EventId, Hash, RealmId, Result};
pub use crypto_store::SecureCryptoStoreAdapter;
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
    EventsQuery {
        service_did: Option<Did>,
        realms: Vec<RealmId>,
        actors: Vec<Did>,
        order: Option<String>,
        filter_digest: Option<Hash>,
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
