mod crypto_store;
#[cfg(all(feature = "native", not(target_arch = "wasm32")))]
mod file;
mod inbox;
mod keystore;
mod memory;
mod seen_window;

use std::future::Future;

use crate::protocol::{DeviceId, Did, EventId, RealmId, Result};
use serde::{Deserialize, Serialize};

use crate::MaybeSendSync;
pub use crypto_store::SecureCryptoStoreAdapter;
#[cfg(all(feature = "native", not(target_arch = "wasm32")))]
pub use file::FileStore;
pub use inbox::{
    DeliveryErrorClass, DeliveryId, DurableInboxStore, MAX_DELIVERY_ERROR_BYTES,
    MAX_PENDING_DELIVERIES, MAX_PENDING_READ, PendingDelivery,
};
pub use keystore::{
    MemorySecureKeyStore, PutSecretOptions, SdkKeyStoreAdapter, SdkKeyStoreSecureAdapter,
    SecretBytes, SecretClass, SecretDurability, SecureKeyStore, SecureKeyStoreBackendInfo,
    SecureKeyStoreError,
};
pub use memory::MemoryStore;
pub use seen_window::{BoundedSeenWindow, DEFAULT_SEEN_EVENTS_CAPACITY};

/// Client-side continuation token.
///
/// This deliberately remains an opaque string instead of the SDK's
/// service-side `Cursor` structure. Arkret v1 forbids clients from decoding or
/// depending on cursor internals; stores and transports must preserve the
/// exact token issued by the service.
pub type OpaqueCursor = String;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum CursorScope {
    Account {
        service_id: Option<Did>,
        actor_id: Did,
        device_id: DeviceId,
    },
    RealmEvents {
        service_id: Option<Did>,
        realm_id: RealmId,
    },
    RealmEventsScan {
        service_id: Option<Did>,
        realm_id: RealmId,
        order: Option<String>,
    },
    DeviceMessages {
        service_id: Option<Did>,
        actor_id: Did,
        device_id: DeviceId,
    },
}

pub trait CursorStore: Clone + MaybeSendSync + 'static {
    fn load(&self, scope: CursorScope) -> impl Future<Output = Result<Option<OpaqueCursor>>> + '_;
    fn save(
        &self,
        scope: CursorScope,
        cursor: OpaqueCursor,
    ) -> impl Future<Output = Result<()>> + '_;
    fn clear(&self, scope: CursorScope) -> impl Future<Output = Result<()>> + '_;
}

pub trait EventCacheStore: Clone + MaybeSendSync + 'static {
    fn seen(&self, event_id: EventId) -> impl Future<Output = Result<bool>> + '_;
    fn remember(&self, event_id: EventId) -> impl Future<Output = Result<()>> + '_;
}
