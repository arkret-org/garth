use arkret_core::{
    DecodedMessage, Event, NotificationDelta, RealmId, RealmUpdate, SyncBackfillOutcome,
    SyncUpdates, ToDeviceMessage,
};
use serde::{Deserialize, Serialize};

/// Typed events emitted by the shared client engines toward a host adapter.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ClientEvent {
    AccountUpdates(SyncUpdates),
    RealmDelta {
        realm_id: RealmId,
        update: RealmUpdate,
    },
    Backfill {
        realm_id: RealmId,
        outcome: SyncBackfillOutcome,
    },
    Message(DecodedMessage),
    Event(Event),
    Notification(NotificationDelta),
    ToDevice(ToDeviceMessage),
}

/// Async host seam: turns a batch of engine-emitted [`ClientEvent`]s into
/// durable client state.
///
/// Contract: the engine `await`s `project` for one checkpoint unit and advances
/// (checkpoints) the cursor ONLY after it returns `Ok`. The projector's durable
/// persistence therefore gates cursor advance — crash-safe and uniform across
/// the account and realm loops (emit/await-then-checkpoint). A `project` error
/// stops the loop without advancing the cursor, so the unit is redelivered.
///
/// This is the batteries-included seam a client (`inkson` / `applet`)
/// implements instead of hand-rolling its own poll loop; the loop itself lives
/// in [`crate::ArkretClient::run_account`] / [`crate::ArkretClient::run_realm`].
pub trait ClientProjector {
    fn project(
        &self,
        batch: Vec<ClientEvent>,
    ) -> impl std::future::Future<Output = arkret_core::Result<()>> + '_;
}
