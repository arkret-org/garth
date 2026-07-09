use arkret_core::{
    Event, NotificationDelta, RealmId, RealmUpdate, SyncBackfillOutcome, SyncUpdates,
    ToDeviceMessage,
};

use crate::DecodedMessage;

/// Typed events emitted by the shared client engines toward a host adapter.
#[derive(Clone, Debug)]
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
/// in [`crate::CokretClient::run_account`] / [`crate::CokretClient::run_realm`].
pub trait ClientProjector {
    fn project(
        &self,
        batch: Vec<ClientEvent>,
    ) -> impl std::future::Future<Output = arkret_core::Result<()>> + '_;
}
