use cokret_core::{
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

/// Host adapter sink for engine output.
///
/// Synchronous, fire-and-forget. Retained for the pre-orchestrator engines
/// (`SubscriptionEngine::run_account` / `run_realm_stream`). New clients should
/// implement [`ClientProjector`] and drive the loop through
/// [`crate::CokretClient::run_account`] / [`crate::CokretClient::run_realm`]
/// instead; this sink is removed once all consumers migrate.
pub trait ClientEventSink {
    fn emit(&self, event: ClientEvent);
}

impl<F> ClientEventSink for F
where
    F: Fn(ClientEvent),
{
    fn emit(&self, event: ClientEvent) {
        self(event);
    }
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
    ) -> impl std::future::Future<Output = cokret_core::Result<()>> + '_;
}
