use cokret_core::{
    AccountStreamInterrupt, Event, NotificationDelta, RealmId, RealmUpdate, SyncBackfillOutcome,
    SyncUpdates, ToDeviceMessage,
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
    Interrupt(AccountStreamInterrupt),
}

/// Host adapter sink for engine output.
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
