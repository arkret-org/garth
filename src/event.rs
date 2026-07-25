use crate::protocol::{
    AccountSubscribeDeviceListChanges, DeviceMessageEnvelope, EphemeralEnvelope, Event,
    EventsQueryOutcome, NotificationDelta, RealmId, RealmUpdate,
};
use serde::{Deserialize, Serialize};

use crate::DecodedMessage;

/// Typed events emitted by the shared client engines toward a host adapter.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ClientEvent {
    AccountUpdates(AccountUpdateContext),
    RealmDelta {
        realm_id: RealmId,
        update: RealmUpdate,
    },
    Backfill {
        realm_id: RealmId,
        outcome: EventsQueryOutcome,
    },
    Message(DecodedMessage),
    Event(Event),
    Notification(NotificationDelta),
    ToDevice(DeviceMessageEnvelope),
}

/// Account-subscribe batch metadata that is not emitted as a granular event.
///
/// Realm updates, to-device messages, and notifications deliberately do not
/// live here: each is emitted once through its dedicated [`ClientEvent`]
/// variant, keeping durable inbox records free of duplicate payloads.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccountUpdateContext {
    /// True when this batch came from a request without a continuation cursor.
    ///
    /// Hosts can use this to build a local history baseline without treating
    /// an initial or recovery catch-up as newly arrived user activity.
    #[serde(default)]
    pub initial_catchup: bool,
    pub malformed_realms: Vec<String>,
    pub to_device_ack_token: Option<String>,
    pub to_device_limited: bool,
    pub to_device_next_cursor: Option<String>,
    pub to_device_lost: bool,
    pub device_lists: AccountSubscribeDeviceListChanges,
    pub presence: Vec<EphemeralEnvelope>,
    pub account_data: Vec<Event>,
    pub agent_signer_evidence: Vec<crate::protocol::AgentSignerEvidence>,
    pub partial: bool,
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
    ) -> impl std::future::Future<Output = crate::protocol::Result<()>> + '_;
}
