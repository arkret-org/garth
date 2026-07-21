//! Stateful sync client utilities owned by the Garth runtime.
//!
//! The protocol types live in `arkret-models-collaboration`. This module adds the client-side
//! control plane: retry/backoff state, response processing and sliding-window
//! subscription helpers.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use arkret_signatures::{PublicKeyMaterial, verify_eddsa_detached_jws_ephemeral_proof};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[cfg(test)]
use crate::protocol::AccountSubscribeFrame;
use crate::protocol::sync::{
    LimitedTimelineState, MembershipBucket, RealmSubscription, RealmUpdate, SubscriptionConfig,
    SyncFilter, SyncRequestBody, SyncUpdates, TimelineFilter, TimelineOrderKey, ToDeviceAck,
    ToDeviceAckStatus, WaitForFrontier,
};
use crate::protocol::{
    AccountStreamInterrupt, AccountSubscribeBatch, AccountSubscribeDeviceListChanges,
    AccountSubscribeFrameKind, AccountSubscribeRealmSummary, CollaborationRealmRole, DeviceId,
    DeviceMessageEnvelope, Did, EphemeralEnvelope, Error, Event, EventId, NotificationDelta,
    NotificationDeltaAction, PresenceStatus, RealmId, Result, Timeline, aggregate_presence_states,
    canonical, validate_last_active_at, validate_status_message,
};

mod loop_control;
mod processor;
mod realm_list;
mod send_queue;
#[cfg(test)]
mod tests;

pub use loop_control::*;
pub use processor::*;
pub use realm_list::*;
pub use send_queue::*;
