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

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[cfg(test)]
use crate::protocol::AccountSubscribeFrame;
use crate::protocol::sync::{
    LimitedTimelineState, RealmUpdate, SubscriptionConfig, SyncFilter, SyncRequestBody,
    SyncUpdates, ToDeviceAck, ToDeviceAckStatus,
};
use crate::protocol::{
    AccountStreamInterrupt, AccountSubscribeBatch, AccountSubscribeDeviceListChanges,
    AccountSubscribeFrameKind, AccountSubscribeRealmSummary, AuthorizationLease, DeviceId,
    DeviceMessageEnvelope, DidCoreId, Error, Event, EventId, IngressReceipt, NotificationDelta,
    NotificationDeltaAction, RealmId, Result, Timeline, canonical,
};

mod loop_control;
mod processor;
mod send_queue;
#[cfg(test)]
mod tests;

pub use loop_control::*;
pub use processor::*;
#[cfg(test)]
pub(crate) use send_queue::test_publication;
pub use send_queue::*;
