use std::future::Future;

use arkret_core::Result;
use serde::{Deserialize, Serialize};

use super::{CursorScope, OpaqueCursor};
use crate::{ClientEvent, MaybeSendSync};

pub const MAX_DELIVERY_ERROR_BYTES: usize = 2048;
pub const MAX_PENDING_READ: usize = 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct DeliveryId(u64);

impl DeliveryId {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingDelivery {
    pub id: DeliveryId,
    pub scope: CursorScope,
    pub cursor: Option<OpaqueCursor>,
    pub events: Vec<ClientEvent>,
    pub attempts: u32,
    pub next_attempt_at_ms: Option<i64>,
    pub error_class: Option<DeliveryErrorClass>,
    pub last_error: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryErrorClass {
    RetryableTransport,
    RateLimited,
    Unauthorized,
    Processing,
    Store,
}

pub trait DurableInboxStore: Clone + MaybeSendSync + 'static {
    /// Atomically replace the cursor for `scope` and append a pending delivery.
    /// Empty event batches only update the cursor and return `None`.
    fn commit(
        &self,
        scope: CursorScope,
        cursor: Option<OpaqueCursor>,
        events: Vec<ClientEvent>,
    ) -> impl Future<Output = Result<Option<DeliveryId>>> + '_;

    fn pending(&self, limit: usize) -> impl Future<Output = Result<Vec<PendingDelivery>>> + '_;

    fn ack(&self, id: DeliveryId) -> impl Future<Output = Result<bool>> + '_;

    fn retry(
        &self,
        id: DeliveryId,
        next_attempt_at_ms: Option<i64>,
        error_class: DeliveryErrorClass,
        error: String,
    ) -> impl Future<Output = Result<bool>> + '_;
}

pub(super) fn bounded_pending_limit(limit: usize) -> usize {
    limit.clamp(1, MAX_PENDING_READ)
}

pub(super) fn bounded_delivery_error(mut error: String) -> String {
    if error.len() <= MAX_DELIVERY_ERROR_BYTES {
        return error;
    }
    let mut end = MAX_DELIVERY_ERROR_BYTES;
    while !error.is_char_boundary(end) {
        end -= 1;
    }
    error.truncate(end);
    error
}
