//! Shared `#[cfg(test)]` helpers for the subscription engine and loop driver.
//!
//! `RecordingExecutor`, `sync_response` and `queued_transport` were previously
//! duplicated verbatim across `driver.rs` and `mod.rs`; they live here so both
//! test modules share a single definition.

use std::collections::{BTreeMap, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arkret::{Result, SyncOutcome, SyncRequestBody};
use serde_json::Value;

use crate::Executor;

#[derive(Clone, Debug, Default)]
pub(crate) struct RecordingExecutor {
    sleeps: Arc<Mutex<Vec<Duration>>>,
}

impl RecordingExecutor {
    pub(crate) fn sleeps(&self) -> Vec<Duration> {
        self.sleeps.lock().unwrap().clone()
    }
}

impl Executor for RecordingExecutor {
    fn sleep(&self, dur: Duration) -> impl Future<Output = ()> + '_ {
        async move {
            self.sleeps.lock().unwrap().push(dur);
        }
    }
}

pub(crate) fn sync_response(cursor: &str) -> SyncOutcome {
    SyncOutcome {
        cursor: cursor.to_owned(),
        realms: BTreeMap::new(),
        left_realms: Vec::new(),
        to_device: Vec::new(),
        to_device_ack_token: None,
        to_device_limited: false,
        to_device_next_cursor: None,
        to_device_lost: None,
        device_lists: Value::Null,
        account_data: Vec::new(),
        presence: Vec::new(),
        notifications: Default::default(),
        partial: false,
    }
}

pub(crate) fn queued_transport(
    responses: Arc<Mutex<VecDeque<Result<SyncOutcome>>>>,
) -> impl Fn(SyncRequestBody) -> Pin<Box<dyn Future<Output = Result<SyncOutcome>> + Send>> {
    move |_request| {
        let responses = Arc::clone(&responses);
        Box::pin(async move {
            responses
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| Ok(sync_response("fallback")))
        })
    }
}
