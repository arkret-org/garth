//! Timeline and event management for the Garth Arkret v1 runtime.
//!
//! This module provides timeline management for Realms, including:
//! - Event pagination
//! - Backfill support
//! - Timeline gaps
//! - Latest event tracking

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::base::BaseClient;
use crate::models::{DeviceId, Did, Event, EventId, RealmId};
use crate::receipts::{ReadReceipt, ReadReceiptScope};
use crate::sync::{
    BackfillDirection, BackfillFrom, BackfillRequestBody, SyncGapReason, TimelineOrderKey,
};
use crate::typing::TypingNotification;
use crate::{Result, Timeline};

/// Configuration for timeline queries.
#[derive(Clone, Debug)]
pub struct TimelineOptions {
    /// Maximum number of events to return
    pub limit: u32,
    /// Direction for pagination
    pub direction: TimelineDirection,
    /// Starting point for pagination
    pub from: TimelineFrom,
}

impl Default for TimelineOptions {
    fn default() -> Self {
        Self {
            limit: 50,
            direction: TimelineDirection::Backward,
            from: TimelineFrom::Latest,
        }
    }
}

/// Direction for timeline pagination.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimelineDirection {
    /// Forward from the starting point (older to newer)
    Forward,
    /// Backward from the starting point (newer to older)
    Backward,
    /// Both directions from the starting point
    Both,
}

/// Starting point for timeline queries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TimelineFrom {
    /// Start from the latest event
    Latest,
    /// Start from a specific event ID
    EventId(EventId),
    /// Start from the beginning
    Beginning,
    /// Start from the end
    End,
}

/// A gap in the timeline where events are missing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimelineGap {
    /// Event ID before the gap
    pub prev_event_id: Option<EventId>,
    /// Event ID after the gap
    pub next_event_id: Option<EventId>,
    /// Estimated number of missing events
    pub estimated_gap_count: Option<u64>,
    /// Older-direction cursor if supplied by sync.
    pub prev_cursor: Option<String>,
    /// Why this gap exists.
    pub reason: SyncGapReason,
}

/// Event with its position in the timeline.
#[derive(Clone, Debug)]
pub struct TimelineEvent {
    /// The event
    pub event: Event,
    /// Deterministic order key.
    pub order: TimelineOrderKey,
    /// Position in the timeline
    pub position: TimelinePosition,
}

/// Position information for a timeline event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TimelinePosition {
    /// Index in the timeline
    pub index: usize,
    /// Whether this is the latest event
    pub is_latest: bool,
}

/// Stable UI-facing timeline item kind.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimelineItemKind {
    /// Message-like event.
    Message,
    /// Generic event that is not reduced into a richer item.
    Event,
    /// Local echo from an outbound queue.
    LocalEcho,
}

/// Aggregated reaction summary for one item.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimelineReactionSummary {
    /// Reaction key.
    pub reaction_key: String,
    /// Number of active senders.
    pub count: u64,
    /// Active senders in deterministic order.
    #[serde(default)]
    pub senders: Vec<Did>,
}

/// Read receipt summary attached to one item.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimelineReadReceipt {
    /// Actor who sent the receipt.
    pub actor_id: Did,
    /// Event the receipt targets.
    pub event_id: EventId,
    /// Read scope of the receipt (`read-receipt.schema.json`).
    pub read_scope: ReadReceiptScope,
    /// Receipt time.
    pub created_at: DateTime<Utc>,
}

/// Typing state attached to a timeline.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimelineTypingUpdate {
    /// Typing user.
    pub user_id: Did,
    /// Typing device.
    pub device_id: DeviceId,
    /// Whether the device is typing.
    pub is_typing: bool,
    /// Expiration time.
    pub expires_at: DateTime<Utc>,
    /// Last update time.
    pub updated_at: DateTime<Utc>,
}

/// Stable UI-facing timeline item.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TimelineItem {
    /// Stable item ID. Message IDs are preferred over event IDs.
    pub item_id: String,
    /// Original event ID that created this item.
    pub event_id: EventId,
    /// Latest event ID after edits/redactions.
    pub latest_event_id: EventId,
    /// Realm ID.
    pub realm_id: RealmId,
    /// Sender of the original event.
    pub sender: Did,
    /// Item kind.
    pub kind: TimelineItemKind,
    /// Original deterministic position. Edits do not move the item.
    pub order: TimelineOrderKey,
    /// Latest event order that modified this item.
    pub latest_order: TimelineOrderKey,
    /// Current content after edits/redactions.
    pub content: Value,
    /// Edit event IDs in receive order.
    #[serde(default)]
    pub edit_event_ids: Vec<EventId>,
    /// Whether the item is redacted.
    pub redacted: bool,
    /// Redaction event ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redacted_by: Option<EventId>,
    /// Reaction summaries keyed by reaction key.
    #[serde(default)]
    pub reactions: BTreeMap<String, TimelineReactionSummary>,
    /// Read receipts attached to this item.
    #[serde(default)]
    pub read_receipts: Vec<TimelineReadReceipt>,
}

impl TimelineItem {
    fn from_event(event: &Event, order: TimelineOrderKey, kind: TimelineItemKind) -> Self {
        let item_id = message_id(event).unwrap_or_else(|| event.event_id.to_string());
        Self {
            item_id,
            event_id: event.event_id.clone(),
            latest_event_id: event.event_id.clone(),
            realm_id: RealmId::new(event.realm_id.to_string()).expect("validated realm id"),
            sender: event.actor_id.clone(),
            kind,
            order: order.clone(),
            latest_order: order,
            content: Value::Object(event.payload.clone().into_iter().collect()),
            edit_event_ids: Vec::new(),
            redacted: false,
            redacted_by: None,
            reactions: BTreeMap::new(),
            read_receipts: Vec::new(),
        }
    }
}

/// Result of focused event loading from local timeline state.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FocusedTimeline {
    /// Requested target event.
    pub target_event_id: EventId,
    /// Items before the target.
    #[serde(default)]
    pub before: Vec<TimelineItem>,
    /// Target item, if loaded locally.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<TimelineItem>,
    /// Items after the target.
    #[serde(default)]
    pub after: Vec<TimelineItem>,
    /// Gaps relevant to this focused load.
    #[serde(default)]
    pub gaps: Vec<TimelineGap>,
    /// Suggested backfill request when the target or surrounding context is missing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backfill_request: Option<BackfillRequestBody>,
}

/// Event cache insertion result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventCacheInsert {
    /// New event was inserted.
    Inserted,
    /// Same event ID and digest was already cached.
    DuplicateEventId,
    /// Same digest was already cached under another event ID.
    DuplicateDigest { existing_event_id: EventId },
}

/// Cached raw event and deterministic order metadata.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CachedEvent {
    /// Parsed event.
    pub event: Event,
    /// Raw event JSON as received from sync/backfill.
    pub raw: Value,
    /// Canonical event digest.
    pub digest: String,
    /// Deterministic order key.
    pub order: TimelineOrderKey,
}

/// Result of applying sync or backfill to the cache.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventCacheUpdate {
    /// Newly inserted event IDs.
    #[serde(default)]
    pub inserted: Vec<EventId>,
    /// Duplicate event IDs ignored.
    #[serde(default)]
    pub duplicate_event_ids: Vec<EventId>,
    /// Duplicate digests ignored.
    #[serde(default)]
    pub duplicate_digests: Vec<EventId>,
    /// Gaps created or remaining for the Realm.
    #[serde(default)]
    pub gaps: Vec<TimelineGap>,
}

/// In-memory event cache for raw events, processed items and timeline gaps.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct EventCache {
    events: BTreeMap<EventId, CachedEvent>,
    digest_index: BTreeMap<String, EventId>,
    depths: BTreeMap<EventId, u64>,
    processed_items: BTreeMap<RealmId, BTreeMap<String, TimelineItem>>,
    gaps: BTreeMap<RealmId, Vec<TimelineGap>>,
}

impl EventCache {
    /// Create an empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert one parsed event, deduplicating by event ID and canonical digest.
    pub fn insert_event(&mut self, event: Event) -> Result<EventCacheInsert> {
        let raw = serde_json::to_value(&event)?;
        self.insert_event_with_raw(event, raw)
    }

    /// Insert one event with its raw JSON payload.
    pub fn insert_event_with_raw(&mut self, event: Event, raw: Value) -> Result<EventCacheInsert> {
        let digest = event.event_digest()?;
        if let Some(existing) = self.events.get(&event.event_id) {
            if existing.digest == digest {
                return Ok(EventCacheInsert::DuplicateEventId);
            }
            return Err(crate::Error::IdempotencyConflict(
                event.event_id.to_string(),
            ));
        }
        if let Some(existing_event_id) = self.digest_index.get(&digest) {
            return Ok(EventCacheInsert::DuplicateDigest {
                existing_event_id: existing_event_id.clone(),
            });
        }

        let depth = causal_depth_for(&event, &self.depths);
        let order = TimelineOrderKey::from_event(&event, depth);
        self.depths.insert(event.event_id.clone(), depth);
        self.digest_index
            .insert(digest.clone(), event.event_id.clone());
        self.events.insert(
            event.event_id.clone(),
            CachedEvent {
                event,
                raw,
                digest,
                order,
            },
        );
        Ok(EventCacheInsert::Inserted)
    }

    /// Apply a sync timeline section and record a limited gap when present.
    pub fn apply_sync_timeline(
        &mut self,
        realm_id: RealmId,
        timeline: &Timeline,
    ) -> Result<EventCacheUpdate> {
        let mut update = EventCacheUpdate::default();
        let mut edge_event_ids = Vec::new();
        for event in &timeline.events {
            let raw = serde_json::to_value(event)?;
            edge_event_ids.push(event.event_id.clone());
            match self.insert_event_with_raw(event.clone(), raw)? {
                EventCacheInsert::Inserted => {
                    update.inserted.push(edge_event_ids.last().unwrap().clone())
                }
                EventCacheInsert::DuplicateEventId => update
                    .duplicate_event_ids
                    .push(edge_event_ids.last().unwrap().clone()),
                EventCacheInsert::DuplicateDigest { existing_event_id } => {
                    update.duplicate_digests.push(existing_event_id)
                }
            }
        }

        if timeline.limited {
            let gap = TimelineGap {
                prev_event_id: edge_event_ids.first().cloned(),
                next_event_id: edge_event_ids.last().cloned(),
                estimated_gap_count: None,
                prev_cursor: timeline.prev_cursor.clone(),
                reason: SyncGapReason::Limited,
            };
            let gaps = self.gaps.entry(realm_id.clone()).or_default();
            if !gaps.contains(&gap) {
                gaps.push(gap);
            }
        }
        update.gaps = self.gaps(&realm_id);
        Ok(update)
    }

    /// Apply backfilled events and clear the oldest persisted gap for the Realm.
    pub fn reconcile_backfill(
        &mut self,
        realm_id: RealmId,
        events: Vec<Event>,
    ) -> Result<EventCacheUpdate> {
        let mut update = EventCacheUpdate::default();
        for event in events {
            let event_id = event.event_id.clone();
            match self.insert_event(event)? {
                EventCacheInsert::Inserted => update.inserted.push(event_id),
                EventCacheInsert::DuplicateEventId => update.duplicate_event_ids.push(event_id),
                EventCacheInsert::DuplicateDigest { existing_event_id } => {
                    update.duplicate_digests.push(existing_event_id)
                }
            }
        }
        if let Some(gaps) = self.gaps.get_mut(&realm_id)
            && !gaps.is_empty()
        {
            gaps.remove(0);
        }
        update.gaps = self.gaps(&realm_id);
        Ok(update)
    }

    /// Store processed timeline items for later restoration.
    pub fn store_processed_items(
        &mut self,
        realm_id: RealmId,
        items: impl IntoIterator<Item = TimelineItem>,
    ) {
        let entry = self.processed_items.entry(realm_id).or_default();
        for item in items {
            entry.insert(item.item_id.clone(), item);
        }
    }

    /// Processed timeline items for a Realm.
    pub fn processed_items(&self, realm_id: &RealmId) -> Vec<TimelineItem> {
        self.processed_items
            .get(realm_id)
            .map(|items| items.values().cloned().collect())
            .unwrap_or_default()
    }

    /// Cached event by ID.
    pub fn event(&self, event_id: &EventId) -> Option<&CachedEvent> {
        self.events.get(event_id)
    }

    /// Persisted gaps for a Realm.
    pub fn gaps(&self, realm_id: &RealmId) -> Vec<TimelineGap> {
        self.gaps.get(realm_id).cloned().unwrap_or_default()
    }

    /// Create a backfill request for the next persisted gap.
    pub fn next_gap_backfill_request(
        &self,
        realm_id: &RealmId,
        limit: u32,
    ) -> Option<BackfillRequestBody> {
        let gap = self.gaps.get(realm_id)?.first()?;
        Some(BackfillRequestBody {
            realm_id: realm_id.clone(),
            from: gap
                .prev_cursor
                .as_ref()
                .map(|cursor| BackfillFrom::Cursor {
                    cursor: cursor.clone(),
                })
                .or_else(|| {
                    gap.prev_event_id
                        .as_ref()
                        .map(|event_id| BackfillFrom::EventId {
                            event_id: event_id.clone(),
                        })
                })
                .unwrap_or(BackfillFrom::Beginning),
            direction: BackfillDirection::Backward,
            limit: Some(limit),
        })
    }
}

/// Timeline for a Realm, managing events and pagination.
#[derive(Clone)]
pub struct TimelineStore {
    /// Realm ID
    realm_id: RealmId,
    /// Base client reference
    _base_client: Arc<BaseClient>,
    /// Events in the timeline
    events: VecDeque<TimelineEvent>,
    /// Event IDs already seen by this timeline.
    event_ids: BTreeSet<EventId>,
    /// Causal depth by event ID.
    event_depths: BTreeMap<EventId, u64>,
    /// Stable timeline items by item ID.
    items: BTreeMap<String, TimelineItem>,
    /// Stable item IDs in deterministic order.
    item_order: Vec<String>,
    /// Event ID to stable item ID.
    event_to_item: BTreeMap<EventId, String>,
    /// Active reaction OR-set keyed by item, actor and reaction key.
    reaction_index: BTreeMap<(String, Did, String), bool>,
    /// Active typing updates keyed by user/device.
    typing: BTreeMap<(Did, DeviceId), TimelineTypingUpdate>,
    /// Known gaps in the timeline
    gaps: Vec<TimelineGap>,
    /// Latest event ID
    latest_event_id: Option<EventId>,
    /// Oldest event ID
    oldest_event_id: Option<EventId>,
    /// Maximum timeline size
    max_size: usize,
}

impl TimelineStore {
    /// Create a new timeline for a Realm.
    pub fn new(realm_id: RealmId, base_client: Arc<BaseClient>) -> Self {
        Self {
            realm_id,
            _base_client: base_client,
            events: VecDeque::with_capacity(100),
            event_ids: BTreeSet::new(),
            event_depths: BTreeMap::new(),
            items: BTreeMap::new(),
            item_order: Vec::new(),
            event_to_item: BTreeMap::new(),
            reaction_index: BTreeMap::new(),
            typing: BTreeMap::new(),
            gaps: Vec::new(),
            latest_event_id: None,
            oldest_event_id: None,
            max_size: 1000,
        }
    }

    /// Set the maximum timeline size.
    pub fn with_max_size(mut self, max_size: usize) -> Self {
        self.max_size = max_size;
        self
    }

    /// Get the number of events in the timeline.
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Check if the timeline is empty.
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Get the latest event ID.
    pub fn latest_event_id(&self) -> Option<&EventId> {
        self.latest_event_id.as_ref()
    }

    /// Get the oldest event ID.
    pub fn oldest_event_id(&self) -> Option<&EventId> {
        self.oldest_event_id.as_ref()
    }

    /// Get events in the timeline.
    pub fn events(&self) -> Vec<TimelineEvent> {
        self.events.iter().cloned().collect()
    }

    /// Get stable UI-facing timeline items.
    pub fn items(&self) -> Vec<TimelineItem> {
        self.item_order
            .iter()
            .filter_map(|item_id| self.items.get(item_id).cloned())
            .collect()
    }

    /// Get one stable item by item ID.
    pub fn get_item(&self, item_id: &str) -> Option<TimelineItem> {
        self.items.get(item_id).cloned()
    }

    /// Get the stable item produced or modified by an event ID.
    pub fn item_for_event(&self, event_id: &EventId) -> Option<TimelineItem> {
        self.event_to_item
            .get(event_id)
            .and_then(|item_id| self.get_item(item_id))
    }

    /// Get a specific event by ID.
    pub fn get_event(&self, event_id: &EventId) -> Option<TimelineEvent> {
        self.events
            .iter()
            .find(|te| &te.event.event_id == event_id)
            .cloned()
    }

    /// Get the latest event.
    pub fn latest_event(&self) -> Option<TimelineEvent> {
        self.events.back().cloned()
    }

    /// Get the oldest event.
    pub fn oldest_event(&self) -> Option<TimelineEvent> {
        self.events.front().cloned()
    }

    /// Add new events to the timeline (typically from sync).
    pub fn append_events(&mut self, events: Vec<Event>) -> Result<()> {
        for event in events {
            self.insert_event(event)?;
            self.trim_front();
        }

        Ok(())
    }

    /// Prepend events from backfill.
    pub fn prepend_events(&mut self, events: Vec<Event>) -> Result<()> {
        for event in events.into_iter().rev() {
            self.insert_event(event)?;
            self.trim_back();
        }

        Ok(())
    }

    /// Get a paginated slice of the timeline.
    pub fn paginate(&self, options: &TimelineOptions) -> Vec<TimelineEvent> {
        let events: Vec<TimelineEvent> = self.events.iter().cloned().collect();

        match &options.from {
            TimelineFrom::Latest => {
                match options.direction {
                    TimelineDirection::Backward => {
                        // Return the latest `limit` events
                        events
                            .into_iter()
                            .rev()
                            .take(options.limit as usize)
                            .collect()
                    }
                    TimelineDirection::Forward => {
                        // Return the oldest `limit` events
                        events.into_iter().take(options.limit as usize).collect()
                    }
                    TimelineDirection::Both => {
                        // Return all events up to limit
                        events.into_iter().take(options.limit as usize).collect()
                    }
                }
            }
            TimelineFrom::EventId(event_id) => {
                if let Some(start_idx) = events.iter().position(|te| &te.event.event_id == event_id)
                {
                    match options.direction {
                        TimelineDirection::Backward => {
                            // Return events before start_idx
                            events[..start_idx]
                                .iter()
                                .rev()
                                .take(options.limit as usize)
                                .cloned()
                                .collect()
                        }
                        TimelineDirection::Forward => {
                            // Return events after start_idx
                            events[start_idx + 1..]
                                .iter()
                                .take(options.limit as usize)
                                .cloned()
                                .collect()
                        }
                        TimelineDirection::Both => {
                            // Return events around start_idx
                            let before = start_idx.saturating_sub(options.limit as usize / 2);
                            let after =
                                (start_idx + options.limit as usize / 2 + 1).min(events.len());
                            events[before..after].to_vec()
                        }
                    }
                } else {
                    // Event not found in timeline
                    Vec::new()
                }
            }
            TimelineFrom::Beginning => events.into_iter().take(options.limit as usize).collect(),
            TimelineFrom::End => events
                .into_iter()
                .rev()
                .take(options.limit as usize)
                .collect(),
        }
    }

    /// Create a backfill request based on timeline gaps.
    pub fn create_backfill_request(&self, limit: u32) -> Option<BackfillRequestBody> {
        // Find the oldest gap or the beginning
        let from = if let Some(gap) = self.gaps.first() {
            if let Some(prev_cursor) = &gap.prev_cursor {
                BackfillFrom::Cursor {
                    cursor: prev_cursor.clone(),
                }
            } else if let Some(prev_id) = &gap.prev_event_id {
                BackfillFrom::EventId {
                    event_id: prev_id.clone(),
                }
            } else {
                BackfillFrom::Beginning
            }
        } else if let Some(oldest_id) = &self.oldest_event_id {
            BackfillFrom::EventId {
                event_id: oldest_id.clone(),
            }
        } else {
            BackfillFrom::Beginning
        };

        Some(BackfillRequestBody {
            realm_id: self.realm_id.clone(),
            from,
            direction: BackfillDirection::Backward,
            limit: Some(limit),
        })
    }

    /// Record a gap in the timeline.
    pub fn record_gap(
        &mut self,
        prev_event_id: Option<EventId>,
        next_event_id: Option<EventId>,
        estimated_count: Option<u64>,
    ) {
        let gap = TimelineGap {
            prev_event_id,
            next_event_id,
            estimated_gap_count: estimated_count,
            prev_cursor: None,
            reason: SyncGapReason::Backfill,
        };
        self.gaps.push(gap);
    }

    /// Record a limited timeline gap from sync.
    pub fn record_limited_gap(
        &mut self,
        prev_event_id: Option<EventId>,
        next_event_id: Option<EventId>,
        prev_cursor: Option<String>,
    ) {
        self.gaps.push(TimelineGap {
            prev_event_id,
            next_event_id,
            estimated_gap_count: None,
            prev_cursor,
            reason: SyncGapReason::Limited,
        });
    }

    /// Clear known gaps (e.g., after backfill).
    pub fn clear_gaps(&mut self) {
        self.gaps.clear();
    }

    /// Get known gaps.
    pub fn gaps(&self) -> Vec<TimelineGap> {
        self.gaps.clone()
    }

    /// Apply a read receipt to a stable timeline item.
    pub fn apply_read_receipt(&mut self, receipt: ReadReceipt) {
        let item_id = self
            .event_to_item
            .get(&receipt.event_id)
            .cloned()
            .unwrap_or_else(|| receipt.event_id.to_string());
        if let Some(item) = self.items.get_mut(&item_id) {
            let summary = TimelineReadReceipt {
                actor_id: receipt.actor_id,
                event_id: receipt.event_id,
                read_scope: receipt.read_scope,
                created_at: receipt.created_at,
            };
            item.read_receipts.retain(|existing| {
                existing.actor_id != summary.actor_id || existing.read_scope != summary.read_scope
            });
            item.read_receipts.push(summary);
            item.read_receipts
                .sort_by(|left, right| left.actor_id.cmp(&right.actor_id));
        }
    }

    /// Apply a typing notification to ephemeral timeline state.
    pub fn apply_typing(&mut self, notification: TypingNotification) {
        let key = (notification.user_id.clone(), notification.device_id.clone());
        if notification.is_typing {
            self.typing.insert(
                key,
                TimelineTypingUpdate {
                    user_id: notification.user_id,
                    device_id: notification.device_id,
                    is_typing: true,
                    expires_at: notification.expires_at,
                    updated_at: notification.updated_at,
                },
            );
        } else {
            self.typing.remove(&key);
        }
    }

    /// Active typing users at `now`, merged across devices.
    pub fn active_typers_at(&self, now: DateTime<Utc>) -> Vec<Did> {
        let mut users = BTreeSet::new();
        for update in self.typing.values() {
            if update.is_typing && update.expires_at > now {
                users.insert(update.user_id.clone());
            }
        }
        users.into_iter().collect()
    }

    /// Load a focused item window around a target event.
    pub fn focused_window(
        &self,
        target_event_id: EventId,
        before: usize,
        after: usize,
    ) -> FocusedTimeline {
        let Some(item_id) = self.event_to_item.get(&target_event_id).cloned() else {
            return FocusedTimeline {
                target_event_id: target_event_id.clone(),
                before: Vec::new(),
                target: None,
                after: Vec::new(),
                gaps: self.gaps.clone(),
                backfill_request: Some(BackfillRequestBody {
                    realm_id: self.realm_id.clone(),
                    from: BackfillFrom::EventId {
                        event_id: target_event_id,
                    },
                    direction: BackfillDirection::Both,
                    limit: Some((before + after + 1) as u32),
                }),
            };
        };

        let Some(index) = self
            .item_order
            .iter()
            .position(|candidate| candidate == &item_id)
        else {
            return FocusedTimeline {
                target_event_id,
                before: Vec::new(),
                target: None,
                after: Vec::new(),
                gaps: self.gaps.clone(),
                backfill_request: None,
            };
        };
        let start = index.saturating_sub(before);
        let end = (index + after + 1).min(self.item_order.len());
        let before_items = self.item_order[start..index]
            .iter()
            .filter_map(|id| self.items.get(id).cloned())
            .collect();
        let after_items = self.item_order[index + 1..end]
            .iter()
            .filter_map(|id| self.items.get(id).cloned())
            .collect();
        let needs_backfill = index < before || index + after + 1 > self.item_order.len();

        // `item_id` came from `event_to_item`, so the item should also be
        // in `items` — but fall back to the requested event id instead of
        // panicking if the two maps ever drift.
        let target = self.items.get(&item_id).cloned();
        let backfill_from_event_id = target
            .as_ref()
            .map(|item| item.event_id.clone())
            .unwrap_or_else(|| target_event_id.clone());

        FocusedTimeline {
            target_event_id,
            before: before_items,
            target,
            after: after_items,
            gaps: self.gaps.clone(),
            backfill_request: needs_backfill.then(|| BackfillRequestBody {
                realm_id: self.realm_id.clone(),
                from: BackfillFrom::EventId {
                    event_id: backfill_from_event_id,
                },
                direction: BackfillDirection::Both,
                limit: Some((before + after + 1) as u32),
            }),
        }
    }

    /// Update positions for all events in the timeline.
    fn update_positions(&mut self) {
        let len = self.events.len();
        for (index, te) in self.events.iter_mut().enumerate() {
            te.position.index = index;
            te.position.is_latest = index == len - 1;
        }
        self.oldest_event_id = self
            .events
            .front()
            .map(|event| event.event.event_id.clone());
        self.latest_event_id = self.events.back().map(|event| event.event.event_id.clone());
    }

    fn insert_event(&mut self, event: Event) -> Result<()> {
        if !self.event_ids.insert(event.event_id.clone()) {
            return Ok(());
        }

        let depth = causal_depth_for(&event, &self.event_depths);
        let order = TimelineOrderKey::from_event(&event, depth);
        self.event_depths.insert(event.event_id.clone(), depth);
        self.apply_item_event(&event, order.clone());

        let entry = TimelineEvent {
            event,
            order: order.clone(),
            position: TimelinePosition {
                index: 0,
                is_latest: false,
            },
        };
        let insert_at = self
            .events
            .iter()
            .position(|existing| existing.order > order);
        if let Some(index) = insert_at {
            self.events.insert(index, entry);
        } else {
            self.events.push_back(entry);
        }
        self.update_positions();
        Ok(())
    }

    fn trim_front(&mut self) {
        while self.events.len() > self.max_size {
            if let Some(event) = self.events.pop_front() {
                self.event_ids.remove(&event.event.event_id);
                self.event_depths.remove(&event.event.event_id);
            }
        }
        self.update_positions();
    }

    fn trim_back(&mut self) {
        while self.events.len() > self.max_size {
            if let Some(event) = self.events.pop_back() {
                self.event_ids.remove(&event.event.event_id);
                self.event_depths.remove(&event.event.event_id);
            }
        }
        self.update_positions();
    }

    fn apply_item_event(&mut self, event: &Event, order: TimelineOrderKey) {
        match event.kind.as_str() {
            "ak.message.create" => self.upsert_message_item(event, order),
            "ak.message.revise" => self.apply_message_revision(event, order),
            "ak.message.redact" | "ak.redaction" => self.apply_message_redaction(event, order),
            "ak.reaction.add" | "ak.reaction.remove" => self.apply_reaction(event),
            _ if event.redacts.is_some() => self.apply_message_redaction(event, order),
            _ => self.upsert_generic_item(event, order),
        }
    }

    fn upsert_message_item(&mut self, event: &Event, order: TimelineOrderKey) {
        let item = TimelineItem::from_event(event, order, TimelineItemKind::Message);
        self.insert_item_for_event(event.event_id.clone(), item);
    }

    fn upsert_generic_item(&mut self, event: &Event, order: TimelineOrderKey) {
        let item = TimelineItem::from_event(event, order, TimelineItemKind::Event);
        self.insert_item_for_event(event.event_id.clone(), item);
    }

    fn insert_item_for_event(&mut self, event_id: EventId, item: TimelineItem) {
        let item_id = item.item_id.clone();
        if !self.items.contains_key(&item_id) {
            self.item_order.push(item_id.clone());
            self.items.insert(item_id.clone(), item);
            self.sort_item_order();
        } else {
            self.event_to_item.insert(event_id, item_id);
            return;
        }
        self.event_to_item.insert(event_id, item_id);
    }

    fn apply_message_revision(&mut self, event: &Event, order: TimelineOrderKey) {
        let Some(item_id) = self.target_item_id(event) else {
            return;
        };
        let Some(item) = self.items.get_mut(&item_id) else {
            return;
        };

        if order >= item.latest_order {
            item.latest_event_id = event.event_id.clone();
            item.latest_order = order;
            item.content = event
                .payload
                .get("content")
                .filter(|content| content.is_object())
                .cloned()
                .unwrap_or_else(|| Value::Object(event.payload.clone().into_iter().collect()));
            item.redacted = false;
            item.redacted_by = None;
        }
        item.edit_event_ids.push(event.event_id.clone());
        self.event_to_item.insert(event.event_id.clone(), item_id);
    }

    fn apply_message_redaction(&mut self, event: &Event, order: TimelineOrderKey) {
        let Some(item_id) = self.target_item_id(event).or_else(|| {
            event
                .redacts
                .as_ref()
                .and_then(|event_id| self.event_to_item.get(event_id).cloned())
        }) else {
            return;
        };
        let Some(item) = self.items.get_mut(&item_id) else {
            return;
        };

        if order >= item.latest_order {
            item.latest_event_id = event.event_id.clone();
            item.latest_order = order;
            item.content = Value::Object(Default::default());
            item.redacted = true;
            item.redacted_by = Some(event.event_id.clone());
        }
        item.edit_event_ids.push(event.event_id.clone());
        self.event_to_item.insert(event.event_id.clone(), item_id);
    }

    fn apply_reaction(&mut self, event: &Event) {
        let Some(item_id) = self.target_item_id(event) else {
            return;
        };
        if !self.items.contains_key(&item_id) {
            return;
        }
        let Some(reaction_key) = string_content_field(event, "reaction_key") else {
            return;
        };

        let active = event.kind == "ak.reaction.add";
        self.reaction_index.insert(
            (
                item_id.clone(),
                event.actor_id.clone(),
                reaction_key.clone(),
            ),
            active,
        );
        self.recompute_reaction_summary(&item_id, &reaction_key);
        self.event_to_item.insert(event.event_id.clone(), item_id);
    }

    fn recompute_reaction_summary(&mut self, item_id: &str, reaction_key: &str) {
        let mut senders: Vec<Did> = self
            .reaction_index
            .iter()
            .filter_map(
                |((candidate_item_id, sender, candidate_reaction), active)| {
                    if candidate_item_id == item_id && candidate_reaction == reaction_key && *active
                    {
                        Some(sender.clone())
                    } else {
                        None
                    }
                },
            )
            .collect();
        senders.sort();
        senders.dedup();

        if let Some(item) = self.items.get_mut(item_id) {
            if senders.is_empty() {
                item.reactions.remove(reaction_key);
            } else {
                item.reactions.insert(
                    reaction_key.to_owned(),
                    TimelineReactionSummary {
                        reaction_key: reaction_key.to_owned(),
                        count: senders.len() as u64,
                        senders,
                    },
                );
            }
        }
    }

    fn target_item_id(&self, event: &Event) -> Option<String> {
        string_content_field(event, "target_message_id")
            .or_else(|| string_content_field(event, "message_id"))
            .or_else(|| {
                string_content_field(event, "target_event_id").and_then(|event_id| {
                    EventId::new(event_id)
                        .ok()
                        .and_then(|event_id| self.event_to_item.get(&event_id).cloned())
                })
            })
    }

    fn sort_item_order(&mut self) {
        self.item_order.sort_by(|left, right| {
            let left_item = self.items.get(left);
            let right_item = self.items.get(right);
            match (left_item, right_item) {
                (Some(left_item), Some(right_item)) => {
                    left_item.order.cmp(&right_item.order).then(left.cmp(right))
                }
                _ => left.cmp(right),
            }
        });
    }

    /// Clear the timeline.
    pub fn clear(&mut self) {
        self.events.clear();
        self.event_ids.clear();
        self.event_depths.clear();
        self.items.clear();
        self.item_order.clear();
        self.event_to_item.clear();
        self.reaction_index.clear();
        self.typing.clear();
        self.gaps.clear();
        self.latest_event_id = None;
        self.oldest_event_id = None;
    }
}

fn causal_depth_for(event: &Event, depths: &BTreeMap<EventId, u64>) -> u64 {
    event
        .prev_refs
        .iter()
        .filter_map(|event_id| depths.get(event_id))
        .copied()
        .max()
        .map(|depth| depth.saturating_add(1))
        .unwrap_or(event.prev_refs.len() as u64)
}

fn message_id(event: &Event) -> Option<String> {
    string_content_field(event, "message_id").or_else(|| string_content_field(event, "id"))
}

fn string_content_field(event: &Event, field: &str) -> Option<String> {
    event.payload.get(field)?.as_str().map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use chrono::Duration;
    use serde_json::json;

    use super::*;
    use crate::{DeviceId, Did, Hlc, RealmId};

    fn create_test_event(realm_id: &RealmId, index: u32) -> Event {
        Event {
            event_id: EventId::new(format!("ak:event:01904100-0000-7000-8000-{:012x}", index))
                .unwrap(),
            kind: arkret_core::events::EventKind::MORPH_CREATE.into(),
            realm_id: realm_id.clone(),
            actor_id: Did::new("did:webvh:z6mkfixture:alice.example.com").unwrap(),
            actor_seq: index as u64,
            created_at: Utc::now(),
            hlc: Hlc::new(format!("01970e589d21-{:04x}-a13f9c2e", index)).unwrap(),
            prev_refs: vec![],
            effective_scope: None,
            refs: vec![],
            preconditions: vec![],
            effects: vec![],
            seal_ref: None,
            auth_context: None,
            seal_basis: None,
            requirements: crate::EventRequirements::default(),
            redacts: None,
            payload: serde_json::from_value(json!({
                "object": {
                    "id": format!("ak:morph:01904100-0000-7000-8000-{:012x}", index),
                    "schema": crate::MORPH_SCHEMA,
                    "realm_id": realm_id.as_str(),
                    "schema_refs": [crate::MORPH_SCHEMA],
                    "morph_type": "task",
                    "stage": "draft",
                    "created_by": "did:webvh:z6mkfixture:alice.example.com",
                    "created_at": "2026-05-02T00:00:00.000Z"
                }
            }))
            .unwrap(),
            executed_by: None,
            authorization_ref: None,
            applet_id: None,
            external_ref: None,
            actor_kind: None,
            unsigned: BTreeMap::new(),
            proofs: vec![],
        }
    }

    #[test]
    fn timeline_starts_empty() {
        let base_client = Arc::new(BaseClient::new());
        let realm_id = RealmId::new("ak:realm:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
        let timeline = TimelineStore::new(realm_id, base_client);

        assert!(timeline.is_empty());
        assert_eq!(timeline.len(), 0);
    }

    #[test]
    fn timeline_appends_events() {
        let base_client = Arc::new(BaseClient::new());
        let realm_id = RealmId::new("ak:realm:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
        let mut timeline = TimelineStore::new(realm_id.clone(), base_client);

        let events = vec![
            create_test_event(&realm_id, 1),
            create_test_event(&realm_id, 2),
            create_test_event(&realm_id, 3),
        ];

        timeline.append_events(events).unwrap();

        assert_eq!(timeline.len(), 3);
        assert!(timeline.latest_event_id().is_some());
    }

    #[test]
    fn timeline_prepends_events() {
        let base_client = Arc::new(BaseClient::new());
        let realm_id = RealmId::new("ak:realm:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
        let mut timeline = TimelineStore::new(realm_id.clone(), base_client);

        // First append some events
        let events1 = vec![
            create_test_event(&realm_id, 4),
            create_test_event(&realm_id, 5),
        ];
        timeline.append_events(events1).unwrap();

        // Then prepend older events
        let events2 = vec![
            create_test_event(&realm_id, 2),
            create_test_event(&realm_id, 3),
        ];
        timeline.prepend_events(events2).unwrap();

        assert_eq!(timeline.len(), 4);
        assert!(timeline.oldest_event_id().is_some());
    }

    #[test]
    fn timeline_paginates_backward_from_latest() {
        let base_client = Arc::new(BaseClient::new());
        let realm_id = RealmId::new("ak:realm:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
        let mut timeline = TimelineStore::new(realm_id.clone(), base_client);

        let events: Vec<Event> = (1..=10).map(|i| create_test_event(&realm_id, i)).collect();
        timeline.append_events(events).unwrap();

        let options = TimelineOptions {
            limit: 3,
            direction: TimelineDirection::Backward,
            from: TimelineFrom::Latest,
        };

        let paginated = timeline.paginate(&options);
        assert_eq!(paginated.len(), 3);
        // Should return the latest 3 events (in reverse order)
        assert_eq!(paginated[0].event.actor_seq, 10);
        assert_eq!(paginated[1].event.actor_seq, 9);
        assert_eq!(paginated[2].event.actor_seq, 8);
    }

    #[test]
    fn timeline_paginates_from_event_id() {
        let base_client = Arc::new(BaseClient::new());
        let realm_id = RealmId::new("ak:realm:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
        let mut timeline = TimelineStore::new(realm_id.clone(), base_client);

        let events: Vec<Event> = (1..=10).map(|i| create_test_event(&realm_id, i)).collect();
        timeline.append_events(events).unwrap();

        let from_event = EventId::new("ak:event:01904100-0000-7000-8000-000000000005").unwrap();
        let options = TimelineOptions {
            limit: 2,
            direction: TimelineDirection::Forward,
            from: TimelineFrom::EventId(from_event),
        };

        let paginated = timeline.paginate(&options);
        assert_eq!(paginated.len(), 2);
        // Should return events after event 5
        assert_eq!(paginated[0].event.actor_seq, 6);
        assert_eq!(paginated[1].event.actor_seq, 7);
    }

    #[test]
    fn timeline_tracks_gaps() {
        let base_client = Arc::new(BaseClient::new());
        let realm_id = RealmId::new("ak:realm:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
        let mut timeline = TimelineStore::new(realm_id, base_client);

        let prev_id = EventId::new("ak:event:01904100-0000-7000-8000-ab84c4c0f437").unwrap();
        let next_id = EventId::new("ak:event:01904100-0000-7000-8000-b76e5d2fe42a").unwrap();

        timeline.record_gap(Some(prev_id.clone()), Some(next_id.clone()), Some(1));

        let gaps = timeline.gaps();
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0].prev_event_id, Some(prev_id));
        assert_eq!(gaps[0].next_event_id, Some(next_id));
    }

    #[test]
    fn timeline_clears_gaps() {
        let base_client = Arc::new(BaseClient::new());
        let realm_id = RealmId::new("ak:realm:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
        let mut timeline = TimelineStore::new(realm_id, base_client);

        timeline.record_gap(None, None, Some(10));
        assert_eq!(timeline.gaps().len(), 1);

        timeline.clear_gaps();
        assert_eq!(timeline.gaps().len(), 0);
    }

    #[test]
    fn timeline_builds_stable_items_and_aggregates_edits_redactions_and_reactions() {
        let base_client = Arc::new(BaseClient::new());
        let realm_id = RealmId::new("ak:realm:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
        let mut timeline = TimelineStore::new(realm_id.clone(), base_client);
        let mut message = create_test_event(&realm_id, 1);
        message.kind = "ak.message.create".into();
        message.payload =
            serde_json::from_value(json!({"message_id":"m1","body":"hello"})).unwrap();
        let mut edit = create_test_event(&realm_id, 2);
        edit.kind = "ak.message.revise".into();
        edit.payload =
            serde_json::from_value(json!({"target_message_id":"m1","content":{"body":"hi"}}))
                .unwrap();
        let mut reaction = create_test_event(&realm_id, 3);
        reaction.kind = "ak.reaction.add".into();
        reaction.payload =
            serde_json::from_value(json!({"message_id":"m1","reaction_key":"+1"})).unwrap();
        let mut redaction = create_test_event(&realm_id, 4);
        redaction.kind = "ak.message.redact".into();
        redaction.payload = serde_json::from_value(json!({"target_message_id":"m1"})).unwrap();

        timeline
            .append_events(vec![message, edit, reaction])
            .unwrap();

        let item = timeline.get_item("m1").unwrap();
        assert_eq!(timeline.items().len(), 1);
        assert_eq!(item.content, json!({"body":"hi"}));
        assert_eq!(item.edit_event_ids.len(), 1);
        assert_eq!(item.reactions["+1"].count, 1);

        timeline.append_events(vec![redaction]).unwrap();
        let redacted = timeline.get_item("m1").unwrap();
        assert!(redacted.redacted);
        assert_eq!(redacted.content, json!({}));
    }

    #[test]
    fn timeline_applies_read_receipts_typing_and_focused_loading() {
        let base_client = Arc::new(BaseClient::new());
        let realm_id = RealmId::new("ak:realm:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
        let mut timeline = TimelineStore::new(realm_id.clone(), base_client);
        let mut message = create_test_event(&realm_id, 1);
        message.kind = "ak.message.create".into();
        message.payload =
            serde_json::from_value(json!({"message_id":"m1","body":"hello"})).unwrap();
        let event_id = message.event_id.clone();
        let actor = Did::new("did:webvh:z6mkfixture:alice.example.com").unwrap();

        timeline.append_events(vec![message]).unwrap();
        timeline.apply_read_receipt(ReadReceipt {
            receipt_type: arkret_core::READ_RECEIPT_TYPE.to_owned(),
            schema: arkret_core::READ_RECEIPT_SCHEMA.to_owned(),
            realm_id: realm_id.clone(),
            actor_id: actor.clone(),
            event_id: event_id.clone(),
            hlc: None,
            read_scope: ReadReceiptScope::realm(),
            created_at: Utc::now(),
        });
        timeline.apply_typing(TypingNotification {
            realm_id,
            user_id: actor.clone(),
            device_id: DeviceId::new("ak:device:01904100-0000-7000-8000-000000000005").unwrap(),
            is_typing: true,
            expires_at: Utc::now() + Duration::seconds(30),
            updated_at: Utc::now(),
        });

        let focused = timeline.focused_window(event_id, 1, 1);

        assert_eq!(timeline.get_item("m1").unwrap().read_receipts.len(), 1);
        assert_eq!(timeline.active_typers_at(Utc::now()), vec![actor]);
        assert!(focused.target.is_some());
        assert!(focused.backfill_request.is_some());
    }

    #[test]
    fn event_cache_deduplicates_records_limited_gaps_and_reconciles_backfill() {
        let realm_id = RealmId::new("ak:realm:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
        let event = create_test_event(&realm_id, 1);
        let event_id = event.event_id.clone();
        let timeline_section = Timeline {
            events: vec![event.clone()],
            limited: true,
            prev_cursor: Some("prev".to_owned()),
            preview_only: None,
            extra: BTreeMap::new(),
        };
        let mut cache = EventCache::new();

        let update = cache
            .apply_sync_timeline(realm_id.clone(), &timeline_section)
            .unwrap();
        let duplicate = cache
            .apply_sync_timeline(realm_id.clone(), &timeline_section)
            .unwrap();
        let request = cache.next_gap_backfill_request(&realm_id, 10).unwrap();
        cache.store_processed_items(
            realm_id.clone(),
            vec![TimelineItem::from_event(
                &event,
                TimelineOrderKey::from_event(&event, 0),
                TimelineItemKind::Message,
            )],
        );
        let backfill = cache
            .reconcile_backfill(realm_id.clone(), vec![create_test_event(&realm_id, 0)])
            .unwrap();

        assert_eq!(update.inserted, vec![event_id.clone()]);
        assert_eq!(duplicate.duplicate_event_ids, vec![event_id]);
        assert!(matches!(request.from, BackfillFrom::Cursor { .. }));
        assert_eq!(cache.processed_items(&realm_id).len(), 1);
        assert!(backfill.gaps.is_empty());
    }
}
