//! Host-facing projection seam over independently committed authority streams.
//!
//! The engine hands a host a batch of [`ClientEvent`] values and only advances
//! a durable cursor after the host's [`ClientProjector`] returns `Ok`. Every
//! Realm delta carries the exact [`CommitStreamRef`] and stream position the
//! governance Station assigned it, so a host indexes per stream. There is no
//! Realm-wide sequence here, and no client-side ordering is ever synthesized:
//! a Realm, each Circle and each Sidecar advance independently.

use std::collections::BTreeMap;

use arkret_event_draft::{EventPayloadExt, MessageEventPayload};
use arkret_models_collaboration::device_messages::{DeviceMessageEnvelope, RecipientDelivery};
use arkret_models_collaboration::sync_frames::account_subscribe::{
    AccountSubscribeBatch, AccountSubscribeDeviceListChanges, AccountSubscribeFrame,
    AccountSubscribeFrameKind, AgentDraftPendingIntentContainer, NotificationDelta, RealmSyncEntry,
    StationCasAccountDataContainer,
};
use arkret_models_collaboration::sync_frames::current_results::AccountCurrentResult;
use arkret_wire::{
    CommitStreamHead, CommitStreamRef, CommittedEventRef, CommittedEventView, Event, EventKind,
    RealmCommit, RealmId, RealmStateSnapshot,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{Error, Result};

/// One Station commit with its exact stream coordinate and disclosure view.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CommittedDelta {
    pub realm_id: RealmId,
    pub view: CommittedEventView,
}

impl CommittedDelta {
    /// Build one delta from a committed-event view, preserving withheld Events.
    pub fn from_committed_event_view(realm_id: RealmId, view: CommittedEventView) -> Result<Self> {
        view.validate_shape()?;
        if view.commit().stream_ref.realm_id() != &realm_id {
            return Err(Error::Protocol(
                "timeline item belongs to another Realm".to_owned(),
            ));
        }
        Ok(Self { realm_id, view })
    }

    pub fn commit(&self) -> &RealmCommit {
        self.view.commit()
    }

    pub fn event(&self) -> Option<&Event> {
        self.view.reducer_input()
    }

    pub fn stream_ref(&self) -> &CommitStreamRef {
        &self.commit().stream_ref
    }

    pub fn stream_position(&self) -> u64 {
        self.commit().stream_position
    }

    pub fn committed_ref(&self) -> CommittedEventRef {
        let commit = self.commit();
        CommittedEventRef {
            event_id: commit.event_ref.clone(),
            commit_id: commit.commit_id.clone(),
            stream_ref: commit.stream_ref.clone(),
            stream_position: commit.stream_position,
        }
    }
}

/// Typed values the shared client engines emit toward a host adapter.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ClientEvent {
    /// Batch-level context that is never repeated by a granular variant.
    AccountUpdates(AccountUpdateContext),
    /// One Station commit on one independent stream. Its Event can be withheld.
    Committed(CommittedDelta),
    /// A decoded message-family Event with its parsed payload.
    Message(Box<DecodedMessage>),
    /// An Event the engine did not decode further.
    Event(Box<Event>),
    /// A Realm current-state frame, full or incremental. The Station selected
    /// and signed every entry; this is not a locally reduced view.
    RealmProjection {
        realm_id: RealmId,
        incremental: bool,
        value: Box<AccountCurrentResult>,
    },
    /// The current signed typed snapshot the Station published for a Realm.
    RealmSnapshot(Box<RealmStateSnapshot>),
    /// The Realm's visible projection was invalidated at a revision.
    RealmInvalidated {
        realm_id: RealmId,
        revision: u64,
    },
    Notification(NotificationDelta),
    /// An ephemeral per-device queue item; never part of a commit stream.
    ToDevice(Box<DeviceMessageEnvelope>),
    /// Producer-signed MLS Welcome from the shared recipient queue. Hosts must
    /// verify and durably admit it before acknowledging the account cursor.
    MlsWelcome(Box<arkret_wire::MlsWelcomeDelivery>),
}

/// Account-subscribe batch metadata that is not emitted as a granular event.
///
/// Realm deltas, to-device messages and notifications deliberately do not live
/// here: each is emitted once through its dedicated [`ClientEvent`] variant, so
/// durable inbox records never carry a duplicate payload.
///
/// Signals are not here either, and never will be: the account aggregate stream
/// carries durable account state only. Momentary announcements ride the
/// separate encrypted Signal rail and are consumed through
/// [`crate::SignalReceiver`].
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AccountUpdateContext {
    /// True when this batch came from a request without a continuation cursor.
    pub initial_catchup: bool,
    /// Realm details the Station reported as unavailable in this frame.
    pub unavailable_realms: Vec<RealmId>,
    pub to_device_ack_token: Option<String>,
    pub to_device_limited: bool,
    pub to_device_next_cursor: Option<String>,
    pub to_device_lost: bool,
    pub device_lists: AccountSubscribeDeviceListChanges,
    pub account_data: Vec<Event>,
    /// Cursor-covered Station-CAS Account Data baseline and deltas.
    #[serde(default)]
    pub station_cas_account_data: Vec<StationCasAccountDataContainer>,
    /// Dedicated controller-private pending-intent carrier, including its own
    /// delta or baseline paging coordinates.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_draft_pending_intents: Option<AgentDraftPendingIntentContainer>,
    pub partial: bool,
    /// True for a `catchup_complete` frame: the catch-up window has been
    /// fully delivered and later frames are live deltas.
    pub catchup_complete: bool,
}

/// Async host seam that turns a batch of engine-emitted [`ClientEvent`]s into
/// durable client state.
///
/// Contract: the engine awaits `project` for one checkpoint unit and advances
/// the durable cursor ONLY after it returns `Ok`. The projector's durable write
/// therefore gates cursor advance. A `project` error stops the loop without
/// advancing the cursor, so the unit is redelivered.
/// The runner awaits the caller-owned projector in place and never spawns it.
/// A caller that spawns the whole runner onto a multithreaded executor must
/// satisfy that executor's `Send` bound at the spawn site; a local UI executor
/// can project through `!Send` state without manufacturing thread safety.
pub trait ClientProjector {
    fn project(
        &self,
        batch: Vec<ClientEvent>,
    ) -> impl std::future::Future<Output = Result<()>> + '_;

    /// Hosts with a transactional inbox may persist the projection and cursor
    /// together. Return true when the checkpoint was committed atomically;
    /// the runner then does not write it a second time.
    fn project_checkpointed(
        &self,
        batch: Vec<ClientEvent>,
        _scope: crate::CursorScope,
        _checkpoint: crate::AccountCursorCheckpoint,
    ) -> impl std::future::Future<Output = Result<bool>> + '_ {
        async move {
            if !batch.is_empty() {
                self.project(batch).await?;
            }
            Ok(false)
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecodedMessage {
    pub event: Event,
    pub payload: MessageEventPayload,
}

#[derive(Clone, Debug)]
pub enum DecodedInbound {
    Message(Box<DecodedMessage>),
    Event(Box<Event>),
}

/// Decodes the message family into typed payloads and leaves every other kind
/// untouched.
#[derive(Clone, Copy, Debug, Default)]
pub struct InboundDecoder;

impl InboundDecoder {
    pub fn new() -> Self {
        Self
    }

    /// Decode, degrading to an undecoded Event when the payload does not parse.
    pub fn decode_event(&self, event: Event) -> DecodedInbound {
        match self.try_decode_event(event.clone()) {
            Ok(decoded) => decoded,
            Err(_) => DecodedInbound::Event(Box::new(event)),
        }
    }

    pub fn try_decode_event(&self, event: Event) -> Result<DecodedInbound> {
        match event.kind {
            EventKind::MessageCreate
            | EventKind::MessageRevise
            | EventKind::MessageRedact
            | EventKind::ReactionAdd
            | EventKind::ReactionRemove => {
                let payload = event.as_message_event_payload()?;
                Ok(DecodedInbound::Message(Box::new(DecodedMessage {
                    event,
                    payload,
                })))
            }
            _ => Ok(DecodedInbound::Event(Box::new(event))),
        }
    }
}

/// A Realm product projection payload with explicit replacement semantics.
/// A full frame replaces the cached product state; an incremental frame
/// overlays its delta while retaining state the Station legitimately omitted.
#[derive(Clone, Copy, Debug)]
pub enum RealmProjectionFrame<'a> {
    Full(&'a Value),
    Incremental(&'a Value),
}

/// Reconcile one Station Realm projection with its cached value.
pub fn reconcile_realm_projection(
    existing: Option<&Value>,
    frame: RealmProjectionFrame<'_>,
) -> Value {
    match frame {
        RealmProjectionFrame::Full(value) => value.clone(),
        RealmProjectionFrame::Incremental(delta) => {
            let mut merged = existing.cloned().unwrap_or(Value::Object(
                serde_json::Map::<String, Value>::new()
                    .into_iter()
                    .collect(),
            ));
            overlay(&mut merged, delta);
            merged
        }
    }
}

fn overlay(target: &mut Value, delta: &Value) {
    match (target, delta) {
        (Value::Object(target), Value::Object(delta)) => {
            for (key, value) in delta {
                if value.is_null() {
                    target.remove(key);
                    continue;
                }
                match target.get_mut(key) {
                    Some(existing) if existing.is_object() && value.is_object() => {
                        overlay(existing, value)
                    }
                    _ => {
                        target.insert(key.clone(), value.clone());
                    }
                }
            }
        }
        (target, delta) => *target = delta.clone(),
    }
}

/// The projection state a host keeps for one Realm: the last verified snapshot
/// and one independent tail per visible stream. No global position exists here.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct RealmProjectionState {
    pub snapshot: Option<RealmStateSnapshot>,
    pub product: Option<Value>,
    pub stream_positions: BTreeMap<CommitStreamRef, u64>,
}

impl RealmProjectionState {
    /// Install a Station-signed typed snapshot as the projection baseline.
    pub fn install_snapshot(&mut self, snapshot: RealmStateSnapshot) {
        for head in &snapshot.visible_stream_heads {
            self.stream_positions
                .insert(head.stream_ref.clone(), head.stream_position);
        }
        self.snapshot = Some(snapshot);
    }

    /// Apply one committed delta on its own stream. A delta must land exactly
    /// one position after the installed tail of that same stream; positions on
    /// other streams are irrelevant and are never consulted.
    pub fn apply(&mut self, delta: &CommittedDelta) -> Result<()> {
        let stream_ref = delta.stream_ref().clone();
        let position = delta.stream_position();
        match self.stream_positions.get(&stream_ref).copied() {
            Some(installed) if position == installed => return Ok(()),
            Some(installed) if position != installed + 1 => {
                return Err(Error::Protocol(format!(
                    "stream {stream_ref:?} advanced to {position} from {installed}"
                )));
            }
            _ => {}
        }
        self.stream_positions.insert(stream_ref, position);
        Ok(())
    }

    pub fn tail(&self, stream_ref: &CommitStreamRef) -> Option<u64> {
        self.stream_positions.get(stream_ref).copied()
    }

    pub fn apply_projection_frame(&mut self, frame: RealmProjectionFrame<'_>) {
        self.product = Some(reconcile_realm_projection(self.product.as_ref(), frame));
    }
}

/// Fan one validated aggregate frame into the ordered [`ClientEvent`] batch a
/// host consumes: batch context first, then per-stream deltas in the order the
/// Station delivered them, then to-device and notification items.
pub fn account_frame_to_client_events(
    frame: &AccountSubscribeFrame,
    initial_catchup: bool,
) -> Result<Vec<ClientEvent>> {
    frame.validate()?;
    let mut batch = Vec::new();
    let mut context = AccountUpdateContext {
        initial_catchup,
        partial: frame.partial.unwrap_or(false),
        catchup_complete: frame.kind == AccountSubscribeFrameKind::CatchupComplete,
        ..AccountUpdateContext::default()
    };
    if let Some(to_device) = &frame.to_device {
        context.to_device_ack_token = to_device.ack_token.clone();
        context.to_device_limited = to_device.limited.unwrap_or(false);
        context.to_device_next_cursor = to_device.next_cursor.clone();
        context.to_device_lost = to_device.lost.unwrap_or(false);
    }
    if let Some(device_lists) = &frame.device_lists {
        context.device_lists = device_lists.clone();
    }
    if let Some(account_data) = &frame.account_data {
        context.account_data = account_data.events.clone();
        if let Some(station_cas) = &account_data.station_cas {
            context.station_cas_account_data.push(station_cas.clone());
        }
    }
    context.agent_draft_pending_intents = frame.agent_draft_pending_intents.clone();

    let mut realm_events = Vec::new();
    if let Some(realms) = &frame.realms {
        for (realm, entry) in &realms.entries {
            let realm_id = RealmId::new(realm.clone())?;
            if entry.unavailable.is_some() {
                context.unavailable_realms.push(realm_id);
                continue;
            }
            realm_events.extend(realm_entry_to_client_events(&realm_id, entry)?);
        }
    }
    batch.push(ClientEvent::AccountUpdates(context));
    batch.extend(realm_events);

    for invalidation in frame.realm_invalidations.iter().flatten() {
        batch.push(ClientEvent::RealmInvalidated {
            realm_id: invalidation.realm_id.clone(),
            revision: invalidation.revision,
        });
    }
    if let Some(to_device) = &frame.to_device {
        for delivery in &to_device.deliveries {
            match delivery {
                RecipientDelivery::DeviceMessage { device_message } => {
                    batch.push(ClientEvent::ToDevice(Box::new(device_message.clone())));
                }
                RecipientDelivery::MlsWelcome { mls_welcome } => {
                    batch.push(ClientEvent::MlsWelcome(Box::new(mls_welcome.clone())));
                }
            }
        }
    }
    if let Some(notifications) = &frame.notifications {
        for item in &notifications.items {
            batch.push(ClientEvent::Notification(item.clone()));
        }
    }
    Ok(batch)
}

fn realm_entry_to_client_events(
    realm_id: &RealmId,
    entry: &RealmSyncEntry,
) -> Result<Vec<ClientEvent>> {
    validate_realm_entry_bindings(realm_id, entry)?;
    let decoder = InboundDecoder::new();
    let mut batch = Vec::new();
    if let Some(current) = &entry.current {
        batch.push(ClientEvent::RealmProjection {
            realm_id: realm_id.clone(),
            incremental: entry.baseline.is_none(),
            value: Box::new(current.clone()),
        });
    }
    if let Some(committed_events) = &entry.committed_events {
        for item in committed_events {
            let delta = CommittedDelta::from_committed_event_view(realm_id.clone(), item.clone())?;
            if let Some(event) = delta.event() {
                match decoder.decode_event(event.clone()) {
                    DecodedInbound::Message(message) => batch.push(ClientEvent::Message(message)),
                    DecodedInbound::Event(_) => {}
                }
            }
            batch.push(ClientEvent::Committed(delta));
        }
    }
    for event in entry
        .account_data
        .iter()
        .flat_map(|container| container.events.iter())
    {
        batch.push(ClientEvent::Event(Box::new(event.clone())));
    }
    Ok(batch)
}

/// Fail closed before a Station current/timeline projection crosses the host
/// boundary. SDK shape validation closes each individual object; these checks
/// bind the nested objects to the Realm map key and to one frozen set of
/// independently advancing stream heads.
fn validate_realm_entry_bindings(realm_id: &RealmId, entry: &RealmSyncEntry) -> Result<()> {
    let heads_belong_to_realm = |heads: &[CommitStreamHead]| {
        heads
            .iter()
            .all(|head| head.stream_ref.realm_id() == realm_id)
    };

    if let Some(current) = &entry.current
        && (&current.realm_id != realm_id || !heads_belong_to_realm(&current.stream_heads))
    {
        return Err(Error::Protocol(
            "typed current result is not bound to its Realm bucket".to_owned(),
        ));
    }

    if let Some(baseline) = &entry.baseline {
        if &baseline.coverage.realm_id != realm_id
            || !heads_belong_to_realm(&baseline.coverage.stream_heads)
            || baseline.complete != baseline.coverage.complete_for_authorized_streams
        {
            return Err(Error::Protocol(
                "typed current baseline coverage is not bound to its Realm bucket".to_owned(),
            ));
        }
        if let Some(current) = &entry.current
            && !same_stream_heads(&current.stream_heads, &baseline.coverage.stream_heads)
        {
            return Err(Error::Protocol(
                "typed current result and baseline cover different stream heads".to_owned(),
            ));
        }
    }

    if let Some(streams) = &entry.streams {
        let frozen_heads = entry
            .current
            .as_ref()
            .map(|current| &current.stream_heads)
            .or_else(|| {
                entry
                    .baseline
                    .as_ref()
                    .map(|baseline| &baseline.coverage.stream_heads)
            });
        for stream in streams {
            if stream.stream_ref.realm_id() != realm_id {
                return Err(Error::Protocol(
                    "timeline window is not bound to its Realm bucket".to_owned(),
                ));
            }
            match (
                stream.preview_only == Some(true),
                &stream.window_start_basis,
            ) {
                (true, Some(_)) => {
                    return Err(Error::Protocol(
                        "preview timeline window cannot also claim a snapshot basis".to_owned(),
                    ));
                }
                // A position-0 window has no basis. The consuming lane must
                // verify its complete chain from genesis before persistence.
                (false, None) => {}
                _ => {}
            }
            // A window may reference a snapshot from an earlier authority
            // generation than the typed current result, and sibling streams
            // may have distinct historical anchors. This shape validator must
            // not promote either claim to verified input: the consuming lane
            // checks each exact snapshot against the fresh authority chain.
            if let Some(frozen_heads) = frozen_heads {
                let Some(head) = frozen_heads
                    .iter()
                    .find(|head| head.stream_ref == stream.stream_ref)
                else {
                    return Err(Error::Protocol(
                        "timeline window stream is absent from typed current heads".to_owned(),
                    ));
                };
                if head.commit_id != stream.head_commit_ref {
                    return Err(Error::Protocol(
                        "timeline window and typed current disagree on the frozen stream head"
                            .to_owned(),
                    ));
                }
                let expected_next_position =
                    head.stream_position.checked_add(1).ok_or_else(|| {
                        Error::Protocol(
                            "typed current stream head cannot advance beyond the maximum position"
                                .to_owned(),
                        )
                    })?;
                if stream.next_position != expected_next_position {
                    return Err(Error::Protocol(
                        "timeline window next position does not follow its typed current head"
                            .to_owned(),
                    ));
                }
            }
        }
    }
    Ok(())
}

fn same_stream_heads(left: &[CommitStreamHead], right: &[CommitStreamHead]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .all(|head| right.iter().any(|candidate| candidate == head))
}

/// Fan a whole validated batch, preserving frame order.
pub fn account_batch_to_client_events(
    batch: &AccountSubscribeBatch,
    initial_catchup: bool,
) -> Result<Vec<ClientEvent>> {
    let mut events = Vec::new();
    for frame in &batch.frames {
        events.extend(account_frame_to_client_events(frame, initial_catchup)?);
    }
    Ok(events)
}

#[cfg(test)]
mod tests {
    use arkret_canonical::DigestSuite;
    use arkret_models_collaboration::sync_frames::account_subscribe::{
        AccountSubscribeRealms, RealmDetailBaseline,
    };
    use arkret_models_collaboration::sync_frames::account_sync::{
        RealmStreamWindow, StreamWindowStartBasis,
    };
    use arkret_models_collaboration::sync_frames::current_results::AccountCurrentCoverage;
    use arkret_wire::{
        CircleId, CommittedEventFullView, CommittedEventWithheldView, EventDisclosure,
        EventDisclosureStatus, EventId, RealmCommitId, RealmSnapshotId, ScopeRef, StrandId,
    };
    use serde_json::json;

    use super::*;
    use crate::test_fixtures::{commit, event, realm_id, realm_stream};

    fn message_event() -> Event {
        event(
            3,
            EventKind::MessageCreate,
            json!({
                "strand_id": StrandId::from_event_id(&EventId::from_digest(
                    DigestSuite::Sha256,
                    [2; 32],
                )),
                "track_name": "discussion",
                "content": {"kind": "ak.content.text", "body": "hello"}
            }),
        )
    }

    fn circle_stream() -> CommitStreamRef {
        CommitStreamRef::Circle {
            realm_id: realm_id(),
            circle_id: CircleId::from_event_id(&EventId::from_digest(DigestSuite::Sha256, [5; 32])),
        }
    }

    fn full_view(commit: RealmCommit, event: Event) -> CommittedEventView {
        CommittedEventView::Full(CommittedEventFullView { commit, event })
    }

    fn delta(event: Event, commit: RealmCommit) -> CommittedDelta {
        CommittedDelta::from_committed_event_view(realm_id(), full_view(commit, event)).unwrap()
    }

    fn stream_head(seed: u8) -> CommitStreamHead {
        let event = message_event();
        let commit = commit(seed, &event, realm_stream(), 1);
        CommitStreamHead {
            stream_ref: commit.stream_ref,
            stream_position: commit.stream_position,
            commit_id: commit.commit_id,
        }
    }

    fn current(heads: Vec<CommitStreamHead>) -> AccountCurrentResult {
        AccountCurrentResult {
            realm_id: realm_id(),
            governance_generation: 7,
            stream_heads: heads,
            entries: Vec::new(),
        }
    }

    #[test]
    fn decoder_parses_a_message_payload() {
        let decoded = InboundDecoder::new()
            .try_decode_event(message_event())
            .unwrap();
        let DecodedInbound::Message(message) = decoded else {
            panic!("the message family must decode");
        };
        assert!(matches!(message.payload, MessageEventPayload::Create(_)));
    }

    #[test]
    fn a_commit_that_does_not_bind_its_event_is_refused() {
        let first = message_event();
        let second = event(4, EventKind::ReactionAdd, json!({}));
        let item = full_view(commit(7, &first, realm_stream(), 1), second);
        assert!(CommittedDelta::from_committed_event_view(realm_id(), item).is_err());
    }

    #[test]
    fn a_withheld_event_preserves_its_commit_coordinate() {
        let event = message_event();
        let commit = commit(7, &event, realm_stream(), 1);
        let expected_event_id = commit.event_ref.clone();
        let item = CommittedEventView::Withheld(CommittedEventWithheldView {
            commit,
            event_disclosure: EventDisclosure {
                status: EventDisclosureStatus::Withheld,
            },
        });

        let delta = CommittedDelta::from_committed_event_view(realm_id(), item).unwrap();

        assert!(delta.event().is_none());
        assert_eq!(delta.stream_ref(), &realm_stream());
        assert_eq!(delta.stream_position(), 1);
        assert_eq!(delta.committed_ref().event_id, expected_event_id);
    }

    #[test]
    fn independent_streams_advance_without_a_shared_position() {
        let mut state = RealmProjectionState::default();
        let realm_event = message_event();
        state
            .apply(&delta(
                realm_event.clone(),
                commit(7, &realm_event, realm_stream(), 1),
            ))
            .unwrap();

        // A Circle stream starts at its own position 1 while the Realm stream
        // is already at 1; no global counter is consulted.
        let circle_stream = circle_stream();
        let CommitStreamRef::Circle { circle_id, .. } = &circle_stream else {
            unreachable!("the fixture constructs a Circle stream")
        };
        let mut circle_event = realm_event.clone();
        circle_event.scope_ref = ScopeRef::Circle {
            realm_id: realm_id(),
            circle_id: circle_id.clone(),
        };
        state
            .apply(&delta(
                circle_event.clone(),
                commit(8, &circle_event, circle_stream.clone(), 1),
            ))
            .unwrap();
        assert_eq!(state.tail(&realm_stream()), Some(1));
        assert_eq!(state.tail(&circle_stream), Some(1));
    }

    #[test]
    fn a_gap_on_one_stream_is_refused() {
        let mut state = RealmProjectionState::default();
        let realm_event = message_event();
        state
            .apply(&delta(
                realm_event.clone(),
                commit(7, &realm_event, realm_stream(), 1),
            ))
            .unwrap();
        assert!(
            state
                .apply(&delta(
                    realm_event.clone(),
                    commit(9, &realm_event, realm_stream(), 3),
                ))
                .is_err()
        );
    }

    #[test]
    fn a_current_result_from_another_realm_is_refused_before_host_projection() {
        let foreign_realm =
            RealmId::from_event_id(&EventId::from_digest(DigestSuite::Sha256, [0x66; 32]));
        let entry = RealmSyncEntry {
            current: Some(AccountCurrentResult {
                realm_id: foreign_realm,
                governance_generation: 7,
                stream_heads: Vec::new(),
                entries: Vec::new(),
            }),
            ..RealmSyncEntry::default()
        };

        assert!(realm_entry_to_client_events(&realm_id(), &entry).is_err());
    }

    #[test]
    fn current_and_complete_baseline_must_name_the_same_stream_heads() {
        let entry = RealmSyncEntry {
            current: Some(current(vec![stream_head(7)])),
            baseline: Some(RealmDetailBaseline {
                snapshot_cursor: "ak:cursor:current-baseline".to_owned(),
                cut_revision: 1,
                coverage: AccountCurrentCoverage {
                    realm_id: realm_id(),
                    stream_heads: vec![stream_head(8)],
                    complete_for_authorized_streams: true,
                },
                complete: true,
            }),
            ..RealmSyncEntry::default()
        };

        assert!(realm_entry_to_client_events(&realm_id(), &entry).is_err());
    }

    #[test]
    fn position_zero_timeline_window_has_no_snapshot_basis() {
        let head = stream_head(7);
        let entry = RealmSyncEntry {
            streams: Some(vec![RealmStreamWindow {
                stream_ref: head.stream_ref.clone(),
                head_commit_ref: head.commit_id,
                next_position: 1,
                limited: false,
                window_limit: 100,
                complete: true,
                preview_only: None,
                window_start_basis: None,
                e2ee_epoch: None,
            }]),
            ..RealmSyncEntry::default()
        };

        assert!(realm_entry_to_client_events(&realm_id(), &entry).is_ok());
    }

    #[test]
    fn preview_window_and_bound_current_result_reach_the_host_together() {
        let head = stream_head(7);
        let entry = RealmSyncEntry {
            streams: Some(vec![RealmStreamWindow {
                stream_ref: head.stream_ref.clone(),
                head_commit_ref: head.commit_id.clone(),
                next_position: 2,
                limited: false,
                window_limit: 100,
                complete: true,
                preview_only: Some(true),
                window_start_basis: None,
                e2ee_epoch: None,
            }]),
            current: Some(current(vec![head])),
            ..RealmSyncEntry::default()
        };

        let projected = realm_entry_to_client_events(&realm_id(), &entry).unwrap();
        assert!(matches!(
            projected.as_slice(),
            [ClientEvent::RealmProjection { .. }]
        ));
    }

    #[test]
    fn timeline_next_position_must_follow_the_typed_current_head() {
        let head = stream_head(7);
        let entry = RealmSyncEntry {
            streams: Some(vec![RealmStreamWindow {
                stream_ref: head.stream_ref.clone(),
                head_commit_ref: head.commit_id.clone(),
                next_position: head.stream_position,
                limited: false,
                window_limit: 100,
                complete: true,
                preview_only: Some(true),
                window_start_basis: None,
                e2ee_epoch: None,
            }]),
            current: Some(current(vec![head])),
            ..RealmSyncEntry::default()
        };

        assert!(realm_entry_to_client_events(&realm_id(), &entry).is_err());
    }

    #[test]
    fn maximum_typed_current_position_cannot_wrap_a_timeline_window() {
        let mut head = stream_head(7);
        head.stream_position = u64::MAX;
        let entry = RealmSyncEntry {
            streams: Some(vec![RealmStreamWindow {
                stream_ref: head.stream_ref.clone(),
                head_commit_ref: head.commit_id.clone(),
                next_position: 0,
                limited: false,
                window_limit: 100,
                complete: true,
                preview_only: Some(true),
                window_start_basis: None,
                e2ee_epoch: None,
            }]),
            current: Some(current(vec![head])),
            ..RealmSyncEntry::default()
        };

        assert!(realm_entry_to_client_events(&realm_id(), &entry).is_err());
    }

    #[test]
    fn historical_timeline_snapshot_generation_is_only_a_shape_claim() {
        let head = stream_head(7);
        let entry = RealmSyncEntry {
            streams: Some(vec![RealmStreamWindow {
                stream_ref: head.stream_ref.clone(),
                head_commit_ref: head.commit_id.clone(),
                next_position: 2,
                limited: false,
                window_limit: 100,
                complete: true,
                preview_only: None,
                window_start_basis: Some(StreamWindowStartBasis {
                    anchor_position: 0,
                    anchor_commit_ref: RealmCommitId::from_digest([0x66; 32]),
                    snapshot_ref: RealmSnapshotId::from_digest([0x77; 32]),
                    governance_generation: 0,
                    accepted_dependency_refs: None,
                }),
                e2ee_epoch: None,
            }]),
            current: Some(current(vec![head])),
            ..RealmSyncEntry::default()
        };

        assert!(realm_entry_to_client_events(&realm_id(), &entry).is_ok());
    }

    #[test]
    fn an_incremental_projection_frame_retains_omitted_state() {
        let cached = json!({"title": "Design", "topic": "layout", "members": {"count": 3}});
        let merged = reconcile_realm_projection(
            Some(&cached),
            RealmProjectionFrame::Incremental(&json!({"members": {"count": 4}})),
        );
        assert_eq!(merged["title"], json!("Design"));
        assert_eq!(merged["topic"], json!("layout"));
        assert_eq!(merged["members"]["count"], json!(4));
    }

    #[test]
    fn a_full_projection_frame_replaces_cached_state() {
        let cached = json!({"title": "Design", "topic": "layout"});
        let merged = reconcile_realm_projection(
            Some(&cached),
            RealmProjectionFrame::Full(&json!({"title": "Design"})),
        );
        assert_eq!(merged, json!({"title": "Design"}));
    }

    #[test]
    fn an_account_frame_emits_context_then_per_stream_deltas() {
        let event = message_event();
        let frame = AccountSubscribeFrame {
            kind: AccountSubscribeFrameKind::Delta,
            cursor: Some("ak:cursor:one".to_owned()),
            realms: Some(AccountSubscribeRealms {
                entries: BTreeMap::from([(
                    realm_id().to_string(),
                    RealmSyncEntry {
                        committed_events: Some(vec![full_view(
                            commit(7, &event, realm_stream(), 1),
                            event.clone(),
                        )]),
                        ..RealmSyncEntry::default()
                    },
                )]),
            }),
            to_device: None,
            device_lists: None,
            account_data: None,
            agent_draft_pending_intents: None,
            notifications: None,
            partial: None,
            priority: None,
            reconnect_after_ms: None,
            realm_list: None,
            realm_list_changes: None,
            baseline: None,
            realm_invalidations: None,
        };
        let batch = account_frame_to_client_events(&frame, true).unwrap();
        assert!(matches!(batch[0], ClientEvent::AccountUpdates(_)));
        assert!(matches!(batch[1], ClientEvent::Message(_)));
        let ClientEvent::Committed(delta) = &batch[2] else {
            panic!("the committed delta must carry its own stream coordinate");
        };
        assert_eq!(delta.stream_position(), 1);
        assert_eq!(delta.stream_ref(), &realm_stream());
    }
}
