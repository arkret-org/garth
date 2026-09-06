//! Pure readers over one account-subscribe step and the Realm projections it
//! carries.
//!
//! Everything here answers a question `client-sync.md` already settles from the
//! frame alone — is this batch empty, does this Realm entry carry durable
//! projection state, which accepted events form the membership-removal
//! frontier, which `(actor, device)` pairs a projection's proofs name — so it
//! is decided identically by every client. No host store, transport, clock or
//! UI participates; the inputs are the decoded SDK frame types and the JSON
//! projection bodies derived from them.

use std::collections::{BTreeMap, BTreeSet};

use arkret_models_collaboration::events_payloads::realm::RealmProfile;
use arkret_models_collaboration::governance::holder_quarantine::{
    HolderQuarantine, HolderQuarantineEntry, HolderQuarantineSurfaceKind,
};
use arkret_wire::{
    AccountDataKey, AccountId, ActorId, DeviceId, Did, Event, EventId, EventKind, PredicateOp,
    REALM_PROFILE_CELL, event_kind_str, project_did_to_core_id,
};
use serde_json::Value;

use crate::protocol::sync::{RealmUpdate, SyncUpdates};
use crate::protocol::{AccountDataRow, DeviceMessageEnvelope, DidCoreId, Error, Result};

/// True when an account-subscribe step carries nothing an ingest could act on.
pub fn account_updates_are_empty(updates: &SyncUpdates) -> bool {
    updates.realm_updates.is_empty()
        && updates.malformed_realm_ids.is_empty()
        && updates.to_device.is_empty()
        && updates.to_device_ack_token.is_none()
        && !updates.to_device_limited
        && updates.to_device_next_cursor.is_none()
        && !updates.to_device_lost
        && updates.device_lists.changed_ids.is_empty()
        && updates.device_lists.left_ids.is_empty()
        && updates.account_data.is_empty()
        && updates.station_cas_account_data.is_empty()
        && updates.notifications.is_empty()
        && updates.agent_signer_evidence.is_empty()
        && !updates.partial
}

/// True when a Realm update carries at least one projection surface worth
/// persisting, as opposed to a bare cursor advance.
pub fn realm_update_has_durable_projection(update: &RealmUpdate) -> bool {
    let entry = &update.entry;
    entry.timeline.is_some()
        || entry.state_at_window_start.is_some()
        || entry.state.is_some()
        || entry.state_after.is_some()
        || entry.account_data.is_some()
        || entry.summary.is_some()
        || entry.member_roster.is_some()
        || entry.unread_notifications.is_some()
        || entry.event_states.is_some()
        || entry.bottoms.is_some()
}

/// The to-device cursor a client may continue from on the standalone queue
/// endpoint.
///
/// `client-sync.md` §10.0: account subscribe is the primary receive path. The
/// standalone queue endpoint is only a continuation path when the account frame
/// explicitly reports a limited batch.
pub fn to_device_backfill_cursor(updates: &SyncUpdates) -> Option<String> {
    updates
        .to_device_limited
        .then(|| updates.to_device_next_cursor.clone())
        .flatten()
}

/// The canonical top-level `state[].events` log of one Realm projection body.
pub fn sync_realm_state_events(body: &Value) -> Vec<Value> {
    body.get("state")
        .and_then(|state| state.get("events"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

/// Discussion message events ride a SEPARATE projection array from the state
/// log: `timeline.events[]`.
pub fn sync_realm_timeline_events(body: &Value) -> Vec<Value> {
    body.get("timeline")
        .and_then(|timeline| timeline.get("events"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

/// Accepted leave/ban membership frontier for one effective scope.
///
/// The Realm-default scope takes every accepted `ak.member.state` transition to
/// `leave`/`ban`. A Circle scope additionally takes the `ak.circle.member.state`
/// transitions naming that Circle, because a Realm departure removes the
/// principal from every Circle in it while a Circle departure does not touch
/// the Realm roster.
pub fn membership_removal_frontier(projection: &Value, circle_id: Option<&str>) -> Vec<EventId> {
    let mut membership_frontier = sync_realm_state_events(projection)
        .into_iter()
        .filter(|event| {
            let kind = event
                .get("kind")
                .or_else(|| event.get("event_kind"))
                .and_then(Value::as_str);
            let payload = event
                .get("payload")
                .or_else(|| event.get("content"))
                .unwrap_or(&Value::Null);
            match kind {
                Some(kind) if kind == EventKind::MemberState.as_str() => true,
                Some(kind) if kind == EventKind::CircleMemberState.as_str() => circle_id
                    .is_some_and(|circle_id| {
                        payload.get("circle_id").and_then(Value::as_str) == Some(circle_id)
                    }),
                _ => false,
            }
        })
        .filter(|event| {
            let payload = event
                .get("payload")
                .or_else(|| event.get("content"))
                .unwrap_or(&Value::Null);
            matches!(
                payload
                    .get("membership")
                    .or_else(|| payload.get("target_state"))
                    .or_else(|| payload.get("state"))
                    .and_then(Value::as_str),
                Some("leave" | "ban")
            )
        })
        .filter_map(|event| {
            event
                .get("event_id")
                .and_then(Value::as_str)
                .and_then(|event_id| EventId::new(event_id.to_owned()).ok())
        })
        .collect::<Vec<_>>();
    membership_frontier.sort();
    membership_frontier.dedup();
    membership_frontier
}

/// The active roster plus the removal frontier a Realm-default MLS Remove
/// obligation is derived from, or `None` when the projection cannot answer.
pub fn realm_membership_removal_basis(
    projection: &Value,
) -> Option<(BTreeSet<ActorId>, Vec<EventId>)> {
    // A truncated roster is not negative membership evidence. Waiting for a
    // complete projection is required before comparing it with the MLS tree.
    if projection
        .get("member_roster_entries_limited")
        .and_then(Value::as_bool)
        != Some(false)
    {
        return None;
    }
    let active_members = projection
        .get("member_roster_entries")?
        .as_array()?
        .iter()
        .filter(|member| member.get("membership").and_then(Value::as_str) == Some("join"))
        .map(|member| serde_json::from_value::<ActorId>(member.get("actor_id")?.clone()).ok())
        .collect::<Option<BTreeSet<_>>>()?;
    let membership_frontier = membership_removal_frontier(projection, None);
    (!membership_frontier.is_empty()).then_some((active_members, membership_frontier))
}

/// Recursively scan a projection `Value` for `ak.member.identity.update`
/// proofs, extracting `(controller_principal_id, device_id)` from each
/// `member_identity.proof.verification_method`. Depth-bounded to mirror the
/// persistent-event scanner.
pub fn collect_member_identity_proof_devices_from_value(
    value: &Value,
    depth: usize,
    out: &mut BTreeSet<(String, String)>,
) {
    const MAX_DEPTH: usize = 12;
    if depth > MAX_DEPTH {
        return;
    }
    match value {
        Value::Object(map) => {
            // A `member_identity` object carries `actor_id` + `proof`.
            if let Some(proof) = map.get("proof").and_then(Value::as_object)
                && let Some(vm) = proof.get("verification_method").and_then(Value::as_str)
                && let Some((controller, device)) = split_verification_method(vm)
            {
                // Bind to the object's own actor_id when present (defence in
                // depth: the controller already equals the asserter at verify
                // time, but we prefetch whatever the proof names so resolution
                // can run).
                out.insert((controller, device));
            }
            for nested in map.values() {
                collect_member_identity_proof_devices_from_value(nested, depth + 1, out);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_member_identity_proof_devices_from_value(item, depth + 1, out);
            }
        }
        _ => {}
    }
}

/// Split a `did:method:identifier#device` verification-method URL into its
/// controller DID and device fragment. Returns `None` when there is no
/// fragment (no device selector).
pub fn split_verification_method(verification_method: &str) -> Option<(String, String)> {
    let (controller, fragment) = verification_method.split_once('#')?;
    let controller = controller
        .split_once('?')
        .map_or(controller, |(head, _)| head)
        .trim();
    let device = fragment.trim();
    if controller.is_empty() || device.is_empty() {
        return None;
    }
    Some((controller.to_owned(), device.to_owned()))
}

/// The `(actor, device)` directory pairs a step's Realm projections name in
/// their proofs.
///
/// §2.10.3 — a minimal-metadata Realm's content authorship never forms a
/// directory pair; its authors verify against the MLS LeafNode instead, so the
/// caller supplies that classification.
pub fn collect_persistent_proof_sender_devices(
    realm_projections: &BTreeMap<String, Value>,
    is_minimal_metadata_realm: &impl Fn(&str) -> bool,
) -> Vec<(String, String)> {
    let mut pairs = BTreeSet::<(String, String)>::new();
    for (realm_id, body) in realm_projections {
        if is_minimal_metadata_realm(realm_id) {
            continue;
        }
        collect_proof_sender_devices_from_value(body, 0, &mut pairs);
    }
    pairs.into_iter().collect()
}

/// Recursively collect proof-bearing `(actor, device)` pairs from one
/// projection body.
pub fn collect_proof_sender_devices_from_value(
    value: &Value,
    depth: usize,
    pairs: &mut BTreeSet<(String, String)>,
) {
    if depth > 32 {
        return;
    }
    match value {
        Value::Object(object) => {
            if let Some((actor, device)) = proof_bearing_sender_device(object) {
                pairs.insert((actor, device));
            }
            for child in object.values() {
                collect_proof_sender_devices_from_value(child, depth + 1, pairs);
            }
        }
        Value::Array(values) => {
            for child in values {
                collect_proof_sender_devices_from_value(child, depth + 1, pairs);
            }
        }
        _ => {}
    }
}

/// The `(account, device)` a proof-bearing projection object names, when its
/// proof controller matches the accountable principal.
pub fn proof_bearing_sender_device(
    object: &serde_json::Map<String, Value>,
) -> Option<(String, String)> {
    let proofs = object
        .get("proofs")
        .and_then(Value::as_array)
        .filter(|proofs| !proofs.is_empty())?;
    let actor = object
        .get("actor_id")
        .or_else(|| object.get("sender_actor_id"))
        .and_then(|value| serde_json::from_value::<ActorId>(value.clone()).ok())?;
    // Delegated Events keep the accountable principal
    // in `actor_id`, while `executed_by` identifies the runtime that actually
    // signed the envelope. Keep this selector byte-aligned with the chat proof
    // verifier when that signer is a real directory-backed device. Independent
    // Agent MLS endpoints use their authenticated LeafNode key instead
    // and deliberately do not form a device-directory lookup here.
    let proof_subject = object
        .get("executed_by")
        .and_then(|value| serde_json::from_value::<ActorId>(value.clone()).ok())
        .unwrap_or(actor);
    let account_id = proof_subject.as_account_id()?;
    let proof_controller = proofs.iter().find_map(|proof| {
        let method = proof.get("verification_method").and_then(Value::as_str)?;
        let controller = {
            let no_query = method.split_once('?').map_or(method, |(head, _)| head);
            no_query.split_once('#').map_or(no_query, |(head, _)| head)
        };
        let controller = Did::new(controller.to_owned()).ok()?;
        let controller_core = project_did_to_core_id(&controller).ok()?;
        (controller_core == account_id.principal_id).then_some(controller)
    })?;
    let device = object
        .get("device_id")
        .or_else(|| object.get("sender_device_id"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|device| !device.is_empty())
        .map(str::to_owned)
        .or_else(|| {
            proof_sender_device_from_verification_method(object, proof_controller.as_str())
        })?;
    Some((account_id.to_string(), device))
}

/// The device fragment of the first proof whose controller is `actor`.
pub fn proof_sender_device_from_verification_method(
    object: &serde_json::Map<String, Value>,
    actor: &str,
) -> Option<String> {
    object
        .get("proofs")
        .and_then(Value::as_array)?
        .iter()
        .filter_map(|proof| proof.get("verification_method").and_then(Value::as_str))
        .find_map(|method| {
            let no_query = method
                .split_once('?')
                .map(|(head, _)| head)
                .unwrap_or(method);
            let (controller, fragment) = no_query.split_once('#')?;
            (controller == actor && fragment.starts_with("ak:device:")).then(|| fragment.to_owned())
        })
}

/// Raw inbox durability is enough for ordinary device messages, but an MLS
/// Welcome is destructive-consumer state: acknowledging it before the MLS
/// runtime imports and durably snapshots the group makes the only join secret
/// disappear from the server queue. The Welcome bootstrap owns that ACK after
/// successful apply (or an explicitly verified stale replay).
pub fn to_device_batch_safe_for_ingest_ack(messages: &[DeviceMessageEnvelope]) -> bool {
    !messages
        .iter()
        .any(|message| message.kind.as_str() == event_kind_str::MLS_WELCOME)
}

/// True when any Realm projection in this step carries an accepted
/// `ak.device.revoke` naming this device.
pub fn response_revokes_local_device(
    realm_projections: &BTreeMap<String, Value>,
    principal_id: &DidCoreId,
    device_id: &str,
) -> bool {
    let device_id = device_id.trim();
    if device_id.is_empty() {
        return false;
    }
    realm_projections.values().any(|body| {
        sync_realm_state_events(body).iter().any(|event| {
            let kind = event
                .get("kind")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let Some(payload) = event.get("payload") else {
                return false;
            };
            kind == event_kind_str::DEVICE_REVOKE
                && payload.get("principal_id").and_then(Value::as_str)
                    == Some(principal_id.as_str())
                && payload.get("device_id").and_then(Value::as_str) == Some(device_id)
        })
    })
}

/// The control-event kind of a discussion-state projection entry, across the
/// field names a projection may carry it under.
pub fn discussion_state_control_event_kind(event: &Value) -> Option<&str> {
    event
        .get("kind")
        .or_else(|| event.get("event_kind"))
        .or_else(|| event.get("type"))
        .and_then(Value::as_str)
}

/// True when a discussion-state projection entry is one of the message /
/// reaction / pin control events an ingest folds.
pub fn discussion_state_event_is_ingestable(event: &Value) -> bool {
    matches!(
        discussion_state_control_event_kind(event),
        Some(
            event_kind_str::MESSAGE_CREATE
                | event_kind_str::MESSAGE_REVISE
                | event_kind_str::MESSAGE_REDACT
                | event_kind_str::REACTION_ADD
                | event_kind_str::REACTION_REMOVE
                | event_kind_str::PIN_ADD
                | event_kind_str::PIN_REMOVE
                | event_kind_str::PIN_REORDER
        )
    )
}

/// The device that signed an accepted human Event, when its producer proof is
/// controlled by the Event's own signing principal.
pub fn accepted_human_event_signing_device(event: &Event) -> Option<DeviceId> {
    let proof = event.proofs.iter().find_map(|proof| proof.as_producer())?;
    let (controller, fragment) = proof.verification_method.as_str().split_once('#')?;
    let controller = Did::new(controller.to_owned()).ok()?;
    let controller = project_did_to_core_id(&controller).ok()?;
    if &controller != event.actor_id.signing_principal_id() {
        return None;
    }
    DeviceId::new(fragment.to_owned()).ok()
}

/// The `(event_id, expected_head, payload)` triple an `ak.realm.profile` Event
/// contributes to the profile cell chain, or `None` when it is not a
/// single-guard head-equality write.
pub fn realm_profile_event_entry(event: &Event) -> Option<(String, Value, Value)> {
    if event.kind != EventKind::RealmProfile {
        return None;
    }
    let payload = serde_json::to_value(&event.payload).ok()?;
    serde_json::from_value::<RealmProfile>(payload.clone()).ok()?;
    let guards = event
        .preconditions
        .iter()
        .filter(|guard| guard.cell_id.as_str() == REALM_PROFILE_CELL)
        .collect::<Vec<_>>();
    let [guard] = guards.as_slice() else {
        return None;
    };
    if guard.predicate.op != PredicateOp::HeadEq {
        return None;
    }
    Some((
        event.event_id.to_string(),
        guard.predicate.value.clone()?,
        payload,
    ))
}

/// Walk the realm-profile cell chain forward from `start`, consuming every
/// entry whose expected head matches. A fork (two candidates for one head)
/// aborts: `cas_register` admits exactly one successor, so an ambiguous set is
/// not a chain this client may collapse.
pub fn advance_realm_profile_chain(
    start: Value,
    entries: &[(String, Value, Value)],
) -> Option<(Value, usize)> {
    let mut current = start;
    let mut remaining = (0..entries.len()).collect::<Vec<_>>();
    let mut consumed = 0;
    loop {
        let candidates = remaining
            .iter()
            .copied()
            .filter(|index| entries[*index].1 == current)
            .collect::<Vec<_>>();
        match candidates.as_slice() {
            [] => return Some((current, consumed)),
            [next] => {
                current = entries[*next].2.clone();
                remaining.retain(|index| index != next);
                consumed += 1;
            }
            _ => return None,
        }
    }
}

/// The event kind of a projection entry, across the two field names a
/// projection may carry it under.
pub fn projection_event_kind(event: &Value) -> &str {
    event
        .get("kind")
        .and_then(Value::as_str)
        .or_else(|| event.get("type").and_then(Value::as_str))
        .unwrap_or("")
}

/// Visit every identity-carrying event in one Realm projection `body`, in the
/// two shapes a client receives them:
///
/// - the canonical top-level `state[]` event log;
/// - inline `identity_events[]` on each member roster entry, where the entry is passed as the actor
///   fallback.
pub fn for_each_projection_identity_event(
    body: &Value,
    mut visit: impl FnMut(&Value, Option<&Value>),
) {
    for event in &sync_realm_state_events(body) {
        visit(event, None);
    }
    for source in [
        body.get("members"),
        body.get("summary").and_then(|s| s.get("members")),
    ]
    .into_iter()
    .flatten()
    {
        let Some(items) = source.as_array() else {
            continue;
        };
        for entry in items {
            if let Some(events) = entry.get("identity_events").and_then(Value::as_array) {
                for event in events {
                    visit(event, Some(entry));
                }
            }
        }
    }
}

/// The holder's pending-review inbox, split by the closed `surface_kind`
/// discriminator.
///
/// `identity/consent-model.md` section 6.1.1 gives the two branches different
/// terminal semantics, so a client that renders them as one list is wrong even
/// when both look like "someone is waiting on me": accepting an
/// `invite_delivery` builds a section 3.2 grant and MAY additionally accept the
/// original invite, while accepting a `consent_request` builds the grant and
/// stops -- that branch has no original object, and the requester retries the
/// normal path once the grant is active.
///
/// A quarantine entry is not a consent cell. It grants nothing, it is not
/// addressed by a `consent_id`, and it never appears in
/// `ak.self.consent.query.cells.v1`. Nor is it the Contact surface: a Contact
/// request has its own `pending_incoming` state and deliberately produces no
/// entry here.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HolderQuarantineReview<'a> {
    /// Quarantined private invite deliveries, oldest first.
    pub invite_deliveries: Vec<&'a HolderQuarantineEntry>,
    /// Quarantined `ak.self.consent.command.request.v1` submissions, oldest
    /// first.
    pub consent_requests: Vec<&'a HolderQuarantineEntry>,
}

impl<'a> HolderQuarantineReview<'a> {
    /// Split one decoded cell. The cell already stores its entries oldest
    /// first, so each branch keeps that order.
    #[must_use]
    pub fn from_cell(cell: &'a HolderQuarantine) -> Self {
        let mut review = Self::default();
        for entry in &cell.quarantine_entries {
            match entry.surface_kind() {
                HolderQuarantineSurfaceKind::InviteDelivery => {
                    review.invite_deliveries.push(entry);
                }
                HolderQuarantineSurfaceKind::ConsentRequest => {
                    review.consent_requests.push(entry);
                }
            }
        }
        review
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.invite_deliveries.is_empty() && self.consent_requests.is_empty()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.invite_deliveries.len() + self.consent_requests.len()
    }
}

/// Decode the holder's `ak.account.holder_quarantine` cell out of one
/// Station-CAS account-data row.
///
/// The row comes from the authoritative register: the account-subscribe
/// `account_data.station_cas` complete baseline and its cursor-covered
/// upsert/remove deltas. `holder_account_id` is the authenticated holder, never
/// an identity read out of the first entry, so a cell addressed to another
/// account fails instead of being rendered.
pub fn holder_quarantine_cell(
    row: &AccountDataRow,
    holder_account_id: &AccountId,
) -> Result<HolderQuarantine> {
    if row.account_data_key != AccountDataKey::ACCOUNT_HOLDER_QUARANTINE {
        return Err(Error::Protocol(format!(
            "{} is not the holder quarantine cell",
            row.account_data_key
        )));
    }
    let cell: HolderQuarantine = serde_json::from_value(row.content.clone())
        .map_err(|error| Error::Protocol(format!("invalid holder quarantine cell: {error}")))?;
    cell.validate_holder(holder_account_id)
        .map_err(|error| Error::Protocol(format!("holder quarantine binding: {error}")))?;
    Ok(cell)
}

#[cfg(test)]
mod tests {
    use arkret_wire::{Hlc, RealmId, ScopeRef};
    use serde_json::json;

    use super::*;

    fn station() -> DidCoreId {
        DidCoreId::new("ak:did_core:web:principal.example").unwrap()
    }

    fn account_actor(principal: &str) -> ActorId {
        ActorId::account(AccountId::new(
            DidCoreId::new(principal).unwrap(),
            station(),
        ))
    }

    fn account_actor_string(did: &str) -> String {
        let core = project_did_to_core_id(&Did::new(did.to_owned()).unwrap()).unwrap();
        AccountId::new(core, station()).to_string()
    }

    fn empty_updates() -> SyncUpdates {
        SyncUpdates {
            realm_updates: Vec::new(),
            malformed_realm_ids: Vec::new(),
            to_device: Vec::new(),
            to_device_ack_token: None,
            to_device_limited: false,
            to_device_next_cursor: None,
            to_device_lost: false,
            device_lists: crate::protocol::AccountSubscribeDeviceListChanges {
                changed_ids: Vec::new(),
                left_ids: Vec::new(),
            },
            account_data: Vec::new(),
            station_cas_account_data: Vec::new(),
            notifications: Vec::new(),
            agent_signer_evidence: Vec::new(),
            partial: false,
        }
    }

    fn realm() -> RealmId {
        RealmId::new("ak:realm:AZQnaSleDidYaYIvfwYy3au5gnd_DSinxyUHEl7ewtxk").unwrap()
    }

    fn fixture_event(kind: &str, payload: Value) -> Event {
        arkret_wire::test_support::raw_event(
            kind,
            ScopeRef::Realm { realm_id: realm() },
            DidCoreId::new("ak:did_core:webvh:z6mkfixture:alice.example").unwrap(),
            station(),
            1,
            Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
            payload,
        )
        .unwrap()
    }

    fn to_device_message(kind: &str) -> DeviceMessageEnvelope {
        let content = if kind == "ak.key.verification.request" {
            json!({
                "transaction_id": "txn-1",
                "from_device_id": "ak:device:0196419b-0000-7000-8000-000000000001",
                "methods": ["ak.key.verification.sas_v1"],
                "timestamp": "2026-07-15T00:00:00.000Z",
                "expires_at": "2026-07-15T00:10:00.000Z"
            })
        } else {
            json!({"request_id": "request-1"})
        };
        serde_json::from_value(json!({
            "device_message_id": "ak:device_message:0196419b-0000-7000-8000-000000000003",
            "kind": kind,
            "sender_account_id": {
                "principal_id": "ak:did_core:webvh:z6mkfixture:alice.example",
                "station_id": "ak:did_core:webvh:z6mkfixture:station.example"
            },
            "sender_device_id": "ak:device:0196419b-0000-7000-8000-000000000001",
            "recipient_account_id": {
                "principal_id": "ak:did_core:webvh:z6mkfixture:bob.example",
                "station_id": "ak:did_core:webvh:z6mkfixture:station.example"
            },
            "recipient_device_id": "ak:device:0196419b-0000-7000-8000-000000000002",
            "sent_at": "2026-07-15T00:00:00.000Z",
            "expires_at": "2026-07-15T00:10:00.000Z",
            "content": content
        }))
        .unwrap()
    }

    #[test]
    fn realm_profile_chain_settles_independently_of_delivery_order() {
        let initial = json!({
            "schema": "ak.schema.realm_profile.v1",
            "title": "Initial"
        });
        let updated = json!({
            "schema": "ak.schema.realm_profile.v1",
            "title": "Updated",
            "summary": "Visible"
        });
        let cleared = json!({
            "schema": "ak.schema.realm_profile.v1",
            "title": "Updated"
        });
        let entries = vec![
            ("event-c".to_owned(), updated.clone(), cleared.clone()),
            ("event-a".to_owned(), Value::Null, initial.clone()),
            ("event-b".to_owned(), initial, updated),
        ];

        let settled = advance_realm_profile_chain(Value::Null, &entries).unwrap();

        assert_eq!(settled, (cleared, 3));
    }

    #[test]
    fn realm_mls_removal_basis_requires_complete_roster_and_accepted_frontier() {
        let removal_event = "ak:event:AXYOPItXAzTTu_rqIAINR7C7AvNSR5bjjBslclmJ9ZVt";
        let projection = json!({
            "member_roster_entries_limited": false,
            "member_roster_entries": [{
                "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:webvh:z6mkfixture:alice.example","station_id":"ak:did_core:web:principal.example"}},
                "membership": "join"
            }],
            "state": {"events": [{
                "event_id": removal_event,
                "kind": "ak.member.state",
                "payload": {
                    "member_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:webvh:z6mkfixture:bob.example","station_id":"ak:did_core:web:principal.example"}},
                    "membership": "ban"
                }
            }]}
        });

        let (active, frontier) = realm_membership_removal_basis(&projection).unwrap();
        assert_eq!(
            active,
            BTreeSet::from([account_actor("ak:did_core:webvh:z6mkfixture:alice.example")])
        );
        assert_eq!(
            frontier,
            vec![EventId::new(removal_event.to_owned()).unwrap()]
        );

        let mut truncated = projection;
        truncated["member_roster_entries_limited"] = json!(true);
        assert!(realm_membership_removal_basis(&truncated).is_none());
    }

    #[test]
    fn frontier_only_account_step_is_projection_empty() {
        let mut updates = empty_updates();
        assert!(account_updates_are_empty(&updates));

        updates.partial = true;
        assert!(!account_updates_are_empty(&updates));
    }

    /// A sync entry with no durable projection must not trigger a Circle scan.
    /// The retired plaintext `ephemeral` bucket is not even decodable, so the
    /// only surviving distinction is durable projection state versus none.
    #[test]
    fn circle_scan_ignores_realm_updates_without_a_durable_projection() {
        assert!(
            serde_json::from_value::<crate::protocol::RealmSyncEntry>(json!({
                "ephemeral": {"events": []}
            }))
            .is_err(),
            "the deleted plaintext ephemeral bucket must not decode on a Realm sync entry"
        );
        let projection_empty = RealmUpdate {
            realm_id: realm(),
            entry: serde_json::from_value(json!({})).expect("empty Realm update"),
        };
        assert!(!realm_update_has_durable_projection(&projection_empty));

        let durable = RealmUpdate {
            realm_id: realm(),
            entry: serde_json::from_value(json!({
                "state": {"events": [serde_json::to_value(fixture_event(
                    "ak.circle.member.remove",
                    json!({"circle_id": "ak:circle:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-"})
                )).unwrap()]}
            }))
            .expect("durable Realm update"),
        };
        assert!(realm_update_has_durable_projection(&durable));
    }

    #[test]
    fn standalone_to_device_pull_requires_limited_account_batch() {
        let mut updates = empty_updates();
        updates.to_device_next_cursor = Some("ak:cursor:page-2".to_owned());
        assert_eq!(to_device_backfill_cursor(&updates), None);

        updates.to_device_limited = true;
        assert_eq!(
            to_device_backfill_cursor(&updates).as_deref(),
            Some("ak:cursor:page-2")
        );
    }

    #[test]
    fn minimal_metadata_realms_never_form_directory_prefetch_pairs() {
        // section 2.10.3: a proof-bearing persistent event inside a
        // minimal-metadata Realm must not contribute an `(actor, device)`
        // `keys/query` prefetch pair; the same shape in an ordinary Realm does.
        // This is the receiver-side "principal_directory_queries = 0"
        // guarantee: no pair, no query.
        let pairwise_envelope = json!({
            "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:key:z6MkpairwiseAlice","station_id":"ak:did_core:web:principal.example"}},
            "device_id": "ak:device:0196419b-0000-7000-8000-0000000000aa",
            "proofs": [{
                "verification_method": "did:key:z6MkpairwiseAlice#z6MkpairwiseAuthorKey"
            }],
        });
        let directory_envelope = json!({
            "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:bob.example","station_id":"ak:did_core:web:principal.example"}},
            "device_id": "ak:device:0196419b-0000-7000-8000-0000000000bb",
            "proofs": [{
                "verification_method": "did:web:bob.example#key-1"
            }],
        });
        let minimal_realm = "ak:realm:AR6sSnzYzneKDHwNTaEOztzBtLnt8geLs44CLQ9Bw2WW";
        let ordinary_realm = "ak:realm:Af9zSmEjGsepWRH4BZAZH6au69G5_e_iQ6s383Z9--fe";
        let mut projections = BTreeMap::new();
        projections.insert(
            minimal_realm.to_owned(),
            json!({ "events": [pairwise_envelope] }),
        );
        projections.insert(
            ordinary_realm.to_owned(),
            json!({ "events": [directory_envelope] }),
        );

        let pairs = collect_persistent_proof_sender_devices(&projections, &|realm_id: &str| {
            realm_id == minimal_realm
        });
        assert_eq!(
            pairs,
            vec![(
                account_actor_string("did:web:bob.example"),
                "ak:device:0196419b-0000-7000-8000-0000000000bb".to_owned()
            )]
        );

        // Control: without the minimal-metadata classification both realms
        // would have contributed pairs.
        let all = collect_persistent_proof_sender_devices(&projections, &|_: &str| false);
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn mls_welcome_requires_consumer_ack_after_group_state_is_durable() {
        assert!(!to_device_batch_safe_for_ingest_ack(&[to_device_message(
            "ak.mls.welcome"
        )]));
        assert!(!to_device_batch_safe_for_ingest_ack(&[
            to_device_message("ak.key.verification.request"),
            to_device_message("ak.mls.welcome"),
        ]));
        assert!(to_device_batch_safe_for_ingest_ack(&[to_device_message(
            "ak.key.verification.request"
        )]));
    }

    #[test]
    fn persistent_proof_sender_device_collection_dedupes_nested_events() {
        let mut projections = BTreeMap::new();
        projections.insert(
            "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19".to_owned(),
            json!({
                "timeline": {
                    "events": [
                        {
                            "event": {
                                "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:alice.example","station_id":"ak:did_core:web:principal.example"}},
                                "device_id": "ak:device:01904100-0000-7000-8000-000000000001",
                                "proofs": [{"verification_method": "did:web:alice.example#ak:device:01904100-0000-7000-8000-000000000001"}]
                            }
                        },
                        {
                            "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:alice.example","station_id":"ak:did_core:web:principal.example"}},
                            "device_id": "ak:device:01904100-0000-7000-8000-000000000001",
                            "proofs": [{"verification_method": "did:web:alice.example#ak:device:01904100-0000-7000-8000-000000000001"}]
                        },
                        {
                            "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:bob.example","station_id":"ak:did_core:web:principal.example"}},
                            "proofs": [{"verification_method": "did:web:bob.example#device"}]
                        },
                        {
                            "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:carol.example","station_id":"ak:did_core:web:principal.example"}},
                            "proofs": [{"verification_method": "did:web:carol.example#ak:device:01904100-0000-7000-8000-000000000002"}]
                        }
                    ]
                }
            }),
        );
        assert_eq!(
            collect_persistent_proof_sender_devices(&projections, &|_: &str| false),
            vec![
                (
                    account_actor_string("did:web:alice.example"),
                    "ak:device:01904100-0000-7000-8000-000000000001".to_owned()
                ),
                (
                    account_actor_string("did:web:carol.example"),
                    "ak:device:01904100-0000-7000-8000-000000000002".to_owned()
                )
            ]
        );
    }

    #[test]
    fn service_executor_does_not_fabricate_an_account_device_query() {
        let controller = "ak:did_core:web:bob.example";
        let agent = "ak:did_core:web:bob.example:agent:assistant";
        let agent_full = "did:web:bob.example:agent:assistant";
        let device = "ak:device:01904100-0000-7000-8000-0000000000aa";
        let mut projections = BTreeMap::new();
        projections.insert(
            "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19".to_owned(),
            json!({
                "timeline": {
                    "events": [{
                        "actor_id": {"kind":"account","account_id":{
                            "principal_id":controller,
                            "station_id":"ak:did_core:web:principal.example"
                        }},
                        "executed_by": {"kind":"service","service_id":agent},
                        "device_id": device,
                        "proofs": [{
                            "verification_method": format!("{agent_full}#{device}")
                        }]
                    }]
                }
            }),
        );

        assert!(collect_persistent_proof_sender_devices(&projections, &|_: &str| false).is_empty());
    }

    #[test]
    fn accepted_device_revoke_targets_current_local_device() {
        let actor = DidCoreId::new("ak:did_core:web:alice.example").unwrap();
        let device = "ak:device:0196419b-0000-7000-8000-000000000001";
        let mut projections = BTreeMap::new();
        projections.insert(
            "ak:realm:AQM8rE4gp8l4axkSbbb9_dkqwWE8ZPYHwFsC24o2mrIL".to_owned(),
            json!({
                "state": { "events": [{
                    "event_id": "ak:event:AV624IkuHj3HmxAYE6uyYmBa4Est3gGGdnOsjn71z5L2",
                    "kind": "ak.device.revoke",
                    "payload": {
                        "principal_id": actor.as_str(),
                        "device_id": device,
                        "revoked_by": "ak:device:0196419b-0000-7000-8000-000000000004",
                        "revoked_at": "2026-07-14T02:00:00.000Z",
                        "reason": "device_loss"
                    }
                }]}
            }),
        );

        assert!(response_revokes_local_device(&projections, &actor, device));
        assert!(!response_revokes_local_device(
            &projections,
            &actor,
            "ak:device:0196419b-0000-7000-8000-0000000000ff"
        ));
        let other_actor = DidCoreId::new("ak:did_core:web:mallory.example").unwrap();
        assert!(!response_revokes_local_device(
            &projections,
            &other_actor,
            device
        ));
    }

    #[test]
    fn malformed_or_non_state_device_revoke_does_not_trigger_local_wipe() {
        let actor = DidCoreId::new("ak:did_core:web:alice.example").unwrap();
        let device = "ak:device:0196419b-0000-7000-8000-000000000001";
        let mut projections = BTreeMap::new();
        projections.insert(
            "ak:realm:AQM8rE4gp8l4axkSbbb9_dkqwWE8ZPYHwFsC24o2mrIL".to_owned(),
            json!({
                "state": { "events": [{
                    "kind": "ak.device.revoke",
                    "principal_id": actor.as_str(),
                    "device_id": device
                }]},
                "timeline": { "events": [{
                    "kind": "ak.device.revoke",
                    "payload": { "principal_id": actor.as_str(), "device_id": device }
                }]}
            }),
        );

        assert!(!response_revokes_local_device(&projections, &actor, device));
    }

    fn quarantine_holder() -> AccountId {
        AccountId::new(
            DidCoreId::new("ak:did_core:web:holder.example").unwrap(),
            station(),
        )
    }

    fn quarantine_row(entries: Value) -> AccountDataRow {
        AccountDataRow {
            account_data_key: AccountDataKey::ACCOUNT_HOLDER_QUARANTINE.to_owned(),
            revision: 3,
            content: json!({
                "schema": "ak.schema.holder_quarantine.v1",
                "updated_at": "2026-09-05T12:00:00.000Z",
                "quarantine_entries": entries,
            }),
            updated_at: "2026-09-05T12:00:00.000Z".parse().unwrap(),
        }
    }

    #[test]
    fn a_restored_quarantine_cell_reviews_each_surface_separately() {
        let row = quarantine_row(json!([
            {
                "entry_digest": format!("sha256:{}", "a".repeat(64)),
                "account_id": {
                    "principal_id": "ak:did_core:web:holder.example",
                    "station_id": "ak:did_core:web:principal.example"
                },
                "source_peer_principal_id": "ak:did_core:web:inviter.example",
                "source_id": "ak:did_core:web:peer-station.example",
                "surface_kind": "invite_delivery",
                "consent_scope": "invite",
                "introduction_kind": "locator_ref",
                "effective_kind": "locator_ref",
                "trust_tier": "high",
                "invite_event_id": "ak:event:AS8XThowW7JnZc80U10gJh-_lqkA-iSQ-LAvBXj6_9O5",
                "request_digest": format!("sha256:{}", "b".repeat(64)),
                "idempotency_key_digest": format!("sha256:{}", "c".repeat(64)),
                "received_at": "2026-09-05T10:00:00.000Z",
                "expires_at": "2026-10-05T10:00:00.000Z"
            },
            {
                "entry_digest": format!("sha256:{}", "d".repeat(64)),
                "account_id": {
                    "principal_id": "ak:did_core:web:holder.example",
                    "station_id": "ak:did_core:web:principal.example"
                },
                "source_peer_principal_id": "ak:did_core:web:asker.example",
                "source_id": "ak:did_core:web:principal.example",
                "surface_kind": "consent_request",
                "consent_scope": "direct_message",
                "received_at": "2026-09-05T11:00:00.000Z",
                "expires_at": "2026-10-05T11:00:00.000Z"
            }
        ]));
        let cell = holder_quarantine_cell(&row, &quarantine_holder()).unwrap();
        let review = HolderQuarantineReview::from_cell(&cell);
        assert_eq!(review.len(), 2);
        assert_eq!(review.invite_deliveries.len(), 1);
        assert_eq!(review.consent_requests.len(), 1);
        assert!(
            review.invite_deliveries[0]
                .surface
                .invite_event_id()
                .is_some()
        );
        assert!(
            review.consent_requests[0]
                .surface
                .invite_event_id()
                .is_none()
        );
        assert!(
            review.consent_requests[0]
                .consent_request_live_key()
                .is_some()
        );
    }

    #[test]
    fn a_cell_addressed_to_another_holder_is_refused() {
        let row = quarantine_row(json!([]));
        let foreign = AccountId::new(
            DidCoreId::new("ak:did_core:web:someone-else.example").unwrap(),
            station(),
        );
        // An empty cell still belongs to one exact account, but it carries no
        // entry to disagree with, so only a wrong key is refusable here.
        holder_quarantine_cell(&row, &foreign).unwrap();
        let mut wrong_key = row;
        wrong_key.account_data_key = "ak.account.invite_receive_policy".to_owned();
        holder_quarantine_cell(&wrong_key, &quarantine_holder())
            .expect_err("another account-data key is not this carrier");
    }
}
