//! Read markers and read receipts for the Garth client runtime.
//!
//! In addition to per-actor receipts and markers, this module hosts the
//! Realm `ReadReceiptPolicy` typed model (component cell
//! `ak.component.realm.read_receipt_policy.v1`) and the
//! `ReadReceiptPreferences` actor-private account-data model
//! (standard key `ak.read_receipt.preferences`). Together they implement
//! the disclosure / preference rules from spec
//! `discovery/read-receipts.md` §2.4-§2.5 and
//! `discovery/client-preferences.md` §3.6.
//!
//! Note: the `ak.strand.track.read_receipt_policy` cell was REMOVED in
//! arkret-spec revision `0a5ab85` (see
//! `arkret-spec/spec/v1/artifacts/registry/removed-event-kinds.json`).
//! Read receipts evaluate at the Realm level; create a child Realm or Circle
//! if a discussion needs an independent boundary.

pub use arkret_models_collaboration::objects::read_receipts::{
    ReadCursor, ReadCursorPosition, ReadReceipt, ReadReceiptDisclosure, ReadReceiptPolicy,
    ReadReceiptPolicyChildViolation, ReadReceiptVisibility,
};
use arkret_wire::ReadCursorId;
pub use arkret_wire::{
    READ_CURSOR_SCHEMA, READ_RECEIPT_SCHEMA, READ_RECEIPT_TYPE, ReadCursorScope, ReadReceiptScope,
    ReadScopeKind,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use crate::{DeviceId, Did, EventId, Hlc, RealmId, Result, StrandId};

fn cursor_scope_for_thread(thread_id: Option<&str>) -> ReadCursorScope {
    match thread_id {
        Some(thread_id) => ReadCursorScope::thread(thread_id),
        None => ReadCursorScope::realm(),
    }
}

fn receipt_scope_for_thread(thread_id: Option<&str>) -> ReadReceiptScope {
    match thread_id {
        Some(thread_id) => ReadReceiptScope::thread(thread_id),
        None => ReadReceiptScope::realm(),
    }
}

fn receipt_scope_thread_id(read_scope: &ReadReceiptScope) -> Option<String> {
    if read_scope.kind == ReadScopeKind::Thread {
        read_scope.object_ref.clone()
    } else {
        None
    }
}

/// Read receipt manager.
///
/// `dedup_window_ms` (default 1000 ms per `service-surface.md` §124)
/// controls the active de-duplication window. Calls to
/// [`Self::send_receipt`] within the window for the same
/// `(realm_id, user_id, thread_id)` collapse into the existing receipt
/// instead of producing a new one.
#[derive(Clone, Debug)]
pub struct ReceiptManager {
    markers: BTreeMap<(RealmId, Did, Option<String>), ReadCursor>,
    receipts: BTreeMap<(RealmId, EventId, Option<String>), Vec<ReadReceipt>>,
    thread_index: BTreeSet<(RealmId, Option<String>)>,
    last_send_at: BTreeMap<(RealmId, Did, Option<String>), DateTime<Utc>>,
    dedup_window_ms: i64,
}

impl Default for ReceiptManager {
    fn default() -> Self {
        Self {
            markers: BTreeMap::new(),
            receipts: BTreeMap::new(),
            thread_index: BTreeSet::new(),
            last_send_at: BTreeMap::new(),
            dedup_window_ms: 1000,
        }
    }
}

impl ReceiptManager {
    /// Create an empty manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Override the active de-duplication window. Use a window of
    /// 0 ms to disable de-duplication entirely.
    pub fn with_dedup_window_ms(mut self, ms: i64) -> Self {
        self.dedup_window_ms = ms.max(0);
        self
    }

    /// Set a read marker (a `ak.schema.read_cursor.v1` value).
    pub fn set_read_marker(
        &mut self,
        realm_id: RealmId,
        actor_id: Did,
        device_id: DeviceId,
        event_id: EventId,
        hlc: Hlc,
        thread_id: Option<String>,
    ) -> Result<ReadCursor> {
        let marker = ReadCursor {
            id: ReadCursorId::new(format!("ak:read_cursor:{}", uuid::Uuid::now_v7()))?,
            schema: READ_CURSOR_SCHEMA.to_owned(),
            actor_id: actor_id.clone(),
            device_id,
            realm_id: realm_id.clone(),
            read_scope: cursor_scope_for_thread(thread_id.as_deref()),
            position: ReadCursorPosition { event_id, hlc },
            updated_at: Utc::now(),
        };
        self.thread_index
            .insert((realm_id.clone(), thread_id.clone()));
        self.markers
            .insert((realm_id, actor_id, thread_id), marker.clone());
        Ok(marker)
    }

    /// Get a read marker.
    pub fn read_marker(
        &self,
        realm_id: &RealmId,
        actor_id: &Did,
        thread_id: Option<&str>,
    ) -> Option<&ReadCursor> {
        self.markers.get(&(
            realm_id.clone(),
            actor_id.clone(),
            thread_id.map(str::to_owned),
        ))
    }

    /// Send/store a read receipt (a `ak.schema.read_receipt.v1` value).
    ///
    /// Honors the active de-duplication window: when a receipt for the
    /// same `(realm_id, actor_id, thread_id)` was issued within the
    /// configured window, the new send is treated as a no-op and the
    /// existing latest receipt is returned. Set `dedup_window_ms = 0`
    /// to disable.
    pub fn send_receipt(
        &mut self,
        realm_id: RealmId,
        actor_id: Did,
        event_id: EventId,
        hlc: Option<Hlc>,
        thread_id: Option<String>,
    ) -> ReadReceipt {
        let now = Utc::now();
        let dedup_key = (realm_id.clone(), actor_id.clone(), thread_id.clone());
        if self.dedup_window_ms > 0
            && let Some(prev) = self.last_send_at.get(&dedup_key)
            && now.signed_duration_since(*prev).num_milliseconds() < self.dedup_window_ms
            && let Some(latest) = self
                .receipts
                .get(&(realm_id.clone(), event_id.clone(), thread_id.clone()))
                .and_then(|stack| stack.last())
        {
            return latest.clone();
        }
        let receipt = ReadReceipt {
            receipt_type: READ_RECEIPT_TYPE.to_owned(),
            schema: READ_RECEIPT_SCHEMA.to_owned(),
            realm_id: realm_id.clone(),
            actor_id,
            event_id: event_id.clone(),
            hlc,
            read_scope: receipt_scope_for_thread(thread_id.as_deref()),
            created_at: now,
        };
        self.thread_index
            .insert((realm_id.clone(), thread_id.clone()));
        self.last_send_at.insert(dedup_key, now);
        self.receipts
            .entry((realm_id, event_id, thread_id))
            .or_default()
            .push(receipt.clone());
        receipt
    }

    /// Process a receipt received from sync.
    pub fn process_receipt(&mut self, receipt: ReadReceipt) {
        let thread_id = receipt_scope_thread_id(&receipt.read_scope);
        self.thread_index
            .insert((receipt.realm_id.clone(), thread_id.clone()));
        self.receipts
            .entry((
                receipt.realm_id.clone(),
                receipt.event_id.clone(),
                thread_id,
            ))
            .or_default()
            .push(receipt);
    }

    /// Receipts for one event/thread.
    pub fn receipts_for_event(
        &self,
        realm_id: &RealmId,
        event_id: &EventId,
        thread_id: Option<&str>,
    ) -> Vec<&ReadReceipt> {
        self.receipts
            .get(&(
                realm_id.clone(),
                event_id.clone(),
                thread_id.map(str::to_owned),
            ))
            .map(|receipts| receipts.iter().collect())
            .unwrap_or_default()
    }

    /// Known thread positions for a Realm.
    pub fn thread_positions(&self, realm_id: &RealmId) -> Vec<Option<String>> {
        self.thread_index
            .iter()
            .filter(|(candidate, _)| candidate == realm_id)
            .map(|(_, thread_id)| thread_id.clone())
            .collect()
    }
}

// ─── Read Receipt disclosure policy (spec read-receipts.md §2.5) ────────

/// `disclosure` field of `ak.realm.read_receipt_policy`. Soft policy —
// Policy wire types are owned by arkret-models-collaboration; Garth only
// evaluates them together with the actor-private preferences below.
// ─── Account-data preferences (client-preferences.md §3.6) ─────────────

/// One scope's worth of read-receipt preference.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopePref {
    /// `None` = inherit (use the next layer up). `Some(true)` /
    /// `Some(false)` = explicit override.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub send: Option<bool>,
    /// `None` = inherit (use the next layer up). `Some(true)` /
    /// `Some(false)` = explicit local-rendering override.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display: Option<bool>,
}

impl ScopePref {
    pub fn send(send: bool) -> Self {
        Self {
            send: Some(send),
            display: None,
        }
    }

    pub fn display(display: bool) -> Self {
        Self {
            send: None,
            display: Some(display),
        }
    }

    pub fn send_and_display(send: bool, display: bool) -> Self {
        Self {
            send: Some(send),
            display: Some(display),
        }
    }
}

/// Account-data value for `ak.read_receipt.preferences`.
///
/// Resolution order is (strand -> Realm -> default); the first non-`None`
/// field wins independently for `send` and `display`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadReceiptPreferences {
    #[serde(default)]
    pub default: ScopePref,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub realms: BTreeMap<RealmId, ScopePref>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub strands: BTreeMap<StrandId, ScopePref>,
}

impl ReadReceiptPreferences {
    /// Standard account-data key.
    pub const ACCOUNT_DATA_KEY: &'static str = "ak.read_receipt.preferences";

    /// Effective `send` for a `(strand, Realm)` scope. If neither strand
    /// nor Realm declares an override, falls back to `default.send`,
    /// then to the protocol-wide default `true` (from spec §2.4 the
    /// global default sends receipts unless the user opts out).
    pub fn effective_send(&self, strand_id: Option<&StrandId>, realm_id: Option<&RealmId>) -> bool {
        if let Some(fid) = strand_id
            && let Some(pref) = self.strands.get(fid)
            && let Some(send) = pref.send
        {
            return send;
        }
        if let Some(sid) = realm_id
            && let Some(pref) = self.realms.get(sid)
            && let Some(send) = pref.send
        {
            return send;
        }
        self.default.send.unwrap_or(true)
    }

    /// Effective local rendering preference for displaying other members'
    /// read receipts. This only gates UI rendering; it does not change
    /// receipt subscription, fanout, unread calculation, or read cursors.
    pub fn effective_display(
        &self,
        strand_id: Option<&StrandId>,
        realm_id: Option<&RealmId>,
    ) -> bool {
        if let Some(fid) = strand_id
            && let Some(pref) = self.strands.get(fid)
            && let Some(display) = pref.display
        {
            return display;
        }
        if let Some(sid) = realm_id
            && let Some(pref) = self.realms.get(sid)
            && let Some(display) = pref.display
        {
            return display;
        }
        self.default.display.unwrap_or(true)
    }
}

/// Outcome of [`should_send_receipt`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiptDecision {
    /// User opted in (or default) AND policy is `Optional`/`Required`.
    Send,
    /// User opted out AND policy is `Optional` or absent.
    Skip,
    /// Realm/Strand policy is `Required` — overrides any user preference.
    ForcedSend,
    /// Realm/Strand policy is `Disabled` — overrides any user preference.
    ForcedSkip,
}

impl ReceiptDecision {
    /// `true` for [`Self::Send`] and [`Self::ForcedSend`].
    pub fn is_send(self) -> bool {
        matches!(self, Self::Send | Self::ForcedSend)
    }

    /// `true` when the decision is policy-locked and the UI MUST NOT
    /// allow the user to flip the per-scope toggle.
    pub fn is_locked(self) -> bool {
        matches!(self, Self::ForcedSend | Self::ForcedSkip)
    }
}

/// Compute whether to generate a `ak.receipt.read` for the given scope.
///
/// `policy` is the effective policy at the Realm
/// boundary. Pass `None` to represent "no policy declared" (treated as
/// `ReadReceiptPolicy::default()` = `Optional` / `Members`).
pub fn should_send_receipt(
    prefs: &ReadReceiptPreferences,
    policy: Option<&ReadReceiptPolicy>,
    strand_id: Option<&StrandId>,
    realm_id: Option<&RealmId>,
) -> ReceiptDecision {
    let disclosure = policy.map(|p| p.disclosure).unwrap_or_default();
    match disclosure {
        ReadReceiptDisclosure::Required => ReceiptDecision::ForcedSend,
        ReadReceiptDisclosure::Disabled => ReceiptDecision::ForcedSkip,
        ReadReceiptDisclosure::Optional => {
            if prefs.effective_send(strand_id, realm_id) {
                ReceiptDecision::Send
            } else {
                ReceiptDecision::Skip
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn did(name: &str) -> Did {
        Did::new(format!("did:webvh:z6mkfixture:{name}.example")).unwrap()
    }

    #[test]
    fn receipts_manage_markers_and_threads() {
        let realm_id = RealmId::new("ak:realm:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
        let alice = did("alice");
        let device = DeviceId::new("ak:device:01904100-0000-7000-8000-000000000005").unwrap();
        let event = EventId::new("ak:event:01904100-0000-7000-8000-834e21b98552").unwrap();
        let hlc = Hlc::new("01970e589d21-0004-a13f9c2e").unwrap();
        let mut manager = ReceiptManager::new();

        let marker = manager
            .set_read_marker(
                realm_id.clone(),
                alice.clone(),
                device,
                event.clone(),
                hlc.clone(),
                Some("t1".to_owned()),
            )
            .unwrap();
        assert_eq!(marker.schema, READ_CURSOR_SCHEMA);
        assert_eq!(marker.read_scope.kind, ReadScopeKind::Thread);
        assert!(manager.read_marker(&realm_id, &alice, Some("t1")).is_some());

        let receipt = manager.send_receipt(
            realm_id.clone(),
            alice,
            event.clone(),
            Some(hlc.clone()),
            Some("t1".to_owned()),
        );
        assert_eq!(receipt.receipt_type, READ_RECEIPT_TYPE);
        assert_eq!(receipt.schema, READ_RECEIPT_SCHEMA);
        manager.send_receipt(
            realm_id.clone(),
            did("bob"),
            event.clone(),
            Some(hlc),
            Some("t1".to_owned()),
        );

        assert_eq!(
            manager
                .receipts_for_event(&realm_id, &event, Some("t1"))
                .len(),
            2
        );
        assert_eq!(
            manager.thread_positions(&realm_id),
            vec![Some("t1".to_owned())]
        );
    }

    fn realm() -> RealmId {
        RealmId::new("ak:realm:01904100-0000-7000-8000-906bb8c30a80").unwrap()
    }

    fn strand() -> StrandId {
        StrandId::new("ak:strand:01904100-0000-7000-8000-c1fe7e18f6fe").unwrap()
    }

    #[test]
    fn prefs_default_send_when_unset_is_true() {
        let prefs = ReadReceiptPreferences::default();
        assert!(prefs.effective_send(None, None));
    }

    #[test]
    fn prefs_default_display_when_unset_is_true() {
        let prefs = ReadReceiptPreferences::default();
        assert!(prefs.effective_display(None, None));
    }

    #[test]
    fn prefs_explicit_default_overrides_protocol_default() {
        let mut prefs = ReadReceiptPreferences::default();
        prefs.default.send = Some(false);
        assert!(!prefs.effective_send(None, None));
        prefs.default.display = Some(false);
        assert!(!prefs.effective_display(None, None));
    }

    #[test]
    fn prefs_resolution_strand_overrides_realm_overrides_default() {
        let mut prefs = ReadReceiptPreferences::default();
        prefs.default.send = Some(true);
        prefs.default.display = Some(true);
        prefs
            .realms
            .insert(realm(), ScopePref::send_and_display(false, false));
        prefs
            .strands
            .insert(strand(), ScopePref::send_and_display(true, true));

        // strand overrides Realm
        assert!(prefs.effective_send(Some(&strand()), Some(&realm())));
        assert!(prefs.effective_display(Some(&strand()), Some(&realm())));
        // Realm overrides default when no strand override
        assert!(!prefs.effective_send(None, Some(&realm())));
        assert!(!prefs.effective_display(None, Some(&realm())));
        // default applies when nothing else matches
        let other_realm = RealmId::new("ak:realm:01904100-0000-7000-8000-de7b2d3c4472").unwrap();
        assert!(prefs.effective_send(None, Some(&other_realm)));
        assert!(prefs.effective_display(None, Some(&other_realm)));
    }

    #[test]
    fn should_send_required_forces_send_overrides_user() {
        let mut prefs = ReadReceiptPreferences::default();
        prefs.default.send = Some(false);
        let policy = ReadReceiptPolicy {
            disclosure: ReadReceiptDisclosure::Required,
            ..Default::default()
        };
        let decision = should_send_receipt(&prefs, Some(&policy), None, None);
        assert_eq!(decision, ReceiptDecision::ForcedSend);
        assert!(decision.is_send());
        assert!(decision.is_locked());
    }

    #[test]
    fn should_send_disabled_forces_skip_overrides_user() {
        let mut prefs = ReadReceiptPreferences::default();
        prefs.default.send = Some(true);
        let policy = ReadReceiptPolicy {
            disclosure: ReadReceiptDisclosure::Disabled,
            ..Default::default()
        };
        let decision = should_send_receipt(&prefs, Some(&policy), None, None);
        assert_eq!(decision, ReceiptDecision::ForcedSkip);
        assert!(!decision.is_send());
        assert!(decision.is_locked());
    }

    #[test]
    fn should_send_optional_defers_to_user_pref() {
        let mut prefs = ReadReceiptPreferences::default();
        prefs.default.send = Some(true);
        let policy = ReadReceiptPolicy::default();
        let decision = should_send_receipt(&prefs, Some(&policy), None, None);
        assert_eq!(decision, ReceiptDecision::Send);
        assert!(!decision.is_locked());

        prefs.default.send = Some(false);
        let decision = should_send_receipt(&prefs, Some(&policy), None, None);
        assert_eq!(decision, ReceiptDecision::Skip);
    }

    #[test]
    fn should_send_no_policy_treats_as_optional() {
        let mut prefs = ReadReceiptPreferences::default();
        prefs.default.send = Some(true);
        let decision = should_send_receipt(&prefs, None, None, None);
        assert_eq!(decision, ReceiptDecision::Send);
    }

    #[test]
    fn policy_default_matches_spec_defaults() {
        let policy = ReadReceiptPolicy::default();
        assert_eq!(policy.disclosure, ReadReceiptDisclosure::Optional);
        assert_eq!(policy.visibility, ReadReceiptVisibility::Members);
        assert!(policy.scope_overrides_allowed);
        assert!(!policy.allow_child_privacy_tightening_against_required);
    }

    #[test]
    fn policy_rejects_unknown_fields() {
        let value = serde_json::json!({
            "disclosure": "required",
            "visibility": "members",
            "allow_child_privacy_tightening_against_required_typo": true
        });
        assert!(serde_json::from_value::<ReadReceiptPolicy>(value).is_err());
    }

    #[test]
    fn child_policy_allows_only_privacy_tightening_by_default() {
        let parent = ReadReceiptPolicy {
            disclosure: ReadReceiptDisclosure::Optional,
            visibility: ReadReceiptVisibility::Members,
            ..Default::default()
        };
        let child = ReadReceiptPolicy {
            disclosure: ReadReceiptDisclosure::Disabled,
            visibility: ReadReceiptVisibility::Private,
            ..Default::default()
        };
        parent.validate_child_policy(&child).unwrap();

        let looser_visibility = ReadReceiptPolicy {
            visibility: ReadReceiptVisibility::Public,
            ..child
        };
        assert_eq!(
            parent.validate_child_policy(&looser_visibility),
            Err(ReadReceiptPolicyChildViolation::VisibilityLoosened)
        );

        let looser_disclosure = ReadReceiptPolicy {
            disclosure: ReadReceiptDisclosure::Required,
            ..child
        };
        assert_eq!(
            parent.validate_child_policy(&looser_disclosure),
            Err(ReadReceiptPolicyChildViolation::DisclosurePrivacyLoosened)
        );
    }

    #[test]
    fn child_policy_respects_required_compliance_floor() {
        let parent = ReadReceiptPolicy {
            disclosure: ReadReceiptDisclosure::Required,
            visibility: ReadReceiptVisibility::Members,
            ..Default::default()
        };
        let child = ReadReceiptPolicy {
            disclosure: ReadReceiptDisclosure::Disabled,
            visibility: ReadReceiptVisibility::Private,
            ..Default::default()
        };
        assert_eq!(
            parent.validate_child_policy(&child),
            Err(ReadReceiptPolicyChildViolation::ComplianceFloorViolated)
        );

        let parent_with_escape = ReadReceiptPolicy {
            allow_child_privacy_tightening_against_required: true,
            ..parent
        };
        parent_with_escape.validate_child_policy(&child).unwrap();
    }

    #[test]
    fn child_policy_requires_exact_inheritance_when_overrides_disabled() {
        let parent = ReadReceiptPolicy {
            disclosure: ReadReceiptDisclosure::Optional,
            visibility: ReadReceiptVisibility::Members,
            scope_overrides_allowed: false,
            ..Default::default()
        };
        parent.validate_child_policy(&parent).unwrap();

        let child = ReadReceiptPolicy {
            disclosure: ReadReceiptDisclosure::Disabled,
            visibility: ReadReceiptVisibility::Members,
            ..parent
        };
        assert_eq!(
            parent.validate_child_policy(&child),
            Err(ReadReceiptPolicyChildViolation::ScopeOverridesDisabled)
        );
    }

    #[test]
    fn prefs_serde_roundtrip() {
        let mut prefs = ReadReceiptPreferences::default();
        prefs.default.send = Some(true);
        prefs.default.display = Some(false);
        prefs
            .realms
            .insert(realm(), ScopePref::send_and_display(false, true));
        prefs.strands.insert(strand(), ScopePref::display(false));
        let json = serde_json::to_string(&prefs).unwrap();
        assert!(json.contains("\"display\""));
        let back: ReadReceiptPreferences = serde_json::from_str(&json).unwrap();
        assert_eq!(back, prefs);
    }
}
