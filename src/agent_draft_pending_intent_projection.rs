//! Durable controller-private projection for Agent draft pending intents.
//!
//! This state is reduced only from the dedicated account-subscribe carrier.
//! Baseline paging coordinates belong to this channel alone; incomplete
//! baselines remain staged while live deltas continue to update installed
//! rows. Removal tombstones remain durable so an old page cannot resurrect
//! ciphertext or another live value.

use std::collections::{BTreeMap, BTreeSet};

use arkret_models_collaboration::sync_frames::account_subscribe::{
    AccountSubscribeFrame, AccountSubscribeFrameKind, AgentDraftPendingIntentChange,
    AgentDraftPendingIntentContainer,
};
use arkret_models_collaboration::sync_frames::demand_sync::AccountBaselineChannel;
use arkret_wire::AccountId;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{Error, Result};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentDraftPendingIntentProjectionUpdate {
    pub installed_changed: bool,
    pub baseline_staged: bool,
    pub baseline_completed: bool,
    pub projection_position: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredPendingIntent {
    value: Value,
    removed: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingBaseline {
    snapshot_cursor: String,
    snapshot_cut_position: u64,
    next_page_offset: Option<u64>,
    rows: BTreeMap<String, StoredPendingIntent>,
    seen: BTreeSet<String>,
    live_overrides: BTreeSet<String>,
}

/// Durable pending-intent current set for one controller account.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentDraftPendingIntentProjection {
    controller_account_id: AccountId,
    #[serde(default)]
    rows: BTreeMap<String, StoredPendingIntent>,
    #[serde(default)]
    pending_baseline: Option<PendingBaseline>,
    #[serde(default)]
    projection_position: Option<u64>,
    #[serde(default)]
    last_delta_fingerprint: Option<Value>,
}

impl AgentDraftPendingIntentProjection {
    pub fn new(controller_account_id: AccountId) -> Self {
        Self {
            controller_account_id,
            rows: BTreeMap::new(),
            pending_baseline: None,
            projection_position: None,
            last_delta_fingerprint: None,
        }
    }

    pub fn controller_account_id(&self) -> &AccountId {
        &self.controller_account_id
    }

    /// Visible live or terminal-redacted rows. Internal removal tombstones are
    /// deliberately excluded.
    pub fn rows(&self) -> impl Iterator<Item = &Value> {
        self.rows
            .values()
            .filter(|record| !record.removed)
            .map(|record| &record.value)
    }

    pub fn len(&self) -> usize {
        self.rows().count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn projection_position(&self) -> Option<u64> {
        self.projection_position
    }

    pub fn pending_snapshot_cursor(&self) -> Option<&str> {
        self.pending_baseline
            .as_ref()
            .map(|baseline| baseline.snapshot_cursor.as_str())
    }

    pub fn pending_next_page_offset(&self) -> Option<u64> {
        self.pending_baseline
            .as_ref()
            .and_then(|baseline| baseline.next_page_offset)
    }

    /// Abandon only channel-private paging state. Installed rows and retained
    /// removal tombstones survive until a fresh baseline completes.
    pub fn reset_pending_baseline(&mut self) {
        self.pending_baseline = None;
        self.projection_position = None;
        self.last_delta_fingerprint = None;
    }

    /// Validate and atomically reduce one account frame.
    pub fn apply_frame(
        &mut self,
        frame: &AccountSubscribeFrame,
    ) -> Result<AgentDraftPendingIntentProjectionUpdate> {
        frame.validate()?;
        let mut staged = self.clone();
        let update = staged.apply_valid_frame(frame)?;
        *self = staged;
        Ok(update)
    }

    fn apply_valid_frame(
        &mut self,
        frame: &AccountSubscribeFrame,
    ) -> Result<AgentDraftPendingIntentProjectionUpdate> {
        if frame.kind == AccountSubscribeFrameKind::ResyncRequired {
            self.reset_pending_baseline();
            return Ok(self.update(false, false, false));
        }
        let Some(container) = &frame.agent_draft_pending_intents else {
            return Ok(self.update(false, false, false));
        };
        match container {
            AgentDraftPendingIntentContainer::Delta {
                projection_position,
                items,
            } => self.apply_delta(*projection_position, items, container),
            AgentDraftPendingIntentContainer::Baseline {
                snapshot_cut_position,
                page_offset,
                next_page_offset,
                items,
            } => {
                let segment = frame.baseline.as_ref().ok_or_else(|| {
                    Error::Protocol("pending-intent baseline lacks its segment".to_owned())
                })?;
                self.apply_baseline(
                    &segment.snapshot_cursor,
                    *snapshot_cut_position,
                    *page_offset,
                    *next_page_offset,
                    items,
                    segment.completes(AccountBaselineChannel::AgentDraftPendingIntents),
                )
            }
        }
    }

    fn apply_delta(
        &mut self,
        position: u64,
        items: &[AgentDraftPendingIntentChange],
        container: &AgentDraftPendingIntentContainer,
    ) -> Result<AgentDraftPendingIntentProjectionUpdate> {
        let fingerprint = serde_json::to_value(container)?;
        if let Some(installed) = self.projection_position {
            if position < installed {
                return Err(Error::Protocol(
                    "pending-intent projection position regressed".to_owned(),
                ));
            }
            if position == installed {
                if self.last_delta_fingerprint.as_ref() == Some(&fingerprint) {
                    return Ok(self.update(false, false, false));
                }
                return Err(Error::Protocol(
                    "pending-intent delta changed at the same projection position".to_owned(),
                ));
            }
        }

        let before = self.rows.clone();
        let mut staged_changed = false;
        for item in items {
            let (key, value, removed) = change_parts(item)?;
            self.check_controller(&value, removed)?;
            install_change(&mut self.rows, key.clone(), value.clone(), removed)?;
            if let Some(baseline) = self.pending_baseline.as_mut() {
                install_change(&mut baseline.rows, key.clone(), value, removed)?;
                baseline.live_overrides.insert(key);
                staged_changed = true;
            }
        }
        self.projection_position = Some(position);
        self.last_delta_fingerprint = Some(fingerprint);
        Ok(self.update(self.rows != before, staged_changed, false))
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_baseline(
        &mut self,
        snapshot_cursor: &str,
        cut: u64,
        page_offset: u64,
        next_page_offset: Option<u64>,
        items: &[AgentDraftPendingIntentChange],
        completed: bool,
    ) -> Result<AgentDraftPendingIntentProjectionUpdate> {
        if self.pending_baseline.is_none() {
            if page_offset != 0 {
                return Err(Error::Protocol(
                    "pending-intent baseline must start at page_offset 0".to_owned(),
                ));
            }
            self.pending_baseline = Some(PendingBaseline {
                snapshot_cursor: snapshot_cursor.to_owned(),
                snapshot_cut_position: cut,
                next_page_offset: Some(0),
                rows: self.rows.clone(),
                seen: BTreeSet::new(),
                live_overrides: BTreeSet::new(),
            });
        }

        let mut changes = Vec::with_capacity(items.len());
        for item in items {
            let (key, value, removed) = change_parts(item)?;
            self.check_controller(&value, removed)?;
            changes.push((key, value, removed));
        }

        let before = self.rows.clone();
        let baseline = self.pending_baseline.as_mut().expect("initialized above");
        if baseline.snapshot_cursor != snapshot_cursor || baseline.snapshot_cut_position != cut {
            return Err(Error::Protocol(
                "pending-intent baseline generation changed before completion".to_owned(),
            ));
        }
        if baseline.next_page_offset != Some(page_offset) {
            return Err(Error::Protocol(
                "pending-intent baseline page_offset is not the expected private offset".to_owned(),
            ));
        }

        for (key, value, removed) in changes {
            baseline.seen.insert(key.clone());
            if !baseline.live_overrides.contains(&key) {
                install_change(&mut baseline.rows, key, value, removed)?;
            }
        }
        baseline.next_page_offset = next_page_offset;
        if !completed {
            return Ok(self.update(false, true, false));
        }
        if next_page_offset.is_some() {
            return Err(Error::Protocol(
                "pending-intent baseline completed before its terminal page".to_owned(),
            ));
        }

        let mut baseline = self.pending_baseline.take().expect("validated above");
        baseline.rows.retain(|key, record| {
            record.removed || baseline.seen.contains(key) || baseline.live_overrides.contains(key)
        });
        self.rows = baseline.rows;
        self.projection_position = Some(self.projection_position.unwrap_or(0).max(cut));
        self.last_delta_fingerprint = None;
        Ok(self.update(self.rows != before, true, true))
    }

    fn check_controller(&self, value: &Value, removed: bool) -> Result<()> {
        let identity = if removed {
            required(value, "key")?
        } else {
            value.clone()
        };
        if required(&identity, "controller_account_id")?
            != serde_json::to_value(&self.controller_account_id)?
        {
            return Err(Error::Protocol(
                "pending-intent row belongs to another controller account".to_owned(),
            ));
        }
        Ok(())
    }

    fn update(
        &self,
        installed_changed: bool,
        baseline_staged: bool,
        baseline_completed: bool,
    ) -> AgentDraftPendingIntentProjectionUpdate {
        AgentDraftPendingIntentProjectionUpdate {
            installed_changed,
            baseline_staged,
            baseline_completed,
            projection_position: self.projection_position,
        }
    }
}

fn required(value: &Value, field: &str) -> Result<Value> {
    value
        .get(field)
        .cloned()
        .ok_or_else(|| Error::Protocol(format!("pending-intent value lacks {field}")))
}

fn key(value: &Value, removed: bool) -> Result<String> {
    let identity = if removed {
        required(value, "key")?
    } else {
        value.clone()
    };
    serde_json::to_string(&json!([
        required(&identity, "controller_account_id")?,
        required(&identity, "agent_id")?,
        required(&identity, "draft_id")?,
    ]))
    .map_err(Into::into)
}

fn core_identity(value: &Value, removed: bool) -> Result<Value> {
    let identity = if removed {
        required(value, "key")?
    } else {
        value.clone()
    };
    Ok(json!([
        required(&identity, "controller_account_id")?,
        required(&identity, "agent_id")?,
        required(&identity, "draft_id")?,
        required(value, "accepted_event_id")?,
        required(value, "canonical_event_digest")?,
        required(value, "content_digest")?,
        required(value, "expires_at")?,
    ]))
}

fn create_identity(value: &Value) -> Result<Value> {
    Ok(json!([
        core_identity(value, false)?,
        required(value, "proposed_action")?,
        required(value, "target")?,
        required(value, "created_at")?,
    ]))
}

fn terminal_metadata(value: &Value) -> Result<Value> {
    match value.get("state").and_then(Value::as_str) {
        Some("consumed") => Ok(json!(["consumed", required(value, "consumption")?])),
        Some("expired") => Ok(json!(["expired", required(value, "expired_at")?])),
        _ => Err(Error::Protocol(
            "pending-intent terminal metadata has a non-terminal state".to_owned(),
        )),
    }
}

fn change_parts(item: &AgentDraftPendingIntentChange) -> Result<(String, Value, bool)> {
    let (value, removed) = match item {
        AgentDraftPendingIntentChange::Upsert(value) => (serde_json::to_value(value)?, false),
        AgentDraftPendingIntentChange::Remove(value) => (serde_json::to_value(value)?, true),
    };
    Ok((key(&value, removed)?, value, removed))
}

fn install_change(
    records: &mut BTreeMap<String, StoredPendingIntent>,
    key: String,
    value: Value,
    removed: bool,
) -> Result<()> {
    let Some(previous) = records.get(&key) else {
        records.insert(key, StoredPendingIntent { value, removed });
        return Ok(());
    };
    if core_identity(&previous.value, previous.removed)? != core_identity(&value, removed)? {
        return Err(Error::Protocol(
            "pending-intent create-once identity changed".to_owned(),
        ));
    }
    if previous.removed {
        if !removed || previous.value != value {
            return Err(Error::Protocol(
                "pending-intent removal cannot be resurrected or changed".to_owned(),
            ));
        }
        return Ok(());
    }

    let previous_state = previous
        .value
        .get("state")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::Protocol("stored pending-intent lacks state".to_owned()))?;
    let next_state = value
        .get("state")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::Protocol("pending-intent change lacks state".to_owned()))?;
    if removed {
        if previous_state != "available"
            && terminal_metadata(&previous.value)? != terminal_metadata(&value)?
        {
            return Err(Error::Protocol(
                "pending-intent removal changed terminal outcome".to_owned(),
            ));
        }
    } else if next_state == "available" {
        if previous_state != "available" || previous.value != value {
            return Err(Error::Protocol(
                "pending-intent terminal state cannot return to available".to_owned(),
            ));
        }
    } else if previous_state == "available" {
        if create_identity(&previous.value)? != create_identity(&value)? {
            return Err(Error::Protocol(
                "pending-intent terminal update changed create-once metadata".to_owned(),
            ));
        }
    } else if previous.value != value {
        return Err(Error::Protocol(
            "pending-intent terminal outcome changed".to_owned(),
        ));
    }
    records.insert(key, StoredPendingIntent { value, removed });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const REALM: &str = "ak:realm:AeWYNl1hiGDuy4WCQ03g5lgs2NZzf_SFYgjsfhG-t9cg";
    const EVENT: &str = "ak:event:AQJmSg1s9QyzppFeJL40dN92YVHZeLdBBt3UWHa9XNOD";
    const DATA_KEY: &str = "ak.agent.draft.v1:29zs6Yu_GblluGkdTEDf8gWy8fRlKv2Am4Ms91DB-U8:HpcHzfESu5dFt2Is2QQ2Tp_c7hfh4SZtz4pKrbxp0_s";

    fn controller() -> AccountId {
        serde_json::from_value(json!({
            "principal_id":"ak:did_core:web:controller.example",
            "station_id":"ak:did_core:web:station.example"
        }))
        .unwrap()
    }

    fn frame(value: Value) -> AccountSubscribeFrame {
        serde_json::from_value(value).unwrap()
    }

    fn live(draft_id: &str) -> Value {
        json!({
            "schema":"ak.schema.agent_draft_pending_intent.v1",
            "controller_account_id":serde_json::to_value(controller()).unwrap(),
            "agent_id":"ak:did_core:web:agent.example",
            "draft_id":draft_id,
            "proposed_action":"ak.message.create",
            "target":{"kind":"realm","realm_id":REALM},
            "content_digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "content_handoff":{
                "scheme":"ak.hpke_x25519_aead_chacha20poly1305.v1",
                "recipients":[{
                    "recipient_device_id":"ak:device:01964137-0000-7000-8000-000000000000",
                    "recipient_hpke_key_digest":"sha256:2222222222222222222222222222222222222222222222222222222222222222",
                    "enc":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    "ciphertext":"AAAAAAAAAAAAAAAAAAAAAA",
                    "ciphertext_digest":"sha256:3333333333333333333333333333333333333333333333333333333333333333"
                }]
            },
            "canonical_event_digest":"sha256:4444444444444444444444444444444444444444444444444444444444444444",
            "accepted_event_id":EVENT,
            "expires_at":"2026-09-20T03:00:00.000Z",
            "created_at":"2026-09-20T01:00:00.000Z",
            "state":"available"
        })
    }

    fn consumed(draft_id: &str) -> Value {
        let mut value = live(draft_id);
        let object = value.as_object_mut().unwrap();
        object.remove("content_handoff");
        object.insert("state".to_owned(), json!("consumed"));
        object.insert(
            "consumption".to_owned(),
            json!({
                "account_data_set_event_id":EVENT,
                "account_data_key":DATA_KEY,
                "accepted_revision":1,
                "consumed_at":"2026-09-20T01:30:00.000Z"
            }),
        );
        value
    }

    fn removal(draft_id: &str) -> Value {
        json!({
            "key":{
                "controller_account_id":serde_json::to_value(controller()).unwrap(),
                "agent_id":"ak:did_core:web:agent.example",
                "draft_id":draft_id
            },
            "accepted_event_id":EVENT,
            "canonical_event_digest":"sha256:4444444444444444444444444444444444444444444444444444444444444444",
            "content_digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "expires_at":"2026-09-20T03:00:00.000Z",
            "state":"consumed",
            "consumption":{
                "account_data_set_event_id":EVENT,
                "account_data_key":DATA_KEY,
                "accepted_revision":1,
                "consumed_at":"2026-09-20T01:30:00.000Z"
            },
            "removed_at":"2026-09-20T04:00:00.000Z"
        })
    }

    fn delta(position: u64, action: &str, value: Value) -> AccountSubscribeFrame {
        frame(json!({
            "kind":"delta",
            "cursor":format!("ak:cursor:pending-{position}"),
            "agent_draft_pending_intents":{
                "mode":"delta",
                "projection_position":position,
                "items":[{"action":action,"value":value}]
            }
        }))
    }

    fn baseline(
        snapshot: &str,
        cut: u64,
        offset: u64,
        next: Option<u64>,
        complete: bool,
        items: Vec<Value>,
    ) -> AccountSubscribeFrame {
        frame(json!({
            "kind":"delta",
            "cursor":format!("ak:cursor:{snapshot}-{offset}"),
            "baseline":{
                "snapshot_cursor":format!("ak:cursor:{snapshot}"),
                "channels":["agent_draft_pending_intents"],
                "completed_channels":if complete { json!(["agent_draft_pending_intents"]) } else { json!([]) }
            },
            "agent_draft_pending_intents":{
                "mode":"baseline",
                "snapshot_cut_position":cut,
                "page_offset":offset,
                "next_page_offset":next,
                "items":items
            }
        }))
    }

    #[test]
    fn staged_baseline_live_terminal_and_removal_are_monotone() {
        let mut projection = AgentDraftPendingIntentProjection::new(controller());
        projection
            .apply_frame(&delta(6, "upsert", live("stale")))
            .unwrap();
        projection
            .apply_frame(&baseline(
                "pending-snapshot",
                7,
                0,
                Some(1),
                false,
                vec![json!({"action":"upsert","value":live("draft-001")})],
            ))
            .unwrap();
        assert_eq!(projection.len(), 1, "an incomplete baseline stays hidden");

        projection
            .apply_frame(&delta(8, "upsert", consumed("draft-001")))
            .unwrap();
        let terminal = projection
            .rows()
            .find(|row| row["draft_id"] == "draft-001")
            .unwrap();
        assert_eq!(terminal["state"], "consumed");
        assert!(terminal.get("content_handoff").is_none());

        projection
            .apply_frame(&baseline(
                "pending-snapshot",
                7,
                1,
                None,
                true,
                vec![json!({"action":"upsert","value":live("draft-001")})],
            ))
            .unwrap();
        assert_eq!(projection.len(), 1);
        assert_eq!(projection.rows().next().unwrap()["state"], "consumed");

        projection
            .apply_frame(&delta(9, "remove", removal("draft-001")))
            .unwrap();
        assert!(projection.is_empty());
        let before = projection.clone();
        assert!(
            projection
                .apply_frame(&delta(10, "upsert", live("draft-001")))
                .is_err()
        );
        assert_eq!(projection, before, "a rejected resurrection is atomic");
    }

    #[test]
    fn private_offsets_and_resync_do_not_discard_installed_rows() {
        let mut projection = AgentDraftPendingIntentProjection::new(controller());
        assert!(
            projection
                .apply_frame(&baseline("bad", 3, 2, None, true, vec![]))
                .is_err()
        );
        projection
            .apply_frame(&delta(2, "upsert", live("draft-001")))
            .unwrap();
        projection
            .apply_frame(&baseline("first", 3, 0, Some(1), false, vec![]))
            .unwrap();
        assert_eq!(projection.pending_next_page_offset(), Some(1));
        projection
            .apply_frame(&frame(json!({"kind":"resync_required"})))
            .unwrap();
        assert!(projection.pending_snapshot_cursor().is_none());
        assert_eq!(projection.len(), 1);
        projection
            .apply_frame(&baseline("fresh", 4, 0, None, true, vec![]))
            .unwrap();
        assert!(projection.is_empty());
    }

    #[test]
    fn other_account_carriers_cannot_create_pending_rows() {
        let mut projection = AgentDraftPendingIntentProjection::new(controller());
        projection
            .apply_frame(&frame(json!({
                "kind":"delta",
                "cursor":"ak:cursor:other-carriers",
                "notifications":{"items":[]},
                "to_device":{"deliveries":[]}
            })))
            .unwrap();
        assert!(projection.is_empty());
    }

    #[test]
    fn account_event_fanout_preserves_the_dedicated_carrier() {
        let source = delta(1, "upsert", live("draft-001"));
        let events = crate::projection::account_frame_to_client_events(&source, true).unwrap();
        let crate::projection::ClientEvent::AccountUpdates(context) = &events[0] else {
            panic!("account update context must be first");
        };
        let AgentDraftPendingIntentContainer::Delta {
            projection_position,
            items,
        } = context
            .agent_draft_pending_intents
            .as_ref()
            .expect("the dedicated carrier must not be dropped")
        else {
            panic!("delta carrier expected");
        };
        assert_eq!(*projection_position, 1);
        assert_eq!(items.len(), 1);
    }
}
