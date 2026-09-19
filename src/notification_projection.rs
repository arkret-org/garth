//! Account-private notification current-row projection.
//!
//! Notification rows arrive on the authenticated account stream rather than a
//! Realm commit stream. This projector keeps their independent current set and
//! stages frozen baseline pages until the notification channel explicitly
//! completes.

use std::collections::{BTreeMap, BTreeSet};

use arkret_models_collaboration::sync_frames::account_subscribe::{
    AccountSubscribeFrame, NotificationDelta, NotificationDeltaAction,
};
use arkret_models_collaboration::sync_frames::demand_sync::AccountBaselineChannel;
use arkret_wire::AccountId;

use crate::{Error, Result};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NotificationProjectionUpdate {
    /// The visible installed current set changed.
    pub installed_changed: bool,
    /// An incomplete baseline's private staging set changed.
    pub baseline_staged: bool,
    pub baseline_completed: bool,
}

#[derive(Clone, Debug)]
struct PendingBaseline {
    snapshot_cursor: String,
    rows: BTreeMap<String, NotificationDelta>,
    live_overrides: BTreeSet<String>,
}

/// Current notification rows for one authenticated account.
#[derive(Clone, Debug)]
pub struct NotificationProjection {
    recipient_account_id: AccountId,
    rows: BTreeMap<String, NotificationDelta>,
    pending_baseline: Option<PendingBaseline>,
}

impl NotificationProjection {
    pub fn new(recipient_account_id: AccountId) -> Self {
        Self {
            recipient_account_id,
            rows: BTreeMap::new(),
            pending_baseline: None,
        }
    }

    pub fn recipient_account_id(&self) -> &AccountId {
        &self.recipient_account_id
    }

    pub fn get(&self, notification_id: &str) -> Option<&NotificationDelta> {
        self.rows.get(notification_id)
    }

    pub fn rows(&self) -> impl Iterator<Item = &NotificationDelta> {
        self.rows.values()
    }

    pub fn len(&self) -> usize {
        self.rows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    pub fn pending_snapshot_cursor(&self) -> Option<&str> {
        self.pending_baseline
            .as_ref()
            .map(|baseline| baseline.snapshot_cursor.as_str())
    }

    /// Abandon an incomplete baseline after the account cursor is reset.
    /// Installed rows remain visible until a new baseline completes.
    pub fn reset_pending_baseline(&mut self) {
        self.pending_baseline = None;
    }

    /// Apply one validated account-stream frame atomically.
    ///
    /// Rows from an incomplete baseline are not visible. Live deltas arriving
    /// while that baseline is in progress are applied to both the installed
    /// set and the staged set, and prevent later frozen pages from restoring an
    /// older value for the same id.
    pub fn apply_frame(
        &mut self,
        frame: &AccountSubscribeFrame,
    ) -> Result<NotificationProjectionUpdate> {
        frame.validate()?;
        let mut staged = self.clone();
        let update = staged.apply_valid_frame(frame)?;
        *self = staged;
        Ok(update)
    }

    fn apply_valid_frame(
        &mut self,
        frame: &AccountSubscribeFrame,
    ) -> Result<NotificationProjectionUpdate> {
        let notification_channel = AccountBaselineChannel::Notifications;
        let baseline = frame.baseline.as_ref().filter(|baseline| {
            baseline.channels.contains(&notification_channel)
                || baseline.completed_channels.contains(&notification_channel)
        });
        let deltas = frame
            .notifications
            .as_ref()
            .map(|container| container.items.as_slice())
            .unwrap_or_default();
        for delta in deltas {
            self.validate_delta(delta)?;
        }

        if let Some(segment) = baseline {
            let pending = match self.pending_baseline.as_mut() {
                Some(pending) if pending.snapshot_cursor == segment.snapshot_cursor => pending,
                Some(_) => {
                    return Err(Error::Protocol(
                        "notification baseline generation changed before completion".to_owned(),
                    ));
                }
                None => self.pending_baseline.insert(PendingBaseline {
                    snapshot_cursor: segment.snapshot_cursor.clone(),
                    rows: BTreeMap::new(),
                    live_overrides: BTreeSet::new(),
                }),
            };
            let mut baseline_staged = false;
            for delta in deltas {
                let id = delta.id.as_str();
                if !pending.live_overrides.contains(id) {
                    baseline_staged |= apply_delta(&mut pending.rows, delta);
                }
            }
            let baseline_completed = segment.completes(notification_channel);
            let mut installed_changed = false;
            if baseline_completed {
                let pending = self
                    .pending_baseline
                    .take()
                    .expect("notification baseline was initialized above");
                installed_changed = self.rows != pending.rows;
                self.rows = pending.rows;
            }
            return Ok(NotificationProjectionUpdate {
                installed_changed,
                baseline_staged,
                baseline_completed,
            });
        }

        let mut changed = false;
        for delta in deltas {
            changed |= apply_delta(&mut self.rows, delta);
            if let Some(pending) = self.pending_baseline.as_mut() {
                let id = delta.id.as_str().to_owned();
                apply_delta(&mut pending.rows, delta);
                pending.live_overrides.insert(id);
            }
        }
        Ok(NotificationProjectionUpdate {
            installed_changed: changed,
            baseline_staged: false,
            baseline_completed: false,
        })
    }

    fn validate_delta(&self, delta: &NotificationDelta) -> Result<()> {
        delta.validate_shape()?;
        delta.verify_recipient_binding(&self.recipient_account_id)?;
        if let Some(approval) = delta.agent_runtime_approval() {
            approval.validate()?;
        }
        Ok(())
    }
}

fn apply_delta(rows: &mut BTreeMap<String, NotificationDelta>, delta: &NotificationDelta) -> bool {
    let id = delta.id.as_str();
    match delta.action {
        NotificationDeltaAction::Upsert => {
            rows.insert(id.to_owned(), delta.clone()).as_ref() != Some(delta)
        }
        NotificationDeltaAction::Remove => rows.remove(id).is_some(),
    }
}

#[cfg(test)]
mod tests {
    use arkret_wire::DidCoreId;
    use serde_json::{Value, json};

    use super::*;

    const ORDINARY_ID: &str =
        "ak:notification_projection:AdaNq4qN-xTAcv8kCT3P9mL5AsSzg0PFlSELggvhw2Pw";

    fn recipient() -> AccountId {
        AccountId::new(
            DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            DidCoreId::new("ak:did_core:web:ps.example").unwrap(),
        )
    }

    fn projection() -> NotificationProjection {
        NotificationProjection::new(recipient())
    }

    fn approval(id: &str, action: &str, expires_at: &str) -> Value {
        let data = if action == "upsert" {
            json!({
                "approval_request_id": "agent_runtime_approval:01964137-0000-7000-8000-000000000000",
                "agent_id": "ak:did_core:webvh:z6mkfixtureagent",
                "requested_at": "2026-07-13T10:00:00.000Z",
                "expires_at": expires_at
            })
        } else {
            json!({"reason": "approved"})
        };
        json!({"id": id, "action": action, "data": data})
    }

    fn ordinary() -> Value {
        json!({
            "id": ORDINARY_ID,
            "action": "upsert",
            "data": {
                "realm_id": "ak:realm:AdF_8ICakbYdEH0Cnl-w5o1WFlnh5rXGWqY_-_G6yM7N",
                "source_event_id": "ak:event:AT33EWBTXdTx5CjY-ogbIIF2T4vh-v7jCMCQ80Fss2Rq",
                "notification_kind": "message",
                "priority": "normal",
                "created_at": "2026-09-10T10:00:00.000Z"
            }
        })
    }

    fn frame(items: Vec<Value>, baseline: Option<Value>) -> AccountSubscribeFrame {
        let mut value = json!({
            "kind": "delta",
            "cursor": "ak:cursor:dGVzdA",
            "notifications": {"items": items}
        });
        if let Some(baseline) = baseline {
            value["baseline"] = baseline;
        }
        serde_json::from_value(value).unwrap()
    }

    fn baseline(completed: bool) -> Value {
        json!({
            "snapshot_cursor": "ak:cursor:YmFzZWxpbmU",
            "channels": ["notifications"],
            "completed_channels": if completed { json!(["notifications"]) } else { json!([]) }
        })
    }

    #[test]
    fn upsert_replaces_and_remove_deletes_the_current_row() {
        let id = "ak:notification:01964137-0000-7000-8000-000000000001";
        let mut projection = projection();
        projection
            .apply_frame(&frame(
                vec![approval(id, "upsert", "2026-07-13T10:15:00.000Z")],
                None,
            ))
            .unwrap();
        projection
            .apply_frame(&frame(
                vec![approval(id, "upsert", "2026-07-13T10:20:00.000Z")],
                None,
            ))
            .unwrap();
        let row = serde_json::to_value(projection.get(id).unwrap()).unwrap();
        assert_eq!(row["data"]["expires_at"], "2026-07-13T10:20:00.000Z");

        projection
            .apply_frame(&frame(
                vec![approval(id, "remove", "2026-07-13T10:20:00.000Z")],
                None,
            ))
            .unwrap();
        assert!(projection.get(id).is_none());
    }

    #[test]
    fn ordinary_row_for_another_recipient_is_rejected_atomically() {
        let id = "ak:notification:01964137-0000-7000-8000-000000000001";
        let mut projection = projection();
        projection
            .apply_frame(&frame(
                vec![approval(id, "upsert", "2026-07-13T10:15:00.000Z")],
                None,
            ))
            .unwrap();
        let other = AccountId::new(
            DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            DidCoreId::new("ak:did_core:web:other.example").unwrap(),
        );
        let mut wrong_projection = NotificationProjection::new(other);
        wrong_projection.rows = projection.rows.clone();

        assert!(
            wrong_projection
                .apply_frame(&frame(vec![ordinary()], None))
                .is_err()
        );
        assert_eq!(wrong_projection.len(), 1);
        assert!(wrong_projection.get(id).is_some());
    }

    #[test]
    fn an_incomplete_baseline_never_replaces_installed_rows() {
        let old = "ak:notification:01964137-0000-7000-8000-000000000001";
        let fresh = "ak:notification:01964137-0000-7000-8000-000000000002";
        let mut projection = projection();
        projection
            .apply_frame(&frame(
                vec![approval(old, "upsert", "2026-07-13T10:15:00.000Z")],
                None,
            ))
            .unwrap();
        let staged = projection
            .apply_frame(&frame(
                vec![approval(fresh, "upsert", "2026-07-13T10:20:00.000Z")],
                Some(baseline(false)),
            ))
            .unwrap();
        assert!(!staged.installed_changed);
        assert!(staged.baseline_staged);
        assert!(projection.get(old).is_some());
        assert!(projection.get(fresh).is_none());

        let update = projection
            .apply_frame(&frame(Vec::new(), Some(baseline(true))))
            .unwrap();
        assert!(update.baseline_completed);
        assert!(projection.get(old).is_none());
        assert!(projection.get(fresh).is_some());
    }

    #[test]
    fn live_remove_during_baseline_is_not_resurrected_by_a_later_frozen_page() {
        let removed = "ak:notification:01964137-0000-7000-8000-000000000001";
        let retained = "ak:notification:01964137-0000-7000-8000-000000000002";
        let row = approval(removed, "upsert", "2026-07-13T10:15:00.000Z");
        let mut projection = projection();
        projection
            .apply_frame(&frame(vec![row.clone()], None))
            .unwrap();
        projection
            .apply_frame(&frame(vec![row.clone()], Some(baseline(false))))
            .unwrap();
        projection
            .apply_frame(&frame(
                vec![approval(removed, "remove", "2026-07-13T10:20:00.000Z")],
                None,
            ))
            .unwrap();
        projection
            .apply_frame(&frame(
                vec![
                    row,
                    approval(retained, "upsert", "2026-07-13T10:20:00.000Z"),
                ],
                Some(baseline(true)),
            ))
            .unwrap();

        assert!(projection.get(removed).is_none());
        assert!(projection.get(retained).is_some());
    }
}
