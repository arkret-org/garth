//! Revision-safe consumer for Station-CAS account-data rows.

use arkret_models_collaboration::sync_frames::account_subscribe::{
    AccountSubscribeFrame, StationCasAccountDataContainer,
};
use arkret_models_collaboration::sync_frames::demand_sync::AccountBaselineChannel;
use imbl::{OrdMap as BTreeMap, OrdSet as BTreeSet};

use crate::{Error, Result};

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct Revision {
    value: u64,
    canonical_change: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct PendingBaseline {
    snapshot_cursor: String,
    revisions: BTreeMap<String, Revision>,
    live_overrides: BTreeSet<String>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StationCasProjectionUpdate {
    pub baseline_staged: bool,
    pub baseline_completed: bool,
    pub live_changed: bool,
}

/// Tracks only the authoritative per-key revision identity needed to reject
/// rollback and equivocation. Product state remains owned by the host
/// projector and is checkpointed atomically with the account cursor.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StationCasProjection {
    revisions: BTreeMap<String, Revision>,
    pending_baseline: Option<PendingBaseline>,
}

impl StationCasProjection {
    /// Visit only changed local checkpoint records. Hosts may put these records
    /// in the same physical transaction as their Account cursor. Paths are
    /// local serde coordinates, never protocol selectors or wire objects.
    pub fn visit_checkpoint_changes(
        &self,
        previous: &Self,
        mut visit: impl FnMut(Vec<String>, Option<serde_json::Value>) -> Result<()>,
    ) -> Result<()> {
        fn revisions(
            path: Vec<String>,
            old: &BTreeMap<String, Revision>,
            new: &BTreeMap<String, Revision>,
            visit: &mut impl FnMut(Vec<String>, Option<serde_json::Value>) -> Result<()>,
        ) -> Result<()> {
            for delta in old.diff(new) {
                let (key, value) = match delta {
                    imbl::ordmap::DiffItem::Add(key, value) => (key, Some(value)),
                    imbl::ordmap::DiffItem::Remove(key, _) => (key, None),
                    imbl::ordmap::DiffItem::Update {
                        new: (key, value), ..
                    } => (key, Some(value)),
                };
                let mut row = path.clone();
                row.push(key.clone());
                visit(row, value.map(serde_json::to_value).transpose()?)?;
            }
            Ok(())
        }
        revisions(
            vec!["revisions".into()],
            &previous.revisions,
            &self.revisions,
            &mut visit,
        )?;
        let old = previous.pending_baseline.as_ref();
        let new = self.pending_baseline.as_ref();
        if old.map(|p| &p.snapshot_cursor) != new.map(|p| &p.snapshot_cursor) {
            visit(
                vec!["pending_baseline".into()],
                Some(match new {
                    None => serde_json::Value::Null,
                    Some(p) => {
                        serde_json::json!({"snapshot_cursor":p.snapshot_cursor,"revisions":{},"live_overrides":[]})
                    }
                }),
            )?;
        }
        let empty = BTreeMap::new();
        revisions(
            vec!["pending_baseline".into(), "revisions".into()],
            old.map_or(&empty, |p| &p.revisions),
            new.map_or(&empty, |p| &p.revisions),
            &mut visit,
        )?;
        // Overrides are independently keyed set records, so a long baseline
        // never serializes its entire accumulated key set on a one-key delta.
        let empty = BTreeSet::new();
        let a = old.map_or(&empty, |p| &p.live_overrides);
        let b = new.map_or(&empty, |p| &p.live_overrides);
        for key in a.clone().symmetric_difference(b.clone()) {
            let path = vec![
                "pending_baseline".into(),
                "live_overrides".into(),
                key.clone(),
            ];
            visit(
                path,
                if b.contains(&key) {
                    Some(serde_json::Value::String(key))
                } else {
                    None
                },
            )?;
        }
        Ok(())
    }

    pub fn reset_for_initial_sync(&mut self) {
        self.revisions.clear();
        self.pending_baseline = None;
    }

    pub fn revision(&self, key: &str) -> Option<u64> {
        self.revisions.get(key).map(|revision| revision.value)
    }

    /// Apply one frame atomically. Any rollback or same-revision conflict
    /// leaves the previously accepted revision set unchanged.
    pub fn apply_frame(
        &mut self,
        frame: &AccountSubscribeFrame,
    ) -> Result<StationCasProjectionUpdate> {
        frame.validate()?;
        let mut staged = self.clone();
        let update = staged.apply_valid_frame(frame)?;
        *self = staged;
        Ok(update)
    }

    fn apply_valid_frame(
        &mut self,
        frame: &AccountSubscribeFrame,
    ) -> Result<StationCasProjectionUpdate> {
        let channel = AccountBaselineChannel::StationCas;
        let baseline = frame.baseline.as_ref().filter(|segment| {
            segment.channels.contains(&channel) || segment.completed_channels.contains(&channel)
        });
        let changes = frame
            .account_data
            .as_ref()
            .and_then(|account_data| account_data.station_cas.as_ref());

        if let Some(segment) = baseline {
            let pending = match self.pending_baseline.as_mut() {
                Some(pending) if pending.snapshot_cursor == segment.snapshot_cursor => pending,
                Some(_) => {
                    return Err(Error::Protocol(
                        "station_cas baseline generation changed before completion".to_owned(),
                    ));
                }
                None => self.pending_baseline.insert(PendingBaseline {
                    snapshot_cursor: segment.snapshot_cursor.clone(),
                    revisions: BTreeMap::new(),
                    live_overrides: BTreeSet::new(),
                }),
            };
            let mut baseline_staged = false;
            if let Some(changes) = changes {
                baseline_staged = apply_changes(
                    &mut pending.revisions,
                    changes,
                    Some(&pending.live_overrides),
                )?;
            }
            let baseline_completed = segment.completes(channel);
            if baseline_completed {
                let pending = self
                    .pending_baseline
                    .take()
                    .expect("station_cas baseline initialized above");
                self.revisions = pending.revisions;
            }
            return Ok(StationCasProjectionUpdate {
                baseline_staged,
                baseline_completed,
                live_changed: false,
            });
        }

        let mut live_changed = false;
        if let Some(changes) = changes {
            live_changed = apply_changes(&mut self.revisions, changes, None)?;
            if let Some(pending) = self.pending_baseline.as_mut() {
                apply_changes(&mut pending.revisions, changes, None)?;
                pending.live_overrides.extend(change_keys(changes));
            }
        }
        Ok(StationCasProjectionUpdate {
            baseline_staged: false,
            baseline_completed: false,
            live_changed,
        })
    }
}

fn apply_changes(
    revisions: &mut BTreeMap<String, Revision>,
    changes: &StationCasAccountDataContainer,
    ignored: Option<&BTreeSet<String>>,
) -> Result<bool> {
    let mut changed = false;
    for change in changes
        .upserts
        .iter()
        .map(|row| {
            Ok::<_, Error>((
                row.account_data_key.clone(),
                row.revision,
                arkret_canonical::canonical_json_bytes(row)?,
            ))
        })
        .chain(changes.removals.iter().map(|row| {
            Ok::<_, Error>((
                row.account_data_key.clone(),
                row.revision,
                arkret_canonical::canonical_json_bytes(row)?,
            ))
        }))
    {
        let (key, revision, canonical_change) = change?;
        if ignored.is_some_and(|ignored| ignored.contains(&key)) {
            continue;
        }
        if let Some(current) = revisions.get(&key) {
            if revision < current.value {
                return Err(Error::Protocol(format!(
                    "station_cas revision regressed for {key}"
                )));
            }
            if revision == current.value {
                if canonical_change == current.canonical_change {
                    continue;
                }
                return Err(Error::Protocol(format!(
                    "station_cas revision conflict for {key}"
                )));
            }
        }
        revisions.insert(
            key,
            Revision {
                value: revision,
                canonical_change,
            },
        );
        changed = true;
    }
    Ok(changed)
}

fn change_keys(changes: &StationCasAccountDataContainer) -> impl Iterator<Item = String> + '_ {
    changes
        .upserts
        .iter()
        .map(|row| row.account_data_key.clone())
        .chain(
            changes
                .removals
                .iter()
                .map(|row| row.account_data_key.clone()),
        )
}

pub(crate) fn is_revision_integrity_error(error: &Error) -> bool {
    matches!(error, Error::Protocol(message) if message.starts_with("station_cas revision ") || message.starts_with("station_cas baseline "))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn frame(
        revision: u64,
        removal: bool,
        baseline: Option<(&str, bool)>,
    ) -> AccountSubscribeFrame {
        let change = if removal {
            json!({
                "upserts": [],
                "removals": [{
                    "account_data_key": "ak.account.invite_delivery",
                    "revision": revision,
                    "updated_at": "2026-09-20T01:00:00.000Z"
                }]
            })
        } else {
            json!({
                "upserts": [{
                    "account_data_key": "ak.account.invite_delivery",
                    "revision": revision,
                    "content": {"revision": revision},
                    "updated_at": "2026-09-20T01:00:00.000Z"
                }],
                "removals": []
            })
        };
        let mut value = json!({
            "kind": "delta",
            "cursor": "ak:cursor:c3RhdGlvbi1jYXM",
            "account_data": {"events": [], "station_cas": change}
        });
        if let Some((snapshot_cursor, completed)) = baseline {
            value["baseline"] = json!({
                "snapshot_cursor": snapshot_cursor,
                "channels": ["station_cas"],
                "completed_channels": if completed { json!(["station_cas"]) } else { json!([]) }
            });
        }
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn rollback_and_same_revision_conflict_are_atomic() {
        let mut projection = StationCasProjection::default();
        projection.apply_frame(&frame(2, false, None)).unwrap();
        projection.apply_frame(&frame(2, false, None)).unwrap();

        assert!(projection.apply_frame(&frame(1, false, None)).is_err());
        assert_eq!(projection.revision("ak.account.invite_delivery"), Some(2));
        assert!(projection.apply_frame(&frame(2, true, None)).is_err());
        assert_eq!(projection.revision("ak.account.invite_delivery"), Some(2));
    }

    #[test]
    fn initial_resync_discards_revision_history_and_installs_completed_baseline() {
        let mut projection = StationCasProjection::default();
        projection.apply_frame(&frame(7, false, None)).unwrap();
        projection.reset_for_initial_sync();

        let update = projection
            .apply_frame(&frame(1, false, Some(("ak:cursor:YmFzZWxpbmU", true))))
            .unwrap();
        assert!(update.baseline_completed);
        assert_eq!(projection.revision("ak.account.invite_delivery"), Some(1));
    }

    #[test]
    fn incomplete_baseline_generation_cannot_change_silently() {
        let mut projection = StationCasProjection::default();
        projection
            .apply_frame(&frame(1, false, Some(("ak:cursor:YmFzZWxpbmUtMQ", false))))
            .unwrap();
        let error = projection
            .apply_frame(&frame(2, false, Some(("ak:cursor:YmFzZWxpbmUtMg", true))))
            .unwrap_err();
        assert!(is_revision_integrity_error(&error));
        assert_eq!(projection.revision("ak.account.invite_delivery"), None);
    }
}
