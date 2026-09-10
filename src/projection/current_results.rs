//! Bounded planning for installation of Station current results.
//!
//! The host reads only the selectors named by one frame, builds this plan,
//! and commits its writes, seen marks, covered cleanup and account cursor in
//! one durable transaction. No history or reducer participates in this path.

use std::collections::BTreeMap;

use arkret_models_collaboration::sync_frames::account_sync::RealmSyncEntry;
use arkret_models_collaboration::sync_frames::current_results::{
    CurrentCoverage, CurrentResultEntry,
};
use arkret_models_collaboration::sync_frames::demand_sync::RealmDetailBaseline;
use arkret_wire::Cursor;
use serde::{Deserialize, Serialize};

use crate::protocol::{Error, Result};

/// Small durable metadata, independent of the number of installed selectors.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct CurrentRealmProgress {
    pub baseline: Option<RealmDetailBaseline>,
    pub invalidated_snapshot: Option<Cursor>,
    pub invalidation_revision: u64,
    pub has_invalidation: bool,
    pub needs_refresh: bool,
}

impl CurrentRealmProgress {
    pub fn invalidate(&mut self, revision: u64) {
        if self.has_invalidation && revision <= self.invalidation_revision {
            return;
        }
        self.has_invalidation = true;
        self.invalidation_revision = revision;
        self.needs_refresh = true;
        self.invalidated_snapshot = self
            .baseline
            .as_ref()
            .map(|baseline| baseline.snapshot_cursor.clone());
    }

    pub fn reset(&mut self) {
        self.needs_refresh = true;
        self.invalidated_snapshot = self
            .baseline
            .as_ref()
            .map(|baseline| baseline.snapshot_cursor.clone());
    }
}

/// A database predicate, never a list of every covered selector.
#[derive(Clone, Debug)]
pub struct CurrentCoverageCleanup {
    pub snapshot_cursor: Cursor,
    pub cut_revision: u64,
    pub coverage: CurrentCoverage,
}

#[derive(Clone, Debug)]
pub struct CurrentInstallPlan {
    pub progress: CurrentRealmProgress,
    pub writes: Vec<CurrentResultEntry>,
    pub seen_selectors: Vec<String>,
    pub begin_snapshot: Option<Cursor>,
    pub cleanup: Option<CurrentCoverageCleanup>,
    /// An invalidated snapshot must not reach secondary product projections.
    pub discard_frame: bool,
}

fn invalid(message: &str) -> Error {
    Error::Protocol(message.to_owned())
}

fn same_canonical(left: &CurrentResultEntry, right: &CurrentResultEntry) -> Result<bool> {
    let left = arkret_canonical::canonical_json_bytes(left)
        .map_err(|error| invalid(&error.to_string()))?;
    let right = arkret_canonical::canonical_json_bytes(right)
        .map_err(|error| invalid(&error.to_string()))?;
    Ok(left == right)
}

/// Validate one replacement while the host holds only this selector's old row.
/// Realm baseline transitions and cleanup still run once through the planner.
pub fn plan_current_entry(
    previous: &CurrentRealmProgress,
    incoming: &RealmSyncEntry,
    entry: &CurrentResultEntry,
    old: Option<&CurrentResultEntry>,
) -> Result<(bool, bool)> {
    let complete = incoming.baseline.as_ref().is_some_and(|segment| {
        previous
            .baseline
            .as_ref()
            .is_some_and(|old| old.snapshot_cursor == segment.snapshot_cursor && old.complete)
    });
    if let Some(segment) = &incoming.baseline {
        if entry.revision() > segment.cut_revision
            || !segment.coverage.covers(entry.selector(), entry.target())
        {
            return Err(invalid("current result is outside its frozen baseline"));
        }
    }
    let seen = incoming.baseline.is_some() && !complete;
    if let Some(old) = old {
        if old.target() != entry.target() {
            return Err(invalid("current selector changed its target"));
        }
        if old.revision() == entry.revision() {
            if !same_canonical(old, entry)? {
                return Err(invalid("current result changed at the same revision"));
            }
            return Ok((false, seen));
        }
        if old.revision() > entry.revision() {
            return Ok((false, seen));
        }
    } else if incoming.baseline.is_none()
        && previous.baseline.as_ref().is_some_and(|baseline| {
            baseline.complete
                && entry.revision() <= baseline.cut_revision
                && baseline.coverage.covers(entry.selector(), entry.target())
        })
    {
        return Ok((false, seen));
    }
    Ok((!complete, seen))
}

/// Preflight one Realm entry without changing host state.
///
/// `existing` contains the current rows for incoming selectors only, including
/// removed/unavailable records. The host must retain their revision and must
/// recheck its transaction generation before committing this plan. For cleanup,
/// delete only covered unseen rows at or below the cut; retain newer live rows.
pub fn plan_current_install(
    previous: &CurrentRealmProgress,
    incoming: &RealmSyncEntry,
    existing: &BTreeMap<String, CurrentResultEntry>,
) -> Result<CurrentInstallPlan> {
    incoming.validate_demand()?;
    let mut plan = CurrentInstallPlan {
        progress: previous.clone(),
        writes: Vec::new(),
        seen_selectors: Vec::new(),
        begin_snapshot: None,
        cleanup: None,
        discard_frame: false,
    };
    let mut already_complete = false;
    if incoming.unavailable.is_some() {
        plan.progress.reset();
        return Ok(plan);
    }
    if let Some(segment) = &incoming.baseline {
        if previous.invalidated_snapshot.as_ref() == Some(&segment.snapshot_cursor)
            || segment.cut_revision < previous.invalidation_revision
        {
            plan.discard_frame = true;
            return Ok(plan);
        }
        match &previous.baseline {
            Some(old) if old.snapshot_cursor == segment.snapshot_cursor => {
                if old.cut_revision != segment.cut_revision || old.coverage != segment.coverage {
                    return Err(invalid("current baseline changed its cut or coverage"));
                }
                already_complete = old.complete;
            }
            _ => {
                plan.begin_snapshot = Some(segment.snapshot_cursor.clone());
            }
        }
        if !already_complete {
            plan.progress.baseline = Some(segment.clone());
            plan.progress.needs_refresh = !segment.complete;
        }
    }
    if let Some(current) = &incoming.current {
        if current.entries.len() > 100 {
            return Err(invalid("current frame exceeds selector budget"));
        }
        let mut delivered = std::collections::BTreeSet::new();
        for entry in &current.entries {
            let key = entry
                .selector()
                .canonical_key()
                .map_err(|error| invalid(&error.to_string()))?;
            if !delivered.insert(key.clone()) {
                return Err(invalid("duplicate current selector in one frame"));
            }
            let (write, seen) = plan_current_entry(previous, incoming, entry, existing.get(&key))?;
            if seen {
                plan.seen_selectors.push(key);
            }
            if write {
                plan.writes.push(entry.clone());
            }
        }
    }
    if let Some(segment) = &incoming.baseline
        && segment.complete
        && !already_complete
    {
        plan.cleanup = Some(CurrentCoverageCleanup {
            snapshot_cursor: segment.snapshot_cursor.clone(),
            cut_revision: segment.cut_revision,
            coverage: segment.coverage.clone(),
        });
    }
    Ok(plan)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn entry(revision: u64, removed: bool) -> CurrentResultEntry {
        serde_json::from_value(json!({
            "selector": {
                "scope_ref": {"kind":"realm","realm_id":"ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI"},
                "cell_id":"ak:cell:ak.component.realm.freeze.v1:null"
            },
            "target":{"kind":"realm"},"revision":revision,
            "result":if removed {json!({"status":"removed"})} else {json!({"status":"value","value":null})}
        })).unwrap()
    }

    fn segment(cut: u64, complete: bool) -> RealmDetailBaseline {
        serde_json::from_value(json!({
            "snapshot_cursor":"ak:cursor:c25hcHNob3Q",
            "cut_revision":cut,
            "coverage":{"realm":true,"strand_ids":[],"members":{"mode":"selected","actor_ids":[]},"event_ids":[]},
            "complete":complete
        })).unwrap()
    }

    fn frame(row: CurrentResultEntry, baseline: Option<RealmDetailBaseline>) -> RealmSyncEntry {
        let mut value = json!({"current":{"entries":[row]}});
        if let Some(baseline) = baseline {
            value["baseline"] = serde_json::to_value(baseline).unwrap();
        }
        serde_json::from_value(value).unwrap()
    }

    fn rows(row: CurrentResultEntry) -> BTreeMap<String, CurrentResultEntry> {
        BTreeMap::from([(row.selector().canonical_key().unwrap(), row)])
    }

    #[test]
    fn old_baseline_marks_seen_without_overwriting_interleaved_live_value() {
        let existing = rows(entry(12, true));
        let plan = plan_current_install(
            &CurrentRealmProgress::default(),
            &frame(entry(7, false), Some(segment(10, true))),
            &existing,
        )
        .unwrap();
        assert!(plan.writes.is_empty());
        assert_eq!(plan.seen_selectors.len(), 1);
        assert_eq!(plan.cleanup.unwrap().cut_revision, 10);
        assert_eq!(existing.values().next().unwrap().revision(), 12);
    }

    #[test]
    fn same_revision_conflict_is_rejected_before_any_host_mutation() {
        let existing = rows(entry(7, false));
        let previous = CurrentRealmProgress::default();
        assert!(
            plan_current_install(
                &previous,
                &frame(entry(7, true), Some(segment(10, true))),
                &existing,
            )
            .is_err()
        );
        assert!(previous.baseline.is_none());
        assert_eq!(existing.values().next().unwrap(), &entry(7, false));
    }

    #[test]
    fn invalidation_discards_old_completion_and_duplicate_does_not_reset_new_progress() {
        let mut progress = CurrentRealmProgress {
            baseline: Some(segment(10, false)),
            ..Default::default()
        };
        progress.invalidate(12);
        let stale = plan_current_install(
            &progress,
            &frame(entry(7, false), Some(segment(10, true))),
            &BTreeMap::new(),
        )
        .unwrap();
        assert!(stale.discard_frame);
        assert!(stale.cleanup.is_none());
        assert!(stale.progress.needs_refresh);
        progress.needs_refresh = false;
        progress.invalidate(12);
        assert!(!progress.needs_refresh);
    }

    #[test]
    fn completed_snapshot_replay_cannot_sweep_using_only_the_replayed_page() {
        let previous = CurrentRealmProgress {
            baseline: Some(segment(10, true)),
            ..Default::default()
        };
        let plan = plan_current_install(
            &previous,
            &frame(entry(7, false), Some(segment(10, false))),
            &BTreeMap::new(),
        )
        .unwrap();
        assert!(plan.progress.baseline.unwrap().complete);
        assert!(plan.cleanup.is_none());
        assert!(plan.writes.is_empty());
        assert!(plan.seen_selectors.is_empty());
    }

    #[test]
    fn late_live_delta_cannot_resurrect_a_covered_selector_pruned_at_the_cut() {
        let previous = CurrentRealmProgress {
            baseline: Some(segment(10, true)),
            ..Default::default()
        };
        let plan = plan_current_install(&previous, &frame(entry(7, false), None), &BTreeMap::new())
            .unwrap();
        assert!(plan.writes.is_empty());
        let plan =
            plan_current_install(&previous, &frame(entry(11, false), None), &BTreeMap::new())
                .unwrap();
        assert_eq!(plan.writes.len(), 1);
    }
}
