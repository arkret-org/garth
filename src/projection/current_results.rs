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

/// Window-level facts a frozen timeline window states once and repeats in
/// every segment (`client-sync.md` 5.2). A producer that varies them per
/// segment makes the window unreadable, so the client refuses the segment
/// rather than picking a value.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimelineWindowLevel {
    pub limited: bool,
    pub preview_only: Option<bool>,
    pub prev_cursor: Option<String>,
}

/// Client-side progress of one Realm's frozen timeline window.
///
/// This is the client half of `realms[id].timeline_baseline`. It is small
/// durable metadata: one generation, its ceiling, its window-level facts and a
/// delivered count. It never grows with history.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct TimelineWindowProgress {
    pub generation: Option<Cursor>,
    /// Immediately superseded generation. Segments naming it are late
    /// responses to interest the client already replaced and must not resolve
    /// or disturb the window it is now waiting on.
    pub superseded_generation: Option<Cursor>,
    pub window_limit: u32,
    pub window_level: Option<TimelineWindowLevel>,
    pub delivered: u32,
    pub complete: bool,
}

impl TimelineWindowProgress {
    /// Retire the tracked window. Interest replacement and Realm invalidation
    /// both land here: the old completion stops being binding and the client
    /// waits for the rebuilt window instead of showing a stale one as done.
    pub fn supersede(&mut self) {
        if let Some(generation) = self.generation.take() {
            self.superseded_generation = Some(generation);
        }
        self.window_limit = 0;
        self.window_level = None;
        self.delivered = 0;
        self.complete = false;
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum TimelineSegmentInstall {
    /// Frozen-window content for the tracked generation.
    Window,
    /// Live increment: it installs content but never completes, reopens or
    /// advances a frozen window.
    Live,
    /// A late segment of a superseded generation, or an entry with no timeline.
    Discard,
}

#[derive(Clone, Debug)]
pub struct TimelineWindowPlan {
    pub progress: TimelineWindowProgress,
    pub install: TimelineSegmentInstall,
    /// The window finished in this frame. Delivery only: it proves nothing
    /// about per-event authentication, decryption, display dependencies, full
    /// history or any read/write permission.
    pub completed_now: bool,
}

/// Preflight one Realm entry's timeline segment without changing host state.
///
/// `delivered_events` is the count of events the host will actually install
/// from this segment after its own identity-based dedupe, so a retried segment
/// cannot inflate the window past its ceiling.
pub fn plan_timeline_window(
    previous: &TimelineWindowProgress,
    incoming: &RealmSyncEntry,
    delivered_events: u32,
) -> Result<TimelineWindowPlan> {
    incoming.validate_demand()?;
    let mut plan = TimelineWindowPlan {
        progress: previous.clone(),
        install: TimelineSegmentInstall::Discard,
        completed_now: false,
    };
    if incoming.unavailable.is_some() {
        // Unavailable is a third outcome: it ends the wait without completing
        // the window and without becoming a successful empty result.
        plan.progress.supersede();
        return Ok(plan);
    }
    let Some(timeline) = &incoming.timeline else {
        return Ok(plan);
    };
    let Some(segment) = &incoming.timeline_baseline else {
        plan.install = TimelineSegmentInstall::Live;
        return Ok(plan);
    };
    let window_level = TimelineWindowLevel {
        limited: timeline.limited,
        preview_only: timeline.preview_only,
        prev_cursor: timeline.prev_cursor.clone(),
    };
    if previous.superseded_generation.as_ref() == Some(&segment.snapshot_cursor) {
        return Ok(plan);
    }
    if previous.generation.as_ref() == Some(&segment.snapshot_cursor) {
        if previous.window_limit != segment.window_limit {
            return Err(invalid(
                "timeline window limit changed inside one frozen generation",
            ));
        }
        if previous.window_level.as_ref() != Some(&window_level) {
            return Err(invalid(
                "timeline window-level field changed inside one frozen generation",
            ));
        }
    } else {
        plan.progress.supersede();
        plan.progress.generation = Some(segment.snapshot_cursor.clone());
        plan.progress.window_limit = segment.window_limit;
        plan.progress.window_level = Some(window_level);
    }
    plan.progress.delivered = plan.progress.delivered.saturating_add(delivered_events);
    if plan.progress.delivered > segment.window_limit {
        return Err(invalid("timeline window delivered more than its ceiling"));
    }
    plan.install = TimelineSegmentInstall::Window;
    if segment.complete {
        plan.completed_now = !plan.progress.complete;
        plan.progress.complete = true;
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

    const GEN_A: &str = "ak:cursor:Z2VuZXJhdGlvbmE";
    const GEN_B: &str = "ak:cursor:Z2VuZXJhdGlvbmI";

    fn window_frame(
        generation: Option<(&str, u32, bool)>,
        limited: bool,
        prev_cursor: Option<&str>,
    ) -> RealmSyncEntry {
        let mut timeline = json!({"events": [], "limited": limited});
        if let Some(prev_cursor) = prev_cursor {
            timeline["prev_cursor"] = json!(prev_cursor);
        }
        let mut value = json!({"timeline": timeline});
        if let Some((cursor, window_limit, complete)) = generation {
            value["timeline_baseline"] = json!({
                "snapshot_cursor": cursor,
                "window_limit": window_limit,
                "complete": complete
            });
        }
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn segmented_window_completes_only_after_its_last_segment() {
        let progress = TimelineWindowProgress::default();
        let first = plan_timeline_window(
            &progress,
            &window_frame(Some((GEN_A, 20, false)), false, None),
            5,
        )
        .unwrap();
        assert_eq!(first.install, TimelineSegmentInstall::Window);
        assert!(!first.progress.complete);
        assert_eq!(first.progress.delivered, 5);
        let last = plan_timeline_window(
            &first.progress,
            &window_frame(Some((GEN_A, 20, true)), false, None),
            3,
        )
        .unwrap();
        assert!(last.progress.complete);
        assert!(last.completed_now);
        assert_eq!(last.progress.delivered, 8);
    }

    #[test]
    fn live_segment_neither_completes_nor_advances_the_window() {
        let seeded = plan_timeline_window(
            &TimelineWindowProgress::default(),
            &window_frame(Some((GEN_A, 20, false)), false, None),
            4,
        )
        .unwrap()
        .progress;
        let live = plan_timeline_window(&seeded, &window_frame(None, false, None), 7).unwrap();
        assert_eq!(live.install, TimelineSegmentInstall::Live);
        assert_eq!(live.progress.delivered, 4);
        assert!(!live.progress.complete);
    }

    #[test]
    fn window_level_facts_and_ceiling_must_not_move_inside_one_generation() {
        let seeded = plan_timeline_window(
            &TimelineWindowProgress::default(),
            &window_frame(Some((GEN_A, 20, false)), true, Some("ak:cursor:cHJldg")),
            5,
        )
        .unwrap()
        .progress;
        assert!(
            plan_timeline_window(
                &seeded,
                &window_frame(Some((GEN_A, 10, true)), true, Some("ak:cursor:cHJldg")),
                1
            )
            .is_err()
        );
        assert!(
            plan_timeline_window(
                &seeded,
                &window_frame(Some((GEN_A, 20, true)), false, None),
                1
            )
            .is_err()
        );
        assert!(
            plan_timeline_window(
                &seeded,
                &window_frame(Some((GEN_A, 20, true)), true, Some("ak:cursor:cHJldg")),
                16
            )
            .is_err(),
            "a window must not deliver past its own ceiling"
        );
    }

    #[test]
    fn a_superseded_generation_cannot_complete_the_window_the_client_waits_on() {
        let first = plan_timeline_window(
            &TimelineWindowProgress::default(),
            &window_frame(Some((GEN_A, 20, false)), false, None),
            5,
        )
        .unwrap()
        .progress;
        let rebuilt = plan_timeline_window(
            &first,
            &window_frame(Some((GEN_B, 50, false)), false, None),
            0,
        )
        .unwrap();
        assert_eq!(
            rebuilt.progress.generation.as_ref().map(Cursor::as_str),
            Some(GEN_B)
        );
        assert_eq!(rebuilt.progress.delivered, 0);
        let stale = plan_timeline_window(
            &rebuilt.progress,
            &window_frame(Some((GEN_A, 20, true)), false, None),
            5,
        )
        .unwrap();
        assert_eq!(stale.install, TimelineSegmentInstall::Discard);
        assert!(!stale.progress.complete);
        assert_eq!(
            stale.progress.generation.as_ref().map(Cursor::as_str),
            Some(GEN_B)
        );
    }

    #[test]
    fn unavailable_ends_the_wait_without_completing_the_window() {
        let seeded = plan_timeline_window(
            &TimelineWindowProgress::default(),
            &window_frame(Some((GEN_A, 20, false)), false, None),
            3,
        )
        .unwrap()
        .progress;
        let entry: RealmSyncEntry = serde_json::from_value(
            json!({"unavailable": {"error_code": "temporarily_unavailable"}}),
        )
        .unwrap();
        let plan = plan_timeline_window(&seeded, &entry, 0).unwrap();
        assert_eq!(plan.install, TimelineSegmentInstall::Discard);
        assert!(!plan.progress.complete);
        assert_eq!(
            plan.progress
                .superseded_generation
                .as_ref()
                .map(Cursor::as_str),
            Some(GEN_A)
        );
    }

    #[test]
    fn a_zero_item_window_still_completes_explicitly() {
        let plan = plan_timeline_window(
            &TimelineWindowProgress::default(),
            &window_frame(Some((GEN_A, 0, true)), false, None),
            0,
        )
        .unwrap();
        assert!(plan.progress.complete);
        assert_eq!(plan.progress.delivered, 0);
        assert_eq!(plan.progress.window_limit, 0);
    }
}
