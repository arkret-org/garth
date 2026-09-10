//! Tests for §5.6 forced-epoch-advance and deterministic member-order jitter.

use super::*;

#[test]
fn force_epoch_advance_only_for_overdue_minimal_metadata_realm() {
    use chrono::{Duration, Utc};
    let started = Utc::now();
    // Non-minimal Realm: hours-old epoch with few messages is not forced.
    assert!(!should_force_epoch_advance(
        false,
        started,
        started + Duration::hours(5),
        10,
        false,
    ));
    // Minimal Realm under the 1h cap: not forced.
    assert!(!should_force_epoch_advance(
        true,
        started,
        started + Duration::minutes(59),
        0,
        false,
    ));
    // Exactly 1h is the inclusive cap (overdue is strictly >1h).
    assert!(!should_force_epoch_advance(
        true,
        started,
        started + Duration::hours(1),
        0,
        false,
    ));
    // Minimal Realm past 1h: forced.
    assert!(should_force_epoch_advance(
        true,
        started,
        started + Duration::hours(1) + Duration::seconds(1),
        0,
        false,
    ));
    // Clock skew (now < started) is never overdue.
    assert!(!should_force_epoch_advance(
        true,
        started,
        started - Duration::minutes(10),
        0,
        false,
    ));
}

#[test]
fn self_preservation_commit_triggers_for_normal_realm_per_spec_5_6() {
    // `encryption-and-audit.md` §5.6 self-preservation
    // SHOULD triggers for a normal (non-minimal-metadata) Realm.
    use chrono::{Duration, Utc};
    let started = Utc::now();
    // ≥1000 observed application messages in the epoch → forced.
    assert!(should_force_epoch_advance(
        false,
        started,
        started + Duration::minutes(1),
        SELF_PRESERVATION_MAX_EPOCH_APP_MESSAGES,
        false,
    ));
    assert!(!should_force_epoch_advance(
        false,
        started,
        started + Duration::minutes(1),
        SELF_PRESERVATION_MAX_EPOCH_APP_MESSAGES - 1,
        false,
    ));
    // Epoch alive ≥7 days → forced (message count irrelevant).
    assert!(should_force_epoch_advance(
        false,
        started,
        started + Duration::days(7),
        0,
        false,
    ));
    assert!(!should_force_epoch_advance(
        false,
        started,
        started + Duration::days(7) - Duration::seconds(1),
        0,
        false,
    ));
    // §5.6 duplicate commit suppression (MUST): a pending `ak.mls.commit` for the
    // scope suppresses a new self-preservation commit on both triggers.
    assert!(!should_force_epoch_advance(
        false,
        started,
        started + Duration::days(30),
        10 * SELF_PRESERVATION_MAX_EPOCH_APP_MESSAGES,
        true,
    ));
    // Clock skew never reads as overdue for the age trigger.
    assert!(!should_force_epoch_advance(
        false,
        started,
        started - Duration::days(30),
        0,
        false,
    ));
}

#[test]
fn idle_self_update_jitter_is_deterministic_and_bounded() {
    // §5.6 deterministic member-order jitter (SHOULD).
    use chrono::{Duration, Utc};
    let started = Utc::now();
    let group = "ak:mls:group:g1";
    let epoch = 7u64;

    // A given (group, epoch, member) slot is stable: same inputs ⇒ same
    // verdict at every probed elapsed time.
    for member in ["did:key:zAlice", "did:key:zBob", "did:key:zCarol"] {
        for hours in [0i64, 1, 12, 23, 24, 48] {
            let now = started + Duration::hours(hours);
            let a = idle_self_update_jitter_passed(group, epoch, member, started, now);
            let b = idle_self_update_jitter_passed(group, epoch, member, started, now);
            assert_eq!(a, b, "jitter verdict must be deterministic");
        }
    }

    // Every member's slot has opened by SELF_PRESERVATION_JITTER_SLOTS-1
    // whole hours (the max possible slot), so a sufficiently-aged epoch
    // clears all members — the commit is never permanently withheld.
    let well_aged = started + Duration::hours(SELF_PRESERVATION_JITTER_SLOTS as i64);
    for member in [
        "did:key:zAlice",
        "did:key:zBob",
        "did:key:zCarol",
        "did:key:zDave",
    ] {
        assert!(
            idle_self_update_jitter_passed(group, epoch, member, started, well_aged),
            "max-aged epoch must clear every member's jitter slot",
        );
    }

    // Clock skew (now < started) is never cleared — fail-safe identical to
    // should_force_epoch_advance.
    assert!(!idle_self_update_jitter_passed(
        group,
        epoch,
        "did:key:zAlice",
        started,
        started - Duration::hours(5),
    ));

    // The slot reshuffles across epochs: at least one member draws a
    // different verdict at a mid-window age when only the base epoch
    // changes (guards against a constant/degenerate slot assignment).
    let mid = started + Duration::hours(1);
    let differs = [
        "did:key:zAlice",
        "did:key:zBob",
        "did:key:zCarol",
        "did:key:zEve",
    ]
    .iter()
    .any(|m| {
        idle_self_update_jitter_passed(group, 7, m, started, mid)
            != idle_self_update_jitter_passed(group, 8, m, started, mid)
    });
    assert!(differs, "jitter slot must depend on base_epoch");
}
