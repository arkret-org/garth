//! Self-preservation commit policy.
//!
//! Pure committer decisions: when an epoch is overdue, and when this member's
//! deterministic jitter slot has opened. No group handle and no host state —
//! the caller reads those facts and asks these functions what to do, which
//! makes the policy identical in every client rather than per host.

use arkret_policy::minimal_metadata_epoch_overdue;

/// Deterministic per-member jitter window (whole hours) over which a large
/// group spreads its self-preservation commits. Each eligible committer maps to
/// a stable slot in `[0, JITTER_SLOTS)` derived from
/// `hash(group_id, base_epoch, own_principal_did)`.
pub const SELF_PRESERVATION_JITTER_SLOTS: u64 = 24;

/// Has THIS member's jitter slot opened yet?
///
/// The member is cleared to emit once the epoch has lived at least `slot` whole
/// hours. Binding `base_epoch` reshuffles the slot every epoch, so the same
/// member does not always draw the long straw. Clock skew (`now` before
/// `epoch_started_at`) reads as "no slot open yet", which is fail-safe.
pub fn idle_self_update_jitter_passed(
    group_id: &str,
    base_epoch: u64,
    own_principal_did: &str,
    epoch_started_at: chrono::DateTime<chrono::Utc>,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    use std::hash::{Hash as _, Hasher as _};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    group_id.hash(&mut hasher);
    base_epoch.hash(&mut hasher);
    own_principal_did.hash(&mut hasher);
    let slot = hasher.finish() % SELF_PRESERVATION_JITTER_SLOTS;
    now.signed_duration_since(epoch_started_at) >= chrono::Duration::hours(slot as i64)
}

/// Normal-Realm self-preservation commit trigger: the epoch has observed at
/// least this many application messages.
pub const SELF_PRESERVATION_MAX_EPOCH_APP_MESSAGES: u64 = 1000;
/// Normal-Realm self-preservation commit trigger: the epoch is at least this
/// many days old.
pub const SELF_PRESERVATION_MAX_EPOCH_AGE_DAYS: i64 = 7;

/// Should a send force-advance the MLS epoch before riding the current one?
///
/// For a minimal-metadata Realm the epoch lifetime is a hard ceiling, delegated
/// to the SDK's [`minimal_metadata_epoch_overdue`], which never reports clock
/// skew as overdue. For a normal Realm a self-update Commit is due once the
/// current epoch observed enough application messages or lived long enough.
/// When a commit for this scope is already in flight, a new self-preservation
/// commit MUST NOT start: the pending commit achieves the same epoch advance.
pub fn should_force_epoch_advance(
    is_minimal_metadata: bool,
    epoch_started_at: chrono::DateTime<chrono::Utc>,
    now: chrono::DateTime<chrono::Utc>,
    app_messages_observed: u64,
    has_pending_commit: bool,
) -> bool {
    if is_minimal_metadata {
        return minimal_metadata_epoch_overdue(epoch_started_at, now);
    }
    if has_pending_commit {
        return false;
    }
    if app_messages_observed >= SELF_PRESERVATION_MAX_EPOCH_APP_MESSAGES {
        return true;
    }
    now.signed_duration_since(epoch_started_at)
        >= chrono::Duration::days(SELF_PRESERVATION_MAX_EPOCH_AGE_DAYS)
}

#[cfg(test)]
mod tests {
    use chrono::Duration;

    use super::*;
    use crate::test_fixtures::at;

    #[test]
    fn a_pending_commit_suppresses_a_new_self_preservation_commit() {
        let started = at(0);
        let now = started + Duration::days(30);
        assert!(should_force_epoch_advance(
            false, started, now, 5_000, false
        ));
        assert!(!should_force_epoch_advance(
            false, started, now, 5_000, true
        ));
    }

    #[test]
    fn clock_skew_never_reads_as_overdue() {
        let started = at(0);
        assert!(!should_force_epoch_advance(
            false,
            started,
            started - Duration::days(1),
            0,
            false
        ));
        assert!(!should_force_epoch_advance(
            true,
            started,
            started - Duration::days(1),
            0,
            false
        ));
    }

    #[test]
    fn the_message_count_trigger_is_independent_of_epoch_age() {
        let started = at(0);
        assert!(should_force_epoch_advance(
            false,
            started,
            started + Duration::minutes(1),
            SELF_PRESERVATION_MAX_EPOCH_APP_MESSAGES,
            false
        ));
    }

    #[test]
    fn a_jitter_slot_opens_within_the_full_window() {
        let started = at(0);
        assert!(idle_self_update_jitter_passed(
            "group-a",
            4,
            "did:webvh:alice.example",
            started,
            started + Duration::hours(SELF_PRESERVATION_JITTER_SLOTS as i64)
        ));
    }

    #[test]
    fn the_jitter_slot_reshuffles_with_the_base_epoch() {
        let started = at(0);
        let open_slots = (0..64)
            .filter(|epoch| {
                idle_self_update_jitter_passed(
                    "group-a",
                    *epoch,
                    "did:webvh:alice.example",
                    started,
                    started + Duration::hours(1),
                )
            })
            .count();
        assert!(open_slots > 0 && open_slots < 64);
    }
}
