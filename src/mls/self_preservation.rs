//! `encryption-and-audit.md` §2.9 / §5.6 self-preservation commit policy.
//!
//! Pure committer decisions: when an epoch is overdue, when this member's
//! deterministic jitter slot has opened, and what governance frontier a Remove
//! commit must canonicalize. No group handle, no host state — the caller reads
//! those facts and asks these functions what the spec says to do, which makes
//! the policy identical in every client rather than per host.

use arkret_policy::minimal_metadata_epoch_overdue;
use arkret_wire::EventId;

use super::status::MlsRuntimeError;

/// Canonicalize the governance frontier required for an MLS Remove commit.
///
/// The caller must pass the accepted `ak.device.revoke` event id or the
/// Realm/Circle governance Control Move that imported that revocation. This
/// helper deliberately does not fall back to `LocalSealView.frontier` or
/// `leaves`: those sets are useful for ordinary commit freshness but are not
/// proof that this Remove covers the specific revocation that triggered it.
pub fn canonical_mls_remove_membership_frontier(
    revocation_membership_frontier: &[EventId],
) -> Result<Vec<EventId>, MlsRuntimeError> {
    if revocation_membership_frontier.is_empty() {
        return Err(MlsRuntimeError::Commit(
            "MLS Remove governance binding requires the accepted ak.device.revoke event \
             or imported revocation Control Move frontier"
                .to_owned(),
        ));
    }
    let mut frontier = revocation_membership_frontier.to_vec();
    frontier.sort();
    frontier.dedup();
    Ok(frontier)
}

/// `encryption-and-audit.md` §5.6 — deterministic per-member jitter window
/// (whole hours) over which a large group spreads its self-preservation
/// commits. The spec's example is "hash by member order to assign delay": each eligible
/// committer maps to a stable slot in `[0, JITTER_SLOTS)` derived from
/// `hash(group_id, base_epoch, own_principal_did)`; a member only emits its
/// idle self-update once the epoch has aged past `slot` extra hours beyond the
/// §5.6 trigger floor. With pending-commit suppression (normative) the first
/// member to land its commit advances the epoch and resets every other
/// member's counter/timer, so later slots almost never fire — exactly the goal
/// of preventing large groups from emitting commits simultaneously at the threshold.
pub const SELF_PRESERVATION_JITTER_SLOTS: u64 = 24;

/// §5.6 deterministic jitter — has THIS member's slot opened yet?
///
/// `slot = hash(group_id ‖ base_epoch ‖ own_principal_did) mod
/// SELF_PRESERVATION_JITTER_SLOTS`. The member is cleared to emit once the
/// epoch has lived at least `slot` whole hours *beyond* the moment the §5.6
/// floor ([`should_force_epoch_advance`]) was crossed. We approximate "beyond
/// the floor" with epoch age, which is exact for the age-based trigger and a
/// safe over-delay for the message-count trigger (count-based floors only ever
/// add latency here, never skip the commit, because suppression + the next
/// idle pass re-evaluate). Binding `base_epoch` means the slot reshuffles every
/// epoch, so the same member doesn't always draw the long straw. Member order
/// (the principal-DID set) is read from the live group, matching the spec's
/// "member order".
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
    let elapsed = now.signed_duration_since(epoch_started_at);
    // Clock skew (now < epoch_started_at) reads as "no slot open yet"; the
    // committer simply waits, fail-safe identical to should_force_epoch_advance.
    elapsed >= chrono::Duration::hours(slot as i64)
}

/// `encryption-and-audit.md` §5.6 — normal-Realm self-preservation commit
/// SHOULD trigger: epoch has observed at least 1000 application messages
/// (implementations MAY declare a lower threshold).
pub const SELF_PRESERVATION_MAX_EPOCH_APP_MESSAGES: u64 = 1000;
/// §5.6 — normal-Realm self-preservation commit SHOULD trigger: epoch age is
/// at least 7 days (implementations MAY declare a shorter threshold).
pub const SELF_PRESERVATION_MAX_EPOCH_AGE_DAYS: i64 = 7;

/// `encryption-and-audit.md` §2.9 + §5.6 — pure committer decision: should a
/// send force-advance the MLS epoch *before* riding the current epoch?
///
/// For a `minimal_metadata_realm` Realm the §2.9 epoch-lifetime SHOULD is a
/// MUST of ≤1h (delegated to the SDK's
/// [`minimal_metadata_epoch_overdue`], which never reports clock
/// skew as overdue).
///
/// For a normal Realm this implements the §5.6 self-preservation SHOULD: a
/// self-update Commit is due once the current epoch has observed ≥ 1000
/// application messages OR has lived ≥ 7 days. §5.6 duplicate commit suppression
/// (normative): when a pending `ak.mls.commit` for this scope is already in
/// flight (`has_pending_commit`), a new self-preservation commit MUST NOT be
/// initiated — the pending commit will achieve the same epoch advance.
/// Clock skew (`now < epoch_started_at`) never reads as overdue.
pub fn should_force_epoch_advance(
    is_minimal_metadata: bool,
    epoch_started_at: chrono::DateTime<chrono::Utc>,
    now: chrono::DateTime<chrono::Utc>,
    app_messages_observed: u64,
    has_pending_commit: bool,
) -> bool {
    if is_minimal_metadata {
        // §2.9 MUST ≤1h — kept independent of the pending-commit suppression
        // so the stricter profile's fail-safe direction is preserved.
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
mod tests;
