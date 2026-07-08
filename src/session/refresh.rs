use chrono::{DateTime, Utc};

pub const REFRESH_SKEW_SECS: i64 = 60;
pub const POLL_INTERVAL_SECS: u64 = 30;
pub const GRANT_ROTATION_SKEW_SECS: i64 = 30 * 60;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefreshDecision {
    NoGrant,
    Fresh,
    Due,
    GrantExpired,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionGrantRefreshState {
    pub grant_expires_at: Option<DateTime<Utc>>,
}

pub fn grant_due_for_rotation(grant: &SessionGrantRefreshState, now: DateTime<Utc>) -> bool {
    match grant.grant_expires_at {
        Some(expires_at) => expires_at.timestamp() - now.timestamp() <= GRANT_ROTATION_SKEW_SECS,
        None => false,
    }
}

pub fn grant_is_dead(grant: &SessionGrantRefreshState, now: DateTime<Utc>) -> bool {
    matches!(grant.grant_expires_at, Some(expires_at) if expires_at <= now)
}

pub fn refresh_decision(
    grant: Option<&SessionGrantRefreshState>,
    now: DateTime<Utc>,
) -> RefreshDecision {
    let Some(grant) = grant else {
        return RefreshDecision::NoGrant;
    };
    if grant_is_dead(grant, now) {
        return RefreshDecision::GrantExpired;
    }
    if grant_due_for_rotation(grant, now) {
        return RefreshDecision::Due;
    }
    RefreshDecision::Fresh
}

#[cfg(test)]
mod tests {
    use chrono::Duration;

    use super::*;

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-07-08T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    fn grant_with_expiry(grant_secs: i64) -> SessionGrantRefreshState {
        SessionGrantRefreshState {
            grant_expires_at: Some(now() + Duration::seconds(grant_secs)),
        }
    }

    #[test]
    fn decision_no_grant_when_unset() {
        assert_eq!(refresh_decision(None, now()), RefreshDecision::NoGrant);
    }

    #[test]
    fn decision_fresh_when_runway_long() {
        let grant = grant_with_expiry(86400);
        assert_eq!(
            refresh_decision(Some(&grant), now()),
            RefreshDecision::Fresh
        );
    }

    #[test]
    fn decision_due_when_grant_within_rotation_skew() {
        let grant = grant_with_expiry(600);
        assert_eq!(refresh_decision(Some(&grant), now()), RefreshDecision::Due);
    }

    #[test]
    fn decision_fresh_when_grant_expiry_unknown() {
        let grant = SessionGrantRefreshState {
            grant_expires_at: None,
        };
        assert_eq!(
            refresh_decision(Some(&grant), now()),
            RefreshDecision::Fresh
        );
    }

    #[test]
    fn decision_grant_expired_when_past_grant_window() {
        let grant = grant_with_expiry(-60);
        assert_eq!(
            refresh_decision(Some(&grant), now()),
            RefreshDecision::GrantExpired
        );
    }

    #[test]
    fn grant_due_for_rotation_fires_only_inside_skew() {
        assert!(!grant_due_for_rotation(&grant_with_expiry(7200), now()));
        assert!(grant_due_for_rotation(&grant_with_expiry(600), now()));

        let unknown = SessionGrantRefreshState {
            grant_expires_at: None,
        };
        assert!(!grant_due_for_rotation(&unknown, now()));
    }

    #[test]
    fn poll_constants_are_sane() {
        const { assert!(POLL_INTERVAL_SECS > 0) };
        const { assert!(POLL_INTERVAL_SECS <= 60) };
        const { assert!(REFRESH_SKEW_SECS > POLL_INTERVAL_SECS as i64) };
    }
}
