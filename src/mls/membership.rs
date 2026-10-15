//! MLS reconciliation over typed roster hints and accepted host facts.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

#[derive(Clone, Debug, PartialEq)]
pub struct MembershipFact {
    pub actor_id: String,
    pub membership: Option<String>,
    pub invite_id: Option<String>,
}
impl MembershipFact {
    pub fn bare(actor_id: impl Into<String>) -> Self {
        Self {
            actor_id: actor_id.into(),
            membership: None,
            invite_id: None,
        }
    }
    pub fn normalized_membership(&self) -> Option<&str> {
        self.membership
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
    }
}
/// Validate canonical roster entries and retain the first duplicate ActorId.
pub fn validated_realm_roster_entries(
    projection: Option<&Value>,
) -> Vec<arkret_models_collaboration::account_subscribe_projections::MemberRosterEntry> {
    let Some(members) = projection
        .and_then(|root| root.get("member_roster_entries"))
        .and_then(Value::as_array)
    else {
        return Vec::new();
    };
    let mut rows = BTreeMap::new();
    for member in members {
        let Ok(entry) = serde_json::from_value::<
            arkret_models_collaboration::account_subscribe_projections::MemberRosterEntry,
        >(member.clone()) else {
            continue;
        };
        if entry.validate().is_err() {
            continue;
        }
        rows.entry(entry.actor_id.clone()).or_insert(entry);
    }
    rows.into_values().collect()
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum MembershipCompleteness {
    #[default]
    Unavailable,
    Limited,
    Complete,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProjectedRealmMembershipHint {
    pub joined: BTreeSet<String>,
    pub completeness: MembershipCompleteness,
}

/// A roster is a wakeup hint; only a complete cut may establish absence.
pub fn projected_membership_hint(projection: Option<&Value>) -> ProjectedRealmMembershipHint {
    let Some(projection) = projection else {
        return ProjectedRealmMembershipHint::default();
    };
    let Some(_) = projection
        .get("member_roster_entries")
        .and_then(Value::as_array)
    else {
        return ProjectedRealmMembershipHint::default();
    };
    let joined = validated_realm_roster_entries(Some(projection))
        .into_iter()
        .filter(|member| member.membership == arkret_models_collaboration::account_subscribe_projections::MemberRosterMembership::Join)
        .map(|member| member.actor_id.to_string())
        .collect();
    let completeness = if projection
        .get("member_roster_entries_limited")
        .and_then(Value::as_bool)
        == Some(false)
    {
        MembershipCompleteness::Complete
    } else {
        MembershipCompleteness::Limited
    };
    ProjectedRealmMembershipHint {
        joined,
        completeness,
    }
}

pub fn admission_joined_members(
    hint: ProjectedRealmMembershipHint,
    facts: impl IntoIterator<Item = MembershipFact>,
) -> BTreeSet<String> {
    let mut joined = hint.joined;
    for member in facts {
        let actor_id = member.actor_id.trim();
        if actor_id.is_empty() {
            continue;
        }
        if member.normalized_membership() == Some("join") {
            joined.insert(actor_id.to_owned());
        } else {
            joined.remove(actor_id);
        }
    }
    joined
}
