//! Account-subscribe Realm projection reconciliation.
//!
//! The account aggregate stream (`ak.self.account.subscribe.v1`) delivers a
//! Realm's product projection either as a full frame or as an incremental
//! delta. A client that caches the projection has to fold the two forms into
//! one cached value without losing state the server legitimately omitted from
//! a delta, and without letting a delta silently drop the create-locked
//! security classification.
//!
//! This is pure JSON folding over the wire shape: no host storage, no
//! transport, no UI. Every client that caches Realm projections needs exactly
//! this fold, which is why it lives here rather than in one host.

use std::collections::BTreeSet;

use serde_json::Value;

/// Account-subscribe Realm projection payload with explicit replacement
/// semantics. Full frames replace cached product state; incremental frames
/// overlay deltas while retaining omitted state.
#[derive(Clone, Copy, Debug)]
pub enum RealmProjectionFrame<'a> {
    Full(&'a Value),
    Incremental(&'a Value),
}

/// Reconcile one server Realm projection with its cached value, then retain
/// the last authoritative create-locked security classification when the
/// accepted frame does not repeat it.
pub fn reconcile_realm_projection(
    existing: Option<&Value>,
    frame: RealmProjectionFrame<'_>,
) -> Value {
    let projection = match frame {
        RealmProjectionFrame::Full(incoming) => incoming.clone(),
        RealmProjectionFrame::Incremental(incoming) => {
            merge_incremental_realm_projection(existing, incoming)
        }
    };
    preserve_realm_security_projection(existing, &projection)
}

fn overlay_json_object(base: &mut Value, incoming: &Value) {
    let (Some(base), Some(incoming)) = (base.as_object_mut(), incoming.as_object()) else {
        *base = incoming.clone();
        return;
    };
    for (key, value) in incoming {
        match base.get_mut(key) {
            Some(current) if current.is_object() && value.is_object() => {
                overlay_json_object(current, value);
            }
            _ => {
                base.insert(key.clone(), value.clone());
            }
        }
    }
}

fn event_id(event: &Value) -> Option<&str> {
    event.get("event_id").and_then(Value::as_str)
}

fn state_event_cells(event: &Value) -> BTreeSet<&str> {
    event
        .get("effects")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|effect| effect.get("cell").and_then(Value::as_str))
        .collect()
}

fn merged_event_container(
    cached: Option<&Value>,
    incoming: &Value,
    replace_same_state_cell: bool,
) -> Value {
    let mut merged = incoming.clone();
    let Some(incoming_events) = incoming.get("events").and_then(Value::as_array) else {
        return merged;
    };
    let mut events = cached
        .and_then(|container| container.get("events"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    for incoming_event in incoming_events {
        let incoming_id = event_id(incoming_event);
        let incoming_cells = replace_same_state_cell.then(|| state_event_cells(incoming_event));
        events.retain(|cached_event| {
            if incoming_id.is_some() && event_id(cached_event) == incoming_id {
                return false;
            }
            let Some(incoming_cells) = incoming_cells.as_ref() else {
                return true;
            };
            if incoming_cells.is_empty() {
                return true;
            }
            state_event_cells(cached_event).is_disjoint(incoming_cells)
        });
        events.push(incoming_event.clone());
    }
    if let Some(object) = merged.as_object_mut() {
        object.insert("events".to_owned(), Value::Array(events));
    }
    merged
}

fn without_state_cells(container: Option<&Value>, cells: &BTreeSet<&str>) -> Option<Value> {
    let mut container = container?.clone();
    let Some(events) = container.get_mut("events").and_then(Value::as_array_mut) else {
        return Some(container);
    };
    events.retain(|event| state_event_cells(event).is_disjoint(cells));
    Some(container)
}

fn state_container_cells(container: Option<&Value>) -> BTreeSet<&str> {
    container
        .and_then(|container| container.get("events"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .flat_map(state_event_cells)
        .collect()
}

/// Apply an account-subscribe Realm delta without treating omitted fields or
/// current-state cells as deletions. `client-sync.md` defines `state` and
/// `state_after` as deltas; timeline events are likewise incremental.
fn merge_incremental_realm_projection(cached: Option<&Value>, incoming: &Value) -> Value {
    let Some(cached) = cached else {
        return incoming.clone();
    };
    let mut merged = cached.clone();
    overlay_json_object(&mut merged, incoming);
    let Some(object) = merged.as_object_mut() else {
        return incoming.clone();
    };
    let incoming_state_cells = state_container_cells(incoming.get("state"));
    let incoming_state_after_cells = state_container_cells(incoming.get("state_after"));
    let mut state = incoming
        .get("state")
        .map(|container| merged_event_container(cached.get("state"), container, true));
    if state.is_none() && !incoming_state_after_cells.is_empty() {
        state = without_state_cells(cached.get("state"), &incoming_state_after_cells);
    } else if !incoming_state_after_cells.is_empty() {
        state = without_state_cells(state.as_ref(), &incoming_state_after_cells);
    }
    if let Some(state) = state {
        object.insert("state".to_owned(), state);
    }

    let state_after_base = without_state_cells(cached.get("state_after"), &incoming_state_cells);
    let state_after = incoming
        .get("state_after")
        .map(|container| merged_event_container(state_after_base.as_ref(), container, true));
    if let Some(state_after) = state_after.or(state_after_base) {
        object.insert("state_after".to_owned(), state_after);
    }
    if let Some(container) = incoming.get("timeline") {
        object.insert(
            "timeline".to_owned(),
            merged_event_container(cached.get("timeline"), container, false),
        );
    }
    merged
}

fn preserve_realm_security_projection(existing: Option<&Value>, incoming: &Value) -> Value {
    let security_state = super::security_state::realm_projection_security_state(incoming)
        .or_else(|| existing.and_then(super::security_state::realm_projection_security_state));
    let mut merged = incoming.clone();
    if let (Some(encrypted), Some(object)) = (security_state, merged.as_object_mut()) {
        // `encryption_profile` is create-locked. Accepted account frames can
        // omit the original `ak.realm.create` event, so retain the last
        // authoritative classification instead of silently downgrading the UI.
        object.insert(
            "__realm_security_encrypted".to_owned(),
            Value::Bool(encrypted),
        );
    }
    merged
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn incremental_realm_delta_preserves_omitted_policy_state() {
        let cached = json!({
            "__kind": "realm",
            "content_scheme": "mls_exporter_aead_v1",
            "history_access": "all_history_for_current_members",
            "summary": {"title": "Shared history"},
            "state": {"events": [
                {
                    "event_id": "ak:event:AOPouRuEAbPjs9CNNW54RZQ5izPb-t3rASYtAKICB4_4",
                    "kind": "ak.realm.create",
                    "effects": [{"cell": "ak:cell:realm.create"}]
                },
                {
                    "event_id": "ak:event:AYwttCl6UHftOF7dIFruPKJ1OzaTcqP5xL4VBoi3jCV0",
                    "kind": "ak.realm.policy_bundle",
                    "effects": [{"cell": "ak:cell:realm.policy_bundle"}],
                    "payload": {"value": {"content_scheme": "mls_exporter_aead_v1"}}
                }
            ]},
            "timeline": {"events": [{"event_id": "ak:event:ArdiKvN1WdQsibAXsFKmzazqXR5bjyMgrLwAYfQJlfNg"}]}
        });
        let incoming = json!({
            "summary": {"joined_member_count": 1},
            "state": {"events": [{
                "event_id": "ak:event:AbY3zzcatsuTwazU86xXdmZh0E8aA5G_xs4cT5T1GSt4",
                "kind": "ak.mls.genesis"
            }]},
            "timeline": {"events": [{"event_id": "ak:event:ArUan4HuaK0xF-YoPctbaNdHflOJq9noQhgxcuPYUjFc"}]}
        });

        let merged =
            reconcile_realm_projection(Some(&cached), RealmProjectionFrame::Incremental(&incoming));

        assert_eq!(merged["content_scheme"], "mls_exporter_aead_v1");
        assert_eq!(merged["summary"]["title"], "Shared history");
        assert_eq!(merged["summary"]["joined_member_count"], 1);
        assert_eq!(merged["state"]["events"].as_array().unwrap().len(), 3);
        assert_eq!(merged["timeline"]["events"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn incremental_state_delta_replaces_the_same_reducer_cell() {
        let cached = json!({
            "state": {"events": [{
                "event_id": "ak:event:AeNOC6NPDq283vfH6UTqiJq9Uy2DXQQ01SIj_J7jhkO0",
                "kind": "ak.realm.policy_bundle",
                "effects": [{"cell": "ak:cell:realm.policy_bundle"}],
                "payload": {"value": {"content_scheme": "mls_rfc9420"}}
            }]},
            "state_after": {"events": [{
                "event_id": "ak:event:AHofA7a120KAdEJgSXxs6l9Nnna66PU65X3xDL_awEBw",
                "kind": "ak.realm.policy_bundle",
                "effects": [{"cell": "ak:cell:realm.policy_bundle"}],
                "payload": {"value": {"content_scheme": "mls_rfc9420"}}
            }]}
        });
        let incoming = json!({
            "state": {"events": [{
                "event_id": "ak:event:Avv2ZpC4D6LojRWUseH7_Cn0rzqd7GLMSKGeMxqLlY44",
                "kind": "ak.realm.policy_bundle",
                "effects": [{"cell": "ak:cell:realm.policy_bundle"}],
                "payload": {"value": {"content_scheme": "mls_exporter_aead_v1"}}
            }]}
        });

        let merged =
            reconcile_realm_projection(Some(&cached), RealmProjectionFrame::Incremental(&incoming));
        let events = merged["state"]["events"].as_array().unwrap();

        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0]["event_id"],
            "ak:event:Avv2ZpC4D6LojRWUseH7_Cn0rzqd7GLMSKGeMxqLlY44"
        );
        assert!(
            merged["state_after"]["events"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn incremental_state_after_delta_shadows_the_same_current_state_cell() {
        let cached = json!({
            "state": {"events": [{
                "event_id": "ak:event:AeNOC6NPDq283vfH6UTqiJq9Uy2DXQQ01SIj_J7jhkO0",
                "kind": "ak.realm.policy_bundle",
                "effects": [{"cell": "ak:cell:realm.policy_bundle"}],
                "payload": {"value": {"content_scheme": "mls_rfc9420"}}
            }]}
        });
        let incoming = json!({
            "state_after": {"events": [{
                "event_id": "ak:event:Avv2ZpC4D6LojRWUseH7_Cn0rzqd7GLMSKGeMxqLlY44",
                "kind": "ak.realm.policy_bundle",
                "effects": [{"cell": "ak:cell:realm.policy_bundle"}],
                "payload": {"value": {"content_scheme": "mls_exporter_aead_v1"}}
            }]}
        });

        let merged =
            reconcile_realm_projection(Some(&cached), RealmProjectionFrame::Incremental(&incoming));

        assert!(merged["state"]["events"].as_array().unwrap().is_empty());
        assert_eq!(
            merged["state_after"]["events"][0]["event_id"],
            "ak:event:Avv2ZpC4D6LojRWUseH7_Cn0rzqd7GLMSKGeMxqLlY44"
        );
    }

    #[test]
    fn incremental_realm_projection_preserves_create_locked_security_state() {
        let encrypted_create = json!({
            "state_at_window_start": {"e2ee_epoch": null},
            "state": {"events": [{
                "kind": "ak.realm.create",
                "payload": {"object": {"encryption_profile": "mls_rfc9420"}}
            }]}
        });
        let initial =
            reconcile_realm_projection(None, RealmProjectionFrame::Full(&encrypted_create));
        assert_eq!(initial["__realm_security_encrypted"], true);

        let partial_delta = json!({
            "state_at_window_start": {
                "realm_metadata": {"title": "Renamed Realm"},
                "e2ee_epoch": null
            },
            "state": {"events": []}
        });
        let merged = reconcile_realm_projection(
            Some(&initial),
            RealmProjectionFrame::Incremental(&partial_delta),
        );

        assert_eq!(merged["__realm_security_encrypted"], true);
        assert!(crate::projection::security_state::realm_projection_is_encrypted(&merged));
    }

    #[test]
    fn full_realm_projection_replaces_product_state_but_preserves_security() {
        let cached = json!({
            "__realm_security_encrypted": true,
            "summary": {"title": "Stale title"},
            "timeline": {"events": [{"event_id": "ak:event:stale"}]}
        });
        let incoming = json!({
            "summary": {"title": "Authoritative title"},
            "state": {"events": []}
        });

        let reconciled =
            reconcile_realm_projection(Some(&cached), RealmProjectionFrame::Full(&incoming));

        assert_eq!(reconciled["__realm_security_encrypted"], true);
        assert_eq!(reconciled["summary"]["title"], "Authoritative title");
        assert!(reconciled.get("timeline").is_none());
    }

    #[test]
    fn full_realm_projection_prefers_explicit_security_over_cached_fallback() {
        let cached = json!({"__realm_security_encrypted": true});
        let incoming = json!({
            "state_at_window_start": {"e2ee_epoch": null},
            "state": {"events": [{
                "kind": "ak.realm.create",
                "payload": {"object": {"encryption_profile": "none"}}
            }]}
        });

        let reconciled =
            reconcile_realm_projection(Some(&cached), RealmProjectionFrame::Full(&incoming));

        assert_eq!(reconciled["__realm_security_encrypted"], false);
    }

    #[test]
    fn incremental_timeline_deduplicates_and_preserves_event_order() {
        let cached = json!({
            "timeline": {"events": [
                {"event_id": "ak:event:one", "payload": {"version": 1}},
                {"event_id": "ak:event:two", "payload": {"version": 1}}
            ]}
        });
        let incoming = json!({
            "timeline": {"events": [
                {"event_id": "ak:event:two", "payload": {"version": 2}},
                {"event_id": "ak:event:three", "payload": {"version": 1}}
            ]}
        });

        let reconciled =
            reconcile_realm_projection(Some(&cached), RealmProjectionFrame::Incremental(&incoming));
        let events = reconciled["timeline"]["events"].as_array().unwrap();
        let event_ids = events
            .iter()
            .map(|event| event["event_id"].as_str().unwrap())
            .collect::<Vec<_>>();

        assert_eq!(
            event_ids,
            vec!["ak:event:one", "ak:event:two", "ak:event:three"]
        );
        assert_eq!(events[1]["payload"]["version"], 2);
    }

    #[test]
    fn realm_projection_keeps_explicit_plaintext_state() {
        let plaintext_create = json!({
            "state_at_window_start": {"e2ee_epoch": null},
            "state": {"events": [{
                "kind": "ak.realm.create",
                "payload": {"object": {"encryption_profile": "none"}}
            }]}
        });
        let merged =
            reconcile_realm_projection(None, RealmProjectionFrame::Full(&plaintext_create));

        assert_eq!(merged["__realm_security_encrypted"], false);
        assert!(!crate::projection::security_state::realm_projection_is_encrypted(&merged));
    }
}
