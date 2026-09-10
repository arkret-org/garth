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

fn merged_event_container(cached: Option<&Value>, incoming: &Value) -> Value {
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
        events
            .retain(|cached_event| incoming_id.is_none() || event_id(cached_event) != incoming_id);
        events.push(incoming_event.clone());
    }
    if let Some(object) = merged.as_object_mut() {
        object.insert("events".to_owned(), Value::Array(events));
    }
    merged
}

/// Merge timeline and presentation metadata. Current selectors are installed
/// by the host transaction; raw current pages must never be folded as Events.
fn merge_incremental_realm_projection(cached: Option<&Value>, incoming: &Value) -> Value {
    let Some(cached) = cached else {
        return incoming.clone();
    };
    let mut merged = cached.clone();
    overlay_json_object(&mut merged, incoming);
    let Some(object) = merged.as_object_mut() else {
        return incoming.clone();
    };
    // The bounded materialized current view is supplied separately by the
    // durable current store after its commit pointer is installed.
    object.remove("current");
    if let Some(current) = cached.get("current") {
        object.insert("current".to_owned(), current.clone());
    }
    if let Some(container) = incoming.get("timeline") {
        object.insert(
            "timeline".to_owned(),
            merged_event_container(cached.get("timeline"), container),
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
    fn incremental_realm_projection_preserves_create_locked_security_state() {
        let encrypted_create = json!({
            "state_at_window_start": {"e2ee_epoch": null},
            "current": {"entries": [{
                "selector":{"scope_ref":{"kind":"realm","realm_id":"ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI"},"cell_id":"ak:cell:ak.component.realm.genesis.v1:null"},
                "result":{"status":"value","value":{"encryption_profile":"mls_rfc9420"}}
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
            "current": {"entries": []}
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
            "current": {"entries": []}
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
            "current": {"entries": [{
                "selector":{"scope_ref":{"kind":"realm","realm_id":"ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI"},"cell_id":"ak:cell:ak.component.realm.genesis.v1:null"},
                "result":{"status":"value","value":{"encryption_profile":"none"}}
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
            "current": {"entries": [{
                "selector":{"scope_ref":{"kind":"realm","realm_id":"ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI"},"cell_id":"ak:cell:ak.component.realm.genesis.v1:null"},
                "result":{"status":"value","value":{"encryption_profile":"none"}}
            }]}
        });
        let merged =
            reconcile_realm_projection(None, RealmProjectionFrame::Full(&plaintext_create));

        assert_eq!(merged["__realm_security_encrypted"], false);
        assert!(!crate::projection::security_state::realm_projection_is_encrypted(&merged));
    }
}
