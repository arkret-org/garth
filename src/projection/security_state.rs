//! Wire-projection security classification and Realm authority-root reading.
//!
//! A client decides whether a Realm / Strand / Circle projection is encrypted
//! by reading the accepted projection itself, never by trusting a local flag.
//! The same projection carries the Realm authority-root controller. Both are
//! pure reads over the wire shape, shared by every client that renders or
//! gates on a projection.

use std::collections::BTreeMap;

use arkret_wire::{ActorId, EventKind, event_kind_str};
use serde_json::Value;

/// First non-empty trimmed string under any of `keys`.
pub fn string_field(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| non_empty_string(value.get(*key)))
}

/// The trimmed string behind `value`, or `None` when absent / blank.
pub fn non_empty_string(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn bool_field(value: &Value, keys: &[&str]) -> Option<bool> {
    keys.iter().find_map(|key| value.get(*key)?.as_bool())
}

fn path_value<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut current = value;
    for segment in path {
        current = current.get(*segment)?;
    }
    Some(current)
}

pub fn encryption_profile_is_encrypted(profile: &str) -> bool {
    let normalized = profile.trim().to_ascii_lowercase().replace(['-', ' '], "_");
    matches!(
        normalized.as_str(),
        "encrypted" | "e2ee" | "mls" | "mls_rfc9420"
    )
}

fn plaintext_visibility_security_state(visibility: &str) -> Option<bool> {
    let normalized = visibility
        .trim()
        .to_ascii_lowercase()
        .replace(['-', ' '], "_");
    match normalized.as_str() {
        "encrypted" | "e2ee" | "private_encrypted" | "mls" | "mls_rfc9420" => Some(true),
        "none" | "plain" | "plaintext" | "public_plaintext" | "server_plaintext" | "visible" => {
            Some(false)
        }
        _ => None,
    }
}

fn plaintext_visibility_value(value: &Value) -> Option<String> {
    value
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| string_field(value, &["default", "mode", "visibility"]))
}

fn decryption_state_security_state(token: &str) -> Option<bool> {
    let normalized = token.trim().to_ascii_lowercase().replace(['-', ' '], "_");
    match normalized.as_str() {
        "opaque" | "encrypted" => Some(true),
        "plaintext" => Some(false),
        _ => None,
    }
}

fn direct_security_state(value: &Value) -> Option<bool> {
    if value.get("encrypted_content").is_some()
        || value
            .get("content")
            .and_then(|content| content.get("encrypted_content"))
            .is_some()
    {
        return Some(true);
    }
    if let Some(encrypted) = bool_field(
        value,
        &[
            "__realm_security_encrypted",
            "encrypted",
            "is_encrypted",
            "e2ee",
            "end_to_end_encrypted",
        ],
    ) {
        return Some(encrypted);
    }
    if let Some(profile) = string_field(value, &["encryption_profile"]) {
        return Some(encryption_profile_is_encrypted(&profile));
    }
    if let Some(state) = string_field(value, &["decryption_state"])
        .and_then(|state| decryption_state_security_state(&state))
    {
        return Some(state);
    }
    value
        .get("plaintext_visibility")
        .and_then(plaintext_visibility_value)
        .and_then(|visibility| plaintext_visibility_security_state(&visibility))
}

pub fn strand_projection_security_state(value: &Value) -> Option<bool> {
    let paths: &[&[&str]] = &[
        &[],
        &["object"],
        &["strand"],
        &["body"],
        &["fields"],
        &["scope"],
        &["scope_circle"],
        &["metadata"],
        &["content"],
        &["tracks", "synthesis"],
    ];
    paths
        .iter()
        .filter_map(|path| path_value(value, path))
        .find_map(direct_security_state)
}

pub fn projection_for_scope_id<'a>(
    projections: &'a BTreeMap<String, Value>,
    scope_id: &str,
) -> Option<&'a Value> {
    let scope_id = scope_id.trim();
    if scope_id.is_empty() {
        return None;
    }
    projections.get(scope_id)
}

fn projection_home_realm_id(body: &Value) -> Option<String> {
    body.get("realm_id")
        .and_then(Value::as_str)
        .or_else(|| {
            body.get("summary")
                .and_then(|summary| summary.get("realm_id"))
                .and_then(Value::as_str)
        })
        .map(str::trim)
        .filter(|realm_id| !realm_id.is_empty())
        .map(ToOwned::to_owned)
}

pub fn security_projection_for_scope_id<'a>(
    projections: &'a BTreeMap<String, Value>,
    scope_id: &str,
) -> Option<&'a Value> {
    let direct = projection_for_scope_id(projections, scope_id)?;
    projection_home_realm_id(direct)
        .and_then(|realm_id| projection_for_scope_id(projections, &realm_id))
        .or(Some(direct))
}

/// Current controller of the Realm authority-root cell, read from the locally
/// projected event log.
///
/// `ak.realm.create` is the registered genesis writer of
/// `ak.component.realm.authority_root.v1` (contract-registry.json), and its
/// registered `value_projection` sets `controller_id` from the Event
/// envelope's `actor_id`; every accepted `ak.realm.owner.transfer` afterwards
/// moves the controller to `payload.patch.controller_id`. This replays those
/// cell inputs in log order; it is not the forbidden `realm_state.owner` /
/// membership fallback — those are projection mirrors of a different fact,
/// and post-P1 realm projections no longer carry them at all.
pub fn realm_authority_root_controller_from_events(events: &[Value]) -> Option<ActorId> {
    realm_authority_root_value_from_events(events).map(|root| root.controller_id)
}

/// Fully replayed current value of the Realm authority-root cell.
///
/// Genesis comes from the accepted `ak.realm.create` envelope `actor_id`; the
/// registered CAS transitions (`ak.realm.owner.transfer` and
/// `ak.realm.authority.reset`) are then applied in log order, mirroring the
/// soland reducer's `apply_realm_authority_transition` effects. `None` when no
/// valid create is projected.
///
/// The `canonical_sha256` of the returned value is exactly the
/// `expected_state_digest` the security-barrier governance payloads must
/// carry, so callers building `ak.realm.owner.transfer` or
/// `ak.realm.authority.reset` MUST source it from here rather than re-deriving
/// fragments.
pub fn realm_authority_root_value_from_events(
    events: &[Value],
) -> Option<arkret_policy::realm_bootstrap::RealmAuthorityRootValue> {
    use arkret_policy::realm_bootstrap::RealmAuthorityRootValue;
    let mut root: Option<RealmAuthorityRootValue> = None;
    for event in events {
        let Some(kind) = event
            .get("kind")
            .or_else(|| event.get("event_kind"))
            .and_then(Value::as_str)
        else {
            continue;
        };
        if kind == EventKind::RealmCreate.as_str() {
            root = (|| {
                let controller_id =
                    serde_json::from_value::<ActorId>(event.get("actor_id")?.clone()).ok()?;
                Some(RealmAuthorityRootValue::genesis(controller_id))
            })();
            continue;
        }
        let Some(current) = root.as_mut() else {
            // Transitions on a Realm with no root cell are rejected server-side
            // (`realm_authority_root_missing`); ignore them here the same way.
            continue;
        };
        match kind {
            event_kind_str::REALM_OWNER_TRANSFER => {
                if let Some(controller) = event
                    .pointer("/payload/patch/controller_id")
                    .cloned()
                    .and_then(|next| serde_json::from_value::<ActorId>(next).ok())
                {
                    let epoch = current.controller_epoch.checked_add(1)?;
                    current.controller_id = controller;
                    current.controller_epoch = epoch;
                }
            }
            event_kind_str::REALM_AUTHORITY_RESET => {
                current.authority_generation = current.authority_generation.checked_add(1)?;
            }
            _ => {}
        }
    }
    root
}

/// [`realm_authority_root_value_from_events`] over the Realm's full
/// projection entry (`realm_tree_projections[realm_id]`).
pub fn realm_authority_root_value_for_realm(
    projections: &BTreeMap<String, Value>,
    realm_id: &str,
) -> Option<arkret_policy::realm_bootstrap::RealmAuthorityRootValue> {
    let events = projections
        .get(realm_id.trim())?
        .get("state")?
        .get("events")?
        .as_array()?;
    realm_authority_root_value_from_events(events)
}

/// [`realm_authority_root_controller_from_events`] over the Realm's full
/// projection entry (`realm_tree_projections[realm_id]`).
pub fn realm_authority_root_controller_for_realm(
    projections: &BTreeMap<String, Value>,
    realm_id: &str,
) -> Option<ActorId> {
    let events = projections
        .get(realm_id.trim())?
        .get("state")?
        .get("events")?
        .as_array()?;
    realm_authority_root_controller_from_events(events)
}

pub fn realm_projection_security_state(body: &Value) -> Option<bool> {
    let summary = body.get("summary").unwrap_or(&Value::Null);
    for container in [
        body,
        summary,
        body.get("object").unwrap_or(&Value::Null),
        body.get("realm").unwrap_or(&Value::Null),
        body.get("metadata").unwrap_or(&Value::Null),
    ] {
        if let Some(state) = direct_security_state(container) {
            return Some(state);
        }
    }

    for event in body
        .get("state")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .chain(
            body.get("state")
                .and_then(|state| state.get("events"))
                .and_then(Value::as_array)
                .into_iter()
                .flatten(),
        )
        .chain(
            body.get("state_after")
                .and_then(|state| state.get("events"))
                .and_then(Value::as_array)
                .into_iter()
                .flatten(),
        )
    {
        let kind = event
            .get("kind")
            .or_else(|| event.get("type"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !kind.contains("realm.create") && !kind.contains("encryption") {
            continue;
        }
        for container in [
            event.get("payload").unwrap_or(&Value::Null),
            event
                .get("payload")
                .and_then(|payload| payload.get("object"))
                .unwrap_or(&Value::Null),
            event.get("content").unwrap_or(&Value::Null),
            event
                .get("content")
                .and_then(|content| content.get("object"))
                .unwrap_or(&Value::Null),
            event.get("object").unwrap_or(&Value::Null),
            event,
        ] {
            if let Some(state) = direct_security_state(container) {
                return Some(state);
            }
        }
    }

    // `state_at_window_start.e2ee_epoch = null` means that this projection
    // does not carry a usable window-start epoch hint. It is not evidence that
    // the Realm's create-locked encryption profile is plaintext. Soland emits
    // this null hint even when the same frame contains an encrypted
    // `ak.realm.create` state event, so only a concrete epoch is affirmative
    // security evidence and null remains unknown.
    if body
        .pointer("/state_at_window_start/e2ee_epoch")
        .is_some_and(|epoch| !epoch.is_null())
    {
        return Some(true);
    }

    None
}

pub fn realm_projection_is_encrypted(body: &Value) -> bool {
    realm_projection_security_state(body).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn realm_authority_root_controller_comes_from_create_envelope_actor() {
        let events = json!([{
            "kind": "ak.realm.create",
            "actor_id": {
                "kind": "account",
                "account_id": {
                    "principal_id": "ak:did_core:webvh:z6mkcreator",
                    "station_id": "ak:did_core:web:station.example"
                }
            },
            "payload": {
                "object": {
                    "schema": "ak.schema.realm_genesis.v1",
                    "purpose": "collaboration"
                }
            }
        }]);
        assert_eq!(
            realm_authority_root_controller_from_events(events.as_array().unwrap()),
            Some(serde_json::from_value(events[0]["actor_id"].clone()).unwrap())
        );
    }

    #[test]
    fn realm_authority_root_replay_follows_owner_transfer_and_reset() {
        let events = json!([
            {
                "kind": "ak.realm.create",
                "actor_id": {
                    "kind": "account",
                    "account_id": {
                        "principal_id": "ak:did_core:webvh:z6mkcreator",
                        "station_id": "ak:did_core:web:station.example"
                    }
                },
                "payload": {
                    "object": {
                        "schema": "ak.schema.realm_genesis.v1",
                        "purpose": "collaboration"
                    }
                }
            },
            {
                "kind": "ak.realm.owner.transfer",
                "actor_id": {
                    "kind": "account",
                    "account_id": {
                        "principal_id": "ak:did_core:webvh:z6mkcreator",
                        "station_id": "ak:did_core:web:station.example"
                    }
                },
                "payload": {
                    "patch": {
                        "controller_id": {
                            "kind": "account",
                            "account_id": {
                                "principal_id": "ak:did_core:web:successor.example",
                                "station_id": "ak:did_core:web:station.example"
                            }
                        }
                    }
                }
            },
            {
                "kind": "ak.realm.authority.reset",
                "actor_id": {
                    "kind": "account",
                    "account_id": {
                        "principal_id": "ak:did_core:web:successor.example",
                        "station_id": "ak:did_core:web:station.example"
                    }
                },
                "payload": {
                    "destructive_confirmation": "ak.realm.authority.reset"
                }
            }
        ]);
        let events = events.as_array().unwrap();
        let root = realm_authority_root_value_from_events(events).unwrap();
        assert_eq!(
            root.controller_id.signing_principal_id().as_str(),
            "ak:did_core:web:successor.example"
        );
        assert_eq!(root.controller_epoch, 1);
        assert_eq!(root.authority_generation, 1);
        // The presentation-grade controller helper follows the same transfer.
        assert_eq!(
            realm_authority_root_controller_from_events(events),
            Some(root.controller_id)
        );
    }

    #[test]
    fn realm_authority_root_replay_accepts_the_current_create_shape() {
        let events = json!([
            {
                "kind": "ak.realm.create",
                "actor_id": {
                    "kind": "account",
                    "account_id": {
                        "principal_id": "ak:did_core:webvh:z6mkcreator",
                        "station_id": "ak:did_core:web:station.example"
                    }
                },
                "payload": { "object": { "schema": "ak.schema.realm_genesis.v1" } }
            },
            {
                "kind": "ak.realm.owner.transfer",
                "payload": {
                    "patch": {
                        "controller_id": {
                            "kind": "account",
                            "account_id": {
                                "principal_id": "ak:did_core:web:successor.example",
                                "station_id": "ak:did_core:web:station.example"
                            }
                        }
                    }
                }
            }
        ]);
        let events = events.as_array().unwrap();
        let root = realm_authority_root_value_from_events(events).unwrap();
        assert_eq!(
            root.controller_id.signing_principal_id().as_str(),
            "ak:did_core:web:successor.example"
        );
        assert_eq!(root.controller_epoch, 1);
        assert_eq!(
            realm_authority_root_controller_from_events(events),
            Some(root.controller_id)
        );
    }

    #[test]
    fn realm_projection_reads_profile_and_plaintext_visibility() {
        let encrypted = json!({
            "summary": {"encryption_profile": "mls_rfc9420"}
        });
        assert_eq!(realm_projection_security_state(&encrypted), Some(true));
        assert!(realm_projection_is_encrypted(&encrypted));

        let e2ee = json!({
            "plaintext_visibility": {"default": "e2ee"}
        });
        assert_eq!(realm_projection_security_state(&e2ee), Some(true));
        assert!(realm_projection_is_encrypted(&e2ee));

        let plaintext = json!({"encryption_profile": "none"});
        assert_eq!(realm_projection_security_state(&plaintext), Some(false));
        assert!(!realm_projection_is_encrypted(&plaintext));

        let synced_epoch = json!({
            "state_at_window_start": {
                "e2ee_epoch": {"epoch": 0, "key_ref": "mock-key:realm"}
            }
        });
        assert_eq!(realm_projection_security_state(&synced_epoch), Some(true));
        assert!(realm_projection_is_encrypted(&synced_epoch));

        let synced_plaintext = json!({
            "state_at_window_start": {"e2ee_epoch": null}
        });
        assert_eq!(
            realm_projection_security_state(&synced_plaintext),
            None,
            "a missing epoch hint is unknown, not an explicit plaintext profile"
        );

        let real_encrypted_sync_shape = json!({
            "state_at_window_start": {
                "actor_profiles": [],
                "realm_metadata": {"title": "Encrypted Realm"},
                "e2ee_epoch": null
            },
            "state": {"events": [{
                "kind": "ak.realm.create",
                "payload": {"object": {"encryption_profile": "mls_rfc9420"}}
            }]}
        });
        assert_eq!(
            realm_projection_security_state(&real_encrypted_sync_shape),
            Some(true),
            "the create-locked profile must win over an absent epoch hint"
        );

        assert_eq!(
            realm_projection_security_state(&json!({
                "schema": "ak.schema.realm.v1",
                "title": "projection still syncing"
            })),
            None,
            "an incomplete Realm projection is unknown, not known-plaintext"
        );
    }

    #[test]
    fn security_projection_follows_space_home_realm() {
        let mut projections = BTreeMap::new();
        projections.insert(
            "ak:realm:AhqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0".to_owned(),
            json!({"summary": {"encryption_profile": "mls_rfc9420"}}),
        );
        projections.insert(
            "ak:space:s1".to_owned(),
            json!({"schema": "ak.schema.space.v1", "realm_id": "ak:realm:AhqX99K03QXK2MTH4KkLKdcUAjZEYYcxENCdxK3f6nN0"}),
        );
        let body = security_projection_for_scope_id(&projections, "ak:space:s1")
            .expect("realm projection for space");
        assert!(realm_projection_is_encrypted(body));
    }
}
