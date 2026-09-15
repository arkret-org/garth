//! Wire-projection security classification and Realm authority-root reading.
//!
//! A client decides whether a Realm / Strand / Circle projection is encrypted
//! by reading the accepted projection itself, never by trusting a local flag.
//! The same projection carries the Realm authority-root controller. Both are
//! pure reads over the wire shape, shared by every client that renders or
//! gates on a projection.

use std::collections::BTreeMap;

use arkret_wire::ActorId;
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

/// Read an already-installed singleton Realm cell. Projection input has passed
/// the SDK's current-result validation and the host's atomic installation.
fn installed_realm_cell_value<'a>(
    body: &'a Value,
    realm_id: Option<&str>,
    cell_id: &str,
) -> Option<&'a Value> {
    installed_cell_value_where(body, cell_id, |entry| {
        entry
            .pointer("/selector/scope_ref/kind")
            .and_then(Value::as_str)
            == Some("realm")
            && realm_id.is_none_or(|id| {
                entry
                    .pointer("/selector/scope_ref/realm_id")
                    .and_then(Value::as_str)
                    == Some(id)
            })
    })
}

/// The one installed current value for `cell_id` in this projection.
///
/// The Station publishes exactly one `source`/`value` per selector, so a
/// unique `value` entry is the whole answer. A missing, duplicated or
/// non-`value` entry is unknown state, never an invitation to re-derive the
/// cell from Events: the client keeps no MV heads and no raw-latest reduction.
pub fn installed_cell_value<'a>(body: &'a Value, cell_id: &str) -> Option<&'a Value> {
    installed_cell_value_where(body, cell_id, |_| true)
}

/// The one installed current value for `cell_id` under exactly `effective_scope`.
///
/// A Realm projection carries its own scope plus the Circles it owns
/// (`sync/current-results.md` §2), so a cell family that exists once per MLS
/// group appears several times in one body. Matching the selector scope keeps
/// a Circle group from reading the enclosing Realm's value.
pub fn installed_scoped_cell_value<'a>(
    body: &'a Value,
    effective_scope: &arkret_wire::ScopeRef,
    cell_id: &str,
) -> Option<&'a Value> {
    let scope = serde_json::to_value(effective_scope).ok()?;
    installed_cell_value_where(body, cell_id, |entry| {
        entry.pointer("/selector/scope_ref") == Some(&scope)
    })
}

fn installed_cell_value_where<'a>(
    body: &'a Value,
    cell_id: &str,
    accept: impl Fn(&Value) -> bool,
) -> Option<&'a Value> {
    let entries = body.pointer("/current/entries")?.as_array()?;
    let mut matches = entries.iter().filter(|entry| {
        entry.pointer("/selector/cell_id").and_then(Value::as_str) == Some(cell_id) && accept(entry)
    });
    let entry = matches.next()?;
    if matches.next().is_some()
        || entry.pointer("/result/status").and_then(Value::as_str) != Some("value")
    {
        return None;
    }
    entry.pointer("/result/value")
}

/// The Station's current authority-root result; no local Event replay.
pub fn realm_authority_root_value_for_realm(
    projections: &BTreeMap<String, Value>,
    realm_id: &str,
) -> Option<arkret_policy::realm_bootstrap::RealmAuthorityRootValue> {
    let value = installed_realm_cell_value(
        projections.get(realm_id)?,
        Some(realm_id),
        "ak:cell:ak.component.realm.authority_root.v1:null",
    )?;
    serde_json::from_value(value.clone()).ok()
}

pub fn realm_authority_root_controller_for_realm(
    projections: &BTreeMap<String, Value>,
    realm_id: &str,
) -> Option<ActorId> {
    realm_authority_root_value_for_realm(projections, realm_id).map(|root| root.controller_actor_id)
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

    if let Some(genesis) =
        installed_realm_cell_value(body, None, "ak:cell:ak.component.realm.genesis.v1:null")
    {
        if let Some(state) = direct_security_state(genesis) {
            return Some(state);
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
    fn authority_root_reads_current_value_and_never_replays_timeline() {
        let realm = "ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI";
        let controller = json!({"kind":"account","account_id":{
            "principal_id":"ak:did_core:web:successor.example",
            "station_id":"ak:did_core:web:station.example"
        }});
        let mut projections = BTreeMap::from([(
            realm.to_owned(),
            json!({
                "current":{"entries":[{
                    "selector":{"scope_ref":{"kind":"realm","realm_id":realm},
                        "cell_id":"ak:cell:ak.component.realm.authority_root.v1:null"},
                    "result":{"status":"value","value":{
                        "controller_actor_id":controller,"controller_epoch":5,"authority_generation":8
                    }}
                }]},
                "timeline":{"events":[{"kind":"ak.realm.authority.reset"}]}
            }),
        )]);
        let root = realm_authority_root_value_for_realm(&projections, realm).unwrap();
        assert_eq!(root.controller_epoch, 5);
        assert_eq!(root.authority_generation, 8);
        projections.get_mut(realm).unwrap()["current"]["entries"][0]["result"] =
            json!({"status":"unavailable","reason":"temporarily_unavailable"});
        assert!(realm_authority_root_value_for_realm(&projections, realm).is_none());
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
            "current": {"entries": [{
                "selector":{"scope_ref":{"kind":"realm","realm_id":"ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI"},"cell_id":"ak:cell:ak.component.realm.genesis.v1:null"},
                "result":{"status":"value","value":{"encryption_profile":"mls_rfc9420"}}
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
