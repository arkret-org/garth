//! Which MLS Welcomes a device may admit, and which recovery prompts its
//! account state implies.
//!
//! A Welcome batch is only admissible when every message in it belongs to the
//! Realm being bootstrapped (`mls.md`: a Welcome names its group through the
//! governance binding, and the canonical group id is a function of the scope),
//! and an accepted `ak.mls.welcome` Event may only be replayed into the local
//! inbox for the exact `(realm, principal, device)` endpoint it names, while it
//! is still live. Both are wire-shape decisions with no host state behind them,
//! so every client answers them identically.

use arkret_models_collaboration::events_payloads::{MlsWelcomePayload, MlsWelcomeRecipient};
use arkret_wire::{Event, EventKind, RealmId, ScopeRef, event_kind_str};
use chrono::{DateTime, Utc};
use serde_json::Value;

/// True when the account has an authoritative "recovery is not configured"
/// answer. An unknown answer never prompts.
pub fn recovery_setup_prompt_required(account_recovery_configured: Option<bool>) -> bool {
    matches!(account_recovery_configured, Some(false))
}

/// A device record's authorization state: revoked devices are never
/// authorized, otherwise authorization follows the verification state.
pub fn device_authorization_from_record(device: &Value) -> Option<bool> {
    if device_revoked(device) {
        return Some(false);
    }
    Some(
        device
            .get("verification_state")
            .and_then(Value::as_str)
            .is_some_and(|state| state == "verified"),
    )
}

/// True when a device record carries any revocation marker.
pub fn device_revoked(device: &Value) -> bool {
    device.get("status").and_then(Value::as_str) == Some("revoked")
        || device
            .get("revoked_at")
            .and_then(Value::as_str)
            .is_some_and(|value| !value.trim().is_empty())
        || device.get("revoked_at").is_some_and(|value| {
            !value.is_null() && !value.as_str().map(str::trim).unwrap_or_default().is_empty()
        })
}

/// True when a `list_key_backups` payload already carries the HPKE
/// `recovery_public_key` secret-storage backup, the passphrase-free
/// fresh-device recovery path.
pub fn recovery_public_key_secret_storage_backup_present(list_payload: &Value) -> bool {
    list_payload
        .get("backups")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .any(|backup| {
            backup.get("backup_kind").and_then(Value::as_str) == Some("secret_storage")
                && backup
                    .get("encryption")
                    .and_then(|encryption| encryption.get("recipient_method"))
                    .and_then(Value::as_str)
                    == Some("recovery_public_key")
        })
}

/// The canonical MLS group id of a Realm's default scope.
pub fn mls_group_id_for_realm(realm_id: &str) -> Result<String, String> {
    let realm_id = RealmId::new(realm_id.trim().to_owned())
        .map_err(|error| format!("invalid MLS Realm id: {error}"))?;
    ScopeRef::Realm { realm_id }
        .canonical_mls_group_id()
        .map_err(|error| error.to_string())
}

/// True when a device-message value is an `ak.mls.welcome` for this Realm.
///
/// This routing filter uses only the governance binding's authoritative scope.
/// Full payload validation remains required before applying a Welcome.
pub fn mls_welcome_message_matches_realm(message: &Value, realm_id: &str) -> bool {
    if message
        .get("kind")
        .or_else(|| message.get("type"))
        .and_then(Value::as_str)
        != Some(event_kind_str::MLS_WELCOME)
    {
        return false;
    }
    let Some(content) = message.get("content") else {
        return false;
    };
    content
        .get("governance_binding")
        .and_then(|binding| binding.get("effective_scope"))
        .and_then(|scope| serde_json::from_value::<ScopeRef>(scope.clone()).ok())
        .is_some_and(|scope| {
            scope
                .realm_id_opt()
                .is_some_and(|id| id.as_str() == realm_id)
        })
}

/// True when a non-empty device-message batch contains only Welcomes for this
/// Realm — the precondition for acknowledging the whole batch after applying
/// it.
pub fn mls_welcome_batch_is_exclusively_for_realm(value: &Value, realm_id: &str) -> bool {
    value
        .get("messages")
        .and_then(Value::as_array)
        .is_some_and(|messages| {
            !messages.is_empty()
                && messages
                    .iter()
                    .all(|message| mls_welcome_message_matches_realm(message, realm_id))
        })
}

/// Drop every message that is not a Welcome for this Realm.
pub fn retain_mls_welcomes_for_realm(value: &mut Value, realm_id: &str) -> Result<(), String> {
    value
        .get_mut("messages")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| "device messages response omits messages array".to_owned())?
        .retain(|message| mls_welcome_message_matches_realm(message, realm_id));
    Ok(())
}

/// One accepted `ak.mls.welcome` Event reduced to the coordinates a local
/// endpoint needs to decide whether to replay it into its inbox.
#[derive(Clone, Debug)]
pub struct AcceptedWelcomeCandidate {
    pub event_id: String,
    pub realm_id: String,
    pub recipient_principal_id: String,
    pub recipient_device_id: String,
    pub expires_at: DateTime<Utc>,
    pub key_package_id: String,
    pub content: Value,
}

/// Reduce one accepted Event to a Welcome candidate, or `None` when it is not
/// a device-addressed Welcome.
pub fn accepted_welcome_candidate(
    event: &Event,
) -> Result<Option<AcceptedWelcomeCandidate>, String> {
    if event.kind != EventKind::MlsWelcome {
        return Ok(None);
    }
    let content = serde_json::to_value(&event.payload)
        .map_err(|error| format!("encode accepted MLS Welcome payload: {error}"))?;
    let payload = serde_json::from_value::<MlsWelcomePayload>(content.clone())
        .map_err(|error| format!("decode accepted MLS Welcome payload: {error}"))?;
    let Some(recipient_principal_id) = payload.recipient_principal_id.as_ref() else {
        return Ok(None);
    };
    let MlsWelcomeRecipient::Device {
        recipient_device_id,
    } = &payload.recipient
    else {
        return Ok(None);
    };
    let Some(scope_realm_id) = payload.governance_binding.effective_scope().realm_id_opt() else {
        return Ok(None);
    };
    if event.realm_id.as_str() != scope_realm_id.as_str() {
        return Err("accepted MLS Welcome Realm and governance scope differ".to_owned());
    }
    Ok(Some(AcceptedWelcomeCandidate {
        event_id: event.event_id.to_string(),
        realm_id: event.realm_id.to_string(),
        recipient_principal_id: recipient_principal_id.to_string(),
        recipient_device_id: recipient_device_id.to_string(),
        expires_at: payload.expires_at,
        key_package_id: payload.keypackage_ref.to_string(),
        content,
    }))
}

/// Merge every candidate addressed to exactly this live endpoint into a
/// device-messages response body, deduplicating on the canonical Event id.
pub fn merge_accepted_welcome_candidates_for_local_endpoint(
    messages_value: &mut Value,
    candidates: impl IntoIterator<Item = AcceptedWelcomeCandidate>,
    realm_id: &str,
    principal_id: &str,
    device_id: &str,
    now: DateTime<Utc>,
) -> Result<usize, String> {
    let messages = messages_value
        .get_mut("messages")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| "device messages response omits messages array".to_owned())?;
    let mut merged = 0;
    for candidate in candidates {
        if candidate.realm_id != realm_id
            || candidate.recipient_principal_id != principal_id
            || candidate.recipient_device_id != device_id
            || candidate.expires_at <= now
        {
            continue;
        }
        let duplicate = messages.iter().any(|message| {
            message
                .pointer("/unsigned/source_event_id")
                .and_then(Value::as_str)
                == Some(candidate.event_id.as_str())
        });
        if duplicate {
            continue;
        }
        messages.push(serde_json::json!({
            "kind": event_kind_str::MLS_WELCOME,
            "content": candidate.content,
            "unsigned": {
                "source_event_id": candidate.event_id,
                "key_package_id": candidate.key_package_id,
            },
        }));
        merged += 1;
    }
    Ok(merged)
}

/// Reduce accepted Events to Welcome candidates and merge the ones addressed to
/// this live endpoint.
pub fn merge_accepted_welcomes_for_local_endpoint(
    messages_value: &mut Value,
    accepted_events: &[Event],
    realm_id: &str,
    principal_id: &str,
    device_id: &str,
    now: DateTime<Utc>,
) -> Result<usize, String> {
    let candidates = accepted_events
        .iter()
        .map(accepted_welcome_candidate)
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .flatten();
    merge_accepted_welcome_candidates_for_local_endpoint(
        messages_value,
        candidates,
        realm_id,
        principal_id,
        device_id,
        now,
    )
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn durable_welcome(device_message_id: &str, realm_id: &str) -> Value {
        json!({
            "device_message_id": device_message_id,
            "kind": "ak.mls.welcome",
            "sender_account_id": {
                "principal_id": "ak:did_core:webvh:alice.example",
                "station_id": "ak:did_core:webvh:station.example"
            },
            "sender_device_id": "ak:device:0196419b-0000-7000-8000-000000000001",
            "recipient_account_id": {
                "principal_id": "ak:did_core:webvh:bob.example",
                "station_id": "ak:did_core:webvh:station.example"
            },
            "recipient_device_id": "ak:device:0196419b-0000-7000-8000-000000000002",
            "sent_at": "2099-01-01T00:00:00.000Z",
            "expires_at": "2100-01-01T00:00:00.000Z",
            "content": {
                "governance_binding": { "effective_scope": { "kind": "realm", "realm_id": realm_id } },
                "ciphertext": "welcome-ciphertext"
            }
        })
    }

    fn accepted_candidate(
        event_id: &str,
        realm_id: &str,
        principal_id: &str,
        device_id: &str,
        expires_at: &str,
    ) -> AcceptedWelcomeCandidate {
        AcceptedWelcomeCandidate {
            event_id: event_id.to_owned(),
            realm_id: realm_id.to_owned(),
            recipient_principal_id: principal_id.to_owned(),
            recipient_device_id: device_id.to_owned(),
            expires_at: expires_at.parse().unwrap(),
            key_package_id:
                "sha256:2222222222222222222222222222222222222222222222222222222222222222".to_owned(),
            content: json!({"ciphertext": "AQID"}),
        }
    }

    #[test]
    fn retired_group_mirror_cannot_override_or_replace_governance_scope() {
        let realm = "ak:realm:AcQV37Nr-Ulm-nqFSnugsZ9MU-I0QBLO7VHTvtcwYWns";
        let other = "ak:realm:AVtcXI0sfnw9Pex-qynbBUykPtV8niszMj0Ko75SINJ2";
        let mut message = durable_welcome("fixture", other);
        message["content"]["mls_group_id"] = json!(mls_group_id_for_realm(realm).unwrap());
        assert!(!mls_welcome_message_matches_realm(&message, realm));
        message["content"]
            .as_object_mut()
            .unwrap()
            .remove("governance_binding");
        assert!(!mls_welcome_message_matches_realm(&message, realm));
    }

    #[test]
    fn bootstrap_applies_only_current_realm_welcomes_and_preserves_ack_boundary() {
        let realm_id = "ak:realm:AcQV37Nr-Ulm-nqFSnugsZ9MU-I0QBLO7VHTvtcwYWns";
        let current = durable_welcome(
            "ak:device_message:0196419b-0000-7000-8000-000000000026",
            realm_id,
        );
        let other = durable_welcome(
            "ak:device_message:0196419b-0000-7000-8000-000000000027",
            "ak:realm:AVtcXI0sfnw9Pex-qynbBUykPtV8niszMj0Ko75SINJ2",
        );
        let mut messages = json!({
            "messages": [current.clone(), other],
        });

        assert!(!mls_welcome_batch_is_exclusively_for_realm(
            &messages, realm_id
        ));
        retain_mls_welcomes_for_realm(&mut messages, realm_id).unwrap();
        assert_eq!(messages["messages"], json!([current]));
        assert!(mls_welcome_batch_is_exclusively_for_realm(
            &messages, realm_id
        ));
    }

    #[test]
    fn bootstrap_recovers_only_live_exact_endpoint_accepted_welcome() {
        let realm_id = "ak:realm:AYo4JWk3bfuR2mX8uX3xALbEPXprrdP2ZWF-dKYP01Wf";
        let principal_id = "ak:did_core:webvh:bob.example";
        let device_id = "ak:device:0196419b-0000-7000-8000-000000000002";
        let live = accepted_candidate(
            "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
            realm_id,
            principal_id,
            device_id,
            "2100-01-01T00:00:00.000Z",
        );
        let wrong_device = accepted_candidate(
            "ak:event:AcQV37Nr-Ulm-nqFSnugsZ9MU-I0QBLO7VHTvtcwYWns",
            realm_id,
            principal_id,
            "ak:device:0196419b-0000-7000-8000-000000000003",
            "2100-01-01T00:00:00.000Z",
        );
        let expired = accepted_candidate(
            "ak:event:AZiQUXWgexBvj0pdmSuNERtMTAFCjqds5-eP8K9OsgEo",
            realm_id,
            principal_id,
            device_id,
            "2000-01-01T00:00:00.000Z",
        );
        let mut messages = json!({"messages": []});

        assert_eq!(
            merge_accepted_welcome_candidates_for_local_endpoint(
                &mut messages,
                [live.clone(), wrong_device, expired],
                realm_id,
                principal_id,
                device_id,
                "2026-08-30T00:00:00.000Z".parse().unwrap(),
            )
            .unwrap(),
            1
        );
        assert_eq!(messages["messages"].as_array().map(Vec::len), Some(1));
        assert_eq!(
            messages["messages"][0]["unsigned"]["source_event_id"],
            live.event_id
        );
        assert_eq!(
            merge_accepted_welcome_candidates_for_local_endpoint(
                &mut messages,
                [live],
                realm_id,
                principal_id,
                device_id,
                "2026-08-30T00:00:00.000Z".parse().unwrap(),
            )
            .unwrap(),
            0,
            "the canonical Event id is the deduplication key"
        );
    }

    #[test]
    fn revoked_or_unverified_device_records_are_never_authorized() {
        assert_eq!(
            device_authorization_from_record(&json!({"verification_state": "verified"})),
            Some(true)
        );
        assert_eq!(
            device_authorization_from_record(
                &json!({"verification_state": "verified", "status": "revoked"})
            ),
            Some(false)
        );
        assert_eq!(
            device_authorization_from_record(
                &json!({"verification_state": "verified", "revoked_at": "2026-01-01T00:00:00.000Z"})
            ),
            Some(false)
        );
        assert_eq!(
            device_authorization_from_record(&json!({"verification_state": "unverified"})),
            Some(false)
        );
    }

    #[test]
    fn recovery_prompt_needs_an_authoritative_negative_answer() {
        assert!(recovery_setup_prompt_required(Some(false)));
        assert!(!recovery_setup_prompt_required(Some(true)));
        assert!(!recovery_setup_prompt_required(None));
    }

    #[test]
    fn recovery_public_key_backup_is_matched_on_class_and_recipient_method() {
        let payload = json!({"backups": [
            {"backup_kind": "mls_history", "encryption": {"recipient_method": "recovery_public_key"}},
            {"backup_kind": "secret_storage", "encryption": {"recipient_method": "passphrase_kdf"}},
        ]});
        assert!(!recovery_public_key_secret_storage_backup_present(&payload));

        let payload = json!({"backups": [
            {"backup_kind": "secret_storage", "encryption": {"recipient_method": "recovery_public_key"}},
        ]});
        assert!(recovery_public_key_secret_storage_backup_present(&payload));
    }
}
