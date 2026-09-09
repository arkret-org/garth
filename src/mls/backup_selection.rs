//! Pure selection over a `list_key_backups`-shaped payload.
//!
//! Which envelope of a key-backup series a restoring client is allowed to open
//! is decided entirely by `key-management.md` (§7.5, §7.6, §9.1) and
//! `device-lifecycle.md` §12: the active-series pointer narrows the eligible
//! series, and the tail is ordered by `(secret_version, series_seq,
//! created_at)`. None of that needs a host, a store or a transport, so every
//! client picks the same envelope from the same server response.
//!
//! Chain verification of the selected tail lives next door in
//! [`crate::mls::backup_series`].

use std::collections::BTreeMap;

use arkret_models_crypto::{BackupKind, SecretStorageItemKind};
use arkret_wire::HistoryEffectiveScope;
use serde_json::Value;

use crate::mls::backup_series::backup_series_seq;
use crate::mls::device_secret::ACCOUNT_MLS_SECRET_CURRENT_VERSION;

/// Iterate the `{"backups": [...]}` payload returned by `list_key_backups`.
pub fn iter_backup_bodies(list_payload: &Value) -> impl Iterator<Item = &Value> {
    list_payload
        .get("backups")
        .and_then(Value::as_array)
        .map(|bodies| bodies.iter())
        .into_iter()
        .flatten()
}

/// The `created_at` an envelope body claims; the last-resort tiebreak.
pub fn backup_created_at(body: &Value) -> &str {
    body.get("created_at")
        .and_then(Value::as_str)
        .unwrap_or_default()
}

/// The `series_id` an envelope body claims.
pub fn backup_series_id(body: &Value) -> &str {
    body.get("series_id")
        .and_then(Value::as_str)
        .unwrap_or_default()
}

fn backup_kind_is(body: &Value, backup_kind: BackupKind) -> bool {
    body.get("backup_kind").and_then(Value::as_str) == Some(backup_kind.as_str())
}

fn backup_item_kind(body: &Value) -> Option<&str> {
    body.get("contents")
        .and_then(Value::as_array)
        .and_then(|contents| contents.first())
        .and_then(|item| item.get("item_kind"))
        .and_then(Value::as_str)
}

/// The `encryption.recipient_method` of a backup envelope.
fn backup_recipient_method(body: &Value) -> Option<&str> {
    body.pointer("/encryption/recipient_method")
        .and_then(Value::as_str)
}

/// True when `body` is an MLS account-secret backup (ANY recipient method).
/// Matched on the dedicated `mls_account_secret` item type.
pub fn is_mls_account_secret_backup(body: &Value) -> bool {
    backup_item_kind(body) == Some(SecretStorageItemKind::MlsAccountSecret.as_str())
}

/// True when `body` is the **passphrase-recoverable** account-secret backup
/// (`recipient_method=passphrase_kdf`). The account secret has TWO backups —
/// this passphrase one and an HPKE `recovery_public_key` one — sharing the same
/// `item_kind`, so the passphrase restore path MUST only pick this variant
/// (else it would try to passphrase-decrypt an HPKE envelope).
pub fn is_passphrase_account_secret_backup(body: &Value) -> bool {
    is_mls_account_secret_backup(body) && backup_recipient_method(body) == Some("passphrase_kdf")
}

/// True when `body` is the HPKE `recovery_public_key` account-secret backup —
/// the passphrase-free fresh-device recovery path (open with the recovery
/// private key, no passphrase prompt).
pub fn is_recovery_public_key_account_secret_backup(body: &Value) -> bool {
    is_mls_account_secret_backup(body)
        && backup_recipient_method(body) == Some("recovery_public_key")
}

/// True when `body` is the encrypted local-plaintext sidecar backup.
pub fn is_mls_private_plaintext_backup(body: &Value) -> bool {
    backup_item_kind(body) == Some(SecretStorageItemKind::MlsPrivatePlaintext.as_str())
}

/// True when `body` belongs to the `mls_history` backup class.
pub fn is_mls_history_backup(body: &Value) -> bool {
    backup_kind_is(body, BackupKind::MlsHistory)
}

/// The current Account Station pointer selects the eligible backup series.
/// Missing, absent or malformed state never permits guessing from envelopes.
pub fn active_series_id_for_backup_class(
    list_payload: &Value,
    backup_kind: BackupKind,
) -> Option<&str> {
    let pointer = list_payload
        .get("active_series")?
        .get(backup_kind.as_str())?;
    if pointer.get("state")?.as_str()? != "active"
        || pointer.get("series_pointer_version")?.as_u64()? == 0
    {
        return None;
    }
    pointer
        .get("active_series_id")?
        .as_str()
        .filter(|id| !id.is_empty())
}

fn matches_active_series(body: &Value, active_series: Option<&str>) -> bool {
    match active_series {
        Some(series_id) => !series_id.is_empty() && backup_series_id(body) == series_id,
        None => false,
    }
}

fn backup_secret_version(body: &Value) -> u64 {
    body.get("contents")
        .and_then(Value::as_array)
        .and_then(|contents| contents.first())
        .and_then(|item| item.get("secret_version"))
        .and_then(Value::as_u64)
        .unwrap_or(0)
}

/// Version recorded in an `mls_account_secret` backup.
pub fn mls_account_secret_backup_version(body: &Value) -> u32 {
    backup_secret_version(body)
        .try_into()
        .ok()
        .filter(|version| *version > 0)
        .unwrap_or(ACCOUNT_MLS_SECRET_CURRENT_VERSION)
}

/// Pick the latest `mls_private_plaintext` backup, if present. Newer
/// `series_seq` wins, followed by the creation timestamp.
pub fn select_mls_private_plaintext_backup(list_payload: &Value) -> Option<Value> {
    let active_series = active_series_id_for_backup_class(list_payload, BackupKind::SecretStorage);
    iter_backup_bodies(list_payload)
        .filter(|body| is_mls_private_plaintext_backup(body))
        .filter(|body| matches_active_series(body, active_series))
        .max_by(|a, b| {
            (backup_series_seq(a), backup_created_at(a))
                .cmp(&(backup_series_seq(b), backup_created_at(b)))
        })
        .cloned()
}

fn account_secret_order(body: &Value) -> (u64, u64, &str) {
    (
        backup_secret_version(body),
        backup_series_seq(body),
        backup_created_at(body),
    )
}

/// Pick the latest `mls_account_secret` backup opened by a passphrase.
///
/// Ordering is `(secret_version, series_seq, created_at)` — `secret_version`
/// FIRST so a rotation that opens a NEW series (genesis `series_seq=0` but a
/// bumped `secret_version`, per key-management.md §9.1) wins over the old
/// series' tail; then `series_seq` so that **within one series the true tail
/// always wins regardless of `created_at`** (a malicious/replaying server MUST
/// NOT be able to resurrect an old low-seq link by stamping a newer
/// timestamp); `created_at` is only a last-resort tiebreak.
///
/// The current Station active-series result selects the only eligible series.
pub fn select_mls_account_secret_backup(list_payload: &Value) -> Option<Value> {
    let active_series = active_series_id_for_backup_class(list_payload, BackupKind::SecretStorage);
    iter_backup_bodies(list_payload)
        .filter(|body| is_passphrase_account_secret_backup(body))
        .filter(|body| matches_active_series(body, active_series))
        .max_by(|a, b| account_secret_order(a).cmp(&account_secret_order(b)))
        .cloned()
}

/// Select the newest HPKE `recovery_public_key` account-secret backup (the
/// passphrase-free fresh-device recovery path). Newest by
/// `(secret_version, series_seq, created_at)`.
pub fn select_mls_account_secret_recovery_public_key_backup(list_payload: &Value) -> Option<Value> {
    let active_series = active_series_id_for_backup_class(list_payload, BackupKind::SecretStorage);
    iter_backup_bodies(list_payload)
        .filter(|body| is_recovery_public_key_account_secret_backup(body))
        .filter(|body| matches_active_series(body, active_series))
        .max_by(|a, b| account_secret_order(a).cmp(&account_secret_order(b)))
        .cloned()
}

/// Select the preferred account-secret backup for fresh-device recovery.
pub fn select_preferred_mls_account_secret_backup(list_payload: &Value) -> Option<Value> {
    select_mls_account_secret_recovery_public_key_backup(list_payload)
}

/// Collect every `mls_history` backup body in the active series.
pub fn select_mls_history_backups(list_payload: &Value) -> Vec<Value> {
    let active_series = active_series_id_for_backup_class(list_payload, BackupKind::MlsHistory);
    iter_backup_bodies(list_payload)
        .filter(|body| backup_kind_is(body, BackupKind::MlsHistory))
        .filter(|body| matches_active_series(body, active_series))
        .cloned()
        .collect()
}

/// Select the newest immutable object for every effective scope in the active
/// `(actor_id, backup_kind=mls_history)` series. Earlier links remain required
/// for chain verification, but must not reintroduce history intentionally
/// removed by a later object for the same scope.
pub fn latest_mls_history_backups_by_scope(list_payload: &Value) -> Vec<Value> {
    let mut latest = BTreeMap::<String, Value>::new();
    for body in select_mls_history_backups(list_payload) {
        let Some(scope) = body
            .get("contents")
            .and_then(Value::as_array)
            .and_then(|contents| contents.first())
            .and_then(|item| item.get("effective_scope"))
            .and_then(|scope| serde_json::from_value::<HistoryEffectiveScope>(scope.clone()).ok())
        else {
            continue;
        };
        let Ok(scope_key) = serde_json::to_string(&scope) else {
            continue;
        };
        let replace = latest.get(&scope_key).is_none_or(|current| {
            (backup_series_seq(&body), backup_created_at(&body))
                > (backup_series_seq(current), backup_created_at(current))
        });
        if replace {
            latest.insert(scope_key, body);
        }
    }
    latest.into_values().collect()
}

/// Collect every envelope in the active `secret_storage` series.
///
/// A series may interleave account-secret and private-sidecar items. Chain
/// verification must retain those intermediate links even when the selected
/// decrypt target is an account-secret envelope.
pub fn all_mls_account_secret_backups(list_payload: &Value) -> Vec<Value> {
    let active_series = active_series_id_for_backup_class(list_payload, BackupKind::SecretStorage);
    iter_backup_bodies(list_payload)
        .filter(|body| backup_kind_is(body, BackupKind::SecretStorage))
        .filter(|body| matches_active_series(body, active_series))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn newest_history_object_is_selected_independently_per_scope() {
        let realm_a = "ak:realm:ASlHbbnJj2aIvNxwyukjGz90ltQwXHCbjIihxsRDrRR5";
        let realm_b = "ak:realm:Ac1aCK8aQdnkYImvdH3DFjq4jDCP198pXYWCGzGuVyj5";
        let history = |backup_id: &str, realm_id: &str, series_seq: u64| {
            json!({
                "backup_id": backup_id,
                "backup_kind": "mls_history",
                "series_id": "ak:backup_series:01964137-0000-7000-8000-000000000001",
                "series_seq": series_seq,
                "created_at": format!("2026-08-24T00:00:0{series_seq}.000Z"),
                "contents": [{
                    "item_kind": "history_secret_ranges",
                    "effective_scope": {"kind": "realm", "realm_id": realm_id},
                    "ranges": [{"from_epoch": 0, "to_epoch": series_seq}],
                }],
            })
        };
        let payload = json!({
            "active_series": {"mls_history": {
                "state": "active", "series_pointer_version": 1,
                "active_series_id": "ak:backup_series:01964137-0000-7000-8000-000000000001",
            }},
            "backups": [
                history("old-a", realm_a, 0),
                history("scope-b", realm_b, 1),
                history("new-a", realm_a, 2),
            ],
        });

        let selected = latest_mls_history_backups_by_scope(&payload);
        let ids = selected
            .iter()
            .filter_map(|body| body.get("backup_id").and_then(Value::as_str))
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(ids, std::collections::BTreeSet::from(["new-a", "scope-b"]));
    }
}
