//! Which key-backup envelope a restoring client is allowed to open.
//!
//! The Account Station's active-series pointer narrows the eligible series and
//! the tail is ordered by `(series_seq, created_at)`. None of that needs a
//! host, a store or a transport, so every client picks the same envelope from
//! the same Station response. Chain verification of the selected tail lives
//! next door in [`crate::mls::backup_series`].

use arkret_models_crypto::{
    BackupActiveSeriesState, KeyBackupRecipientMethod, KeyBackupSummary, KeysBackupsList,
    SecretStorageItemKind,
};
use arkret_wire::BackupSeriesId;

/// The Station-published active series for the secret-storage backup class.
/// An absent or malformed pointer never permits guessing from the envelopes.
pub fn active_series_id(active_series: &BackupActiveSeriesState) -> Option<&BackupSeriesId> {
    active_series.secret_storage.series_id()
}

/// Every summary that belongs to the Station's active series.
pub fn summaries_in_active_series(list: &KeysBackupsList) -> Vec<&KeyBackupSummary> {
    let Some(series_id) = active_series_id(&list.active_series) else {
        return Vec::new();
    };
    list.backups
        .iter()
        .filter(|summary| &summary.series_id == series_id)
        .collect()
}

/// The tail of the active series: the highest `series_seq`, breaking ties on
/// `created_at` and then on `backup_id` so every client picks the same row.
pub fn select_active_series_tail(list: &KeysBackupsList) -> Option<&KeyBackupSummary> {
    summaries_in_active_series(list)
        .into_iter()
        .max_by(|left, right| {
            left.series_seq
                .cmp(&right.series_seq)
                .then(left.created_at.cmp(&right.created_at))
                .then(left.backup_id.as_str().cmp(right.backup_id.as_str()))
        })
}

/// The tail restricted to one recipient method. The account secret is stored
/// under two envelopes with the same item kind — a passphrase one and an HPKE
/// `recovery_public_key` one — so a restore path MUST name the variant it can
/// actually open instead of taking whichever row sorts first.
pub fn select_active_series_tail_for_recipient_method(
    list: &KeysBackupsList,
    recipient_method: KeyBackupRecipientMethod,
) -> Option<&KeyBackupSummary> {
    let series_id = active_series_id(&list.active_series)?;
    list.backups
        .iter()
        .filter(|summary| {
            &summary.series_id == series_id
                && summary.encryption.recipient_method == recipient_method
        })
        .max_by(|left, right| {
            left.series_seq
                .cmp(&right.series_seq)
                .then(left.created_at.cmp(&right.created_at))
                .then(left.backup_id.as_str().cmp(right.backup_id.as_str()))
        })
}

/// True when a fetched envelope carries the named secret-storage item.
pub fn carries_item_kind(
    backup: &arkret_models_crypto::KeyBackup,
    item_kind: SecretStorageItemKind,
) -> bool {
    backup
        .contents
        .iter()
        .any(|content| content.item_kind == item_kind)
}

/// True when the account already has the passphrase-free fresh-device recovery
/// envelope, so a client can stop prompting for a recovery passphrase.
pub fn recovery_public_key_backup_present(list: &KeysBackupsList) -> bool {
    list.backups.iter().any(|summary| {
        summary.encryption.recipient_method == KeyBackupRecipientMethod::RecoveryPublicKey
    })
}

/// True when the account has an authoritative "recovery is not configured"
/// answer. An unknown answer never prompts.
pub fn recovery_setup_prompt_required(account_recovery_configured: Option<bool>) -> bool {
    matches!(account_recovery_configured, Some(false))
}

#[cfg(test)]
mod tests {
    use arkret_models_crypto::{BackupActiveSeriesPointer, BackupKind, KeyBackupSummaryEncryption};
    use arkret_wire::{AccountId, BackupId, DidCoreId, Hash};

    use super::*;
    use crate::test_fixtures::{actor_id, at, device_id, realm_id};

    fn series(suffix: &str) -> BackupSeriesId {
        BackupSeriesId::new(format!(
            "ak:backup_series:0196419b-0000-7000-8000-00000000001{suffix}"
        ))
        .unwrap()
    }

    fn summary(
        seq: u64,
        series_id: BackupSeriesId,
        recipient_method: KeyBackupRecipientMethod,
    ) -> KeyBackupSummary {
        KeyBackupSummary {
            backup_id: BackupId::new(format!(
                "ak:backup:0196419b-0000-7000-8000-00000000003{seq}"
            ))
            .unwrap(),
            actor_id: actor_id(),
            device_id: Some(device_id()),
            backup_kind: BackupKind::SecretStorage,
            backup_version: "kb_1".to_owned(),
            created_at: at(u32::try_from(seq).unwrap()),
            updated_at: None,
            expires_at: None,
            ciphertext_digest: Hash::new(format!("sha256:{}", "b".repeat(64))).unwrap(),
            encryption: KeyBackupSummaryEncryption {
                recipient_method,
                recipient_key_ref: None,
            },
            series_id,
            series_seq: seq,
        }
    }

    fn list(pointer: BackupActiveSeriesPointer, backups: Vec<KeyBackupSummary>) -> KeysBackupsList {
        KeysBackupsList {
            backups,
            active_series: BackupActiveSeriesState {
                account_id: AccountId::new(
                    DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
                    DidCoreId::new("ak:did_core:web:station.example").unwrap(),
                ),
                control_realm_id: realm_id(),
                source_commit_ref: None,
                secret_storage: pointer,
            },
            next_cursor: None,
            has_more: false,
        }
    }

    #[test]
    fn an_absent_active_series_pointer_selects_nothing() {
        let backups = vec![summary(
            3,
            series("0"),
            KeyBackupRecipientMethod::SecretStorageKey,
        )];
        assert!(
            select_active_series_tail(&list(BackupActiveSeriesPointer::Absent {}, backups))
                .is_none()
        );
    }

    #[test]
    fn a_backup_outside_the_active_series_is_never_selected() {
        let backups = vec![
            summary(9, series("1"), KeyBackupRecipientMethod::SecretStorageKey),
            summary(2, series("0"), KeyBackupRecipientMethod::SecretStorageKey),
        ];
        let selected = select_active_series_tail(&list(
            BackupActiveSeriesPointer::Active {
                active_series_id: series("0"),
                series_pointer_version: 4,
            },
            backups,
        ))
        .unwrap()
        .clone();
        assert_eq!(selected.series_seq, 2);
        assert_eq!(selected.series_id, series("0"));
    }

    #[test]
    fn the_passphrase_and_recovery_key_envelopes_are_selected_separately() {
        let backups = vec![
            summary(1, series("0"), KeyBackupRecipientMethod::PassphraseKdf),
            summary(2, series("0"), KeyBackupRecipientMethod::RecoveryPublicKey),
        ];
        let list = list(
            BackupActiveSeriesPointer::Active {
                active_series_id: series("0"),
                series_pointer_version: 4,
            },
            backups,
        );
        assert_eq!(
            select_active_series_tail_for_recipient_method(
                &list,
                KeyBackupRecipientMethod::PassphraseKdf
            )
            .unwrap()
            .series_seq,
            1
        );
        assert_eq!(
            select_active_series_tail_for_recipient_method(
                &list,
                KeyBackupRecipientMethod::RecoveryPublicKey
            )
            .unwrap()
            .series_seq,
            2
        );
        assert!(recovery_public_key_backup_present(&list));
    }

    #[test]
    fn a_recovery_prompt_needs_an_authoritative_negative_answer() {
        assert!(recovery_setup_prompt_required(Some(false)));
        assert!(!recovery_setup_prompt_required(Some(true)));
        assert!(!recovery_setup_prompt_required(None));
    }
}
