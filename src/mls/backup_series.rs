//! Key-backup `supersedes_id` chain construction and verification.
//!
//! A key-backup series is a hash-linked chain: every successor names its
//! predecessor's `backup_id` and pins that predecessor's signature-independent
//! canonical digest. A restoring client MUST walk the chain back to genesis
//! before trusting the tail, otherwise a Station can roll the series back,
//! forge a high `series_seq`, or withhold an intermediate envelope. The walk is
//! pure wire-shape verification, so it belongs to every client rather than to
//! one host.

use std::collections::BTreeMap;

use arkret_models_crypto::KeyBackup;
use arkret_wire::{BackupId, Hash};

use crate::executor::{HostClock, SystemClock};
use crate::{Error, Result};

/// `sha256:<hex>` over the canonical bytes of a backup envelope with its
/// `auth_data.signature` stripped, so the digest stays stable across
/// (re)signing. This is what a successor pins in `supersedes_digest`.
pub fn series_supersedes_digest(previous: &KeyBackup) -> Result<Hash> {
    let bytes = previous
        .signing_payload_bytes()
        .map_err(|error| Error::Protocol(format!("series supersedes digest failed: {error}")))?;
    Hash::new(format!(
        "sha256:{}",
        arkret_canonical::sha256_hex(bytes.as_slice())
    ))
    .map_err(Error::from)
}

/// Generate a fresh protocol `backup_id` for a new envelope in a series.
pub fn fresh_backup_id() -> Result<BackupId> {
    let unix_ms = SystemClock.now().timestamp_millis().max(0) as u64;
    BackupId::new(format!(
        "ak:backup:{}",
        arkret_identifiers::uuid_v7_at(unix_ms)
    ))
    .map_err(Error::from)
}

/// Verify a key-backup series chain from `tail` back to genesis.
///
/// `tail` is the highest-`series_seq` envelope selected for the series and
/// `all` is the full candidate set returned by the Station. The chain is valid
/// only when every `series_seq` in `0..=tail` is present exactly once, each
/// successor's `supersedes_id` names the immediate predecessor's `backup_id`,
/// and each `supersedes_digest` matches that predecessor's canonical digest.
///
/// A gap, a duplicate, a mislinked predecessor or a digest mismatch fails
/// closed, so a rolled-back or forged series can never be restored from.
pub fn verify_series_chain(tail: &KeyBackup, all: &[KeyBackup]) -> Result<()> {
    let series_id = &tail.series_id;
    let mut by_seq: BTreeMap<u64, &KeyBackup> = BTreeMap::new();
    for backup in all {
        if &backup.series_id != series_id {
            continue;
        }
        if by_seq.insert(backup.series_seq, backup).is_some() {
            return Err(broken(format!(
                "duplicate series_seq {} in series {series_id}",
                backup.series_seq
            )));
        }
    }
    for seq in 0..=tail.series_seq {
        let Some(backup) = by_seq.get(&seq) else {
            return Err(broken(format!(
                "missing series_seq {seq} in series {series_id}"
            )));
        };
        backup
            .validate()
            .map_err(|error| broken(format!("series_seq {seq} is invalid: {error}")))?;
        if seq == 0 {
            continue;
        }
        let previous = by_seq
            .get(&(seq - 1))
            .ok_or_else(|| broken(format!("missing predecessor series_seq {}", seq - 1)))?;
        if backup.supersedes_id.as_ref() != Some(&previous.backup_id) {
            return Err(broken(format!(
                "series_seq {seq} supersedes_id does not name its predecessor"
            )));
        }
        if backup.supersedes_digest.as_ref() != Some(&series_supersedes_digest(previous)?) {
            return Err(broken(format!(
                "series_seq {seq} supersedes_digest mismatch"
            )));
        }
    }
    Ok(())
}

fn broken(detail: String) -> Error {
    Error::Protocol(format!("series_chain_broken: {detail}"))
}

#[cfg(test)]
mod tests {
    use arkret_models_crypto::{
        BackupKind, KeyBackupAead, KeyBackupAeadName, KeyBackupAuthData, KeyBackupDomainSeparation,
        KeyBackupEncryption, KeyBackupRecipientMethod, KeyBackupSignatureAlgorithm,
        KeyBackupSourceCommitRef, SecretStorageContentIndex, SecretStorageItemKind,
    };
    use arkret_wire::{BackupSeriesId, Base64UrlString, DidUrl, EventId, RealmCommitId};

    use super::*;
    use crate::test_fixtures::{actor_id, at, device_id};

    fn series_id() -> BackupSeriesId {
        BackupSeriesId::new("ak:backup_series:0196419b-0000-7000-8000-000000000010").unwrap()
    }

    fn backup_id(seq: u64) -> BackupId {
        BackupId::new(format!(
            "ak:backup:0196419b-0000-7000-8000-00000000002{seq}"
        ))
        .unwrap()
    }

    fn backup(seq: u64, previous: Option<&KeyBackup>) -> KeyBackup {
        let mut value = KeyBackup {
            backup_id: backup_id(seq),
            actor_id: actor_id(),
            device_id: Some(device_id()),
            backup_kind: BackupKind::SecretStorage,
            mixed_secret_storage: false,
            backup_version: "kb_1".to_owned(),
            recovery_policy_ref: None,
            created_at: at(0),
            updated_at: None,
            expires_at: None,
            encryption: KeyBackupEncryption {
                recipient_method: KeyBackupRecipientMethod::SecretStorageKey,
                recipient_key_ref: Some("ak:secret_storage_key:default".to_owned()),
                hpke_suite: None,
                kdf: None,
                aead: KeyBackupAead {
                    name: KeyBackupAeadName::Chacha20Poly1305,
                    aead_profile: None,
                    nonce_salt: None,
                    nonce: Some(Base64UrlString::new("AAAAAAAAAAAAAAAA").unwrap()),
                    enc: None,
                    extra: Default::default(),
                },
                key_commitment: None,
                extra: Default::default(),
            },
            domain_separation: KeyBackupDomainSeparation {
                subdomain: "mls_account_secret".to_owned(),
                aead_aad_extensions: Default::default(),
            },
            contents: vec![SecretStorageContentIndex {
                item_kind: SecretStorageItemKind::MlsAccountSecret,
                secret_id: "account-secret".to_owned(),
            }],
            ciphertext: Base64UrlString::new("AQID").unwrap(),
            ciphertext_digest: Hash::new(format!("sha256:{}", "b".repeat(64))).unwrap(),
            plaintext_commitment: None,
            auth_data: KeyBackupAuthData {
                device_id: device_id(),
                verification_method: DidUrl::new("did:web:alice.example#key-1").unwrap(),
                signature_algorithm: KeyBackupSignatureAlgorithm::Ed25519,
                signature: Base64UrlString::new("AA").unwrap(),
                device_authorize_event_id: EventId::from_digest(
                    arkret_canonical::DigestSuite::Sha256,
                    [4; 32],
                ),
            },
            retention: None,
            series_id: series_id(),
            series_seq: seq,
            supersedes_id: None,
            supersedes_digest: None,
            source_commit_ref: Some(KeyBackupSourceCommitRef {
                realm_commit_id: RealmCommitId::from_digest(
                    [u8::try_from(seq).unwrap().wrapping_add(10); 32],
                ),
                device_generation_ref: seq + 1,
            }),
            extra: Default::default(),
        };
        if let Some(previous) = previous {
            value.supersedes_id = Some(previous.backup_id.clone());
            value.supersedes_digest = Some(series_supersedes_digest(previous).unwrap());
        }
        value
    }

    #[test]
    fn a_complete_chain_verifies_back_to_genesis() {
        let genesis = backup(0, None);
        let second = backup(1, Some(&genesis));
        let third = backup(2, Some(&second));
        verify_series_chain(&third, &[genesis, second, third.clone()]).unwrap();
    }

    #[test]
    fn source_commit_provenance_is_independent_of_the_backup_predecessor_chain() {
        let genesis = backup(0, None);
        let second = backup(1, Some(&genesis));
        let source = second.source_commit_ref.as_ref().unwrap();
        assert_eq!(source.device_generation_ref, 2);
        assert_ne!(
            source.realm_commit_id.to_string(),
            second.supersedes_id.as_ref().unwrap().to_string()
        );
        verify_series_chain(&second, &[genesis, second.clone()]).unwrap();
    }

    #[test]
    fn a_withheld_intermediate_envelope_fails_closed() {
        let genesis = backup(0, None);
        let second = backup(1, Some(&genesis));
        let third = backup(2, Some(&second));
        let error = verify_series_chain(&third, &[genesis, third.clone()]).unwrap_err();
        assert!(error.to_string().contains("series_chain_broken"));
    }

    #[test]
    fn a_forged_supersedes_digest_fails_closed() {
        let genesis = backup(0, None);
        let mut second = backup(1, Some(&genesis));
        second.supersedes_digest = Some(Hash::new(format!("sha256:{}", "c".repeat(64))).unwrap());
        let error = verify_series_chain(&second, &[genesis, second.clone()]).unwrap_err();
        assert!(error.to_string().contains("supersedes_digest mismatch"));
    }

    #[test]
    fn a_mislinked_predecessor_fails_closed() {
        let genesis = backup(0, None);
        let mut second = backup(1, Some(&genesis));
        second.supersedes_id = Some(backup_id(9));
        let error = verify_series_chain(&second, &[genesis, second.clone()]).unwrap_err();
        assert!(error.to_string().contains("does not name its predecessor"));
    }

    #[test]
    fn a_duplicate_sequence_number_fails_closed() {
        let genesis = backup(0, None);
        let second = backup(1, Some(&genesis));
        let error =
            verify_series_chain(&second, &[genesis.clone(), genesis, second.clone()]).unwrap_err();
        assert!(error.to_string().contains("duplicate series_seq"));
    }
}
