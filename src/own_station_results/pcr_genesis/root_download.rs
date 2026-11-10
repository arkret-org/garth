//! Current-device, per-original history reads with durable exact retries.

use arkret_models_crypto::{
    BackupKind, ContentHistoryBackupAccess, KeyBackup, KeyBackupSignatureAlgorithm,
    KeyBackupSummary, KeyBackupUnlockAuthority, KeyBackupUnlockProof,
    KeyBackupUnlockSignatureProof, KeysBackupsIssueUnlockChallengeRequestBody,
    KeysBackupsUnlockChallenge, KeysBackupsUnlockRequestBody,
};
use arkret_wire::{ActorId, Base64UrlString, DeviceId, DidUrl, Hash, NonEmptyString};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::OwnStationHumanPcrEvent;
use crate::{Result, SecureKeyStore};

#[cfg(not(target_arch = "wasm32"))]
type RawSigner<'a> = dyn Fn(&[u8]) -> Result<Vec<u8>> + Send + Sync + 'a;
#[cfg(target_arch = "wasm32")]
type RawSigner<'a> = dyn Fn(&[u8]) -> Result<Vec<u8>> + 'a;
#[cfg(not(target_arch = "wasm32"))]
type Clock<'a> = dyn Fn() -> DateTime<Utc> + Send + Sync + 'a;
#[cfg(target_arch = "wasm32")]
type Clock<'a> = dyn Fn() -> DateTime<Utc> + 'a;

/// The host keeps its accepted replacement signer and clock. Recovery secrets
/// are deliberately absent from this network-only capability.
pub struct PcrHistoryBackupReader<'a> {
    pub device: &'a DeviceId,
    pub audience: &'a str,
    pub store: &'a dyn SecureKeyStore,
    pub signing_key: &'a arkret_signatures::PublicKeyMaterial,
    pub sign_raw: &'a RawSigner<'a>,
    pub now: &'a Clock<'a>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Download {
    request: KeysBackupsIssueUnlockChallengeRequestBody,
    challenge: Option<KeysBackupsUnlockChallenge>,
    proof: Option<KeysBackupsUnlockRequestBody>,
    ciphertext: Option<KeyBackup>,
}

impl Download {
    fn new(history: ContentHistoryBackupAccess) -> Result<Self> {
        let mut random = [0; 32];
        getrandom::fill(&mut random).map_err(rejected)?;
        Ok(Self {
            request: KeysBackupsIssueUnlockChallengeRequestBody {
                request_id: Base64UrlString::new(arkret_canonical::base64url_encode(random))
                    .map_err(rejected)?,
                subject_actor_id: None,
                custody_authorization_ref: None,
                content_history: Some(history),
            },
            challenge: None,
            proof: None,
            ciphertext: None,
        })
    }
}

fn rejected(detail: impl std::fmt::Display) -> crate::Error {
    super::protocol(&format!("PCR history download: {detail}"))
}

impl OwnStationHumanPcrEvent<'_> {
    /// Fetch an original or Native-approved replacement root block. The Native
    /// endpoint independently checks current authority and the original mapping.
    /// A saved ciphertext is only local history material; import still verifies
    /// its complete index, original producer and original recovery policy.
    pub async fn download_content_root_backup(
        &self,
        summary: &KeyBackupSummary,
        root_refs: &[Hash],
        reader: &PcrHistoryBackupReader<'_>,
    ) -> Result<KeyBackup> {
        self.validate_history_selection(root_refs)?;
        let account = self.pcr.account()?;
        if summary.actor_id != ActorId::account(account.clone())
            || summary.backup_kind != BackupKind::SecretStorage
            || reader.audience.is_empty()
        {
            return Err(rejected("backup owner, kind or audience differs"));
        }
        let history = ContentHistoryBackupAccess {
            source: self.reference()?,
            root_refs: root_refs.to_vec(),
        };
        history.validate()?;
        let key = format!(
            "content-root-download/v1/{}",
            arkret_canonical::sha256_digest(arkret_canonical::canonical_json_bytes(&(
                account,
                reader.device,
                reader.audience,
                &summary.backup_id,
                &summary.series_id,
                &summary.ciphertext_digest,
                &history,
            ))?),
        );
        for _ in 0..8 {
            self.full()?;
            let previous = reader
                .store
                .read_secret_bytes_durable(&key)
                .await
                .map_err(rejected)?;
            self.full()?;
            let mut state = if let Some(bytes) = &previous {
                serde_json::from_slice::<Download>(bytes.as_slice())?
            } else {
                Download::new(history.clone())?
            };
            state.request.validate()?;
            if state.request.content_history.as_ref() != Some(&history)
                || state.request.subject_actor_id.is_some()
                || state.request.custody_authorization_ref.is_some()
                || state.challenge.is_some() != state.proof.is_some()
            {
                return Err(rejected("saved request differs from exact history intent"));
            }
            if let Some(ciphertext) = &state.ciphertext {
                validate_ciphertext(ciphertext, summary)?;
                self.full()?;
                return Ok(ciphertext.clone());
            }
            if previous.is_none() {
                if !save(reader, &key, None, &state).await? {
                    continue;
                }
                self.full()?;
                continue;
            }
            let bytes = previous.as_ref().map(|bytes| bytes.as_slice());
            if let (Some(challenge), Some(proof)) = (&state.challenge, &state.proof) {
                self.validate_download_proof(summary, reader, &state.request, challenge, proof)?;
                if challenge.issued_at > (reader.now)() {
                    return Err(rejected("saved challenge is in the future"));
                }
                if challenge.expires_at <= (reader.now)() {
                    // A new challenge has a new immutable issuance request;
                    // never reuse the old id with changed signed fields.
                    state = Download::new(history.clone())?;
                    if !save(reader, &key, bytes, &state).await? {
                        continue;
                    }
                    self.full()?;
                    continue;
                }
                let ciphertext = self
                    .pcr
                    .source
                    .http_client()?
                    .unlock_key_backup(&summary.backup_id, proof)
                    .await?;
                self.full()?;
                validate_ciphertext(&ciphertext, summary)?;
                state.ciphertext = Some(ciphertext);
            } else {
                let challenge = self
                    .pcr
                    .source
                    .http_client()?
                    .issue_key_backup_unlock_challenge(&summary.backup_id, &state.request)
                    .await?;
                self.full()?;
                challenge.validate_for_request(&state.request, &summary.backup_id)?;
                let now = (reader.now)();
                self.validate_download_challenge(summary, reader, &challenge)?;
                if challenge.issued_at > now {
                    return Err(rejected("challenge is in the future"));
                }
                if challenge.expires_at <= now {
                    state = Download::new(history.clone())?;
                    if !save(reader, &key, bytes, &state).await? {
                        continue;
                    }
                    self.full()?;
                    continue;
                }
                let mut proof = KeyBackupUnlockProof {
                    schema: KeyBackupUnlockProof::SCHEMA.into(),
                    authority: KeyBackupUnlockAuthority::CurrentDevice {
                        challenge_id: challenge.challenge_id.clone(),
                        nonce: challenge.nonce.clone(),
                    },
                    account_id: account.clone(),
                    requesting_device_id: reader.device.clone(),
                    backup_id: summary.backup_id.clone(),
                    backup_kind: summary.backup_kind,
                    series_id: summary.series_id.clone(),
                    ciphertext_digest: summary.ciphertext_digest.clone(),
                    challenge: challenge.challenge.clone(),
                    service_id: account.station_id.clone(),
                    audience: NonEmptyString::new(reader.audience.to_owned()).map_err(rejected)?,
                    issued_at: challenge.issued_at,
                    expires_at: challenge.expires_at,
                    signature_proof: KeyBackupUnlockSignatureProof {
                        verification_method: self.download_signing_method(reader)?,
                        signature_algorithm: KeyBackupSignatureAlgorithm::Ed25519,
                        signature: Base64UrlString::new(arkret_canonical::base64url_encode(
                            [0; 64],
                        ))
                        .map_err(rejected)?,
                    },
                    subject_actor_id: None,
                    custody_authorization_ref: None,
                    content_history: Some(history.clone()),
                };
                proof.signature_proof.signature =
                    Base64UrlString::new(arkret_canonical::base64url_encode((reader.sign_raw)(
                        &proof.signing_payload_bytes()?,
                    )?))
                    .map_err(rejected)?;
                let proof = KeysBackupsUnlockRequestBody { proof };
                self.validate_download_proof(summary, reader, &state.request, &challenge, &proof)?;
                state.challenge = Some(challenge);
                state.proof = Some(proof);
            }
            self.full()?;
            if !save(reader, &key, bytes, &state).await? {
                continue;
            }
            self.full()?;
        }
        Err(rejected("download checkpoint retry budget exhausted"))
    }

    fn download_signing_method(&self, reader: &PcrHistoryBackupReader<'_>) -> Result<DidUrl> {
        DidUrl::new(format!(
            "{}#{}",
            self.pcr.principal.value()?.resolution_projection.did,
            reader.device
        ))
        .map_err(rejected)
    }

    fn validate_download_challenge(
        &self,
        summary: &KeyBackupSummary,
        reader: &PcrHistoryBackupReader<'_>,
        challenge: &KeysBackupsUnlockChallenge,
    ) -> Result<()> {
        if challenge.account_id != *self.pcr.account()?
            || challenge.requesting_device_id != *reader.device
            || challenge.backup_id != summary.backup_id
            || challenge.series_id != summary.series_id
            || challenge.ciphertext_digest != summary.ciphertext_digest
            || challenge.audience.as_str() != reader.audience
        {
            return Err(rejected(
                "challenge differs from current device or immutable object",
            ));
        }
        Ok(())
    }

    fn validate_download_proof(
        &self,
        summary: &KeyBackupSummary,
        reader: &PcrHistoryBackupReader<'_>,
        request: &KeysBackupsIssueUnlockChallengeRequestBody,
        challenge: &KeysBackupsUnlockChallenge,
        body: &KeysBackupsUnlockRequestBody,
    ) -> Result<()> {
        challenge.validate_for_request(request, &summary.backup_id)?;
        self.validate_download_challenge(summary, reader, challenge)?;
        let proof = &body.proof;
        proof.validate()?;
        if proof.authority
            != (KeyBackupUnlockAuthority::CurrentDevice {
                challenge_id: challenge.challenge_id.clone(),
                nonce: challenge.nonce.clone(),
            })
            || proof.account_id != challenge.account_id
            || proof.requesting_device_id != *reader.device
            || proof.backup_id != summary.backup_id
            || proof.backup_kind != summary.backup_kind
            || proof.series_id != summary.series_id
            || proof.ciphertext_digest != summary.ciphertext_digest
            || proof.challenge != challenge.challenge
            || proof.service_id != challenge.service_id
            || proof.audience != challenge.audience
            || proof.issued_at != challenge.issued_at
            || proof.expires_at != challenge.expires_at
            || proof.content_history != request.content_history
            || proof.subject_actor_id.is_some()
            || proof.custody_authorization_ref.is_some()
            || proof.signature_proof.verification_method != self.download_signing_method(reader)?
            || proof.signature_proof.signature_algorithm != KeyBackupSignatureAlgorithm::Ed25519
        {
            return Err(rejected("saved proof differs from frozen challenge"));
        }
        arkret_signatures::proof::verify_ed25519_raw_transcript_signature(
            &proof.signing_payload_bytes()?,
            proof.signature_proof.signature.as_str(),
            reader.signing_key,
        )
        .map_err(rejected)
    }
}

async fn save(
    reader: &PcrHistoryBackupReader<'_>,
    key: &str,
    expected: Option<&[u8]>,
    state: &Download,
) -> Result<bool> {
    reader
        .store
        .compare_exchange_secret_bytes_durable(key, expected, &serde_json::to_vec(state)?)
        .await
        .map_err(rejected)
}

fn validate_ciphertext(backup: &KeyBackup, summary: &KeyBackupSummary) -> Result<()> {
    backup.validate()?;
    backup.validate_ciphertext_digest()?;
    if backup.backup_id != summary.backup_id
        || backup.actor_id != summary.actor_id
        || backup.backup_kind != summary.backup_kind
        || backup.series_id != summary.series_id
        || backup.ciphertext_digest != summary.ciphertext_digest
        || backup.custodian_actor_id.is_some()
        || backup.custody_authorization_ref.is_some()
    {
        return Err(rejected(
            "downloaded immutable object differs from its selected summary",
        ));
    }
    Ok(())
}
