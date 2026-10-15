//! Provider-opaque v1 checkpoint envelopes. Secret acquisition and live MLS
//! provider restoration remain host responsibilities.

use arkret_models_crypto::MlsGroupStateRecord;
use arkret_wire::EventId;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use chrono::{DateTime, Utc};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

/// Magic-bytes prefix burned into every v1 envelope.
///
/// The literal is at-rest data, not a name: it is the HKDF `info` string and
/// the leading AEAD additional-data bytes of every envelope already written to
/// disk. Renaming it would make every stored checkpoint undecryptable.
pub const MLS_ENVELOPE_MAGIC: &[u8] = b"inkson-mls-snap-v1";

/// AEAD envelope version. `1` = ChaCha20-Poly1305 AEAD with
/// `(magic, salt, epoch, recorded_at)` bound into the AAD.
pub const AEAD_VERSION_CHACHA20_POLY1305: u8 = 1;

/// Typed envelope wrapping an encrypted MLS group state record, persisted for
/// same-endpoint restart recovery. The plaintext fields here are the minimum
/// required for tamper detection and outdated-checkpoint detection; everything
/// else (signing key set, provider storage entries) lives inside `ciphertext`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MlsLocalCheckpointEnvelope {
    /// The Realm id the envelope belongs to. Not encrypted: the boot path
    /// needs to map envelopes to Realms without decrypting them all first.
    pub realm_id: String,
    /// Recorded MLS group id. Surfaced for debug and audit; leaks no material.
    pub group_id: String,
    /// MLS epoch as recorded at checkpoint time. Primary signal for
    /// outdated-checkpoint detection.
    pub epoch: u64,
    /// Immutable epoch at which this device joined the group. Request planning
    /// uses this boundary; the mutable current epoch must never stand in for it.
    pub admission_epoch: u64,
    /// Accepted `ak.mls.genesis` or `ak.mls.commit` Event that materialized
    /// this exact `(group_id, epoch)` state. The reference is public metadata,
    /// but keeping it inside the envelope lets a restoring device recover the
    /// authoring base together with the executable MLS state.
    pub group_state_event_id: Option<EventId>,
    /// Per-envelope salt used during device-secret stretching, hex-encoded so
    /// the JSON form stays human-debuggable.
    pub salt_hex: String,
    /// ChaCha20-Poly1305 AEAD output: ciphertext followed by the 16-byte tag.
    pub ciphertext_hex: String,
    /// 12-byte ChaCha20-Poly1305 nonce, freshly generated per envelope.
    pub mac_hex: String,
    /// Timestamp at which the checkpoint was taken. Used by "newest envelope
    /// wins" tie-breaking, and bound into the AEAD AAD so a tampered envelope
    /// cannot fake a fresh recording time.
    pub recorded_at: DateTime<Utc>,
    /// Wall-clock time at which the device first held *this* MLS epoch. Unlike
    /// [`Self::recorded_at`] (refreshed on every re-checkpoint, including
    /// epoch-preserving reaction sends) this advances only when the epoch
    /// number changes, so it is a faithful epoch-age clock for the
    /// `minimal_metadata_realm` cap. Not bound into the AAD: it is a local
    /// scheduling hint, never a confidentiality boundary.
    pub epoch_started_at: DateTime<Utc>,
    /// Number of MLS application messages observed (sent or successfully
    /// decrypted) on this device within the current epoch. Drives the
    /// self-preservation commit trigger. Resets whenever the epoch advances.
    /// Like [`Self::epoch_started_at`] it is a local scheduling hint.
    pub app_messages_observed: u64,
    /// AEAD scheme tag. New envelopes always serialize with
    /// [`AEAD_VERSION_CHACHA20_POLY1305`].
    pub aead_version: u8,
}

/// Errors produced while encrypting, decrypting or verifying an envelope.
#[derive(Debug, thiserror::Error)]
pub enum EnvelopeError {
    /// Device checkpoint secret did not match the one used at encryption time,
    /// or the envelope was tampered with. The two cases are indistinguishable
    /// by design (an AEAD tag failure could be either).
    #[error("snapshot secret mismatch (or envelope tampered)")]
    SecretMismatch,
    /// The envelope decrypts cleanly but its recorded epoch is strictly less
    /// than the caller-supplied floor. Restoring would silently fork the MLS
    /// group; the caller must obtain a newer envelope first.
    #[error("outdated snapshot: envelope epoch {envelope_epoch} < current epoch {current_epoch}")]
    OutdatedCheckpoint {
        envelope_epoch: u64,
        current_epoch: u64,
    },
    /// Hex decode or structural problem.
    #[error("malformed envelope: {0}")]
    Malformed(String),
    /// The AEAD verified but the inner `MlsGroupStateRecord` no longer parses.
    #[error("inner state record invalid: {0}")]
    InvalidStateRecord(String),
}

/// Encrypt a serialized MLS group state record under a device checkpoint
/// secret. `realm_id` is metadata only (not encrypted); `state_bytes` is the
/// SDK-serialized `MlsGroupStateRecord` JSON. `salt` SHOULD be a 16-byte random
/// value; the helper accepts any length so tests can pin a deterministic salt.
#[allow(clippy::expect_used)]
pub fn encrypt_state(
    realm_id: &str,
    group_id: &str,
    epoch: u64,
    state_bytes: &[u8],
    checkpoint_secret: &str,
    salt: &[u8],
) -> MlsLocalCheckpointEnvelope {
    let recorded_at = Utc::now();
    let key = derive_key(checkpoint_secret, salt);
    let mut nonce_bytes = [0_u8; 12];
    getrandom::fill(&mut nonce_bytes).expect("operating system RNG must be available");
    let nonce = Nonce::from(nonce_bytes);
    let aad = build_aead_aad(salt, epoch, recorded_at);
    let cipher = ChaCha20Poly1305::new((&key).into());
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: state_bytes,
                aad: &aad,
            },
        )
        // ChaCha20-Poly1305 encryption only fails when the plaintext exceeds
        // the 256 GiB AEAD limit, which an MLS group state record cannot reach.
        .expect("chacha20-poly1305 encrypt should not fail for in-memory MLS state");
    MlsLocalCheckpointEnvelope {
        realm_id: realm_id.to_owned(),
        group_id: group_id.to_owned(),
        epoch,
        admission_epoch: epoch,
        group_state_event_id: None,
        salt_hex: hex_encode(salt),
        ciphertext_hex: hex_encode(&ciphertext),
        mac_hex: hex_encode(nonce.as_slice()),
        recorded_at,
        // New-epoch baseline: a freshly minted envelope is assumed to start a
        // new epoch on this device. The reaction path re-checkpoints WITHOUT
        // advancing the epoch and overrides this through
        // [`MlsLocalCheckpointEnvelope::carry_epoch_started_at`].
        epoch_started_at: recorded_at,
        app_messages_observed: 0,
        aead_version: AEAD_VERSION_CHACHA20_POLY1305,
    }
}

/// Decrypt the envelope and return the inner state bytes (the SDK's
/// `MlsGroupStateRecord` JSON).
pub fn decrypt_envelope(
    envelope: &MlsLocalCheckpointEnvelope,
    checkpoint_secret: &str,
) -> Result<Vec<u8>, EnvelopeError> {
    match envelope.aead_version {
        AEAD_VERSION_CHACHA20_POLY1305 => decrypt_envelope_aead_v1(envelope, checkpoint_secret),
        other => Err(EnvelopeError::Malformed(format!(
            "unsupported aead_version {other}"
        ))),
    }
}

#[allow(clippy::expect_used)]
fn decrypt_envelope_aead_v1(
    envelope: &MlsLocalCheckpointEnvelope,
    checkpoint_secret: &str,
) -> Result<Vec<u8>, EnvelopeError> {
    let salt = hex_decode(&envelope.salt_hex)
        .ok_or_else(|| EnvelopeError::Malformed("salt is not hex".to_owned()))?;
    let ciphertext = hex_decode(&envelope.ciphertext_hex)
        .ok_or_else(|| EnvelopeError::Malformed("ciphertext is not hex".to_owned()))?;
    let nonce_bytes = hex_decode(&envelope.mac_hex)
        .ok_or_else(|| EnvelopeError::Malformed("nonce is not hex".to_owned()))?;
    if nonce_bytes.len() != 12 {
        return Err(EnvelopeError::Malformed(format!(
            "nonce length {} (expected 12 for ChaCha20-Poly1305)",
            nonce_bytes.len()
        )));
    }
    let key = derive_key(checkpoint_secret, &salt);
    let aad = build_aead_aad(&salt, envelope.epoch, envelope.recorded_at);
    let cipher = ChaCha20Poly1305::new((&key).into());
    let nonce = Nonce::try_from(nonce_bytes.as_slice()).expect("nonce length was validated");
    cipher
        .decrypt(
            &nonce,
            Payload {
                msg: &ciphertext,
                aad: &aad,
            },
        )
        // An AEAD failure is the typed SecretMismatch signal; "wrong key" and
        // "tampered envelope" are deliberately not distinguished.
        .map_err(|_| EnvelopeError::SecretMismatch)
}

/// Build the AEAD additional-data bytes binding the envelope's plaintext
/// metadata. Any caller-side mutation of one of these fields invalidates the
/// AEAD tag.
fn build_aead_aad(salt: &[u8], epoch: u64, recorded_at: DateTime<Utc>) -> Vec<u8> {
    let mut out = Vec::with_capacity(MLS_ENVELOPE_MAGIC.len() + salt.len() + 8 + 8);
    out.extend_from_slice(MLS_ENVELOPE_MAGIC);
    out.extend_from_slice(salt);
    out.extend_from_slice(&epoch.to_be_bytes());
    out.extend_from_slice(&recorded_at.timestamp().to_be_bytes());
    out
}

/// Decrypt and verify epoch freshness. Returns the inner state bytes when the
/// envelope's epoch is `>= current_epoch_floor`, otherwise
/// [`EnvelopeError::OutdatedCheckpoint`], so a device that already knows of a
/// newer accepted epoch never binds to a stale envelope and forks the group.
pub fn decrypt_with_epoch_check(
    envelope: &MlsLocalCheckpointEnvelope,
    checkpoint_secret: &str,
    current_epoch_floor: u64,
) -> Result<Vec<u8>, EnvelopeError> {
    let bytes = decrypt_envelope(envelope, checkpoint_secret)?;
    if envelope.epoch < current_epoch_floor {
        return Err(EnvelopeError::OutdatedCheckpoint {
            envelope_epoch: envelope.epoch,
            current_epoch: current_epoch_floor,
        });
    }
    Ok(bytes)
}

impl MlsLocalCheckpointEnvelope {
    /// Carry the epoch-start clock forward from a prior checkpoint when this
    /// re-checkpoint did NOT advance the epoch.
    ///
    /// [`encrypt_state`] optimistically stamps `epoch_started_at =
    /// recorded_at`, which is correct for any commit that bumps the epoch. The
    /// reaction send path and the account-secret rotation path re-encrypt the
    /// *same* epoch and must inherit the previous epoch's start time instead of
    /// resetting the epoch-age clock on every reaction.
    #[must_use]
    pub fn carry_epoch_started_at(mut self, previous: &MlsLocalCheckpointEnvelope) -> Self {
        if self.epoch == previous.epoch {
            self.epoch_started_at = previous.epoch_started_at;
        }
        self
    }

    /// Set the per-epoch observed application-message count on a freshly minted
    /// envelope. Callers compute the value as `previous.app_messages_observed +
    /// new_messages` when the epoch is unchanged, or just `new_messages` after
    /// a commit advanced the epoch.
    #[must_use]
    pub fn with_app_messages_observed(mut self, count: u64) -> Self {
        self.app_messages_observed = count;
        self
    }

    /// Round-trip the inner `MlsGroupStateRecord` (after [`decrypt_envelope`])
    /// into the SDK's typed shape.
    pub fn restore_state_record(bytes: &[u8]) -> Result<MlsGroupStateRecord, EnvelopeError> {
        serde_json::from_slice::<MlsGroupStateRecord>(bytes)
            .map_err(|err| EnvelopeError::InvalidStateRecord(err.to_string()))
    }
}

#[allow(clippy::expect_used)]
fn derive_key(checkpoint_secret: &str, salt: &[u8]) -> [u8; 32] {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), checkpoint_secret.as_bytes());
    let mut out = [0_u8; 32];
    hkdf.expand(MLS_ENVELOPE_MAGIC, &mut out)
        .expect("HKDF output length is fixed at 32 bytes");
    out
}

fn hex_encode(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

fn hex_decode(value: &str) -> Option<Vec<u8>> {
    hex::decode(value).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const REALM: &str = "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE";

    fn fixed_salt() -> Vec<u8> {
        b"round-28-mls-snapshot-salt-x".to_vec()
    }

    #[test]
    fn persist_restore_round_trip_recovers_state_bytes() {
        let bytes = b"opaque provider state".to_vec();
        let envelope = encrypt_state(REALM, "aabbccdd", 7, &bytes, "correct horse", &fixed_salt());
        assert_eq!(envelope.realm_id, REALM);
        assert_eq!(envelope.group_id, "aabbccdd");
        assert_eq!(envelope.epoch, 7);
        assert_ne!(envelope.ciphertext_hex, hex_encode(&bytes));
        assert_eq!(
            decrypt_envelope(&envelope, "correct horse").expect("happy-path decrypt"),
            bytes
        );
    }

    #[test]
    fn a_wrong_secret_or_a_rewritten_epoch_fails_the_aead() {
        let envelope = encrypt_state(REALM, "aabbccdd", 7, b"state", "secret", &fixed_salt());
        assert!(matches!(
            decrypt_envelope(&envelope, "other secret"),
            Err(EnvelopeError::SecretMismatch)
        ));
        let mut tampered = envelope.clone();
        tampered.epoch = 9;
        assert!(matches!(
            decrypt_envelope(&tampered, "secret"),
            Err(EnvelopeError::SecretMismatch)
        ));
    }

    #[test]
    fn an_envelope_below_the_epoch_floor_is_refused() {
        let envelope = encrypt_state(REALM, "aabbccdd", 3, b"state", "secret", &fixed_salt());
        assert!(matches!(
            decrypt_with_epoch_check(&envelope, "secret", 4),
            Err(EnvelopeError::OutdatedCheckpoint {
                envelope_epoch: 3,
                current_epoch: 4
            })
        ));
        assert!(decrypt_with_epoch_check(&envelope, "secret", 3).is_ok());
    }

    #[test]
    fn an_epoch_preserving_recheckpoint_keeps_the_epoch_clock() {
        let first = encrypt_state(REALM, "aabbccdd", 5, b"one", "secret", &fixed_salt());
        let second = encrypt_state(REALM, "aabbccdd", 5, b"two", "secret", &fixed_salt())
            .carry_epoch_started_at(&first);
        assert_eq!(second.epoch_started_at, first.epoch_started_at);
        let advanced = encrypt_state(REALM, "aabbccdd", 6, b"three", "secret", &fixed_salt())
            .carry_epoch_started_at(&first);
        assert!(advanced.epoch_started_at >= first.epoch_started_at);
        assert_eq!(advanced.app_messages_observed, 0);
        assert_eq!(
            advanced
                .with_app_messages_observed(12)
                .app_messages_observed,
            12
        );
    }
}
