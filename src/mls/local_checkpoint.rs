//! Device-local MLS group-state persistence.
//!
//! A client needs MLS group state to survive process restarts: without
//! persistence the next message must refetch a Welcome and rejoin from
//! scratch, which drops the device's leaf and churns the epoch — not
//! viable for production, since MLS commits are causally tied to the
//! Seal lattice.
//!
//! This module owns the at-rest envelope only:
//!
//! 1. **Serialize on commit.** The SDK MLS group exposes `export_state_record()` /
//!    `restore_from_state_record()` so the provider storage round-trips through a typed
//!    [`MlsGroupStateRecord`]. [`MlsLocalCheckpointEnvelope`] wraps that record in a device-scoped
//!    confidentiality layer so a stolen local state blob does not leak the provider keys.
//!
//! 2. **Persist locally.** The active group checkpoint is endpoint-bound state. Human portable
//!    recovery must use scope-bound `history_secret_ranges` material and never exports this
//!    checkpoint through `key_backup`.
//!
//! 3. **Restore on boot.** [`decrypt_with_epoch_check`] decrypts the envelope with this device's
//!    MLS checkpoint secret and rejects a stale epoch. Two failure modes are pinned in tests:
//!    [`EnvelopeError::SecretMismatch`] (wrong device secret or tampered envelope) and
//!    [`EnvelopeError::OutdatedCheckpoint`] (the envelope's recorded epoch is older than the current
//!    Seal view — a paired-in device must NOT bind to a stale epoch since that would silently fork
//!    the group). Reconstructing the live group from the decrypted record needs the SDK MLS
//!    engine, so that last step stays with the host that links it.
//!
//! ### Crypto choice
//!
//! The envelope uses ChaCha20-Poly1305 AEAD, which builds cleanly on wasm32. The layout:
//!
//! * **Key derivation:** HKDF-SHA256 with the per-envelope salt and the device checkpoint secret as
//!   input keying material. The resulting 32-byte key feeds the ChaCha20-Poly1305 AEAD directly.
//! * **Symmetric layer:** ChaCha20-Poly1305 AEAD with a fresh 12-byte random nonce per envelope.
//!   The nonce is stored alongside the ciphertext so decryption is self-contained.
//! * **Tamper detection:** the AEAD's built-in Poly1305 tag covers the ciphertext. We additionally
//!   bind the envelope's `(salt, epoch, recorded_at, magic)` into the AEAD's `additional_data` so a
//!   tampered envelope (e.g. an attacker swapping the recorded epoch to bypass the freshness check)
//!   trips the AEAD verification instead of decrypting cleanly under a forged epoch.
//! * **Replay defence:** `recorded_at` is part of the AEAD AAD, so an envelope cannot be
//!   replayed with a forged timestamp to make it look fresh. The freshness check
//!   ([`decrypt_with_epoch_check`]) still relies on the epoch ordering provided by the Seal view,
//!   but the AAD binding guarantees the timestamp the caller sees has not been swapped out.

use arkret_models_crypto::MlsGroupStateRecord;
use arkret_wire::EventId;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use chrono::{DateTime, Utc};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::executor::{HostClock, SystemClock};
use crate::queued_record::QueuedMlsLocalCheckpoint;

/// Magic-bytes prefix burned into every v1 envelope.
///
/// The literal is at-rest data, not a name: it is the HKDF `info` string and
/// the leading AEAD additional-data bytes of every envelope already written to
/// disk. Renaming it would make every stored checkpoint undecryptable, so it keeps
/// its original spelling through both the move out of the host crate and the
/// rename off the word snapshot.
pub const MLS_ENVELOPE_MAGIC: &[u8] = b"inkson-mls-snap-v1";

/// AEAD envelope version. `1` = ChaCha20-Poly1305 AEAD with
/// `(salt, epoch, recorded_at, magic)` bound into the AAD.
pub const AEAD_VERSION_CHACHA20_POLY1305: u8 = 1;

/// Typed envelope wrapping an encrypted MLS group state record. Persisted by
/// the host for same-endpoint restart recovery. The fields here are
/// the minimum required for tamper detection + outdated-checkpoint
/// detection; everything else (signing key set / openmls provider
/// storage entries) lives inside the key-backup `ciphertext`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MlsLocalCheckpointEnvelope {
    /// The realm id the envelope belongs to. Not encrypted —
    /// the boot path needs to know which envelope maps to which
    /// Realm without decrypting them all first.
    pub realm_id: String,
    /// Recorded MLS group id (hex-encoded by the SDK). Surfaced for
    /// debug + audit; does not leak material.
    pub group_id: String,
    /// MLS epoch as recorded at checkpoint time. Primary signal for
    /// outdated-checkpoint detection — a peer that paired in a fresher
    /// device sees the larger epoch on the server's seal view.
    pub epoch: u64,
    /// Immutable epoch at which this device joined the group. Request planning
    /// uses this boundary; the mutable current epoch must never stand in for it.
    pub admission_epoch: u64,
    /// Accepted `ak.mls.genesis` or `ak.mls.commit` Event that materialized
    /// this exact `(group_id, epoch)` state. The reference is public metadata,
    /// but keeping it inside the encrypted backup envelope lets a fresh device
    /// restore the authoring frontier together with the executable MLS state.
    pub group_state_event_id: Option<EventId>,
    /// Per-envelope salt used during device-secret stretching.
    /// Hex-encoded so the JSON form is human-debuggable.
    pub salt_hex: String,
    /// ChaCha20-Poly1305 AEAD output, which is the encrypted plaintext
    /// followed by the 16-byte Poly1305 tag.
    pub ciphertext_hex: String,
    /// 12-byte ChaCha20-Poly1305 nonce. The nonce is freshly generated
    /// per envelope so replay is prevented at the AEAD layer.
    pub mac_hex: String,
    /// RFC 3339 timestamp at which the snapshot was taken. Used by
    /// "newest envelope wins" tie-breaking on multi-device restore.
    /// For [`AEAD_VERSION_CHACHA20_POLY1305`] envelopes the timestamp
    /// is also bound into the AEAD AAD so a tampered envelope cannot
    /// fake a fresh recording time.
    pub recorded_at: DateTime<Utc>,
    /// SEC-08 (`encryption-and-audit.md` §2.9) — wall-clock time at which
    /// the device first held *this* MLS epoch. Unlike [`Self::recorded_at`]
    /// (refreshed on every re-snapshot, including epoch-preserving reaction
    /// sends), this advances ONLY when the epoch number changes, so it is a
    /// faithful epoch-age clock for the `minimal_metadata_realm` 1h cap.
    /// Not bound into the AEAD AAD: it is a local scheduling hint, never a
    /// confidentiality boundary.
    pub epoch_started_at: DateTime<Utc>,
    /// Per `encryption-and-audit.md` §5.6 — number of MLS
    /// application messages observed (sent OR successfully decrypted) on
    /// this device within the CURRENT epoch. Drives the spec's
    /// self-preservation commit SHOULD trigger ("epoch has observed at least
    /// 1000 application messages"). Resets to the in-flight message count whenever
    /// the epoch advances; carried forward (and bumped) by epoch-preserving
    /// re-snapshots. Like [`Self::epoch_started_at`] it is a local
    /// scheduling hint, not a confidentiality boundary, so it is not bound
    /// into the AEAD AAD.
    pub app_messages_observed: u64,
    /// AEAD scheme tag. New envelopes always serialize with
    /// [`AEAD_VERSION_CHACHA20_POLY1305`].
    pub aead_version: u8,
}

impl MlsLocalCheckpointEnvelope {
    pub fn into_queued(self) -> QueuedMlsLocalCheckpoint {
        QueuedMlsLocalCheckpoint {
            realm_id: self.realm_id,
            group_id: self.group_id,
            epoch: self.epoch,
            admission_epoch: self.admission_epoch,
            group_state_event_id: self.group_state_event_id,
            salt_hex: self.salt_hex,
            ciphertext_hex: self.ciphertext_hex,
            mac_hex: self.mac_hex,
            recorded_at: self.recorded_at,
            epoch_started_at: self.epoch_started_at,
            app_messages_observed: self.app_messages_observed,
            aead_version: self.aead_version,
        }
    }
}

impl From<QueuedMlsLocalCheckpoint> for MlsLocalCheckpointEnvelope {
    fn from(snapshot: QueuedMlsLocalCheckpoint) -> Self {
        Self {
            realm_id: snapshot.realm_id,
            group_id: snapshot.group_id,
            epoch: snapshot.epoch,
            admission_epoch: snapshot.admission_epoch,
            group_state_event_id: snapshot.group_state_event_id,
            salt_hex: snapshot.salt_hex,
            ciphertext_hex: snapshot.ciphertext_hex,
            mac_hex: snapshot.mac_hex,
            recorded_at: snapshot.recorded_at,
            epoch_started_at: snapshot.epoch_started_at,
            app_messages_observed: snapshot.app_messages_observed,
            aead_version: snapshot.aead_version,
        }
    }
}

/// Errors produced while encrypting / decrypting / verifying an MLS
/// snapshot envelope. Each variant maps onto a UI-visible error
/// message + a typed test assertion.
#[derive(Debug, thiserror::Error)]
pub enum EnvelopeError {
    /// Device snapshot secret did not match the one used at encryption
    /// time, OR the envelope was tampered with. The two cases are
    /// indistinguishable by design (a MAC failure could be either).
    #[error("snapshot secret mismatch (or envelope tampered)")]
    SecretMismatch,
    /// The envelope is well-formed and decrypts cleanly but its
    /// recorded epoch is strictly less than the caller-supplied
    /// "current" epoch (typically taken from the latest Seal view).
    /// Restoring would silently fork the MLS group; the caller must
    /// fetch a newer envelope before restoring.
    #[error("outdated snapshot: envelope epoch {envelope_epoch} < current epoch {current_epoch}")]
    OutdatedCheckpoint {
        envelope_epoch: u64,
        current_epoch: u64,
    },
    /// Hex decode / structural problem.
    #[error("malformed envelope: {0}")]
    Malformed(String),
    /// Round-trip JSON parse on the inner `MlsGroupStateRecord`
    /// failed. Distinct from [`Self::SecretMismatch`] because
    /// the MAC verified — the bytes match, but the inner shape
    /// changed. This usually means the SDK bumped its on-disk format
    /// in an incompatible way; the user must take a fresh snapshot.
    #[error("inner state record invalid: {0}")]
    InvalidStateRecord(String),
    /// Crypto error from the SDK's `restore_from_state_record` call.
    /// Raised by the host that links the SDK MLS engine, not by this
    /// module — the envelope layer stops at the decrypted state record.
    #[error("SDK restore failed: {0}")]
    SdkRestore(String),
    /// F-WASM-MLS-1: the byte-level envelope decrypted cleanly but
    /// the live MLS group can't be reconstructed on this target —
    /// today, wasm32. The caller can still decrypt the envelope and
    /// parse the inner `MlsGroupStateRecord` to render the metadata
    /// (epoch / device_id / signer_public_key), but encrypt /
    /// decrypt of new messages requires the native SDK provider.
    #[error(
        "wasm32 MLS group restore is not supported — render the decrypted state record metadata instead"
    )]
    WasmMlsRestoreUnsupported,
}

/// Encrypt a serialised MLS group state record under a device checkpoint secret.
/// `realm_id` is metadata only (not encrypted); `state_bytes` is the
/// SDK-serialised `MlsGroupStateRecord` JSON. `salt` SHOULD be a
/// 16-byte random value but the helper accepts any length so tests
/// can pin a deterministic salt.
///
/// Phase A.6 #2: produces a [`AEAD_VERSION_CHACHA20_POLY1305`]
/// envelope. The AEAD AAD binds the envelope's metadata
/// (`MLS_ENVELOPE_MAGIC || salt || epoch_be || recorded_at_unix_be`),
/// so a tampered envelope (e.g. an attacker swapping the recorded
/// epoch / timestamp) fails the AEAD verification instead of
/// decrypting cleanly.
#[allow(clippy::expect_used)]
pub fn encrypt_state(
    realm_id: &str,
    group_id: &str,
    epoch: u64,
    state_bytes: &[u8],
    checkpoint_secret: &str,
    salt: &[u8],
) -> MlsLocalCheckpointEnvelope {
    let recorded_at = SystemClock.now();
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
        // ChaCha20-Poly1305 encryption only fails when the plaintext
        // exceeds the 256 GiB AEAD limit, which is impossible for an
        // MLS group state record. Treat as unreachable.
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
        // new epoch on this device, so the epoch clock starts now. The reaction
        // path (which re-snapshots WITHOUT advancing the epoch) overrides this
        // via [`MlsLocalCheckpointEnvelope::carry_epoch_started_at`] so the §2.9 1h cap
        // measures true epoch age, not last-write time.
        epoch_started_at: recorded_at,
        app_messages_observed: 0,
        aead_version: AEAD_VERSION_CHACHA20_POLY1305,
    }
}

/// Decrypt the envelope and return the inner state bytes (the SDK's
/// `MlsGroupStateRecord` JSON).
///
/// For [`AEAD_VERSION_CHACHA20_POLY1305`] envelopes the AEAD's
/// Poly1305 tag detects both device-secret mismatch and tamper.
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
        // ChaCha20-Poly1305 decrypt failure is the typed SecretMismatch
        // signal; we deliberately do not distinguish "wrong key" from
        // "tampered envelope".
        .map_err(|_| EnvelopeError::SecretMismatch)
}

/// Phase A.6 #2: build the AEAD additional-data bytes binding the
/// envelope's plaintext metadata (magic, salt, epoch, timestamp).
/// Any caller-side mutation of one of these fields invalidates the
/// AEAD tag.
fn build_aead_aad(salt: &[u8], epoch: u64, recorded_at: DateTime<Utc>) -> Vec<u8> {
    let mut out = Vec::with_capacity(MLS_ENVELOPE_MAGIC.len() + salt.len() + 8 + 8);
    out.extend_from_slice(MLS_ENVELOPE_MAGIC);
    out.extend_from_slice(salt);
    out.extend_from_slice(&epoch.to_be_bytes());
    out.extend_from_slice(&recorded_at.timestamp().to_be_bytes());
    out
}

/// Decrypt + verify epoch freshness. Returns the inner state bytes
/// when the envelope's epoch is `>= current_epoch_floor`, otherwise
/// [`EnvelopeError::OutdatedCheckpoint`]. Used by the multi-device
/// restore path so a freshly-paired device doesn't bind to a stale
/// envelope and silently fork the group.
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
    /// SEC-08 — carry the epoch-start clock forward from a prior snapshot when
    /// this re-snapshot did NOT advance the epoch.
    ///
    /// [`encrypt_state`] optimistically stamps `epoch_started_at = recorded_at`
    /// (correct for any commit that bumps the epoch). The reaction send path and
    /// the account-secret rotation path re-encrypt the *same* epoch, so they
    /// must inherit the previous epoch's start time instead of resetting the 1h
    /// `minimal_metadata_realm` clock on every reaction. When the epoch genuinely
    /// changed, the freshly stamped `recorded_at` baseline is kept.
    #[must_use]
    pub fn carry_epoch_started_at(mut self, previous: &MlsLocalCheckpointEnvelope) -> Self {
        if self.epoch == previous.epoch {
            self.epoch_started_at = previous.epoch_started_at;
        }
        self
    }

    /// `encryption-and-audit.md` §5.6 — set the per-epoch observed application-message
    /// count on a freshly minted envelope. Callers compute the value as
    /// `previous.app_messages_observed + new_messages` when the epoch is
    /// unchanged, or just `new_messages` after a commit advanced the epoch.
    #[must_use]
    pub fn with_app_messages_observed(mut self, count: u64) -> Self {
        self.app_messages_observed = count;
        self
    }

    /// Round-trip the inner `MlsGroupStateRecord` (after
    /// `decrypt_envelope`) into the SDK's typed shape.
    pub fn restore_state_record(bytes: &[u8]) -> Result<MlsGroupStateRecord, EnvelopeError> {
        serde_json::from_slice::<MlsGroupStateRecord>(bytes)
            .map_err(|err| EnvelopeError::InvalidStateRecord(err.to_string()))
    }
}

// ───────────────────── Crypto primitives ────────────────────────

#[allow(clippy::expect_used)]
fn derive_key(checkpoint_secret: &str, salt: &[u8]) -> [u8; 32] {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), checkpoint_secret.as_bytes());
    let mut out = [0u8; 32];
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
    use serde_json::json;

    use super::*;

    fn fixed_salt() -> Vec<u8> {
        // Deterministic salt for round-trip tests; production callers
        // pass `getrandom::fill`-derived bytes.
        b"round-28-mls-snapshot-salt-x".to_vec()
    }

    fn fake_state_record_bytes(group_id: &str, epoch: u64) -> Vec<u8> {
        // We don't depend on the SDK shape here — the encrypt/decrypt
        // path is byte-transparent. The test exercises the envelope
        // boundary; the SDK round-trip is exercised separately on
        // native by the host that links the SDK MLS engine.
        let body = json!({
            "group_id": group_id,
            "principal_id": "ak:did_core:web:alice.example",
            "device_id": "dev_alice_1",
            "epoch": epoch,
            "serialized_state": [1, 2, 3, 4, 5, 6, 7, 8],
            "updated_at": "2026-05-09T00:00:00.000Z",
        });
        serde_json::to_vec(&body).unwrap()
    }

    #[test]
    fn persist_restore_round_trip_recovers_group_state() {
        let bytes = fake_state_record_bytes("aabbccdd", 7);
        let envelope = encrypt_state(
            "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
            "aabbccdd",
            7,
            &bytes,
            "correct horse battery staple",
            &fixed_salt(),
        );
        assert_eq!(
            envelope.realm_id,
            "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE"
        );
        assert_eq!(envelope.group_id, "aabbccdd");
        assert_eq!(envelope.epoch, 7);
        // Ciphertext is not the plaintext — encryption did something.
        assert_ne!(envelope.ciphertext_hex, hex_encode(&bytes));

        let plaintext = decrypt_envelope(&envelope, "correct horse battery staple")
            .expect("happy-path decrypt");
        assert_eq!(plaintext, bytes);
    }

    #[test]
    fn checkpoint_secret_mismatch_is_rejected_distinct_from_other_errors() {
        let bytes = fake_state_record_bytes("dead", 1);
        let envelope = encrypt_state(
            "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
            "dead",
            1,
            &bytes,
            "secret one",
            &fixed_salt(),
        );
        let result = decrypt_envelope(&envelope, "secret two");
        assert!(matches!(result, Err(EnvelopeError::SecretMismatch)));

        // Tampered ciphertext also surfaces as SecretMismatch
        // (AEAD failure — the two cases are indistinguishable by
        // design and both block restore).
        let mut tampered = envelope.clone();
        let replacement = if tampered.ciphertext_hex.starts_with("ff") {
            "00"
        } else {
            "ff"
        };
        tampered.ciphertext_hex.replace_range(0..2, replacement);
        let result = decrypt_envelope(&tampered, "secret one");
        assert!(matches!(result, Err(EnvelopeError::SecretMismatch)));
    }

    #[test]
    fn outdated_snapshot_is_rejected_via_epoch_check() {
        let bytes = fake_state_record_bytes("beef", 3);
        let envelope = encrypt_state(
            "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
            "beef",
            3,
            &bytes,
            "p1",
            &fixed_salt(),
        );

        // current_epoch_floor == 3 → still acceptable (>=).
        let ok = decrypt_with_epoch_check(&envelope, "p1", 3);
        assert!(ok.is_ok(), "epoch == floor should pass: {:?}", ok.err());

        // current_epoch_floor == 5 → envelope is stale by 2 epochs.
        let result = decrypt_with_epoch_check(&envelope, "p1", 5);
        match result {
            Err(EnvelopeError::OutdatedCheckpoint {
                envelope_epoch,
                current_epoch,
            }) => {
                assert_eq!(envelope_epoch, 3);
                assert_eq!(current_epoch, 5);
            }
            other => panic!("expected OutdatedCheckpoint, got {other:?}"),
        }

        // Secret mismatch beats outdated check (we don't leak the
        // envelope epoch to a caller without the device secret).
        let result = decrypt_with_epoch_check(&envelope, "wrong", 5);
        assert!(matches!(result, Err(EnvelopeError::SecretMismatch)));
    }

    #[test]
    fn malformed_hex_surfaces_typed_error() {
        let mut envelope = encrypt_state(
            "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
            "feed",
            1,
            b"abc",
            "p",
            &fixed_salt(),
        );
        envelope.ciphertext_hex = "zzzz".to_owned(); // not hex
        let result = decrypt_envelope(&envelope, "p");
        assert!(matches!(result, Err(EnvelopeError::Malformed(_))));
    }

    #[test]
    fn epoch_started_at_defaults_to_recorded_at_on_fresh_envelope() {
        // SEC-08 — a freshly minted envelope assumes a new epoch baseline:
        // the epoch clock starts at recording time.
        let envelope = encrypt_state("s", "g", 5, b"x", "p", &fixed_salt());
        assert_eq!(envelope.epoch_started_at, envelope.recorded_at);
    }

    #[test]
    fn carry_epoch_started_at_preserves_clock_only_when_epoch_unchanged() {
        // SEC-08 — re-snapshotting the SAME epoch (reaction / rotation) must
        // inherit the prior epoch-start time so the 1h cap measures true epoch
        // age, not last-write time.
        let prev = encrypt_state("s", "g", 7, b"a", "p", &fixed_salt());
        let same_epoch = encrypt_state("s", "g", 7, b"b", "p", &fixed_salt());
        assert_ne!(same_epoch.epoch_started_at, prev.epoch_started_at);
        let carried = same_epoch.carry_epoch_started_at(&prev);
        assert_eq!(carried.epoch_started_at, prev.epoch_started_at);

        // An epoch advance keeps the fresh baseline (clock resets on commit).
        let next_epoch = encrypt_state("s", "g", 8, b"c", "p", &fixed_salt());
        let baseline = next_epoch.epoch_started_at;
        let kept = next_epoch.carry_epoch_started_at(&prev);
        assert_eq!(kept.epoch_started_at, baseline);
    }

    #[test]
    fn encrypt_with_distinct_salts_produces_distinct_ciphertext() {
        // Sanity: salt randomisation defeats rainbow-table lookups
        // even when the same device secret + plaintext is used across
        // two snapshots. Mirrors the SDK key_backup invariant.
        let bytes = fake_state_record_bytes("a", 1);
        let one = encrypt_state("s", "a", 1, &bytes, "p", b"salt-one");
        let two = encrypt_state("s", "a", 1, &bytes, "p", b"salt-two");
        assert_ne!(one.ciphertext_hex, two.ciphertext_hex);
        assert_ne!(one.mac_hex, two.mac_hex);
    }

    #[test]
    fn invalid_state_record_surfaces_typed_error() {
        // The AEAD tag verifies (encryption is byte-transparent), but the
        // inner bytes don't parse as `MlsGroupStateRecord`. The error
        // is `InvalidStateRecord`, distinct from `SecretMismatch`.
        let envelope = encrypt_state(
            "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
            "z",
            0,
            b"this is not json",
            "p",
            &fixed_salt(),
        );
        let plaintext = decrypt_envelope(&envelope, "p").unwrap();
        #[cfg(not(target_arch = "wasm32"))]
        {
            let parsed = MlsLocalCheckpointEnvelope::restore_state_record(&plaintext);
            assert!(matches!(parsed, Err(EnvelopeError::InvalidStateRecord(_))));
        }
        #[cfg(target_arch = "wasm32")]
        let _ = plaintext;
    }
}
