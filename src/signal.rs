//! Receiver for the encrypted-only Signal rail (`zh/sync/signal.md`).
//!
//! A Signal is a peer of Event and Device Message, not a subtype: it advances
//! no `actor_seq`, enters no Seal coverage and produces no reducer state. It
//! also never travels on the account-subscribe stream — `send` and `subscribe`
//! are its own rail (§4), and the exact payload type, target and sender
//! sequence live inside the ciphertext and are never reconstructible from the
//! outer header (§1).
//!
//! There is no plaintext branch. An implementation that cannot verify
//! encrypted signals for a scope MUST withdraw the scope capability rather
//! than fall back (§3), so every seam here fails closed.
//!
//! This crate holds no MLS group state, so the two checks that need it are
//! host seams: [`SignalSenderKeyResolver`] resolves the sending device's
//! active signing method *under `seal_ref`*, and [`SignalDecryptor`] opens the
//! AEAD with the scope's MLS-exporter content key. Everything a receiver can
//! decide from the envelope alone is decided here.

use std::collections::BTreeMap;

use chrono::{DateTime, Duration, Utc};
use serde_json::Value;

use crate::MaybeSendSync;
use crate::protocol::signatures::{PublicKeyMaterial, verify_eddsa_signal_proof};
use crate::protocol::{Did, Error, Result, ScopeRef, SignalEnvelope, canonical};
use crate::store::{BoundedSeenWindow, DEFAULT_SEEN_EVENTS_CAPACITY};

pub use crate::protocol::{PresenceStatus, aggregate_presence_states};
use crate::protocol::{validate_last_active_at, validate_status_message};

/// Decrypted payload kind of a presence Signal (`profiles-presence.md` §3.3).
pub const SIGNAL_PLAINTEXT_KIND_PRESENCE: &str = "ak.presence";

/// Resolver for the sending device's active signing key.
///
/// The contract is deliberately stated over the whole envelope rather than
/// over `(actor_id, device_id)`: `signal.md` §1 requires
/// `proof.verification_method` to resolve, **at `seal_ref`**, to an active
/// device signing method that `sender_actor_id` authorized for
/// `sender_device_id`, and forbids substituting string equality between the
/// verification-method fragment and the device id for that lookup.
/// Implementations therefore read accepted device-authorization state at the
/// Seal basis, and return `None` — failing the Signal closed — whenever the
/// device is not authorized to send into `scope_ref` at that basis.
pub trait SignalSenderKeyResolver: MaybeSendSync {
    fn resolve_sender_key(&self, envelope: &SignalEnvelope) -> Option<PublicKeyMaterial>;
}

impl<F> SignalSenderKeyResolver for F
where
    F: Fn(&SignalEnvelope) -> Option<PublicKeyMaterial> + MaybeSendSync,
{
    fn resolve_sender_key(&self, envelope: &SignalEnvelope) -> Option<PublicKeyMaterial> {
        self(envelope)
    }
}

/// Opener for the AEAD ciphertext of a Signal.
///
/// The content key is derived from the scope's MLS group exporter under label
/// `ak.signal-v1`, and the nonce from the canonical
/// `{key_ref, epoch, device_id, purpose, aead_profile}` context of
/// `encoding.md` §10.1. Both need accepted MLS state, which this crate does
/// not hold by layering.
///
/// Implementations MUST fail closed when `encrypted_payload.aead_profile` is
/// not the ciphersuite the group at `key_ref.group_state_ref` actually
/// negotiated, when `epoch` names no known epoch of that group, or when the
/// recomputed sender nonce prefix does not match the declared `nonce`
/// (`signal.md` §1, `encoding.md` §10.1). The AAD is
/// `encrypted_payload.aad_digest`, which [`SignalReceiver`] has already
/// recomputed from the immutable outer header before this is called.
pub trait SignalDecryptor: MaybeSendSync {
    fn open(&self, envelope: &SignalEnvelope) -> Result<Vec<u8>>;
}

/// Decrypted, sender-bound Signal payload.
///
/// `kind` and `payload_sequence` are the common minimum. Product profiles may
/// additionally carry `actor_id` and an inner `ttl_ms`; when present they are
/// checked against the authenticated envelope. `body` keeps the whole decoded
/// object so a domain projection can read its own further fields without a
/// second parse.
#[derive(Clone, Debug, PartialEq)]
pub struct SignalPlaintext {
    pub kind: String,
    pub actor_id: Did,
    pub payload_sequence: u64,
    pub ttl_ms: Option<u64>,
    pub body: BTreeMap<String, Value>,
    /// Outer `sent_at`, the reference instant for the plaintext TTL and the
    /// tie-breaker for `status_message` selection (`profiles-presence.md`
    /// §3.3).
    pub sent_at: DateTime<Utc>,
    /// The earlier of the outer `expires_at` and `sent_at + ttl_ms` when the
    /// product profile carries an inner TTL.
    pub expires_at: DateTime<Utc>,
    pub scope_ref: ScopeRef,
    pub seal_ref: crate::protocol::SealId,
    pub sender_device_id: crate::protocol::DeviceId,
}

impl SignalPlaintext {
    fn parse(envelope: &SignalEnvelope, plaintext: &[u8]) -> Result<Self> {
        let value = canonical::parse_canonical_json(plaintext)?;
        let Value::Object(map) = value else {
            return Err(Error::Protocol(
                "signal plaintext must be a canonical JSON object".to_owned(),
            ));
        };
        let kind = map
            .get("kind")
            .and_then(Value::as_str)
            .filter(|kind| !kind.is_empty())
            .ok_or_else(|| Error::Protocol("signal plaintext requires kind".to_owned()))?
            .to_owned();
        if let Some(actor_value) = map.get("actor_id") {
            let actor = actor_value.as_str().ok_or_else(|| {
                Error::Protocol("signal plaintext actor_id must be a DID string".to_owned())
            })?;
            let actor_id = Did::new(actor).map_err(|error| Error::Protocol(error.to_string()))?;
            // The outer proof authenticates `sender_actor_id` only. A
            // plaintext that names a different actor is an unauthenticated
            // claim about a third party.
            if actor_id != envelope.sender_actor_id {
                return Err(Error::Protocol(
                    "signal plaintext actor_id must equal the authenticated sender_actor_id"
                        .to_owned(),
                ));
            }
        }
        let payload_sequence = map
            .get("payload_sequence")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                Error::Protocol("signal plaintext requires payload_sequence".to_owned())
            })?;
        let ttl_ms = match map.get("ttl_ms") {
            Some(value) => Some(value.as_u64().filter(|ttl| *ttl > 0).ok_or_else(|| {
                Error::Protocol("signal plaintext ttl_ms must be a positive integer".to_owned())
            })?),
            None => None,
        };
        let expires_at = match ttl_ms {
            Some(ttl_ms) => {
                let milliseconds = i64::try_from(ttl_ms).map_err(|_| {
                    Error::Protocol("signal plaintext ttl_ms is out of range".to_owned())
                })?;
                let inner_expiry = envelope.sent_at
                    + Duration::try_milliseconds(milliseconds).ok_or_else(|| {
                        Error::Protocol("signal plaintext ttl_ms is out of range".to_owned())
                    })?;
                inner_expiry.min(envelope.expires_at)
            }
            None => envelope.expires_at,
        };
        Ok(Self {
            kind,
            actor_id: envelope.sender_actor_id.clone(),
            payload_sequence,
            ttl_ms,
            body: map.into_iter().collect(),
            sent_at: envelope.sent_at,
            expires_at,
            scope_ref: envelope.scope_ref.clone(),
            seal_ref: envelope.seal_ref.clone(),
            sender_device_id: envelope.sender_device_id.clone(),
        })
    }
}

/// Receiver-side admission for encrypted Signals.
///
/// Order matters: the envelope is fully checked before any key material is
/// touched, and decrypted only after the sending device's proof verifies, so
/// an unauthenticated envelope can never reach the AEAD.
#[derive(Debug)]
pub struct SignalReceiver {
    seen: BoundedSeenWindow<(String, String, u64)>,
}

impl Default for SignalReceiver {
    fn default() -> Self {
        Self::new()
    }
}

impl SignalReceiver {
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_SEEN_EVENTS_CAPACITY)
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            seen: BoundedSeenWindow::new(capacity),
        }
    }

    /// Admit one Signal and return its decrypted payload.
    ///
    /// Performs, in order: the shared structural contract
    /// ([`SignalEnvelope::validate_structural`] — `scope_ref.realm_id` equal to
    /// the envelope Realm, the fixed `scheme` / `purpose`, the class TTL
    /// ceiling, the recomputed `aad_digest` over the immutable header, the
    /// `proof.created_at == sent_at` equality, the recomputed
    /// `envelope_digest` and the canonical size bound); wall-clock expiry;
    /// the Seal-relative device authorization lookup; the device proof
    /// signature; the AEAD open; the closed plaintext shape; and finally the
    /// `(sender_device_id, scope_ref, payload_sequence)` de-duplication of
    /// `signal.md` §2.
    pub fn accept(
        &mut self,
        envelope: &SignalEnvelope,
        resolver: &dyn SignalSenderKeyResolver,
        decryptor: &dyn SignalDecryptor,
        now: DateTime<Utc>,
    ) -> Result<SignalPlaintext> {
        envelope
            .validate_structural()
            .map_err(|error| Error::Protocol(error.to_string()))?;
        if envelope.expires_at <= now {
            return Err(Error::Protocol("signal has already expired".to_owned()));
        }
        let public_key = resolver.resolve_sender_key(envelope).ok_or_else(|| {
            Error::Protocol(
                "signal sender device is not an authorized active signer at seal_ref".to_owned(),
            )
        })?;
        verify_eddsa_signal_proof(envelope, &public_key)
            .map_err(|error| Error::Crypto(error.to_string()))?;
        let plaintext = decryptor.open(envelope)?;
        let parsed = SignalPlaintext::parse(envelope, &plaintext)?;
        let key = (
            envelope.sender_device_id.as_str().to_owned(),
            scope_key(&envelope.scope_ref)?,
            parsed.payload_sequence,
        );
        if !self.seen.remember(key) {
            return Err(Error::Protocol(
                "signal repeats an already delivered (sender_device_id, scope_ref, payload_sequence)"
                    .to_owned(),
            ));
        }
        Ok(parsed)
    }
}

fn scope_key(scope_ref: &ScopeRef) -> Result<String> {
    let bytes = canonical::canonical_json_bytes(&serde_json::to_value(scope_ref)?)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// One accepted per-device presence observation.
#[derive(Clone, Debug, PartialEq)]
pub struct PresenceObservation {
    pub state: PresenceStatus,
    pub status_message: Option<String>,
    pub last_active_at: Option<String>,
    pub payload_sequence: u64,
    pub sent_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Receiver-side presence projection (`profiles-presence.md` §3.3).
///
/// The aggregation is the receiver's job and only the receiver's: a Sync
/// Service may not decrypt, aggregate or project presence content. Only
/// signals whose outer *and* plaintext TTL are unexpired and whose sequence
/// has not regressed are considered.
#[derive(Clone, Debug, Default)]
pub struct PresenceProjection {
    devices: BTreeMap<Did, BTreeMap<String, PresenceObservation>>,
}

impl PresenceProjection {
    pub fn new() -> Self {
        Self::default()
    }

    /// Fold one decrypted presence plaintext into the projection.
    ///
    /// Returns the stored observation, or an error when the plaintext is not
    /// a presence payload, carries a value outside the closed `state` set, or
    /// regresses the per-device sequence. `state` is a v1 closed set: an
    /// unknown value is dropped, never mapped to a nearby state
    /// (`profiles-presence.md` §3.2).
    pub fn apply(&mut self, plaintext: &SignalPlaintext) -> Result<PresenceObservation> {
        if plaintext.kind != SIGNAL_PLAINTEXT_KIND_PRESENCE {
            return Err(Error::Protocol(format!(
                "presence projection received plaintext kind '{}'",
                plaintext.kind
            )));
        }
        let state = plaintext
            .body
            .get("state")
            .and_then(Value::as_str)
            .and_then(PresenceStatus::parse_wire)
            .ok_or_else(|| {
                Error::Protocol("presence state is outside the v1 closed set".to_owned())
            })?;
        let status_message = match plaintext.body.get("status_message") {
            Some(value) => {
                let text = value.as_str().ok_or_else(|| {
                    Error::Protocol("presence status_message must be a string".to_owned())
                })?;
                validate_status_message(text)
                    .map_err(|error| Error::Protocol(error.to_string()))?;
                Some(text.to_owned())
            }
            None => None,
        };
        let last_active_at = match plaintext.body.get("last_active_at") {
            Some(value) => {
                let text = value.as_str().ok_or_else(|| {
                    Error::Protocol("presence last_active_at must be a string".to_owned())
                })?;
                validate_last_active_at(text)
                    .map_err(|error| Error::Protocol(error.to_string()))?;
                Some(text.to_owned())
            }
            None => None,
        };
        let device_key = plaintext.sender_device_id.as_str().to_owned();
        let entry = self.devices.entry(plaintext.actor_id.clone()).or_default();
        if let Some(previous) = entry.get(&device_key)
            && previous.payload_sequence >= plaintext.payload_sequence
        {
            return Err(Error::Protocol(
                "presence payload_sequence regressed for this device".to_owned(),
            ));
        }
        let observation = PresenceObservation {
            state,
            status_message,
            last_active_at,
            payload_sequence: plaintext.payload_sequence,
            sent_at: plaintext.sent_at,
            expires_at: plaintext.expires_at,
        };
        entry.insert(device_key, observation.clone());
        Ok(observation)
    }

    /// Unexpired per-device observations for an actor, in device-id order.
    pub fn observations(&self, actor_id: &Did, now: DateTime<Utc>) -> Vec<&PresenceObservation> {
        self.devices
            .get(actor_id)
            .map(|devices| {
                devices
                    .values()
                    .filter(|observation| observation.expires_at > now)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Aggregate state under the canonical priority `dnd > online > idle`,
    /// falling back to `offline` when no unexpired signal remains.
    pub fn aggregated(&self, actor_id: &Did, now: DateTime<Utc>) -> PresenceStatus {
        aggregate_presence_states(
            self.observations(actor_id, now)
                .into_iter()
                .map(|observation| observation.state),
        )
    }

    /// Most recently sent non-empty `status_message` among unexpired signals.
    pub fn status_message(&self, actor_id: &Did, now: DateTime<Utc>) -> Option<&str> {
        self.observations(actor_id, now)
            .into_iter()
            .filter(|observation| {
                observation
                    .status_message
                    .as_deref()
                    .is_some_and(|message| !message.is_empty())
            })
            .max_by_key(|observation| observation.sent_at)
            .and_then(|observation| observation.status_message.as_deref())
    }

    /// Most recently sent validated `last_active_at` among unexpired signals.
    pub fn last_active_at(&self, actor_id: &Did, now: DateTime<Utc>) -> Option<&str> {
        self.observations(actor_id, now)
            .into_iter()
            .filter(|observation| observation.last_active_at.is_some())
            .max_by_key(|observation| observation.sent_at)
            .and_then(|observation| observation.last_active_at.as_deref())
    }

    /// Drop observations at or past their effective expiry, returning the
    /// number removed.
    pub fn expire(&mut self, now: DateTime<Utc>) -> usize {
        let before = self.devices.values().map(BTreeMap::len).sum::<usize>();
        self.devices.retain(|_, devices| {
            devices.retain(|_, observation| observation.expires_at > now);
            !devices.is_empty()
        });
        before - self.devices.values().map(BTreeMap::len).sum::<usize>()
    }
}

#[cfg(test)]
mod tests {
    use arkret_wire::{DeviceId, Hash, RealmId, SealId};
    use chrono::TimeZone;
    use ed25519_dalek::SigningKey;
    use serde_json::json;

    use super::*;
    use crate::protocol::signal::{SignalClass, SignalEncryptedPayload, SignalKeyRef, SignalProof};
    use crate::protocol::signatures::sign_eddsa_detached_jws;

    fn realm() -> RealmId {
        RealmId::new("ak:realm:01904100-0000-7000-8000-65c7feb295d7").unwrap()
    }

    fn actor() -> Did {
        Did::new("did:webvh:z6mkfixture:alice.example").unwrap()
    }

    fn device(suffix: &str) -> DeviceId {
        DeviceId::new(format!("ak:device:01904100-0000-7000-8000-{suffix}")).unwrap()
    }

    fn sent_at() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, 28, 12, 0, 0).unwrap()
    }

    /// Build a fully signed Signal whose ciphertext field literally carries the
    /// plaintext bytes, paired with a decryptor that returns them. The AEAD
    /// itself needs MLS state this crate does not hold; every check under test
    /// here is a receiver check that runs before or after the open.
    fn signed_signal(
        device_id: DeviceId,
        plaintext: Value,
        signal_class: SignalClass,
        ttl_seconds: i64,
        seed: [u8; 32],
    ) -> (SignalEnvelope, PublicKeyMaterial, Vec<u8>) {
        let plaintext_bytes = canonical::canonical_json_bytes(&plaintext).unwrap();
        let signing_key = SigningKey::from_bytes(&seed);
        let verification_method = format!("{}#{}", actor(), device_id);
        let mut envelope = SignalEnvelope {
            realm_id: realm(),
            scope_ref: ScopeRef::Realm { realm_id: realm() },
            sender_actor_id: actor(),
            sender_device_id: device_id,
            seal_ref: SealId::new(format!("ak:seal:sha256:{}", "a".repeat(64))).unwrap(),
            signal_class,
            sent_at: sent_at(),
            expires_at: sent_at() + Duration::seconds(ttl_seconds),
            encrypted_payload: SignalEncryptedPayload {
                scheme: crate::protocol::signal::SIGNAL_AEAD_SCHEME.to_owned(),
                key_ref: SignalKeyRef {
                    algorithm: "MLS-EXPORTER-AEAD".to_owned(),
                    group_state_ref: "ak:event:01904100-0000-7000-8000-cccccccccccc".to_owned(),
                },
                purpose: crate::protocol::signal::SIGNAL_AEAD_PURPOSE.to_owned(),
                aead_profile: "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519".to_owned(),
                epoch: 7,
                nonce: "AAAAAAAAAAAAAAAA".to_owned(),
                ciphertext: "Q2lwaGVydGV4dFBsYWNlaG9sZGVy".to_owned(),
                aad_digest: Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
            },
            proof: SignalProof {
                kind: "detached_jws".to_owned(),
                verification_method,
                alg: "EdDSA".to_owned(),
                envelope_digest: Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
                created_at: sent_at(),
                domain: None,
                audience: None,
                jws: "header..signature".to_owned(),
            },
        };
        envelope.encrypted_payload.aad_digest = envelope.expected_aad_digest().unwrap();
        envelope.proof.envelope_digest = envelope.envelope_digest().unwrap();
        let binding = envelope.proof_binding_bytes().unwrap();
        envelope.proof.jws = sign_eddsa_detached_jws(&signing_key, &binding).unwrap();
        let public_key = PublicKeyMaterial::Ed25519Raw {
            bytes: signing_key.verifying_key().to_bytes().to_vec(),
        };
        (envelope, public_key, plaintext_bytes)
    }

    struct FixedDecryptor(Vec<u8>);

    impl SignalDecryptor for FixedDecryptor {
        fn open(&self, _envelope: &SignalEnvelope) -> Result<Vec<u8>> {
            Ok(self.0.clone())
        }
    }

    struct RefusingDecryptor;

    impl SignalDecryptor for RefusingDecryptor {
        fn open(&self, _envelope: &SignalEnvelope) -> Result<Vec<u8>> {
            Err(Error::Protocol(
                "aead_profile is not the group suite".to_owned(),
            ))
        }
    }

    fn presence_plaintext(state: &str, sequence: u64) -> Value {
        json!({
            "kind": SIGNAL_PLAINTEXT_KIND_PRESENCE,
            "actor_id": actor().as_str(),
            "state": state,
            "payload_sequence": sequence,
            "ttl_ms": 30_000
        })
    }

    fn key_of(public_key: PublicKeyMaterial) -> impl SignalSenderKeyResolver {
        move |_envelope: &SignalEnvelope| Some(public_key.clone())
    }

    #[test]
    fn receiver_accepts_a_signed_presence_signal_and_projects_the_plaintext() {
        let (envelope, public_key, plaintext) = signed_signal(
            device("000000000005"),
            presence_plaintext("online", 1),
            SignalClass::Session,
            30,
            [11; 32],
        );
        let mut receiver = SignalReceiver::new();
        let accepted = receiver
            .accept(
                &envelope,
                &key_of(public_key),
                &FixedDecryptor(plaintext),
                sent_at(),
            )
            .unwrap();

        assert_eq!(accepted.kind, SIGNAL_PLAINTEXT_KIND_PRESENCE);
        assert_eq!(accepted.payload_sequence, 1);
        let mut projection = PresenceProjection::new();
        projection.apply(&accepted).unwrap();
        assert_eq!(
            projection.aggregated(&actor(), sent_at()),
            PresenceStatus::Online
        );
    }

    #[test]
    fn receiver_accepts_a_profile_without_plaintext_actor_or_ttl() {
        let plaintext_value = json!({
            "kind": "ak.message.stream",
            "payload_sequence": 2,
            "strand_id": "ak:strand:01904100-0000-7000-8000-000000000006",
            "track_name": "discussion",
            "message_id": "ak:message:01904100-0000-7000-8000-000000000007",
            "attempt": 0,
            "stream_id": "ak:message_stream:01904100-0000-7000-8000-000000000008",
            "seq": 0,
            "frame_kind": "keyframe",
            "format": "plain",
            "text": "hello",
            "truncated": false
        });
        let (envelope, public_key, plaintext) = signed_signal(
            device("000000000005"),
            plaintext_value,
            SignalClass::Session,
            30,
            [26; 32],
        );
        let accepted = SignalReceiver::new()
            .accept(
                &envelope,
                &key_of(public_key),
                &FixedDecryptor(plaintext),
                sent_at(),
            )
            .unwrap();

        assert_eq!(accepted.actor_id, actor());
        assert_eq!(accepted.ttl_ms, None);
        assert_eq!(accepted.expires_at, envelope.expires_at);
    }

    #[test]
    fn receiver_rejects_a_signal_whose_sender_device_is_not_authorized_at_seal_ref() {
        let (envelope, _public_key, plaintext) = signed_signal(
            device("000000000005"),
            presence_plaintext("online", 1),
            SignalClass::Session,
            30,
            [12; 32],
        );
        let mut receiver = SignalReceiver::new();
        let unauthorized = |_envelope: &SignalEnvelope| None;

        let error = receiver
            .accept(
                &envelope,
                &unauthorized,
                &FixedDecryptor(plaintext),
                sent_at(),
            )
            .unwrap_err();

        assert!(format!("{error}").contains("authorized active signer"));
    }

    #[test]
    fn receiver_rejects_a_signal_signed_by_another_device_key() {
        let (envelope, _public_key, plaintext) = signed_signal(
            device("000000000005"),
            presence_plaintext("online", 1),
            SignalClass::Session,
            30,
            [13; 32],
        );
        let other = PublicKeyMaterial::Ed25519Raw {
            bytes: SigningKey::from_bytes(&[14; 32])
                .verifying_key()
                .to_bytes()
                .to_vec(),
        };
        let mut receiver = SignalReceiver::new();

        assert!(
            receiver
                .accept(
                    &envelope,
                    &key_of(other),
                    &FixedDecryptor(plaintext),
                    sent_at()
                )
                .is_err()
        );
    }

    #[test]
    fn receiver_rejects_a_session_signal_past_the_class_ttl_ceiling() {
        // `session` tops out at 30 seconds; 120 is the cross-class hard cap.
        let (envelope, public_key, plaintext) = signed_signal(
            device("000000000005"),
            presence_plaintext("online", 1),
            SignalClass::Session,
            120,
            [15; 32],
        );
        let mut receiver = SignalReceiver::new();

        let error = receiver
            .accept(
                &envelope,
                &key_of(public_key),
                &FixedDecryptor(plaintext),
                sent_at(),
            )
            .unwrap_err();

        assert!(format!("{error}").contains("signal_ttl_out_of_range"));
    }

    #[test]
    fn receiver_rejects_an_expired_signal() {
        let (envelope, public_key, plaintext) = signed_signal(
            device("000000000005"),
            presence_plaintext("online", 1),
            SignalClass::Session,
            30,
            [16; 32],
        );
        let mut receiver = SignalReceiver::new();

        let error = receiver
            .accept(
                &envelope,
                &key_of(public_key),
                &FixedDecryptor(plaintext),
                sent_at() + Duration::seconds(30),
            )
            .unwrap_err();

        assert!(format!("{error}").contains("already expired"));
    }

    #[test]
    fn receiver_deduplicates_the_sender_scope_sequence_triple() {
        let (envelope, public_key, plaintext) = signed_signal(
            device("000000000005"),
            presence_plaintext("online", 1),
            SignalClass::Session,
            30,
            [17; 32],
        );
        let mut receiver = SignalReceiver::new();
        let resolver = key_of(public_key);
        receiver
            .accept(
                &envelope,
                &resolver,
                &FixedDecryptor(plaintext.clone()),
                sent_at(),
            )
            .unwrap();

        let error = receiver
            .accept(&envelope, &resolver, &FixedDecryptor(plaintext), sent_at())
            .unwrap_err();

        assert!(format!("{error}").contains("already delivered"));
    }

    #[test]
    fn receiver_refuses_a_plaintext_that_claims_another_actor() {
        let mut foreign = presence_plaintext("online", 1);
        foreign["actor_id"] = json!("did:webvh:z6mkfixture:mallory.example");
        let (envelope, public_key, _) = signed_signal(
            device("000000000005"),
            presence_plaintext("online", 1),
            SignalClass::Session,
            30,
            [18; 32],
        );
        let mut receiver = SignalReceiver::new();

        let error = receiver
            .accept(
                &envelope,
                &key_of(public_key),
                &FixedDecryptor(canonical::canonical_json_bytes(&foreign).unwrap()),
                sent_at(),
            )
            .unwrap_err();

        assert!(format!("{error}").contains("must equal the authenticated sender_actor_id"));
    }

    #[test]
    fn receiver_propagates_a_decryptor_that_fails_the_ciphersuite_check_closed() {
        let (envelope, public_key, _) = signed_signal(
            device("000000000005"),
            presence_plaintext("online", 1),
            SignalClass::Session,
            30,
            [19; 32],
        );
        let mut receiver = SignalReceiver::new();

        let error = receiver
            .accept(
                &envelope,
                &key_of(public_key),
                &RefusingDecryptor,
                sent_at(),
            )
            .unwrap_err();

        assert!(format!("{error}").contains("group suite"));
    }

    #[test]
    fn presence_projection_aggregates_devices_and_expires_them() {
        let mut projection = PresenceProjection::new();
        for (suffix, state, seed) in [
            ("000000000005", "online", [21u8; 32]),
            ("000000000006", "dnd", [22u8; 32]),
        ] {
            let (envelope, public_key, plaintext) = signed_signal(
                device(suffix),
                presence_plaintext(state, 1),
                SignalClass::Session,
                30,
                seed,
            );
            let accepted = SignalReceiver::new()
                .accept(
                    &envelope,
                    &key_of(public_key),
                    &FixedDecryptor(plaintext),
                    sent_at(),
                )
                .unwrap();
            projection.apply(&accepted).unwrap();
        }

        assert_eq!(projection.observations(&actor(), sent_at()).len(), 2);
        assert_eq!(
            projection.aggregated(&actor(), sent_at()),
            PresenceStatus::Dnd
        );
        assert_eq!(projection.expire(sent_at() + Duration::seconds(30)), 2);
        assert_eq!(
            projection.aggregated(&actor(), sent_at() + Duration::seconds(30)),
            PresenceStatus::Offline
        );
    }

    #[test]
    fn presence_projection_rejects_a_regressed_sequence_and_an_unknown_state() {
        let device_id = device("000000000005");
        let mut projection = PresenceProjection::new();
        let (envelope, public_key, plaintext) = signed_signal(
            device_id.clone(),
            presence_plaintext("online", 4),
            SignalClass::Session,
            30,
            [23; 32],
        );
        let accepted = SignalReceiver::new()
            .accept(
                &envelope,
                &key_of(public_key),
                &FixedDecryptor(plaintext),
                sent_at(),
            )
            .unwrap();
        projection.apply(&accepted).unwrap();

        let (older_envelope, older_key, older_plaintext) = signed_signal(
            device_id.clone(),
            presence_plaintext("dnd", 3),
            SignalClass::Session,
            30,
            [24; 32],
        );
        let older = SignalReceiver::new()
            .accept(
                &older_envelope,
                &key_of(older_key),
                &FixedDecryptor(older_plaintext),
                sent_at(),
            )
            .unwrap();
        assert!(projection.apply(&older).is_err());
        assert_eq!(
            projection.aggregated(&actor(), sent_at()),
            PresenceStatus::Online
        );

        // `unavailable` is a pre-v1 leftover, not a v1 wire value: it is
        // dropped, never mapped onto a nearby state.
        let (unknown_envelope, unknown_key, unknown_plaintext) = signed_signal(
            device_id,
            presence_plaintext("unavailable", 5),
            SignalClass::Session,
            30,
            [25; 32],
        );
        let unknown = SignalReceiver::new()
            .accept(
                &unknown_envelope,
                &key_of(unknown_key),
                &FixedDecryptor(unknown_plaintext),
                sent_at(),
            )
            .unwrap();
        assert!(projection.apply(&unknown).is_err());
    }
}
