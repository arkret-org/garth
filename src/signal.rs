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
//! This crate holds no MLS group state or device directory, so the two checks
//! that need them are host seams: [`SignalSenderKeyResolver`] resolves the
//! sending device's active signing method from the host's *current* accepted
//! device directory, and [`SignalDecryptor`] opens the AEAD with the scope's
//! MLS-exporter content key. Everything a receiver can decide from the
//! envelope alone is decided here.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
#[cfg(test)]
use serde_json::Value;

use crate::MaybeSendSync;
use crate::protocol::signatures::{PublicKeyMaterial, verify_ed25519_signal_proof};
use crate::protocol::{
    AccountId, ActorId, Error, Result, ScopeRef, SignalEnvelope, SignalSequence,
    SignalSequenceDecision, SignalSequenceHighWater, canonical, open_signal_plaintext,
};
use crate::store::{BoundedSeenWindow, DEFAULT_SEEN_EVENTS_CAPACITY};

pub use crate::protocol::{PresenceStatus, aggregate_presence_states};
use crate::protocol::{validate_last_active_at, validate_status_message};

/// Decrypted payload kind of a presence Signal (`profiles-presence.md` §3.3).
pub const SIGNAL_PLAINTEXT_KIND_PRESENCE: &str = "ak.presence";

/// Decrypted payload kind of a call signalling Signal
/// (`webrtc-signaling.md`; the closed body is
/// [`crate::protocol::CallSignalPlaintext`]).
pub const SIGNAL_PLAINTEXT_KIND_CALL: &str = "ak.call.signal";

/// A Signal signing key admitted by the host from the current local PCR/device
/// state for the exact public AccountId.
#[derive(Clone, Debug)]
pub struct VerifiedSignalSenderKey {
    public_key: PublicKeyMaterial,
    actor_id: ActorId,
    device_id: crate::protocol::DeviceId,
    verification_method: crate::protocol::DidUrl,
    authority: AccountId,
    device_authorize_event_id: crate::protocol::EventId,
}

impl VerifiedSignalSenderKey {
    /// Production constructor: admit one directory-resolved signing key as
    /// the verified sender key for `(actor_id, device_id)`.
    ///
    /// The caller (a [`SignalSenderKeyResolver`] implementation) remains
    /// responsible for the host-state half of `signal.md` §1: resolving the
    /// authoritative verify key from its *current* accepted device directory
    /// through current root-anchored PCR state or a verified origin-Station
    /// projection attestation with exact account, generation, status and expiry.
    /// Known revocation or fencing always overrides a remaining MLS leaf.
    /// That evidence lives outside this crate by
    /// layering — garth holds no device directory or PCR state.
    ///
    /// What this constructor does enforce, fail-closed, is every completeness
    /// condition of the evidence tuple that is decidable locally:
    ///
    /// * `authority` is structurally valid and equals the complete account
    ///   carried by `actor_id`, including its Station;
    /// * `verification_method` is a DID URL whose DID projects to
    ///   the signing principal of `actor_id` and whose fragment equals `device_id` (the §1
    ///   directory-lookup completeness condition, mirrored from
    ///   [`SignalEnvelope::validate_structural`] so a mis-bound key cannot be
    ///   constructed even before an envelope exists);
    /// * `public_key` decodes to a 32-byte Ed25519 verifying key, so
    ///   malformed key material is rejected here instead of surfacing as a
    ///   spurious signature failure later.
    pub fn from_directory_evidence(
        public_key: PublicKeyMaterial,
        actor_id: ActorId,
        device_id: crate::protocol::DeviceId,
        verification_method: crate::protocol::DidUrl,
        authority: AccountId,
        device_authorize_event_id: crate::protocol::EventId,
    ) -> Result<Self> {
        authority
            .validate()
            .map_err(|error| Error::Protocol(error.to_string()))?;
        if actor_id.as_account_id() != Some(&authority) {
            return Err(Error::Protocol(
                "signal sender authority account_id does not name the exact sender actor"
                    .to_owned(),
            ));
        }
        let (controller, fragment) =
            verification_method
                .as_str()
                .split_once('#')
                .ok_or_else(|| {
                    Error::Protocol(
                        "signal sender verification_method requires a DID URL fragment".to_owned(),
                    )
                })?;
        let controller_core = crate::protocol::Did::new(controller)
            .map_err(|error| Error::Protocol(error.to_string()))
            .and_then(|did| {
                crate::protocol::project_did_to_core_id(&did)
                    .map_err(|error| Error::Protocol(error.to_string()))
            })?;
        if &controller_core != actor_id.signing_principal_id() || fragment != device_id.as_str() {
            return Err(Error::Protocol(
                "signal sender verification_method controller or fragment does not match the directory key"
                    .to_owned(),
            ));
        }
        // Fail malformed key material closed at admission time.
        public_key
            .ed25519_bytes()
            .map_err(|error| Error::Protocol(error.to_string()))?;
        Ok(Self {
            public_key,
            actor_id,
            device_id,
            verification_method,
            authority,
            device_authorize_event_id,
        })
    }

    /// The exact key whose producer proof admission already verified.
    pub fn public_key(&self) -> &PublicKeyMaterial {
        &self.public_key
    }

    /// The current accepted authorization to bind to the winning MLS leaf.
    pub fn device_authorize_event_id(&self) -> &crate::protocol::EventId {
        &self.device_authorize_event_id
    }

    fn validate_for(&self, envelope: &SignalEnvelope) -> Result<()> {
        if self.actor_id != envelope.sender_actor_id
            || self.device_id != envelope.sender_device_id
            || self.verification_method != envelope.proof.verification_method
            || envelope.sender_actor_id.as_account_id() != Some(&self.authority)
        {
            return Err(Error::Protocol(
                "signal verified sender key does not bind this envelope".to_owned(),
            ));
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn for_test(envelope: &SignalEnvelope, public_key: PublicKeyMaterial) -> Self {
        let authority = envelope.sender_actor_id.as_account_id().unwrap().clone();
        Self {
            public_key,
            actor_id: envelope.sender_actor_id.clone(),
            device_id: envelope.sender_device_id.clone(),
            verification_method: envelope.proof.verification_method.clone(),
            authority,
            device_authorize_event_id: crate::protocol::EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                [0x42; 32],
            ),
        }
    }
}

/// Resolver for the sending device's active signing key.
///
/// The contract is stated over the whole envelope rather than over
/// `(actor_id, device_id)` so an implementation can also check
/// `proof.verification_method` itself. Two separate state domains meet here
/// and must not be collapsed:
///
/// * the **Realm/scope** basis is `envelope.seal_ref` — membership, capability
///   and product actions are re-evaluated there;
/// * **device authorization** is independently replayed for the exact
///   authority pair selected by the Realm membership. It cannot be
///   target-Seal-relative:
///   a target-Realm Seal does not locate another principal's device frontier,
///   and `keys_query_request_body` carries no as-of basis by design.
///
/// Implementations return `None` — failing the Signal closed — when exact
/// authority evidence is unavailable, the device is revoked or non-active,
/// its generation is fenced or conflicted, or the frozen trust chain is
/// incomplete. `signal.md` §1
/// requires the method's DID to project to the sender's signing principal
/// and its fragment to equal `sender_device_id`, but that is only the
/// completeness condition of the lookup key and is already enforced by
/// [`SignalEnvelope::validate_structural`]; it is never a substitute for the
/// directory lookup.
pub trait SignalSenderKeyResolver: MaybeSendSync {
    fn resolve_sender_key(&self, envelope: &SignalEnvelope) -> Option<VerifiedSignalSenderKey>;
}

impl<F> SignalSenderKeyResolver for F
where
    F: Fn(&SignalEnvelope) -> Option<VerifiedSignalSenderKey> + MaybeSendSync,
{
    fn resolve_sender_key(&self, envelope: &SignalEnvelope) -> Option<VerifiedSignalSenderKey> {
        self(envelope)
    }
}

/// Opener for the AEAD ciphertext of a Signal.
///
/// The Signal key is derived under `ak.signal-v1` from the root selected by
/// the scope's accepted content policy: history root for exporter-content,
/// or the separate non-deliverable Signal root for standard MLS. The nonce is
/// the full-width sender counter (`encoding.md` §10.1). This needs accepted
/// MLS state, which this crate does not hold. The opener must cross-bind the supplied current
/// sender evidence to the complete accepted MLS leaf identity, signing key
/// and authorization Event, and resolve the exact scope/group/epoch/winning
/// state reference. Successful AEAD alone is not sender authentication.
///
/// Implementations MUST fail closed when `encrypted_payload.aead_profile` is
/// not the ciphersuite the group at `key_ref.group_state_ref` actually
/// negotiated, when `epoch` is not the accepted current epoch, or when the
/// nonce counter violates its encoding or replay domain. The AAD is the
/// canonical immutable header bytes; [`SignalReceiver`] has already checked
/// their digest against `encrypted_payload.aad_digest` before this is called.
pub trait SignalDecryptor: MaybeSendSync {
    fn open(
        &self,
        envelope: &SignalEnvelope,
        verified_sender: &VerifiedSignalSenderKey,
    ) -> Result<Vec<u8>>;
}

/// Decrypted, sender-bound Signal payload.
///
/// `kind` and `payload_sequence` are the §1.1 common minimum, lifted out of the
/// [`payload`] so the dedupe triple and the product route can be read without
/// matching the union. `payload` is the typed profile the SDK selected by
/// `kind`; projections must match that union rather than reparsing raw JSON.
#[derive(Clone, Debug, PartialEq)]
pub struct SignalPlaintext {
    pub kind: String,
    pub actor_id: ActorId,
    pub payload_sequence: u64,
    pub ttl_ms: Option<u64>,
    /// The registered closed profile this plaintext parsed as.
    ///
    /// This is the only admitted parse: `signal.md` §1.1 requires a receiver to
    /// select the corresponding closed schema by `kind` and drop anything else
    /// as `schema_violation`, and forbids hand-parsing a plaintext by field
    /// name. Consumers match this union to access profile fields.
    pub payload: arkret_models_collaboration::signal_plaintext::SignalPlaintext,
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
    fn parse(
        envelope: &SignalEnvelope,
        sender_actor_id: &ActorId,
        plaintext: &[u8],
    ) -> Result<Self> {
        // One entry for the whole family: dispatch on `kind`, validate against
        // the selected closed profile, reject an unregistered `kind`. Nothing
        // below reconstructs the common minimum by field name.
        let payload =
            open_signal_plaintext(plaintext).map_err(|error| Error::Protocol(error.to_string()))?;
        // §1.1 cross-boundary rules: an in-ciphertext `actor_id` MUST equal the
        // authenticated `sender_actor_id` (the outer proof authenticates only
        // that, so a plaintext naming a third party is an unauthenticated
        // claim), and a plaintext `ttl_ms` may only tighten the envelope.
        payload
            .bind_to_envelope(sender_actor_id, envelope.sent_at, envelope.expires_at)
            .map_err(|error| Error::Protocol(error.to_string()))?;
        Ok(Self {
            kind: payload.kind().as_str().to_owned(),
            actor_id: sender_actor_id.clone(),
            payload_sequence: payload.payload_sequence(),
            ttl_ms: payload.ttl_ms(),
            expires_at: payload.effective_expires_at(envelope.sent_at, envelope.expires_at),
            payload,
            sent_at: envelope.sent_at,
            scope_ref: envelope.scope_ref.clone(),
            seal_ref: envelope.seal_ref.clone(),
            sender_device_id: envelope.sender_device_id.clone(),
        })
    }

    /// The decrypted `ak.receipt.read` profile, if this is one.
    pub fn read_receipt(&self) -> Option<&crate::protocol::ReadReceipt> {
        match &self.payload {
            arkret_models_collaboration::signal_plaintext::SignalPlaintext::ReadReceipt(
                receipt,
            ) => Some(receipt),
            _ => None,
        }
    }

    /// The decrypted `ak.presence` profile, if this is one.
    pub fn presence(&self) -> Option<&crate::protocol::PresencePlaintext> {
        match &self.payload {
            arkret_models_collaboration::signal_plaintext::SignalPlaintext::Presence(presence) => {
                Some(presence)
            }
            _ => None,
        }
    }

    /// The decrypted `ak.typing` profile, if this is one.
    pub fn typing(&self) -> Option<&crate::protocol::TypingPlaintext> {
        match &self.payload {
            arkret_models_collaboration::signal_plaintext::SignalPlaintext::Typing(typing) => {
                Some(typing)
            }
            _ => None,
        }
    }
}

/// Receiver-side admission for encrypted Signals.
///
/// Order matters: the envelope is fully checked before any key material is
/// touched, and decrypted only after the sending device's proof verifies, so
/// an unauthenticated envelope can never reach the AEAD.
#[derive(Debug)]
pub struct SignalReceiver {
    seen_envelope_digests: BoundedSeenWindow<String>,
    sequence_high_waters: BTreeMap<(ActorId, String, String), ActiveSignalHighWater>,
    capacity: usize,
}

#[derive(Debug)]
struct ActiveSignalHighWater {
    high_water: SignalSequenceHighWater,
    retain_until: DateTime<Utc>,
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
        let capacity = capacity.max(1);
        Self {
            seen_envelope_digests: BoundedSeenWindow::new(capacity),
            sequence_high_waters: BTreeMap::new(),
            capacity,
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
    /// the exact-authority device evidence lookup; the device proof
    /// signature; exact-envelope replay suppression; the AEAD open; the closed
    /// plaintext shape; and finally the strictly-increasing,
    /// non-contiguous `(sender_device_id, scope_ref)` sequence high-water rule
    /// of `signal.md` §2.
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
        let verified_key = resolver.resolve_sender_key(envelope).ok_or_else(|| {
            Error::Protocol("signal sender device lacks exact-authority verified state".to_owned())
        })?;
        verified_key.validate_for(envelope)?;
        verify_ed25519_signal_proof(envelope, &verified_key.public_key)
            .map_err(|error| Error::Crypto(error.to_string()))?;
        let envelope_digest = envelope.proof.envelope_digest.as_str();
        if self.seen_envelope_digests.contains(envelope_digest) {
            return Err(Error::Protocol(
                "signal_exact_envelope_replay: envelope_digest was already delivered".to_owned(),
            ));
        }
        let plaintext = decryptor.open(envelope, &verified_key)?;
        let parsed = SignalPlaintext::parse(envelope, &envelope.sender_actor_id, &plaintext)?;
        let domain = (
            envelope.sender_actor_id.clone(),
            envelope.sender_device_id.as_str().to_owned(),
            scope_key(&envelope.scope_ref)?,
        );
        self.sequence_high_waters
            .retain(|_, active| active.retain_until > now);
        if !self.sequence_high_waters.contains_key(&domain) {
            if self.sequence_high_waters.len() >= self.capacity {
                return Err(Error::Protocol(
                    "signal_sequence_domain_capacity_exceeded: all tracked domains are still active"
                        .to_owned(),
                ));
            }
            self.sequence_high_waters.insert(
                domain.clone(),
                ActiveSignalHighWater {
                    high_water: SignalSequenceHighWater::default(),
                    retain_until: envelope.expires_at,
                },
            );
        }
        let active = self
            .sequence_high_waters
            .get_mut(&domain)
            .expect("signal sequence domain was inserted above");
        let decision = active
            .high_water
            .observe(SignalSequence::new(parsed.payload_sequence));
        if let SignalSequenceDecision::Stale {
            high_water,
            candidate,
        } = decision
        {
            return Err(Error::Protocol(format!(
                "signal_payload_sequence_stale: candidate {} did not advance high-water {}",
                candidate.get(),
                high_water.get()
            )));
        }
        active.retain_until = active.retain_until.max(envelope.expires_at);
        self.seen_envelope_digests
            .remember(envelope_digest.to_owned());
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
    devices: BTreeMap<ActorId, BTreeMap<String, PresenceObservation>>,
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
        let presence = plaintext.presence().ok_or_else(|| {
            Error::Protocol("presence projection received a non-presence payload".to_owned())
        })?;
        let state = match presence.state {
            arkret_models_collaboration::signal_plaintext::PresenceState::Online => {
                PresenceStatus::Online
            }
            arkret_models_collaboration::signal_plaintext::PresenceState::Idle => {
                PresenceStatus::Idle
            }
            arkret_models_collaboration::signal_plaintext::PresenceState::Offline => {
                PresenceStatus::Offline
            }
            arkret_models_collaboration::signal_plaintext::PresenceState::Dnd => {
                PresenceStatus::Dnd
            }
        };
        let status_message = presence.status_message.clone();
        if let Some(text) = status_message.as_deref() {
            validate_status_message(text).map_err(|error| Error::Protocol(error.to_string()))?;
        }
        let last_active_at = presence.last_active_at.clone();
        if let Some(text) = last_active_at.as_deref() {
            validate_last_active_at(text).map_err(|error| Error::Protocol(error.to_string()))?;
        }
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
    pub fn observations(
        &self,
        actor_id: &ActorId,
        now: DateTime<Utc>,
    ) -> Vec<&PresenceObservation> {
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
    pub fn aggregated(&self, actor_id: &ActorId, now: DateTime<Utc>) -> PresenceStatus {
        aggregate_presence_states(
            self.observations(actor_id, now)
                .into_iter()
                .map(|observation| observation.state),
        )
    }

    /// Most recently sent non-empty `status_message` among unexpired signals.
    pub fn status_message(&self, actor_id: &ActorId, now: DateTime<Utc>) -> Option<&str> {
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
    pub fn last_active_at(&self, actor_id: &ActorId, now: DateTime<Utc>) -> Option<&str> {
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
    use chrono::Duration;

    use arkret_wire::{DeviceId, DidCoreId, DidUrl, EventId, Hash, RealmId, SealId};
    use chrono::TimeZone;
    use ed25519_dalek::SigningKey;
    use serde_json::json;

    use super::*;
    use crate::protocol::signal::{SignalClass, SignalEncryptedPayload, SignalKeyRef, SignalProof};
    use crate::protocol::signatures::sign_ed25519_detached_jws;

    fn realm() -> RealmId {
        RealmId::new("ak:realm:AUhJ30wlw7UA5CWJk9HZUsDp0GyhA-QVSF565JjdtLul").unwrap()
    }

    fn actor() -> DidCoreId {
        DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap()
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
        let verification_method =
            DidUrl::new(format!("did:webvh:z6mkfixture:alice.example#{device_id}")).unwrap();
        let mut envelope = SignalEnvelope {
            realm_id: realm(),
            scope_ref: ScopeRef::Realm { realm_id: realm() },
            sender_actor_id: account_actor(),
            sender_device_id: device_id,
            seal_ref: SealId::new(format!("ak:seal:sha256:{}", "a".repeat(64))).unwrap(),
            signal_class,
            sent_at: sent_at(),
            expires_at: sent_at() + Duration::seconds(ttl_seconds),
            encrypted_payload: SignalEncryptedPayload {
                scheme: crate::protocol::signal::SIGNAL_AEAD_SCHEME.to_owned(),
                key_ref: SignalKeyRef {
                    algorithm: "MLS-EXPORTER-AEAD".to_owned(),
                    group_state_ref: EventId::from_digest(
                        arkret_canonical::DigestSuite::Sha256,
                        [0xcc; 32],
                    )
                    .to_string(),
                },
                purpose: crate::protocol::signal::SIGNAL_AEAD_PURPOSE.to_owned(),
                aead_profile: "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519".to_owned(),
                epoch: 7,
                nonce: arkret_canonical::base64url_encode(&seed[..12]),
                ciphertext: arkret_canonical::base64url_encode(&seed[..16]),
                aad_digest: Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
            },
            proof: SignalProof {
                kind: "detached_jws".to_owned(),
                verification_method,
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
        envelope.proof.jws = sign_ed25519_detached_jws(&signing_key, &binding).unwrap();
        let public_key = PublicKeyMaterial::Ed25519Raw {
            bytes: signing_key.verifying_key().to_bytes().to_vec(),
        };
        (envelope, public_key, plaintext_bytes)
    }

    struct FixedDecryptor(Vec<u8>);

    impl SignalDecryptor for FixedDecryptor {
        fn open(
            &self,
            _envelope: &SignalEnvelope,
            _sender: &VerifiedSignalSenderKey,
        ) -> Result<Vec<u8>> {
            Ok(self.0.clone())
        }
    }

    struct RefusingDecryptor;

    impl SignalDecryptor for RefusingDecryptor {
        fn open(
            &self,
            _envelope: &SignalEnvelope,
            _sender: &VerifiedSignalSenderKey,
        ) -> Result<Vec<u8>> {
            Err(Error::Protocol(
                "aead_profile is not the group suite".to_owned(),
            ))
        }
    }

    fn presence_plaintext(state: &str, sequence: u64) -> Value {
        json!({
            "kind": SIGNAL_PLAINTEXT_KIND_PRESENCE,
            "actor_id": account_actor(),
            "state": state,
            "payload_sequence": sequence,
            "ttl_ms": 30_000
        })
    }

    fn account_actor() -> ActorId {
        ActorId::account(AccountId::new(
            actor(),
            DidCoreId::new("ak:did_core:web:principal.example").unwrap(),
        ))
    }

    fn key_of(public_key: PublicKeyMaterial) -> impl SignalSenderKeyResolver {
        move |envelope: &SignalEnvelope| {
            Some(VerifiedSignalSenderKey::for_test(
                envelope,
                public_key.clone(),
            ))
        }
    }

    fn directory_evidence_parts() -> (PublicKeyMaterial, ActorId, DeviceId, DidUrl, AccountId) {
        let device_id = device("000000000005");
        let public_key = PublicKeyMaterial::Ed25519Raw {
            bytes: SigningKey::from_bytes(&[41; 32])
                .verifying_key()
                .to_bytes()
                .to_vec(),
        };
        let verification_method =
            DidUrl::new(format!("did:webvh:z6mkfixture:alice.example#{device_id}")).unwrap();
        let authority = AccountId::new(
            actor(),
            DidCoreId::new("ak:did_core:web:principal.example").unwrap(),
        );
        (
            public_key,
            account_actor(),
            device_id,
            verification_method,
            authority,
        )
    }

    fn authorize_event() -> EventId {
        EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [0x42; 32])
    }

    #[test]
    fn from_directory_evidence_admits_a_consistent_tuple() {
        let (public_key, actor_id, device_id, verification_method, authority) =
            directory_evidence_parts();
        let key = VerifiedSignalSenderKey::from_directory_evidence(
            public_key,
            actor_id,
            device_id,
            verification_method,
            authority,
            authorize_event(),
        )
        .unwrap();
        assert_eq!(key.actor_id, account_actor());
        assert_eq!(key.device_id, device("000000000005"));
    }

    #[test]
    fn from_directory_evidence_rejects_an_authority_pair_naming_another_principal() {
        let (public_key, actor_id, device_id, verification_method, _) = directory_evidence_parts();
        let foreign_authority = AccountId::new(
            DidCoreId::new("ak:did_core:webvh:z6mkother").unwrap(),
            DidCoreId::new("ak:did_core:web:principal.example").unwrap(),
        );
        let error = VerifiedSignalSenderKey::from_directory_evidence(
            public_key,
            actor_id,
            device_id,
            verification_method,
            foreign_authority,
            authorize_event(),
        )
        .unwrap_err();
        assert!(
            format!("{error}").contains("authority account_id"),
            "{error}"
        );
    }

    #[test]
    fn from_directory_evidence_rejects_the_same_principal_at_another_station() {
        let (public_key, actor_id, device_id, verification_method, mut authority) =
            directory_evidence_parts();
        authority.station_id = DidCoreId::new("ak:did_core:web:other-station.example").unwrap();
        assert!(
            VerifiedSignalSenderKey::from_directory_evidence(
                public_key,
                actor_id,
                device_id,
                verification_method,
                authority,
                authorize_event(),
            )
            .is_err()
        );
    }

    #[test]
    fn from_directory_evidence_rejects_a_fragment_naming_another_device() {
        let (public_key, actor_id, _, verification_method, authority) = directory_evidence_parts();
        let error = VerifiedSignalSenderKey::from_directory_evidence(
            public_key,
            actor_id,
            device("000000000006"),
            verification_method,
            authority,
            authorize_event(),
        )
        .unwrap_err();
        assert!(
            format!("{error}").contains("controller or fragment"),
            "{error}"
        );
    }

    #[test]
    fn from_directory_evidence_rejects_a_controller_projecting_to_another_actor() {
        let (public_key, actor_id, device_id, _, authority) = directory_evidence_parts();
        let foreign_method =
            DidUrl::new(format!("did:webvh:z6mkother:mallory.example#{device_id}")).unwrap();
        let error = VerifiedSignalSenderKey::from_directory_evidence(
            public_key,
            actor_id,
            device_id,
            foreign_method,
            authority,
            authorize_event(),
        )
        .unwrap_err();
        assert!(
            format!("{error}").contains("controller or fragment"),
            "{error}"
        );
    }

    #[test]
    fn from_directory_evidence_rejects_malformed_key_material() {
        let (_, actor_id, device_id, verification_method, authority) = directory_evidence_parts();
        let truncated = PublicKeyMaterial::Ed25519Raw {
            bytes: vec![0u8; 16],
        };
        assert!(
            VerifiedSignalSenderKey::from_directory_evidence(
                truncated,
                actor_id,
                device_id,
                verification_method,
                authority,
                authorize_event(),
            )
            .is_err()
        );
    }

    #[test]
    fn receiver_accepts_a_directory_evidence_key_end_to_end() {
        let (envelope, public_key, plaintext) = signed_signal(
            device("000000000005"),
            presence_plaintext("online", 1),
            SignalClass::Session,
            30,
            [42; 32],
        );
        let resolver = move |envelope: &SignalEnvelope| {
            let authority = envelope.sender_actor_id.as_account_id().unwrap().clone();
            VerifiedSignalSenderKey::from_directory_evidence(
                public_key.clone(),
                envelope.sender_actor_id.clone(),
                envelope.sender_device_id.clone(),
                envelope.proof.verification_method.clone(),
                authority,
                authorize_event(),
            )
            .ok()
        };
        let accepted = SignalReceiver::new()
            .accept(&envelope, &resolver, &FixedDecryptor(plaintext), sent_at())
            .unwrap();
        assert_eq!(accepted.kind, SIGNAL_PLAINTEXT_KIND_PRESENCE);
    }

    #[test]
    fn unavailable_or_revoked_current_authority_does_not_advance_receive_state() {
        let (envelope, public_key, plaintext) = signed_signal(
            device("000000000005"),
            presence_plaintext("online", 99),
            SignalClass::Session,
            30,
            [42; 32],
        );
        let mut receiver = SignalReceiver::new();
        // The old member may still possess its MLS leaf and epoch secret.
        // Revocation is decided independently, before invoking the opener.
        let revoked = |_envelope: &SignalEnvelope| None;
        assert!(
            receiver
                .accept(&envelope, &revoked, &RefusingDecryptor, sent_at())
                .is_err()
        );
        assert!(receiver.sequence_high_waters.is_empty());
        assert!(
            !receiver
                .seen_envelope_digests
                .contains(envelope.proof.envelope_digest.as_str())
        );
        assert!(
            receiver
                .accept(
                    &envelope,
                    &key_of(public_key),
                    &FixedDecryptor(plaintext),
                    sent_at()
                )
                .is_ok()
        );
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
            projection.aggregated(&account_actor(), sent_at()),
            PresenceStatus::Online
        );
    }

    #[test]
    fn receiver_accepts_a_profile_without_plaintext_actor_or_ttl() {
        let plaintext_value = json!({
            "kind": "ak.message.stream",
            "payload_sequence": 2,
            "strand_id": arkret_wire::StrandId::from_event_id(&EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                [6; 32],
            )),
            "track_name": "discussion",
            "message_id": arkret_wire::MessageId::from_event_id(&EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                [7; 32],
            )),
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

        assert_eq!(accepted.actor_id, account_actor());
        assert_eq!(accepted.ttl_ms, None);
        assert_eq!(accepted.expires_at, envelope.expires_at);
    }

    #[test]
    fn receiver_rejects_a_signal_without_verified_sender_authority_evidence() {
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

        assert!(format!("{error}").contains("exact-authority verified state"));
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

        assert!(format!("{error}").contains("signal_exact_envelope_replay"));
    }

    #[test]
    fn receiver_sequences_are_isolated_between_same_principal_station_accounts() {
        let seed = [19; 32];
        let (first, public_key, first_plaintext) = signed_signal(
            device("000000000005"),
            presence_plaintext("online", 1),
            SignalClass::Session,
            30,
            seed,
        );
        let mut second = first.clone();
        let mut account_id = second.sender_actor_id.as_account_id().unwrap().clone();
        account_id.station_id = DidCoreId::new("ak:did_core:web:other-station.example").unwrap();
        second.sender_actor_id = ActorId::account(account_id);
        second.encrypted_payload.aad_digest = second.expected_aad_digest().unwrap();
        second.proof.envelope_digest = second.envelope_digest().unwrap();
        second.proof.jws = sign_ed25519_detached_jws(
            &SigningKey::from_bytes(&seed),
            &second.proof_binding_bytes().unwrap(),
        )
        .unwrap();
        let mut second_plaintext = presence_plaintext("online", 1);
        second_plaintext["actor_id"] = serde_json::to_value(&second.sender_actor_id).unwrap();
        let second_plaintext = canonical::canonical_json_bytes(&second_plaintext).unwrap();
        let resolver = key_of(public_key);
        let mut receiver = SignalReceiver::new();
        receiver
            .accept(
                &first,
                &resolver,
                &FixedDecryptor(first_plaintext),
                sent_at(),
            )
            .unwrap();
        receiver
            .accept(
                &second,
                &resolver,
                &FixedDecryptor(second_plaintext),
                sent_at(),
            )
            .unwrap();
        assert_eq!(receiver.sequence_high_waters.len(), 2);
    }

    #[test]
    fn receiver_accepts_forward_gaps_and_rejects_stale_new_emissions() {
        let mut receiver = SignalReceiver::new();
        for (sequence, state, seed) in [(7, "online", [31u8; 32]), (1024, "idle", [32u8; 32])] {
            let (envelope, public_key, plaintext) = signed_signal(
                device("000000000005"),
                presence_plaintext(state, sequence),
                SignalClass::Session,
                30,
                seed,
            );
            let accepted = receiver
                .accept(
                    &envelope,
                    &key_of(public_key),
                    &FixedDecryptor(plaintext),
                    sent_at(),
                )
                .unwrap();
            assert_eq!(accepted.payload_sequence, sequence);
        }

        // A distinct, correctly signed envelope below the high-water is stale,
        // not an exact transport replay.  The large accepted gap is normal.
        let (stale, public_key, plaintext) = signed_signal(
            device("000000000005"),
            presence_plaintext("dnd", 8),
            SignalClass::Session,
            30,
            [33u8; 32],
        );
        let error = receiver
            .accept(
                &stale,
                &key_of(public_key),
                &FixedDecryptor(plaintext),
                sent_at(),
            )
            .unwrap_err();
        assert!(
            format!("{error}").contains("signal_payload_sequence_stale"),
            "{error}"
        );
    }

    #[test]
    fn receiver_refuses_a_plaintext_that_claims_another_actor() {
        let mut foreign = presence_plaintext("online", 1);
        foreign["actor_id"] = json!(ActorId::account(AccountId::new(
            DidCoreId::new("ak:did_core:webvh:z6mkfixture:mallory.example").unwrap(),
            DidCoreId::new("ak:did_core:web:principal.example").unwrap(),
        )));
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

        assert!(format!("{error}").contains("must equal the envelope sender_actor_id"));
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

        assert_eq!(
            projection.observations(&account_actor(), sent_at()).len(),
            2
        );
        assert_eq!(
            projection.aggregated(&account_actor(), sent_at()),
            PresenceStatus::Dnd
        );
        assert_eq!(projection.expire(sent_at() + Duration::seconds(30)), 2);
        assert_eq!(
            projection.aggregated(&account_actor(), sent_at() + Duration::seconds(30)),
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
            projection.aggregated(&account_actor(), sent_at()),
            PresenceStatus::Online
        );

        // `unavailable` is a pre-v1 leftover, not a v1 wire value: it is
        // dropped, never mapped onto a nearby state. It now fails at admission
        // rather than at projection — `signal.md` §1.1 makes the closed profile
        // schema the admission gate, so a payload carrying an unregistered
        // enum value never reaches a product projection at all.
        let (unknown_envelope, unknown_key, unknown_plaintext) = signed_signal(
            device_id,
            presence_plaintext("unavailable", 5),
            SignalClass::Session,
            30,
            [25; 32],
        );
        let error = SignalReceiver::new()
            .accept(
                &unknown_envelope,
                &key_of(unknown_key),
                &FixedDecryptor(unknown_plaintext),
                sent_at(),
            )
            .unwrap_err();
        assert!(format!("{error}").contains("schema_violation"), "{error}");
    }
}
