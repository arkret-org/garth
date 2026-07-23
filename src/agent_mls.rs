//! Runtime-neutral Native Agent MLS lifecycle orchestration.
//!
//! The protocol DTOs and cryptographic primitives remain owned by the Arkret
//! SDK. This module owns only the durable ordering required of an Agent
//! runtime: persist private KeyPackage material before upload, atomically
//! persist joined group state with the exact signed consume intent, replay
//! intents after restart, and quiesce the old endpoint before authorization
//! replacement.

use std::collections::{BTreeMap, BTreeSet};

use arkret_canonical::{base64url_decode, canonical_json_bytes};
use arkret_mls::{ArkretMlsGroup, ArkretMlsIdentity};
use arkret_models_collaboration::events_payloads::list_message_mimi_mls::{
    MlsClaimTrustBinding, MlsWelcomePayload,
};
use arkret_models_crypto::{
    EncryptedPayload, KeyPackagesConsumeRequestBody, KeyPackagesConsumeUnsignedRequest,
    KeyPackagesRevokeOutcome, KeyPackagesRevokeRequestBody, KeyPackagesRevokeUnsignedRequest,
    KeyPackagesUploadRequestBody, MlsCommitEnvelope, MlsGroupStateRecord, MlsKeyPackageRecord,
    MlsWelcomeEnvelope,
};
use arkret_wire::{DeviceId, DeviceMessageId, Did, EventId, Hash};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{Error, PutSecretOptions, Result, SecretClass, SecretDurability, SecureKeyStore};

const SNAPSHOT_CONTEXT: &str = "arkret-agent-mls-runtime-v1";

fn protocol_error(message: impl Into<String>) -> Error {
    Error::Protocol(message.into())
}

fn map_protocol_error(context: &str, error: impl std::fmt::Display) -> Error {
    protocol_error(format!("{context}: {error}"))
}

/// Current accepted `ak.agent.key.authorize` binding for one runtime endpoint.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentMlsAuthorizationBinding {
    pub principal_id: Did,
    pub device_id: DeviceId,
    pub authorization_event_id: EventId,
    pub verification_method: String,
    pub signing_public_key: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

impl AgentMlsAuthorizationBinding {
    pub fn validate_at(&self, now: DateTime<Utc>) -> Result<()> {
        if self.verification_method.trim().is_empty() {
            return Err(protocol_error(
                "Agent MLS authorization verification_method is required",
            ));
        }
        if self.signing_public_key.len() != 32 {
            return Err(protocol_error(
                "Agent MLS authorization Ed25519 public key must be 32 bytes",
            ));
        }
        if self.expires_at.is_some_and(|expires_at| expires_at <= now) {
            return Err(protocol_error("Agent MLS authorization is expired"));
        }
        Ok(())
    }
}

/// Durable runtime phase. Every mutating MLS operation requires `Active`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentMlsRuntimePhase {
    Active,
    Quiescing,
    ReadyForReplacement,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoredKeyPackage {
    record: MlsKeyPackageRecord,
    upload_accepted: bool,
}

/// Exact consume attempt persisted in the same aggregate as the joined group.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentMlsConsumeIntent {
    pub message_id: DeviceMessageId,
    pub principal_id: Did,
    pub device_id: DeviceId,
    pub authorization_event_id: EventId,
    pub claim_id: String,
    pub keypackage_ref: String,
    pub keypackage_id: String,
    pub request: KeyPackagesConsumeRequestBody,
}

/// Fully typed input obtained from one standard device-message Welcome.
#[derive(Clone, Debug)]
pub struct AgentMlsWelcomeInput {
    pub message_id: DeviceMessageId,
    pub key_package_id: String,
    pub payload: MlsWelcomePayload,
    pub claimed_capabilities: Vec<String>,
}

/// Host-supplied verification against current requester authorization and the
/// accepted governance/Seal view. The runtime invokes both gates before any
/// joined state is persisted.
pub trait AgentMlsWelcomeVerifier {
    fn verify_claim_envelope(&self, payload: &MlsWelcomePayload) -> Result<()>;

    fn verify_governance_binding(
        &self,
        payload: &MlsWelcomePayload,
        group: &ArkretMlsGroup,
    ) -> Result<()>;
}

#[derive(Clone, Debug)]
pub enum AgentMlsWelcomeOutcome {
    ConsumeRequired(KeyPackagesConsumeRequestBody),
    AlreadyPending(KeyPackagesConsumeRequestBody),
    AlreadyConsumed,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct AgentMlsRuntimeSnapshot {
    context: String,
    binding: AgentMlsAuthorizationBinding,
    phase: AgentMlsRuntimePhase,
    identity_private_state: Vec<u8>,
    key_packages: BTreeMap<String, StoredKeyPackage>,
    groups: BTreeMap<String, MlsGroupStateRecord>,
    pending_consumes: BTreeMap<String, AgentMlsConsumeIntent>,
    consumed_claims: BTreeSet<String>,
    pending_message_acks: BTreeSet<DeviceMessageId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pending_revoke: Option<KeyPackagesRevokeRequestBody>,
}

impl AgentMlsRuntimeSnapshot {
    fn validate(&self) -> Result<()> {
        if self.context != SNAPSHOT_CONTEXT {
            return Err(protocol_error("unsupported Agent MLS runtime snapshot"));
        }
        if self.identity_private_state.is_empty() {
            return Err(protocol_error(
                "Agent MLS runtime snapshot has no identity private state",
            ));
        }
        for (keypackage_ref, stored) in &self.key_packages {
            if keypackage_ref != stored.record.keypackage_ref.as_str()
                || stored.record.principal_id != self.binding.principal_id
                || stored.record.device_id != self.binding.device_id
            {
                return Err(protocol_error(
                    "Agent MLS runtime KeyPackage binding mismatch",
                ));
            }
        }
        if self.groups.values().any(|group| {
            group.principal_id != self.binding.principal_id
                || group.device_id != self.binding.device_id
        }) {
            return Err(protocol_error("Agent MLS runtime group binding mismatch"));
        }
        for (claim_id, intent) in &self.pending_consumes {
            let key_package_matches = self
                .key_packages
                .get(&intent.keypackage_ref)
                .is_some_and(|stored| stored.record.keypackage_id == intent.keypackage_id);
            if claim_id != &intent.claim_id
                || intent.principal_id != self.binding.principal_id
                || intent.device_id != self.binding.device_id
                || intent.authorization_event_id != self.binding.authorization_event_id
                || intent.request.consumer_device_id != self.binding.device_id
                || intent.request.claim_ids != [claim_id.clone()]
                || intent.request.key_package_refs != [intent.keypackage_id.clone()]
                || !key_package_matches
                || self.consumed_claims.contains(claim_id)
            {
                return Err(protocol_error(
                    "Agent MLS runtime consume intent binding mismatch",
                ));
            }
        }
        if self.phase == AgentMlsRuntimePhase::Active && self.pending_revoke.is_some() {
            return Err(protocol_error(
                "active Agent MLS runtime cannot retain a replacement revoke",
            ));
        }
        Ok(())
    }
}

/// Durable Native Agent MLS state machine backed by one atomic secret value.
pub struct AgentMlsRuntime<S> {
    secure_store: S,
    storage_key: String,
    snapshot: AgentMlsRuntimeSnapshot,
}

impl<S> AgentMlsRuntime<S>
where
    S: SecureKeyStore,
{
    /// Create a new endpoint and durably store its identity/private
    /// KeyPackages before returning any upload request to the caller.
    pub async fn initialize(
        secure_store: S,
        storage_key: impl Into<String>,
        binding: AgentMlsAuthorizationBinding,
        signing_seed: [u8; 32],
        key_package_low_watermark: usize,
        now: DateTime<Utc>,
    ) -> Result<Self> {
        binding.validate_at(now)?;
        let storage_key = storage_key.into();
        if storage_key.trim().is_empty() {
            return Err(protocol_error("Agent MLS runtime storage key is required"));
        }
        if secure_store.get_secret_bytes(&storage_key)?.is_some() {
            return Err(protocol_error("Agent MLS runtime state already exists"));
        }
        let identity = ArkretMlsIdentity::from_ed25519_signing_seed(
            binding.principal_id.clone(),
            binding.device_id.clone(),
            signing_seed,
        )
        .map_err(|error| map_protocol_error("create Agent MLS identity", error))?;
        ensure_identity_matches_binding(&identity, &binding)?;
        let mut key_packages = BTreeMap::new();
        for _ in 0..key_package_low_watermark {
            let record = identity
                .key_package_record()
                .map_err(|error| map_protocol_error("create Agent MLS KeyPackage", error))?;
            key_packages.insert(
                record.keypackage_ref.as_str().to_owned(),
                StoredKeyPackage {
                    record,
                    upload_accepted: false,
                },
            );
        }
        let snapshot = AgentMlsRuntimeSnapshot {
            context: SNAPSHOT_CONTEXT.to_owned(),
            binding,
            phase: AgentMlsRuntimePhase::Active,
            identity_private_state: identity
                .export_private_state()
                .map_err(|error| map_protocol_error("export Agent MLS identity", error))?,
            key_packages,
            groups: BTreeMap::new(),
            pending_consumes: BTreeMap::new(),
            consumed_claims: BTreeSet::new(),
            pending_message_acks: BTreeSet::new(),
            pending_revoke: None,
        };
        persist_snapshot(&secure_store, &storage_key, &snapshot).await?;
        Ok(Self {
            secure_store,
            storage_key,
            snapshot,
        })
    }

    /// Restore the exact aggregate after restart and reject a stale, replaced,
    /// revoked, expired, or differently bound current authorization.
    pub fn restore(
        secure_store: S,
        storage_key: impl Into<String>,
        current_binding: &AgentMlsAuthorizationBinding,
        now: DateTime<Utc>,
    ) -> Result<Self> {
        current_binding.validate_at(now)?;
        let storage_key = storage_key.into();
        let encoded = secure_store
            .get_secret_bytes(&storage_key)?
            .ok_or_else(|| protocol_error("Agent MLS runtime state is missing"))?;
        let snapshot: AgentMlsRuntimeSnapshot = serde_json::from_slice(&encoded)
            .map_err(|error| map_protocol_error("decode Agent MLS runtime state", error))?;
        snapshot.validate()?;
        if &snapshot.binding != current_binding {
            return Err(protocol_error(
                "Agent MLS runtime authorization binding is no longer current",
            ));
        }
        let identity = restore_identity(&snapshot)?;
        ensure_identity_matches_binding(&identity, current_binding)?;
        Ok(Self {
            secure_store,
            storage_key,
            snapshot,
        })
    }

    pub fn phase(&self) -> AgentMlsRuntimePhase {
        self.snapshot.phase
    }

    pub fn binding(&self) -> &AgentMlsAuthorizationBinding {
        &self.snapshot.binding
    }

    pub fn pending_consume_intents(&self) -> Vec<&AgentMlsConsumeIntent> {
        self.snapshot.pending_consumes.values().collect()
    }

    pub fn pending_message_acks(&self) -> Vec<&DeviceMessageId> {
        self.snapshot.pending_message_acks.iter().collect()
    }

    pub fn group_state(&self, group_id: &str) -> Option<&MlsGroupStateRecord> {
        self.snapshot.groups.get(group_id)
    }

    /// Return the public KeyPackage record retained for an upload. Private
    /// init-key material remains confined to the encrypted runtime snapshot.
    pub fn key_package_record(&self, keypackage_ref: &str) -> Option<&MlsKeyPackageRecord> {
        self.snapshot
            .key_packages
            .get(keypackage_ref)
            .map(|stored| &stored.record)
    }

    /// Return the exact signed upload attempt for every locally durable package
    /// that has not yet received an accepted server outcome.
    pub fn pending_upload_request(
        &self,
        current_binding: &AgentMlsAuthorizationBinding,
        now: DateTime<Utc>,
    ) -> Result<Option<KeyPackagesUploadRequestBody>> {
        self.require_active(current_binding, now)?;
        let records = self
            .snapshot
            .key_packages
            .values()
            .filter(|stored| {
                !stored.upload_accepted
                    && stored.record.state == arkret_models_crypto::MlsKeyPackageState::Published
                    && stored
                        .record
                        .expires_at
                        .is_none_or(|expires_at| expires_at > now)
            })
            .map(|stored| stored.record.clone())
            .collect::<Vec<_>>();
        if records.is_empty() {
            return Ok(None);
        }
        let identity = restore_identity(&self.snapshot)?;
        identity
            .signed_key_packages_upload_request(
                &records,
                &self.snapshot.binding.verification_method,
            )
            .map(Some)
            .map_err(|error| map_protocol_error("sign Agent MLS KeyPackage upload", error))
    }

    /// Refill the pool transactionally. The newly generated private material
    /// is durably committed before the signed upload request can be observed.
    pub async fn ensure_key_package_pool(
        &mut self,
        current_binding: &AgentMlsAuthorizationBinding,
        key_package_low_watermark: usize,
        now: DateTime<Utc>,
    ) -> Result<Option<KeyPackagesUploadRequestBody>> {
        self.require_active(current_binding, now)?;
        let usable = self
            .snapshot
            .key_packages
            .values()
            .filter(|stored| {
                stored
                    .record
                    .expires_at
                    .is_none_or(|expires_at| expires_at > now)
                    && stored.record.state == arkret_models_crypto::MlsKeyPackageState::Published
            })
            .count();
        if usable < key_package_low_watermark {
            let identity = restore_identity(&self.snapshot)?;
            let mut next = self.snapshot.clone();
            for _ in usable..key_package_low_watermark {
                let record = identity
                    .key_package_record()
                    .map_err(|error| map_protocol_error("refill Agent MLS KeyPackage", error))?;
                next.key_packages.insert(
                    record.keypackage_ref.as_str().to_owned(),
                    StoredKeyPackage {
                        record,
                        upload_accepted: false,
                    },
                );
            }
            next.identity_private_state = identity
                .export_private_state()
                .map_err(|error| map_protocol_error("export refilled Agent MLS identity", error))?;
            self.commit(next).await?;
        }
        self.pending_upload_request(current_binding, now)
    }

    pub async fn mark_upload_accepted(
        &mut self,
        current_binding: &AgentMlsAuthorizationBinding,
        accepted_refs: &[String],
        now: DateTime<Utc>,
    ) -> Result<()> {
        self.require_active(current_binding, now)?;
        if accepted_refs.is_empty() {
            return Err(protocol_error(
                "Agent MLS upload outcome accepted no KeyPackage refs",
            ));
        }
        let mut next = self.snapshot.clone();
        for keypackage_ref in accepted_refs {
            let stored = next.key_packages.get_mut(keypackage_ref).ok_or_else(|| {
                protocol_error("Agent MLS upload outcome references an unknown KeyPackage")
            })?;
            stored.upload_accepted = true;
        }
        self.commit(next).await
    }

    /// Validate and join a durable Welcome. Group state and the byte-identical
    /// signed consume attempt are committed by one durable write before the
    /// request is returned to the transport.
    pub async fn process_welcome<V>(
        &mut self,
        current_binding: &AgentMlsAuthorizationBinding,
        input: AgentMlsWelcomeInput,
        verifier: &V,
        now: DateTime<Utc>,
    ) -> Result<AgentMlsWelcomeOutcome>
    where
        V: AgentMlsWelcomeVerifier,
    {
        self.require_active(current_binding, now)?;
        let claim_id = input.payload.claim_id.as_str().to_owned();
        validate_welcome_input(&self.snapshot, &input, now)?;
        verifier.verify_claim_envelope(&input.payload)?;
        if self.snapshot.consumed_claims.contains(&claim_id) {
            return Ok(AgentMlsWelcomeOutcome::AlreadyConsumed);
        }
        if let Some(intent) = self.snapshot.pending_consumes.get(&claim_id) {
            let envelope = welcome_envelope(&input.payload)?;
            if intent.message_id != input.message_id
                || intent.keypackage_ref != input.payload.keypackage_ref.as_str()
                || intent.keypackage_id != input.key_package_id
                || intent.request.welcome_ref.as_deref() != Some(envelope.welcome_hash.as_str())
            {
                return Err(protocol_error(
                    "conflicting Agent MLS Welcome replay for pending claim",
                ));
            }
            return Ok(AgentMlsWelcomeOutcome::AlreadyPending(
                intent.request.clone(),
            ));
        }

        let identity = restore_identity(&self.snapshot)?;
        let envelope = welcome_envelope(&input.payload)?;
        let group = ArkretMlsGroup::join_from_welcome(identity, &envelope)
            .map_err(|error| map_protocol_error("join Agent MLS Welcome", error))?;
        verifier.verify_governance_binding(&input.payload, &group)?;
        let group_state = group
            .export_state_record()
            .map_err(|error| map_protocol_error("export joined Agent MLS group", error))?;
        let unsigned = KeyPackagesConsumeUnsignedRequest {
            key_package_refs: vec![input.key_package_id.clone()],
            consumer_device_id: self.snapshot.binding.device_id.clone(),
            claim_ids: vec![claim_id.clone()],
            welcome_ref: Some(envelope.welcome_hash.as_str().to_owned()),
            realm_id: Some(input.payload.governance_binding.realm_id().clone()),
            strand_id: input
                .payload
                .peer_claim_receipt
                .as_ref()
                .and_then(|receipt| receipt.request.strand_id.clone()),
            mls_group_id: Some(input.payload.mls_group_id.as_str().to_owned()),
            epoch: Some(input.payload.epoch),
        };
        let request = group
            .identity()
            .signed_key_packages_consume_request(
                unsigned,
                &self.snapshot.binding.verification_method,
            )
            .map_err(|error| map_protocol_error("sign Agent MLS consume intent", error))?;
        let mut next = self.snapshot.clone();
        next.identity_private_state = group
            .identity()
            .export_private_state()
            .map_err(|error| map_protocol_error("export joined Agent MLS identity", error))?;
        next.groups
            .insert(group_state.group_id.clone(), group_state);
        let keypackage_ref = input.payload.keypackage_ref.as_str().to_owned();
        let stored = next
            .key_packages
            .get_mut(&keypackage_ref)
            .ok_or_else(|| protocol_error("Welcome KeyPackage disappeared during commit"))?;
        stored.record.state = arkret_models_crypto::MlsKeyPackageState::Claimed;
        stored.record.claim_id = Some(claim_id.clone());
        next.pending_consumes.insert(
            claim_id.clone(),
            AgentMlsConsumeIntent {
                message_id: input.message_id,
                principal_id: self.snapshot.binding.principal_id.clone(),
                device_id: self.snapshot.binding.device_id.clone(),
                authorization_event_id: self.snapshot.binding.authorization_event_id.clone(),
                claim_id,
                keypackage_ref,
                keypackage_id: input.key_package_id,
                request: request.clone(),
            },
        );
        self.commit(next).await?;
        Ok(AgentMlsWelcomeOutcome::ConsumeRequired(request))
    }

    /// Persist the consume outcome and the still-pending device-message ack in
    /// one transaction. A crash after this method therefore replays the ack,
    /// never the Welcome join.
    pub async fn mark_consume_accepted(
        &mut self,
        current_binding: &AgentMlsAuthorizationBinding,
        claim_id: &str,
        consumed_refs: &[String],
        now: DateTime<Utc>,
    ) -> Result<DeviceMessageId> {
        self.require_active(current_binding, now)?;
        let intent = self
            .snapshot
            .pending_consumes
            .get(claim_id)
            .ok_or_else(|| protocol_error("Agent MLS consume intent is missing"))?;
        if !consumed_refs
            .iter()
            .any(|value| value == &intent.keypackage_id)
        {
            return Err(protocol_error(
                "Agent MLS consume outcome omitted the intended KeyPackage",
            ));
        }
        let message_id = intent.message_id.clone();
        let mut next = self.snapshot.clone();
        next.pending_consumes.remove(claim_id);
        next.consumed_claims.insert(claim_id.to_owned());
        next.pending_message_acks.insert(message_id.clone());
        if let Some(stored) = next.key_packages.get_mut(&intent.keypackage_ref) {
            stored.record.state = arkret_models_crypto::MlsKeyPackageState::Consumed;
        }
        self.commit(next).await?;
        Ok(message_id)
    }

    pub async fn mark_message_acked(
        &mut self,
        current_binding: &AgentMlsAuthorizationBinding,
        message_id: &DeviceMessageId,
        now: DateTime<Utc>,
    ) -> Result<()> {
        self.require_active(current_binding, now)?;
        if !self.snapshot.pending_message_acks.contains(message_id) {
            return Err(protocol_error(
                "Agent MLS device-message ack is not pending",
            ));
        }
        let mut next = self.snapshot.clone();
        next.pending_message_acks.remove(message_id);
        self.commit(next).await
    }

    pub async fn apply_commit(
        &mut self,
        current_binding: &AgentMlsAuthorizationBinding,
        commit: &MlsCommitEnvelope,
        now: DateTime<Utc>,
    ) -> Result<u64> {
        self.require_active(current_binding, now)?;
        let state = self
            .snapshot
            .groups
            .get(&commit.group_id)
            .ok_or_else(|| protocol_error("Agent MLS group state is missing"))?;
        let mut group = ArkretMlsGroup::restore_from_state_record(state)
            .map_err(|error| map_protocol_error("restore Agent MLS group", error))?;
        let epoch = group
            .apply_commit(commit)
            .map_err(|error| map_protocol_error("apply Agent MLS commit", error))?;
        let mut next = self.snapshot.clone();
        next.identity_private_state = group
            .identity()
            .export_private_state()
            .map_err(|error| map_protocol_error("export updated Agent MLS identity", error))?;
        let state = group
            .export_state_record()
            .map_err(|error| map_protocol_error("export updated Agent MLS group", error))?;
        next.groups.insert(state.group_id.clone(), state);
        self.commit(next).await?;
        Ok(epoch)
    }

    pub async fn encrypt_payload(
        &mut self,
        current_binding: &AgentMlsAuthorizationBinding,
        group_id: &str,
        event_kind: &str,
        plaintext: &[u8],
        now: DateTime<Utc>,
    ) -> Result<EncryptedPayload> {
        self.require_active(current_binding, now)?;
        let mut group = self.restore_group(group_id)?;
        let payload = group
            .encrypt_payload(event_kind, plaintext)
            .map_err(|error| map_protocol_error("encrypt Agent MLS payload", error))?;
        self.commit_group(group).await?;
        Ok(payload)
    }

    pub async fn decrypt_payload(
        &mut self,
        current_binding: &AgentMlsAuthorizationBinding,
        group_id: &str,
        payload: &EncryptedPayload,
        now: DateTime<Utc>,
    ) -> Result<Vec<u8>> {
        self.require_active(current_binding, now)?;
        let mut group = self.restore_group(group_id)?;
        let plaintext = group
            .decrypt_payload(payload)
            .map_err(|error| map_protocol_error("decrypt Agent MLS payload", error))?;
        self.commit_group(group).await?;
        Ok(plaintext)
    }

    /// Quiesce this endpoint and persist the exact old-key revoke request.
    pub async fn prepare_authorization_replacement(
        &mut self,
        current_binding: &AgentMlsAuthorizationBinding,
        now: DateTime<Utc>,
    ) -> Result<Option<KeyPackagesRevokeRequestBody>> {
        self.require_active(current_binding, now)?;
        if !self.snapshot.pending_consumes.is_empty()
            || !self.snapshot.pending_message_acks.is_empty()
        {
            return Err(protocol_error(
                "Agent MLS pending consume and ack work must drain before replacement",
            ));
        }
        let refs = self
            .snapshot
            .key_packages
            .values()
            .filter(|stored| {
                stored.upload_accepted
                    && stored.record.state == arkret_models_crypto::MlsKeyPackageState::Published
            })
            .map(|stored| stored.record.keypackage_id.clone())
            .collect::<Vec<_>>();
        let mut next = self.snapshot.clone();
        if refs.is_empty() {
            next.phase = AgentMlsRuntimePhase::ReadyForReplacement;
            self.commit(next).await?;
            return Ok(None);
        }
        let identity = restore_identity(&self.snapshot)?;
        let request = identity
            .signed_key_packages_revoke_request(
                KeyPackagesRevokeUnsignedRequest {
                    key_package_refs: refs,
                    device_id: self.snapshot.binding.device_id.clone(),
                    reason: Some("authorization_superseded".to_owned()),
                },
                &self.snapshot.binding.verification_method,
            )
            .map_err(|error| map_protocol_error("sign Agent MLS replacement revoke", error))?;
        next.phase = AgentMlsRuntimePhase::Quiescing;
        next.pending_revoke = Some(request.clone());
        self.commit(next).await?;
        Ok(Some(request))
    }

    pub fn pending_revoke_request(&self) -> Option<&KeyPackagesRevokeRequestBody> {
        self.snapshot.pending_revoke.as_ref()
    }

    pub async fn mark_revoke_accepted(&mut self, outcome: &KeyPackagesRevokeOutcome) -> Result<()> {
        if self.snapshot.phase != AgentMlsRuntimePhase::Quiescing {
            return Err(protocol_error("Agent MLS runtime is not quiescing"));
        }
        let request = self
            .snapshot
            .pending_revoke
            .as_ref()
            .ok_or_else(|| protocol_error("Agent MLS replacement revoke is missing"))?;
        if request
            .key_package_refs
            .iter()
            .any(|keypackage_ref| !outcome.revoked.contains(keypackage_ref))
        {
            return Err(protocol_error(
                "Agent MLS replacement revoke outcome is incomplete",
            ));
        }
        let mut next = self.snapshot.clone();
        for keypackage_id in &request.key_package_refs {
            if let Some(stored) = next
                .key_packages
                .values_mut()
                .find(|stored| stored.record.keypackage_id == *keypackage_id)
            {
                stored.record.state = arkret_models_crypto::MlsKeyPackageState::Revoked;
            }
        }
        next.pending_revoke = None;
        next.phase = AgentMlsRuntimePhase::ReadyForReplacement;
        self.commit(next).await
    }

    /// Replace the endpoint only after the old pool revoke was durably
    /// accepted. Old groups, claims, sessions, and pending Welcomes are not
    /// carried across the new authorization/key/device binding.
    pub async fn finish_authorization_replacement(
        &mut self,
        new_binding: AgentMlsAuthorizationBinding,
        new_signing_seed: [u8; 32],
        key_package_low_watermark: usize,
        now: DateTime<Utc>,
    ) -> Result<()> {
        if self.snapshot.phase != AgentMlsRuntimePhase::ReadyForReplacement {
            return Err(protocol_error(
                "old Agent MLS endpoint must be revoked before replacement",
            ));
        }
        new_binding.validate_at(now)?;
        if new_binding.principal_id != self.snapshot.binding.principal_id {
            return Err(protocol_error(
                "Agent MLS authorization replacement cannot change principal",
            ));
        }
        if new_binding.authorization_event_id == self.snapshot.binding.authorization_event_id
            || new_binding.verification_method == self.snapshot.binding.verification_method
            || new_binding.device_id == self.snapshot.binding.device_id
        {
            return Err(protocol_error(
                "Agent MLS authorization replacement must rotate event, key, and device binding",
            ));
        }
        let identity = ArkretMlsIdentity::from_ed25519_signing_seed(
            new_binding.principal_id.clone(),
            new_binding.device_id.clone(),
            new_signing_seed,
        )
        .map_err(|error| map_protocol_error("create replacement Agent MLS identity", error))?;
        ensure_identity_matches_binding(&identity, &new_binding)?;
        let mut key_packages = BTreeMap::new();
        for _ in 0..key_package_low_watermark {
            let record = identity.key_package_record().map_err(|error| {
                map_protocol_error("create replacement Agent MLS KeyPackage", error)
            })?;
            key_packages.insert(
                record.keypackage_ref.as_str().to_owned(),
                StoredKeyPackage {
                    record,
                    upload_accepted: false,
                },
            );
        }
        let next = AgentMlsRuntimeSnapshot {
            context: SNAPSHOT_CONTEXT.to_owned(),
            binding: new_binding,
            phase: AgentMlsRuntimePhase::Active,
            identity_private_state: identity.export_private_state().map_err(|error| {
                map_protocol_error("export replacement Agent MLS identity", error)
            })?,
            key_packages,
            groups: BTreeMap::new(),
            pending_consumes: BTreeMap::new(),
            consumed_claims: BTreeSet::new(),
            pending_message_acks: BTreeSet::new(),
            pending_revoke: None,
        };
        self.commit(next).await
    }

    fn require_active(
        &self,
        current_binding: &AgentMlsAuthorizationBinding,
        now: DateTime<Utc>,
    ) -> Result<()> {
        current_binding.validate_at(now)?;
        if self.snapshot.phase != AgentMlsRuntimePhase::Active {
            return Err(protocol_error("Agent MLS runtime is quiesced"));
        }
        if &self.snapshot.binding != current_binding {
            return Err(protocol_error(
                "Agent MLS authorization binding is no longer current",
            ));
        }
        Ok(())
    }

    fn restore_group(&self, group_id: &str) -> Result<ArkretMlsGroup> {
        let state = self
            .snapshot
            .groups
            .get(group_id)
            .ok_or_else(|| protocol_error("Agent MLS group state is missing"))?;
        ArkretMlsGroup::restore_from_state_record(state)
            .map_err(|error| map_protocol_error("restore Agent MLS group", error))
    }

    async fn commit_group(&mut self, group: ArkretMlsGroup) -> Result<()> {
        let mut next = self.snapshot.clone();
        next.identity_private_state = group
            .identity()
            .export_private_state()
            .map_err(|error| map_protocol_error("export Agent MLS identity", error))?;
        let state = group
            .export_state_record()
            .map_err(|error| map_protocol_error("export Agent MLS group", error))?;
        next.groups.insert(state.group_id.clone(), state);
        self.commit(next).await
    }

    async fn commit(&mut self, next: AgentMlsRuntimeSnapshot) -> Result<()> {
        next.validate()?;
        persist_snapshot(&self.secure_store, &self.storage_key, &next).await?;
        self.snapshot = next;
        Ok(())
    }
}

fn restore_identity(snapshot: &AgentMlsRuntimeSnapshot) -> Result<ArkretMlsIdentity> {
    ArkretMlsIdentity::restore_from_private_state(
        snapshot.binding.principal_id.clone(),
        snapshot.binding.device_id.clone(),
        &snapshot.identity_private_state,
    )
    .map_err(|error| map_protocol_error("restore Agent MLS identity", error))
}

fn ensure_identity_matches_binding(
    identity: &ArkretMlsIdentity,
    binding: &AgentMlsAuthorizationBinding,
) -> Result<()> {
    if identity.principal_id != binding.principal_id
        || identity.device_id != binding.device_id
        || identity.signature_public_key() != binding.signing_public_key
    {
        return Err(protocol_error(
            "Agent MLS identity does not match the current authorization binding",
        ));
    }
    Ok(())
}

async fn persist_snapshot<S>(
    secure_store: &S,
    storage_key: &str,
    snapshot: &AgentMlsRuntimeSnapshot,
) -> Result<()>
where
    S: SecureKeyStore,
{
    snapshot.validate()?;
    let encoded = Zeroizing::new(
        serde_json::to_vec(snapshot)
            .map_err(|error| map_protocol_error("encode Agent MLS runtime state", error))?,
    );
    secure_store
        .put_secret(
            storage_key,
            &encoded,
            PutSecretOptions {
                durability: SecretDurability::DurableBeforeReturn,
                class: SecretClass::MlsSecret,
            },
        )
        .await?;
    Ok(())
}

fn validate_welcome_input(
    snapshot: &AgentMlsRuntimeSnapshot,
    input: &AgentMlsWelcomeInput,
    now: DateTime<Utc>,
) -> Result<()> {
    let payload = &input.payload;
    if payload.expires_at <= now {
        return Err(protocol_error("Agent MLS Welcome is expired"));
    }
    if payload.recipient_principal_id != snapshot.binding.principal_id
        || payload.recipient_device_id != snapshot.binding.device_id
    {
        return Err(protocol_error(
            "Agent MLS Welcome recipient binding mismatch",
        ));
    }
    if payload.claim_ref.claim_id != payload.claim_id
        || payload.claim_ref.keypackage_ref != payload.keypackage_ref
        || payload.claim_ref.keypackage_digest != payload.keypackage_digest
        || payload.claim_envelope.claim_id != payload.claim_id
        || payload.claim_envelope.keypackage_ref != payload.keypackage_ref
        || payload.claim_envelope.keypackage_digest != payload.keypackage_digest
    {
        return Err(protocol_error("Agent MLS Welcome claim binding mismatch"));
    }
    if payload.governance_binding.mls_group_id() != payload.mls_group_id.as_str()
        || payload.governance_binding.next_epoch() != payload.epoch
    {
        return Err(protocol_error(
            "Agent MLS Welcome governance group or epoch mismatch",
        ));
    }
    if payload.claim_envelope.created_at > payload.expires_at {
        return Err(protocol_error(
            "Agent MLS Welcome claim envelope is newer than its expiry",
        ));
    }
    match &payload.claim_ref.trust_binding {
        MlsClaimTrustBinding::AgentKeyAuthorizeEventId(event_id)
            if event_id.as_str() == snapshot.binding.authorization_event_id.as_str() => {}
        _ => {
            return Err(protocol_error(
                "Agent MLS Welcome authorization binding is stale or invalid",
            ));
        }
    }
    let stored = snapshot
        .key_packages
        .get(payload.keypackage_ref.as_str())
        .ok_or_else(|| protocol_error("Agent MLS Welcome references an unknown KeyPackage"))?;
    if !stored.upload_accepted {
        return Err(protocol_error(
            "Agent MLS Welcome references a KeyPackage not accepted by the server",
        ));
    }
    if stored.record.keypackage_id != input.key_package_id
        || stored.record.keypackage_ref.as_str() != payload.keypackage_ref.as_str()
        || stored.record.keypackage_ref != payload.keypackage_digest
    {
        return Err(protocol_error(
            "Agent MLS Welcome KeyPackage digest mismatch",
        ));
    }
    if stored
        .record
        .expires_at
        .is_some_and(|expires_at| expires_at <= now)
    {
        return Err(protocol_error("Agent MLS Welcome KeyPackage is expired"));
    }
    let claimed_capabilities = &input.claimed_capabilities;
    let capabilities_bytes = canonical_json_bytes(&claimed_capabilities)
        .map_err(|error| map_protocol_error("canonicalize claimed capabilities", error))?;
    let capabilities_digest = Hash::new(arkret_canonical::sha256_digest(&capabilities_bytes))?;
    if capabilities_digest != payload.claim_ref.capabilities_digest
        || claimed_capabilities
            .iter()
            .any(|capability| !stored.record.capabilities.contains(capability))
    {
        return Err(protocol_error(
            "Agent MLS Welcome claimed capability binding mismatch",
        ));
    }
    if payload.claim_envelope.intended_realm_id != *payload.governance_binding.realm_id() {
        return Err(protocol_error("Agent MLS Welcome Realm binding mismatch"));
    }
    let envelope = welcome_envelope(payload)?;
    if envelope.group_id != payload.mls_group_id.as_str()
        || envelope.epoch != payload.epoch
        || envelope.welcome_hash != payload.claim_envelope.welcome_digest
    {
        return Err(protocol_error(
            "Agent MLS Welcome ciphertext binding mismatch",
        ));
    }
    Ok(())
}

fn welcome_envelope(payload: &MlsWelcomePayload) -> Result<MlsWelcomeEnvelope> {
    let ciphertext = payload
        .carrier
        .ciphertext()
        .ok_or_else(|| protocol_error("Agent MLS Welcome has no inline ciphertext"))?;
    let bytes = base64url_decode(ciphertext.as_bytes())
        .map_err(|error| map_protocol_error("decode Agent MLS Welcome", error))?;
    let welcome_hash = Hash::new(arkret_canonical::sha256_digest(&bytes))?;
    Ok(MlsWelcomeEnvelope {
        group_id: payload.mls_group_id.as_str().to_owned(),
        epoch: payload.epoch,
        recipient_principal_id: payload.recipient_principal_id.clone(),
        recipient_device_id: payload.recipient_device_id.clone(),
        welcome: ciphertext.to_owned(),
        welcome_hash,
        ratchet_tree: None,
    })
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU64;

    use arkret_models_collaboration::events_payloads::list_message_mimi_mls::{
        MlsRequesterTrustBinding, MlsWelcomeCarrier, MlsWelcomeClaimEnvelope,
        MlsWelcomePayloadClaimRef,
    };
    use arkret_models_crypto::{MLS_GOVERNANCE_BINDING_FULL_PROFILE, MlsGovernanceBindingPayload};
    use arkret_wire::{Base64UrlString, MlsGroupId, NonEmptyString, RealmId};
    use chrono::Duration;
    use ed25519_dalek::SigningKey;

    use super::*;
    use crate::MemorySecureKeyStore;

    struct TestVerifier;

    impl AgentMlsWelcomeVerifier for TestVerifier {
        fn verify_claim_envelope(&self, _payload: &MlsWelcomePayload) -> Result<()> {
            Ok(())
        }

        fn verify_governance_binding(
            &self,
            payload: &MlsWelcomePayload,
            group: &ArkretMlsGroup,
        ) -> Result<()> {
            if group
                .current_governance_binding()
                .map_err(|error| map_protocol_error("read test governance binding", error))?
                != Some(payload.governance_binding.clone())
            {
                return Err(protocol_error("test governance binding mismatch"));
            }
            Ok(())
        }
    }

    fn did(name: &str) -> Did {
        Did::new(format!("did:webvh:z6mkfixture:{name}.example")).unwrap()
    }

    fn device(suffix: &str) -> DeviceId {
        DeviceId::new(format!("ak:device:01904100-0000-7000-8000-{suffix}")).unwrap()
    }

    fn event(suffix: &str) -> EventId {
        EventId::new(format!("ak:event:01904100-0000-7000-8000-{suffix}")).unwrap()
    }

    fn hash(byte: char) -> Hash {
        Hash::new(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
    }

    fn binding(seed: [u8; 32], suffix: &str) -> AgentMlsAuthorizationBinding {
        let principal_id = did("native-agent");
        AgentMlsAuthorizationBinding {
            principal_id: principal_id.clone(),
            device_id: device(suffix),
            authorization_event_id: event(suffix),
            verification_method: format!("{principal_id}#runtime-{suffix}"),
            signing_public_key: SigningKey::from_bytes(&seed)
                .verifying_key()
                .to_bytes()
                .to_vec(),
            expires_at: Some(Utc::now() + Duration::days(1)),
        }
    }

    #[tokio::test]
    async fn persists_before_upload_and_replays_identical_attempt_after_restart() {
        let store = MemorySecureKeyStore::new();
        let now = Utc::now();
        let binding = binding([17; 32], "000000000101");
        let runtime = AgentMlsRuntime::initialize(
            store.clone(),
            "agent-mls-test",
            binding.clone(),
            [17; 32],
            2,
            now,
        )
        .await
        .unwrap();
        let first = runtime
            .pending_upload_request(&binding, now)
            .unwrap()
            .unwrap();
        assert_eq!(first.key_packages.len(), 2);
        let restored = AgentMlsRuntime::restore(store, "agent-mls-test", &binding, now).unwrap();
        let replay = restored
            .pending_upload_request(&binding, now)
            .unwrap()
            .unwrap();
        assert_eq!(
            serde_json::to_value(first).unwrap(),
            serde_json::to_value(replay).unwrap()
        );
    }

    #[tokio::test]
    async fn welcome_group_and_consume_intent_survive_restart_atomically() {
        let store = MemorySecureKeyStore::new();
        let now = Utc::now();
        let binding = binding([19; 32], "000000000201");
        let mut runtime = AgentMlsRuntime::initialize(
            store.clone(),
            "agent-mls-welcome",
            binding.clone(),
            [19; 32],
            1,
            now,
        )
        .await
        .unwrap();
        let upload = runtime
            .pending_upload_request(&binding, now)
            .unwrap()
            .unwrap();
        let entry = upload.key_packages[0].clone();
        runtime
            .mark_upload_accepted(&binding, std::slice::from_ref(&entry.keypackage_ref), now)
            .await
            .unwrap();

        let owner = ArkretMlsIdentity::new_basic(did("owner"), device("000000000202")).unwrap();
        let realm_id = RealmId::new("ak:realm:01904100-0000-7000-8000-000000000203").unwrap();
        let raw_group_id = b"agent-runtime-live-group";
        let group_id = arkret_canonical::base64url_encode(raw_group_id);
        let genesis_binding = MlsGovernanceBindingPayload::realm(
            realm_id.clone(),
            group_id.clone(),
            0,
            0,
            vec![event("000000000204")],
            hash('2'),
            hash('3'),
            hash('4'),
            MLS_GOVERNANCE_BINDING_FULL_PROFILE,
            "ak.reducer.v1",
        )
        .unwrap();
        let mut owner_group = owner
            .create_group_with_governance_binding(raw_group_id, &genesis_binding)
            .unwrap();
        let record = runtime
            .snapshot
            .key_packages
            .get(&entry.keypackage_ref)
            .unwrap()
            .record
            .clone();
        let governance_binding = MlsGovernanceBindingPayload::realm(
            realm_id.clone(),
            group_id.clone(),
            0,
            1,
            vec![event("000000000204")],
            hash('2'),
            hash('3'),
            hash('4'),
            MLS_GOVERNANCE_BINDING_FULL_PROFILE,
            "ak.reducer.v1",
        )
        .unwrap();
        let add = owner_group
            .add_member_with_governance_binding(&record, &governance_binding)
            .unwrap();
        let capabilities = record.capabilities.clone();
        let capabilities_digest = Hash::new(arkret_canonical::sha256_digest(
            &canonical_json_bytes(&capabilities).unwrap(),
        ))
        .unwrap();
        let claim_id = NonEmptyString::new("claim-agent-runtime-001").unwrap();
        let claim_ref = MlsWelcomePayloadClaimRef {
            claim_id: claim_id.clone(),
            keypackage_ref: record.keypackage_ref.as_str().to_owned(),
            keypackage_digest: record.keypackage_ref.clone(),
            capabilities_digest,
            trust_binding: MlsClaimTrustBinding::AgentKeyAuthorizeEventId(
                NonEmptyString::new(binding.authorization_event_id.as_str()).unwrap(),
            ),
        };
        let claim_envelope = MlsWelcomeClaimEnvelope {
            keypackage_ref: record.keypackage_ref.as_str().to_owned(),
            keypackage_digest: record.keypackage_ref.clone(),
            intended_realm_id: realm_id,
            claim_id: claim_id.clone(),
            requester_did: did("owner"),
            trust_binding: MlsRequesterTrustBinding::SskGeneration(NonZeroU64::new(1).unwrap()),
            nonce: NonEmptyString::new("agent-runtime-claim-nonce").unwrap(),
            welcome_digest: add.welcome.welcome_hash.clone(),
            created_at: now,
            signature: arkret_models_crypto::KeyOperationSignature {
                kid: NonEmptyString::new("did:webvh:z6mkfixture:owner.example#ssk-1").unwrap(),
                alg: Some(NonEmptyString::new("EdDSA").unwrap()),
                sig: Base64UrlString::new("AQ").unwrap(),
            },
        };
        let payload = MlsWelcomePayload {
            mls_group_id: MlsGroupId::new(group_id.clone()).unwrap(),
            epoch: add.welcome.epoch,
            recipient_principal_id: binding.principal_id.clone(),
            recipient_device_id: binding.device_id.clone(),
            sender_device_id: Some(device("000000000202")),
            keypackage_ref: record.keypackage_ref.as_str().to_owned(),
            keypackage_digest: record.keypackage_ref.clone(),
            claim_id: claim_id.clone(),
            claim_ref,
            claim_envelope,
            peer_claim_receipt: None,
            carrier: MlsWelcomeCarrier::new(
                None,
                None,
                Some(NonEmptyString::new(add.welcome.welcome.clone()).unwrap()),
            )
            .unwrap(),
            commit_ref: None,
            governance_binding,
            expires_at: now + Duration::hours(1),
        };
        let welcome_input = AgentMlsWelcomeInput {
            message_id: DeviceMessageId::new(
                "ak:device_message:01904100-0000-7000-8000-000000000205",
            )
            .unwrap(),
            key_package_id: record.keypackage_id,
            payload,
            claimed_capabilities: capabilities,
        };
        let mut inconsistent = welcome_input.clone();
        inconsistent.payload.claim_ref.claim_id =
            NonEmptyString::new("claim-agent-runtime-conflict").unwrap();
        assert!(
            runtime
                .process_welcome(&binding, inconsistent, &TestVerifier, now)
                .await
                .is_err()
        );
        let outcome = runtime
            .process_welcome(&binding, welcome_input.clone(), &TestVerifier, now)
            .await
            .unwrap();
        let request = match outcome {
            AgentMlsWelcomeOutcome::ConsumeRequired(request) => request,
            other => panic!("unexpected Welcome outcome: {other:?}"),
        };
        assert!(matches!(
            runtime
                .process_welcome(&binding, welcome_input.clone(), &TestVerifier, now)
                .await
                .unwrap(),
            AgentMlsWelcomeOutcome::AlreadyPending(_)
        ));
        let mut conflicting = welcome_input;
        conflicting.message_id =
            DeviceMessageId::new("ak:device_message:01904100-0000-7000-8000-000000000206").unwrap();
        assert!(
            runtime
                .process_welcome(&binding, conflicting, &TestVerifier, now)
                .await
                .is_err()
        );

        let mut restored =
            AgentMlsRuntime::restore(store, "agent-mls-welcome", &binding, now).unwrap();
        assert!(restored.group_state(&group_id).is_some());
        assert_eq!(restored.pending_consume_intents().len(), 1);
        assert_eq!(
            serde_json::to_value(&restored.pending_consume_intents()[0].request).unwrap(),
            serde_json::to_value(&request).unwrap()
        );
        restored
            .mark_consume_accepted(&binding, claim_id.as_str(), &request.key_package_refs, now)
            .await
            .unwrap();
        let refill = restored
            .ensure_key_package_pool(&binding, 1, now)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(refill.key_packages.len(), 1);
    }

    #[tokio::test]
    async fn replacement_quiesces_old_endpoint_and_requires_complete_revoke() {
        let store = MemorySecureKeyStore::new();
        let now = Utc::now();
        let old_binding = binding([21; 32], "000000000301");
        let mut runtime = AgentMlsRuntime::initialize(
            store,
            "agent-mls-replacement",
            old_binding.clone(),
            [21; 32],
            1,
            now,
        )
        .await
        .unwrap();
        let upload = runtime
            .pending_upload_request(&old_binding, now)
            .unwrap()
            .unwrap();
        runtime
            .mark_upload_accepted(
                &old_binding,
                std::slice::from_ref(&upload.key_packages[0].keypackage_ref),
                now,
            )
            .await
            .unwrap();
        let revoke = runtime
            .prepare_authorization_replacement(&old_binding, now)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(runtime.phase(), AgentMlsRuntimePhase::Quiescing);
        assert!(runtime.pending_upload_request(&old_binding, now).is_err());
        runtime
            .mark_revoke_accepted(&KeyPackagesRevokeOutcome {
                revoked: revoke.key_package_refs,
                failures: Vec::new(),
            })
            .await
            .unwrap();
        let new_binding = binding([22; 32], "000000000302");
        runtime
            .finish_authorization_replacement(new_binding.clone(), [22; 32], 1, now)
            .await
            .unwrap();
        assert_eq!(runtime.binding(), &new_binding);
        assert!(runtime.pending_upload_request(&old_binding, now).is_err());
        assert!(
            runtime
                .pending_upload_request(&new_binding, now)
                .unwrap()
                .is_some()
        );
    }
}
