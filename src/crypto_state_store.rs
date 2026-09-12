//! Durable crypto store traits and an in-memory implementation.
//!
//! The SDK keeps this layer independent from OpenMLS internals. Applications can
//! serialize provider-specific MLS state into `MlsGroupStateRecord` while using
//! the typed Arkret envelopes for KeyPackages, Welcomes and Commits.

use std::collections::BTreeMap;
use std::future::Future;

use arkret_models_collaboration::events_payloads::{MlsGenesisPayload, MlsWelcomePayload};
use arkret_models_crypto::{
    MlsAcceptedArtifactOutcome, MlsAcceptedArtifactRequestBody, MlsCommitPayload,
};
pub use arkret_models_crypto::{MlsCommitSource, MlsGroupStateSink};
use arkret_wire::WireError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::protocol::{
    DeviceId, DeviceVerificationState, DidCoreId, Error, Event, EventId, EventKind, Hash,
    MlsCommitEnvelope, MlsKeyPackageRecord, MlsWelcomeEnvelope, Result, ScopeRef,
};
use crate::{MaybeSend, MaybeSendSync, QueuedMlsLocalCheckpoint};

/// Local processing state for an exact Welcome envelope.
///
/// Receipt, admission, and successful MLS consumption are deliberately
/// separate. Merely observing an old Welcome must never authorize a join or
/// make recovery choose it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MlsWelcomeState {
    Received,
    Accepted,
    Consumed,
}

// `MlsGroupStateRecord` moved to `arkret_models_crypto::mls_records` so the MLS
// behavior layer can consume it without the SDK crypto store. Re-exported here
// to keep the `crate::MlsGroupStateRecord` path and the `crate::protocol::` surface
// stable.
pub use arkret_models_crypto::MlsGroupStateRecord;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MlsEpochSecretRecord {
    pub group_id: String,
    pub epoch: u64,
    pub secret_ref: String,
    pub encrypted_secret: Vec<u8>,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredDeviceVerification {
    pub principal_id: DidCoreId,
    pub device_id: DeviceId,
    pub state: DeviceVerificationState,
    pub updated_at: DateTime<Utc>,
}

/// One encrypted MLS snapshot committed from a Station-accepted Event. The snapshot itself is the
/// ready marker: no parallel in-memory readiness bit exists.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableAcceptedMlsArtifact {
    pub event: Event,
    pub event_digest: Hash,
    pub winning_transition_ref: EventId,
    pub transition_head: arkret_models_crypto::MlsEpochHead,
    pub snapshot: QueuedMlsLocalCheckpoint,
    pub history_secret: QueuedMlsHistorySecret,
}

/// Host-encrypted history material committed atomically with an accepted MLS
/// post-state. Garth treats the ciphertext as opaque.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueuedMlsHistorySecret {
    pub group_id: String,
    pub epoch: u64,
    pub transition_ref: EventId,
    pub ciphertext: Vec<u8>,
}

/// Fully prepared local material for one Station-accepted MLS artifact.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedAcceptedMlsArtifact {
    pub snapshot: QueuedMlsLocalCheckpoint,
    pub history_secret: QueuedMlsHistorySecret,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptedMlsArtifactState {
    pub artifacts: BTreeMap<String, DurableAcceptedMlsArtifact>,
    pub ready_groups: BTreeMap<String, String>,
    pub history_secrets: BTreeMap<String, QueuedMlsHistorySecret>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VersionedAcceptedMlsArtifactState {
    pub revision: u64,
    pub snapshot: AcceptedMlsArtifactState,
}

/// Durable atomic store for accepted MLS artifacts. A successful CAS MUST mean
/// the encrypted snapshot is crash-recoverable before it returns `true`.
pub trait AcceptedMlsArtifactStore: Clone + MaybeSendSync + 'static {
    fn load_accepted_mls_artifacts(&self) -> Result<VersionedAcceptedMlsArtifactState>;

    fn compare_and_swap_accepted_mls_artifacts<'a>(
        &'a self,
        expected_revision: u64,
        snapshot: &'a AcceptedMlsArtifactState,
    ) -> impl Future<Output = Result<bool>> + MaybeSend + 'a;
}

/// Provider boundary invoked after the Station accepts the exact Event and
/// its binding matches the selected transition (including a Welcome target). Implementations MUST
/// derive the returned material from the Event, previous durable snapshot and
/// host-owned durable staging/secure-key inputs. A CAS retry may invoke
/// `prepare` again; preparation MUST NOT publish readiness, persist history
/// material, consume staging, or mutate an authoritative provider state.
pub trait AcceptedMlsArtifactApplicator: MaybeSendSync {
    fn prepare<'a>(
        &'a self,
        event: &'a Event,
        previous: Option<&'a QueuedMlsLocalCheckpoint>,
    ) -> impl Future<Output = Result<PreparedAcceptedMlsArtifact>> + MaybeSend + 'a;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AcceptedMlsArtifactCommitOutcome {
    Applied,
    ExactReplay,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AcceptedMlsArtifactCommit {
    pub outcome: AcceptedMlsArtifactCommitOutcome,
    pub artifact: DurableAcceptedMlsArtifact,
}

pub struct AcceptedMlsArtifactConsumer<S> {
    store: S,
}

impl<S> AcceptedMlsArtifactConsumer<S>
where
    S: AcceptedMlsArtifactStore,
{
    pub fn new(store: S) -> Self {
        Self { store }
    }

    pub fn store(&self) -> &S {
        &self.store
    }

    pub fn ready_checkpoint(
        &self,
        scope: &ScopeRef,
        group_id: &str,
    ) -> Result<Option<QueuedMlsLocalCheckpoint>> {
        let state = self.store.load_accepted_mls_artifacts()?.snapshot;
        let key = ready_group_key(scope, group_id)?;
        let Some(event_id) = state.ready_groups.get(&key) else {
            return Ok(None);
        };
        let artifact = state.artifacts.get(event_id).ok_or_else(|| {
            Error::Protocol("accepted MLS ready index references a missing artifact".to_owned())
        })?;
        artifact.transition_head.validate()?;
        if artifact.snapshot.group_id != group_id
            || artifact.snapshot.aead_version != 1
            || artifact.transition_head.effective_scope != *scope
            || artifact.transition_head.mls_group_id.as_str() != group_id
            || artifact.transition_head.next_epoch != artifact.snapshot.epoch
            || artifact.transition_head.transition_ref != artifact.winning_transition_ref
            || artifact.snapshot.group_state_event_id.as_ref()
                != Some(&artifact.winning_transition_ref)
        {
            return Err(Error::Protocol(
                "accepted MLS ready index references a mismatched snapshot".to_owned(),
            ));
        }
        let history_key = history_secret_key(&artifact.history_secret);
        if state.history_secrets.get(&history_key) != Some(&artifact.history_secret) {
            return Err(Error::Protocol(
                "accepted MLS ready artifact has no exact durable history secret".to_owned(),
            ));
        }
        Ok(Some(artifact.snapshot.clone()))
    }

    /// Consume one exact Event accepted by the authenticated Account Station.
    /// The host must keep the response in its current account/session scope.
    pub async fn consume<A>(
        &self,
        request: &MlsAcceptedArtifactRequestBody,
        outcome: &MlsAcceptedArtifactOutcome,
        event: &Event,
        applicator: &A,
    ) -> Result<AcceptedMlsArtifactCommit>
    where
        A: AcceptedMlsArtifactApplicator,
    {
        let accepted = accepted_artifact(request, outcome, event)?;
        self.consume_accepted(accepted, applicator).await
    }

    async fn consume_accepted<A>(
        &self,
        accepted: StationAcceptedMlsArtifact,
        applicator: &A,
    ) -> Result<AcceptedMlsArtifactCommit>
    where
        A: AcceptedMlsArtifactApplicator,
    {
        for _ in 0..16 {
            let current = self.store.load_accepted_mls_artifacts()?;
            let event_key = accepted.event.event_id.to_string();
            if let Some(existing) = current.snapshot.artifacts.get(&event_key) {
                if existing.event == accepted.event
                    && existing.event_digest == accepted.event_digest
                    && existing.winning_transition_ref == accepted.winning_transition_ref
                    && existing.transition_head == accepted.transition_head
                {
                    return Ok(AcceptedMlsArtifactCommit {
                        outcome: AcceptedMlsArtifactCommitOutcome::ExactReplay,
                        artifact: existing.clone(),
                    });
                }
                return Err(Error::IdempotencyConflict(event_key));
            }

            let ready_key = ready_group_key(&accepted.scope, &accepted.group_id)?;
            let previous = current
                .snapshot
                .ready_groups
                .get(&ready_key)
                .and_then(|id| current.snapshot.artifacts.get(id));
            let previous_snapshot = match &accepted.application {
                AcceptedMlsApplication::Genesis => {
                    if previous.is_some() {
                        return Err(Error::Protocol(
                            "accepted MLS Genesis cannot replace a ready group".to_owned(),
                        ));
                    }
                    None
                }
                AcceptedMlsApplication::Commit {
                    base_epoch,
                    base_epoch_ref,
                } => {
                    let previous = previous.ok_or_else(|| {
                        Error::Protocol(
                            "accepted MLS Commit has no durable base snapshot".to_owned(),
                        )
                    })?;
                    if previous.snapshot.epoch != *base_epoch
                        || previous.winning_transition_ref.as_str() != base_epoch_ref
                    {
                        return Err(Error::Protocol(format!(
                            "accepted MLS Commit does not extend the durable winning base: local epoch={}, transition={}, required epoch={}, transition={}",
                            previous.snapshot.epoch,
                            previous.winning_transition_ref,
                            base_epoch,
                            base_epoch_ref,
                        )));
                    }
                    Some(&previous.snapshot)
                }
                AcceptedMlsApplication::Welcome => {
                    if previous.is_some_and(|artifact| artifact.snapshot.epoch >= accepted.epoch) {
                        return Err(Error::Protocol(
                            "accepted MLS Welcome cannot replace an equal or newer durable epoch"
                                .to_owned(),
                        ));
                    }
                    previous.map(|artifact| &artifact.snapshot)
                }
            };
            let prepared = applicator
                .prepare(&accepted.event, previous_snapshot)
                .await?;
            validate_prepared_artifact(&accepted, &prepared)?;
            let artifact = DurableAcceptedMlsArtifact {
                event: accepted.event.clone(),
                event_digest: accepted.event_digest.clone(),
                winning_transition_ref: accepted.winning_transition_ref.clone(),
                transition_head: accepted.transition_head.clone(),
                snapshot: prepared.snapshot,
                history_secret: prepared.history_secret,
            };
            let mut next = current.snapshot;
            next.artifacts.insert(event_key.clone(), artifact.clone());
            next.ready_groups.insert(ready_key, event_key);
            let secret = artifact.history_secret.clone();
            let secret_key = history_secret_key(&secret);
            if let Some(existing) = next.history_secrets.get(&secret_key)
                && existing != &secret
            {
                return Err(Error::IdempotencyConflict(secret_key));
            }
            next.history_secrets.insert(secret_key, secret);
            if self
                .store
                .compare_and_swap_accepted_mls_artifacts(current.revision, &next)
                .await?
            {
                return Ok(AcceptedMlsArtifactCommit {
                    outcome: AcceptedMlsArtifactCommitOutcome::Applied,
                    artifact,
                });
            }
        }
        Err(Error::Protocol(
            "accepted MLS artifact store remained concurrently modified".to_owned(),
        ))
    }
}

#[derive(Clone)]
enum AcceptedMlsApplication {
    Genesis,
    Commit {
        base_epoch: u64,
        base_epoch_ref: String,
    },
    Welcome,
}

#[derive(Clone)]
struct StationAcceptedMlsArtifact {
    event: Event,
    event_digest: Hash,
    scope: ScopeRef,
    group_id: String,
    epoch: u64,
    winning_transition_ref: EventId,
    transition_head: arkret_models_crypto::MlsEpochHead,
    application: AcceptedMlsApplication,
}

fn accepted_artifact(
    request: &MlsAcceptedArtifactRequestBody,
    outcome: &MlsAcceptedArtifactOutcome,
    event: &Event,
) -> Result<StationAcceptedMlsArtifact> {
    outcome.validate_for_request(request)?;
    if event.event_id != request.artifact_ref || event.scope_ref != request.effective_scope {
        return Err(Error::Protocol(
            "MLS artifact differs from the exact Station query".to_owned(),
        ));
    }
    let (binding, epoch, reference, transition_digest, application) = match event.kind {
        EventKind::MlsGenesis => {
            let payload: MlsGenesisPayload =
                serde_json::from_value(serde_json::to_value(&event.payload)?)?;
            let digest = payload.transition_digest()?;
            (
                payload.governance_binding,
                0,
                event.event_id.clone(),
                Some(digest),
                AcceptedMlsApplication::Genesis,
            )
        }
        EventKind::MlsCommit => {
            let payload: MlsCommitPayload =
                serde_json::from_value(serde_json::to_value(&event.payload)?)?;
            (
                payload.governance_binding().clone(),
                payload.next_epoch(),
                event.event_id.clone(),
                Some(payload.commit_digest().clone()),
                AcceptedMlsApplication::Commit {
                    base_epoch: payload.base_epoch(),
                    base_epoch_ref: payload.base_epoch_ref().to_owned(),
                },
            )
        }
        EventKind::MlsWelcome => {
            let payload: MlsWelcomePayload =
                serde_json::from_value(serde_json::to_value(&event.payload)?)?;
            let epoch = payload.epoch();
            (
                payload.governance_binding,
                epoch,
                payload.commit_ref,
                None,
                AcceptedMlsApplication::Welcome,
            )
        }
        _ => return Err(Error::Protocol("Event is not an MLS artifact".to_owned())),
    };
    let head = &outcome.transition_head;
    if binding != outcome.governance_binding
        || reference != head.transition_ref
        || epoch != binding.next_epoch()
        || transition_digest
            .as_ref()
            .is_some_and(|digest| digest != &head.mls_transition_digest)
    {
        return Err(Error::Protocol(
            "MLS Event payload differs from the accepted Station transition".to_owned(),
        ));
    }
    Ok(StationAcceptedMlsArtifact {
        event: event.clone(),
        event_digest: event.event_id.event_digest(),
        scope: request.effective_scope.clone(),
        group_id: request.mls_group_id.to_string(),
        epoch,
        winning_transition_ref: reference,
        transition_head: head
            .epoch_head(&binding)
            .map_err(|error| Error::Protocol(error.to_string()))?,
        application,
    })
}

fn validate_prepared_artifact(
    accepted: &StationAcceptedMlsArtifact,
    prepared: &PreparedAcceptedMlsArtifact,
) -> Result<()> {
    let snapshot = &prepared.snapshot;
    if snapshot.group_id != accepted.group_id
        || snapshot.epoch != accepted.epoch
        || snapshot.group_state_event_id.as_ref() != Some(&accepted.winning_transition_ref)
        || snapshot.aead_version != 1
        || snapshot.salt_hex.is_empty()
        || snapshot.ciphertext_hex.is_empty()
        || snapshot.mac_hex.is_empty()
    {
        return Err(Error::Protocol(
            "applied MLS snapshot does not bind the accepted winning artifact".to_owned(),
        ));
    }
    if snapshot.admission_epoch > snapshot.epoch {
        return Err(Error::Protocol(
            "accepted MLS snapshot admission epoch exceeds its current epoch".to_owned(),
        ));
    }
    let secret = &prepared.history_secret;
    if secret.group_id != accepted.group_id
        || secret.epoch != accepted.epoch
        || secret.transition_ref != accepted.winning_transition_ref
        || secret.ciphertext.is_empty()
    {
        return Err(Error::Protocol(
            "accepted MLS history secret is not bound to the winning transition".to_owned(),
        ));
    }
    Ok(())
}

fn history_secret_key(secret: &QueuedMlsHistorySecret) -> String {
    format!("{}\u{1f}{:020}", secret.group_id, secret.epoch)
}

fn ready_group_key(scope: &ScopeRef, group_id: &str) -> Result<String> {
    let canonical = scope.canonical_mls_group_id()?;
    if canonical != group_id {
        return Err(Error::Protocol(
            "MLS ready key group id is not canonical for its scope".to_owned(),
        ));
    }
    Ok(format!("{}\u{1f}{group_id}", serde_json::to_string(scope)?))
}

// `put_mls_group_state` / `commits_for_group` moved to the narrow
// `arkret_models_crypto::{MlsGroupStateSink, MlsCommitSource}` ports so the MLS
// behavior layer can persist / read those records without depending on the
// umbrella crate — and so binding them here does not drag OpenMLS into ordinary
// build. `CryptoStore` re-declares them as supertraits: any `impl CryptoStore`
// still satisfies both ports, and existing `&mut impl CryptoStore` call sites
// coerce unchanged. Direct callers of the two moved methods now need the port
// trait in scope.
pub trait CryptoStore: Send + Sync + MlsGroupStateSink + MlsCommitSource {
    fn mls_group_state(&self, group_id: &str) -> Option<&MlsGroupStateRecord>;
    fn put_key_package(&mut self, record: MlsKeyPackageRecord) -> Result<()>;
    fn key_package(
        &self,
        principal_id: &DidCoreId,
        device_id: &DeviceId,
    ) -> Option<&MlsKeyPackageRecord>;
    fn key_packages_for_device(
        &self,
        principal_id: &DidCoreId,
        device_id: &DeviceId,
    ) -> Vec<&MlsKeyPackageRecord>;
    fn put_welcome(&mut self, record: MlsWelcomeEnvelope) -> Result<()>;
    fn welcomes_for_device(
        &self,
        principal_id: &DidCoreId,
        device_id: &DeviceId,
    ) -> Vec<&MlsWelcomeEnvelope>;
    fn welcomes_for_endpoint(
        &self,
        endpoint: &crate::protocol::MlsEndpointIdentity,
    ) -> Vec<&MlsWelcomeEnvelope>;
    fn mark_welcome_accepted(&mut self, welcome_hash: &crate::protocol::Hash) -> Result<()>;
    fn mark_welcome_consumed(&mut self, welcome_hash: &crate::protocol::Hash) -> Result<()>;
    fn welcome_state(&self, welcome_hash: &crate::protocol::Hash) -> Option<MlsWelcomeState>;
    fn put_commit(&mut self, record: MlsCommitEnvelope) -> Result<()>;
    fn put_epoch_secret(&mut self, record: MlsEpochSecretRecord) -> Result<()>;
    fn epoch_secret(&self, group_id: &str, epoch: u64) -> Option<&MlsEpochSecretRecord>;
    fn put_device_verification(&mut self, record: StoredDeviceVerification) -> Result<()>;
    fn device_verification(
        &self,
        principal_id: &DidCoreId,
        device_id: &DeviceId,
    ) -> Option<&StoredDeviceVerification>;
}

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct MemoryCryptoStore {
    group_states: BTreeMap<String, MlsGroupStateRecord>,
    key_packages: BTreeMap<crate::protocol::Hash, MlsKeyPackageRecord>,
    welcomes: Vec<MlsWelcomeEnvelope>,
    welcome_states: BTreeMap<crate::protocol::Hash, MlsWelcomeState>,
    commits: BTreeMap<String, Vec<MlsCommitEnvelope>>,
    epoch_secrets: BTreeMap<(String, u64), MlsEpochSecretRecord>,
    device_verifications: BTreeMap<(DidCoreId, DeviceId), StoredDeviceVerification>,
}

// The store aggregates MLS group snapshots, key packages and sealed epoch
// secrets: Debug renders entry counts only so no secret bytes can reach logs.
impl std::fmt::Debug for MemoryCryptoStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoryCryptoStore")
            .field("group_states", &self.group_states.len())
            .field("key_packages", &self.key_packages.len())
            .field("welcomes", &self.welcomes.len())
            .field("commits", &self.commits.len())
            .field("epoch_secrets", &self.epoch_secrets.len())
            .field("device_verifications", &self.device_verifications.len())
            .finish()
    }
}

impl MemoryCryptoStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl MlsGroupStateSink for MemoryCryptoStore {
    fn put_mls_group_state(
        &mut self,
        record: MlsGroupStateRecord,
    ) -> std::result::Result<(), WireError> {
        if let Some(existing) = self.group_states.get(&record.group_id)
            && record.epoch < existing.epoch
        {
            return Err(WireError::Protocol(
                "MLS group state rollback protection rejected older epoch".to_owned(),
            ));
        }
        self.group_states.insert(record.group_id.clone(), record);
        Ok(())
    }
}

impl MlsCommitSource for MemoryCryptoStore {
    fn commits_for_group(&self, group_id: &str) -> Vec<&MlsCommitEnvelope> {
        self.commits
            .get(group_id)
            .map(|commits| commits.iter().collect())
            .unwrap_or_default()
    }
}

impl CryptoStore for MemoryCryptoStore {
    fn mls_group_state(&self, group_id: &str) -> Option<&MlsGroupStateRecord> {
        self.group_states.get(group_id)
    }

    fn put_key_package(&mut self, record: MlsKeyPackageRecord) -> Result<()> {
        let key = record.keypackage_ref.clone();
        match self.key_packages.get(&key) {
            Some(existing)
                if crate::protocol::canonical::canonical_sha256(existing)?
                    == crate::protocol::canonical::canonical_sha256(&record)? =>
            {
                Ok(())
            }
            Some(_) => Err(Error::IdempotencyConflict(
                record.keypackage_ref.to_string(),
            )),
            None => {
                self.key_packages.insert(key, record);
                Ok(())
            }
        }
    }

    fn key_package(
        &self,
        principal_id: &DidCoreId,
        device_id: &DeviceId,
    ) -> Option<&MlsKeyPackageRecord> {
        self.key_packages_for_device(principal_id, device_id)
            .into_iter()
            .find(|record| record.is_usable())
    }

    fn key_packages_for_device(
        &self,
        principal_id: &DidCoreId,
        device_id: &DeviceId,
    ) -> Vec<&MlsKeyPackageRecord> {
        self.key_packages
            .values()
            .filter(|record| {
                matches!(
                    &record.endpoint,
                    crate::protocol::MlsEndpointIdentity::HumanDevice {
                        principal_id: owner,
                        device_id: owner_device,
                    } if owner == principal_id && owner_device == device_id
                )
            })
            .collect()
    }

    fn put_welcome(&mut self, record: MlsWelcomeEnvelope) -> Result<()> {
        if record.group_id.is_empty() {
            return Err(Error::Protocol("MLS welcome group_id is empty".to_owned()));
        }
        if let Some(existing) = self.welcomes.iter().find(|welcome| {
            welcome.group_id == record.group_id
                && welcome.epoch == record.epoch
                && welcome.recipient == record.recipient
        }) {
            return if existing.welcome_hash == record.welcome_hash {
                Ok(())
            } else {
                Err(Error::IdempotencyConflict(format!(
                    "welcome:{}:{}:{}",
                    record.group_id,
                    record.epoch,
                    record.recipient.actor_id()
                )))
            };
        }
        self.welcome_states
            .insert(record.welcome_hash.clone(), MlsWelcomeState::Received);
        self.welcomes.push(record);
        Ok(())
    }

    fn welcomes_for_device(
        &self,
        principal_id: &DidCoreId,
        device_id: &DeviceId,
    ) -> Vec<&MlsWelcomeEnvelope> {
        self.welcomes
            .iter()
            .filter(|welcome| {
                matches!(
                    &welcome.recipient,
                    crate::protocol::MlsEndpointIdentity::HumanDevice {
                        principal_id: owner,
                        device_id: owner_device,
                    } if owner == principal_id && owner_device == device_id
                )
            })
            .collect()
    }

    fn welcomes_for_endpoint(
        &self,
        endpoint: &crate::protocol::MlsEndpointIdentity,
    ) -> Vec<&MlsWelcomeEnvelope> {
        self.welcomes
            .iter()
            .filter(|welcome| &welcome.recipient == endpoint)
            .collect()
    }

    fn mark_welcome_accepted(&mut self, welcome_hash: &crate::protocol::Hash) -> Result<()> {
        let state = self
            .welcome_states
            .get_mut(welcome_hash)
            .ok_or_else(|| Error::Protocol(format!("MLS welcome not found: {welcome_hash}")))?;
        match state {
            MlsWelcomeState::Received | MlsWelcomeState::Accepted => {
                *state = MlsWelcomeState::Accepted;
                Ok(())
            }
            MlsWelcomeState::Consumed => Ok(()),
        }
    }

    fn mark_welcome_consumed(&mut self, welcome_hash: &crate::protocol::Hash) -> Result<()> {
        let state = self
            .welcome_states
            .get_mut(welcome_hash)
            .ok_or_else(|| Error::Protocol(format!("MLS welcome not found: {welcome_hash}")))?;
        match state {
            MlsWelcomeState::Accepted | MlsWelcomeState::Consumed => {
                *state = MlsWelcomeState::Consumed;
                Ok(())
            }
            MlsWelcomeState::Received => Err(Error::Protocol(
                "MLS welcome must be accepted before consumption".to_owned(),
            )),
        }
    }

    fn welcome_state(&self, welcome_hash: &crate::protocol::Hash) -> Option<MlsWelcomeState> {
        self.welcome_states.get(welcome_hash).copied()
    }

    fn put_commit(&mut self, record: MlsCommitEnvelope) -> Result<()> {
        if record.group_id.is_empty() {
            return Err(Error::Protocol("MLS commit group_id is empty".to_owned()));
        }
        let commits = self.commits.entry(record.group_id.clone()).or_default();
        if commits
            .iter()
            .any(|commit| commit.commit_digest == record.commit_digest)
        {
            return Ok(());
        }
        if commits.iter().any(|commit| commit.epoch == record.epoch) {
            return Err(Error::IdempotencyConflict(format!(
                "commit:{}:{}",
                record.group_id, record.epoch
            )));
        }
        commits.push(record);
        Ok(())
    }

    fn put_epoch_secret(&mut self, record: MlsEpochSecretRecord) -> Result<()> {
        self.epoch_secrets
            .insert((record.group_id.clone(), record.epoch), record);
        Ok(())
    }

    fn epoch_secret(&self, group_id: &str, epoch: u64) -> Option<&MlsEpochSecretRecord> {
        self.epoch_secrets.get(&(group_id.to_owned(), epoch))
    }

    fn put_device_verification(&mut self, record: StoredDeviceVerification) -> Result<()> {
        self.device_verifications.insert(
            (record.principal_id.clone(), record.device_id.clone()),
            record,
        );
        Ok(())
    }

    fn device_verification(
        &self,
        principal_id: &DidCoreId,
        device_id: &DeviceId,
    ) -> Option<&StoredDeviceVerification> {
        self.device_verifications
            .get(&(principal_id.clone(), device_id.clone()))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use serde_json::json;

    use super::*;
    use crate::protocol::{Hash, RealmId};

    fn principal_id(name: &str) -> DidCoreId {
        DidCoreId::new(format!("ak:did_core:webvh:z6mkfixture:{name}.example")).unwrap()
    }

    fn device(id: &str) -> DeviceId {
        let mut acc = 0xcbf29ce484222325u64;
        for byte in id.bytes() {
            acc = (acc ^ u64::from(byte)).wrapping_mul(0x100000001b3);
        }
        DeviceId::new(format!(
            "ak:device:01904100-0000-7000-8000-{:012x}",
            acc & 0x0000_ffff_ffff_ffff
        ))
        .unwrap()
    }

    #[derive(Clone, Default)]
    struct TestAcceptedStore {
        state: Arc<Mutex<VersionedAcceptedMlsArtifactState>>,
        fail_write: Arc<AtomicBool>,
    }

    impl AcceptedMlsArtifactStore for TestAcceptedStore {
        fn load_accepted_mls_artifacts(&self) -> Result<VersionedAcceptedMlsArtifactState> {
            self.state
                .lock()
                .map_err(|_| Error::Protocol("test accepted store lock poisoned".to_owned()))
                .map(|state| state.clone())
        }

        fn compare_and_swap_accepted_mls_artifacts<'a>(
            &'a self,
            expected_revision: u64,
            snapshot: &'a AcceptedMlsArtifactState,
        ) -> impl Future<Output = Result<bool>> + MaybeSend + 'a {
            async move {
                if self.fail_write.load(Ordering::SeqCst) {
                    return Err(Error::Protocol(
                        "injected accepted artifact write failure".to_owned(),
                    ));
                }
                let mut state = self
                    .state
                    .lock()
                    .map_err(|_| Error::Protocol("test accepted store lock poisoned".to_owned()))?;
                if state.revision != expected_revision {
                    return Ok(false);
                }
                state.revision += 1;
                state.snapshot = snapshot.clone();
                Ok(true)
            }
        }
    }

    struct TestApplicator {
        group_id: String,
        calls: AtomicUsize,
    }

    impl AcceptedMlsArtifactApplicator for TestApplicator {
        fn prepare<'a>(
            &'a self,
            event: &'a Event,
            previous: Option<&'a QueuedMlsLocalCheckpoint>,
        ) -> impl Future<Output = Result<PreparedAcceptedMlsArtifact>> + MaybeSend + 'a {
            async move {
                self.calls.fetch_add(1, Ordering::SeqCst);
                let (epoch, admission_epoch, transition) = match event.kind {
                    EventKind::MlsGenesis => (0, 0, event.event_id.clone()),
                    EventKind::MlsCommit => {
                        let previous = previous.ok_or_else(|| {
                            Error::Protocol("test Commit lacks a prior snapshot".to_owned())
                        })?;
                        (1, previous.admission_epoch, event.event_id.clone())
                    }
                    EventKind::MlsWelcome => {
                        let epoch = event
                            .payload
                            .get("epoch")
                            .and_then(serde_json::Value::as_u64)
                            .unwrap();
                        (
                            epoch,
                            epoch,
                            EventId::new(
                                event
                                    .payload
                                    .get("commit_ref")
                                    .and_then(serde_json::Value::as_str)
                                    .unwrap()
                                    .to_owned(),
                            )?,
                        )
                    }
                    _ => {
                        return Err(Error::Protocol(
                            "test applicator received a non-MLS artifact".to_owned(),
                        ));
                    }
                };
                Ok(PreparedAcceptedMlsArtifact {
                    history_secret: QueuedMlsHistorySecret {
                        group_id: self.group_id.clone(),
                        epoch,
                        transition_ref: transition.clone(),
                        ciphertext: vec![4],
                    },
                    snapshot: QueuedMlsLocalCheckpoint {
                        realm_id: "realm".to_owned(),
                        group_id: self.group_id.clone(),
                        epoch,
                        admission_epoch,
                        group_state_event_id: Some(transition),
                        salt_hex: "01".to_owned(),
                        ciphertext_hex: "02".to_owned(),
                        mac_hex: "03".to_owned(),
                        recorded_at: Utc::now(),
                        epoch_started_at: Utc::now(),
                        app_messages_observed: 0,
                        aead_version: 1,
                    },
                })
            }
        }
    }

    fn artifact_event(kind: EventKind, sequence: u64) -> Event {
        arkret_wire::test_support::raw_event(
            kind.as_str(),
            ScopeRef::Realm {
                realm_id: RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19")
                    .unwrap(),
            },
            principal_id("alice"),
            principal_id("server"),
            sequence,
            arkret_test_kit::pinned_hlc(u16::try_from(sequence).expect("fixture HLC counter")),
            json!({}),
        )
        .unwrap()
    }

    fn station_artifact(
        event: Event,
        scope: ScopeRef,
        group_id: &str,
        epoch: u64,
        winning_transition_ref: EventId,
        application: AcceptedMlsApplication,
    ) -> StationAcceptedMlsArtifact {
        let transition_head = arkret_models_crypto::MlsEpochHead {
            transition_ref: winning_transition_ref.clone(),
            transition_event_digest: winning_transition_ref.event_digest(),
            mls_transition_digest: winning_transition_ref.event_digest(),
            effective_scope: scope.clone(),
            mls_group_id: arkret_wire::Base64UrlString::new(group_id).unwrap(),
            previous_epoch: epoch.saturating_sub(1),
            next_epoch: epoch,
            content_scheme: arkret_wire::ContentScheme::MlsRfc9420,
        };
        StationAcceptedMlsArtifact {
            transition_head,
            event_digest: event.event_id.identity_key().event_digest(),
            event,
            scope,
            group_id: group_id.to_owned(),
            epoch,
            winning_transition_ref,
            application,
        }
    }

    #[tokio::test]
    async fn accepted_genesis_commit_and_welcome_share_one_durable_path() {
        let realm_id =
            RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19").unwrap();
        let scope = ScopeRef::Realm { realm_id };
        let group_id = scope.canonical_mls_group_id().unwrap();
        let store = TestAcceptedStore::default();
        let consumer = AcceptedMlsArtifactConsumer::new(store.clone());
        let applicator = TestApplicator {
            group_id: group_id.clone(),
            calls: AtomicUsize::new(0),
        };
        let genesis = artifact_event(EventKind::MlsGenesis, 1);
        let commit = artifact_event(EventKind::MlsCommit, 2);
        let mut welcome = artifact_event(EventKind::MlsWelcome, 3);
        welcome.payload =
            serde_json::from_value(json!({"epoch": 1, "commit_ref": commit.event_id})).unwrap();

        consumer
            .consume_accepted(
                station_artifact(
                    genesis.clone(),
                    scope.clone(),
                    &group_id,
                    0,
                    genesis.event_id.clone(),
                    AcceptedMlsApplication::Genesis,
                ),
                &applicator,
            )
            .await
            .unwrap();

        let restarted = AcceptedMlsArtifactConsumer::new(store.clone());
        restarted
            .consume_accepted(
                station_artifact(
                    commit.clone(),
                    scope.clone(),
                    &group_id,
                    1,
                    commit.event_id.clone(),
                    AcceptedMlsApplication::Commit {
                        base_epoch: 0,
                        base_epoch_ref: genesis.event_id.to_string(),
                    },
                ),
                &applicator,
            )
            .await
            .unwrap();
        let duplicate_welcome = restarted
            .consume_accepted(
                station_artifact(
                    welcome.clone(),
                    scope.clone(),
                    &group_id,
                    1,
                    commit.event_id.clone(),
                    AcceptedMlsApplication::Welcome,
                ),
                &applicator,
            )
            .await
            .unwrap_err();
        assert!(duplicate_welcome.to_string().contains("cannot replace"));

        let ready = restarted
            .ready_checkpoint(&scope, &group_id)
            .unwrap()
            .unwrap();
        assert_eq!(ready.epoch, 1);
        assert_eq!(ready.admission_epoch, 0);
        assert_eq!(ready.group_state_event_id, Some(commit.event_id.clone()));
        assert_eq!(applicator.calls.load(Ordering::SeqCst), 2);
        assert_eq!(
            store
                .load_accepted_mls_artifacts()
                .unwrap()
                .snapshot
                .artifacts
                .len(),
            2
        );
        assert_eq!(
            store
                .load_accepted_mls_artifacts()
                .unwrap()
                .snapshot
                .history_secrets
                .len(),
            2
        );
        let joining = AcceptedMlsArtifactConsumer::new(TestAcceptedStore::default());
        joining
            .consume_accepted(
                station_artifact(
                    welcome,
                    scope.clone(),
                    &group_id,
                    1,
                    commit.event_id,
                    AcceptedMlsApplication::Welcome,
                ),
                &applicator,
            )
            .await
            .unwrap();
        assert_eq!(
            joining
                .ready_checkpoint(&scope, &group_id)
                .unwrap()
                .unwrap()
                .epoch,
            1
        );
    }

    #[tokio::test]
    async fn exact_replay_does_not_reapply_the_artifact() {
        let realm_id =
            RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19").unwrap();
        let scope = ScopeRef::Realm { realm_id };
        let group_id = scope.canonical_mls_group_id().unwrap();
        let consumer = AcceptedMlsArtifactConsumer::new(TestAcceptedStore::default());
        let applicator = TestApplicator {
            group_id: group_id.clone(),
            calls: AtomicUsize::new(0),
        };
        let event = artifact_event(EventKind::MlsGenesis, 1);
        let accepted = station_artifact(
            event.clone(),
            scope,
            &group_id,
            0,
            event.event_id.clone(),
            AcceptedMlsApplication::Genesis,
        );
        consumer
            .consume_accepted(accepted.clone(), &applicator)
            .await
            .unwrap();
        let replay = consumer
            .consume_accepted(accepted, &applicator)
            .await
            .unwrap();
        assert_eq!(
            replay.outcome,
            AcceptedMlsArtifactCommitOutcome::ExactReplay
        );
        assert_eq!(applicator.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn ready_snapshot_rejects_mismatched_retained_epoch_metadata() {
        let event = artifact_event(EventKind::MlsGenesis, 1);
        let scope = event.scope_ref.clone();
        let group_id = scope.canonical_mls_group_id().unwrap();
        let store = TestAcceptedStore::default();
        let consumer = AcceptedMlsArtifactConsumer::new(store.clone());
        let applicator = TestApplicator {
            group_id: group_id.clone(),
            calls: AtomicUsize::new(0),
        };
        consumer
            .consume_accepted(
                station_artifact(
                    event.clone(),
                    scope.clone(),
                    &group_id,
                    0,
                    event.event_id.clone(),
                    AcceptedMlsApplication::Genesis,
                ),
                &applicator,
            )
            .await
            .unwrap();
        assert!(
            consumer
                .ready_checkpoint(&scope, &group_id)
                .unwrap()
                .is_some()
        );
        let mut current = store.load_accepted_mls_artifacts().unwrap();
        let artifact = current
            .snapshot
            .artifacts
            .get_mut(event.event_id.as_str())
            .unwrap();
        artifact.transition_head.next_epoch = 1;
        assert!(
            store
                .compare_and_swap_accepted_mls_artifacts(current.revision, &current.snapshot)
                .await
                .unwrap()
        );
        assert!(consumer.ready_checkpoint(&scope, &group_id).is_err());
    }

    #[tokio::test]
    async fn failed_durable_write_never_publishes_ready() {
        let realm_id =
            RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19").unwrap();
        let scope = ScopeRef::Realm { realm_id };
        let group_id = scope.canonical_mls_group_id().unwrap();
        let store = TestAcceptedStore::default();
        store.fail_write.store(true, Ordering::SeqCst);
        let consumer = AcceptedMlsArtifactConsumer::new(store);
        let applicator = TestApplicator {
            group_id: group_id.clone(),
            calls: AtomicUsize::new(0),
        };
        let event = artifact_event(EventKind::MlsGenesis, 1);
        let error = consumer
            .consume_accepted(
                station_artifact(
                    event.clone(),
                    scope.clone(),
                    &group_id,
                    0,
                    event.event_id,
                    AcceptedMlsApplication::Genesis,
                ),
                &applicator,
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("write failure"));
        assert!(
            consumer
                .ready_checkpoint(&scope, &group_id)
                .unwrap()
                .is_none()
        );
        assert!(
            consumer
                .store()
                .load_accepted_mls_artifacts()
                .unwrap()
                .snapshot
                .history_secrets
                .is_empty()
        );
    }

    #[test]
    fn memory_crypto_store_roundtrips_mls_records_and_verification() {
        let alice = principal_id("alice");
        let device_id = device("phone");
        let mut store = MemoryCryptoStore::new();

        store
            .put_mls_group_state(MlsGroupStateRecord {
                group_id: "group1".to_owned(),
                endpoint: crate::protocol::MlsEndpointIdentity::human_device(
                    alice.clone(),
                    device_id.clone(),
                ),
                epoch: 3,
                serialized_state: b"state".to_vec(),
                updated_at: Utc::now(),
            })
            .unwrap();
        assert_eq!(store.mls_group_state("group1").unwrap().epoch, 3);

        store
            .put_key_package(MlsKeyPackageRecord {
                keypackage_id: format!("ak:mls:kp:{}", uuid::Uuid::now_v7()),
                endpoint: crate::protocol::MlsEndpointIdentity::human_device(
                    alice.clone(),
                    device_id.clone(),
                ),
                keypackage: "kp".to_owned(),
                keypackage_ref: Hash::new(
                    "sha256:1111111111111111111111111111111111111111111111111111111111111111",
                )
                .unwrap(),
                cipher_suites: vec!["suite".to_owned()],
                capabilities: Vec::new(),
                state: crate::protocol::MlsKeyPackageState::Published,
                claim_id: None,
                created_at: Utc::now(),
                expires_at: None,
                last_resort: false,
            })
            .unwrap();
        assert!(store.key_package(&alice, &device_id).is_some());

        store
            .put_device_verification(StoredDeviceVerification {
                principal_id: alice.clone(),
                device_id: device_id.clone(),
                state: DeviceVerificationState::Verified,
                updated_at: Utc::now(),
            })
            .unwrap();
        assert_eq!(
            store.device_verification(&alice, &device_id).unwrap().state,
            DeviceVerificationState::Verified
        );
    }

    #[test]
    fn crypto_store_rejects_group_state_rollback() {
        let alice = principal_id("alice");
        let device_id = device("phone");
        let mut store = MemoryCryptoStore::new();
        store
            .put_mls_group_state(MlsGroupStateRecord {
                group_id: "group1".to_owned(),
                endpoint: crate::protocol::MlsEndpointIdentity::human_device(
                    alice.clone(),
                    device_id.clone(),
                ),
                epoch: 5,
                serialized_state: b"newer".to_vec(),
                updated_at: Utc::now(),
            })
            .unwrap();
        assert!(
            store
                .put_mls_group_state(MlsGroupStateRecord {
                    group_id: "group1".to_owned(),
                    endpoint: crate::protocol::MlsEndpointIdentity::human_device(alice, device_id),
                    epoch: 4,
                    serialized_state: b"older".to_vec(),
                    updated_at: Utc::now(),
                })
                .is_err()
        );
        assert_eq!(store.mls_group_state("group1").unwrap().epoch, 5);
    }

    #[test]
    fn memory_crypto_store_deduplicates_welcomes_and_commits() {
        let alice = principal_id("alice");
        let device_id = device("phone");
        let mut store = MemoryCryptoStore::new();
        let welcome = MlsWelcomeEnvelope {
            group_id: "group1".to_owned(),
            epoch: 1,
            recipient: crate::protocol::MlsEndpointIdentity::human_device(
                alice.clone(),
                device_id.clone(),
            ),
            welcome: "welcome".to_owned(),
            welcome_hash: Hash::new(
                "sha256:2222222222222222222222222222222222222222222222222222222222222222",
            )
            .unwrap(),
            ratchet_tree: None,
        };

        store.put_welcome(welcome.clone()).unwrap();
        store.put_welcome(welcome.clone()).unwrap();
        assert_eq!(store.welcomes_for_device(&alice, &device_id).len(), 1);
        assert!(store.mark_welcome_consumed(&welcome.welcome_hash).is_err());
        store.mark_welcome_accepted(&welcome.welcome_hash).unwrap();
        store.mark_welcome_consumed(&welcome.welcome_hash).unwrap();
        store.mark_welcome_consumed(&welcome.welcome_hash).unwrap();
        assert_eq!(
            store.welcome_state(&welcome.welcome_hash),
            Some(MlsWelcomeState::Consumed)
        );

        let mut conflicting_welcome = welcome;
        conflicting_welcome.welcome_hash =
            Hash::new("sha256:3333333333333333333333333333333333333333333333333333333333333333")
                .unwrap();
        assert!(matches!(
            store.put_welcome(conflicting_welcome),
            Err(Error::IdempotencyConflict(_))
        ));

        let commit = MlsCommitEnvelope {
            group_id: "group1".to_owned(),
            epoch: 2,
            commit: "commit".to_owned(),
            commit_digest: Hash::new(
                "sha256:4444444444444444444444444444444444444444444444444444444444444444",
            )
            .unwrap(),
            ratchet_tree: None,
        };
        store.put_commit(commit.clone()).unwrap();
        store.put_commit(commit.clone()).unwrap();
        assert_eq!(store.commits_for_group("group1").len(), 1);

        let mut conflicting_commit = commit;
        conflicting_commit.commit_digest =
            Hash::new("sha256:5555555555555555555555555555555555555555555555555555555555555555")
                .unwrap();
        assert!(matches!(
            store.put_commit(conflicting_commit),
            Err(Error::IdempotencyConflict(_))
        ));
    }
}
