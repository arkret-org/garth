//! User profile management for the Garth client runtime.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    ACTOR_PROFILE_SCHEMA, ActorKind, ActorProfile, ActorProfileId, ActorStatus, AppletId, BlobRef,
    Did, Error, Hash, Hlc, ObjectCreatePayload, ObjectPatchPayload, Patch, RealmId, Result,
};

/// User profile state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserProfile {
    /// User DID.
    pub user_id: Did,
    /// Display name.
    pub display_name: Option<String>,
    /// Canonical Arkret avatar Blob reference.
    pub avatar_blob_ref: Option<BlobRef>,
    /// Bio/description.
    pub bio: Option<String>,
    /// Monotonic profile version.
    pub version: u64,
    /// Last update time.
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub updated_at: DateTime<Utc>,
}

impl UserProfile {
    /// Create an empty profile at version 0.
    pub fn new(user_id: Did) -> Self {
        Self {
            user_id,
            display_name: None,
            avatar_blob_ref: None,
            bio: None,
            version: 0,
            updated_at: Utc::now(),
        }
    }
}

/// External device approval mode for sovereign deployments.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalDeviceApprovalMode {
    Allow,
    RequireApproval,
    Deny,
}

/// Data classification level used by sovereign deployment policy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataClassification {
    Public,
    Internal,
    Confidential,
    Restricted,
}

/// Sovereign deployment policy primitives for profiles and realms.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SovereignDeploymentPolicy {
    pub deployment_id: String,
    pub owner: Did,
    pub home_domain: String,
    #[serde(default)]
    pub closed_federation: bool,
    #[serde(default)]
    pub federation_allowlist: BTreeSet<String>,
    #[serde(default)]
    pub resolver_pins: BTreeMap<String, String>,
    pub external_device_approval: ExternalDeviceApprovalMode,
    #[serde(default)]
    pub data_classification: BTreeMap<String, DataClassification>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
}

impl SovereignDeploymentPolicy {
    /// Create a closed-federation policy owned by a DID.
    pub fn closed(owner: Did, home_domain: impl Into<String>) -> Self {
        Self {
            deployment_id: format!("deploy_{}", uuid::Uuid::now_v7()),
            owner,
            home_domain: home_domain.into(),
            closed_federation: true,
            federation_allowlist: BTreeSet::new(),
            resolver_pins: BTreeMap::new(),
            external_device_approval: ExternalDeviceApprovalMode::RequireApproval,
            data_classification: BTreeMap::new(),
            created_at: Utc::now(),
        }
    }

    /// Add a federated domain to the allowlist.
    pub fn allow_domain(&mut self, domain: impl Into<String>) {
        self.federation_allowlist.insert(domain.into());
    }

    /// Check whether a federated domain is allowed.
    pub fn is_domain_allowed(&self, domain: &str) -> bool {
        !self.closed_federation || self.federation_allowlist.contains(domain)
    }

    /// Pin a DID resolver endpoint or trust root.
    pub fn pin_resolver(&mut self, did_method: impl Into<String>, resolver_ref: impl Into<String>) {
        self.resolver_pins
            .insert(did_method.into(), resolver_ref.into());
    }

    /// Classify a data subject reference.
    pub fn classify(&mut self, subject_ref: impl Into<String>, classification: DataClassification) {
        self.data_classification
            .insert(subject_ref.into(), classification);
    }
}

/// Realm export manifest used for validation before import.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RealmExportManifest {
    pub export_id: String,
    pub realm_id: RealmId,
    pub exported_by: Did,
    pub source_service_id: Did,
    pub event_count: u64,
    pub state_digest: String,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
}

/// Result of validating an import manifest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RealmImportValidation {
    pub accepted: bool,
    pub errors: Vec<String>,
}

/// Service replacement contract for sovereign deployments.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceReplacementPlan {
    pub old_service_id: Did,
    pub new_service_id: Did,
    pub reason: String,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub effective_at: DateTime<Utc>,
    #[serde(default)]
    pub preserve_service_history: bool,
}

impl ServiceReplacementPlan {
    /// Validate a service replacement contract.
    pub fn validate(&self, now: DateTime<Utc>) -> Result<()> {
        if self.old_service_id == self.new_service_id {
            return Err(Error::Protocol(
                "replacement service must change".to_owned(),
            ));
        }
        if self.effective_at < now {
            return Err(Error::Protocol(
                "replacement effective time is in the past".to_owned(),
            ));
        }
        if self.reason.trim().is_empty() {
            return Err(Error::Protocol("replacement reason is empty".to_owned()));
        }
        Ok(())
    }
}

/// Validate a Realm import manifest against expected local constraints.
pub fn validate_realm_import(
    manifest: &RealmExportManifest,
    expected_realm_id: Option<&RealmId>,
    allowed_source_services: &BTreeSet<Did>,
) -> RealmImportValidation {
    let mut errors = Vec::new();
    if let Some(expected_realm_id) = expected_realm_id
        && &manifest.realm_id != expected_realm_id
    {
        errors.push("Realm id mismatch".to_owned());
    }
    if manifest.event_count == 0 {
        errors.push("export contains no events".to_owned());
    }
    if !manifest.state_digest.starts_with("sha256:") {
        errors.push("state hash is not a sha256 digest".to_owned());
    }
    if !allowed_source_services.is_empty()
        && !allowed_source_services.contains(&manifest.source_service_id)
    {
        errors.push("source service is not allowed".to_owned());
    }

    RealmImportValidation {
        accepted: errors.is_empty(),
        errors,
    }
}

/// Optional TSP trust binding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TspTrustBinding {
    pub subject: Did,
    pub tsp_endpoint: String,
    pub trust_anchor: String,
    pub binding_proof: String,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub expires_at: Option<DateTime<Utc>>,
}

impl TspTrustBinding {
    /// Check whether the binding is active.
    pub fn is_active(&self, at: DateTime<Utc>) -> bool {
        !self.binding_proof.is_empty()
            && self
                .expires_at
                .map(|expires_at| expires_at > at)
                .unwrap_or(true)
    }
}

/// Pairwise control message kind.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PairwiseControlMessageKind {
    DeviceApprovalRequest,
    DeviceApprovalDecision,
    ResolverPinUpdate,
    TrustBindingUpdate,
    KillSwitch,
    Custom(String),
}

/// Pairwise control message hook payload.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PairwiseControlMessage {
    pub message_id: String,
    pub sender: Did,
    pub recipient: Did,
    pub kind: PairwiseControlMessageKind,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub payload: Value,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub expires_at: Option<DateTime<Utc>>,
}

/// In-memory profile manager with version history.
#[derive(Clone, Debug, Default)]
pub struct ProfileManager {
    profiles: BTreeMap<Did, UserProfile>,
    history: BTreeMap<Did, Vec<UserProfile>>,
}

impl ProfileManager {
    /// Create an empty profile manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the current profile.
    pub fn profile(&self, user_id: &Did) -> Option<&UserProfile> {
        self.profiles.get(user_id)
    }

    /// Get profile version history.
    pub fn history(&self, user_id: &Did) -> Vec<&UserProfile> {
        self.history
            .get(user_id)
            .map(|history| history.iter().collect())
            .unwrap_or_default()
    }

    /// Replace profile fields and increment version.
    pub fn update_profile(
        &mut self,
        user_id: Did,
        display_name: Option<String>,
        avatar_blob_ref: Option<BlobRef>,
        bio: Option<String>,
    ) -> UserProfile {
        let mut profile = self
            .profiles
            .remove(&user_id)
            .unwrap_or_else(|| UserProfile::new(user_id.clone()));
        profile.display_name = display_name;
        profile.avatar_blob_ref = avatar_blob_ref;
        profile.bio = bio;
        profile.version += 1;
        profile.updated_at = Utc::now();
        self.profiles.insert(user_id.clone(), profile.clone());
        self.history
            .entry(user_id)
            .or_default()
            .push(profile.clone());
        profile
    }

    /// Update display name only.
    pub fn set_display_name(
        &mut self,
        user_id: Did,
        display_name: impl Into<String>,
    ) -> UserProfile {
        let current = self
            .profiles
            .get(&user_id)
            .cloned()
            .unwrap_or_else(|| UserProfile::new(user_id.clone()));
        self.update_profile(
            user_id,
            Some(display_name.into()),
            current.avatar_blob_ref,
            current.bio,
        )
    }

    /// Update the canonical avatar Blob reference only.
    pub fn set_avatar_blob_ref(&mut self, user_id: Did, avatar_blob_ref: BlobRef) -> UserProfile {
        let current = self
            .profiles
            .get(&user_id)
            .cloned()
            .unwrap_or_else(|| UserProfile::new(user_id.clone()));
        self.update_profile(
            user_id,
            current.display_name,
            Some(avatar_blob_ref),
            current.bio,
        )
    }

    /// Update bio only.
    pub fn set_bio(&mut self, user_id: Did, bio: impl Into<String>) -> UserProfile {
        let current = self
            .profiles
            .get(&user_id)
            .cloned()
            .unwrap_or_else(|| UserProfile::new(user_id.clone()));
        self.update_profile(
            user_id,
            current.display_name,
            current.avatar_blob_ref,
            Some(bio.into()),
        )
    }

    /// Get a specific profile version.
    pub fn profile_version(&self, user_id: &Did, version: u64) -> Result<&UserProfile> {
        self.history
            .get(user_id)
            .and_then(|history| history.iter().find(|profile| profile.version == version))
            .ok_or_else(|| Error::Protocol("profile version not found".to_owned()))
    }
}

// ─── S-9 (savfox SDK gap): ak.profile.create / ak.profile.update builder ──

/// Operation kind discriminant for [`ProfileCreateBuilder::build`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProfileEventKind {
    /// `ak.profile.create` — first appearance of an actor profile.
    Create,
    /// `ak.profile.update` — subsequent revisions.
    Update,
}

impl ProfileEventKind {
    /// Wire string for `Event::kind`.
    pub fn as_str(self) -> &'static str {
        match self {
            ProfileEventKind::Create => "ak.profile.create",
            ProfileEventKind::Update => "ak.profile.update",
        }
    }
}

/// Build a `ak.profile.create` / `ak.profile.update` Event Envelope
/// payload using the spec wire shapes:
///
/// - create: `{ "object": ActorProfile }`
/// - update: `object_patch_payload` with `target_ref`
///
/// Applet-managed Ghost Actor profiles use `actor_kind = "integration"`;
/// `managed_by_applet` and `external_ref` live under
/// `ActorProfile.profile_fields`, and accountability is represented only
/// by top-level `accountable_principal_ids`.
#[derive(Clone, Debug)]
pub struct ProfileCreateBuilder {
    realm_id: RealmId,
    actor_id: Did,
    profile_id: ActorProfileId,
    display_name: Option<String>,
    handle: Option<String>,
    agent_slug: Option<String>,
    avatar_blob_ref: Option<BlobRef>,
    actor_kind: Option<ActorKind>,
    status: Option<ActorStatus>,
    accountable_principal_ids: Vec<Did>,
    profile_fields: BTreeMap<String, Value>,
    kind: ProfileEventKind,
    authorization_ref: Option<String>,
    executed_by: Option<Did>,
    applet_id: Option<AppletId>,
    expected_state_digest: Option<Hash>,
}

impl ProfileCreateBuilder {
    /// Construct a new builder for a `ak.profile.create` Envelope.
    /// Switch to `ak.profile.update` via [`Self::for_update`].
    pub fn new(realm_id: RealmId, actor_id: Did) -> Self {
        Self {
            realm_id,
            actor_id,
            profile_id: new_actor_profile_id(),
            display_name: None,
            handle: None,
            agent_slug: None,
            avatar_blob_ref: None,
            actor_kind: None,
            status: None,
            accountable_principal_ids: Vec::new(),
            profile_fields: BTreeMap::new(),
            kind: ProfileEventKind::Create,
            authorization_ref: None,
            executed_by: None,
            applet_id: None,
            expected_state_digest: None,
        }
    }

    pub fn for_update(mut self, profile_id: ActorProfileId) -> Self {
        self.kind = ProfileEventKind::Update;
        self.profile_id = profile_id;
        self
    }

    pub fn with_actor_profile_id(mut self, profile_id: ActorProfileId) -> Self {
        self.profile_id = profile_id;
        self
    }

    pub fn with_display_name(mut self, display_name: impl Into<String>) -> Self {
        self.display_name = Some(display_name.into());
        self
    }

    pub fn with_handle(mut self, handle: impl Into<String>) -> Self {
        self.handle = Some(handle.into());
        self
    }

    /// Set the controller-scoped agent selector slug. Only meaningful when
    /// `actor_kind=agent` under `ak.profile.personal_agent_provisioning.v1`;
    /// it is a projection hint, never an authorization or discovery handle
    /// (`actor-profile.schema.json` `agent_slug`).
    pub fn with_agent_slug(mut self, agent_slug: impl Into<String>) -> Self {
        self.agent_slug = Some(agent_slug.into());
        self
    }

    pub fn with_avatar_blob_ref(mut self, avatar_blob_ref: BlobRef) -> Self {
        self.avatar_blob_ref = Some(avatar_blob_ref);
        self
    }

    pub fn with_bio(mut self, bio: impl Into<String>) -> Self {
        self.profile_fields
            .insert("bio".to_owned(), Value::String(bio.into()));
        self
    }

    pub fn with_actor_kind(mut self, actor_kind: ActorKind) -> Self {
        self.actor_kind = Some(actor_kind);
        self
    }

    pub fn with_status(mut self, status: ActorStatus) -> Self {
        self.status = Some(status);
        self
    }

    pub fn with_accountable_principal_ids(mut self, accountable_principal_ids: Vec<Did>) -> Self {
        self.accountable_principal_ids = accountable_principal_ids;
        self
    }

    /// Stamp this profile as an Applet-managed Ghost Actor. This emits the
    /// schema-legal shape from `applet-integration.md` §9:
    /// `actor_kind = "integration"`, `profile_fields.managed_by_applet`,
    /// and top-level `accountable_principal_ids`.
    pub fn with_ghost_actor_profile(
        mut self,
        applet_id: AppletId,
        accountable_principal_ids: Vec<Did>,
    ) -> Self {
        self.actor_kind = Some(ActorKind::Integration);
        self.profile_fields.insert(
            "managed_by_applet".to_owned(),
            Value::String(applet_id.to_string()),
        );
        self.accountable_principal_ids = accountable_principal_ids;
        self
    }

    /// Attach the bridge-side external reference (e.g. `{"slack_user_id":
    /// "U12345"}`) as `profile_fields.external_ref`.
    pub fn with_external_ref(mut self, external_ref: Value) -> Self {
        self.profile_fields
            .insert("external_ref".to_owned(), external_ref);
        self
    }

    pub fn with_profile_field(mut self, key: impl Into<String>, value: Value) -> Self {
        self.profile_fields.insert(key.into(), value);
        self
    }

    pub fn with_authorization_ref(mut self, authorization_ref: impl Into<String>) -> Self {
        self.authorization_ref = Some(authorization_ref.into());
        self
    }

    pub fn with_executed_by(mut self, executed_by: Did) -> Self {
        self.executed_by = Some(executed_by);
        self
    }

    pub fn with_applet_id(mut self, applet_id: AppletId) -> Self {
        self.applet_id = Some(applet_id);
        self
    }

    pub fn with_event_external_ref(mut self, external_ref: Value) -> Self {
        self.profile_fields
            .insert("external_ref".to_owned(), external_ref);
        self
    }

    pub fn with_expected_state_digest(mut self, expected_state_digest: Hash) -> Self {
        self.expected_state_digest = Some(expected_state_digest);
        self
    }

    /// Build the unsigned `Event` Envelope. Caller is responsible for
    /// `actor_seq` + `hlc` + (re-)signing via
    /// [`arkret_signatures::sign_event`].
    pub fn build(self, actor_seq: u64, hlc: Hlc) -> Result<crate::Event> {
        self.validate_authorization_fields()?;
        let content = match self.kind {
            ProfileEventKind::Create => self.create_payload()?,
            ProfileEventKind::Update => self.update_payload()?,
        };

        let mut event = crate::Event::new(
            self.kind.as_str(),
            self.realm_id.clone(),
            self.actor_id.clone(),
            actor_seq,
            hlc,
            content,
        )?;
        event.authorization_ref = self.authorization_ref;
        event.executed_by = self.executed_by;
        Ok(event)
    }

    fn create_payload(&self) -> Result<Value> {
        let display_name = self.display_name.clone().ok_or_else(|| {
            Error::Protocol("actor_profile.create requires display_name".to_owned())
        })?;
        if display_name.trim().is_empty() {
            return Err(Error::Protocol(
                "actor_profile.display_name must not be empty".to_owned(),
            ));
        }
        if display_name.chars().count() > 128 {
            return Err(Error::Protocol(
                "actor_profile.display_name must not exceed 128 chars".to_owned(),
            ));
        }

        let profile = ActorProfile {
            id: self.profile_id.clone(),
            schema: ACTOR_PROFILE_SCHEMA.to_owned(),
            realm_id: Some(self.realm_id.clone()),
            principal_id: self.actor_id.clone(),
            actor_kind: self.actor_kind.clone().unwrap_or(ActorKind::User),
            display_name,
            handle: self.handle.clone(),
            agent_slug: self.agent_slug.clone(),
            avatar_blob_ref: self.avatar_blob_ref.clone(),
            status: self.status.clone(),
            accountable_principal_ids: self.accountable_principal_ids.clone(),
            profile_fields: self.profile_fields.clone(),
            created_at: Utc::now(),
            updated_by: None,
            updated_at: None,
        };
        Ok(ObjectCreatePayload::new(profile).to_value()?)
    }

    fn update_payload(&self) -> Result<Value> {
        let mut patch = Patch::new();
        if let Some(display_name) = &self.display_name {
            patch.insert("display_name", Value::String(display_name.clone()))?;
        }
        if let Some(handle) = &self.handle {
            patch.insert("handle", Value::String(handle.clone()))?;
        }
        if let Some(avatar_blob_ref) = &self.avatar_blob_ref {
            patch.insert(
                "avatar_blob_ref",
                Value::String(avatar_blob_ref.to_string()),
            )?;
        }
        if let Some(actor_kind) = &self.actor_kind {
            patch.insert("actor_kind", serde_json::to_value(actor_kind)?)?;
        }
        if let Some(status) = &self.status {
            patch.insert("status", serde_json::to_value(status)?)?;
        }
        if !self.accountable_principal_ids.is_empty() {
            patch.insert(
                "accountable_principal_ids",
                Value::Array(
                    self.accountable_principal_ids
                        .iter()
                        .map(|did| Value::String(did.to_string()))
                        .collect(),
                ),
            )?;
        }
        for (key, value) in &self.profile_fields {
            patch.insert(format!("profile_fields.{key}"), value.clone())?;
        }
        let payload =
            ObjectPatchPayload::for_target(self.profile_id.to_string(), patch).map(|payload| {
                if let Some(expected_state_digest) = &self.expected_state_digest {
                    payload.with_expected_state_digest(expected_state_digest.clone())
                } else {
                    payload
                }
            })?;
        Ok(payload.to_value()?)
    }

    fn validate_authorization_fields(&self) -> Result<()> {
        if let Some(authorization_ref) = &self.authorization_ref
            && authorization_ref.trim().is_empty()
        {
            return Err(Error::Protocol(
                "authorization_ref must not be empty".to_owned(),
            ));
        }
        if self.executed_by.is_some() && self.authorization_ref.is_none() {
            return Err(Error::Protocol(
                "executed_by requires authorization_ref on profile event".to_owned(),
            ));
        }
        if self.applet_id.is_some() && self.authorization_ref.is_none() {
            return Err(Error::Protocol(
                "applet_id requires authorization_ref on profile event".to_owned(),
            ));
        }
        Ok(())
    }
}

fn new_actor_profile_id() -> ActorProfileId {
    ActorProfileId::new(format!("ak:actor_profile:{}", uuid::Uuid::now_v7()))
        .expect("uuid v7 produces a valid actor_profile id")
}

#[cfg(test)]
mod profile_builder_tests {
    use super::*;

    fn realm() -> RealmId {
        RealmId::new("ak:realm:01904100-0000-7000-8000-65c7feb295d7").unwrap()
    }

    fn alice() -> Did {
        Did::new("did:webvh:z6mkfixture:alice.example").unwrap()
    }

    fn applet_owner() -> Did {
        Did::new("did:webvh:z6mkfixture:owner.example").unwrap()
    }

    fn profile_id() -> ActorProfileId {
        ActorProfileId::new("ak:actor_profile:01904100-0000-7000-8000-aaaaaaaaaaaa").unwrap()
    }

    fn applet_id() -> AppletId {
        AppletId::new("ak:applet:01904100-0000-7000-8000-aaaaaaaaaaaa").unwrap()
    }

    fn hlc() -> Hlc {
        Hlc::new("01970e589d21-0004-a13f9c2e").unwrap()
    }

    #[test]
    fn profile_create_builder_stamps_kind_and_actor_id() {
        let event = ProfileCreateBuilder::new(realm(), alice())
            .with_display_name("Alice")
            .build(1, hlc())
            .unwrap();
        assert_eq!(event.kind, "ak.profile.create");
        assert_eq!(
            event.payload["object"]["principal_id"],
            "did:webvh:z6mkfixture:alice.example"
        );
        assert_eq!(event.payload["object"]["actor_kind"], "user");
        assert_eq!(event.payload["object"]["display_name"], "Alice");
    }

    #[test]
    fn profile_update_switches_event_kind() {
        let event = ProfileCreateBuilder::new(realm(), alice())
            .for_update(profile_id())
            .with_display_name("Alice 2")
            .build(2, hlc())
            .unwrap();
        assert_eq!(event.kind, "ak.profile.update");
        assert_eq!(
            event.payload["target_ref"],
            "ak:actor_profile:01904100-0000-7000-8000-aaaaaaaaaaaa"
        );
        assert_eq!(event.payload["patch"]["display_name"], "Alice 2");
    }

    #[test]
    fn profile_ghost_kind_stamps_required_fields() {
        let event = ProfileCreateBuilder::new(realm(), alice())
            .with_ghost_actor_profile(applet_id(), vec![applet_owner()])
            .with_display_name("Alice on Slack")
            .with_external_ref(serde_json::json!({"slack_user_id": "U12345"}))
            .build(1, hlc())
            .unwrap();
        let object = &event.payload["object"];
        assert_eq!(object["actor_kind"], "integration");
        assert_eq!(
            object["profile_fields"]["managed_by_applet"],
            "ak:applet:01904100-0000-7000-8000-aaaaaaaaaaaa"
        );
        assert_eq!(
            object["accountable_principal_ids"][0],
            "did:webvh:z6mkfixture:owner.example"
        );
        assert_eq!(
            object["profile_fields"]["external_ref"]["slack_user_id"],
            "U12345"
        );
        assert!(object.get("accountability").is_none());
        assert!(object.get("managed_by_applet").is_none());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn did(name: &str) -> Did {
        Did::new(format!("did:webvh:z6mkfixture:{name}.example")).unwrap()
    }

    #[test]
    fn profiles_manage_display_avatar_bio_and_versions() {
        let alice = did("alice");
        let mut manager = ProfileManager::new();

        let v1 = manager.set_display_name(alice.clone(), "Alice");
        assert_eq!(v1.version, 1);
        assert_eq!(v1.display_name, Some("Alice".to_owned()));

        let avatar_blob_ref = BlobRef::new(concat!(
            "ak:blob:sha256:",
            "01015dc8af66d01f557ea63f13538f1964848840a350c5311d1efc8ad138bb91"
        ))
        .unwrap();
        let v2 = manager.set_avatar_blob_ref(alice.clone(), avatar_blob_ref.clone());
        assert_eq!(v2.version, 2);
        assert_eq!(v2.display_name, Some("Alice".to_owned()));
        assert_eq!(v2.avatar_blob_ref, Some(avatar_blob_ref));

        let v3 = manager.set_bio(alice.clone(), "Builder");
        assert_eq!(v3.version, 3);
        assert_eq!(
            manager.profile(&alice).unwrap().bio,
            Some("Builder".to_owned())
        );
        assert_eq!(manager.history(&alice).len(), 3);
        assert_eq!(
            manager.profile_version(&alice, 1).unwrap().display_name,
            Some("Alice".to_owned())
        );
    }

    #[test]
    fn sovereign_policy_validates_domains_resolver_pins_and_imports() {
        let alice = did("alice");
        let service = did("svc");
        let mut policy = SovereignDeploymentPolicy::closed(alice.clone(), "example.com");
        assert!(!policy.is_domain_allowed("remote.example"));
        policy.allow_domain("remote.example");
        policy.pin_resolver("web", "https://resolver.example");
        policy.classify("Realm:private", DataClassification::Restricted);
        assert!(policy.is_domain_allowed("remote.example"));
        assert_eq!(policy.resolver_pins["web"], "https://resolver.example");

        let manifest = RealmExportManifest {
            export_id: "export1".to_owned(),
            realm_id: RealmId::new("ak:realm:01904100-0000-7000-8000-9b64700c6ee8").unwrap(),
            exported_by: alice,
            source_service_id: service.clone(),
            event_count: 10,
            state_digest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .to_owned(),
            created_at: Utc::now(),
        };
        let validation = validate_realm_import(
            &manifest,
            Some(&manifest.realm_id),
            &BTreeSet::from([service]),
        );
        assert!(validation.accepted);
    }

    #[test]
    fn service_replacement_tsp_and_pairwise_control_models_validate() {
        let old_service = did("old");
        let new_service = did("new");
        let plan = ServiceReplacementPlan {
            old_service_id: old_service.clone(),
            new_service_id: new_service.clone(),
            reason: "rotate service".to_owned(),
            effective_at: Utc::now() + chrono::Duration::hours(1),
            preserve_service_history: true,
        };
        plan.validate(Utc::now()).unwrap();

        let binding = TspTrustBinding {
            subject: old_service.clone(),
            tsp_endpoint: "https://tsp.example".to_owned(),
            trust_anchor: "seal".to_owned(),
            binding_proof: "proof".to_owned(),
            created_at: Utc::now(),
            expires_at: None,
        };
        assert!(binding.is_active(Utc::now()));

        let message = PairwiseControlMessage {
            message_id: "ctrl1".to_owned(),
            sender: old_service,
            recipient: new_service,
            kind: PairwiseControlMessageKind::ResolverPinUpdate,
            payload: serde_json::json!({"method": "web"}),
            created_at: Utc::now(),
            expires_at: None,
        };
        assert_eq!(message.kind, PairwiseControlMessageKind::ResolverPinUpdate);
    }
}
