//! Base client state machine for the Garth Arkret v1 runtime.
//!
//! This module implements the core client state management without IO operations.
//! It handles:
//! - Session management
//! - Sync token tracking
//! - Realm state management
//! - Event processing and state resolution
//! - Read markers and notifications

use std::collections::BTreeMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
// `parking_lot::RwLock` has no lock-poisoning, so a panic while holding a
// guard can't cascade into `unwrap()` panics at every other access point the
// way `std::sync::RwLock` does. Guards are returned directly (no `Result`).
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::Result;
use crate::cursor::{SyncPositions, SyncTracker};
use crate::media::{Attachment, MediaMetadata, MemoryBlobStore};
use crate::models::{BlobRef, DeviceId, Did, Event, RealmId};
use crate::presence::Presence;
use crate::profile::UserProfile;
use crate::resolver::RealmState;
use crate::settings::ClientSettings;
use crate::sync::PresenceStatus;

/// Session metadata for the authenticated user.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionMeta {
    /// User DID
    pub user_id: Did,
    /// Device ID
    pub device_id: DeviceId,
    /// Session credential (if using token-based auth)
    pub session_credential: Option<String>,
    /// Session expiration
    pub expires_at: Option<DateTime<Utc>>,
}

impl SessionMeta {
    /// Create new session metadata.
    pub fn new(user_id: Did, device_id: DeviceId) -> Self {
        Self {
            user_id,
            device_id,
            session_credential: None,
            expires_at: None,
        }
    }

    /// Check if the session is expired.
    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            Utc::now() > expires_at
        } else {
            false
        }
    }
}

/// Serializable state required to restore a local authenticated session.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionRestore {
    /// Session metadata.
    pub session: SessionMeta,
    /// Last known sync token for the default sync stream.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sync_token: Option<String>,
}

/// Realm state in the client.
#[derive(Clone, Debug)]
pub struct ClientRealm {
    /// Realm ID.
    pub realm_id: RealmId,
    /// Current state (joined, left, invited)
    pub state: RealmMembershipState,
    /// Resolved Realm state.
    pub realm_state: RealmState,
    /// Read marker for this Realm.
    pub read_marker: Option<String>,
    /// Notification count
    pub notification_count: u64,
    /// Highlight count
    pub highlight_count: u64,
}

/// Realm membership state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RealmMembershipState {
    /// User is a member of the Realm.
    Joined,
    /// User has left the Realm.
    Left,
    /// User is invited to the Realm.
    Invited,
}

/// Bootstrap sequence step.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BootstrapStepKind {
    /// Resolve the principal DID and account context.
    Resolve,
    /// Discover sync, events and snapshot services.
    DiscoverServices,
    /// Fetch invites and grants needed to enter realms.
    FetchInvitesAndGrants,
    /// Fetch and verify a reducer snapshot.
    FetchSnapshot,
    /// Pull increments after the snapshot cursor.
    PullIncrements,
    /// Run the reducer over snapshot plus increments.
    RunReducer,
    /// Enter cursor subscription / long-poll sync.
    EnterCursorSubscription,
}

/// Bootstrap step status.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BootstrapStepStatus {
    /// Not started.
    Pending,
    /// Running now.
    Running,
    /// Completed.
    Complete,
}

/// One bootstrap step with status metadata.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootstrapStep {
    /// Step kind.
    pub kind: BootstrapStepKind,
    /// Current status.
    pub status: BootstrapStepStatus,
    /// Last status transition.
    pub updated_at: DateTime<Utc>,
}

/// Client bootstrap sequence model.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootstrapSequence {
    /// Principal being bootstrapped.
    pub principal_id: Did,
    /// Device being bootstrapped.
    pub device_id: DeviceId,
    /// Optional target realm.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    /// Discovered sync service.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_id: Option<Did>,
    /// Ordered bootstrap steps.
    pub steps: Vec<BootstrapStep>,
    /// Sync token after entering cursor subscription.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sync_token: Option<String>,
}

impl BootstrapSequence {
    /// Create a bootstrap sequence with the protocol-defined step order.
    pub fn new(principal_id: Did, device_id: DeviceId, realm_id: Option<RealmId>) -> Self {
        let now = Utc::now();
        let steps = [
            BootstrapStepKind::Resolve,
            BootstrapStepKind::DiscoverServices,
            BootstrapStepKind::FetchInvitesAndGrants,
            BootstrapStepKind::FetchSnapshot,
            BootstrapStepKind::PullIncrements,
            BootstrapStepKind::RunReducer,
            BootstrapStepKind::EnterCursorSubscription,
        ]
        .into_iter()
        .map(|kind| BootstrapStep {
            kind,
            status: BootstrapStepStatus::Pending,
            updated_at: now,
        })
        .collect();

        Self {
            principal_id,
            device_id,
            realm_id,
            service_id: None,
            steps,
            sync_token: None,
        }
    }

    /// Mark a step as running.
    pub fn mark_running(&mut self, kind: BootstrapStepKind) -> Result<()> {
        self.update_step(kind, BootstrapStepStatus::Running)
    }

    /// Mark a step as complete.
    pub fn mark_complete(&mut self, kind: BootstrapStepKind) -> Result<()> {
        self.update_step(kind, BootstrapStepStatus::Complete)
    }

    /// Next pending step.
    pub fn next_pending(&self) -> Option<BootstrapStepKind> {
        self.steps
            .iter()
            .find(|step| step.status == BootstrapStepStatus::Pending)
            .map(|step| step.kind)
    }

    /// True once every step is complete.
    pub fn is_complete(&self) -> bool {
        self.steps
            .iter()
            .all(|step| step.status == BootstrapStepStatus::Complete)
    }

    fn update_step(&mut self, kind: BootstrapStepKind, status: BootstrapStepStatus) -> Result<()> {
        let step = self
            .steps
            .iter_mut()
            .find(|step| step.kind == kind)
            .ok_or_else(|| crate::Error::Protocol("bootstrap step not found".to_owned()))?;
        step.status = status;
        step.updated_at = Utc::now();
        Ok(())
    }
}

/// Base client state machine.
///
/// This client manages all local state without performing IO operations.
/// It processes sync responses and maintains the current state of realms.
#[derive(Clone)]
pub struct BaseClient {
    /// Session metadata
    session: Arc<RwLock<Option<SessionMeta>>>,
    /// Current sync tracker
    sync_tracker: Arc<RwLock<SyncTracker>>,
    /// Realm states by Realm ID.
    realms: Arc<RwLock<BTreeMap<String, ClientRealm>>>,
    /// Local profile cache.
    profiles: Arc<RwLock<BTreeMap<String, UserProfile>>>,
    /// Local presence cache.
    presence: Arc<RwLock<BTreeMap<String, Presence>>>,
    /// Local account data cache.
    account_data: Arc<RwLock<BTreeMap<String, Value>>>,
    /// Local settings cache.
    settings: Arc<RwLock<BTreeMap<String, ClientSettings>>>,
    /// Local in-memory media store for no-IO facade helpers.
    media: Arc<RwLock<MemoryBlobStore>>,
}

impl BaseClient {
    /// Create a new base client with default in-memory caches.
    pub fn new() -> Self {
        Self {
            session: Arc::new(RwLock::new(None)),
            sync_tracker: Arc::new(RwLock::new(SyncTracker::new())),
            realms: Arc::new(RwLock::new(BTreeMap::new())),
            profiles: Arc::new(RwLock::new(BTreeMap::new())),
            presence: Arc::new(RwLock::new(BTreeMap::new())),
            account_data: Arc::new(RwLock::new(BTreeMap::new())),
            settings: Arc::new(RwLock::new(BTreeMap::new())),
            media: Arc::new(RwLock::new(MemoryBlobStore::new())),
        }
    }

    /// Get the current session metadata.
    pub fn session_meta(&self) -> Option<SessionMeta> {
        self.session.read().as_ref().cloned()
    }

    /// Set the session metadata.
    pub fn set_session_meta(&self, meta: SessionMeta) -> Result<()> {
        let mut session = self.session.write();
        *session = Some(meta);
        Ok(())
    }

    /// Create and store session metadata after an authentication strand succeeds.
    pub fn login_with_session(
        &self,
        user_id: Did,
        device_id: DeviceId,
        session_credential: Option<String>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<SessionMeta> {
        let meta = SessionMeta {
            user_id,
            device_id,
            session_credential,
            expires_at,
        };
        self.set_session_meta(meta.clone())?;
        Ok(meta)
    }

    /// Restore a previously persisted local session.
    pub fn restore_session(&self, restore: SessionRestore) -> Result<()> {
        if restore.session.is_expired() {
            return Err(crate::Error::Protocol(
                "cannot restore expired session".to_owned(),
            ));
        }

        self.set_session_meta(restore.session)?;
        if let Some(sync_token) = restore.sync_token {
            self.set_sync_token(sync_token);
        }
        Ok(())
    }

    /// Capture the current local session restore payload.
    pub fn session_restore(&self) -> Option<SessionRestore> {
        self.session_meta().map(|session| SessionRestore {
            session,
            sync_token: self.sync_token(),
        })
    }

    /// Return the authenticated session or fail when the client is logged out.
    pub fn whoami(&self) -> Result<SessionMeta> {
        self.session_meta()
            .filter(|meta| !meta.is_expired())
            .ok_or_else(|| crate::Error::Protocol("no active session".to_owned()))
    }

    /// Clear the session (logout).
    pub fn clear_session(&self) -> Result<()> {
        let mut session = self.session.write();
        *session = None;

        // Clear sync state
        let mut tracker = self.sync_tracker.write();
        tracker.clear();
        tracker.sync_tokens.clear();

        // Clear all realms
        let mut realms = self.realms.write();
        realms.clear();

        Ok(())
    }

    /// Check if the client has an active session.
    pub fn is_logged_in(&self) -> bool {
        let session = self.session.read();
        match session.as_ref() {
            Some(meta) => !meta.is_expired(),
            None => false,
        }
    }

    /// Get the current sync token.
    pub fn sync_token(&self) -> Option<String> {
        let tracker = self.sync_tracker.read();
        tracker.sync_tokens.get("default").cloned()
    }

    /// Set the default sync token.
    pub fn set_sync_token(&self, token: impl Into<String>) {
        self.sync_tracker
            .write()
            .sync_tokens
            .insert("default".to_owned(), token.into());
    }

    /// Get the current cursor for resuming sync.
    pub fn current_cursor(&self) -> Result<crate::Cursor> {
        let tracker = self.sync_tracker.read();
        // `SyncTracker` moved to arkret-hlc (core-retirement batch 2) and now
        // surfaces `HlcError`; coerce it into the SDK facade error via `?`.
        Ok(tracker.current_cursor()?)
    }

    /// Persist sync positions in the local client state machine.
    pub fn save_sync_positions(&self, positions: SyncPositions) -> Result<()> {
        self.sync_tracker.write().positions = positions;
        Ok(())
    }

    /// Get the current sync positions.
    pub fn sync_positions(&self) -> SyncPositions {
        self.sync_tracker.read().positions.clone()
    }

    /// Bind a sync token to a service key.
    pub fn bind_sync_token(
        &self,
        service_key: impl Into<String>,
        token: impl Into<String>,
    ) -> Result<()> {
        self.sync_tracker
            .write()
            .sync_tokens
            .insert(service_key.into(), token.into());
        Ok(())
    }

    /// Get a sync token by service key.
    pub fn sync_token_for(&self, service_key: &str) -> Option<String> {
        self.sync_tracker
            .read()
            .sync_tokens
            .get(service_key)
            .cloned()
    }

    /// Get a Realm by ID.
    pub fn get_realm(&self, realm_id: &RealmId) -> Option<ClientRealm> {
        let realms = self.realms.read();
        realms.get(realm_id.as_str()).cloned()
    }

    /// Get all joined realms.
    pub fn joined_realms(&self) -> Vec<ClientRealm> {
        let realms = self.realms.read();
        realms
            .values()
            .filter(|s| s.state == RealmMembershipState::Joined)
            .cloned()
            .collect()
    }

    /// Get all invited realms.
    pub fn invited_realms(&self) -> Vec<ClientRealm> {
        let realms = self.realms.read();
        realms
            .values()
            .filter(|s| s.state == RealmMembershipState::Invited)
            .cloned()
            .collect()
    }

    /// Get all left realms.
    pub fn left_realms(&self) -> Vec<ClientRealm> {
        let realms = self.realms.read();
        realms
            .values()
            .filter(|s| s.state == RealmMembershipState::Left)
            .cloned()
            .collect()
    }

    /// Process events and update Realm states.
    pub fn process_events(&self, realm_id: &RealmId, events: Vec<Event>) -> Result<()> {
        let mut realms = self.realms.write();
        let client_realm = realms
            .entry(realm_id.as_str().to_owned())
            .or_insert_with(|| {
                let realm_state = RealmState::new(realm_id.clone());
                ClientRealm {
                    realm_id: realm_id.clone(),
                    state: RealmMembershipState::Joined,
                    realm_state,
                    read_marker: None,
                    notification_count: 0,
                    highlight_count: 0,
                }
            });

        client_realm.realm_state.apply_events(&events)?;

        Ok(())
    }

    /// Update Realm membership state.
    pub fn update_realm_membership_state(
        &self,
        realm_id: &RealmId,
        state: RealmMembershipState,
    ) -> Result<()> {
        let mut realms = self.realms.write();
        let client_realm = realms
            .entry(realm_id.as_str().to_owned())
            .or_insert_with(|| {
                let realm_state = RealmState::new(realm_id.clone());
                ClientRealm {
                    realm_id: realm_id.clone(),
                    state,
                    realm_state,
                    read_marker: None,
                    notification_count: 0,
                    highlight_count: 0,
                }
            });
        client_realm.state = state;
        Ok(())
    }

    /// Update unread counts for a Realm.
    pub fn update_unread_counts(
        &self,
        realm_id: &RealmId,
        notification_count: u64,
        highlight_count: u64,
    ) -> Result<()> {
        let mut realms = self.realms.write();
        if let Some(client_realm) = realms.get_mut(realm_id.as_str()) {
            client_realm.notification_count = notification_count;
            client_realm.highlight_count = highlight_count;
        }
        Ok(())
    }

    /// Set the read marker for a Realm.
    pub fn set_read_marker(&self, realm_id: &RealmId, marker: String) -> Result<()> {
        let mut realms = self.realms.write();
        if let Some(client_realm) = realms.get_mut(realm_id.as_str()) {
            client_realm.read_marker = Some(marker);
        }
        Ok(())
    }

    /// Get the read marker for a Realm.
    pub fn read_marker(&self, realm_id: &RealmId) -> Option<String> {
        let realms = self.realms.read();
        realms
            .get(realm_id.as_str())
            .and_then(|s| s.read_marker.clone())
    }

    /// Get a cached profile.
    pub fn profile(&self, user_id: &Did) -> Option<UserProfile> {
        self.profiles.read().get(user_id.as_str()).cloned()
    }

    /// Read-modify-write the current user's cached profile inside a single
    /// write-lock critical section. Composite setters must go through this
    /// helper: a read-then-write across two lock acquisitions loses
    /// concurrent updates to the fields the caller did not touch.
    fn mutate_my_profile(&self, mutate: impl FnOnce(&mut UserProfile)) -> Result<UserProfile> {
        let session = self.whoami()?;
        let mut profiles = self.profiles.write();
        let profile = profiles
            .entry(session.user_id.as_str().to_owned())
            .or_insert_with(|| UserProfile::new(session.user_id.clone()));
        mutate(profile);
        profile.version += 1;
        profile.updated_at = Utc::now();
        Ok(profile.clone())
    }

    /// Replace cached profile fields for the current user.
    pub fn update_my_profile(
        &self,
        display_name: Option<String>,
        avatar_blob_ref: Option<BlobRef>,
        bio: Option<String>,
    ) -> Result<UserProfile> {
        self.mutate_my_profile(|profile| {
            profile.display_name = display_name;
            profile.avatar_blob_ref = avatar_blob_ref;
            profile.bio = bio;
        })
    }

    /// Set the current user's display name, leaving the other profile
    /// fields untouched (atomic single-lock update; no lost updates under
    /// concurrent profile writes).
    pub fn set_my_display_name(&self, display_name: impl Into<String>) -> Result<UserProfile> {
        let display_name = display_name.into();
        self.mutate_my_profile(|profile| {
            profile.display_name = Some(display_name);
        })
    }

    /// Get cached presence for a user.
    pub fn presence(&self, user_id: &Did) -> Option<Presence> {
        self.presence.read().get(user_id.as_str()).cloned()
    }

    /// Set cached presence for any user.
    pub fn set_presence(
        &self,
        user_id: Did,
        status: PresenceStatus,
        status_msg: Option<String>,
    ) -> Result<Presence> {
        let presence = Presence {
            user_id: user_id.clone(),
            status,
            last_active: Some(Utc::now()),
            active_device: None,
            status_msg,
        };
        self.presence
            .write()
            .insert(user_id.as_str().to_owned(), presence.clone());
        Ok(presence)
    }

    /// Set cached presence for the current user.
    pub fn set_my_presence(
        &self,
        status: PresenceStatus,
        status_msg: Option<String>,
    ) -> Result<Presence> {
        let session = self.whoami()?;
        self.set_presence(session.user_id, status, status_msg)
    }

    /// Store current-user account data by type.
    pub fn set_account_data(&self, data_type: impl Into<String>, content: Value) -> Result<()> {
        self.whoami()?;
        self.account_data.write().insert(data_type.into(), content);
        Ok(())
    }

    /// Get current-user account data by type.
    pub fn account_data(&self, data_type: &str) -> Option<Value> {
        self.account_data.read().get(data_type).cloned()
    }

    /// Get all current-user account data.
    pub fn all_account_data(&self) -> BTreeMap<String, Value> {
        self.account_data.read().clone()
    }

    /// Get cached settings for a user, returning defaults when no cache exists.
    pub fn settings(&self, user_id: &Did) -> ClientSettings {
        self.settings
            .read()
            .get(user_id.as_str())
            .cloned()
            .unwrap_or_else(|| ClientSettings::new(user_id.clone()))
    }

    /// Get settings for the current user.
    pub fn my_settings(&self) -> Result<ClientSettings> {
        let session = self.whoami()?;
        Ok(self.settings(&session.user_id))
    }

    /// Replace cached settings for a user.
    pub fn update_settings(&self, settings: ClientSettings) -> Result<()> {
        self.settings
            .write()
            .insert(settings.user_id.as_str().to_owned(), settings);
        Ok(())
    }

    /// Upload media bytes into the local in-memory media store.
    pub fn upload_media(
        &self,
        bytes: impl AsRef<[u8]>,
        media_type: impl Into<String>,
        filename: Option<String>,
    ) -> Result<MediaMetadata> {
        let session = self.whoami()?;
        self.media
            .write()
            .upload(bytes, media_type, filename, session.user_id)
    }

    /// Download media bytes from the local in-memory media store.
    pub fn download_media(&self, blob_ref: &BlobRef) -> Option<Vec<u8>> {
        self.media.read().download(blob_ref).map(<[u8]>::to_vec)
    }

    /// Upload an attachment into the local in-memory media store.
    pub fn upload_attachment(
        &self,
        id: impl Into<String>,
        filename: impl Into<String>,
        media_type: impl Into<String>,
        bytes: impl AsRef<[u8]>,
    ) -> Result<Attachment> {
        let session = self.whoami()?;
        self.media
            .write()
            .upload_attachment(id, filename, media_type, bytes, session.user_id)
    }

    /// Upload an encrypted attachment into the local in-memory media store.
    pub fn upload_encrypted_attachment(
        &self,
        id: impl Into<String>,
        filename: impl Into<String>,
        media_type: impl Into<String>,
        plaintext: impl AsRef<[u8]>,
        key: &[u8],
    ) -> Result<Attachment> {
        let session = self.whoami()?;
        self.media.write().upload_encrypted_attachment(
            id,
            filename,
            media_type,
            plaintext,
            key,
            session.user_id,
        )
    }

    /// Download and decrypt a local encrypted attachment.
    pub fn download_decrypted_attachment(&self, id: &str, key: &[u8]) -> Result<Vec<u8>> {
        self.media.read().download_decrypted_attachment(id, key)
    }
}

impl Default for BaseClient {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_meta_checks_expiration() {
        let meta = SessionMeta {
            user_id: Did::new("did:webvh:z6mkfixture:alice.example.com").unwrap(),
            device_id: DeviceId::new("ak:device:01904100-0000-7000-8000-000000000005").unwrap(),
            session_credential: Some("token".to_owned()),
            expires_at: Some(Utc::now() - chrono::Duration::hours(1)),
        };

        assert!(meta.is_expired());
    }

    #[test]
    fn session_meta_valid_when_not_expired() {
        let meta = SessionMeta {
            user_id: Did::new("did:webvh:z6mkfixture:alice.example.com").unwrap(),
            device_id: DeviceId::new("ak:device:01904100-0000-7000-8000-000000000005").unwrap(),
            session_credential: Some("token".to_owned()),
            expires_at: Some(Utc::now() + chrono::Duration::hours(1)),
        };

        assert!(!meta.is_expired());
    }

    #[test]
    fn base_client_starts_with_no_session() {
        let client = BaseClient::new();
        assert!(!client.is_logged_in());
        assert!(client.session_meta().is_none());
    }

    #[test]
    fn base_client_can_set_session() {
        let client = BaseClient::new();
        let meta = SessionMeta::new(
            Did::new("did:webvh:z6mkfixture:alice.example.com").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-000000000005").unwrap(),
        );

        client.set_session_meta(meta.clone()).unwrap();
        assert!(client.is_logged_in());

        let retrieved = client.session_meta().unwrap();
        assert_eq!(retrieved.user_id, meta.user_id);
        assert_eq!(retrieved.device_id, meta.device_id);
    }

    #[test]
    fn base_client_clears_session() {
        let client = BaseClient::new();
        let meta = SessionMeta::new(
            Did::new("did:webvh:z6mkfixture:alice.example.com").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-000000000005").unwrap(),
        );

        client.set_session_meta(meta).unwrap();
        assert!(client.is_logged_in());

        client.clear_session().unwrap();
        assert!(!client.is_logged_in());
    }

    #[test]
    fn base_client_restores_session_and_whoami() {
        let client = BaseClient::new();
        let meta = client
            .login_with_session(
                Did::new("did:webvh:z6mkfixture:alice.example.com").unwrap(),
                DeviceId::new("ak:device:01904100-0000-7000-8000-000000000005").unwrap(),
                Some("token".to_owned()),
                None,
            )
            .unwrap();
        client.set_sync_token("s123");

        let restore = client.session_restore().unwrap();
        assert_eq!(restore.session, meta);
        assert_eq!(restore.sync_token, Some("s123".to_owned()));

        client.clear_session().unwrap();
        assert!(client.sync_token().is_none());
        client.restore_session(restore).unwrap();
        assert_eq!(
            client.whoami().unwrap().user_id,
            Did::new("did:webvh:z6mkfixture:alice.example.com").unwrap()
        );
        assert_eq!(client.sync_token(), Some("s123".to_owned()));
    }

    #[test]
    fn base_client_persists_sync_positions_and_service_tokens() {
        let client = BaseClient::new();
        let positions = SyncPositions {
            realms: BTreeMap::from([(
                "ak:realm:0196419b-0000-7000-8000-000000000000".to_owned(),
                crate::cursor::RealmSyncPosition {
                    frontier: vec!["ak:event:019640ed-8000-7000-8000-000000000000".to_owned()],
                    timeline_order: "01970e589d21-0004-a13f9c2e".to_owned(),
                    state_digest:
                        "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                            .to_owned(),
                },
            )]),
            devices: None,
        };

        client.save_sync_positions(positions).unwrap();
        client
            .bind_sync_token("did:webvh:z6mkfixture:sync.example", "sync-token")
            .unwrap();

        assert_eq!(client.sync_positions().realms.len(), 1);
        let current_cursor = client.current_cursor().unwrap();
        assert!(!current_cursor.h.is_empty());
        assert_eq!(
            client.sync_token_for("did:webvh:z6mkfixture:sync.example"),
            Some("sync-token".to_owned())
        );
    }

    #[test]
    fn bootstrap_sequence_tracks_ordered_runtime_steps() {
        let principal = Did::new("did:webvh:z6mkfixture:alice.example.com").unwrap();
        let device = DeviceId::new("ak:device:01904100-0000-7000-8000-000000000005").unwrap();
        let mut sequence = BootstrapSequence::new(principal, device, None);

        assert_eq!(sequence.next_pending(), Some(BootstrapStepKind::Resolve));
        sequence.mark_running(BootstrapStepKind::Resolve).unwrap();
        sequence.mark_complete(BootstrapStepKind::Resolve).unwrap();
        assert_eq!(
            sequence.next_pending(),
            Some(BootstrapStepKind::DiscoverServices)
        );

        for kind in [
            BootstrapStepKind::DiscoverServices,
            BootstrapStepKind::FetchInvitesAndGrants,
            BootstrapStepKind::FetchSnapshot,
            BootstrapStepKind::PullIncrements,
            BootstrapStepKind::RunReducer,
            BootstrapStepKind::EnterCursorSubscription,
        ] {
            sequence.mark_complete(kind).unwrap();
        }

        assert!(sequence.is_complete());
    }

    #[test]
    fn base_client_exposes_profile_presence_account_settings_and_media_helpers() {
        let client = BaseClient::new();
        let alice = Did::new("did:webvh:z6mkfixture:alice.example.com").unwrap();
        client
            .login_with_session(
                alice.clone(),
                DeviceId::new("ak:device:01904100-0000-7000-8000-000000000005").unwrap(),
                None,
                None,
            )
            .unwrap();

        let profile = client.set_my_display_name("Alice").unwrap();
        assert_eq!(profile.display_name, Some("Alice".to_owned()));
        assert_eq!(client.profile(&alice).unwrap().version, 1);

        let presence = client
            .set_my_presence(PresenceStatus::Online, Some("available".to_owned()))
            .unwrap();
        assert_eq!(presence.status, PresenceStatus::Online);
        assert_eq!(
            client.presence(&alice).unwrap().status_msg,
            Some("available".to_owned())
        );

        client
            .set_account_data("theme", serde_json::json!({"value": "dark"}))
            .unwrap();
        assert_eq!(client.account_data("theme").unwrap()["value"], "dark");

        let mut settings = client.my_settings().unwrap();
        settings.language = "zh-CN".to_owned();
        client.update_settings(settings).unwrap();
        assert_eq!(client.my_settings().unwrap().language, "zh-CN");

        let metadata = client
            .upload_media(b"hello", "text/plain", Some("hello.txt".to_owned()))
            .unwrap();
        assert_eq!(client.download_media(&metadata.blob_ref).unwrap(), b"hello");

        client
            .upload_encrypted_attachment("a1", "secret.txt", "text/plain", b"secret", b"key")
            .unwrap();
        assert_eq!(
            client.download_decrypted_attachment("a1", b"key").unwrap(),
            b"secret"
        );
    }

    #[test]
    fn base_client_tracks_realm_state() {
        let client = BaseClient::new();
        let realm_id = RealmId::new("ak:realm:01904100-0000-7000-8000-9b64700c6ee8").unwrap();

        client
            .update_realm_membership_state(&realm_id, RealmMembershipState::Joined)
            .unwrap();

        let realm = client.get_realm(&realm_id);
        assert!(realm.is_some());
        assert_eq!(realm.unwrap().state, RealmMembershipState::Joined);
    }

    #[test]
    fn base_client_filters_joined_realms() {
        let client = BaseClient::new();
        let realm1 = RealmId::new("ak:realm:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
        let realm2 = RealmId::new("ak:realm:01904100-0000-7000-8000-f949e0272316").unwrap();
        let realm3 = RealmId::new("ak:realm:01904100-0000-7000-8000-46f8537dc94e").unwrap();

        client
            .update_realm_membership_state(&realm1, RealmMembershipState::Joined)
            .unwrap();
        client
            .update_realm_membership_state(&realm2, RealmMembershipState::Left)
            .unwrap();
        client
            .update_realm_membership_state(&realm3, RealmMembershipState::Invited)
            .unwrap();

        let joined = client.joined_realms();
        assert_eq!(joined.len(), 1);
        assert_eq!(joined[0].realm_id, realm1);

        let left = client.left_realms();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].realm_id, realm2);

        let invited = client.invited_realms();
        assert_eq!(invited.len(), 1);
        assert_eq!(invited[0].realm_id, realm3);
    }
}
