//! Durable local persistence helpers for SDK runtimes.
//!
//! This module intentionally stays focused on the persistence surfaces the SDK
//! still consumes today: state snapshots, event cache, account/session data,
//! blob metadata, audit logs, and a small generic cache helper.

use std::collections::{BTreeMap, VecDeque};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::protocol::auth::AuthSession;
use crate::protocol::models::BlobMetadata;
use crate::protocol::resolver::{RealmState, SnapshotRestore, StateSnapshot};
use crate::protocol::{BlobRef, Did, Error, Event, EventId, RealmId, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    GroupCreated,
    MemberJoined,
    MemberRemoved,
    GroupMerged,
    EpochAdvanced,
    KeyRotated,
    KeyExported,
    KeyBackedUp,
    KeyRestored,
    MessageValidated,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    pub timestamp: DateTime<Utc>,
    pub action: AuditAction,
    pub actor: Option<Did>,
    pub group_id: Option<String>,
    pub detail: String,
}

pub trait StateSnapshotStore: Send + Sync {
    fn put_state_snapshot(&mut self, snapshot: StateSnapshot) -> Result<()>;
    fn state_snapshot(&self, realm_id: &RealmId) -> Option<&StateSnapshot>;
    fn remove_state_snapshot(&mut self, realm_id: &RealmId) -> Result<()>;
}

pub trait EventCacheStore: Send + Sync {
    fn put_event(&mut self, event: Event) -> Result<()>;
    fn event(&self, event_id: &EventId) -> Option<&Event>;
    fn events_for_realm(&self, realm_id: &RealmId) -> Vec<&Event>;
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct StoredAccountData {
    pub principal_id: Did,
    pub data_type: String,
    pub content: Value,
    pub updated_at: DateTime<Utc>,
}

pub trait AccountSessionStore: Send + Sync {
    fn put_session(&mut self, session: AuthSession) -> Result<()>;
    fn session(&self, session_id: &str) -> Option<&AuthSession>;
    fn sessions_for_principal(&self, principal_id: &Did) -> Vec<&AuthSession>;
    fn revoke_session(&mut self, session_id: &str) -> Result<()>;
    fn put_account_data(&mut self, data: StoredAccountData) -> Result<()>;
    fn account_data(&self, principal_id: &Did, data_type: &str) -> Option<&StoredAccountData>;
}

pub trait BlobMetadataStore: Send + Sync {
    fn put_blob_metadata(&mut self, metadata: BlobMetadata) -> Result<()>;
    fn blob_metadata(&self, blob_ref: &BlobRef) -> Option<&BlobMetadata>;
}

pub trait AuditLogStore: Send + Sync {
    fn append_audit_entry(&mut self, entry: AuditEntry) -> Result<()>;
    fn audit_entries(&self) -> Vec<&AuditEntry>;
}

/// Store encryption key derived from a passphrase and salt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoreEncryptionKey([u8; 32]);

impl StoreEncryptionKey {
    /// Derive a key using repeated SHA-256 rounds.
    pub fn derive(passphrase: &str, salt: &[u8], rounds: u32) -> Self {
        let mut key =
            crate::protocol::canonical::sha256_bytes_from_slices(&[passphrase.as_bytes(), salt]);
        for _ in 0..rounds.max(1) {
            key = crate::protocol::canonical::sha256_bytes_from_slices(&[&key, salt]);
        }
        Self(key)
    }

    pub fn seal(&self, bytes: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        crate::crypto_box::seal(bytes, &self.0, aad)
    }
}

#[derive(Clone, Debug, Default)]
pub struct MemoryPersistenceStore {
    snapshots: BTreeMap<RealmId, StateSnapshot>,
    events: BTreeMap<RealmId, BTreeMap<EventId, (String, Event)>>,
    event_index: BTreeMap<EventId, RealmId>,
    sessions: BTreeMap<String, AuthSession>,
    sessions_by_principal: BTreeMap<Did, Vec<String>>,
    account_data: BTreeMap<(Did, String), StoredAccountData>,
    blob_metadata: BTreeMap<BlobRef, (String, BlobMetadata)>,
    audit_entries: Vec<AuditEntry>,
}

impl MemoryPersistenceStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl StateSnapshotStore for MemoryPersistenceStore {
    fn put_state_snapshot(&mut self, snapshot: StateSnapshot) -> Result<()> {
        snapshot.verify()?;
        self.snapshots.insert(snapshot.realm_id.clone(), snapshot);
        Ok(())
    }

    fn state_snapshot(&self, realm_id: &RealmId) -> Option<&StateSnapshot> {
        self.snapshots.get(realm_id)
    }

    fn remove_state_snapshot(&mut self, realm_id: &RealmId) -> Result<()> {
        self.snapshots.remove(realm_id);
        Ok(())
    }
}

impl EventCacheStore for MemoryPersistenceStore {
    fn put_event(&mut self, event: Event) -> Result<()> {
        let digest = event.event_digest()?;
        if let Some(existing_realm_id) = self.event_index.get(&event.event_id) {
            let existing_digest = self
                .events
                .get(existing_realm_id)
                .and_then(|events| events.get(&event.event_id))
                .map(|(existing_digest, _)| existing_digest);
            return match existing_digest {
                Some(existing_digest) if existing_digest == &digest => Ok(()),
                _ => Err(Error::IdempotencyConflict(event.event_id.to_string())),
            };
        }

        let realm_scope = RealmId::new(event.realm_id.to_string())?;
        self.event_index
            .insert(event.event_id.clone(), realm_scope.clone());
        self.events
            .entry(realm_scope)
            .or_default()
            .insert(event.event_id.clone(), (digest, event));
        Ok(())
    }

    fn event(&self, event_id: &EventId) -> Option<&Event> {
        self.event_index.get(event_id).and_then(|realm_id| {
            self.events
                .get(realm_id)
                .and_then(|events| events.get(event_id))
                .map(|(_, event)| event)
        })
    }

    fn events_for_realm(&self, realm_id: &RealmId) -> Vec<&Event> {
        self.events
            .get(realm_id)
            .map(|events| events.values().map(|(_, event)| event).collect())
            .unwrap_or_default()
    }
}

impl AccountSessionStore for MemoryPersistenceStore {
    fn put_session(&mut self, session: AuthSession) -> Result<()> {
        if let Some(existing) = self.sessions.get(&session.session_id) {
            return if existing == &session {
                Ok(())
            } else {
                Err(Error::IdempotencyConflict(session.session_id))
            };
        }

        self.sessions_by_principal
            .entry(session.principal_id.clone())
            .or_default()
            .push(session.session_id.clone());
        self.sessions.insert(session.session_id.clone(), session);
        Ok(())
    }

    fn session(&self, session_id: &str) -> Option<&AuthSession> {
        self.sessions.get(session_id)
    }

    fn sessions_for_principal(&self, principal_id: &Did) -> Vec<&AuthSession> {
        self.sessions_by_principal
            .get(principal_id)
            .into_iter()
            .flat_map(|session_ids| session_ids.iter())
            .filter_map(|session_id| self.sessions.get(session_id))
            .collect()
    }

    fn revoke_session(&mut self, session_id: &str) -> Result<()> {
        let session = self
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| Error::Protocol(format!("session not found: {session_id}")))?;
        session.revoked = true;
        Ok(())
    }

    fn put_account_data(&mut self, data: StoredAccountData) -> Result<()> {
        self.account_data
            .insert((data.principal_id.clone(), data.data_type.clone()), data);
        Ok(())
    }

    fn account_data(&self, principal_id: &Did, data_type: &str) -> Option<&StoredAccountData> {
        self.account_data
            .get(&(principal_id.clone(), data_type.to_owned()))
    }
}

impl BlobMetadataStore for MemoryPersistenceStore {
    fn put_blob_metadata(&mut self, metadata: BlobMetadata) -> Result<()> {
        let digest = crate::protocol::canonical::canonical_sha256(&metadata)?;
        match self.blob_metadata.get(&metadata.blob_ref) {
            Some((existing_digest, _)) if existing_digest == &digest => Ok(()),
            Some(_) => Err(Error::IdempotencyConflict(metadata.blob_ref.to_string())),
            None => {
                self.blob_metadata
                    .insert(metadata.blob_ref.clone(), (digest, metadata));
                Ok(())
            }
        }
    }

    fn blob_metadata(&self, blob_ref: &BlobRef) -> Option<&BlobMetadata> {
        self.blob_metadata
            .get(blob_ref)
            .map(|(_, metadata)| metadata)
    }
}

impl AuditLogStore for MemoryPersistenceStore {
    fn append_audit_entry(&mut self, entry: AuditEntry) -> Result<()> {
        self.audit_entries.push(entry);
        Ok(())
    }

    fn audit_entries(&self) -> Vec<&AuditEntry> {
        self.audit_entries.iter().collect()
    }
}

pub fn rebuild_realm_state_from_events<S>(store: &S, realm_id: &RealmId) -> Result<RealmState>
where
    S: EventCacheStore,
{
    let events: Vec<Event> = store
        .events_for_realm(realm_id)
        .into_iter()
        .cloned()
        .collect();
    let mut state = RealmState::new(realm_id.clone());
    state.apply_events(&events)?;
    Ok(state)
}

pub fn restore_realm_state_from_persistence<S>(
    store: &S,
    realm_id: &RealmId,
) -> Result<SnapshotRestore>
where
    S: EventCacheStore + StateSnapshotStore,
{
    let events: Vec<Event> = store
        .events_for_realm(realm_id)
        .into_iter()
        .cloned()
        .collect();
    // `arkret-state` returns `arkret_wire::WireError`; bridge into the SDK's
    // `crate::protocol::Error` via the `?` From conversion.
    Ok(RealmState::restore_snapshot_or_replay(
        store.state_snapshot(realm_id).cloned(),
        realm_id.clone(),
        &events,
    )?)
}

/// Small LRU cache for store objects.
#[derive(Clone, Debug)]
pub struct StoreCache<K, V>
where
    K: Ord + Clone,
    V: Clone,
{
    capacity: usize,
    entries: BTreeMap<K, V>,
    order: VecDeque<K>,
}

impl<K, V> StoreCache<K, V>
where
    K: Ord + Clone,
    V: Clone,
{
    /// Create a cache with a fixed capacity.
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            entries: BTreeMap::new(),
            order: VecDeque::new(),
        }
    }

    /// Insert a value.
    pub fn insert(&mut self, key: K, value: V) {
        self.entries.insert(key.clone(), value);
        self.order.retain(|existing| existing != &key);
        self.order.push_back(key);
        while self.entries.len() > self.capacity {
            if let Some(oldest) = self.order.pop_front() {
                self.entries.remove(&oldest);
            }
        }
    }

    /// Get a cached value.
    pub fn get(&self, key: &K) -> Option<&V> {
        self.entries.get(key)
    }

    /// Current cache size.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True if cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use chrono::Utc;
    use serde_json::json;

    use super::*;
    use crate::protocol::resolver::SnapshotRestoreSource;
    use crate::protocol::{
        BLOB_SCHEMA, BlobRef, DeviceId, Did, EventId, Hash, Hlc, ObjectState, RealmId,
    };

    fn morph_event(event_id: &str, title: &str) -> Event {
        Event {
            event_id: EventId::new(event_id).unwrap(),
            kind: crate::protocol::events::EventKind::MORPH_CREATE.into(),
            realm_id: RealmId::new("ak:realm:01904100-0000-7000-8000-9b64700c6ee8").unwrap(),
            actor_id: Did::new("did:webvh:z6mkfixture:alice.example.com").unwrap(),
            actor_seq: 1,
            created_at: Utc::now(),
            hlc: Some(Hlc::new("01970e589d22-0009-11111111").unwrap()),
            prev_refs: vec![],
            effective_scope: None,
            refs: vec![],
            causal_refs: vec![],
            preconditions: vec![],
            effects: vec![],
            seal_ref: None,
            conflict_keys_digest: None,
            auth_context: None,
            seal_basis: None,
            requirements: crate::protocol::EventRequirements::default(),
            redacts: None,
            payload: serde_json::from_value(json!({
                "object": {
                    "id": "ak:morph:01904100-0000-7000-8000-b7a4e10c8c77",
                    "schema": crate::protocol::MORPH_SCHEMA,
                    "realm_id": "ak:realm:01904100-0000-7000-8000-9b64700c6ee8",
                    "schema_refs": [crate::protocol::MORPH_SCHEMA],
                    "morph_type": "task",
                    "metadata": {"title": title},
                    "stage": "draft",
                    "created_by": "did:webvh:z6mkfixture:alice.example.com",
                    "created_at": "2026-05-02T00:00:00.000Z"
                }
            }))
            .unwrap(),
            executed_by: None,
            authorization_ref: None,
            applet_id: None,
            external_ref: None,
            actor_kind: None,
            unsigned: BTreeMap::new(),
            proofs: vec![],
        }
    }

    fn blob_metadata(blob_ref: BlobRef, size_bytes: u64) -> BlobMetadata {
        BlobMetadata {
            schema: BLOB_SCHEMA.to_owned(),
            realm_id: None,
            blob_ref,
            content_digest: Hash::new(
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .unwrap(),
            size_bytes,
            media_type: "text/plain".to_owned(),
            filename: Some("note.txt".to_owned()),
            encryption: None,
            thumbnail_blob_ref: None,
            created_by: Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
            created_at: Utc::now(),
            updated_by: None,
            updated_at: None,
        }
    }

    #[test]
    fn projection_rebuild_helpers_replay_event_cache_and_use_valid_snapshot() {
        let realm_id = RealmId::new("ak:realm:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
        let event = morph_event(
            "ak:event:01904100-0000-7000-8000-ec26a4d295c0",
            "Stored task",
        );
        let mut store = MemoryPersistenceStore::new();
        store.put_event(event.clone()).unwrap();
        store.put_event(event.clone()).unwrap();

        let mut conflicting = event;
        conflicting.payload = serde_json::from_value(json!({
            "object": {
                "id": "ak:morph:01904100-0000-7000-8000-b7a4e10c8c77",
                "schema": crate::protocol::MORPH_SCHEMA,
                "realm_id": "ak:realm:01904100-0000-7000-8000-9b64700c6ee8",
                "schema_refs": [crate::protocol::MORPH_SCHEMA],
                "morph_type": "task",
                "metadata": {"title": "Changed"},
                "stage": "draft",
                "created_by": "did:webvh:z6mkfixture:alice.example.com",
                "created_at": "2026-05-02T00:00:00.000Z"
            }
        }))
        .unwrap();
        assert!(matches!(
            store.put_event(conflicting),
            Err(Error::IdempotencyConflict(_))
        ));

        let state = rebuild_realm_state_from_events(&store, &realm_id).unwrap();
        assert_eq!(state.morphs.len(), 1);
        assert_eq!(
            state
                .morphs
                .get("ak:morph:01904100-0000-7000-8000-b7a4e10c8c77")
                .unwrap()
                .state,
            Some(ObjectState::Active)
        );

        store.put_state_snapshot(state.snapshot().unwrap()).unwrap();
        let restored = restore_realm_state_from_persistence(&store, &realm_id).unwrap();
        assert_eq!(restored.source, SnapshotRestoreSource::Snapshot);
        assert_eq!(restored.state.morphs.len(), 1);
    }

    #[test]
    fn memory_persistence_store_roundtrips_auxiliary_records() {
        let mut store = MemoryPersistenceStore::new();
        let principal_id = Did::new("did:webvh:z6mkfixture:alice.example").unwrap();
        let device_id = DeviceId::new("ak:device:01904100-0000-7000-8000-000000000001").unwrap();
        let session = AuthSession {
            session_id: "sess-1".to_owned(),
            user_id: principal_id.clone(),
            principal_id: principal_id.clone(),
            device_id,
            session_credential: "credential".to_owned(),
            renewal_credential: "renewal".to_owned(),
            expires_at: Utc::now(),
            revoked: false,
            created_at: Utc::now(),
        };
        store.put_session(session.clone()).unwrap();
        store.put_session(session).unwrap();
        assert_eq!(store.sessions_for_principal(&principal_id).len(), 1);
        store.revoke_session("sess-1").unwrap();
        assert!(store.session("sess-1").unwrap().revoked);

        store
            .put_account_data(StoredAccountData {
                principal_id: principal_id.clone(),
                data_type: "settings".to_owned(),
                content: json!({"theme": "dark"}),
                updated_at: Utc::now(),
            })
            .unwrap();
        assert_eq!(
            store
                .account_data(&principal_id, "settings")
                .unwrap()
                .content,
            json!({"theme": "dark"})
        );

        let blob_ref =
            BlobRef::new("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                .unwrap();
        let metadata = blob_metadata(blob_ref.clone(), 12);
        store.put_blob_metadata(metadata.clone()).unwrap();
        store.put_blob_metadata(metadata.clone()).unwrap();
        let mut conflicting_metadata = metadata;
        conflicting_metadata.size_bytes = 13;
        assert!(matches!(
            store.put_blob_metadata(conflicting_metadata),
            Err(Error::IdempotencyConflict(_))
        ));
        assert_eq!(store.blob_metadata(&blob_ref).unwrap().size_bytes, 12);

        store
            .append_audit_entry(AuditEntry {
                timestamp: Utc::now(),
                action: AuditAction::KeyBackedUp,
                actor: Some(principal_id),
                group_id: Some("group1".to_owned()),
                detail: "backup".to_owned(),
            })
            .unwrap();
        assert_eq!(store.audit_entries().len(), 1);
    }

    #[test]
    fn store_cache_evicts_lru_entries() {
        let mut cache = StoreCache::new(2);
        cache.insert("a", 1);
        cache.insert("b", 2);
        cache.insert("c", 3);

        assert!(cache.get(&"a").is_none());
        assert_eq!(cache.get(&"b"), Some(&2));
        assert_eq!(cache.len(), 2);
    }
}
