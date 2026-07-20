//! Presence management for the Garth Arkret v1 runtime.
//!
//! This module provides user presence management, including:
//! - Online/offline status tracking
//! - Last active timestamp
//! - Device-specific presence
//! - Presence status updates

use std::collections::BTreeMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};

use crate::Result;
use crate::base::BaseClient;
use crate::models::Did;
use crate::sync::PresenceStatus;

/// Presence information for a user.
#[derive(Clone, Debug)]
pub struct Presence {
    /// User DID
    pub user_id: Did,
    /// Current presence status
    pub status: PresenceStatus,
    /// Last active timestamp
    pub last_active: Option<DateTime<Utc>>,
    /// Currently active device
    pub active_device: Option<String>,
    /// Status message
    pub status_msg: Option<String>,
}

/// Presence manager.
#[derive(Clone)]
pub struct PresenceManager {
    /// Base client reference
    base_client: Arc<BaseClient>,
    /// Presence by user ID
    presence: Arc<std::sync::RwLock<BTreeMap<String, Presence>>>,
}

impl PresenceManager {
    /// Create a new presence manager.
    pub fn new(base_client: Arc<BaseClient>) -> Self {
        Self {
            base_client,
            presence: Arc::new(std::sync::RwLock::new(BTreeMap::new())),
        }
    }

    /// Get presence for a user.
    pub fn get(&self, user_id: &Did) -> Option<Presence> {
        self.presence
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(user_id.as_str())
            .cloned()
    }

    /// Set presence for a user.
    pub fn set(&self, presence: Presence) -> Result<()> {
        let user_id = presence.user_id.as_str().to_owned();
        self.presence
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(user_id, presence);
        Ok(())
    }

    /// Update presence status for a user.
    pub fn update_status(&self, user_id: &Did, status: PresenceStatus) -> Result<()> {
        let mut presence_map = self
            .presence
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let entry = presence_map
            .entry(user_id.as_str().to_owned())
            .or_insert_with(|| Presence {
                user_id: user_id.clone(),
                status: PresenceStatus::Offline,
                last_active: None,
                active_device: None,
                status_msg: None,
            });

        entry.status = status;
        entry.last_active = Some(Utc::now());

        Ok(())
    }

    /// Set the current user's presence status.
    pub fn set_my_status(&self, status: PresenceStatus) -> Result<()> {
        if let Some(session_meta) = self.base_client.session_meta() {
            self.update_status(&session_meta.user_id, status)
        } else {
            Err(crate::Error::Protocol("no session".to_owned()))
        }
    }

    /// Get all online users.
    pub fn online_users(&self) -> Vec<Presence> {
        self.presence
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .filter(|p| p.status == PresenceStatus::Online)
            .cloned()
            .collect()
    }

    /// Default presence TTL (5 minutes).
    ///
    /// Users with no `last_active` update within this window are
    /// transitioned from `Online`/`Idle`/`Dnd` to `Offline`
    /// when [`Self::expire_idle_presence`] runs. Spec value lives in
    /// `service-surface.md`; the SDK ships with the conservative
    /// 5-minute default and the constant is exposed for callers that
    /// want to tighten or relax the window.
    pub const DEFAULT_TTL: chrono::Duration = chrono::Duration::minutes(5);

    /// Transition stale `Online` / `Idle` / `Dnd` entries to
    /// `Offline` when their `last_active` is older than `ttl` relative
    /// to `now`. Returns the number of entries that were flipped.
    ///
    /// Callers SHOULD invoke this on a tick (e.g. every 60 s) — the
    /// SDK does not spawn its own background task.
    pub fn expire_idle_presence(&self, now: DateTime<Utc>, ttl: chrono::Duration) -> usize {
        let mut map = self
            .presence
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut flipped = 0;
        for entry in map.values_mut() {
            if entry.status == PresenceStatus::Offline {
                continue;
            }
            let stale = match entry.last_active {
                Some(last) => now.signed_duration_since(last) >= ttl,
                None => true,
            };
            if stale {
                entry.status = PresenceStatus::Offline;
                flipped += 1;
            }
        }
        flipped
    }

    /// Get all users with a specific status.
    pub fn users_with_status(&self, status: PresenceStatus) -> Vec<Presence> {
        self.presence
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .filter(|p| p.status == status)
            .cloned()
            .collect()
    }

    /// Get all presence data.
    pub fn all(&self) -> BTreeMap<String, Presence> {
        self.presence
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Clear all presence data.
    pub fn clear(&self) -> Result<()> {
        self.presence
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presence_manager_sets_and_gets() {
        let base_client = Arc::new(BaseClient::new());
        let manager = PresenceManager::new(base_client);

        let user_id = Did::new("did:webvh:z6mkfixture:alice.example.com").unwrap();
        let presence = Presence {
            user_id: user_id.clone(),
            status: PresenceStatus::Online,
            last_active: Some(Utc::now()),
            active_device: None,
            status_msg: None,
        };

        manager.set(presence).unwrap();

        let retrieved = manager.get(&user_id).unwrap();
        assert_eq!(retrieved.status, PresenceStatus::Online);
        assert_eq!(retrieved.user_id, user_id);
    }

    #[test]
    fn presence_manager_updates_status() {
        let base_client = Arc::new(BaseClient::new());
        let manager = PresenceManager::new(base_client);

        let user_id = Did::new("did:webvh:z6mkfixture:alice.example.com").unwrap();

        manager
            .update_status(&user_id, PresenceStatus::Online)
            .unwrap();
        let presence = manager.get(&user_id).unwrap();
        assert_eq!(presence.status, PresenceStatus::Online);
        assert!(presence.last_active.is_some());

        manager
            .update_status(&user_id, PresenceStatus::Offline)
            .unwrap();
        let presence = manager.get(&user_id).unwrap();
        assert_eq!(presence.status, PresenceStatus::Offline);
    }

    #[test]
    fn presence_manager_lists_online_users() {
        let base_client = Arc::new(BaseClient::new());
        let manager = PresenceManager::new(base_client);

        let user1 = Did::new("did:webvh:z6mkfixture:alice.example.com").unwrap();
        let user2 = Did::new("did:webvh:z6mkfixture:bob.example.com").unwrap();

        manager
            .update_status(&user1, PresenceStatus::Online)
            .unwrap();
        manager
            .update_status(&user2, PresenceStatus::Offline)
            .unwrap();

        let online = manager.online_users();
        assert_eq!(online.len(), 1);
        assert_eq!(online[0].user_id, user1);
    }

    #[test]
    fn presence_manager_filters_by_status() {
        let base_client = Arc::new(BaseClient::new());
        let manager = PresenceManager::new(base_client);

        let user1 = Did::new("did:webvh:z6mkfixture:alice.example.com").unwrap();
        let user2 = Did::new("did:webvh:z6mkfixture:bob.example.com").unwrap();
        let user3 = Did::new("did:webvh:z6mkfixture:charlie.example.com").unwrap();

        manager
            .update_status(&user1, PresenceStatus::Online)
            .unwrap();
        manager.update_status(&user2, PresenceStatus::Dnd).unwrap();
        manager.update_status(&user3, PresenceStatus::Dnd).unwrap();

        let dnd = manager.users_with_status(PresenceStatus::Dnd);
        assert_eq!(dnd.len(), 2);
    }
}
