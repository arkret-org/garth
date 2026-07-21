//! Account data management for the Garth Arkret v1 runtime.
//!
//! This module provides account data management for users, including:
//! - User-specific settings
//! - Client-specific data
//! - Account data synchronization

use std::collections::BTreeMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::base::BaseClient;
use crate::{Did, Hash, NonEmptyString, Result};

/// Standard account-data type for the personal blocklist
/// (`moderation.md` §4.1).
pub const ACCOUNT_DATA_BLOCKLIST: &str = "ak.account.blocklist";

/// AKP R3 spec-sync (2026-05-27) — wire payload for `ak.account_data.set`.
/// Mirrors `event-payload.schema.json#/$defs/account_data_set_payload`:
/// owner/key/body/encrypted_payload/body_digest/tombstone/updated_at/
/// expected_state_digest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountDataSetPayload {
    /// Account owner DID. MUST equal the submitting actor.
    pub owner: Did,
    /// Account-data type key (e.g. `ak.account.blocklist`,
    /// `m.push_rules`).
    pub key: NonEmptyString,
    /// Plaintext body.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<BTreeMap<String, Value>>,
    /// AEAD-wrapped body (preferred at rest for sensitive types).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_payload: Option<BTreeMap<String, Value>>,
    /// SHA-256 digest of the canonical body for tombstone-safe deletes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_digest: Option<Hash>,
    /// Tombstone marker — when true the entry is logically deleted.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub tombstone: bool,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub updated_at: DateTime<Utc>,
    /// CAS guard against expected per-key state digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_state_digest: Option<Hash>,
}

/// AKP R3 spec-sync (2026-05-27) — `ak.account.blocklist` payload shape.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountBlocklistPayload {
    pub version: u64,
    #[serde(default)]
    pub entries: Vec<AccountBlocklistPayloadEntry>,
}

/// Single entry inside an [`AccountBlocklistPayload`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountBlocklistPayloadEntry {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry_id: Option<NonEmptyString>,
    pub target: AccountBlocklistTarget,
    pub mode: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub applies_to: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<NonEmptyString>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    #[serde(
        default,
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountBlocklistTarget {
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub did: Option<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<NonEmptyString>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmRemarkSubject {
    pub kind: String,
    pub id: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmRemark {
    #[serde(default = "default_remark_version")]
    pub version: u32,
    pub subject: RealmRemarkSubject,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub local_name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub note: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub pinned: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified_title_at_save: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub verified_owning_organizations_at_save: Vec<String>,
    #[serde(
        default = "Utc::now",
        with = "arkret_canonical::serde_helpers::canonical_timestamp"
    )]
    pub saved_at: DateTime<Utc>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub updated_at: Option<DateTime<Utc>>,
}

impl RealmRemark {
    pub fn new(realm_id: impl Into<String>, local_name: impl Into<String>) -> Self {
        Self {
            version: 1,
            subject: RealmRemarkSubject {
                kind: "realm".to_owned(),
                id: realm_id.into(),
            },
            local_name: local_name.into(),
            saved_at: Utc::now(),
            ..Self::default()
        }
    }

    pub fn with_pinned_preserving_fields(
        realm_id: impl Into<String>,
        existing: Option<&Self>,
        pinned: bool,
        updated_at: Option<DateTime<Utc>>,
    ) -> Self {
        let realm_id = realm_id.into();
        let mut next = existing
            .cloned()
            .unwrap_or_else(|| Self::new(realm_id.clone(), ""));
        next.version = 1;
        next.subject = RealmRemarkSubject {
            kind: "realm".to_owned(),
            id: realm_id,
        };
        next.pinned = pinned;
        if let Some(updated_at) = updated_at {
            next.updated_at = Some(updated_at);
        }
        next
    }

    pub fn is_empty(&self) -> bool {
        self.local_name.trim().is_empty()
            && self.note.trim().is_empty()
            && self.tags.is_empty()
            && !self.pinned
    }

    pub fn display_name<'a>(&'a self, fallback: &'a str) -> &'a str {
        let local_name = self.local_name.trim();
        if local_name.is_empty() {
            fallback
        } else {
            local_name
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContactRemarkSubject {
    pub kind: String,
    pub did: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContactRemark {
    #[serde(default = "default_remark_version")]
    pub version: u32,
    pub subject: ContactRemarkSubject,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub local_name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub note: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub pinned: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified_handle_at_save: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub saved_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
}

impl ContactRemark {
    pub fn new(actor_did: impl Into<String>, local_name: impl Into<String>) -> Self {
        Self {
            version: 1,
            subject: ContactRemarkSubject {
                kind: "actor".to_owned(),
                did: actor_did.into(),
            },
            local_name: local_name.into(),
            ..Self::default()
        }
    }

    pub fn with_pinned_preserving_fields(
        actor_did: impl Into<String>,
        existing: Option<&Self>,
        pinned: bool,
        updated_at: Option<String>,
    ) -> Self {
        let actor_did = actor_did.into();
        let mut next = existing
            .cloned()
            .unwrap_or_else(|| Self::new(actor_did.clone(), ""));
        next.version = 1;
        next.subject = ContactRemarkSubject {
            kind: "actor".to_owned(),
            did: actor_did,
        };
        next.pinned = pinned;
        if let Some(updated_at) = updated_at {
            if next.saved_at.is_none() && !next.is_empty() {
                next.saved_at = Some(updated_at.clone());
            }
            next.updated_at = Some(updated_at);
        }
        next
    }

    pub fn is_empty(&self) -> bool {
        self.local_name.trim().is_empty()
            && self.note.trim().is_empty()
            && self.tags.is_empty()
            && !self.pinned
    }

    pub fn display_name<'a>(&'a self, fallback: &'a str) -> &'a str {
        let local_name = self.local_name.trim();
        if local_name.is_empty() {
            fallback
        } else {
            local_name
        }
    }
}

fn default_remark_version() -> u32 {
    1
}

/// Account data entry.
#[derive(Clone, Debug)]
pub struct AccountData {
    /// Data type
    pub data_type: String,
    /// Data content
    pub content: Value,
}

/// Account data manager.
#[derive(Clone)]
pub struct AccountDataManager {
    /// Base client reference
    _base_client: Arc<BaseClient>,
    /// Account data by type
    account_data: Arc<std::sync::RwLock<BTreeMap<String, AccountData>>>,
}

impl AccountDataManager {
    /// Create a new account data manager.
    pub fn new(base_client: Arc<BaseClient>) -> Self {
        Self {
            _base_client: base_client,
            account_data: Arc::new(std::sync::RwLock::new(BTreeMap::new())),
        }
    }

    /// Get account data by type.
    pub fn get(&self, data_type: &str) -> Option<AccountData> {
        self.account_data
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(data_type)
            .cloned()
    }

    /// Set account data.
    pub fn set(&self, data_type: String, content: Value) -> Result<()> {
        let account_data = AccountData {
            data_type: data_type.clone(),
            content,
        };
        self.account_data
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(data_type, account_data);
        Ok(())
    }

    /// Remove account data.
    pub fn remove(&self, data_type: &str) -> Result<()> {
        self.account_data
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(data_type);
        Ok(())
    }

    /// Get all account data.
    pub fn all(&self) -> BTreeMap<String, AccountData> {
        self.account_data
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Clear all account data.
    pub fn clear(&self) -> Result<()> {
        self.account_data
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
    fn account_data_manager_sets_and_gets() {
        let base_client = Arc::new(BaseClient::new());
        let manager = AccountDataManager::new(base_client);

        let content = serde_json::json!({"theme": "dark"});
        manager.set("theme".to_owned(), content.clone()).unwrap();

        let retrieved = manager.get("theme").unwrap();
        assert_eq!(retrieved.data_type, "theme");
        assert_eq!(retrieved.content, content);
    }

    #[test]
    fn account_data_manager_removes() {
        let base_client = Arc::new(BaseClient::new());
        let manager = AccountDataManager::new(base_client);

        manager
            .set("test".to_owned(), serde_json::json!({"key": "value"}))
            .unwrap();
        assert!(manager.get("test").is_some());

        manager.remove("test").unwrap();
        assert!(manager.get("test").is_none());
    }

    #[test]
    fn account_data_manager_lists_all() {
        let base_client = Arc::new(BaseClient::new());
        let manager = AccountDataManager::new(base_client);

        manager
            .set("key1".to_owned(), serde_json::json!(1))
            .unwrap();
        manager
            .set("key2".to_owned(), serde_json::json!(2))
            .unwrap();

        let all = manager.all();
        assert_eq!(all.len(), 2);
        assert!(all.contains_key("key1"));
        assert!(all.contains_key("key2"));
    }

    #[test]
    fn contact_remark_uses_canonical_subject_shape() {
        let value =
            serde_json::to_value(ContactRemark::new("did:web:alice.example", "Alice")).unwrap();
        assert_eq!(value["subject"]["kind"], "actor");
        assert_eq!(value["subject"]["did"], "did:web:alice.example");
        assert!(value.get("actor_id").is_none());
    }
}
