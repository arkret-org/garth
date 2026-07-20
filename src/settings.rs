//! Client settings, privacy preferences and blocklists for Garth.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{Did, RealmId};

/// Client theme.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThemeSetting {
    Light,
    Dark,
    System,
    Custom(String),
}

/// Notification preferences.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotificationPreferences {
    /// Enable in-app notifications.
    pub enabled: bool,
    /// Enable push notifications.
    pub push_enabled: bool,
    /// Enable email notifications.
    pub email_enabled: bool,
    /// Muted Realms.
    pub muted_realms: BTreeSet<RealmId>,
}

impl Default for NotificationPreferences {
    fn default() -> Self {
        Self {
            enabled: true,
            push_enabled: true,
            email_enabled: false,
            muted_realms: BTreeSet::new(),
        }
    }
}

/// Privacy settings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacySettings {
    /// Whether profile can appear in discovery.
    pub profile_discoverable: bool,
    /// Whether read receipts are public by default.
    pub public_read_receipts: bool,
    /// Whether presence can be shown to other users.
    pub presence_visible: bool,
}

impl Default for PrivacySettings {
    fn default() -> Self {
        Self {
            profile_discoverable: true,
            public_read_receipts: true,
            presence_visible: true,
        }
    }
}

/// Client settings for one user.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientSettings {
    /// User DID.
    pub user_id: Did,
    /// Theme preference.
    pub theme: ThemeSetting,
    /// BCP-47 language tag.
    pub language: String,
    /// Notification preferences.
    pub notifications: NotificationPreferences,
    /// Privacy settings.
    pub privacy: PrivacySettings,
    /// Last update time.
    pub updated_at: DateTime<Utc>,
}

impl ClientSettings {
    /// Create default settings.
    pub fn new(user_id: Did) -> Self {
        Self {
            user_id,
            theme: ThemeSetting::System,
            language: "en".to_owned(),
            notifications: NotificationPreferences::default(),
            privacy: PrivacySettings::default(),
            updated_at: Utc::now(),
        }
    }
}

/// In-memory settings and blocklist manager.
#[derive(Clone, Debug, Default)]
pub struct SettingsManager {
    settings: BTreeMap<Did, ClientSettings>,
    blocklists: BTreeMap<Did, BTreeSet<Did>>,
}

impl SettingsManager {
    /// Create an empty manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get settings, creating defaults if missing.
    pub fn settings_mut(&mut self, user_id: Did) -> &mut ClientSettings {
        self.settings
            .entry(user_id.clone())
            .or_insert_with(|| ClientSettings::new(user_id))
    }

    /// Get settings.
    pub fn settings(&self, user_id: &Did) -> Option<&ClientSettings> {
        self.settings.get(user_id)
    }

    /// Set theme.
    pub fn set_theme(&mut self, user_id: Did, theme: ThemeSetting) {
        let settings = self.settings_mut(user_id);
        settings.theme = theme;
        settings.updated_at = Utc::now();
    }

    /// Set language.
    pub fn set_language(&mut self, user_id: Did, language: impl Into<String>) {
        let settings = self.settings_mut(user_id);
        settings.language = language.into();
        settings.updated_at = Utc::now();
    }

    /// Update notification preferences.
    pub fn set_notification_preferences(
        &mut self,
        user_id: Did,
        preferences: NotificationPreferences,
    ) {
        let settings = self.settings_mut(user_id);
        settings.notifications = preferences;
        settings.updated_at = Utc::now();
    }

    /// Mute a Realm.
    pub fn mute_realm(&mut self, user_id: Did, realm_id: RealmId) {
        let settings = self.settings_mut(user_id);
        settings.notifications.muted_realms.insert(realm_id);
        settings.updated_at = Utc::now();
    }

    /// Update privacy settings.
    pub fn set_privacy_settings(&mut self, user_id: Did, privacy: PrivacySettings) {
        let settings = self.settings_mut(user_id);
        settings.privacy = privacy;
        settings.updated_at = Utc::now();
    }

    /// Add a user to the blocklist.
    pub fn block_user(&mut self, owner: Did, blocked: Did) -> bool {
        self.blocklists.entry(owner).or_default().insert(blocked)
    }

    /// Remove a user from the blocklist.
    pub fn unblock_user(&mut self, owner: &Did, blocked: &Did) -> bool {
        self.blocklists
            .get_mut(owner)
            .map(|blocked_users| blocked_users.remove(blocked))
            .unwrap_or(false)
    }

    /// Check if a user is blocked.
    pub fn is_blocked(&self, owner: &Did, blocked: &Did) -> bool {
        self.blocklists
            .get(owner)
            .map(|blocked_users| blocked_users.contains(blocked))
            .unwrap_or(false)
    }

    /// List blocked users.
    pub fn blocked_users(&self, owner: &Did) -> Vec<&Did> {
        self.blocklists
            .get(owner)
            .map(|blocked_users| blocked_users.iter().collect())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn did(name: &str) -> Did {
        Did::new(format!("did:webvh:z6mkfixture:{name}.example")).unwrap()
    }

    #[test]
    fn settings_manage_theme_language_notifications_and_privacy() {
        let alice = did("alice");
        let realm_id = RealmId::new("ak:realm:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
        let mut manager = SettingsManager::new();

        manager.set_theme(alice.clone(), ThemeSetting::Dark);
        manager.set_language(alice.clone(), "zh-CN");
        manager.mute_realm(alice.clone(), realm_id.clone());
        manager.set_privacy_settings(
            alice.clone(),
            PrivacySettings {
                profile_discoverable: false,
                public_read_receipts: false,
                presence_visible: true,
            },
        );

        let settings = manager.settings(&alice).unwrap();
        assert_eq!(settings.theme, ThemeSetting::Dark);
        assert_eq!(settings.language, "zh-CN");
        assert!(settings.notifications.muted_realms.contains(&realm_id));
        assert!(!settings.privacy.profile_discoverable);
    }

    #[test]
    fn settings_manage_blocklists() {
        let alice = did("alice");
        let bob = did("bob");
        let mut manager = SettingsManager::new();

        assert!(manager.block_user(alice.clone(), bob.clone()));
        assert!(manager.is_blocked(&alice, &bob));
        assert_eq!(manager.blocked_users(&alice), vec![&bob]);
        assert!(manager.unblock_user(&alice, &bob));
        assert!(!manager.is_blocked(&alice, &bob));
    }
}
