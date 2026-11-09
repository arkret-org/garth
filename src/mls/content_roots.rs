//! Local history-only roots and pre-network crypto intents in the authoritative
//! secure store. Neither local possession nor persistence grants native write,
//! membership, history-disclosure or backup-recipient authority.

use arkret_models_crypto::{
    ContentEndpoint, ContentProtection, ContentRootBackupEntry, ContentRootContext, KeyBackup,
    SecretStorageItemKind,
};
use arkret_wire::{ActorId, Hash, MlsWelcomeRecipientEndpoint};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{Error, Result, SecureKeyStore};

const CAS_ATTEMPTS: usize = 8;

pub fn is_content_root_vault_key(key: &str) -> bool {
    [
        "content-root/v1/",
        "content-root-backup/v1/",
        "content-salt/v1/",
    ]
    .iter()
    .any(|prefix| key.starts_with(prefix) || key.contains(&format!(".{prefix}")))
}

/// All inputs that can change the authenticated ciphertext, before a salt is
/// allocated. The intent already fixes delegation, participants and extensions.
pub struct ContentSaltBinding<'a> {
    pub intent: &'a arkret_event_draft::EventIntent,
    pub root_context: &'a ContentRootContext,
    pub root_ref: &'a Hash,
    pub producer: &'a ContentEndpoint,
    pub content_type: &'a str,
    pub protection: &'a ContentProtection,
    pub plaintext: &'a [u8],
}

#[cfg(test)]
#[path = "content_roots_tests.rs"]
mod tests;

impl ContentSaltBinding<'_> {
    fn digest(&self) -> Result<Hash> {
        self.root_context.validate().map_err(rejected)?;
        self.producer.validate().map_err(rejected)?;
        self.protection.validate().map_err(rejected)?;
        let outer = self.intent.pre_encryption_outer_event().map_err(rejected)?;
        let actor = outer
            .get("executed_by")
            .filter(|actor| !actor.is_null())
            .or_else(|| outer.get("actor_id"))
            .ok_or_else(|| rejected("frozen actual signer missing"))?;
        if self.intent.scope_ref() != &self.root_context.effective_scope
            || *actor != serde_json::to_value(&self.producer.actor_id)?
            || !self.protection.root_refs.contains(self.root_ref)
            || self.protection.backup_refs.is_empty()
            || self.content_type.is_empty()
        {
            return Err(rejected(
                "salt binding differs from its complete intent or root dependencies",
            ));
        }
        let value = serde_json::json!({"outer_event":outer,
            "root_context":self.root_context,"root_ref":self.root_ref,
            "producer":self.producer,"content_type":self.content_type,
            "protection":self.protection,
            "plaintext_digest":arkret_canonical::sha256_digest(self.plaintext)});
        Hash::new(arkret_canonical::sha256_digest(
            arkret_canonical::canonical_json_bytes(&value)?,
        ))
        .map_err(rejected)
    }
}

/// Callers verify original authority and recipient access before importing a
/// history root. Store implementations must provide real durable read and CAS;
/// the default unsupported implementations never become an in-memory fallback.
pub struct ContentRootVault<'a> {
    store: &'a dyn SecureKeyStore,
    subject: &'a ActorId,
    endpoint: &'a MlsWelcomeRecipientEndpoint,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SaltIntent {
    binding: Hash,
    salt: String,
}

fn rejected(message: impl std::fmt::Display) -> Error {
    Error::Protocol(format!("content root vault: {message}"))
}

impl<'a> ContentRootVault<'a> {
    pub fn new(
        store: &'a dyn SecureKeyStore,
        subject: &'a ActorId,
        endpoint: &'a MlsWelcomeRecipientEndpoint,
    ) -> Self {
        Self {
            store,
            subject,
            endpoint,
        }
    }

    fn key(&self, class: &str, selector: impl Serialize) -> Result<String> {
        let bytes =
            arkret_canonical::canonical_json_bytes(&(self.subject, self.endpoint, selector))?;
        Ok(format!(
            "{class}/v1/{}",
            arkret_canonical::sha256_digest(bytes)
        ))
    }

    fn validate_root(root: &ContentRootBackupEntry) -> Result<()> {
        if arkret_crypto::content_history::content_root_ref(
            &root.root_base64url,
            &root.root_context,
        )
        .map_err(rejected)?
            != root.root_ref
        {
            return Err(rejected("root does not match its original commitment"));
        }
        arkret_models_crypto::SecretStorageEntry::ContentRoot(root.clone())
            .validate()
            .map_err(rejected)
    }

    /// Retain only authenticated R and its public context, never an MLS private
    /// checkpoint. Success resolves after the backend's durable commit.
    pub async fn retain_root(&self, root: &ContentRootBackupEntry) -> Result<()> {
        Self::validate_root(root)?;
        let key = self.key("content-root", &root.root_ref)?;
        let bytes = Zeroizing::new(serde_json::to_vec(root)?);
        for _ in 0..CAS_ATTEMPTS {
            let previous = self
                .store
                .read_secret_bytes_durable(&key)
                .await
                .map_err(rejected)?;
            if let Some(previous) = previous {
                let stored: ContentRootBackupEntry = serde_json::from_slice(previous.as_slice())?;
                Self::validate_root(&stored)?;
                if stored.root_context != root.root_context
                    || stored.root_base64url != root.root_base64url
                {
                    return Err(rejected(
                        "immutable root entry conflicts with its retained original",
                    ));
                }
                return Ok(());
            }
            if self
                .store
                .compare_exchange_secret_bytes_durable(&key, None, &bytes)
                .await
                .map_err(rejected)?
            {
                return Ok(());
            }
        }
        Err(rejected("root retention contended"))
    }

    /// Reading a retained root does not restore active MLS state or membership.
    /// A host may use its already hydrated authoritative cache on a synchronous
    /// projection path. A cache miss remains pending; it never creates a root.
    pub fn cached_root(&self, reference: &Hash) -> Result<Option<ContentRootBackupEntry>> {
        let key = self.key("content-root", reference)?;
        let Some(bytes) = self.store.get_secret_bytes(&key).map_err(rejected)? else {
            return Ok(None);
        };
        let root: ContentRootBackupEntry = serde_json::from_slice(bytes.as_slice())?;
        Self::validate_root(&root)?;
        if root.root_ref != *reference {
            return Err(rejected("cached root selector differs"));
        }
        Ok(Some(root))
    }

    /// Reading a retained root does not restore active MLS state or membership.
    pub async fn root(&self, reference: &Hash) -> Result<Option<ContentRootBackupEntry>> {
        let key = self.key("content-root", reference)?;
        let Some(bytes) = self
            .store
            .read_secret_bytes_durable(&key)
            .await
            .map_err(rejected)?
        else {
            return Ok(None);
        };
        let root: ContentRootBackupEntry = serde_json::from_slice(bytes.as_slice())?;
        Self::validate_root(&root)?;
        if root.root_ref != *reference {
            return Err(rejected("retained root is bound to another reference"));
        }
        Ok(Some(root))
    }

    /// Freeze the final signed ciphertext before its first PUT. The operation
    /// is immutable: retries load these exact bytes instead of sealing again.
    /// A successful local freeze is not a native PUT acknowledgement.
    pub async fn freeze_backup(&self, operation: &str, backup: &KeyBackup) -> Result<KeyBackup> {
        if operation.is_empty() || backup.actor_id != *self.subject {
            return Err(rejected("backup operation or complete subject differs"));
        }
        backup.validate().map_err(rejected)?;
        for item in &backup.contents {
            if item.item_kind != SecretStorageItemKind::ContentEpochRoot {
                return Err(rejected("root vault cannot publish another secret class"));
            }
            let reference = item
                .root_ref
                .as_ref()
                .ok_or_else(|| rejected("root index missing"))?;
            let root = self
                .root(reference)
                .await?
                .ok_or_else(|| rejected("backup root has not been durably retained"))?;
            if item.root_context.as_ref() != Some(&root.root_context) {
                return Err(rejected(
                    "backup index differs from its retained original root",
                ));
            }
        }
        let key = self.key("content-root-backup", operation)?;
        let bytes = serde_json::to_vec(backup)?;
        for _ in 0..CAS_ATTEMPTS {
            if let Some(previous) = self
                .store
                .read_secret_bytes_durable(&key)
                .await
                .map_err(rejected)?
            {
                if previous.as_slice() != bytes {
                    return Err(rejected(
                        "backup operation already has different frozen bytes",
                    ));
                }
                return Ok(serde_json::from_slice(previous.as_slice())?);
            }
            if self
                .store
                .compare_exchange_secret_bytes_durable(&key, None, &bytes)
                .await
                .map_err(rejected)?
            {
                return Ok(backup.clone());
            }
        }
        Err(rejected("backup freeze contended"))
    }

    pub async fn frozen_backup(&self, operation: &str) -> Result<Option<KeyBackup>> {
        if operation.is_empty() {
            return Err(rejected("backup operation is empty"));
        }
        let key = self.key("content-root-backup", operation)?;
        let Some(bytes) = self
            .store
            .read_secret_bytes_durable(&key)
            .await
            .map_err(rejected)?
        else {
            return Ok(None);
        };
        let backup: KeyBackup = serde_json::from_slice(bytes.as_slice())?;
        backup.validate().map_err(rejected)?;
        if backup.actor_id != *self.subject {
            return Err(rejected("frozen backup has another complete subject"));
        }
        Ok(Some(backup))
    }

    /// Any changed binding gets a fresh salt; an exact retry keeps its salt.
    pub async fn reserve_salt(
        &self,
        operation: &str,
        content_path: &str,
        binding: &ContentSaltBinding<'_>,
    ) -> Result<String> {
        if operation.is_empty() || !content_path.starts_with('/') {
            return Err(rejected(
                "salt intent requires its operation and exact content path",
            ));
        }
        let root = self
            .root(binding.root_ref)
            .await?
            .ok_or_else(|| rejected("salt allocation requires the durably retained root"))?;
        if root.root_context != *binding.root_context {
            return Err(rejected("salt context differs from its retained root"));
        }
        let binding = binding.digest()?;
        let key = self.key("content-salt", (operation, content_path))?;
        for _ in 0..CAS_ATTEMPTS {
            let previous = self
                .store
                .read_secret_bytes_durable(&key)
                .await
                .map_err(rejected)?;
            if let Some(previous) = &previous {
                let intent: SaltIntent = serde_json::from_slice(previous.as_slice())?;
                if arkret_canonical::base64url_decode(&intent.salt)
                    .map_err(rejected)?
                    .len()
                    != 32
                {
                    return Err(rejected("retained salt has invalid width"));
                }
                if intent.binding == binding {
                    return Ok(intent.salt);
                }
            }
            let intent = SaltIntent {
                binding: binding.clone(),
                salt: arkret_crypto::content_history::fresh_content_key_salt().map_err(rejected)?,
            };
            let bytes = serde_json::to_vec(&intent)?;
            if self
                .store
                .compare_exchange_secret_bytes_durable(
                    &key,
                    previous.as_ref().map(|value| value.as_slice()),
                    &bytes,
                )
                .await
                .map_err(rejected)?
            {
                return Ok(intent.salt);
            }
        }
        Err(rejected("salt reservation contended"))
    }
}
