//! Local state and crypto-intent tests, not native authorization or a physical
//! server-backup acceptance test. Memory is only the shared test backend.

use super::*;
use crate::MemorySecureKeyStore;

fn fixture() -> (
    ContentRootBackupEntry,
    KeyBackup,
    ContentEndpoint,
    arkret_event_draft::EventIntent,
) {
    let f = arkret_schema_conformance::spec_json_artifact("fixtures/content-history-fixture.json")
        .unwrap();
    let root = serde_json::from_value(f["root_backup"]["plaintext"]["items"][0].clone()).unwrap();
    let backup = serde_json::from_value(f["root_backup"]["envelope"].clone()).unwrap();
    let producer: ContentEndpoint =
        serde_json::from_value(f["kat"]["content_context"]["producer"].clone()).unwrap();
    let outer = &f["kat"]["outer_event"];
    let intent = serde_json::from_value(serde_json::json!({
        "kind":outer["kind"],"scope_ref":outer["scope_ref"],
        "actor_id":producer.actor_id,"created_at":outer["created_at"],
        "payload":f["local_message_authoring"],
    }))
    .unwrap();
    (root, backup, producer, intent)
}

#[tokio::test]
async fn reopened_vault_keeps_only_original_roots_and_exact_backup_ciphertext() {
    let (root, backup, ..) = fixture();
    let store = MemorySecureKeyStore::default();
    let endpoint = MlsWelcomeRecipientEndpoint::Device {
        device_id: backup.signature_proof.device_id.clone().unwrap(),
    };
    let vault = ContentRootVault::new(&store, &backup.actor_id, &endpoint);
    assert!(vault.freeze_backup("first-root", &backup).await.is_err());
    vault.retain_root(&root).await.unwrap();
    assert_eq!(
        vault.cached_root(&root.root_ref).unwrap(),
        Some(root.clone())
    );
    vault.freeze_backup("first-root", &backup).await.unwrap();
    let reopened = ContentRootVault::new(&store, &backup.actor_id, &endpoint);
    assert_eq!(
        reopened.root(&root.root_ref).await.unwrap(),
        Some(root.clone())
    );
    assert_eq!(
        reopened.frozen_backup("first-root").await.unwrap(),
        Some(backup.clone())
    );
    let mut changed = backup.clone();
    changed.created_at += chrono::Duration::seconds(1);
    assert!(
        reopened
            .freeze_backup("first-root", &changed)
            .await
            .is_err()
    );
    assert_eq!(
        reopened.frozen_backup("first-root").await.unwrap(),
        Some(backup.clone())
    );
    let other =
        arkret_wire::DeviceId::new("ak:device:01904100-0000-7000-8000-000000000002").unwrap();
    assert!(
        ContentRootVault::new(
            &store,
            &backup.actor_id,
            &MlsWelcomeRecipientEndpoint::Device { device_id: other }
        )
        .root(&root.root_ref)
        .await
        .unwrap()
        .is_none()
    );
    let mut changed = root.clone();
    changed.secret_id.push_str("_changed");
    vault.retain_root(&changed).await.unwrap();
    assert_eq!(
        vault.root(&root.root_ref).await.unwrap(),
        Some(root.clone())
    );
    changed.root_ref = Hash::new(arkret_canonical::sha256_digest(b"not-the-root")).unwrap();
    assert!(vault.retain_root(&changed).await.is_err());
}

#[tokio::test]
async fn concurrent_exact_salt_intents_converge_and_changed_bindings_never_reuse_the_salt() {
    let (root, backup, producer, intent) = fixture();
    let store = YieldingStore::default();
    let endpoint = MlsWelcomeRecipientEndpoint::Device {
        device_id: backup.signature_proof.device_id.clone().unwrap(),
    };
    let vault = ContentRootVault::new(&store, &backup.actor_id, &endpoint);
    let protection = ContentProtection {
        root_refs: vec![root.root_ref.clone()],
        blob_refs: vec![],
        backup_refs: vec![backup.backup_id.clone()],
    };
    let mut binding = ContentSaltBinding {
        intent: &intent,
        root_context: &root.root_context,
        root_ref: &root.root_ref,
        producer: &producer,
        content_type: "application/vnd.arkret.message+json",
        protection: &protection,
        plaintext: b"first plaintext",
    };
    assert!(
        vault
            .reserve_salt("message", "/encrypted_content", &binding)
            .await
            .is_err()
    );
    vault.retain_root(&root).await.unwrap();
    let (left, right) = tokio::join!(
        vault.reserve_salt("message", "/encrypted_content", &binding),
        vault.reserve_salt("message", "/encrypted_content", &binding),
    );
    let first = left.unwrap();
    assert_eq!(first, right.unwrap());
    let reopened = ContentRootVault::new(&store, &backup.actor_id, &endpoint);
    assert_eq!(
        reopened
            .reserve_salt("message", "/encrypted_content", &binding)
            .await
            .unwrap(),
        first
    );
    let metadata = vault
        .reserve_salt("message", "/encrypted_metadata", &binding)
        .await
        .unwrap();
    assert_ne!(metadata, first);
    binding.plaintext = b"changed plaintext";
    let second = vault
        .reserve_salt("message", "/encrypted_content", &binding)
        .await
        .unwrap();
    assert_ne!(second, first);
    binding.plaintext = b"first plaintext";
    let third = vault
        .reserve_salt("message", "/encrypted_content", &binding)
        .await
        .unwrap();
    assert_ne!(third, first);
    assert_ne!(third, second);
    let mut changed_intent = serde_json::to_value(&intent).unwrap();
    changed_intent["external_ref"] = serde_json::json!({"app":"changed"});
    let changed_intent = serde_json::from_value(changed_intent).unwrap();
    binding.intent = &changed_intent;
    assert_ne!(
        vault
            .reserve_salt("message", "/encrypted_content", &binding)
            .await
            .unwrap(),
        third
    );
}

#[tokio::test]
async fn salt_rejects_another_actual_actor_scope_or_missing_backup_dependency() {
    let (root, backup, mut producer, intent) = fixture();
    let store = MemorySecureKeyStore::default();
    let endpoint = MlsWelcomeRecipientEndpoint::Device {
        device_id: backup.signature_proof.device_id.clone().unwrap(),
    };
    let vault = ContentRootVault::new(&store, &backup.actor_id, &endpoint);
    vault.retain_root(&root).await.unwrap();
    let mut protection = ContentProtection {
        root_refs: vec![root.root_ref.clone()],
        blob_refs: vec![],
        backup_refs: vec![],
    };
    let binding = ContentSaltBinding {
        intent: &intent,
        root_context: &root.root_context,
        root_ref: &root.root_ref,
        producer: &producer,
        content_type: "application/vnd.arkret.message+json",
        protection: &protection,
        plaintext: b"secret",
    };
    assert!(
        vault
            .reserve_salt("message", "/encrypted_content", &binding)
            .await
            .is_err()
    );
    protection.backup_refs.push(backup.backup_id.clone());
    producer.actor_id = ActorId::account(arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new("ak:did_core:web:other.example").unwrap(),
        backup.actor_id.as_account_id().unwrap().station_id.clone(),
    ));
    let binding = ContentSaltBinding {
        intent: &intent,
        root_context: &root.root_context,
        root_ref: &root.root_ref,
        producer: &producer,
        content_type: "application/vnd.arkret.message+json",
        protection: &protection,
        plaintext: b"secret",
    };
    assert!(
        vault
            .reserve_salt("message", "/encrypted_content", &binding)
            .await
            .is_err()
    );
}

#[cfg(not(target_arch = "wasm32"))]
type StoreFuture<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;
#[cfg(target_arch = "wasm32")]
type StoreFuture<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + 'a>>;

#[derive(Default)]
struct YieldingStore(MemorySecureKeyStore);

impl SecureKeyStore for YieldingStore {
    fn store_secret_bytes(&self, key: &str, value: &[u8]) -> crate::SecureKeyStoreResult<()> {
        self.0.store_secret_bytes(key, value)
    }
    fn get_secret_bytes(
        &self,
        key: &str,
    ) -> crate::SecureKeyStoreResult<Option<arkret_keystore::KeyBytes>> {
        self.0.get_secret_bytes(key)
    }
    fn delete_secret(&self, key: &str) -> crate::SecureKeyStoreResult<()> {
        self.0.delete_secret(key)
    }
    fn list_secret_keys(&self, prefix: Option<&str>) -> crate::SecureKeyStoreResult<Vec<String>> {
        self.0.list_secret_keys(prefix)
    }
    fn backend_info(&self) -> crate::SecureKeyStoreBackendInfo {
        self.0.backend_info()
    }
    fn read_secret_bytes_durable<'a>(
        &'a self,
        key: &'a str,
    ) -> StoreFuture<'a, crate::SecureKeyStoreResult<Option<arkret_keystore::KeyBytes>>> {
        Box::pin(async move {
            let value = self.0.read_secret_bytes_durable(key).await;
            tokio::task::yield_now().await;
            value
        })
    }
    fn compare_exchange_secret_bytes_durable<'a>(
        &'a self,
        key: &'a str,
        expected: Option<&'a [u8]>,
        replacement: &'a [u8],
    ) -> StoreFuture<'a, crate::SecureKeyStoreResult<bool>> {
        Box::pin(async move {
            tokio::task::yield_now().await;
            self.0
                .compare_exchange_secret_bytes_durable(key, expected, replacement)
                .await
        })
    }
}

#[derive(Default)]
struct CacheOnlyStore(MemorySecureKeyStore);

impl SecureKeyStore for CacheOnlyStore {
    fn store_secret_bytes(&self, key: &str, value: &[u8]) -> crate::SecureKeyStoreResult<()> {
        self.0.store_secret_bytes(key, value)
    }
    fn get_secret_bytes(
        &self,
        key: &str,
    ) -> crate::SecureKeyStoreResult<Option<arkret_keystore::KeyBytes>> {
        self.0.get_secret_bytes(key)
    }
    fn delete_secret(&self, key: &str) -> crate::SecureKeyStoreResult<()> {
        self.0.delete_secret(key)
    }
    fn list_secret_keys(&self, prefix: Option<&str>) -> crate::SecureKeyStoreResult<Vec<String>> {
        self.0.list_secret_keys(prefix)
    }
    fn backend_info(&self) -> crate::SecureKeyStoreBackendInfo {
        self.0.backend_info()
    }
}

#[tokio::test]
async fn unsupported_durability_never_falls_back_to_sync_or_cache_writes() {
    let (root, backup, ..) = fixture();
    let store = CacheOnlyStore::default();
    let endpoint = MlsWelcomeRecipientEndpoint::Device {
        device_id: backup.signature_proof.device_id.clone().unwrap(),
    };
    let vault = ContentRootVault::new(&store, &backup.actor_id, &endpoint);
    assert!(vault.retain_root(&root).await.is_err());
    assert!(vault.root(&root.root_ref).await.is_err());
    assert!(vault.freeze_backup("first-root", &backup).await.is_err());
    assert!(store.list_secret_keys(None).unwrap().is_empty());
    for prefix in [
        "content-root/v1/",
        "content-root-state/v1/",
        "content-root-backup/v1/",
        "content-root-download/v1/",
        "content-salt/v1/",
    ] {
        assert!(is_content_root_vault_key(&format!("{prefix}digest")));
        assert!(is_content_root_vault_key(&format!("user.{prefix}digest")));
    }
    assert!(!is_content_root_vault_key("ordinary-preferences"));
}

#[tokio::test]
async fn original_state_lookup_survives_reopen_and_repairs_an_interrupted_index() {
    let (root, backup, ..) = fixture();
    let store = MemorySecureKeyStore::default();
    let endpoint = MlsWelcomeRecipientEndpoint::Device {
        device_id: backup.signature_proof.device_id.clone().unwrap(),
    };
    let vault = ContentRootVault::new(&store, &backup.actor_id, &endpoint);
    let context = &root.root_context;
    assert!(
        vault
            .root_for_group_state(&context.effective_scope, &context.group_state_ref)
            .await
            .unwrap()
            .is_none()
    );
    vault.retain_root(&root).await.unwrap();
    let reopened = ContentRootVault::new(&store, &backup.actor_id, &endpoint);
    assert_eq!(
        reopened
            .root_for_group_state(&context.effective_scope, &context.group_state_ref)
            .await
            .unwrap(),
        Some(root.clone())
    );
    // Model a crash after the immutable root write but before its index write.
    let key = vault
        .key(
            "content-root-state",
            (&context.effective_scope, &context.group_state_ref),
        )
        .unwrap();
    store.delete_secret(&key).unwrap();
    assert!(
        reopened
            .root_for_group_state(&context.effective_scope, &context.group_state_ref)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        reopened.root(&root.root_ref).await.unwrap(),
        Some(root.clone())
    );
    reopened.retain_root(&root).await.unwrap();
    assert_eq!(
        reopened
            .root_for_group_state(&context.effective_scope, &context.group_state_ref)
            .await
            .unwrap(),
        Some(root.clone())
    );
    let other = MlsWelcomeRecipientEndpoint::Device {
        device_id: arkret_wire::DeviceId::new("ak:device:01904100-0000-7000-8000-000000000002")
            .unwrap(),
    };
    assert!(
        ContentRootVault::new(&store, &backup.actor_id, &other)
            .root_for_group_state(&context.effective_scope, &context.group_state_ref)
            .await
            .unwrap()
            .is_none()
    );
    let mut account = backup.actor_id.as_account_id().unwrap().clone();
    account.station_id =
        arkret_wire::DidCoreId::new("ak:did_core:web:other-station.example").unwrap();
    assert!(
        ContentRootVault::new(&store, &ActorId::account(account), &endpoint)
            .root_for_group_state(&context.effective_scope, &context.group_state_ref)
            .await
            .unwrap()
            .is_none()
    );
    let wrong = EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [92; 32]);
    assert!(
        reopened
            .root_for_group_state(&context.effective_scope, &wrong)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn original_state_lookup_rejects_conflicts_misdirection_and_missing_root_records() {
    let (root, backup, ..) = fixture();
    let store = MemorySecureKeyStore::default();
    let endpoint = MlsWelcomeRecipientEndpoint::Device {
        device_id: backup.signature_proof.device_id.clone().unwrap(),
    };
    let vault = ContentRootVault::new(&store, &backup.actor_id, &endpoint);
    vault.retain_root(&root).await.unwrap();
    let context = &root.root_context;
    let mut conflict = root.clone();
    conflict.root_context.backup_strategy_ref =
        EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [93; 32]);
    conflict.root_ref = arkret_crypto::content_history::content_root_ref(
        &conflict.root_base64url,
        &conflict.root_context,
    )
    .unwrap();
    assert!(vault.retain_root(&conflict).await.is_err());
    assert_eq!(
        vault
            .root_for_group_state(&context.effective_scope, &context.group_state_ref)
            .await
            .unwrap(),
        Some(root.clone())
    );
    let mut other = root.clone();
    other.root_context.group_state_ref =
        EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [94; 32]);
    other.root_ref = arkret_crypto::content_history::content_root_ref(
        &other.root_base64url,
        &other.root_context,
    )
    .unwrap();
    vault.retain_root(&other).await.unwrap();
    let key = vault
        .key(
            "content-root-state",
            (&context.effective_scope, &context.group_state_ref),
        )
        .unwrap();
    store
        .store_secret_bytes(&key, &serde_json::to_vec(&other.root_ref).unwrap())
        .unwrap();
    assert!(
        vault
            .root_for_group_state(&context.effective_scope, &context.group_state_ref)
            .await
            .is_err()
    );
    store
        .delete_secret(&vault.key("content-root", &other.root_ref).unwrap())
        .unwrap();
    assert!(
        vault
            .root_for_group_state(&context.effective_scope, &context.group_state_ref)
            .await
            .is_err()
    );
}
