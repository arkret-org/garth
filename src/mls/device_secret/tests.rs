//! Tests for authority- and device-scoped MLS secret management.

use arkret_wire::{AccountId, DeviceId, Did, DidCoreId, project_did_to_core_id};

use super::*;
use crate::store::{MemorySecureKeyStore, SecureKeyStore, SecureKeyStoreError};

fn authority(principal_did: &str, server_id: &str) -> AccountId {
    let did = Did::new(principal_did).unwrap();
    AccountId::new(
        project_did_to_core_id(&did).unwrap(),
        DidCoreId::new(server_id).unwrap(),
    )
}

fn device(number: u8) -> DeviceId {
    DeviceId::new(format!("ak:device:01904100-0000-7000-8000-{number:012}")).unwrap()
}

#[test]
fn account_secret_is_reused_within_exact_authority() {
    let store = MemorySecureKeyStore::new();
    let authority = authority(
        "did:webvh:z6mkalice:old.example:alice",
        "ak:did_core:web:server.example",
    );
    let first = load_or_create_account_mls_secret(&store, &authority).unwrap();
    let second = load_or_create_account_mls_secret(&store, &authority).unwrap();
    assert_eq!(first, second);
    assert_eq!(first.len(), 43);
}

#[test]
fn checkpoint_secret_load_does_not_create() {
    let store = MemorySecureKeyStore::new();
    let authority = authority(
        "did:webvh:z6mkalice:alice.example",
        "ak:did_core:web:server.example",
    );
    let missing = load_device_checkpoint_secret(&store, &authority, &device(1)).unwrap_err();
    assert!(matches!(missing, SecureKeyStoreError::NotFound));
    assert!(store.list_secret_keys(None).unwrap().is_empty());
}

#[test]
fn same_core_relocation_keeps_the_account_secret_key() {
    let old_authority = authority(
        "did:webvh:z6mkalice:old.example:alice",
        "ak:did_core:web:server.example",
    );
    let relocated_authority = authority(
        "did:webvh:z6mkalice:new.example:users:alice",
        "ak:did_core:web:server.example",
    );
    assert_eq!(old_authority, relocated_authority);
    assert_eq!(
        account_mls_secret_key(&old_authority).unwrap(),
        account_mls_secret_key(&relocated_authority).unwrap()
    );
}

#[test]
fn same_principal_on_different_servers_has_distinct_secrets() {
    let store = MemorySecureKeyStore::new();
    let first = authority(
        "did:webvh:z6mkalice:alice.example",
        "ak:did_core:web:server-a.example",
    );
    let second = authority(
        "did:webvh:z6mkalice:alice.example",
        "ak:did_core:web:server-b.example",
    );
    store_account_mls_secret(&store, &first, "server-a-secret").unwrap();
    store_account_mls_secret(&store, &second, "server-b-secret").unwrap();

    assert_eq!(
        load_account_mls_secret(&store, &first)
            .unwrap()
            .unwrap()
            .secret,
        "server-a-secret"
    );
    assert_eq!(
        load_account_mls_secret(&store, &second)
            .unwrap()
            .unwrap()
            .secret,
        "server-b-secret"
    );
    assert_ne!(
        account_mls_secret_key(&first).unwrap(),
        account_mls_secret_key(&second).unwrap()
    );
}

#[test]
fn account_secret_is_shared_across_devices_but_keypackage_state_is_not() {
    let store = MemorySecureKeyStore::new();
    let authority = authority(
        "did:webvh:z6mkalice:alice.example",
        "ak:did_core:web:server.example",
    );
    let first_device = device(1);
    let second_device = device(2);
    store_account_mls_secret(&store, &authority, "shared-secret").unwrap();
    assert_eq!(
        load_device_checkpoint_secret(&store, &authority, &first_device).unwrap(),
        load_device_checkpoint_secret(&store, &authority, &second_device).unwrap()
    );

    let first_key =
        mls_key_package_identity_state_key(&authority, &first_device, "ak:keypackage:one").unwrap();
    let second_key =
        mls_key_package_identity_state_key(&authority, &second_device, "ak:keypackage:one")
            .unwrap();
    assert_ne!(first_key, second_key);
}

#[test]
fn keypackage_inventory_is_v1_and_authority_device_scoped() {
    let first_authority = authority(
        "did:webvh:z6mkalice:alice.example",
        "ak:did_core:web:server-a.example",
    );
    let second_authority = authority(
        "did:webvh:z6mkalice:alice.example",
        "ak:did_core:web:server-b.example",
    );
    let first_device = device(1);
    let second_device = device(2);
    let key = mls_key_package_inventory_key(&first_authority, &first_device).unwrap();
    assert!(key.starts_with("inkson.mls_key_package.inventory.v1."));
    assert_ne!(
        key,
        mls_key_package_inventory_key(&second_authority, &first_device).unwrap()
    );
    assert_ne!(
        key,
        mls_key_package_inventory_key(&first_authority, &second_device).unwrap()
    );
}

#[test]
fn recovered_version_replaces_stale_higher_versions_only_in_its_authority() {
    let store = MemorySecureKeyStore::new();
    let first = authority(
        "did:webvh:z6mkalice:alice.example",
        "ak:did_core:web:server-a.example",
    );
    let second = authority(
        "did:webvh:z6mkalice:alice.example",
        "ak:did_core:web:server-b.example",
    );
    store_account_mls_secret_version(&store, &first, 3, "stale").unwrap();
    store_account_mls_secret_version(&store, &second, 3, "other-server").unwrap();
    replace_account_mls_secret_version(&store, &first, 2, "recovered").unwrap();

    assert_eq!(
        load_account_mls_secret(&store, &first)
            .unwrap()
            .unwrap()
            .secret,
        "recovered"
    );
    assert_eq!(
        load_account_mls_secret(&store, &second)
            .unwrap()
            .unwrap()
            .secret,
        "other-server"
    );
}
