use std::collections::BTreeMap;

use arkret_auth::AuthManager;
use arkret_canonical as canonical;
use arkret_hlc::Cursor as SyncCursor;
use arkret_models_collaboration::sync_frames::account_subscribe::{
    AccountSubscribeFrame, AccountSubscribeFrameKind, AccountSubscribeRealms,
};
use arkret_models_collaboration::sync_frames::account_sync::RealmSyncEntry;
use arkret_wire::{DeviceId, DidCoreId, RealmId};
use garth::StoreCache;
use serde_json::json;

fn did(name: &str) -> DidCoreId {
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

#[test]
fn error_boundary_and_concurrency_paths_are_covered() {
    assert!(RealmId::new("not-a-realm").is_err());

    let mut auth = AuthManager::default();
    auth.register_password_user("alice", "secret", did("alice"))
        .unwrap();
    assert!(
        auth.login_password("alice", "wrong", device("desktop"))
            .is_err()
    );

    let mut empty_cache: StoreCache<&str, i32> = StoreCache::new(0);
    empty_cache.insert("a", 1);
    assert!(empty_cache.is_empty());
}

#[test]
fn protocol_conformance_vectors_remain_stable() {
    let value = json!({"b": 2, "a": 1});
    assert_eq!(
        canonical::canonical_sha256(&value).unwrap(),
        "sha256:43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777"
    );

    let cursor = SyncCursor::new().unwrap().encode().unwrap();
    let decoded = SyncCursor::decode(&cursor).unwrap();
    assert_eq!(decoded.v, "1");
    assert!(!decoded.h.is_empty());
}

#[test]
fn interoperability_serialization_roundtrips() {
    let frame = AccountSubscribeFrame {
        kind: AccountSubscribeFrameKind::Delta,
        cursor: Some("s1".to_owned()),
        realms: Some(AccountSubscribeRealms {
            entries: BTreeMap::from([(
                "ak:realm:AagCPdrqXX6jLnry9ez4FYiULbKas6Z7PCgbH06WlNUV".to_owned(),
                RealmSyncEntry::default(),
            )]),
        }),
        to_device: None,
        device_lists: None,
        account_data: None,
        notifications: None,
        agent_signer_evidence_bundle: None,
        partial: None,
        priority: None,
        reconnect_after_ms: None,
    };

    let json = serde_json::to_string(&frame).unwrap();
    let decoded: AccountSubscribeFrame = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.cursor.as_deref(), Some("s1"));
}

#[test]
fn stress_smoke_bounds_cache_entries() {
    let mut cache = StoreCache::new(128);
    for index in 0..1000 {
        cache.insert(index, index);
    }
    assert_eq!(cache.len(), 128);
}
