use std::collections::BTreeMap;

use arkret_canonical as canonical;
use arkret_hlc::Cursor as SyncCursor;
use arkret_models_collaboration::sync_frames::account_subscribe::{
    AccountSubscribeFrame, AccountSubscribeFrameKind, AccountSubscribeRealms,
};
use arkret_models_collaboration::sync_frames::account_sync::RealmSyncEntry;
use serde_json::json;

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
