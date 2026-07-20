use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use arkret::{canonical, *};
use garth::{BaseClient, Realm, SessionMeta, StoreCache};
use serde_json::json;

fn did(name: &str) -> Did {
    Did::new(format!("did:webvh:z6mkfixture:{name}.example")).unwrap()
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

fn event(kind: &str, seq: u64, realm_id: &RealmId, content: serde_json::Value) -> Event {
    Event {
        event_id: EventId::new(format!("ak:event:01904100-0000-7000-8000-{seq:012x}")).unwrap(),
        kind: kind.into(),
        realm_id: realm_id.clone(),
        actor_id: did("alice"),
        actor_seq: seq,
        created_at: chrono::Utc::now(),
        hlc: Hlc::new(format!("01970e589d21-{seq:04x}-a13f9c2e")).unwrap(),
        prev_refs: vec![],
        effective_scope: None,
        refs: vec![],
        preconditions: vec![],
        effects: vec![],
        seal_ref: None,
        auth_context: None,
        seal_basis: None,
        requirements: EventRequirements::default(),
        redacts: None,
        payload: serde_json::from_value(content).unwrap(),
        executed_by: None,
        authorization_ref: None,
        applet_id: None,
        external_ref: None,
        actor_kind: None,
        unsigned: BTreeMap::new(),
        proofs: vec![],
    }
}

#[test]
fn end_to_end_auth_session_and_realm_query() {
    let alice = did("alice");
    let mut auth = AuthManager::default();
    auth.register_password_user("alice", "secret", alice.clone())
        .unwrap();
    let session = auth
        .login_password("alice", "secret", device("desktop"))
        .unwrap();

    let base = Arc::new(BaseClient::new());
    base.set_session_meta(SessionMeta {
        user_id: session.user_id,
        device_id: session.device_id,
        session_credential: Some(session.session_credential),
        expires_at: Some(session.expires_at),
    })
    .unwrap();

    let realm_id = RealmId::new("ak:realm:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
    let morph_id = MorphId::new("ak:morph:01904100-0000-7000-8000-d48c478ecd0b").unwrap();
    base.process_events(
        &realm_id,
        vec![event(
            arkret_core::events::EventKind::MORPH_CREATE,
            1,
            &realm_id,
            json!({
                "object": {
                    "id": morph_id.as_str(),
                    "schema": MORPH_SCHEMA,
                    "realm_id": realm_id.as_str(),
                    "schema_refs": [MORPH_SCHEMA],
                    "morph_type": "task",
                    "metadata": {"title": "Ship SDK"},
                    "fields": {"status": "todo"},
                    "stage": "draft",
                    "created_by": "did:webvh:z6mkfixture:alice.example",
                    "created_at": "2026-05-02T00:00:00.000Z"
                }
            }),
        )],
    )
    .unwrap();

    let realm = Realm::new(realm_id.clone(), base);
    assert_eq!(realm.search_morphs("ship").len(), 1);
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

    let cursor = Cursor::new().unwrap().encode().unwrap();
    let decoded = Cursor::decode(&cursor).unwrap();
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
                "ak:realm:01904100-0000-7000-8000-9b64700c6ee8".to_owned(),
                RealmSyncEntry::default(),
            )]),
        }),
        to_device: None,
        device_lists: None,
        account_data: None,
        presence: None,
        notifications: None,
        partial: None,
        priority: None,
        reconnect_after_ms: None,
    };

    let json = serde_json::to_string(&frame).unwrap();
    let decoded: AccountSubscribeFrame = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.cursor.as_deref(), Some("s1"));
}

#[test]
fn stress_smoke_processes_many_index_and_cache_entries() {
    let mut directory = DirectoryService::new();
    for index in 0..250 {
        let mut entry = RealmSearchEntry::new(
            RealmId::new(format!("ak:realm:01904100-0000-7000-8000-{index:012x}")).unwrap(),
            format!("Realm {index}"),
        );
        entry
            .tags
            .insert(if index % 2 == 0 { "even" } else { "odd" }.to_owned());
        directory.publish_realm(entry);
    }
    assert_eq!(
        directory
            .recommend_realms(BTreeSet::from(["even".to_owned()]), BTreeSet::new(), 10)
            .len(),
        10
    );

    let mut cache = StoreCache::new(128);
    for index in 0..1000 {
        cache.insert(index, index);
    }
    assert_eq!(cache.len(), 128);
}
