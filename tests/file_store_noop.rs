#![cfg(all(feature = "native", not(target_arch = "wasm32")))]

use arkret_wire::{CommitStreamRef, EventId, RealmId};
use garth::{CursorScope, CursorStore, EventCacheStore, FileStore};

fn scope() -> CursorScope {
    CursorScope::CommitStream {
        service_id: None,
        stream_ref: CommitStreamRef::Realm {
            realm_id: RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19")
                .unwrap(),
        },
    }
}

#[tokio::test]
async fn identical_cursor_save_is_a_file_noop() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("garth.json");
    let store = FileStore::open(&path).unwrap();
    store
        .save(scope(), "ak:cursor:same".to_owned())
        .await
        .unwrap();
    let before = std::fs::read(&path).unwrap();
    store
        .save(scope(), "ak:cursor:same".to_owned())
        .await
        .unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), before);
}

#[tokio::test]
async fn file_store_reopens_durable_cursor() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("garth.json");
    FileStore::open(&path)
        .unwrap()
        .save(scope(), "ak:cursor:durable".to_owned())
        .await
        .unwrap();
    let reopened = FileStore::open(&path).unwrap();
    assert_eq!(
        reopened.load(scope()).await.unwrap().as_deref(),
        Some("ak:cursor:durable")
    );
}

#[tokio::test]
async fn duplicate_event_remember_is_idempotent() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("garth.json");
    let store = FileStore::open(&path).unwrap();
    let event_id = EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [7; 32]);
    store.remember(event_id.clone()).await.unwrap();
    let before = std::fs::read(&path).unwrap();
    store.remember(event_id.clone()).await.unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert!(store.seen(event_id).await.unwrap());
}

#[tokio::test]
async fn clear_missing_cursor_is_idempotent() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("garth.json");
    let store = FileStore::open(&path).unwrap();
    store
        .save(scope(), "ak:cursor:present".to_owned())
        .await
        .unwrap();
    store.clear(scope()).await.unwrap();
    let before = std::fs::read(&path).unwrap();
    store.clear(scope()).await.unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), before);
}
