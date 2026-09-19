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

#[tokio::test]
async fn independent_handles_preserve_each_others_cursor_updates() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("garth.json");
    let first = FileStore::open(&path).unwrap();
    let second = FileStore::open(&path).unwrap();
    let other_scope = CursorScope::CommitStream {
        service_id: None,
        stream_ref: CommitStreamRef::Realm {
            realm_id: RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc18")
                .unwrap(),
        },
    };

    first
        .save(scope(), "ak:cursor:first".to_owned())
        .await
        .unwrap();
    second
        .save(other_scope.clone(), "ak:cursor:second".to_owned())
        .await
        .unwrap();

    assert_eq!(
        second.load(scope()).await.unwrap().as_deref(),
        Some("ak:cursor:first")
    );
    assert_eq!(
        first.load(other_scope).await.unwrap().as_deref(),
        Some("ak:cursor:second")
    );
}

#[tokio::test]
async fn independent_handle_observes_newly_committed_event() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("garth.json");
    let first = FileStore::open(&path).unwrap();
    let second = FileStore::open(&path).unwrap();
    let event_id = EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [9; 32]);

    first.remember(event_id.clone()).await.unwrap();

    assert!(second.seen(event_id).await.unwrap());
}

#[tokio::test]
async fn recent_event_window_is_bounded_and_survives_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("garth.json");
    let store = FileStore::open_with_seen_capacity(&path, 2).unwrap();
    let oldest = EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [1; 32]);
    let middle = EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [2; 32]);
    let newest = EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [3; 32]);
    store.remember(oldest.clone()).await.unwrap();
    store.remember(middle.clone()).await.unwrap();
    store.remember(newest.clone()).await.unwrap();

    let reopened = FileStore::open_with_seen_capacity(&path, 2).unwrap();
    assert!(!reopened.seen(oldest).await.unwrap());
    assert!(reopened.seen(middle).await.unwrap());
    assert!(reopened.seen(newest).await.unwrap());
}
