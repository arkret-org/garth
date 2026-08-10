#![cfg(all(feature = "native", not(target_arch = "wasm32")))]

use std::time::Duration;

use arkret_wire::{DeviceId, DidCoreId, EventId};
use garth::{
    CursorScope, CursorStore, DurableInboxStore, EventCacheStore, FileStore, OutboundQueueStore,
};

fn account_scope() -> CursorScope {
    CursorScope::Account {
        service_id: None,
        actor_id: DidCoreId::new("ak:did_core:webvh:z6mkfixture:alice.example").unwrap(),
        device_id: DeviceId::new("ak:device:01904100-0000-7000-8000-000000000001").unwrap(),
    }
}

#[tokio::test]
async fn idle_mutations_leave_the_file_untouched() {
    let path = std::env::temp_dir().join(format!(
        "garth-filestore-integration-noop-{}.json",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&path);
    let store = FileStore::open(&path).unwrap();
    let scope = account_scope();
    let cursor = "ak:cursor:stable".to_owned();
    let event = EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [0x77; 32]);

    store.save(scope.clone(), cursor.clone()).await.unwrap();
    store.remember(event.clone()).await.unwrap();
    let before_bytes = std::fs::read(&path).unwrap();
    let before_modified = std::fs::metadata(&path).unwrap().modified().unwrap();

    tokio::time::sleep(Duration::from_millis(25)).await;
    store.save(scope.clone(), cursor.clone()).await.unwrap();
    store.commit(scope, Some(cursor), Vec::new()).await.unwrap();
    store.remember(event).await.unwrap();
    store
        .mutate_outbound(|_| Ok::<_, garth::Error>(()))
        .await
        .unwrap();

    assert_eq!(std::fs::read(&path).unwrap(), before_bytes);
    assert_eq!(
        std::fs::metadata(&path).unwrap().modified().unwrap(),
        before_modified
    );
    assert!(!store.has_active_outbound().unwrap());
    let _ = std::fs::remove_file(&path);
}
