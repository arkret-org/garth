use arkret::sync_client::SendQueueItemKind;
use arkret_core::RealmId;
use garth::{
    ArkretClient, ClientEvent, ClientProjector, MemoryStore, NativeExecutor, OutboundEngine,
};

struct Projector;

impl ClientProjector for Projector {
    async fn project(&self, batch: Vec<ClientEvent>) -> arkret_core::Result<()> {
        println!("projected {} client events", batch.len());
        Ok(())
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> arkret_core::Result<()> {
    let store = MemoryStore::new();
    let client = ArkretClient::new(NativeExecutor, store.clone(), store.clone());
    let _subscriptions = client.subscription_engine();
    let _projector = Projector;

    // A host builds signed/encrypted wire events in its OutboundSubmitter;
    // queue identity, persistence, retry and local-echo lifecycle stay shared.
    let outbound = OutboundEngine::new(store);
    outbound
        .enqueue(
            Some("example-transaction-1".to_owned()),
            RealmId::new("ak:realm:01904100-0000-7000-8000-000000000001")?,
            SendQueueItemKind::Message,
            serde_json::json!({"kind": "ak.content.text", "body": "hello"}),
            Vec::new(),
        )
        .await?;
    println!(
        "queued {} outbound item",
        outbound.snapshot().await?.items.len()
    );
    Ok(())
}
