use arkret_http_client::ClientBuilder;
use arkret_wire::{CommitStreamRef, EventId, RealmId};
use garth::{
    ArkretClient, MemoryOutboundQueueStore, MemoryStore, OutboundEngine, RealmProjectionState,
    RealmReplica, SystemClock,
};
use url::Url;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Discovery normally supplies this verified Station URL.
    let transport = ClientBuilder::new(Url::parse("https://station.example")?).build()?;
    let client = ArkretClient::new(transport, MemoryStore::new());

    // Every Realm, Circle and Sidecar is replicated as its own commit stream.
    let realm_id = RealmId::from_event_id(&EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        [7; 32],
    ));
    let replica = RealmReplica::new(realm_id.clone());
    assert_eq!(replica.realm_id, realm_id);

    // The host projection keeps one independent tail per visible stream and
    // never a Realm-wide position.
    let projection = RealmProjectionState::default();
    assert_eq!(
        projection.tail(&CommitStreamRef::Realm {
            realm_id: realm_id.clone()
        }),
        None
    );

    // Producer submissions are durable before they are ever forwarded.
    let outbound = OutboundEngine::new(MemoryOutboundQueueStore::new(), SystemClock);
    let _ = outbound.store();
    let _authority = client.authority();

    println!("minimal garth client is ready for verified authority discovery");
    Ok(())
}
