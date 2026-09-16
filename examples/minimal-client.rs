use arkret_http_client::ClientBuilder;
use arkret_wire::{EventId, RealmId};
use garth::{ArkretClient, MemoryStore, RealmReplica};
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
    let _authority = client.authority();
    println!("minimal garth client is ready for verified authority discovery");
    Ok(())
}
