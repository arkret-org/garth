use arkret_state::resolver::RealmState;
use arkret_wire::RealmId;
use garth::{MemoryPersistenceStore, StateSnapshotStore, restore_realm_state_from_persistence};

fn main() -> garth::Result<()> {
    let realm_id = RealmId::new("ak:realm:AagCPdrqXX6jLnry9ez4FYiULbKas6Z7PCgbH06WlNUV")?;
    let state = RealmState::new(realm_id.clone());

    let mut store = MemoryPersistenceStore::new();
    store.put_state_snapshot(state.snapshot()?)?;

    let restored = restore_realm_state_from_persistence(&store, &realm_id)?;
    assert_eq!(restored.state.realm_id, realm_id);

    Ok(())
}
