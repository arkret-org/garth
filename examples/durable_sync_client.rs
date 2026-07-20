use garth::{MemoryPersistenceStore, StateSnapshotStore, restore_realm_state_from_persistence};
use garth::{RealmId, RealmState};

fn main() -> garth::Result<()> {
    let realm_id = RealmId::new("ak:realm:01904100-0000-7000-8000-9b64700c6ee8")?;
    let state = RealmState::new(realm_id.clone());

    let mut store = MemoryPersistenceStore::new();
    store.put_state_snapshot(state.snapshot()?)?;

    let restored = restore_realm_state_from_persistence(&store, &realm_id)?;
    assert_eq!(restored.state.realm_id, realm_id);

    Ok(())
}
