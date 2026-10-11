#[test]
fn shared_authority_objects_keep_the_client_transport_bytes() {
    let (commit, handoff) = arkret_test_kit::authority_objects::objects();
    let commit: arkret_wire::RealmCommit =
        serde_json::from_slice(&serde_json::to_vec(&commit).unwrap()).unwrap();
    let handoff: arkret_wire::RealmAuthorityHandoff =
        serde_json::from_slice(&serde_json::to_vec(&handoff).unwrap()).unwrap();
    arkret_test_kit::authority_objects::assert_canonical_objects(&commit, &handoff);
}
