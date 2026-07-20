use garth::BaseClient;
use garth::*;
use serde_json::json;

fn did(name: &str) -> Did {
    Did::new(format!("did:webvh:z6mkfixture:{name}.example")).unwrap()
}

#[test]
fn runtime_builds_client_signs_event_and_verifies_binding() {
    let realm_id = RealmId::new("ak:realm:01904100-0000-7000-8000-000000000001").unwrap();
    let mut event = Event::new(
        garth::events::EventKind::MESSAGE_CREATE,
        realm_id.clone(),
        did("alice"),
        1,
        Hlc::new("01970e589d21-0001-a13f9c2e").unwrap(),
        json!({
            "message_id": "ak:message:01904100-0000-7000-8000-000000000001",
            "strand_id": "ak:strand:01904100-0000-7000-8000-000000000001",
            "track_name": "discussion",
            "content": {"kind": "ak.content.text", "body": "hello"}
        }),
    )
    .unwrap();
    let digest = event.event_digest().unwrap();
    event.proofs.push(Proof {
        kind: "detached_jws".to_owned(),
        alg: "EdDSA".to_owned(),
        verification_method: "did:webvh:z6mkfixture:alice.example#device-1".to_owned(),
        event_digest: Hash::new(digest).unwrap(),
        created_at: chrono::Utc::now(),
        domain: None,
        audience: None,
        jws: "AAAA.BBBB.CCCC".to_owned(),
    });
    event.validate_proof_bindings().unwrap();

    let client = BaseClient::new();
    client.process_events(&realm_id, vec![event]).unwrap();
    let realm = client.get_realm(&realm_id).unwrap();
    assert!(
        realm
            .realm_state
            .messages
            .contains_key("ak:message:01904100-0000-7000-8000-000000000001")
    );
}
