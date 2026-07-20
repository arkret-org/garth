use super::*;
use crate::base::SessionMeta;
use crate::{DeviceId, Event, EventRequirements, Hlc, OperationType};

fn sessioned_base() -> Arc<BaseClient> {
    let base_client = Arc::new(BaseClient::new());
    let meta = SessionMeta::new(
        Did::new("did:webvh:z6mkfixture:alice.example.com").unwrap(),
        DeviceId::new("ak:device:01904100-0000-7000-8000-000000000005").unwrap(),
    );
    base_client.set_session_meta(meta).unwrap();
    base_client
}

fn event(kind: &str, seq: u64, realm_id: &RealmId, content: Value) -> Event {
    Event {
        event_id: EventId::new(format!("ak:event:01904100-0000-7000-8000-{seq:012x}")).unwrap(),
        kind: kind.into(),
        realm_id: realm_id.clone(),
        actor_id: Did::new("did:webvh:z6mkfixture:alice.example.com").unwrap(),
        actor_seq: seq,
        created_at: Utc::now(),
        hlc: Hlc::new(format!("01970e589d21-{seq:04x}-a13f9c2e")).unwrap(),
        prev_refs: vec![],
        effective_scope: None,
        refs: vec![],
        preconditions: vec![],
        effects: vec![],
        seal_ref: None,
        auth_context: None,
        seal_basis: None,
        requirements: EventRequirements::default(),
        redacts: None,
        payload: serde_json::from_value(content).unwrap(),
        executed_by: None,
        authorization_ref: None,
        applet_id: None,
        external_ref: None,
        actor_kind: None,
        unsigned: BTreeMap::new(),
        proofs: vec![],
    }
}

fn morph_create_payload(morph_id: &MorphId, morph_type: &str, title: &str) -> Value {
    json!({
        "object": {
            "id": morph_id.as_str(),
            "schema": crate::MORPH_SCHEMA,
            "realm_id": "ak:realm:01904100-0000-7000-8000-9b64700c6ee8",
            "schema_refs": [crate::MORPH_SCHEMA],
            "morph_type": morph_type,
            "metadata": {"title": title},
            "stage": "draft",
            "created_by": "did:webvh:z6mkfixture:alice.example.com",
            "created_at": "2026-05-02T00:00:00.000Z"
        }
    })
}

#[test]
fn realm_checks_membership() {
    let base_client = Arc::new(BaseClient::new());
    let realm_id = RealmId::new("ak:realm:01904100-0000-7000-8000-9b64700c6ee8").unwrap();

    base_client
        .update_realm_membership_state(&realm_id, RealmMembershipState::Joined)
        .unwrap();

    let realm = Realm::new(realm_id, base_client);
    assert!(realm.is_joined());
    assert!(!realm.is_invited());
    assert!(!realm.is_left());
}

#[test]
fn realm_creates_morph_operation() {
    let base_client = sessioned_base();
    let realm_id = RealmId::new("ak:realm:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
    let realm = Realm::new(realm_id.clone(), base_client);

    let op = realm
        .create_morph_operation(
            "task",
            Some("Test task".to_owned()),
            None,
            None,
            BTreeMap::new(),
        )
        .unwrap();

    assert_eq!(op.operation_type, OperationType::Create);
    assert_eq!(op.realm_id.as_str(), realm_id.as_str());
    assert_eq!(op.object_type, arkret_core::events::EventKind::MORPH_CREATE);
    assert_eq!(op.payload["object"]["morph_type"], "task");
    assert_eq!(op.payload["object"]["metadata"]["title"], "Test task");
    assert!(
        op.payload["object"]["id"]
            .as_str()
            .unwrap()
            .starts_with("ak:morph:")
    );
}

#[test]
fn realm_creates_relation_operation() {
    let base_client = sessioned_base();
    let realm_id = RealmId::new("ak:realm:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
    let realm = Realm::new(realm_id.clone(), base_client);

    let input = RelationOperationInput::new(
        RelationKind::DependsOn,
        "ak:morph:01904100-0000-7000-8000-d48c478ecd0b",
        "ak:morph:01904100-0000-7000-8000-e75dc3f6ab2e",
    );
    let op = realm.create_relation_operation(input).unwrap();

    assert_eq!(op.operation_type, OperationType::Create);
    assert_eq!(op.realm_id.as_str(), realm_id.as_str());
    assert_eq!(op.payload["kind"], "depends_on");
    assert_eq!(
        op.payload["from_ref"],
        "ak:morph:01904100-0000-7000-8000-d48c478ecd0b"
    );
    assert_eq!(
        op.payload["to_ref"],
        "ak:morph:01904100-0000-7000-8000-e75dc3f6ab2e"
    );
}

#[test]
fn realm_creates_strand_operations_and_reads_default_view_relations() {
    let base_client = sessioned_base();
    let realm_id = RealmId::new("ak:realm:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
    let realm = Realm::new(realm_id.clone(), base_client.clone());

    let create = realm
        .create_strand_operation(
            "Payment refactor",
            Some("Unify payment strands".to_owned()),
            BTreeMap::new(),
        )
        .unwrap();
    let strand_id = StrandId::new(create.payload["object"]["id"].as_str().unwrap()).unwrap();
    assert_eq!(create.operation_type, OperationType::Create);
    assert_eq!(
        create.object_type,
        arkret_core::events::EventKind::STRAND_CREATE
    );
    assert!(create.payload["object"]["tracks"]["synthesis"].is_object());

    base_client
        .process_events(
            &realm_id,
            vec![
                event(
                    arkret_core::events::EventKind::STRAND_CREATE,
                    1,
                    &realm_id,
                    json!({
                        "object": {
                            "id": strand_id.as_str(),
                            "schema": crate::STRAND_SCHEMA,
                            "realm_id": realm_id.as_str(),
                            "metadata": {"title": "Payment refactor"},
                            "tracks": {"synthesis": {}},
                            "created_by": "did:webvh:z6mkfixture:alice.example.com",
                            "created_at": "2026-05-02T00:00:00.000Z"
                        }
                    }),
                ),
                event(
                    arkret_core::events::EventKind::RELATION_CREATE,
                    2,
                    &realm_id,
                    json!({
                        "kind": "has_default_view",
                        "from_ref": strand_id.as_str(),
                        "to_ref": "ak:view:01904100-0000-7000-8000-08ca7b733afd"
                    }),
                ),
            ],
        )
        .unwrap();

    let refreshed = Realm::new(realm_id, base_client);
    assert_eq!(refreshed.strands().len(), 1);
    assert_eq!(refreshed.strand_default_views(&strand_id).len(), 1);
}

#[test]
fn realm_strand_move_operation_uses_target_space_id() {
    let base_client = sessioned_base();
    let realm_id = RealmId::new("ak:realm:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
    let realm = Realm::new(realm_id.clone(), base_client);
    let strand_id = StrandId::new("ak:strand:01904100-0000-7000-8000-000000000010").unwrap();
    let board_space_id = SpaceId::new("ak:space:01904100-0000-7000-8000-000000000020").unwrap();
    let target_space_id = SpaceId::new("ak:space:01904100-0000-7000-8000-000000000030").unwrap();

    let op = realm
        .move_strand_operation(strand_id, board_space_id, target_space_id, "a0", None)
        .unwrap();

    assert_eq!(op.operation_type, OperationType::Update);
    assert_eq!(op.realm_id.as_str(), realm_id.as_str());
    assert_eq!(op.object_type, arkret_core::events::EventKind::STRAND_MOVE);
    assert_eq!(
        op.payload["target_space_id"],
        "ak:space:01904100-0000-7000-8000-000000000030"
    );
    assert!(op.payload.get("target_realm_id").is_none());
}

#[test]
fn realm_queries_searches_and_aggregates_morphs() {
    let base_client = sessioned_base();
    let realm_id = RealmId::new("ak:realm:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
    let task_id = MorphId::new("ak:morph:01904100-0000-7000-8000-d48c478ecd0b").unwrap();
    let doc_id = MorphId::new("ak:morph:01904100-0000-7000-8000-e75dc3f6ab2e").unwrap();
    base_client
        .process_events(
            &realm_id,
            vec![
                event(
                    arkret_core::events::EventKind::MORPH_CREATE,
                    1,
                    &realm_id,
                    json!({
                        "object": {
                            "id": task_id.as_str(),
                            "schema": crate::MORPH_SCHEMA,
                            "realm_id": realm_id.as_str(),
                            "schema_refs": [crate::MORPH_SCHEMA],
                            "morph_type": "task",
                            "metadata": {"title": "Alpha task"},
                            "content": {"kind": "ak.content.text", "body": "implement local search"},
                            "fields": {"status": "todo", "priority": 2},
                            "stage": "draft",
                            "created_by": "did:webvh:z6mkfixture:alice.example.com",
                            "created_at": "2026-05-02T00:00:00.000Z"
                        }
                    }),
                ),
                event(
                    arkret_core::events::EventKind::MORPH_CREATE,
                    2,
                    &realm_id,
                    json!({
                        "object": {
                            "id": doc_id.as_str(),
                            "schema": crate::MORPH_SCHEMA,
                            "realm_id": realm_id.as_str(),
                            "schema_refs": [crate::MORPH_SCHEMA],
                            "morph_type": "document",
                            "metadata": {"title": "Spec"},
                            "fields": {"status": "done", "priority": 1},
                            "stage": "draft",
                            "created_by": "did:webvh:z6mkfixture:alice.example.com",
                            "created_at": "2026-05-02T00:00:00.000Z"
                        }
                    }),
                ),
            ],
        )
        .unwrap();
    let realm = Realm::new(realm_id, base_client);

    let results = realm.query_morphs(MorphQuery {
        morph_types: vec!["task".to_owned()],
        filters: vec![Filter::Predicate(FieldFilter {
            field: "fields.status".to_owned(),
            op: FilterOp::Eq,
            value: Some(json!("todo")),
        })],
        order_by: vec![SortSpec {
            field: "fields.priority".to_owned(),
            direction: SortDirection::Desc,
            nulls: None,
        }],
        limit: Some(10),
    });
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].id.as_str(), task_id.as_str());

    assert_eq!(realm.search_morphs("LOCAL SEARCH").len(), 1);

    let aggregation = realm.aggregate_morphs(&["fields.status"]);
    assert_eq!(aggregation.total, 2);
    assert_eq!(aggregation.by_type["task"], 1);
    assert_eq!(aggregation.by_field["fields.status"]["todo"], 1);
}

#[test]
fn realm_traverses_relation_ref_graph_paths_and_cycles() {
    let base_client = sessioned_base();
    let realm_id = RealmId::new("ak:realm:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
    let a = "ak:morph:01904100-0000-7000-8000-093d58d9d0c4";
    let b = "ak:morph:01904100-0000-7000-8000-af13d24f756d";
    let c = "ak:morph:01904100-0000-7000-8000-28bb259aec1d";
    base_client
        .process_events(
            &realm_id,
            vec![
                event(
                    arkret_core::events::EventKind::MORPH_CREATE,
                    1,
                    &realm_id,
                    morph_create_payload(&MorphId::new(a).unwrap(), "task", "A"),
                ),
                event(
                    arkret_core::events::EventKind::MORPH_CREATE,
                    2,
                    &realm_id,
                    morph_create_payload(&MorphId::new(b).unwrap(), "task", "B"),
                ),
                event(
                    arkret_core::events::EventKind::MORPH_CREATE,
                    3,
                    &realm_id,
                    morph_create_payload(&MorphId::new(c).unwrap(), "task", "C"),
                ),
                event(
                    arkret_core::events::EventKind::RELATION_CREATE,
                    4,
                    &realm_id,
                    json!({"kind": "depends_on", "from_ref": a, "to_ref": b}),
                ),
                event(
                    arkret_core::events::EventKind::RELATION_CREATE,
                    5,
                    &realm_id,
                    json!({"kind": "depends_on", "from_ref": b, "to_ref": c}),
                ),
                event(
                    arkret_core::events::EventKind::RELATION_CREATE,
                    6,
                    &realm_id,
                    json!({"kind": "depends_on", "from_ref": c, "to_ref": a}),
                ),
            ],
        )
        .unwrap();
    let realm = Realm::new(realm_id, base_client);

    assert_eq!(
        realm.traverse_relation_refs(
            a,
            Some(RelationKind::DependsOn),
            GraphTraversal::BreadthFirst,
            Some(2)
        ),
        vec![b.to_owned(), c.to_owned()]
    );
    assert_eq!(
        realm
            .shortest_relation_ref_path(a, c, Some(RelationKind::DependsOn))
            .unwrap(),
        vec![a.to_owned(), b.to_owned(), c.to_owned()]
    );
    assert!(realm.relation_ref_graph_has_cycle(Some(RelationKind::DependsOn)));
}

#[test]
fn realm_tracks_morph_versions_compares_and_rolls_back() {
    let base_client = sessioned_base();
    let realm_id = RealmId::new("ak:realm:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
    let morph_id = MorphId::new("ak:morph:01904100-0000-7000-8000-69c57da8d707").unwrap();
    base_client
        .process_events(
            &realm_id,
            vec![
                event(
                    arkret_core::events::EventKind::MORPH_CREATE,
                    1,
                    &realm_id,
                    json!({
                        "object": {
                            "id": morph_id.as_str(),
                            "schema": crate::MORPH_SCHEMA,
                            "realm_id": realm_id.as_str(),
                            "schema_refs": [crate::MORPH_SCHEMA],
                            "morph_type": "task",
                            "metadata": {"title": "Initial"},
                            "fields": {"status": "todo"},
                            "stage": "draft",
                            "created_by": "did:webvh:z6mkfixture:alice.example.com",
                            "created_at": "2026-05-02T00:00:00.000Z"
                        }
                    }),
                ),
                event(
                    arkret_core::events::EventKind::MORPH_UPDATE,
                    2,
                    &realm_id,
                    json!({
                        "target_ref": morph_id.as_str(),
                        "patch": {"metadata.title": "Updated", "fields": {"status": "done", "owner": "alice"}}
                    }),
                ),
            ],
        )
        .unwrap();
    let realm = Realm::new(realm_id, base_client);

    let versions = realm.morph_versions(&morph_id);
    assert_eq!(versions.len(), 2);
    assert_eq!(versions[0].version, 0);
    assert_eq!(versions[1].version, 1);

    let diff = realm.compare_morph_versions(&morph_id, 0, 1).unwrap();
    assert!(diff.title_changed);
    assert_eq!(diff.added_fields, vec!["owner".to_owned()]);
    assert_eq!(diff.changed_fields, vec!["status".to_owned()]);

    let rollback = realm.rollback_morph_operation(morph_id, 0).unwrap();
    assert_eq!(rollback.payload["patch"]["metadata.title"], "Initial");
    assert!(rollback.payload.get("rollback_to_version").is_none());
}

#[test]
fn realm_creates_batch_morph_operations() {
    let base_client = sessioned_base();
    let realm_id = RealmId::new("ak:realm:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
    let realm = Realm::new(realm_id, base_client);

    let creates = realm
        .batch_create_morph_operations(vec![
            BatchCreateMorph {
                morph_type: "task".to_owned(),
                title: Some("A".to_owned()),
                summary: None,
                content: None,
                fields: BTreeMap::new(),
            },
            BatchCreateMorph {
                morph_type: "document".to_owned(),
                title: Some("B".to_owned()),
                summary: None,
                content: None,
                fields: BTreeMap::new(),
            },
        ])
        .unwrap();
    assert_eq!(creates.len(), 2);

    let updates = realm
        .batch_update_morph_operations(vec![BatchUpdateMorph {
            morph_id: MorphId::new("ak:morph:01904100-0000-7000-8000-604e58949e32").unwrap(),
            title: Some("Updated".to_owned()),
            summary: None,
            content: None,
            fields: None,
        }])
        .unwrap();
    assert_eq!(updates.len(), 1);

    let archives = realm
        .batch_archive_morph_operations(vec![
            MorphId::new("ak:morph:01904100-0000-7000-8000-604e58949e32").unwrap(),
        ])
        .unwrap();
    assert_eq!(archives.len(), 1);
}

#[test]
fn realm_provides_message_membership_and_media_convenience_helpers() {
    let base_client = sessioned_base();
    let realm_id = RealmId::new("ak:realm:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
    let realm = Realm::new(realm_id.clone(), base_client.clone());
    let bob = Did::new("did:webvh:z6mkfixture:bob.example.com").unwrap();

    let text = realm.send_text("hello").unwrap();
    assert_eq!(text.object_type, "ak.message.create");
    assert_eq!(text.payload["content"]["body"], "hello");

    let message_id = MessageId::new(text.payload["message_id"].as_str().unwrap()).unwrap();
    let edit = realm
        .edit_message(message_id.clone(), json!({"body": "updated"}))
        .unwrap();
    assert_eq!(edit.object_type, "ak.message.revise");
    assert_eq!(edit.object_id, Some(message_id.as_str().to_owned()));

    let redact = realm
        .redact_message(message_id, Some("cleanup".to_owned()))
        .unwrap();
    assert_eq!(redact.operation_type, OperationType::Redact);

    let join = realm.join_realm().unwrap();
    assert_eq!(join.object_type, "ak.member.state");
    assert_eq!(
        base_client.get_realm(&realm_id).unwrap().state,
        RealmMembershipState::Joined
    );

    let leave = realm.leave_realm().unwrap();
    assert_eq!(leave.object_type, "ak.member.state");
    assert_eq!(
        base_client.get_realm(&realm_id).unwrap().state,
        RealmMembershipState::Left
    );

    assert_eq!(
        realm
            .ban(bob.clone(), Some("spam".to_owned()))
            .unwrap()
            .object_type,
        "ak.member.state"
    );
    assert_eq!(realm.unban(bob).unwrap().object_type, "ak.member.state");

    let media = realm
        .upload_media(b"bytes", "text/plain", Some("note.txt".to_owned()))
        .unwrap();
    assert_eq!(realm.download_media(&media.blob_ref).unwrap(), b"bytes");

    realm
        .upload_encrypted_attachment("att1", "secret.txt", "text/plain", b"secret", b"key")
        .unwrap();
    assert_eq!(
        realm.download_decrypted_attachment("att1", b"key").unwrap(),
        b"secret"
    );
}

#[test]
fn member_add_with_candidate_emits_routable_join_with_typed_binding() {
    use crate::models::{
        CandidateIntent, DeliveryBindingHint, DeliveryMode, Handle, HandleHintBindingSource,
        MemberDeliveryBindingCandidate, Proof, RecipientServiceType,
    };

    let base_client = sessioned_base();
    let realm_id = RealmId::new("ak:realm:01904100-0000-7000-8000-000000000300").unwrap();
    let realm = Realm::new(realm_id.clone(), base_client);

    let subject = Did::new("did:webvh:z6mkfixture:bob.example".to_owned()).unwrap();
    let principal = Did::new("did:webvh:z6mkfixture:principal.acme.example".to_owned()).unwrap();
    let mut modes = std::collections::BTreeSet::new();
    modes.insert(DeliveryMode::Events);
    modes.insert(DeliveryMode::Sync);
    let candidate = MemberDeliveryBindingCandidate {
        subject_id: subject.clone(),
        handle: Handle::parse("bob:acme.example").unwrap(),
        handle_aliases: vec![],
        member_delivery_binding: DeliveryBindingHint {
            recipient_service_id: principal.clone(),
            recipient_service_type: RecipientServiceType::PrincipalServer,
            binding_source: HandleHintBindingSource::OrganizationPolicy,
            delivery_modes: modes,
            service_acceptance_ref: Some(
                "ak:event:01890000-0000-7000-8000-0000000000a1".to_owned(),
            ),
            policy_event_ref: Some("ak:event:01890000-0000-7000-8000-0000000000a2".to_owned()),
        },
        issuer_service_id: principal,
        audience: realm_id.as_str().to_owned(),
        expires_at: Utc::now() + chrono::Duration::hours(1),
        issued_at: Utc::now(),
        source_refs: vec![EventId::new("ak:event:01890000-0000-7000-8000-0000000000a3").unwrap()],
        proofs: vec![Proof {
            kind: "detached_jws".to_owned(),
            alg: "EdDSA".to_owned(),
            verification_method: "did:webvh:z6mkfixture:principal.acme.example#key-1".to_owned(),
            event_digest: Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
            created_at: "2026-05-19T00:00:00Z".parse().unwrap(),
            domain: None,
            audience: None,
            jws: "aaa.bbb.ccc".to_owned(),
        }],
        claim_digest: None,
        intent: CandidateIntent::MemberAdd,
    };

    let op = realm.member_add_with_candidate(&candidate).unwrap();
    assert_eq!(op.object_type, "ak.member.state");
    let payload = &op.payload;
    assert_eq!(payload["actor_id"], serde_json::json!(subject));
    assert_eq!(payload["membership"], "join");
    assert_eq!(payload["delivery_status"], "routable");
    assert!(payload["delivery_binding"].is_object());
    assert!(payload.get("handle").is_none());
    assert!(payload.get("delivery_binding_candidate").is_none());
}

#[test]
fn member_add_with_candidate_rejects_audience_mismatch() {
    use crate::models::{
        CandidateIntent, DeliveryBindingHint, DeliveryMode, Handle, HandleHintBindingSource,
        MemberDeliveryBindingCandidate, Proof, RecipientServiceType,
    };

    let base_client = sessioned_base();
    let realm_id = RealmId::new("ak:realm:01904100-0000-7000-8000-000000000301").unwrap();
    let realm = Realm::new(realm_id, base_client);

    let principal = Did::new("did:webvh:z6mkfixture:principal.acme.example".to_owned()).unwrap();
    let mut modes = std::collections::BTreeSet::new();
    modes.insert(DeliveryMode::Events);
    let candidate = MemberDeliveryBindingCandidate {
        subject_id: Did::new("did:webvh:z6mkfixture:bob.example".to_owned()).unwrap(),
        handle: Handle::parse("bob:acme.example").unwrap(),
        handle_aliases: vec![],
        member_delivery_binding: DeliveryBindingHint {
            recipient_service_id: principal.clone(),
            recipient_service_type: RecipientServiceType::PrincipalServer,
            binding_source: HandleHintBindingSource::OrganizationPolicy,
            delivery_modes: modes,
            service_acceptance_ref: Some(
                "ak:event:01890000-0000-7000-8000-0000000000a1".to_owned(),
            ),
            policy_event_ref: Some("ak:event:01890000-0000-7000-8000-0000000000a2".to_owned()),
        },
        issuer_service_id: principal,
        // Wrong audience — Realm id does not match.
        audience: "ak:realm:DEADBEEF-0000-7000-8000-00000000ffff".to_owned(),
        expires_at: Utc::now() + chrono::Duration::hours(1),
        issued_at: Utc::now(),
        source_refs: vec![EventId::new("ak:event:01890000-0000-7000-8000-0000000000a3").unwrap()],
        proofs: vec![Proof {
            kind: "detached_jws".to_owned(),
            alg: "EdDSA".to_owned(),
            verification_method: "did:webvh:z6mkfixture:principal.acme.example#key-1".to_owned(),
            event_digest: Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
            created_at: "2026-05-19T00:00:00Z".parse().unwrap(),
            domain: None,
            audience: None,
            jws: "aaa.bbb.ccc".to_owned(),
        }],
        claim_digest: None,
        intent: CandidateIntent::MemberAdd,
    };

    let err = realm.member_add_with_candidate(&candidate).unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("audience"),
        "expected audience mismatch error, got: {msg}"
    );
}
