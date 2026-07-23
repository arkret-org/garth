use std::collections::BTreeMap;

use crate::protocol::{
    AccountSubscribeRealms, AccountSubscribeUnreadCounts, DeviceMessageContainer,
    EphemeralEventContainer, ErrorEnvelope, EventContainer, ProtocolKind, RealmSyncEntry,
};
use arkret_signatures::{PublicKeyMaterial, sign_eddsa_detached_jws};
use ed25519_dalek::SigningKey;
use serde_json::json;

use super::*;
use crate::protocol::{
    AccountNotificationDataKind, AgentRuntimeApprovalNotificationData,
    AgentRuntimeApprovalNotificationRemovalData, AgentRuntimeApprovalRemovalReason,
    DeviceMessageId, Did, EphemeralEnvelope, Hash, NotificationContainer, NotificationData,
    NotificationId, NotificationType, Proof, RealmId,
};

fn sync_response(cursor: &str) -> AccountSubscribeBatch {
    AccountSubscribeBatch {
        cursor: cursor.to_owned(),
        frames: vec![AccountSubscribeFrame {
            kind: AccountSubscribeFrameKind::Delta,
            cursor: Some(cursor.to_owned()),
            realms: None,
            to_device: None,
            device_lists: None,
            account_data: None,
            presence: None,
            notifications: None,
            partial: None,
            priority: None,
            reconnect_after_ms: None,
        }],
    }
}

fn delta_mut(batch: &mut AccountSubscribeBatch) -> &mut AccountSubscribeFrame {
    batch.frames.first_mut().unwrap()
}

fn approval_notifications(notification_id: &str, expires_at: &str) -> NotificationContainer {
    NotificationContainer {
        items: vec![NotificationDelta {
            id: NotificationId::new(notification_id).unwrap(),
            notification_type: NotificationType::Agent,
            action: NotificationDeltaAction::Add,
            data: Some(NotificationData::AgentRuntimeApproval(
                AgentRuntimeApprovalNotificationData {
                    kind: AccountNotificationDataKind::AgentRuntimeApproval,
                    approval_request_id:
                        "agent_runtime_approval:01964137-0000-7000-8000-000000000001".to_owned(),
                    agent_id: Did::new("did:webvh:z6mkfixture:agent.example").unwrap(),
                    requested_at: DateTime::parse_from_rfc3339("2026-07-13T10:00:00.000Z")
                        .unwrap()
                        .with_timezone(&Utc),
                    expires_at: DateTime::parse_from_rfc3339(expires_at)
                        .unwrap()
                        .with_timezone(&Utc),
                },
            )),
        }],
    }
}

fn signed_presence(
    realm_id: RealmId,
    actor_id: Did,
    device_id: DeviceId,
    sent_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    state: &str,
    seed: [u8; 32],
) -> (EphemeralEnvelope, PublicKeyMaterial) {
    let signing_key = SigningKey::from_bytes(&seed);
    let verification_method = format!("{actor_id}#{device_id}");
    let mut envelope = EphemeralEnvelope::new(
        "ak.presence",
        realm_id,
        actor_id.clone(),
        device_id,
        sent_at,
        expires_at,
        serde_json::from_value(json!({"state":state})).unwrap(),
        Proof {
            kind: "detached_jws".to_owned(),
            alg: "EdDSA".to_owned(),
            verification_method,
            event_digest: Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
            created_at: sent_at,
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: "header..signature".to_owned(),
        },
    )
    .unwrap();
    envelope.proof.event_digest = Hash::new(canonical::sha256_digest(
        envelope.canonical_bytes_without_proof().unwrap(),
    ))
    .unwrap();
    let binding = envelope
        .proof
        .canonical_ephemeral_binding_bytes(&actor_id)
        .unwrap();
    envelope.proof.jws = sign_eddsa_detached_jws(&signing_key, &binding).unwrap();
    let public_key = PublicKeyMaterial::Ed25519Raw {
        bytes: signing_key.verifying_key().to_bytes().to_vec(),
    };
    (envelope, public_key)
}

#[test]
fn backoff_grows_until_capped() {
    let mut backoff = ExponentialBackoff::new(BackoffConfig {
        initial_delay: Duration::from_millis(100),
        max_delay: Duration::from_millis(250),
        multiplier: 2,
        // Deterministic delays for the exact assertions below.
        jitter: false,
    });

    assert_eq!(backoff.record_failure(), Duration::from_millis(100));
    assert_eq!(backoff.record_failure(), Duration::from_millis(200));
    assert_eq!(backoff.record_failure(), Duration::from_millis(250));
    backoff.reset();
    assert_eq!(backoff.current_delay(), Duration::ZERO);
}

#[test]
fn sync_loop_recovers_after_failure() {
    let mut calls = 0;
    let mut transport = |request: SyncRequestBody| {
        calls += 1;
        if calls == 1 {
            assert_eq!(request.catchup, Some(true));
            Err(Error::Api {
                status: 503,
                error: Box::new(ErrorEnvelope::new("unavailable", "network down")),
            })
        } else {
            assert!(request.after.is_none());
            assert_eq!(request.catchup, Some(true));
            Ok(sync_response("s1"))
        }
    };
    let mut sync_loop = SyncLoop::new();

    assert!(matches!(
        sync_loop.step(&mut transport),
        SyncLoopStep::Retry { .. }
    ));
    assert!(matches!(
        sync_loop.step(&mut transport),
        SyncLoopStep::Updates(_)
    ));
    assert_eq!(sync_loop.token(), Some("s1"));
}

#[test]
fn sync_loop_rejects_empty_cursor_without_advancing_position() {
    let mut transport = |_request: SyncRequestBody| Ok(sync_response(""));
    let mut sync_loop = SyncLoop::new();

    assert!(matches!(
        sync_loop.step(&mut transport),
        SyncLoopStep::Failed { error }
            if error.contains("requires a non-empty cursor")
    ));
    assert!(sync_loop.token().is_none());
}

#[test]
fn sync_loop_discards_rejected_cursor_before_retry() {
    let mut sync_loop = SyncLoop::from_snapshot(SyncLoopSnapshot {
        token: Some("ak:cursor:expired".to_owned()),
        timeout_ms: 30_000,
        gap_strategy: SyncGapStrategy::PreserveTokenAndBackfill,
    });
    let mut transport = |request: SyncRequestBody| {
        assert_eq!(request.after.as_deref(), Some("ak:cursor:expired"));
        Err(Error::Api {
            status: 410,
            error: Box::new(ErrorEnvelope::new("cursor_expired", "cursor expired")),
        })
    };

    assert!(matches!(
        sync_loop.step(&mut transport),
        SyncLoopStep::Retry { retry_after, .. } if retry_after.is_zero()
    ));
    assert!(sync_loop.token().is_none());
    assert!(sync_loop.recovery_actions().is_empty());
}

#[test]
fn sync_loop_exposes_to_device_loss_recovery_actions() {
    let mut transport = |_request: SyncRequestBody| {
        let mut response = sync_response("loss1");
        delta_mut(&mut response).to_device = Some(DeviceMessageContainer {
            messages: Vec::new(),
            ack_token: None,
            lost: Some(true),
            limited: None,
            next_cursor: None,
            extra: BTreeMap::new(),
        });
        Ok(response)
    };
    let mut sync_loop = SyncLoop::new();

    match sync_loop.step(&mut transport) {
        SyncLoopStep::Updates(updates) => assert!(updates.to_device_lost),
        other => panic!("expected sync updates, got {other:?}"),
    }
    let expected = vec![
        SyncRecoveryAction::RefetchDeviceLists,
        SyncRecoveryAction::RequestMissingMlsMaterial,
        SyncRecoveryAction::RestoreFromKeyBackup,
    ];
    assert_eq!(sync_loop.recovery_actions(), expected);
    assert_eq!(sync_loop.take_recovery_actions(), expected);
    assert!(sync_loop.recovery_actions().is_empty());
}

#[tokio::test]
async fn async_sync_loop_uses_transport_and_persists_token() {
    let transport = |request: SyncRequestBody| async move {
        assert_eq!(request.catchup, Some(true));
        assert!(request.after.is_none());
        Ok(sync_response("async1"))
    };
    let mut sync_loop = SyncLoop::new().with_timeout(Duration::from_millis(15));

    assert!(matches!(
        sync_loop.step_async(&transport).await,
        SyncLoopStep::Updates(_)
    ));
    let snapshot = sync_loop.snapshot();
    assert_eq!(snapshot.token.as_deref(), Some("async1"));

    let restored = SyncLoop::from_snapshot(snapshot);
    assert_eq!(restored.next_request().after.as_deref(), Some("async1"));
}

#[tokio::test]
async fn async_sync_loop_honors_cancellation() {
    let transport = |_request: SyncRequestBody| async { Ok(sync_response("unused")) };
    let control = SyncLoopControl::new();
    control.cancel();

    let mut sync_loop = SyncLoop::new();

    assert!(matches!(
        sync_loop
            .step_async_with_control(&transport, &control)
            .await,
        SyncLoopStep::Cancelled
    ));
    assert!(sync_loop.token().is_none());
}

#[test]
fn sync_loop_control_applies_backpressure() {
    let control = SyncLoopControl::new().with_backpressure(BackpressureConfig {
        max_in_flight_requests: 1,
        retry_after: Duration::from_millis(25),
    });
    let permit = control.try_acquire().unwrap();

    assert!(control.try_acquire().is_none());
    assert_eq!(
        control.backpressure_retry_after(),
        Duration::from_millis(25)
    );

    drop(permit);
    assert!(control.try_acquire().is_some());
}

#[test]
fn sync_loop_can_reset_token_on_limited_timeline_gap() {
    let realm_id = "ak:realm:01904100-0000-7000-8000-9b64700c6ee8";
    let mut response = sync_response("gap-token");
    let entry = RealmSyncEntry {
        timeline: Some(Timeline {
            events: Vec::new(),
            limited: true,
            prev_cursor: Some("prev".to_owned()),
            preview_only: None,
            extra: BTreeMap::new(),
        }),
        ..Default::default()
    };
    delta_mut(&mut response).realms = Some(AccountSubscribeRealms {
        entries: BTreeMap::from([(realm_id.to_owned(), entry)]),
    });
    let mut transport = |_request: SyncRequestBody| Ok(response.clone());
    let mut sync_loop =
        SyncLoop::new().with_gap_strategy(SyncGapStrategy::ResetTokenOnLimitedTimeline);

    assert!(matches!(
        sync_loop.step(&mut transport),
        SyncLoopStep::Updates(_)
    ));
    assert!(sync_loop.token().is_none());
}

#[test]
fn sync_loop_includes_wait_for_frontier() {
    let realm_id = RealmId::new("ak:realm:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
    let wait_for = WaitForFrontier {
        positions: vec![crate::protocol::sync::SyncStreamPosition {
            realm_id,
            frontier: Vec::new(),
            timeline_order: crate::protocol::Hlc::new("01970e589d21-0000-a13f9c2e").unwrap(),
            state_digest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .to_owned(),
        }],
        timeout_ms: 5000,
    };

    let request = SyncLoop::new()
        .with_wait_for(wait_for.clone())
        .next_request();

    assert_eq!(request.wait_for, Some(wait_for));
}

#[test]
fn processor_dispatches_all_update_categories() {
    let realm_id = "ak:realm:01904100-0000-7000-8000-9b64700c6ee8";
    let mut response = sync_response("s2");
    let entry = RealmSyncEntry {
        summary: Some(AccountSubscribeRealmSummary {
            joined_member_count: Some(2),
            invited_member_count: None,
            heroes: None,
        }),
        unread_notifications: Some(AccountSubscribeUnreadCounts {
            notification_count: Some(3),
            highlight_count: Some(1),
        }),
        ..Default::default()
    };
    let sender = Did::new("did:webvh:z6mkfixture:alice.example").unwrap();
    let recipient = Did::new("did:webvh:z6mkfixture:bob.example").unwrap();
    let realm = RealmId::new(realm_id).unwrap();
    let presence_device_id =
        DeviceId::new("ak:device:01904100-0000-7000-8000-000000000005").unwrap();
    let presence_sent_at = Utc::now();
    let (presence_event, presence_public_key) = signed_presence(
        realm.clone(),
        sender.clone(),
        presence_device_id.clone(),
        presence_sent_at,
        presence_sent_at + chrono::Duration::seconds(30),
        "online",
        [7; 32],
    );
    let account_data_event = Event::new(
        "ak.account_data.set",
        realm,
        sender.clone(),
        2,
        crate::protocol::Hlc::new("01970e589d22-0000-a13f9c2e").unwrap(),
        json!({"key":"ak.settings","body":{"theme":"light"}}),
    )
    .unwrap();
    let frame = delta_mut(&mut response);
    frame.realms = Some(AccountSubscribeRealms {
        entries: BTreeMap::from([(realm_id.to_owned(), entry)]),
    });
    frame.to_device = Some(DeviceMessageContainer {
        messages: vec![DeviceMessageEnvelope {
            message_id: DeviceMessageId::new(
                "ak:device_message:01904100-0000-7000-8000-000000000007",
            )
            .unwrap(),
            kind: ProtocolKind::new("ak.test.message").unwrap(),
            content: serde_json::from_value(json!({"ok":true})).unwrap(),
            sender_principal_id: sender.clone(),
            sender_device_id: DeviceId::new("ak:device:01904100-0000-7000-8000-000000000005")
                .unwrap(),
            recipient_principal_id: recipient,
            recipient_device_id: DeviceId::new("ak:device:01904100-0000-7000-8000-000000000006")
                .unwrap(),
            sent_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::hours(1),
            device_proof: None,
            unsigned: None,
        }],
        ack_token: Some("ack-sync-1".to_owned()),
        lost: Some(true),
        limited: Some(true),
        next_cursor: Some("device-cursor-2".to_owned()),
        extra: BTreeMap::new(),
    });
    frame.device_lists = Some(AccountSubscribeDeviceListChanges {
        changed: vec![sender.clone()],
        left: Vec::new(),
    });
    frame.presence = Some(EphemeralEventContainer {
        events: vec![presence_event],
    });
    frame.account_data = Some(EventContainer {
        events: vec![account_data_event],
        extra: BTreeMap::new(),
    });
    let notification_id = "ak:notification:01964137-0000-7000-8000-000000000000";
    frame.notifications = Some(approval_notifications(
        notification_id,
        "2026-07-13T10:15:00.000Z",
    ));

    let mut processor = SyncResponseProcessor::new();
    let resolver_actor = sender.clone();
    let resolver_device = presence_device_id.clone();
    let resolver = move |actor: &Did, device: &DeviceId| {
        (actor == &resolver_actor && device == &resolver_device)
            .then(|| presence_public_key.clone())
    };
    let updates = processor
        .process_with_ephemeral_key_resolver(response, &resolver)
        .unwrap();
    let parsed_realm_id = RealmId::new(realm_id).unwrap();

    assert_eq!(updates.realm_updates.len(), 1);
    assert_eq!(
        processor
            .realm(&parsed_realm_id)
            .unwrap()
            .notification_count,
        3
    );
    assert_eq!(processor.drain_to_device().len(), 1);
    assert_eq!(updates.to_device_ack_token.as_deref(), Some("ack-sync-1"));
    assert!(updates.to_device_limited);
    assert_eq!(
        updates.to_device_next_cursor.as_deref(),
        Some("device-cursor-2")
    );
    assert!(updates.to_device_lost);
    let expected_recovery_actions = vec![
        SyncRecoveryAction::RefetchDeviceLists,
        SyncRecoveryAction::RequestMissingMlsMaterial,
        SyncRecoveryAction::RestoreFromKeyBackup,
    ];
    assert_eq!(processor.recovery_actions(), expected_recovery_actions);
    assert_eq!(processor.take_recovery_actions(), expected_recovery_actions);
    assert!(processor.recovery_actions().is_empty());
    assert_eq!(processor.presence(&sender).len(), 1);
    assert_eq!(
        processor.aggregated_presence(&sender),
        PresenceStatus::Online
    );
    assert!(processor.account_data("ak.settings").is_some());
    assert!(processor.notification(notification_id).is_some());
    assert_eq!(processor.device_lists().changed.len(), 1);
}

#[test]
fn ephemeral_only_realm_delta_preserves_durable_processor_summary() {
    let realm_id = "ak:realm:01904100-0000-7000-8000-9b64700c6ee8";
    let parsed_realm_id = RealmId::new(realm_id).unwrap();
    let mut processor = SyncResponseProcessor::new();

    let mut baseline = sync_response("s-summary-1");
    delta_mut(&mut baseline).realms = Some(AccountSubscribeRealms {
        entries: BTreeMap::from([(
            realm_id.to_owned(),
            RealmSyncEntry {
                summary: Some(AccountSubscribeRealmSummary {
                    joined_member_count: Some(2),
                    invited_member_count: None,
                    heroes: None,
                }),
                ..Default::default()
            },
        )]),
    });
    processor.process(baseline).unwrap();

    let mut ephemeral = sync_response("s-summary-2");
    delta_mut(&mut ephemeral).realms = Some(AccountSubscribeRealms {
        entries: BTreeMap::from([(
            realm_id.to_owned(),
            RealmSyncEntry {
                ephemeral: Some(EphemeralEventContainer { events: Vec::new() }),
                ..Default::default()
            },
        )]),
    });
    processor.process(ephemeral).unwrap();

    assert_eq!(
        processor
            .realm(&parsed_realm_id)
            .and_then(|realm| realm.summary.as_ref())
            .and_then(|summary| summary.joined_member_count),
        Some(2)
    );
}

#[test]
fn processor_authenticates_retains_and_aggregates_per_device_presence() {
    let realm = RealmId::new("ak:realm:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
    let actor = Did::new("did:webvh:z6mkfixture:alice.example").unwrap();
    let device_a = DeviceId::new("ak:device:01904100-0000-7000-8000-000000000005").unwrap();
    let device_b = DeviceId::new("ak:device:01904100-0000-7000-8000-000000000006").unwrap();
    let now = Utc::now();
    let (online, key_a) = signed_presence(
        realm.clone(),
        actor.clone(),
        device_a.clone(),
        now,
        now + chrono::Duration::seconds(30),
        "online",
        [11; 32],
    );
    let (dnd, key_b) = signed_presence(
        realm,
        actor.clone(),
        device_b.clone(),
        now,
        now + chrono::Duration::seconds(30),
        "dnd",
        [12; 32],
    );
    let keys = BTreeMap::from([
        ((actor.clone(), device_a), key_a),
        ((actor.clone(), device_b), key_b),
    ]);
    let resolver =
        move |actor: &Did, device: &DeviceId| keys.get(&(actor.clone(), device.clone())).cloned();
    let mut batch = sync_response("presence-multi-device");
    delta_mut(&mut batch).presence = Some(EphemeralEventContainer {
        events: vec![online, dnd],
    });

    let mut processor = SyncResponseProcessor::new();
    let updates = processor
        .process_with_ephemeral_key_resolver(batch, &resolver)
        .unwrap();

    assert_eq!(updates.presence.len(), 2);
    assert_eq!(processor.presence(&actor).len(), 2);
    assert_eq!(processor.aggregated_presence(&actor), PresenceStatus::Dnd);
    assert_eq!(
        processor.expire_presence(now + chrono::Duration::seconds(30)),
        2
    );
    assert!(processor.presence(&actor).is_empty());
    assert_eq!(
        processor.aggregated_presence(&actor),
        PresenceStatus::Offline
    );
}

#[test]
fn processor_drops_unverified_and_expired_presence() {
    let realm = RealmId::new("ak:realm:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
    let actor = Did::new("did:webvh:z6mkfixture:alice.example").unwrap();
    let device = DeviceId::new("ak:device:01904100-0000-7000-8000-000000000005").unwrap();
    let now = Utc::now();
    let (unverified, _) = signed_presence(
        realm.clone(),
        actor.clone(),
        device.clone(),
        now,
        now + chrono::Duration::seconds(30),
        "online",
        [21; 32],
    );
    let (expired, expired_key) = signed_presence(
        realm,
        actor.clone(),
        device,
        now - chrono::Duration::seconds(60),
        now - chrono::Duration::seconds(30),
        "online",
        [22; 32],
    );
    let resolver = move |_actor: &Did, _device: &DeviceId| Some(expired_key.clone());
    let mut batch = sync_response("presence-reject");
    delta_mut(&mut batch).presence = Some(EphemeralEventContainer {
        events: vec![unverified, expired],
    });

    let mut processor = SyncResponseProcessor::new();
    let updates = processor
        .process_with_ephemeral_key_resolver(batch, &resolver)
        .unwrap();

    assert!(updates.presence.is_empty());
    assert!(processor.presence(&actor).is_empty());
}

#[test]
fn processor_tracks_limited_timelines_and_to_device_ack() {
    let realm_id = "ak:realm:01904100-0000-7000-8000-9b64700c6ee8";
    let parsed_realm_id = RealmId::new(realm_id).unwrap();
    let event = Event::new(
        "ak.message.create",
        parsed_realm_id.clone(),
        Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
        1,
        crate::protocol::Hlc::new("01970e589d21-0000-a13f9c2e").unwrap(),
        json!({"body":"hello"}),
    )
    .unwrap();
    let mut response = sync_response("s3");
    let entry = RealmSyncEntry {
        timeline: Some(Timeline {
            events: vec![event],
            limited: true,
            prev_cursor: Some("prev".to_owned()),
            preview_only: None,
            extra: BTreeMap::new(),
        }),
        ..Default::default()
    };
    delta_mut(&mut response).realms = Some(AccountSubscribeRealms {
        entries: BTreeMap::from([(realm_id.to_owned(), entry)]),
    });

    let mut processor = SyncResponseProcessor::new();
    processor.process(response).unwrap();
    let ack = processor.acknowledge_to_device(
        "devmsg1",
        DeviceId::new("ak:device:01904100-0000-7000-8000-000000000005").unwrap(),
        ToDeviceAckStatus::Processed,
    );

    assert_eq!(
        processor
            .realm(&parsed_realm_id)
            .unwrap()
            .limited_timeline_count,
        1
    );
    assert_eq!(processor.limited_timelines().len(), 1);
    assert_eq!(processor.to_device_ack("devmsg1"), Some(&ack));
}

#[test]
fn processor_applies_notification_add_update_and_remove_deltas() {
    let notification_id = "ak:notification:01964137-0000-7000-8000-000000000001";
    let mut processor = SyncResponseProcessor::new();
    let mut add = sync_response("s-add");
    delta_mut(&mut add).notifications = Some(approval_notifications(
        notification_id,
        "2026-07-13T10:15:00.000Z",
    ));
    processor.process(add).unwrap();
    assert!(processor.notification(notification_id).is_some());

    let mut update = sync_response("s-update");
    let mut update_notifications =
        approval_notifications(notification_id, "2026-07-13T10:20:00.000Z");
    update_notifications.items[0].action = NotificationDeltaAction::Update;
    delta_mut(&mut update).notifications = Some(update_notifications);
    processor.process(update).unwrap();
    let serialized =
        serde_json::to_value(processor.notification(notification_id).unwrap()).unwrap();
    assert_eq!(serialized["data"]["expires_at"], "2026-07-13T10:20:00.000Z");

    let mut remove = sync_response("s-remove");
    delta_mut(&mut remove).notifications = Some(NotificationContainer {
        items: vec![NotificationDelta {
            id: NotificationId::new(notification_id).unwrap(),
            notification_type: NotificationType::Agent,
            action: NotificationDeltaAction::Remove,
            data: Some(NotificationData::AgentRuntimeApprovalRemoval(
                AgentRuntimeApprovalNotificationRemovalData {
                    kind: AccountNotificationDataKind::AgentRuntimeApproval,
                    reason: AgentRuntimeApprovalRemovalReason::Approved,
                },
            )),
        }],
    });
    processor.process(remove).unwrap();
    assert!(processor.notification(notification_id).is_none());
}

#[test]
fn send_queue_is_idempotent_orders_dependencies_and_snapshots() {
    let realm_id = RealmId::new("ak:realm:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
    let mut queue = SendQueue::new();
    let message = queue
        .enqueue_message(
            Some("txn1".to_owned()),
            realm_id.clone(),
            json!({"body":"hello"}),
        )
        .unwrap();
    let duplicate = queue
        .enqueue_message(
            Some("txn1".to_owned()),
            realm_id.clone(),
            json!({"body":"hello"}),
        )
        .unwrap();
    let edit = queue
        .enqueue_edit(
            Some("txn2".to_owned()),
            realm_id,
            EventId::new("ak:event:01904100-0000-7000-8000-ab84c4c0f437").unwrap(),
            json!({"content":{"body":"hi"}}),
            vec!["txn1".to_owned()],
        )
        .unwrap();

    assert_eq!(message.payload_digest, duplicate.payload_digest);
    assert_eq!(queue.ready_batch(Utc::now(), 10), vec![message]);

    queue.mark_sending("txn1").unwrap();
    queue
        .mark_sent(
            "txn1",
            EventId::new("ak:event:01904100-0000-7000-8000-ab84c4c0f437").unwrap(),
        )
        .unwrap();
    assert_eq!(queue.ready_batch(Utc::now(), 10), vec![edit]);

    let restored = SendQueue::from_snapshot(queue.snapshot()).unwrap();
    assert_eq!(restored.len(), 2);
    assert_eq!(restored.get("txn1").unwrap().status, SendQueueStatus::Sent);
}

#[test]
fn send_queue_rejects_unbounded_active_work() {
    let realm_id = RealmId::new("ak:realm:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
    let mut queue = SendQueue::new();
    for index in 0..MAX_SEND_QUEUE_ITEMS {
        queue
            .enqueue_message(
                Some(format!("bounded-{index}")),
                realm_id.clone(),
                json!({"index": index}),
            )
            .unwrap();
    }

    let error = queue
        .enqueue_message(
            Some("over-limit".to_owned()),
            realm_id,
            json!({"over_limit": true}),
        )
        .unwrap_err();
    assert!(error.to_string().contains("item limit"));
    assert_eq!(queue.len(), MAX_SEND_QUEUE_ITEMS);
}

#[test]
fn send_queue_prunes_unreferenced_terminal_work_at_capacity() {
    let realm_id = RealmId::new("ak:realm:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
    let mut queue = SendQueue::new();
    for index in 0..MAX_SEND_QUEUE_ITEMS {
        queue
            .enqueue_message(
                Some(format!("prunable-{index}")),
                realm_id.clone(),
                json!({"index": index}),
            )
            .unwrap();
    }
    queue
        .mark_sent(
            "prunable-0",
            EventId::new("ak:event:01904100-0000-7000-8000-ab84c4c0f437").unwrap(),
        )
        .unwrap();

    queue
        .enqueue_message(
            Some("replacement".to_owned()),
            realm_id,
            json!({"replacement": true}),
        )
        .unwrap();
    assert!(queue.get("prunable-0").is_none());
    assert!(queue.get("replacement").is_some());
    assert_eq!(queue.len(), MAX_SEND_QUEUE_ITEMS);
}

#[test]
fn send_queue_preserves_transitive_dependencies_during_capacity_pruning() {
    let realm_id = RealmId::new("ak:realm:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
    let mut queue = SendQueue::new();
    queue
        .enqueue_message(
            Some("dependency-root".to_owned()),
            realm_id.clone(),
            json!({"root": true}),
        )
        .unwrap();
    queue
        .enqueue(
            Some("dependency-middle".to_owned()),
            realm_id.clone(),
            SendQueueItemKind::Message,
            json!({"middle": true}),
            vec!["dependency-root".to_owned()],
        )
        .unwrap();
    queue
        .enqueue(
            Some("active-leaf".to_owned()),
            realm_id.clone(),
            SendQueueItemKind::Message,
            json!({"leaf": true}),
            vec!["dependency-middle".to_owned()],
        )
        .unwrap();
    queue
        .mark_sent(
            "dependency-root",
            EventId::new("ak:event:01904100-0000-7000-8000-ab84c4c0f437").unwrap(),
        )
        .unwrap();
    queue
        .mark_sent(
            "dependency-middle",
            EventId::new("ak:event:01904100-0000-7000-8000-ab84c4c0f438").unwrap(),
        )
        .unwrap();
    for index in queue.len()..MAX_SEND_QUEUE_ITEMS {
        queue
            .enqueue_message(
                Some(format!("capacity-{index}")),
                realm_id.clone(),
                json!({"index": index}),
            )
            .unwrap();
    }

    assert!(
        queue
            .enqueue_message(
                Some("over-limit".to_owned()),
                realm_id,
                json!({"over_limit": true}),
            )
            .is_err()
    );
    assert!(queue.get("dependency-root").is_some());
    assert!(queue.get("dependency-middle").is_some());
    assert!(queue.get("active-leaf").is_some());
}

#[test]
fn send_queue_serializes_unsigned_intents_per_realm_actor_scope() {
    let realm_a = RealmId::new("ak:realm:01904100-0000-7000-8000-000000000001").unwrap();
    let realm_b = RealmId::new("ak:realm:01904100-0000-7000-8000-000000000002").unwrap();
    let actor = Did::new("did:webvh:z6mkfixture:alice.example").unwrap();
    let mut queue = SendQueue::new();

    for (transaction_id, realm_id) in [
        ("scope-a-1", realm_a.clone()),
        ("scope-a-2", realm_a),
        ("scope-b-1", realm_b),
    ] {
        let item = queue
            .enqueue_message(
                Some(transaction_id.to_owned()),
                realm_id,
                json!({"unsigned_intent": transaction_id}),
            )
            .unwrap();
        queue
            .set_actor_scope(&item.transaction_id, actor.clone())
            .unwrap();
    }

    let ready = queue.ready_batch(Utc::now(), 10);
    assert_eq!(
        ready
            .iter()
            .map(|item| item.transaction_id.as_str())
            .collect::<Vec<_>>(),
        vec!["scope-a-1", "scope-b-1"]
    );

    queue.mark_sending("scope-a-1").unwrap();
    queue
        .mark_sent(
            "scope-a-1",
            EventId::new("ak:event:01904100-0000-7000-8000-000000000001").unwrap(),
        )
        .unwrap();
    assert!(
        queue
            .ready_batch(Utc::now(), 10)
            .iter()
            .any(|item| item.transaction_id == "scope-a-2")
    );
}

#[test]
fn send_queue_replays_exact_persisted_bytes_and_links_semantic_replacement() {
    let realm_id = RealmId::new("ak:realm:01904100-0000-7000-8000-000000000001").unwrap();
    let actor = Did::new("did:webvh:z6mkfixture:alice.example").unwrap();
    let mut queue = SendQueue::new();
    let original = queue
        .enqueue_message(
            Some("attempt-1".to_owned()),
            realm_id.clone(),
            json!({"signed": "immutable-body-1"}),
        )
        .unwrap();
    queue
        .set_actor_scope(&original.transaction_id, actor.clone())
        .unwrap();
    let exact_bytes = queue
        .get("attempt-1")
        .unwrap()
        .canonical_payload_bytes
        .clone();

    queue.mark_sending("attempt-1").unwrap();
    queue
        .mark_failed("attempt-1", std::time::Duration::ZERO)
        .unwrap();
    let restored = SendQueue::from_snapshot(queue.snapshot()).unwrap();
    assert_eq!(
        restored.get("attempt-1").unwrap().canonical_payload_bytes,
        exact_bytes
    );

    let mut queue = restored;
    let replacement = queue
        .supersede(
            "attempt-1",
            "attempt-2".to_owned(),
            realm_id,
            SendQueueItemKind::Message,
            json!({"signed": "immutable-body-2"}),
            Vec::new(),
        )
        .unwrap();
    assert_eq!(
        queue.get("attempt-1").unwrap().status,
        SendQueueStatus::Superseded
    );
    assert_eq!(replacement.local_operation_id, "attempt-1");
    assert_eq!(
        replacement.supersedes_transaction_id.as_deref(),
        Some("attempt-1")
    );
    assert_eq!(replacement.actor_id, Some(actor));
    assert_ne!(replacement.canonical_payload_bytes, exact_bytes);
}

#[test]
fn send_queue_cancels_dependent_edit_redaction_and_reaction() {
    let realm_id = RealmId::new("ak:realm:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
    let event_id = EventId::new("ak:event:01904100-0000-7000-8000-ab84c4c0f437").unwrap();
    let mut queue = SendQueue::new();
    queue
        .enqueue_message(
            Some("txn1".to_owned()),
            realm_id.clone(),
            json!({"body":"hello"}),
        )
        .unwrap();
    queue
        .enqueue_redaction(
            Some("txn2".to_owned()),
            realm_id.clone(),
            event_id.clone(),
            None,
            vec!["txn1".to_owned()],
        )
        .unwrap();
    queue
        .enqueue_reaction(
            Some("txn3".to_owned()),
            realm_id,
            event_id,
            "+1".to_owned(),
            true,
            vec!["txn2".to_owned()],
        )
        .unwrap();

    queue.cancel("txn1", true).unwrap();

    assert_eq!(
        queue.get("txn1").unwrap().status,
        SendQueueStatus::Cancelled
    );
    assert_eq!(
        queue.get("txn2").unwrap().status,
        SendQueueStatus::Cancelled
    );
    assert_eq!(
        queue.get("txn3").unwrap().status,
        SendQueueStatus::Cancelled
    );
}

#[test]
fn sliding_sync_builds_windowed_subscriptions_and_applies_deltas() {
    let s1 = RealmId::new("ak:realm:01904100-0000-7000-8000-000000000001").unwrap();
    let s2 = RealmId::new("ak:realm:01904100-0000-7000-8000-000000000002").unwrap();
    let s3 = RealmId::new("ak:realm:01904100-0000-7000-8000-000000000003").unwrap();
    let s4 = RealmId::new("ak:realm:01904100-0000-7000-8000-000000000004").unwrap();

    let mut sliding = SlidingSync::new();
    sliding.set_realm_list(vec![s1.clone(), s2.clone(), s3]);
    sliding.set_windows(vec![SlidingWindow::new(0, 2).unwrap()]);
    sliding.apply_delta(&[s1], vec![(1, s4.clone())]);

    let config = sliding.subscription_config();

    assert_eq!(config.subscriptions.len(), 2);
    assert_eq!(config.subscriptions[0].realm_id, s2);
    assert_eq!(config.subscriptions[1].realm_id, s4);
    assert!(sliding.is_subscribed(&s4));
}

#[test]
fn realm_list_sorts_filters_and_reports_incremental_changes() {
    let s1 = RealmId::new("ak:realm:01904100-0000-7000-8000-f949e0272316").unwrap();
    let s2 = RealmId::new("ak:realm:01904100-0000-7000-8000-46f8537dc94e").unwrap();
    let mut list = RealmListService::new();
    let mut alpha = RealmListEntry::joined(s1);
    alpha.name = Some("Alpha".to_owned());
    alpha.unread_count = 1;
    let mut beta = RealmListEntry::joined(s2.clone());
    beta.name = Some("Beta".to_owned());
    beta.favorite = true;
    beta.unread_count = 5;

    let first = list.upsert(alpha);
    let second = list.upsert(beta);
    let sorted = list.set_sort(RealmListSort::Unread);
    let filtered = list.set_filter(RealmListFilter {
        unread_only: true,
        ..RealmListFilter::default()
    });

    assert!(matches!(first.changes[0], RealmListChange::Inserted { .. }));
    assert!(
        second
            .changes
            .iter()
            .any(|change| matches!(change, RealmListChange::Inserted { .. }))
    );
    assert_eq!(sorted.ordered[0], s2);
    assert_eq!(filtered.ordered.len(), 2);

    let snapshot = list.snapshot();
    let restored = RealmListService::from_snapshot(snapshot);
    assert_eq!(restored.entries().len(), 2);
    assert_eq!(restored.entries()[0].realm_id, s2);
}

#[test]
fn realm_list_folds_typed_direct_conversation_role_from_window_start() {
    let realm_id = RealmId::new("ak:realm:01904100-0000-7000-8000-0000000000d1").unwrap();
    let update: RealmUpdate = serde_json::from_value(json!({
        "realm_id": realm_id,
        "entry": {
            "state_at_window_start": {
                "actor_profiles": {},
                "realm_metadata": {
                    "title": "Direct conversation",
                    "collaboration_role": "direct_conversation"
                },
                "e2ee_epoch": null
            }
        }
    }))
    .unwrap();
    let mut list = RealmListService::new();

    list.apply_space_update(&update, MembershipBucket::Joined);

    assert_eq!(
        list.entries()[0].collaboration_role,
        Some(CollaborationRealmRole::DirectConversation)
    );
}
