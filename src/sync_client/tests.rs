use std::collections::BTreeMap;

use crate::protocol::{
    AccountSubscribeRealms, AccountSubscribeUnreadCounts, DeviceId, DeviceMessageContainer,
    DeviceMessageEnvelope, DeviceMessageSender, ErrorEnvelope, EventContainer, ProtocolKind,
    RealmSyncEntry,
};
use arkret_models_collaboration::sync_frames::account_sync::DeviceMessageContent;
use arkret_wire::{DidCoreId, EventKind, Hlc, OpaqueLocalId, ScopeRef};
use serde_json::{Value, json};

use super::*;
use crate::protocol::{
    AgentRuntimeApprovalNotificationData, AgentRuntimeApprovalNotificationRemovalData,
    AgentRuntimeApprovalRemovalReason, DeviceMessageId, NotificationContainer, NotificationData,
    NotificationId, RealmId,
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
            notifications: None,
            agent_signer_evidence_bundle: None,
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
            action: NotificationDeltaAction::Upsert,
            data: Some(NotificationData::AgentRuntimeApproval(
                AgentRuntimeApprovalNotificationData {
                    approval_request_id: OpaqueLocalId::new(
                        "agent_runtime_approval:01964137-0000-7000-8000-000000000001",
                    )
                    .unwrap(),
                    agent_id: DidCoreId::new("ak:did_core:webvh:z6mkfixture:agent.example")
                        .unwrap(),
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

fn publication_lease(realm_id: RealmId) -> arkret_wire::AuthorizationLease {
    let issued_at = Utc::now() - chrono::Duration::minutes(5);
    super::send_queue::test_publication::lease(
        realm_id,
        issued_at,
        issued_at + chrono::Duration::hours(1),
    )
}

/// The receipt a policy-accepted ingress returns in
/// `EventsSubmitOutcome.ingress_receipts[]`.
fn accepted_receipt() -> arkret_wire::IngressReceipt {
    let realm_id = RealmId::new("ak:realm:AagCPdrqXX6jLnry9ez4FYiULbKas6Z7PCgbH06WlNUV").unwrap();
    let lease = publication_lease(realm_id);
    let received_at = lease.issued_at + chrono::Duration::minutes(1);
    super::send_queue::test_publication::receipt(received_at)
}

fn event_id(seed: u8) -> EventId {
    EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [seed; 32])
}

fn actor_id(core_id: &DidCoreId) -> DidCoreId {
    core_id.clone()
}

fn queued_record(realm_id: &RealmId, payload: Value) -> crate::QueuedRecord {
    let event = arkret_wire::test_support::raw_event_at(
        EventKind::MessageCreate.as_str(),
        ScopeRef::Realm {
            realm_id: realm_id.clone(),
        },
        actor_id(&DidCoreId::new("ak:did_core:webvh:z6mkfixture:alice.example").unwrap()),
        DidCoreId::new("ak:did_core:web:principal.example").unwrap(),
        1,
        Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
        payload,
        chrono::DateTime::parse_from_rfc3339("2026-07-13T10:00:00.000Z")
            .unwrap()
            .with_timezone(&chrono::Utc),
    )
    .unwrap();
    crate::QueuedRecord::SdkEvent(Box::new(
        crate::QueuedSdkEvent::unauthored(
            crate::QueuedEventIntent::new(
                arkret_event_draft::EventIntent::from_authored(&event),
                arkret_canonical::DigestSuite::Sha256,
            ),
            "test-operation".to_owned(),
            "test-attempt".to_owned(),
            None,
            crate::AuthoringGeneration {
                authority_model: crate::AuthoringAuthorityModel::AcceptedDevice,
                authority_principal_id: arkret_wire::DidCoreId::new(
                    "ak:did_core:webvh:z6mkfixture:alice.example",
                )
                .unwrap(),
                generation_ref: "test-generation".to_owned(),
            },
            None,
        )
        .unwrap(),
    ))
}

trait SendQueueTestExt {
    fn enqueue_test_record(
        &mut self,
        transaction_id: Option<String>,
        realm_id: RealmId,
        content: Value,
    ) -> Result<SendQueueItem>;

    fn enqueue_dependent_test_record(
        &mut self,
        transaction_id: Option<String>,
        realm_id: RealmId,
        content: Value,
        depends_on: Vec<String>,
    ) -> Result<SendQueueItem>;
}

impl SendQueueTestExt for SendQueue {
    fn enqueue_test_record(
        &mut self,
        transaction_id: Option<String>,
        realm_id: RealmId,
        content: Value,
    ) -> Result<SendQueueItem> {
        self.enqueue(
            transaction_id,
            realm_id.clone(),
            queued_record(&realm_id, content),
            Vec::new(),
        )
    }

    fn enqueue_dependent_test_record(
        &mut self,
        transaction_id: Option<String>,
        realm_id: RealmId,
        content: Value,
        depends_on: Vec<String>,
    ) -> Result<SendQueueItem> {
        self.enqueue(
            transaction_id,
            realm_id.clone(),
            queued_record(&realm_id, content),
            depends_on,
        )
    }
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
    let mut transport = |request: SyncRequestBody, _options| {
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
    let mut transport = |_request: SyncRequestBody, _options| Ok(sync_response(""));
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
    let mut transport = |request: SyncRequestBody, _options| {
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
    let mut transport = |_request: SyncRequestBody, _options| {
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
    let transport = |request: SyncRequestBody, _options| async move {
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
    let transport = |_request: SyncRequestBody, _options| async { Ok(sync_response("unused")) };
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
    let realm_id = "ak:realm:AagCPdrqXX6jLnry9ez4FYiULbKas6Z7PCgbH06WlNUV";
    let mut response = sync_response("gap-token");
    let entry = RealmSyncEntry {
        timeline: Some(Timeline {
            events: Vec::new(),
            limited: true,
            prev_cursor: Some("prev".to_owned()),
            preview_only: None,
            ordered_log_siblings: Vec::new(),
            extra: BTreeMap::new(),
        }),
        ..Default::default()
    };
    delta_mut(&mut response).realms = Some(AccountSubscribeRealms {
        entries: BTreeMap::from([(realm_id.to_owned(), entry)]),
    });
    let mut transport = |_request: SyncRequestBody, _options| Ok(response.clone());
    let mut sync_loop =
        SyncLoop::new().with_gap_strategy(SyncGapStrategy::ResetTokenOnLimitedTimeline);

    assert!(matches!(
        sync_loop.step(&mut transport),
        SyncLoopStep::Updates(_)
    ));
    assert!(sync_loop.token().is_none());
}

#[test]
fn sync_loop_sends_wait_for_as_header_option() {
    let barrier = "ak:cursor:01904100-0000-7000-8000-9b64700c6ee8";
    let sync_loop = SyncLoop::new().with_wait_for(barrier);

    let request = sync_loop.next_request();
    let options = sync_loop.next_request_options();

    assert_eq!(request.after, None);
    assert_eq!(options.wait_for.as_deref(), Some(barrier));
}

#[test]
fn processor_dispatches_all_update_categories() {
    let realm_id = "ak:realm:AagCPdrqXX6jLnry9ez4FYiULbKas6Z7PCgbH06WlNUV";
    let mut response = sync_response("s2");
    let entry = RealmSyncEntry {
        summary: Some(AccountSubscribeRealmSummary {
            joined_member_count: Some(2),
            invited_member_count: None,
            hero_ids: None,
        }),
        unread_notifications: Some(AccountSubscribeUnreadCounts {
            notification_count: Some(3),
            highlight_count: Some(1),
        }),
        ..Default::default()
    };
    let sender = DidCoreId::new("ak:did_core:webvh:z6mkfixture:alice.example").unwrap();
    let recipient = DidCoreId::new("ak:did_core:webvh:z6mkfixture:bob.example").unwrap();
    let realm = RealmId::new(realm_id).unwrap();
    let account_data_event = arkret_wire::test_support::raw_event(
        "ak.account_data.set",
        crate::protocol::ScopeRef::Realm { realm_id: realm },
        actor_id(&sender),
        DidCoreId::new("ak:did_core:web:principal.example").unwrap(),
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
            device_message_id: DeviceMessageId::new(
                "ak:device_message:01904100-0000-7000-8000-000000000007",
            )
            .unwrap(),
            kind: ProtocolKind::new("ak.test.message").unwrap(),
            content: DeviceMessageContent::Extension(BTreeMap::from([(
                "ok".to_owned(),
                json!(true),
            )])),
            sender_principal_id: sender.clone(),
            sender: DeviceMessageSender::Device {
                sender_device_id: DeviceId::new("ak:device:01904100-0000-7000-8000-000000000005")
                    .unwrap(),
            },
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
        changed_ids: vec![sender.clone()],
        left_ids: Vec::new(),
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
    let updates = processor.process(response).unwrap();
    let parsed_realm_id = RealmId::new(realm_id).unwrap();

    assert_eq!(updates.realm_updates.len(), 1);
    assert_eq!(
        processor
            .realm(&parsed_realm_id)
            .unwrap()
            .notification_count,
        3
    );
    assert_eq!(updates.to_device.len(), 1);
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
    assert!(processor.account_data("ak.settings").is_some());
    assert!(processor.notification(notification_id).is_some());
    assert_eq!(processor.device_lists().changed_ids.len(), 1);
}

/// A per-stream Realm delta that reports only, say, unread counts carries no
/// `summary`. That absence is not a retraction: the last durable summary must
/// survive it.
#[test]
fn summary_less_realm_delta_preserves_durable_processor_summary() {
    let realm_id = "ak:realm:AagCPdrqXX6jLnry9ez4FYiULbKas6Z7PCgbH06WlNUV";
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
                    hero_ids: None,
                }),
                ..Default::default()
            },
        )]),
    });
    processor.process(baseline).unwrap();

    let mut unread_only = sync_response("s-summary-2");
    delta_mut(&mut unread_only).realms = Some(AccountSubscribeRealms {
        entries: BTreeMap::from([(
            realm_id.to_owned(),
            RealmSyncEntry {
                unread_notifications: Some(AccountSubscribeUnreadCounts {
                    notification_count: Some(4),
                    highlight_count: Some(0),
                }),
                ..Default::default()
            },
        )]),
    });
    processor.process(unread_only).unwrap();

    assert_eq!(
        processor
            .realm(&parsed_realm_id)
            .and_then(|realm| realm.summary.as_ref())
            .and_then(|summary| summary.joined_member_count),
        Some(2)
    );
}

// Account subscribe carries durable account state only. Per-device signal
// authentication, deterministic presence aggregation, expiry and the refusal
// of unverified signals belong to the encrypted rail and are covered in
// `crate::signal`.

#[test]
fn processor_tracks_limited_timelines() {
    let realm_id = "ak:realm:AagCPdrqXX6jLnry9ez4FYiULbKas6Z7PCgbH06WlNUV";
    let parsed_realm_id = RealmId::new(realm_id).unwrap();
    let event = arkret_wire::test_support::raw_event(
        "ak.message.create",
        crate::protocol::ScopeRef::Realm {
            realm_id: parsed_realm_id.clone(),
        },
        actor_id(&DidCoreId::new("ak:did_core:webvh:z6mkfixture:alice.example").unwrap()),
        DidCoreId::new("ak:did_core:web:principal.example").unwrap(),
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
            ordered_log_siblings: Vec::new(),
            extra: BTreeMap::new(),
        }),
        ..Default::default()
    };
    delta_mut(&mut response).realms = Some(AccountSubscribeRealms {
        entries: BTreeMap::from([(realm_id.to_owned(), entry)]),
    });

    let mut processor = SyncResponseProcessor::new();
    processor.process(response).unwrap();

    assert_eq!(
        processor
            .realm(&parsed_realm_id)
            .unwrap()
            .limited_timeline_count,
        1
    );
    assert_eq!(processor.limited_timelines().len(), 1);
}

#[test]
fn processor_applies_notification_upsert_and_remove_deltas() {
    let notification_id = "ak:notification:01964137-0000-7000-8000-000000000001";
    let mut processor = SyncResponseProcessor::new();
    let mut initial_upsert = sync_response("s-upsert-initial");
    delta_mut(&mut initial_upsert).notifications = Some(approval_notifications(
        notification_id,
        "2026-07-13T10:15:00.000Z",
    ));
    processor.process(initial_upsert).unwrap();
    assert!(processor.notification(notification_id).is_some());

    let mut replacement_upsert = sync_response("s-upsert-replacement");
    let replacement_notifications =
        approval_notifications(notification_id, "2026-07-13T10:20:00.000Z");
    delta_mut(&mut replacement_upsert).notifications = Some(replacement_notifications);
    processor.process(replacement_upsert).unwrap();
    let serialized =
        serde_json::to_value(processor.notification(notification_id).unwrap()).unwrap();
    assert_eq!(serialized["data"]["expires_at"], "2026-07-13T10:20:00.000Z");

    let mut remove = sync_response("s-remove");
    delta_mut(&mut remove).notifications = Some(NotificationContainer {
        items: vec![NotificationDelta {
            id: NotificationId::new(notification_id).unwrap(),
            action: NotificationDeltaAction::Remove,
            data: Some(NotificationData::AgentRuntimeApprovalRemoval(
                AgentRuntimeApprovalNotificationRemovalData {
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
    let realm_id = RealmId::new("ak:realm:AagCPdrqXX6jLnry9ez4FYiULbKas6Z7PCgbH06WlNUV").unwrap();
    let mut queue = SendQueue::new();
    let record = queued_record(&realm_id, json!({"body":"hello"}));
    let message = queue
        .enqueue(
            Some("txn1".to_owned()),
            realm_id.clone(),
            record.clone(),
            Vec::new(),
        )
        .unwrap();
    let duplicate = queue
        .enqueue(
            Some("txn1".to_owned()),
            realm_id.clone(),
            record,
            Vec::new(),
        )
        .unwrap();
    let edit = queue
        .enqueue_dependent_test_record(
            Some("txn2".to_owned()),
            realm_id,
            json!({"content":{"body":"hi"}}),
            vec!["txn1".to_owned()],
        )
        .unwrap();

    assert_eq!(message.payload_digest, duplicate.payload_digest);
    assert_eq!(queue.ready_batch(Utc::now(), 10), vec![message]);

    queue.mark_sending("txn1").unwrap();
    queue
        .mark_sent("txn1", event_id(1), vec![accepted_receipt()])
        .unwrap();
    assert_eq!(queue.ready_batch(Utc::now(), 10), vec![edit]);

    let restored = SendQueue::from_snapshot(queue.snapshot()).unwrap();
    assert_eq!(restored.len(), 2);
    assert_eq!(restored.get("txn1").unwrap().status, SendQueueStatus::Sent);
}

#[test]
fn send_queue_snapshot_is_tagged_and_rejects_untagged_kind_content_shape() {
    let realm_id = RealmId::new("ak:realm:AagCPdrqXX6jLnry9ez4FYiULbKas6Z7PCgbH06WlNUV").unwrap();
    let mut queue = SendQueue::new();
    queue
        .enqueue_test_record(
            Some("tagged".to_owned()),
            realm_id,
            json!({"body": "hello"}),
        )
        .unwrap();
    assert_eq!(
        queue
            .get("tagged")
            .unwrap()
            .record
            .event_kind()
            .unwrap()
            .as_str(),
        EventKind::MessageCreate.as_str()
    );
    let encoded = serde_json::to_value(queue.snapshot()).unwrap();
    assert_eq!(
        encoded.pointer("/items/0/record/record_type"),
        Some(&Value::String("sdk_event".to_owned()))
    );
    assert!(encoded.pointer("/items/0/kind").is_none());
    assert!(encoded.pointer("/items/0/content").is_none());

    let untagged = json!({
        "items": [],
        "next_sequence": 0
    });
    assert!(serde_json::from_value::<SendQueueSnapshot>(untagged).is_err());
}

#[test]
fn send_queue_rejects_unbounded_active_work() {
    let realm_id = RealmId::new("ak:realm:AagCPdrqXX6jLnry9ez4FYiULbKas6Z7PCgbH06WlNUV").unwrap();
    let mut queue = SendQueue::new();
    for index in 0..MAX_SEND_QUEUE_ITEMS {
        queue
            .enqueue_test_record(
                Some(format!("bounded-{index}")),
                realm_id.clone(),
                json!({"index": index}),
            )
            .unwrap();
    }

    let error = queue
        .enqueue_test_record(
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
    let realm_id = RealmId::new("ak:realm:AagCPdrqXX6jLnry9ez4FYiULbKas6Z7PCgbH06WlNUV").unwrap();
    let mut queue = SendQueue::new();
    for index in 0..MAX_SEND_QUEUE_ITEMS {
        queue
            .enqueue_test_record(
                Some(format!("prunable-{index}")),
                realm_id.clone(),
                json!({"index": index}),
            )
            .unwrap();
    }
    queue
        .mark_sent("prunable-0", event_id(1), vec![accepted_receipt()])
        .unwrap();

    queue
        .enqueue_test_record(
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
    let realm_id = RealmId::new("ak:realm:AagCPdrqXX6jLnry9ez4FYiULbKas6Z7PCgbH06WlNUV").unwrap();
    let mut queue = SendQueue::new();
    queue
        .enqueue_test_record(
            Some("dependency-root".to_owned()),
            realm_id.clone(),
            json!({"root": true}),
        )
        .unwrap();
    queue
        .enqueue(
            Some("dependency-middle".to_owned()),
            realm_id.clone(),
            queued_record(&realm_id, json!({"middle": true})),
            vec!["dependency-root".to_owned()],
        )
        .unwrap();
    queue
        .enqueue(
            Some("active-leaf".to_owned()),
            realm_id.clone(),
            queued_record(&realm_id, json!({"leaf": true})),
            vec!["dependency-middle".to_owned()],
        )
        .unwrap();
    queue
        .mark_sent("dependency-root", event_id(1), vec![accepted_receipt()])
        .unwrap();
    queue
        .mark_sent("dependency-middle", event_id(2), vec![accepted_receipt()])
        .unwrap();
    for index in queue.len()..MAX_SEND_QUEUE_ITEMS {
        queue
            .enqueue_test_record(
                Some(format!("capacity-{index}")),
                realm_id.clone(),
                json!({"index": index}),
            )
            .unwrap();
    }

    assert!(
        queue
            .enqueue_test_record(
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
    let realm_a = RealmId::new("ak:realm:AfF-hFqRoMbajXkPapH-xaq0xwK-UKt2ph2zTs9JZRAO").unwrap();
    let realm_b = RealmId::new("ak:realm:AT0jIIg6naB0Vkqbb-ip6eunf-bHr5-nh4pz2_kYNyVX").unwrap();
    let actor = actor_id(&DidCoreId::new("ak:did_core:webvh:z6mkfixture:alice.example").unwrap());
    let mut queue = SendQueue::new();

    for (transaction_id, realm_id) in [
        ("scope-a-1", realm_a.clone()),
        ("scope-a-2", realm_a),
        ("scope-b-1", realm_b),
    ] {
        let item = queue
            .enqueue_test_record(
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
        .mark_sent("scope-a-1", event_id(1), vec![accepted_receipt()])
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
    let realm_id = RealmId::new("ak:realm:AfF-hFqRoMbajXkPapH-xaq0xwK-UKt2ph2zTs9JZRAO").unwrap();
    let actor = actor_id(&DidCoreId::new("ak:did_core:webvh:z6mkfixture:alice.example").unwrap());
    let mut queue = SendQueue::new();
    let original = queue
        .enqueue_test_record(
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
            realm_id.clone(),
            queued_record(&realm_id, json!({"signed": "immutable-body-2"})),
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
fn send_queue_cancels_transitive_dependents() {
    let realm_id = RealmId::new("ak:realm:AagCPdrqXX6jLnry9ez4FYiULbKas6Z7PCgbH06WlNUV").unwrap();
    let mut queue = SendQueue::new();
    queue
        .enqueue_test_record(
            Some("txn1".to_owned()),
            realm_id.clone(),
            json!({"body":"hello"}),
        )
        .unwrap();
    queue
        .enqueue_dependent_test_record(
            Some("txn2".to_owned()),
            realm_id.clone(),
            json!({"dependency": 1}),
            vec!["txn1".to_owned()],
        )
        .unwrap();
    queue
        .enqueue_dependent_test_record(
            Some("txn3".to_owned()),
            realm_id,
            json!({"dependency": 2}),
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
fn send_queue_refuses_delayed_acceptance_without_an_ingress_receipt() {
    // A receipt is the only evidence that the Event reached a policy-accepted
    // ingress inside its lease window (`offline-publication.md` §2). Recording
    // an acceptance without one would leave a locally "sent" item that no peer
    // can ever be made to accept.
    let realm_id = RealmId::new("ak:realm:AagCPdrqXX6jLnry9ez4FYiULbKas6Z7PCgbH06WlNUV").unwrap();
    let mut queue = SendQueue::new();
    queue
        .enqueue_test_record(
            Some("txn1".to_owned()),
            realm_id.clone(),
            json!({"body": "hi"}),
        )
        .unwrap();
    queue
        .bind_authorization_lease("txn1", publication_lease(realm_id))
        .unwrap();

    let error = queue
        .mark_sent("txn1", event_id(1), Vec::new())
        .unwrap_err();

    assert!(format!("{error}").contains("at least one ingress receipt"));
    assert_eq!(queue.get("txn1").unwrap().status, SendQueueStatus::Queued);
}

#[test]
fn send_queue_accepts_online_submission_without_an_ingress_receipt() {
    // Online publication has no authorization lease, so there is no lease
    // window for an ingress receipt to bind (`event_submission.rs`).
    let realm_id = RealmId::new("ak:realm:AagCPdrqXX6jLnry9ez4FYiULbKas6Z7PCgbH06WlNUV").unwrap();
    let mut queue = SendQueue::new();
    queue
        .enqueue_test_record(Some("txn1".to_owned()), realm_id, json!({"body": "hi"}))
        .unwrap();

    queue.mark_sent("txn1", event_id(1), Vec::new()).unwrap();

    assert_eq!(queue.get("txn1").unwrap().status, SendQueueStatus::Sent);
    assert!(queue.get("txn1").unwrap().ingress_receipts.is_empty());
}

#[test]
fn send_queue_keeps_the_original_receipt_across_an_idempotent_retry() {
    // `offline-publication.md` §2.1: an idempotent retry must return the
    // original receipt. A later `received_at` would extend an already fixed
    // revocation window, so the durable copy wins over whatever the retry
    // reported.
    let realm_id = RealmId::new("ak:realm:AagCPdrqXX6jLnry9ez4FYiULbKas6Z7PCgbH06WlNUV").unwrap();
    let mut queue = SendQueue::new();
    queue
        .enqueue_test_record(Some("txn1".to_owned()), realm_id.clone(), json!({"a": 1}))
        .unwrap();
    let lease = publication_lease(realm_id);
    queue
        .bind_authorization_lease("txn1", lease.clone())
        .unwrap();
    let original = super::send_queue::test_publication::receipt(
        lease.issued_at + chrono::Duration::minutes(1),
    );
    let re_signed = super::send_queue::test_publication::receipt(
        lease.issued_at + chrono::Duration::minutes(30),
    );
    let event_id = event_id(1);

    queue
        .mark_sent("txn1", event_id.clone(), vec![original.clone()])
        .unwrap();
    queue.mark_sent("txn1", event_id, vec![re_signed]).unwrap();

    let item = queue.get("txn1").unwrap();
    assert_eq!(item.status, SendQueueStatus::Sent);
    assert_eq!(item.ingress_receipts, vec![original]);
}

#[test]
fn send_queue_retires_unreceipted_work_once_its_lease_expires() {
    // An Event that first appears after its lease expired without a receipt is
    // permanently rejected (`offline-publication.md` §2), so it stops being
    // schedulable work rather than retrying forever.
    let realm_id = RealmId::new("ak:realm:AagCPdrqXX6jLnry9ez4FYiULbKas6Z7PCgbH06WlNUV").unwrap();
    let mut queue = SendQueue::new();
    queue
        .enqueue_test_record(Some("txn1".to_owned()), realm_id.clone(), json!({"a": 1}))
        .unwrap();
    let lease = publication_lease(realm_id);
    let expires_at = lease.expires_at;
    queue.bind_authorization_lease("txn1", lease).unwrap();

    assert_eq!(
        queue
            .ready_batch(expires_at - chrono::Duration::minutes(1), 10)
            .len(),
        1
    );
    assert!(queue.ready_batch(expires_at, 10).is_empty());
    assert_eq!(queue.expire_unreceipted_leases(expires_at), vec!["txn1"]);
    assert_eq!(
        queue.get("txn1").unwrap().status,
        SendQueueStatus::LeaseExpired
    );
}

#[test]
fn send_queue_refuses_a_lease_scoped_to_another_realm() {
    let realm_id = RealmId::new("ak:realm:AagCPdrqXX6jLnry9ez4FYiULbKas6Z7PCgbH06WlNUV").unwrap();
    let other_realm =
        RealmId::new("ak:realm:ASc9wABHjT9O0CyPDbA8mMnMYoVQe0dWU7KkoFC-vH73").unwrap();
    let mut queue = SendQueue::new();
    queue
        .enqueue_test_record(Some("txn1".to_owned()), realm_id, json!({"a": 1}))
        .unwrap();

    let error = queue
        .bind_authorization_lease("txn1", publication_lease(other_realm))
        .unwrap_err();

    assert!(format!("{error}").contains("different Realm"));
}
