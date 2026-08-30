use super::*;

/// Processed account-subscribe state and ordered delivery queues.
///
/// The account-subscribe stream carries durable account state only. Momentary
/// announcements (presence, typing, receipts, call setup) are not part of it:
/// they ride the encrypted-only Signal rail (`zh/sync/signal.md` §4) and are
/// consumed through [`crate::signal::SignalReceiver`].
#[derive(Clone, Debug, Default)]
pub struct SyncResponseProcessor {
    realms: BTreeMap<RealmId, ProcessedRealm>,
    limited_timelines: BTreeMap<RealmId, LimitedTimelineState>,
    changed_device_lists: BTreeSet<ActorId>,
    left_device_lists: BTreeSet<ActorId>,
    pending_recovery_actions: BTreeSet<SyncRecoveryAction>,
    account_data: BTreeMap<String, Event>,
    notifications: BTreeMap<String, NotificationDelta>,
}

/// Recovery work the application must schedule after reliable to-device
/// delivery was lost for the current device.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncRecoveryAction {
    RefetchDeviceLists,
    RequestMissingMlsMaterial,
    RestoreFromKeyBackup,
}

impl SyncRecoveryAction {
    fn to_device_loss_actions() -> [Self; 3] {
        [
            Self::RefetchDeviceLists,
            Self::RequestMissingMlsMaterial,
            Self::RestoreFromKeyBackup,
        ]
    }
}

impl SyncResponseProcessor {
    pub fn new() -> Self {
        Self::default()
    }

    /// Process an ordered, validated account-subscribe catch-up batch without
    /// folding its canonical frames through an alternate wire model.
    pub fn process(&mut self, batch: AccountSubscribeBatch) -> Result<SyncUpdates> {
        let mut staged = self.clone();
        let updates = staged.process_staged(batch)?;
        *self = staged;
        Ok(updates)
    }

    fn process_staged(&mut self, batch: AccountSubscribeBatch) -> Result<SyncUpdates> {
        if batch.cursor.trim().is_empty() {
            return Err(Error::Protocol(
                "account subscribe batch requires a non-empty cursor".to_owned(),
            ));
        }

        let mut realm_updates = Vec::new();
        let mut malformed_realms = Vec::new();
        let mut to_device = Vec::new();
        let mut to_device_ack_token = None;
        let mut to_device_limited = false;
        let mut to_device_next_cursor = None;
        let mut to_device_lost = false;
        let mut changed_device_lists = BTreeSet::new();
        let mut left_device_lists = BTreeSet::new();
        let mut account_data = Vec::new();
        let mut notifications = Vec::new();
        let mut agent_signer_evidence = Vec::new();
        let mut partial = false;

        for frame in batch.frames {
            frame.validate()?;
            if frame.kind != AccountSubscribeFrameKind::Delta {
                return Err(Error::Protocol(
                    "account subscribe batch contains a non-delta frame".to_owned(),
                ));
            }

            if let Some(realms) = frame.realms {
                for (raw_realm_id, entry) in realms.entries {
                    let Ok(realm_id) = RealmId::new(raw_realm_id.clone()) else {
                        malformed_realms.push(raw_realm_id);
                        continue;
                    };
                    let processed = self.realms.entry(realm_id.clone()).or_default();
                    if let Some(timeline) = &entry.timeline {
                        processed.timeline_events += timeline.events.len();
                        processed.last_timeline = Some(timeline.clone());
                        processed.last_limited = timeline.limited;
                        processed.last_prev_cursor = timeline.prev_cursor.clone();
                        if timeline.limited {
                            let limited =
                                LimitedTimelineState::from_timeline(realm_id.clone(), timeline);
                            processed.limited_timeline_count += 1;
                            processed.pending_gap = limited.gap.clone();
                            self.limited_timelines.insert(realm_id.clone(), limited);
                        }
                    }
                    processed.state_events += entry
                        .state
                        .as_ref()
                        .map_or(0, |container| container.events.len());
                    // Realm entries are per-stream deltas: a delta that only
                    // reports, say, unread counts or event states legitimately
                    // omits `summary`. Do not erase the last durable summary
                    // in that case.
                    if let Some(summary) = &entry.summary {
                        processed.summary = Some(summary.clone());
                    }
                    if let Some(unread) = &entry.unread_notifications {
                        processed.notification_count = unread.notification_count.unwrap_or(0);
                        processed.highlight_count = unread.highlight_count.unwrap_or(0);
                    }
                    realm_updates.push(RealmUpdate { realm_id, entry });
                }
            }

            if let Some(container) = frame.to_device {
                if container.lost.unwrap_or(false) {
                    to_device_lost = true;
                }
                to_device_limited |= container.limited.unwrap_or(false);
                if container.ack_token.is_some() {
                    to_device_ack_token = container.ack_token;
                }
                if container.next_cursor.is_some() {
                    to_device_next_cursor = container.next_cursor;
                }
                to_device.extend(container.messages);
            }
            if let Some(changes) = frame.device_lists {
                changed_device_lists.extend(changes.changed_ids.iter().cloned());
                left_device_lists.extend(changes.left_ids.iter().cloned());
                self.changed_device_lists.extend(changes.changed_ids);
                self.left_device_lists.extend(changes.left_ids);
            }
            if let Some(container) = frame.account_data {
                for event in container.events {
                    if let Some(key) = event.payload.get("key").and_then(Value::as_str) {
                        self.account_data.insert(key.to_owned(), event.clone());
                    }
                    account_data.push(event);
                }
            }
            if let Some(container) = frame.notifications {
                for notification in container.items {
                    match notification.action {
                        NotificationDeltaAction::Upsert => {
                            self.notifications
                                .insert(notification.id.as_str().to_owned(), notification.clone());
                        }
                        NotificationDeltaAction::Remove => {
                            self.notifications.remove(notification.id.as_str());
                        }
                    }
                    notifications.push(notification);
                }
            }
            if let Some(bundle) = frame.agent_signer_evidence_bundle {
                agent_signer_evidence.extend(bundle.evidence_items);
            }
            partial |= frame.partial.unwrap_or(false);
        }

        if to_device_lost {
            self.pending_recovery_actions
                .extend(SyncRecoveryAction::to_device_loss_actions());
        }

        Ok(SyncUpdates {
            realm_updates,
            malformed_realm_ids: malformed_realms,
            to_device,
            to_device_ack_token,
            to_device_limited,
            to_device_next_cursor,
            to_device_lost,
            device_lists: AccountSubscribeDeviceListChanges {
                changed_ids: changed_device_lists.into_iter().collect(),
                left_ids: left_device_lists.into_iter().collect(),
            },
            account_data,
            notifications,
            agent_signer_evidence,
            partial,
        })
    }

    pub fn realm(&self, realm_id: &RealmId) -> Option<&ProcessedRealm> {
        self.realms.get(realm_id)
    }

    pub fn limited_timelines(&self) -> Vec<&LimitedTimelineState> {
        self.limited_timelines.values().collect()
    }

    pub fn account_data(&self, key: &str) -> Option<&Event> {
        self.account_data.get(key)
    }

    pub fn notification(&self, id: &str) -> Option<&NotificationDelta> {
        self.notifications.get(id)
    }

    pub fn device_lists(&self) -> AccountSubscribeDeviceListChanges {
        AccountSubscribeDeviceListChanges {
            changed_ids: self.changed_device_lists.iter().cloned().collect(),
            left_ids: self.left_device_lists.iter().cloned().collect(),
        }
    }

    pub fn recovery_actions(&self) -> Vec<SyncRecoveryAction> {
        self.pending_recovery_actions.iter().cloned().collect()
    }

    pub fn take_recovery_actions(&mut self) -> Vec<SyncRecoveryAction> {
        let actions = self.recovery_actions();
        self.pending_recovery_actions.clear();
        actions
    }

    pub fn clear(&mut self) {
        *self = Self::default();
    }
}

#[derive(Clone, Debug, Default)]
pub struct ProcessedRealm {
    pub last_timeline: Option<Timeline>,
    pub timeline_events: usize,
    pub state_events: usize,
    pub summary: Option<AccountSubscribeRealmSummary>,
    pub notification_count: u64,
    pub highlight_count: u64,
    pub last_limited: bool,
    pub last_prev_cursor: Option<String>,
    pub limited_timeline_count: usize,
    pub pending_gap: Option<crate::protocol::sync::SyncGap>,
}
