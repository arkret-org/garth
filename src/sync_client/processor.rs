use super::*;

/// Resolver for an active, authorized device signing key. Implementations
/// normally read a previously validated `keys/query` device directory.
pub trait EphemeralDeviceKeyResolver: Send + Sync {
    fn resolve_active_device_key(
        &self,
        actor_id: &Did,
        device_id: &DeviceId,
    ) -> Option<PublicKeyMaterial>;
}

impl<F> EphemeralDeviceKeyResolver for F
where
    F: Fn(&Did, &DeviceId) -> Option<PublicKeyMaterial> + Send + Sync,
{
    fn resolve_active_device_key(
        &self,
        actor_id: &Did,
        device_id: &DeviceId,
    ) -> Option<PublicKeyMaterial> {
        self(actor_id, device_id)
    }
}

/// Processed account-subscribe state and ordered delivery queues.
#[derive(Clone, Debug, Default)]
pub struct SyncResponseProcessor {
    realms: BTreeMap<RealmId, ProcessedRealm>,
    limited_timelines: BTreeMap<RealmId, LimitedTimelineState>,
    to_device: VecDeque<DeviceMessageEnvelope>,
    to_device_acks: BTreeMap<String, ToDeviceAck>,
    changed_device_lists: BTreeSet<Did>,
    left_device_lists: BTreeSet<Did>,
    pending_recovery_actions: BTreeSet<SyncRecoveryAction>,
    presence: BTreeMap<Did, BTreeMap<DeviceId, EphemeralEnvelope>>,
    account_data: BTreeMap<String, Event>,
    notifications: BTreeMap<String, NotificationDelta>,
    last_token: Option<String>,
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
    /// Process a batch without an authorized device-key resolver. Presence is
    /// fail-closed and omitted; all non-ephemeral update categories continue
    /// to be processed.
    pub fn process(&mut self, batch: AccountSubscribeBatch) -> Result<SyncUpdates> {
        self.process_at(batch, Utc::now(), None)
    }

    /// Process a batch and authenticate every presence signal against the
    /// active device key returned by `resolver`.
    pub fn process_with_ephemeral_key_resolver(
        &mut self,
        batch: AccountSubscribeBatch,
        resolver: &dyn EphemeralDeviceKeyResolver,
    ) -> Result<SyncUpdates> {
        self.process_at(batch, Utc::now(), Some(resolver))
    }

    fn process_at(
        &mut self,
        batch: AccountSubscribeBatch,
        now: DateTime<Utc>,
        resolver: Option<&dyn EphemeralDeviceKeyResolver>,
    ) -> Result<SyncUpdates> {
        if batch.cursor.trim().is_empty() {
            return Err(Error::Protocol(
                "account subscribe batch requires a non-empty cursor".to_owned(),
            ));
        }
        self.last_token = Some(batch.cursor);
        self.expire_presence(now);

        let mut realm_updates = Vec::new();
        let mut malformed_realms = Vec::new();
        let mut to_device = Vec::new();
        let mut to_device_ack_token = None;
        let mut to_device_limited = false;
        let mut to_device_next_cursor = None;
        let mut to_device_lost = false;
        let mut changed_device_lists = BTreeSet::new();
        let mut left_device_lists = BTreeSet::new();
        let mut presence = Vec::new();
        let mut account_data = Vec::new();
        let mut notifications = Vec::new();
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
                    // Realm entries are per-stream deltas. An
                    // ephemeral-only entry legitimately omits `summary`; do
                    // not erase the last durable summary in that case.
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
                to_device_limited = container.limited.unwrap_or(false);
                if container.ack_token.is_some() {
                    to_device_ack_token = container.ack_token;
                }
                if container.next_cursor.is_some() {
                    to_device_next_cursor = container.next_cursor;
                }
                for message in container.messages {
                    self.to_device.push_back(message.clone());
                    to_device.push(message);
                }
            }
            if let Some(changes) = frame.device_lists {
                changed_device_lists.extend(changes.changed.iter().cloned());
                left_device_lists.extend(changes.left.iter().cloned());
                self.changed_device_lists.extend(changes.changed);
                self.left_device_lists.extend(changes.left);
            }
            if let Some(container) = frame.presence {
                for event in container.events {
                    if !self.verify_presence(&event, now, resolver) {
                        continue;
                    }
                    self.presence
                        .entry(event.actor_id.clone())
                        .or_default()
                        .insert(event.device_id.clone(), event.clone());
                    presence.push(event);
                }
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
                        NotificationDeltaAction::Add | NotificationDeltaAction::Update => {
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
            partial |= frame.partial.unwrap_or(false);
        }

        if to_device_lost {
            self.pending_recovery_actions
                .extend(SyncRecoveryAction::to_device_loss_actions());
        }

        Ok(SyncUpdates {
            realm_updates,
            malformed_realms,
            to_device,
            to_device_ack_token,
            to_device_limited,
            to_device_next_cursor,
            to_device_lost,
            device_lists: AccountSubscribeDeviceListChanges {
                changed: changed_device_lists.into_iter().collect(),
                left: left_device_lists.into_iter().collect(),
            },
            presence,
            account_data,
            notifications,
            partial,
        })
    }

    pub fn realm(&self, realm_id: &RealmId) -> Option<&ProcessedRealm> {
        self.realms.get(realm_id)
    }

    pub fn drain_to_device(&mut self) -> Vec<DeviceMessageEnvelope> {
        self.to_device.drain(..).collect()
    }

    pub fn acknowledge_to_device(
        &mut self,
        message_id: impl Into<String>,
        device_id: DeviceId,
        status: ToDeviceAckStatus,
    ) -> ToDeviceAck {
        let message_id = message_id.into();
        let ack = ToDeviceAck {
            message_id: message_id.clone(),
            device_id,
            status,
            acknowledged_at: Utc::now(),
        };
        self.to_device_acks.insert(message_id, ack.clone());
        ack
    }

    pub fn to_device_ack(&self, message_id: &str) -> Option<&ToDeviceAck> {
        self.to_device_acks.get(message_id)
    }

    pub fn limited_timelines(&self) -> Vec<&LimitedTimelineState> {
        self.limited_timelines.values().collect()
    }

    pub fn last_token(&self) -> Option<&str> {
        self.last_token.as_deref()
    }

    /// Return all currently cached, authenticated per-device broadcasts for
    /// an actor in deterministic device-id order.
    pub fn presence(&self, actor_id: &Did) -> Vec<&EphemeralEnvelope> {
        self.presence
            .get(actor_id)
            .map(|devices| devices.values().collect())
            .unwrap_or_default()
    }

    /// Aggregate the authenticated per-device presence states using the
    /// canonical protocol priority (`dnd > online > idle > offline`).
    pub fn aggregated_presence(&self, actor_id: &Did) -> PresenceStatus {
        aggregate_presence_states(
            self.presence(actor_id)
                .into_iter()
                .filter_map(presence_state),
        )
    }

    /// Drop cached broadcasts at or past their authoritative expiry.
    pub fn expire_presence(&mut self, now: DateTime<Utc>) -> usize {
        let before = self.presence.values().map(BTreeMap::len).sum::<usize>();
        self.presence.retain(|_, devices| {
            devices.retain(|_, event| event.expires_at > now);
            !devices.is_empty()
        });
        before - self.presence.values().map(BTreeMap::len).sum::<usize>()
    }

    pub fn account_data(&self, key: &str) -> Option<&Event> {
        self.account_data.get(key)
    }

    pub fn notification(&self, id: &str) -> Option<&NotificationDelta> {
        self.notifications.get(id)
    }

    pub fn device_lists(&self) -> AccountSubscribeDeviceListChanges {
        AccountSubscribeDeviceListChanges {
            changed: self.changed_device_lists.iter().cloned().collect(),
            left: self.left_device_lists.iter().cloned().collect(),
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

    fn verify_presence(
        &self,
        event: &EphemeralEnvelope,
        now: DateTime<Utc>,
        resolver: Option<&dyn EphemeralDeviceKeyResolver>,
    ) -> bool {
        if event.kind != "ak.presence"
            || event.expires_at <= now
            || event.validate().is_err()
            || presence_state(event).is_none()
        {
            return false;
        }
        let Some(public_key) = resolver.and_then(|resolver| {
            resolver.resolve_active_device_key(&event.actor_id, &event.device_id)
        }) else {
            return false;
        };
        verify_eddsa_detached_jws_ephemeral_proof(event, &public_key).is_ok()
    }
}

fn presence_state(event: &EphemeralEnvelope) -> Option<PresenceStatus> {
    let state = PresenceStatus::parse_wire(event.payload.get("state")?.as_str()?)?;
    if event
        .payload
        .get("last_active_at")
        .and_then(Value::as_str)
        .is_some_and(|value| validate_last_active_at(value).is_err())
    {
        return None;
    }
    if event
        .payload
        .get("status_message")
        .and_then(Value::as_str)
        .is_some_and(|value| validate_status_message(value).is_err())
    {
        return None;
    }
    Some(state)
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
    pub pending_gap: Option<arkret_core::sync::SyncGap>,
}
