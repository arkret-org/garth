use arkret_core::SyncUpdates;

use crate::ClientEvent;

/// Fan an account-subscribe step's [`SyncUpdates`] into the ordered
/// [`ClientEvent`] batch a host consumes: the whole `AccountUpdates` first
/// (carries batch context — to-device ack token, `partial`, presence, account
/// data), then the granular realm / to-device / notification deltas.
pub fn account_updates_to_events(updates: SyncUpdates) -> Vec<ClientEvent> {
    let mut batch = Vec::new();
    batch.push(ClientEvent::AccountUpdates(updates.clone()));

    for update in updates.realm_updates {
        batch.push(ClientEvent::RealmDelta {
            realm_id: update.realm_id.clone(),
            update,
        });
    }
    for message in updates.to_device {
        batch.push(ClientEvent::ToDevice(message));
    }
    for notification in updates.notifications {
        batch.push(ClientEvent::Notification(notification));
    }
    batch
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use arkret_core::{
        AccountSubscribeDeviceListChanges, NotificationDelta, NotificationDeltaAction,
        NotificationId, NotificationType, RealmId, RealmSyncEntry, RealmUpdate, SyncUpdates,
    };

    use super::*;

    fn updates() -> SyncUpdates {
        SyncUpdates {
            realm_updates: vec![RealmUpdate {
                realm_id: RealmId::new("ak:realm:01904100-0000-7000-8000-000000000001").unwrap(),
                entry: RealmSyncEntry::default(),
            }],
            malformed_realms: Vec::new(),
            to_device: Vec::new(),
            to_device_ack_token: None,
            to_device_limited: false,
            to_device_next_cursor: None,
            to_device_lost: false,
            device_lists: AccountSubscribeDeviceListChanges {
                changed: Vec::new(),
                left: Vec::new(),
            },
            presence: Vec::new(),
            account_data: Vec::new(),
            notifications: vec![NotificationDelta {
                id: NotificationId::new("ak:notification:01964137-0000-7000-8000-000000000010")
                    .unwrap(),
                notification_type: NotificationType::Agent,
                action: NotificationDeltaAction::Remove,
                data: None,
            }],
            partial: false,
        }
    }

    #[test]
    fn account_update_fanout_emits_raw_and_granular_events() {
        let kinds = Arc::new(Mutex::new(Vec::new()));
        for event in account_updates_to_events(updates()) {
            let kind = match event {
                ClientEvent::AccountUpdates(_) => "account",
                ClientEvent::RealmDelta { .. } => "realm",
                ClientEvent::Notification(_) => "notification",
                _ => "other",
            };
            kinds.lock().unwrap().push(kind);
        }

        assert_eq!(
            kinds.lock().unwrap().as_slice(),
            &["account", "realm", "notification"]
        );
    }
}
