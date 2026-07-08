use cokret_core::SyncUpdates;

use crate::{ClientEvent, ClientEventSink};

pub fn emit_account_updates<S>(sink: &S, updates: SyncUpdates)
where
    S: ClientEventSink + ?Sized,
{
    sink.emit(ClientEvent::AccountUpdates(updates.clone()));

    for update in updates.realm_updates {
        sink.emit(ClientEvent::RealmDelta {
            realm_id: update.realm_id.clone(),
            update,
        });
    }
    for message in updates.to_device {
        sink.emit(ClientEvent::ToDevice(message));
    }
    for notification in updates.notifications {
        sink.emit(ClientEvent::Notification(notification));
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use cokret_core::{DeviceListChanges, NotificationDelta, RealmId, RealmUpdate, SyncUpdates};
    use serde_json::Value;

    use super::*;

    fn updates() -> SyncUpdates {
        SyncUpdates {
            realm_updates: vec![RealmUpdate {
                realm_id: RealmId::new("ck:realm:01904100-0000-7000-8000-000000000001").unwrap(),
                timeline: None,
                state: Vec::new(),
                summary: Value::Null,
            }],
            malformed_realms: Vec::new(),
            to_device: Vec::new(),
            to_device_ack_token: None,
            to_device_limited: false,
            to_device_next_cursor: None,
            to_device_lost: false,
            device_lists: DeviceListChanges::default(),
            presence: Vec::new(),
            account_data: Vec::new(),
            notifications: vec![NotificationDelta {
                id: "n1".to_owned(),
                notification_type: "mention".to_owned(),
                action: "add".to_owned(),
                data: None,
            }],
            partial: false,
        }
    }

    #[test]
    fn account_update_fanout_emits_raw_and_granular_events() {
        let kinds = Arc::new(Mutex::new(Vec::new()));
        let kinds_for_sink = Arc::clone(&kinds);
        let sink = move |event: ClientEvent| {
            let kind = match event {
                ClientEvent::AccountUpdates(_) => "account",
                ClientEvent::RealmDelta { .. } => "realm",
                ClientEvent::Notification(_) => "notification",
                _ => "other",
            };
            kinds_for_sink.lock().unwrap().push(kind);
        };

        emit_account_updates(&sink, updates());

        assert_eq!(
            kinds.lock().unwrap().as_slice(),
            &["account", "realm", "notification"]
        );
    }
}
