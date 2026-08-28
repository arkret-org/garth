use crate::protocol::SyncUpdates;

use crate::{AccountUpdateContext, ClientEvent};

/// Fan an account-subscribe step's [`SyncUpdates`] into the ordered
/// [`ClientEvent`] batch a host consumes: non-repeated batch context first,
/// then the granular realm / to-device / notification deltas.
pub fn account_updates_to_events(updates: SyncUpdates) -> Vec<ClientEvent> {
    account_updates_to_events_with_origin(updates, false)
}

pub(crate) fn account_updates_to_events_with_origin(
    updates: SyncUpdates,
    initial_catchup: bool,
) -> Vec<ClientEvent> {
    let SyncUpdates {
        realm_updates,
        malformed_realm_ids: malformed_realms,
        to_device,
        to_device_ack_token,
        to_device_limited,
        to_device_next_cursor,
        to_device_lost,
        device_lists,
        account_data,
        notifications,
        agent_signer_evidence,
        partial,
    } = updates;
    let mut batch = vec![ClientEvent::AccountUpdates(AccountUpdateContext {
        initial_catchup,
        malformed_realms,
        to_device_ack_token,
        to_device_limited,
        to_device_next_cursor,
        to_device_lost,
        device_lists,
        account_data,
        agent_signer_evidence,
        partial,
    })];

    for update in realm_updates {
        batch.push(ClientEvent::RealmDelta {
            realm_id: update.realm_id.clone(),
            update,
        });
    }
    for message in to_device {
        batch.push(ClientEvent::ToDevice(message));
    }
    for notification in notifications {
        batch.push(ClientEvent::Notification(notification));
    }
    batch
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use crate::protocol::{
        AccountSubscribeDeviceListChanges, NotificationDelta, NotificationDeltaAction,
        NotificationId, RealmId, RealmSyncEntry, RealmUpdate, SyncUpdates,
    };

    use super::*;

    fn updates() -> SyncUpdates {
        SyncUpdates {
            realm_updates: vec![RealmUpdate {
                realm_id: RealmId::new("ak:realm:AfF-hFqRoMbajXkPapH-xaq0xwK-UKt2ph2zTs9JZRAO")
                    .unwrap(),
                entry: RealmSyncEntry::default(),
            }],
            malformed_realm_ids: Vec::new(),
            to_device: Vec::new(),
            to_device_ack_token: None,
            to_device_limited: false,
            to_device_next_cursor: None,
            to_device_lost: false,
            device_lists: AccountSubscribeDeviceListChanges {
                changed_ids: Vec::new(),
                left_ids: Vec::new(),
            },
            account_data: Vec::new(),
            notifications: vec![NotificationDelta {
                id: NotificationId::new("ak:notification:01964137-0000-7000-8000-000000000010")
                    .unwrap(),
                action: NotificationDeltaAction::Remove,
                data: None,
            }],
            agent_signer_evidence: Vec::new(),
            partial: false,
        }
    }

    #[test]
    fn account_update_fanout_emits_context_and_each_granular_event_once() {
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
        let events = account_updates_to_events(updates());
        let ClientEvent::AccountUpdates(context) = &events[0] else {
            panic!("first event must carry account batch context");
        };
        assert!(context.account_data.is_empty());
        assert!(!context.initial_catchup);
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event, ClientEvent::RealmDelta { .. }))
                .count(),
            1
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event, ClientEvent::Notification(_)))
                .count(),
            1
        );
    }

    #[test]
    fn account_update_fanout_preserves_initial_catchup_origin() {
        let events = account_updates_to_events_with_origin(updates(), true);
        let ClientEvent::AccountUpdates(context) = &events[0] else {
            panic!("first event must carry account batch context");
        };
        assert!(context.initial_catchup);
    }
}
