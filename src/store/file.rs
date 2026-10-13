//! Native durable state shared safely by independent client handles.

use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use arkret_wire::EventId;

use super::{
    AccountCursorCheckpoint, CursorScope, CursorStore, DEFAULT_SEEN_EVENTS_CAPACITY,
    DeliveryErrorClass, DeliveryId, DurableInboxStore, EventCacheStore, MAX_DELIVERY_ERROR_BYTES,
    MAX_PENDING_DELIVERIES, MAX_PENDING_READ, OpaqueCursor, PendingDelivery, StoreState,
};
use crate::{Error, Result};

/// Native JSON store for cursors, recent committed Event identities and stamp floors.
///
/// Each operation takes a sidecar OS lock and reloads the file. Separate
/// `FileStore` instances therefore cannot overwrite one another with stale
/// in-memory snapshots.
#[derive(Clone, Debug)]
pub struct FileStore {
    path: Arc<PathBuf>,
    seen_capacity: usize,
}

impl FileStore {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self> {
        Self::open_with_seen_capacity(path, DEFAULT_SEEN_EVENTS_CAPACITY)
    }

    pub fn open_with_seen_capacity(path: impl Into<PathBuf>, seen_capacity: usize) -> Result<Self> {
        let store = Self {
            path: Arc::new(path.into()),
            seen_capacity: seen_capacity.max(1),
        };
        let _guard = acquire_store_lock(&store.path)?;
        let mut state = load_state(&store.path)?;
        let changed = trim_seen_events(&mut state, store.seen_capacity);
        if changed {
            persist(&store.path, &state)?;
        }
        Ok(store)
    }

    fn read<T>(&self, read: impl FnOnce(&StoreState) -> T) -> Result<T> {
        let _guard = acquire_store_lock(&self.path)?;
        let state = load_state(&self.path)?;
        Ok(read(&state))
    }

    /// Enumerate retained local checkpoints. A cursor is continuity state,
    /// never authorization to fetch or consume its stream.
    pub fn cursor_scopes(&self) -> Result<Vec<CursorScope>> {
        self.read(|state| state.cursors.keys().cloned().collect())
    }

    /// Read due heads after selecting the first unacknowledged delivery of
    /// each exact cursor scope. A deferred head never exposes its successor.
    /// Filtering before the read bound prevents another scope's backlog from
    /// hiding an independently ready delivery outside the legacy pending window.
    pub fn ready_inbox_heads(
        &self,
        now_ms: i64,
        blocked_scopes: &BTreeSet<CursorScope>,
        limit: usize,
    ) -> Result<Vec<PendingDelivery<Vec<crate::ClientEvent>>>> {
        self.read(|state| {
            let mut observed = BTreeSet::new();
            state
                .inbox
                .values()
                .filter(|delivery| observed.insert(delivery.scope.clone()))
                .filter(|delivery| !blocked_scopes.contains(&delivery.scope))
                .filter(|delivery| delivery.next_attempt_at_ms.is_none_or(|at| at <= now_ms))
                .take(limit.clamp(1, MAX_PENDING_READ))
                .cloned()
                .collect()
        })
    }

    /// Pending scope identity is local scheduling state, never authorization.
    /// Recovery of another scope need not wait for these deliveries to ACK.
    pub fn pending_cursor_scopes(&self) -> Result<BTreeSet<CursorScope>> {
        self.read(|state| {
            state
                .inbox
                .values()
                .map(|delivery| delivery.scope.clone())
                .collect()
        })
    }

    fn mutate<T>(&self, mutation: impl FnOnce(&mut StoreState) -> Result<(T, bool)>) -> Result<T> {
        let _guard = acquire_store_lock(&self.path)?;
        let mut state = load_state(&self.path)?;
        let trimmed = trim_seen_events(&mut state, self.seen_capacity);
        let (value, changed) = mutation(&mut state)?;
        if trimmed || changed {
            persist(&self.path, &state)?;
        }
        Ok(value)
    }

    /// Persist one projected account batch and its cursor checkpoint under one
    /// file lock and one atomic replace. A replay of the same cursor does not
    /// append a second delivery.
    pub fn commit_account_batch(
        &self,
        scope: CursorScope,
        checkpoint: AccountCursorCheckpoint,
        events: Vec<crate::ClientEvent>,
    ) -> Result<()> {
        crate::projection::validate_client_event_payloads(&events)?;
        self.mutate(|state| {
            if state.account_checkpoints.get(&scope) == Some(&checkpoint) {
                return Ok(((), false));
            }
            if !events.is_empty() {
                if state.inbox.len() >= MAX_PENDING_DELIVERIES {
                    return Err(Error::Storage("durable account inbox is full".to_owned()));
                }
                let id = next_inbox_id(state)?;
                state.inbox.insert(
                    id,
                    PendingDelivery {
                        id,
                        scope: scope.clone(),
                        cursor: Some(checkpoint.cursor.clone()),
                        payload: events,
                        attempts: 0,
                        next_attempt_at_ms: None,
                        error_class: None,
                        last_error: None,
                    },
                );
            }
            state
                .cursors
                .insert(scope.clone(), checkpoint.cursor.clone());
            state.account_checkpoints.insert(scope, checkpoint);
            Ok(((), true))
        })
    }

    pub fn has_active_outbound(&self) -> Result<bool> {
        self.read(|state| {
            state
                .outbound
                .items
                .iter()
                .any(|item| !item.status.is_terminal())
        })
    }

    /// Advance and durably commit an HLC floor under the cross-process lock
    /// for synchronous local authoring paths.
    pub fn advance_floor_sync(
        &self,
        scope: crate::StampScope,
        update: crate::StampFloorUpdate,
    ) -> Result<crate::StampFloor> {
        self.mutate(|state| {
            let next = state
                .stamp_floors
                .get(&scope)
                .copied()
                .unwrap_or_default()
                .apply(update)?;
            let changed = state.stamp_floors.get(&scope).copied() != Some(next);
            state.stamp_floors.insert(scope, next);
            Ok((next, changed))
        })
    }
}

fn next_inbox_id(state: &mut StoreState) -> Result<DeliveryId> {
    let next = state.inbox_next_id.max(1);
    let id = DeliveryId::from_stored_u64(next)?;
    state.inbox_next_id = next
        .checked_add(1)
        .ok_or_else(|| Error::Storage("durable account inbox id overflow".to_owned()))?;
    Ok(id)
}

impl DurableInboxStore<Vec<crate::ClientEvent>> for FileStore {
    async fn commit(
        &self,
        scope: CursorScope,
        cursor: Option<OpaqueCursor>,
        payload: Vec<crate::ClientEvent>,
    ) -> Result<DeliveryId> {
        crate::projection::validate_client_event_payloads(&payload)?;
        self.mutate(|state| {
            if state.inbox.len() >= MAX_PENDING_DELIVERIES {
                return Err(Error::Storage("durable account inbox is full".to_owned()));
            }
            let id = next_inbox_id(state)?;
            if let Some(ref value) = cursor {
                state.cursors.insert(scope.clone(), value.clone());
            }
            state.inbox.insert(
                id,
                PendingDelivery {
                    id,
                    scope,
                    cursor,
                    payload,
                    attempts: 0,
                    next_attempt_at_ms: None,
                    error_class: None,
                    last_error: None,
                },
            );
            Ok((id, true))
        })
    }

    async fn pending(&self, limit: usize) -> Result<Vec<PendingDelivery<Vec<crate::ClientEvent>>>> {
        self.read(|state| {
            state
                .inbox
                .values()
                .take(limit.clamp(1, MAX_PENDING_READ))
                .cloned()
                .collect()
        })
    }

    async fn ack(&self, id: DeliveryId) -> Result<bool> {
        self.mutate(|state| {
            let removed = state.inbox.remove(&id).is_some();
            Ok((removed, removed))
        })
    }

    async fn retry(
        &self,
        id: DeliveryId,
        next_attempt_at_ms: Option<i64>,
        error_class: DeliveryErrorClass,
        mut error: String,
    ) -> Result<bool> {
        error.truncate(error.floor_char_boundary(MAX_DELIVERY_ERROR_BYTES));
        self.mutate(|state| {
            let Some(delivery) = state.inbox.get_mut(&id) else {
                return Ok((false, false));
            };
            delivery.attempts = delivery.attempts.saturating_add(1);
            delivery.next_attempt_at_ms = next_attempt_at_ms;
            delivery.error_class = Some(error_class);
            delivery.last_error = Some(error);
            Ok((true, true))
        })
    }
}

impl CursorStore for FileStore {
    async fn load(&self, scope: CursorScope) -> Result<Option<OpaqueCursor>> {
        self.read(|state| state.cursors.get(&scope).cloned())
    }

    async fn save(&self, scope: CursorScope, cursor: OpaqueCursor) -> Result<()> {
        self.mutate(|state| {
            let checkpoint_removed = state.account_checkpoints.remove(&scope).is_some();
            if state.cursors.get(&scope) == Some(&cursor) && !checkpoint_removed {
                Ok(((), false))
            } else {
                state.cursors.insert(scope, cursor);
                Ok(((), true))
            }
        })
    }

    async fn clear(&self, scope: CursorScope) -> Result<()> {
        self.mutate(|state| {
            let cursor = state.cursors.remove(&scope).is_some();
            let checkpoint = state.account_checkpoints.remove(&scope).is_some();
            Ok(((), cursor || checkpoint))
        })
    }

    async fn load_account_checkpoint(
        &self,
        scope: CursorScope,
    ) -> Result<Option<AccountCursorCheckpoint>> {
        self.read(|state| state.account_checkpoints.get(&scope).cloned())
    }

    async fn save_account_checkpoint(
        &self,
        scope: CursorScope,
        checkpoint: AccountCursorCheckpoint,
    ) -> Result<()> {
        self.mutate(|state| {
            let changed = state.cursors.get(&scope) != Some(&checkpoint.cursor)
                || state.account_checkpoints.get(&scope) != Some(&checkpoint);
            state
                .cursors
                .insert(scope.clone(), checkpoint.cursor.clone());
            state.account_checkpoints.insert(scope, checkpoint);
            Ok(((), changed))
        })
    }
}

impl EventCacheStore for FileStore {
    async fn seen(&self, event_id: EventId) -> Result<bool> {
        self.read(|state| state.committed_events.contains(&event_id))
    }

    async fn remember(&self, event_id: EventId) -> Result<()> {
        self.mutate(|state| {
            if state.committed_events.contains(&event_id) {
                return Ok(((), false));
            }
            state.committed_events.push_back(event_id);
            trim_seen_events(state, self.seen_capacity);
            Ok(((), true))
        })
    }
}

impl crate::OutboundQueueStore for FileStore {
    fn mutate_outbound<'a, R>(
        &'a self,
        mutation: impl FnOnce(&mut crate::SendQueue) -> Result<R> + crate::MaybeSend + 'a,
    ) -> crate::outbound::BoxOutboundFuture<'a, R>
    where
        R: crate::MaybeSend + 'a,
    {
        Box::pin(async move {
            self.mutate(|state| {
                let mut queue =
                    crate::SendQueue::from_snapshot(std::mem::take(&mut state.outbound));
                let value = mutation(&mut queue)?;
                for item in queue.items() {
                    item.submission.validate_queued_request()?;
                }
                state.outbound = queue.snapshot();
                Ok((value, true))
            })
        })
    }
}

impl crate::MonotonicStampStore for FileStore {
    async fn load_floor(&self, scope: crate::StampScope) -> Result<Option<crate::StampFloor>> {
        self.read(|state| state.stamp_floors.get(&scope).copied())
    }

    async fn advance_floor(
        &self,
        scope: crate::StampScope,
        update: crate::StampFloorUpdate,
    ) -> Result<crate::StampFloor> {
        self.advance_floor_sync(scope, update)
    }
}

fn trim_seen_events(state: &mut StoreState, capacity: usize) -> bool {
    let mut changed = false;
    while state.committed_events.len() > capacity {
        state.committed_events.pop_front();
        changed = true;
    }
    changed
}

fn lock_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".lock");
    PathBuf::from(name)
}

fn acquire_store_lock(path: &Path) -> Result<File> {
    let lock_path = lock_path(path);
    if let Some(parent) = lock_path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .map_err(|error| Error::Storage(format!("create {}: {error}", parent.display())))?;
    }
    let lock = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(|error| Error::Storage(format!("open {}: {error}", lock_path.display())))?;
    lock.lock()
        .map_err(|error| Error::Storage(format!("lock {}: {error}", lock_path.display())))?;
    Ok(lock)
}

fn load_state(path: &Path) -> Result<StoreState> {
    if !path.exists() {
        return Ok(StoreState::default());
    }
    let bytes = std::fs::read(path)
        .map_err(|error| Error::Storage(format!("read {}: {error}", path.display())))?;
    if bytes.is_empty() {
        return Ok(StoreState::default());
    }
    serde_json::from_slice(&bytes).map_err(Error::CanonicalJson)
}

fn persist(path: &Path, state: &StoreState) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .map_err(|error| Error::Storage(format!("create {}: {error}", parent.display())))?;
    }
    let bytes = serde_json::to_vec(state)?;
    let temporary_path = path.with_extension("garth-tmp");
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&temporary_path)
        .map_err(|error| Error::Storage(format!("open {}: {error}", temporary_path.display())))?;
    file.write_all(&bytes)
        .map_err(|error| Error::Storage(format!("write {}: {error}", path.display())))?;
    file.sync_all()
        .map_err(|error| Error::Storage(format!("sync {}: {error}", temporary_path.display())))?;
    drop(file);
    std::fs::rename(&temporary_path, path).map_err(|error| {
        Error::Storage(format!(
            "replace {} from {}: {error}",
            path.display(),
            temporary_path.display()
        ))
    })
}

#[cfg(test)]
mod inbox_tests {
    use arkret_wire::{AccountId, ActorId, DeviceId, DidCoreId};

    use super::*;

    fn scope() -> CursorScope {
        let principal = DidCoreId::new("ak:did_core:web:agent.example").unwrap();
        let station = DidCoreId::new("ak:did_core:web:station.example").unwrap();
        CursorScope::Account {
            service_id: Some(station.clone()),
            actor_id: ActorId::account(AccountId::new(principal, station)),
            device_id: DeviceId::new("ak:device:01964139-0000-7000-8000-000000000001").unwrap(),
        }
    }

    #[tokio::test]
    async fn account_batch_and_cursor_survive_reopen_without_replay_duplication() {
        let home = tempfile::tempdir().unwrap();
        let path = home.path().join("account.json");
        let checkpoint = AccountCursorCheckpoint {
            cursor: "cursor-one".to_owned(),
            station_cas: crate::StationCasProjection::default(),
        };
        let batch = vec![crate::ClientEvent::AccountUpdates(Default::default())];
        FileStore::open(&path)
            .unwrap()
            .commit_account_batch(scope(), checkpoint.clone(), batch)
            .unwrap();

        let reopened = FileStore::open(&path).unwrap();
        assert_eq!(reopened.cursor_scopes().unwrap(), vec![scope()]);
        assert_eq!(
            reopened.load_account_checkpoint(scope()).await.unwrap(),
            Some(checkpoint.clone())
        );
        let pending = reopened.pending(32).await.unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].payload.len(), 1);

        reopened
            .commit_account_batch(
                scope(),
                checkpoint,
                vec![crate::ClientEvent::AccountUpdates(Default::default())],
            )
            .unwrap();
        assert_eq!(reopened.pending(32).await.unwrap().len(), 1);
        assert!(reopened.ack(pending[0].id).await.unwrap());
        assert!(
            FileStore::open(&path)
                .unwrap()
                .pending(32)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn ready_heads_preserve_account_batch_payload_and_aggregate_retry() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("aggregate-head.json");
        let store = FileStore::open(&path).unwrap();
        let payload = vec![
            crate::ClientEvent::AccountUpdates(Default::default()),
            crate::ClientEvent::AccountUpdates(Default::default()),
        ];
        store
            .commit_account_batch(
                scope(),
                AccountCursorCheckpoint {
                    cursor: "aggregate-cut".to_owned(),
                    station_cas: crate::StationCasProjection::default(),
                },
                payload,
            )
            .unwrap();
        let head = store.ready_inbox_heads(1000, &BTreeSet::new(), 32).unwrap();
        assert_eq!(head.len(), 1);
        assert_eq!(head[0].scope, scope());
        assert_eq!(head[0].payload.len(), 2);
        store
            .retry(
                head[0].id,
                Some(2000),
                DeliveryErrorClass::Processing,
                "aggregate item remains unresolved".to_owned(),
            )
            .await
            .unwrap();
        let reopened = FileStore::open(&path).unwrap();
        assert!(
            reopened
                .ready_inbox_heads(1000, &BTreeSet::new(), 32)
                .unwrap()
                .is_empty()
        );
        let retried = reopened
            .ready_inbox_heads(2000, &BTreeSet::new(), 32)
            .unwrap();
        assert_eq!(retried.len(), 1);
        assert_eq!(retried[0].id, head[0].id);
        assert_eq!(retried[0].scope, scope());
        assert_eq!(retried[0].payload.len(), 2);
        assert_eq!(retried[0].cursor.as_deref(), Some("aggregate-cut"));
        assert_eq!(retried[0].attempts, 1);
    }

    #[tokio::test]
    async fn ready_heads_reach_private_scope_beyond_pending_window_without_overtaking_retry() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("scope-heads.json");
        let store = FileStore::open(&path).unwrap();
        let realm = arkret_wire::RealmId::from_event_id(&EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [11; 32],
        ));
        let shared = CursorScope::CommitStream {
            service_id: None,
            stream_ref: arkret_wire::CommitStreamRef::Realm {
                realm_id: realm.clone(),
            },
        };
        let private = CursorScope::CommitStream {
            service_id: None,
            stream_ref: arkret_wire::CommitStreamRef::Sidecar {
                realm_id: realm,
                sidecar_id: arkret_wire::SidecarId::from_event_id(&EventId::from_digest(
                    arkret_canonical::DigestSuite::Sha256,
                    [12; 32],
                )),
            },
        };
        let payload = vec![crate::ClientEvent::AccountUpdates(Default::default())];
        let (shared_head, private_head) = store
            .mutate(|state| {
                let mut shared_head = None;
                for index in 0..=MAX_PENDING_READ {
                    let id = next_inbox_id(state)?;
                    shared_head.get_or_insert(id);
                    state.inbox.insert(
                        id,
                        PendingDelivery {
                            id,
                            scope: shared.clone(),
                            cursor: Some(format!("shared-{index}")),
                            payload: payload.clone(),
                            attempts: 0,
                            next_attempt_at_ms: (index == 0).then_some(5000),
                            error_class: None,
                            last_error: None,
                        },
                    );
                }
                let id = next_inbox_id(state)?;
                state.inbox.insert(
                    id,
                    PendingDelivery {
                        id,
                        scope: private.clone(),
                        cursor: Some("private-cut".to_owned()),
                        payload: payload.clone(),
                        attempts: 0,
                        next_attempt_at_ms: None,
                        error_class: None,
                        last_error: None,
                    },
                );
                Ok(((shared_head.unwrap(), id), true))
            })
            .unwrap();
        let reopened = FileStore::open(&path).unwrap();
        assert!(
            reopened
                .pending(MAX_PENDING_READ)
                .await
                .unwrap()
                .iter()
                .all(|delivery| delivery.scope == shared)
        );
        let ready = reopened
            .ready_inbox_heads(1000, &BTreeSet::new(), 1)
            .unwrap();
        assert_eq!(
            ready.iter().map(|delivery| delivery.id).collect::<Vec<_>>(),
            vec![private_head]
        );
        assert_eq!(ready[0].cursor.as_deref(), Some("private-cut"));
        assert_eq!(
            reopened.pending_cursor_scopes().unwrap(),
            BTreeSet::from([shared.clone(), private.clone()])
        );
        assert!(
            reopened
                .ready_inbox_heads(1000, &BTreeSet::from([private.clone()]), 32)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            reopened
                .ready_inbox_heads(5000, &BTreeSet::new(), 1)
                .unwrap()[0]
                .id,
            shared_head
        );
        reopened
            .retry(
                shared_head,
                Some(8000),
                DeliveryErrorClass::Processing,
                "unknown current cut".to_owned(),
            )
            .await
            .unwrap();
        assert_eq!(
            reopened
                .ready_inbox_heads(5000, &BTreeSet::new(), 1)
                .unwrap()[0]
                .id,
            private_head
        );
        reopened.ack(private_head).await.unwrap();
        assert!(
            reopened
                .ready_inbox_heads(5000, &BTreeSet::new(), 32)
                .unwrap()
                .is_empty()
        );
        assert_eq!(reopened.pending(1).await.unwrap()[0].id, shared_head);
        reopened.ack(shared_head).await.unwrap();
        assert!(
            reopened
                .ready_inbox_heads(5000, &BTreeSet::new(), 1)
                .unwrap()[0]
                .id
                > shared_head
        );
    }

    #[tokio::test]
    async fn agent_delivery_cursor_reopens_and_is_fenced_by_current_key_authorization() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("agent.json");
        let actor_id = ActorId::account(AccountId::new(
            DidCoreId::new("ak:did_core:web:agent.example").unwrap(),
            DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        ));
        let scope = CursorScope::AgentDeliveries {
            service_id: Some(DidCoreId::new("ak:did_core:web:station.example").unwrap()),
            actor_id,
            verification_method: arkret_wire::DidUrl::new("did:web:agent.example#runtime").unwrap(),
            authorization_event_ref: EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                [1; 32],
            ),
        };
        FileStore::open(&path)
            .unwrap()
            .save(scope.clone(), "old-endpoint-cursor".to_owned())
            .await
            .unwrap();
        let reopened = FileStore::open(&path).unwrap();
        assert_eq!(
            reopened.load(scope.clone()).await.unwrap().as_deref(),
            Some("old-endpoint-cursor")
        );
        let mut rotated = scope;
        let CursorScope::AgentDeliveries {
            authorization_event_ref,
            ..
        } = &mut rotated
        else {
            unreachable!()
        };
        *authorization_event_ref =
            EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [2; 32]);
        assert_eq!(reopened.load(rotated).await.unwrap(), None);
    }
}
