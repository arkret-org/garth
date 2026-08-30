use super::*;
use crate::QueuedRecord;

/// Send queue item lifecycle.
///
/// The receipted / un-receipted boundary is the one that matters for a bounded
/// offline write (`offline-publication.md` §2): before [`Self::Sent`] the
/// Event has no [`IngressReceipt`] and may only be first-published while its
/// [`AuthorizationLease`] is still valid; from [`Self::Sent`] on, the same
/// digest may be cached, retransmitted and federated with no further deadline.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SendQueueStatus {
    /// Waiting for connectivity or dependencies. Not receipted.
    Queued,
    /// Currently being sent. Not receipted.
    Sending,
    /// A policy-accepted ingress receipted the Event. Awaiting propagation.
    Sent,
    /// Send failed and may be retried after `next_retry_at`. Not receipted.
    Failed,
    /// User or dependency cancellation.
    Cancelled,
    /// Replaced by a newly-authored immutable attempt for the same local
    /// operation after an explicit `accepted=false` CAS response.
    Superseded,
    /// The bound authorization lease expired before any ingress receipted the
    /// Event. `offline-publication.md` §2 makes this permanent: an Event that
    /// first appears after its lease expired without a qualifying receipt is
    /// rejected forever, so the item is retired instead of retried.
    LeaseExpired,
}

/// Local echo projected before a queued item is sent.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalEcho {
    /// Idempotent transaction ID.
    pub transaction_id: String,
    /// Stable local item ID for UI reconciliation.
    pub item_id: String,
    /// Realm receiving the item.
    pub realm_id: RealmId,
    /// Local creation time.
    pub created_at: DateTime<Utc>,
    /// Current queue status.
    pub status: SendQueueStatus,
}

/// One queued outbound event.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SendQueueItem {
    /// Idempotent transaction ID.
    pub transaction_id: String,
    /// Stable host operation identity shared by semantic replacements.
    pub local_operation_id: String,
    /// Previous immutable attempt replaced by this item, when any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supersedes_transaction_id: Option<String>,
    /// Target Realm.
    pub realm_id: RealmId,
    /// Actor partition for ordinary Event authoring. Generic non-Event queue
    /// items leave this unset.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<ActorId>,
    /// Self-describing, strongly typed queue record.
    pub record: QueuedRecord,
    /// Canonical hash of the idempotent payload.
    pub payload_digest: String,
    /// Exact canonical payload persisted for deterministic transport replay.
    pub canonical_payload_bytes: Vec<u8>,
    /// Other transaction IDs that must be sent first.
    pub depends_on: Vec<String>,
    /// Lifecycle status.
    pub status: SendQueueStatus,
    /// Number of send attempts.
    pub attempts: u32,
    /// Next retry time after a transient failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_retry_at: Option<DateTime<Utc>>,
    /// Basis-bound offline publication authorization for this attempt.
    ///
    /// It is not an Event field and never enters the Event digest
    /// (`offline-publication.md` §2.1); it is persisted here because the first
    /// submission must carry it and because its `expires_at` is the deadline
    /// past which an un-receipted item can never be published at all.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_lease: Option<AuthorizationLease>,
    /// Receipts an ingress issued for this Event, persisted verbatim.
    ///
    /// Once stored they are never replaced: an idempotent retry must return
    /// the original receipt, and re-signing it with a later `received_at`
    /// would extend a revocation window that is already fixed
    /// (`offline-publication.md` §2.1).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ingress_receipts: Vec<IngressReceipt>,
    /// Server Event identity once sent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_event_id: Option<EventId>,
    /// Queue insertion order.
    pub sequence: u64,
    /// Local enqueue time.
    pub enqueued_at: DateTime<Utc>,
    /// Last lifecycle update time.
    pub updated_at: DateTime<Utc>,
    /// Local echo for UI consumers.
    pub local_echo: LocalEcho,
}

/// Serializable send queue state.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum SendQueueSnapshotSchema {
    #[default]
    #[serde(rename = "org.arkret.garth.send_queue.v1")]
    V1,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SendQueueSnapshot {
    /// Snapshot schema. Its required presence makes the clean break from the
    /// retired `kind` + `content` format explicit and fail-closed.
    pub schema: SendQueueSnapshotSchema,
    /// Items in queue order.
    pub items: Vec<SendQueueItem>,
    /// Next insertion sequence.
    pub next_sequence: u64,
}

/// In-memory send queue with idempotent transaction semantics.
#[derive(Clone, Debug, Default)]
pub struct SendQueue {
    items: BTreeMap<String, SendQueueItem>,
    order: VecDeque<String>,
    next_sequence: u64,
}

pub const MAX_SEND_QUEUE_ITEMS: usize = 4_096;

impl SendQueue {
    /// Create an empty queue.
    pub fn new() -> Self {
        Self::default()
    }

    /// Restore a queue from a serialized snapshot.
    ///
    /// A persisted `Sending` status is stale by construction: it means the
    /// process died (or the send future was dropped) between `mark_sending`
    /// and `mark_sent` / `mark_failed`, and nothing will ever transition it
    /// again — `is_ready` does not schedule `Sending` items, so the item and
    /// its whole `depends_on` chain would be stuck forever. Restore
    /// normalizes it to `Failed` with an immediate retry; the resend is safe
    /// because submission is idempotent on `event_id` / transaction identity
    /// (operations-sync.md §events.submit dedup).
    pub fn from_snapshot(snapshot: SendQueueSnapshot) -> Result<Self> {
        if snapshot.items.len() > MAX_SEND_QUEUE_ITEMS {
            return Err(Error::Protocol(format!(
                "send queue snapshot exceeds the {MAX_SEND_QUEUE_ITEMS} item limit"
            )));
        }
        let mut queue = Self {
            next_sequence: snapshot.next_sequence,
            ..Self::default()
        };
        for mut item in snapshot.items {
            item.record.validate()?;
            validate_record_scope(&item.realm_id, &item.record)?;
            let canonical_payload_bytes = canonical::canonical_json_bytes(&item.record)?;
            if canonical_payload_bytes != item.canonical_payload_bytes {
                return Err(Error::Protocol(
                    "send queue snapshot canonical record bytes mismatch".to_owned(),
                ));
            }
            let payload_digest =
                queue_payload_digest(&item.realm_id, &item.record, &item.depends_on)?;
            if payload_digest != item.payload_digest {
                return Err(Error::Protocol(
                    "send queue snapshot record digest mismatch".to_owned(),
                ));
            }
            if item.local_echo.transaction_id != item.transaction_id
                || item.local_echo.realm_id != item.realm_id
                || item.local_echo.status != item.status
            {
                return Err(Error::Protocol(
                    "send queue snapshot local echo does not match its item".to_owned(),
                ));
            }
            if queue.items.contains_key(&item.transaction_id) {
                return Err(Error::IdempotencyConflict(item.transaction_id));
            }
            if item.status == SendQueueStatus::Sending {
                item.status = SendQueueStatus::Failed;
                item.next_retry_at = None;
                item.updated_at = Utc::now();
                item.local_echo.status = item.status;
            }
            queue.order.push_back(item.transaction_id.clone());
            queue.items.insert(item.transaction_id.clone(), item);
        }
        Ok(queue)
    }

    /// Export queue state for persistence by the embedding application.
    pub fn snapshot(&self) -> SendQueueSnapshot {
        SendQueueSnapshot {
            schema: SendQueueSnapshotSchema::V1,
            items: self
                .order
                .iter()
                .filter_map(|transaction_id| self.items.get(transaction_id).cloned())
                .collect(),
            next_sequence: self.next_sequence,
        }
    }

    /// Number of queued items in all states.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// True when the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Attach the authoring partition to a newly enqueued item.
    pub fn set_actor_scope(&mut self, transaction_id: &str, actor_id: ActorId) -> Result<()> {
        let item = self.item_mut(transaction_id)?;
        if item.record.actor_id()? != &actor_id {
            return Err(Error::Protocol(
                "send queue actor scope does not match its typed record".to_owned(),
            ));
        }
        item.actor_id = Some(actor_id);
        Ok(())
    }

    /// Atomically replace an unsigned intent payload with its first immutable
    /// signed attempt before any transport call.
    pub fn mark_prepared(
        &mut self,
        transaction_id: &str,
        record: QueuedRecord,
    ) -> Result<SendQueueItem> {
        record.validate()?;
        let existing = self.items.get(transaction_id).ok_or_else(|| {
            Error::Protocol(format!(
                "send queue transaction not found: {}",
                transaction_id
            ))
        })?;
        validate_record_scope(&existing.realm_id, &record)?;
        if existing
            .actor_id
            .as_ref()
            .is_some_and(|actor_id| record.actor_id().ok() != Some(actor_id))
        {
            return Err(Error::Protocol(
                "prepared send queue record changed its actor scope".to_owned(),
            ));
        }
        let item = self.item_mut(transaction_id)?;
        item.record = record;
        item.canonical_payload_bytes = canonical::canonical_json_bytes(&item.record)?;
        item.payload_digest = queue_payload_digest(&item.realm_id, &item.record, &item.depends_on)?;
        item.status = SendQueueStatus::Queued;
        item.next_retry_at = None;
        item.updated_at = Utc::now();
        item.local_echo.status = item.status;
        Ok(item.clone())
    }

    /// Enqueue a self-describing outbound record.
    pub fn enqueue(
        &mut self,
        transaction_id: Option<String>,
        realm_id: RealmId,
        record: QueuedRecord,
        depends_on: Vec<String>,
    ) -> Result<SendQueueItem> {
        record.validate()?;
        validate_record_scope(&realm_id, &record)?;
        let payload_digest = queue_payload_digest(&realm_id, &record, &depends_on)?;
        let transaction_id = transaction_id
            .unwrap_or_else(|| format!("txn_{}", payload_digest.trim_start_matches("sha256:")));

        if let Some(existing) = self.items.get(&transaction_id) {
            if existing.payload_digest == payload_digest {
                return Ok(existing.clone());
            }
            return Err(Error::IdempotencyConflict(transaction_id));
        }
        if self.items.len() >= MAX_SEND_QUEUE_ITEMS {
            self.prune_unreferenced_terminal();
        }
        if self.items.len() >= MAX_SEND_QUEUE_ITEMS {
            return Err(Error::Protocol(format!(
                "send queue reached the {MAX_SEND_QUEUE_ITEMS} item limit"
            )));
        }

        let now = Utc::now();
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.saturating_add(1);
        let local_echo = LocalEcho {
            transaction_id: transaction_id.clone(),
            item_id: format!("local:{}", transaction_id),
            realm_id: realm_id.clone(),
            created_at: now,
            status: SendQueueStatus::Queued,
        };
        let canonical_payload_bytes = canonical::canonical_json_bytes(&record)?;
        let item = SendQueueItem {
            transaction_id: transaction_id.clone(),
            local_operation_id: transaction_id.clone(),
            supersedes_transaction_id: None,
            realm_id,
            actor_id: None,
            record,
            payload_digest,
            canonical_payload_bytes,
            depends_on,
            status: SendQueueStatus::Queued,
            attempts: 0,
            next_retry_at: None,
            authorization_lease: None,
            ingress_receipts: Vec::new(),
            remote_event_id: None,
            sequence,
            enqueued_at: now,
            updated_at: now,
            local_echo,
        };
        self.order.push_back(transaction_id.clone());
        self.items.insert(transaction_id, item.clone());
        Ok(item)
    }

    /// Atomically retire one immutable attempt and enqueue its semantic
    /// replacement. The new transaction must carry a distinct identity and
    /// payload, while retaining the stable local operation identity.
    pub fn supersede(
        &mut self,
        transaction_id: &str,
        replacement_transaction_id: String,
        realm_id: RealmId,
        record: QueuedRecord,
        depends_on: Vec<String>,
    ) -> Result<SendQueueItem> {
        let local_operation_id = self
            .get(transaction_id)
            .ok_or_else(|| Error::Protocol("superseded queue item disappeared".to_owned()))?
            .local_operation_id
            .clone();
        let actor_id = self
            .get(transaction_id)
            .and_then(|item| item.actor_id.clone());
        let previous_sequence = self
            .get(transaction_id)
            .map(|item| item.sequence)
            .ok_or_else(|| Error::Protocol("superseded queue item disappeared".to_owned()))?;
        {
            let previous = self.item_mut(transaction_id)?;
            previous.status = SendQueueStatus::Superseded;
            previous.next_retry_at = None;
            previous.updated_at = Utc::now();
            previous.local_echo.status = previous.status;
        }
        self.enqueue(
            Some(replacement_transaction_id.clone()),
            realm_id,
            record,
            depends_on,
        )?;
        let item = self.item_mut(&replacement_transaction_id)?;
        item.local_operation_id = local_operation_id;
        item.actor_id = actor_id;
        item.supersedes_transaction_id = Some(transaction_id.to_owned());
        item.sequence = previous_sequence;
        item.local_echo.item_id = format!("local:{}", item.local_operation_id);
        Ok(item.clone())
    }

    /// Items ready to send now, in dependency-safe order.
    pub fn ready_batch(&self, now: DateTime<Utc>, limit: usize) -> Vec<SendQueueItem> {
        self.order
            .iter()
            .filter_map(|transaction_id| self.items.get(transaction_id))
            .filter(|item| self.is_ready(item, now))
            .take(limit)
            .cloned()
            .collect()
    }

    /// Get one queue item.
    pub fn get(&self, transaction_id: &str) -> Option<&SendQueueItem> {
        self.items.get(transaction_id)
    }

    /// Active items in queue order, excluding terminal history.
    pub fn active_items(&self) -> Vec<SendQueueItem> {
        self.order
            .iter()
            .filter_map(|transaction_id| self.items.get(transaction_id))
            .filter(|item| {
                matches!(
                    item.status,
                    SendQueueStatus::Queued | SendQueueStatus::Sending | SendQueueStatus::Failed
                )
            })
            .cloned()
            .collect()
    }

    /// Remove old terminal items that are not dependencies of retained work.
    pub fn prune_terminal_before(&mut self, cutoff: DateTime<Utc>) -> usize {
        let candidates = self
            .items
            .values()
            .filter(|item| {
                matches!(
                    item.status,
                    SendQueueStatus::Sent
                        | SendQueueStatus::Cancelled
                        | SendQueueStatus::Superseded
                        | SendQueueStatus::LeaseExpired
                ) && item.updated_at < cutoff
            })
            .map(|item| item.transaction_id.clone())
            .collect::<BTreeSet<_>>();
        let protected = self
            .items
            .values()
            .filter(|item| !candidates.contains(&item.transaction_id))
            .flat_map(|item| item.depends_on.iter().cloned())
            .collect::<BTreeSet<_>>();
        let removable = candidates
            .difference(&protected)
            .cloned()
            .collect::<BTreeSet<_>>();
        for transaction_id in &removable {
            self.items.remove(transaction_id);
        }
        self.order
            .retain(|transaction_id| !removable.contains(transaction_id));
        removable.len()
    }

    fn prune_unreferenced_terminal(&mut self) -> usize {
        let mut pending = self
            .items
            .values()
            .filter(|item| {
                matches!(
                    item.status,
                    SendQueueStatus::Queued | SendQueueStatus::Sending | SendQueueStatus::Failed
                )
            })
            .flat_map(|item| item.depends_on.iter().cloned())
            .collect::<Vec<_>>();
        let mut protected = BTreeSet::new();
        while let Some(transaction_id) = pending.pop() {
            if !protected.insert(transaction_id.clone()) {
                continue;
            }
            if let Some(item) = self.items.get(&transaction_id) {
                pending.extend(item.depends_on.iter().cloned());
            }
        }
        let removable = self
            .items
            .values()
            .filter(|item| {
                matches!(
                    item.status,
                    SendQueueStatus::Sent
                        | SendQueueStatus::Cancelled
                        | SendQueueStatus::Superseded
                        | SendQueueStatus::LeaseExpired
                ) && !protected.contains(&item.transaction_id)
            })
            .map(|item| item.transaction_id.clone())
            .collect::<BTreeSet<_>>();
        for transaction_id in &removable {
            self.items.remove(transaction_id);
        }
        self.order
            .retain(|transaction_id| !removable.contains(transaction_id));
        removable.len()
    }

    /// Mark an item as actively sending.
    pub fn mark_sending(&mut self, transaction_id: &str) -> Result<()> {
        let item = self.item_mut(transaction_id)?;
        item.status = SendQueueStatus::Sending;
        item.attempts = item.attempts.saturating_add(1);
        item.next_retry_at = None;
        item.updated_at = Utc::now();
        item.local_echo.status = item.status;
        Ok(())
    }

    /// Bind the authorization lease this attempt will be published under.
    ///
    /// A lease may only narrow authorization that already exists in its basis,
    /// so one whose scope belongs to another Realm is refused outright
    /// (`offline-publication.md` §1).
    pub fn bind_authorization_lease(
        &mut self,
        transaction_id: &str,
        lease: AuthorizationLease,
    ) -> Result<()> {
        lease.validate_structural()?;
        let item = self.item_mut(transaction_id)?;
        if lease.scope_ref.realm_id() != &item.realm_id {
            return Err(Error::Protocol(
                "authorization lease scope belongs to a different Realm than the queued item"
                    .to_owned(),
            ));
        }
        item.authorization_lease = Some(lease);
        item.updated_at = Utc::now();
        Ok(())
    }

    /// Mark an item as accepted by a policy-accepted ingress.
    ///
    /// A delayed/offline item that is bound to an authorization lease requires
    /// at least one receipt: acceptance without one leaves the Event with no
    /// proof that it arrived inside its lease window, which is exactly what a
    /// later peer cannot reconstruct. An ordinary online submission has no
    /// lease and therefore no lease-bound receipt. Already-stored receipts win
    /// over the supplied ones so an idempotent retry cannot overwrite the
    /// original `received_at`.
    pub fn mark_sent(
        &mut self,
        transaction_id: &str,
        remote_event_id: EventId,
        ingress_receipts: Vec<IngressReceipt>,
    ) -> Result<()> {
        let expects_receipt = self
            .get(transaction_id)
            .and_then(|item| item.authorization_lease.as_ref())
            .is_some();
        for receipt in &ingress_receipts {
            receipt.validate_structural()?;
        }
        let item = self.item_mut(transaction_id)?;
        if item.ingress_receipts.is_empty() {
            if expects_receipt && ingress_receipts.is_empty() {
                return Err(Error::Protocol(
                    "an accepted submission must carry at least one ingress receipt".to_owned(),
                ));
            }
            item.ingress_receipts = ingress_receipts;
        }
        item.status = SendQueueStatus::Sent;
        item.remote_event_id = Some(remote_event_id);
        item.next_retry_at = None;
        item.updated_at = Utc::now();
        item.local_echo.status = item.status;
        Ok(())
    }

    /// Retire every un-receipted item whose lease has expired, returning the
    /// retired transaction ids.
    ///
    /// Retrying them could never succeed: a first publication after
    /// `expires_at` with no qualifying receipt is permanently rejected
    /// (`offline-publication.md` §2), and a client that kept retrying would
    /// only mislead the user about the write's fate.
    pub fn expire_unreceipted_leases(&mut self, now: DateTime<Utc>) -> Vec<String> {
        let expired: Vec<String> = self
            .items
            .values()
            .filter(|item| {
                matches!(
                    item.status,
                    SendQueueStatus::Queued | SendQueueStatus::Sending | SendQueueStatus::Failed
                ) && item.ingress_receipts.is_empty()
                    && item
                        .authorization_lease
                        .as_ref()
                        .is_some_and(|lease| lease.expires_at <= now)
            })
            .map(|item| item.transaction_id.clone())
            .collect();
        for transaction_id in &expired {
            if let Ok(item) = self.item_mut(transaction_id) {
                item.status = SendQueueStatus::LeaseExpired;
                item.next_retry_at = None;
                item.updated_at = now;
                item.local_echo.status = item.status;
            }
        }
        expired
    }

    /// Mark an item as failed and schedule retry.
    pub fn mark_failed(&mut self, transaction_id: &str, retry_after: Duration) -> Result<()> {
        let item = self.item_mut(transaction_id)?;
        item.status = SendQueueStatus::Failed;
        item.next_retry_at =
            Some(Utc::now() + chrono::Duration::from_std(retry_after).unwrap_or_default());
        item.updated_at = Utc::now();
        item.local_echo.status = item.status;
        Ok(())
    }

    /// Cancel an item, optionally cascading to dependent queued items.
    pub fn cancel(&mut self, transaction_id: &str, cascade: bool) -> Result<()> {
        self.cancel_one(transaction_id)?;
        if cascade {
            let dependents: Vec<_> = self
                .items
                .values()
                .filter(|item| {
                    item.depends_on
                        .iter()
                        .any(|dependency| dependency == transaction_id)
                })
                .map(|item| item.transaction_id.clone())
                .collect();
            for dependent in dependents {
                self.cancel(&dependent, true)?;
            }
        }
        Ok(())
    }

    fn is_ready(&self, item: &SendQueueItem, now: DateTime<Utc>) -> bool {
        if !matches!(
            item.status,
            SendQueueStatus::Queued | SendQueueStatus::Failed
        ) {
            return false;
        }
        if item
            .next_retry_at
            .map(|retry_at| retry_at > now)
            .unwrap_or(false)
        {
            return false;
        }
        // An un-receipted Event past its lease window can never be admitted
        // (`offline-publication.md` §2), so it is not schedulable work.
        if item.ingress_receipts.is_empty()
            && item
                .authorization_lease
                .as_ref()
                .is_some_and(|lease| lease.expires_at <= now)
        {
            return false;
        }
        if let Some(actor_id) = &item.actor_id
            && self.items.values().any(|earlier| {
                earlier.transaction_id != item.transaction_id
                    && earlier.realm_id == item.realm_id
                    && earlier.actor_id.as_ref() == Some(actor_id)
                    && earlier.sequence < item.sequence
                    && matches!(
                        earlier.status,
                        SendQueueStatus::Queued
                            | SendQueueStatus::Sending
                            | SendQueueStatus::Failed
                    )
            })
        {
            return false;
        }
        item.depends_on.iter().all(|dependency| {
            self.items
                .get(dependency)
                .map(|dependency| dependency.status == SendQueueStatus::Sent)
                .unwrap_or(false)
        })
    }

    fn item_mut(&mut self, transaction_id: &str) -> Result<&mut SendQueueItem> {
        self.items.get_mut(transaction_id).ok_or_else(|| {
            Error::Protocol(format!(
                "send queue transaction not found: {}",
                transaction_id
            ))
        })
    }

    fn cancel_one(&mut self, transaction_id: &str) -> Result<()> {
        let item = self.item_mut(transaction_id)?;
        item.status = SendQueueStatus::Cancelled;
        item.next_retry_at = None;
        item.updated_at = Utc::now();
        item.local_echo.status = item.status;
        Ok(())
    }
}

fn queue_payload_digest(
    realm_id: &RealmId,
    record: &QueuedRecord,
    depends_on: &[String],
) -> Result<String> {
    Ok(canonical::canonical_sha256(&serde_json::json!({
        "realm_id": realm_id,
        "record": record,
        "depends_on": depends_on,
    }))?)
}

fn validate_record_scope(realm_id: &RealmId, record: &QueuedRecord) -> Result<()> {
    if record.realm_id()? != realm_id {
        return Err(Error::Protocol(
            "send queue Realm does not match its typed record".to_owned(),
        ));
    }
    Ok(())
}

/// Publication-evidence fixtures shared by the outbound and queue tests.
///
/// They build the exact shapes `offline-publication.md` §1 / §2 define, so a
/// test that binds a lease or records a receipt exercises the same structural
/// gate production code runs.
#[cfg(test)]
pub(crate) mod test_publication {
    use arkret_wire::SchemaId;
    use chrono::{DateTime, Utc};

    use arkret_wire::{
        AuthoritySetAuthorizationRule, AuthoritySetIssuer, AuthoritySetIssuerRole,
        AuthoritySetPolicy, AuthoritySetPolicyKind, AuthoritySetPolicySource, AuthoritySetRef,
        AuthoritySetSourceKind, AuthorizationLease, AuthorizationLeaseId, DeviceId, Did, DidCoreId,
        DidUrl, EventId, Hash, IngressReceipt, LeaseBasisRef, PayloadProof, ReceiptId, RiskTier,
        ScopeRef, SealId,
    };

    use crate::protocol::RealmId;

    pub(crate) fn lease(
        realm_id: RealmId,
        issued_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> AuthorizationLease {
        let scope_ref = ScopeRef::Realm { realm_id };
        let authority_set_policy = realm_admission_policy(scope_ref.clone(), "ak.message.create");
        let authority_set_ref = policy_ref(&authority_set_policy);
        let mut lease = AuthorizationLease {
            authorization_lease_id: AuthorizationLeaseId::new(
                "ak:authorization_lease:01904100-0000-7000-8000-aaaaaaaaaaaa",
            )
            .unwrap(),
            basis_ref: LeaseBasisRef::Seal(
                SealId::new(format!("ak:seal:sha256:{}", "a".repeat(64))).unwrap(),
            ),
            actor_id: arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                DidCoreId::new("ak:did_core:webvh:z6mkfixture:alice.example").unwrap(),
                DidCoreId::new("ak:did_core:web:principal.example").unwrap(),
            )),
            device_id: DeviceId::new("ak:device:01904100-0000-7000-8000-bbbbbbbbbbbb").unwrap(),
            scope_ref,
            action: "ak.message.create".to_owned(),
            authorization_rule_id: "realm_admission".to_owned(),
            risk_tier: RiskTier::Low,
            issued_at,
            expires_at,
            authority_set_ref,
            authority_set_policy,
            proofs: Vec::new(),
        };
        let digest = lease.lease_digest().unwrap();
        lease.proofs = vec![issuer_proof(
            "did:webvh:z6mkfixture:authority.example#key-1",
            digest,
            issued_at,
        )];
        lease
    }

    pub(crate) fn receipt(received_at: DateTime<Utc>) -> IngressReceipt {
        let mut receipt = IngressReceipt {
            receipt_id: ReceiptId::new("ak:receipt:01904100-0000-7000-8000-cccccccccccc").unwrap(),
            event_digest: Hash::new(format!("sha256:{}", "d".repeat(64))).unwrap(),
            qualified_ingress_did: Did::new("did:webvh:z6mkfixture:ingress.example".to_owned())
                .unwrap(),
            received_at,
            ingress_frontier: vec![
                EventId::new("ak:event:ATqrupSFYozzL7O90hPaSlvHmLnxxSRiRUZA4RgeuZpD".to_owned())
                    .unwrap(),
            ],
            proofs: Vec::new(),
        };
        let digest = receipt.receipt_digest().unwrap();
        receipt.proofs = vec![issuer_proof(
            "did:webvh:z6mkfixture:ingress.example#key-1",
            digest,
            received_at,
        )];
        receipt
    }

    fn realm_admission_policy(scope_ref: ScopeRef, action: &str) -> AuthoritySetPolicy {
        AuthoritySetPolicy {
            schema: SchemaId::AUTHORITY_SET_POLICY_V1.to_owned(),
            authority_set_id: "ak.authority_set.realm_admission.v1".to_owned(),
            policy_kind: AuthoritySetPolicyKind::RealmAdmission,
            scope_ref,
            source: AuthoritySetPolicySource {
                source_kind: AuthoritySetSourceKind::RealmControl,
                source_ref: format!("ak:seal:sha256:{}", "a".repeat(64)),
                source_digest: Hash::new(format!("sha256:{}", "b".repeat(64))).unwrap(),
                generation_ref: "1".to_owned(),
            },
            authorization_rules: vec![AuthoritySetAuthorizationRule {
                rule_id: "realm_admission".to_owned(),
                issuer_role: AuthoritySetIssuerRole::RealmAdmission,
                allowed_actions: vec![action.to_owned()],
                issuers: vec![AuthoritySetIssuer {
                    verification_method: DidUrl::new(
                        "did:webvh:z6mkfixture:authority.example#key-1",
                    )
                    .unwrap(),
                }],
                threshold: 1,
            }],
        }
    }

    fn policy_ref(policy: &AuthoritySetPolicy) -> AuthoritySetRef {
        AuthoritySetRef {
            authority_set_id: policy.authority_set_id.clone(),
            authority_set_digest: policy.digest().unwrap(),
        }
    }

    fn issuer_proof(
        verification_method: &str,
        payload_digest: Hash,
        created_at: DateTime<Utc>,
    ) -> PayloadProof {
        PayloadProof {
            kind: "detached_jws".to_owned(),
            verification_method: DidUrl::new(verification_method).unwrap(),
            payload_digest,
            created_at,
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: "a..b".to_owned(),
        }
    }
}
