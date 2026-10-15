//! Ordinary Account clients consume original governance results through their
//! accepted, authenticated Station. Native Station/audit verification remains
//! in `replica` and is deliberately not weakened by this module.

use std::collections::BTreeMap;

use arkret_http_client::own_station_results::{
    BoundOwnStationResponse, OwnStationResultClient, OwnStationSessionSnapshot,
};
use arkret_models_collaboration::authority_commit::{
    SelfAuthoritySubmitOutcome, SelfAuthoritySubmitRequest,
};
use arkret_models_collaboration::sync_frames::account_sync::StreamWindowStartBasis;
use arkret_models_identity::signer_key_operations::{
    HistoricalSignerKeyQuerySender, SignerKeyQueryOutcome, SignerKeyQuerySelector,
    SignerKeysQueryRequestBody,
};
use arkret_wire::{
    CommitStreamHead, CommitStreamRef, CommittedEventRef, CommittedEventView, EventId,
    ReadableFloor, RealmId, RealmSnapshotId, RealmStateSnapshot, RequestId, StreamScanDirection,
    StreamScanOutcome, StreamScanRequest, TypedCurrentRow,
};

use crate::{Error, Result};

pub struct OwnStationScanPage {
    response: BoundOwnStationResponse<StreamScanRequest, StreamScanOutcome>,
}
impl OwnStationScanPage {
    pub fn rows(&self) -> Result<&[CommittedEventView]> {
        Ok(&self.response.value()?.committed_events)
    }
    pub fn into_rows(self) -> Result<Vec<CommittedEventView>> {
        Ok(self.response.into_value()?.committed_events)
    }
    pub fn session(&self) -> &OwnStationSessionSnapshot {
        self.response.session()
    }
}

/// An exact accepted original, admitted without replaying private governance
/// history or advancing any stream checkpoint. Only the authenticated read
/// path below can construct this local consumption proof.
pub struct OwnStationWindowDependency {
    response: BoundOwnStationResponse<EventId, CommittedEventView>,
}

pub async fn read_window_dependency(
    client: &OwnStationResultClient,
    reference: &CommittedEventRef,
) -> Result<OwnStationWindowDependency> {
    let response = client.committed_event_get(&reference.event_id).await?;
    let response = consume_bound_event(client, reference, response).await?;
    Ok(OwnStationWindowDependency { response })
}

impl OwnStationWindowDependency {
    pub(crate) fn encoded_len(&self) -> Result<usize> {
        Ok(serde_json::to_vec(self.response.value()?)
            .map_err(|error| protocol(&error.to_string()))?
            .len())
    }
}

/// Separate from `VerifiedFloorSnapshot`: this is ordinary local consumption,
/// not independently audited or portable evidence.
pub struct OwnStationFloorSnapshot {
    response: BoundOwnStationResponse<(RealmId, RealmSnapshotId), RealmStateSnapshot>,
    stream_ref: CommitStreamRef,
}
impl OwnStationFloorSnapshot {
    pub fn snapshot(&self) -> Result<&RealmStateSnapshot> {
        Ok(self.response.value()?)
    }
    pub fn head(&self) -> Result<&CommitStreamHead> {
        self.snapshot()?
            .visible_stream_heads
            .iter()
            .find(|head| head.stream_ref == self.stream_ref)
            .ok_or_else(|| protocol("floor snapshot omitted its stream"))
    }
    pub fn governance_generation(&self) -> Result<u64> {
        Ok(self.snapshot()?.governance_generation)
    }
    pub fn history_access(&self) -> Result<arkret_wire::HistoryAccess> {
        Ok(self.snapshot()?.retention_and_history_floor.history_access)
    }
    pub fn rows(&self) -> Result<Vec<TypedCurrentRow>> {
        Ok(self
            .response
            .value()?
            .current_state_entries
            .iter()
            .filter(|row| match row {
                TypedCurrentRow::Value {
                    source_stream_ref, ..
                } => source_stream_ref == &self.stream_ref,
            })
            .cloned()
            .collect())
    }
}

#[derive(Clone)]
pub struct OwnStationReplica {
    realm_id: RealmId,
    context: Option<OwnStationSessionSnapshot>,
    heads: BTreeMap<CommitStreamRef, CommitStreamHead>,
    current_heads: BTreeMap<CommitStreamRef, CommitStreamHead>,
    generations: BTreeMap<CommitStreamRef, u64>,
    snapshot: Option<RealmStateSnapshot>,
}

impl OwnStationReplica {
    pub fn new(realm_id: RealmId) -> Self {
        Self {
            realm_id,
            context: None,
            heads: BTreeMap::new(),
            current_heads: BTreeMap::new(),
            generations: BTreeMap::new(),
            snapshot: None,
        }
    }
    pub fn head(&self, stream: &CommitStreamRef) -> Option<&CommitStreamHead> {
        self.heads.get(stream)
    }
    pub fn snapshot(&self) -> Option<&RealmStateSnapshot> {
        self.snapshot.as_ref()
    }
    /// Start live consumption at the installed current cut. This admits only
    /// its exact original head, never the unreadable historical prefix or a
    /// preview window. Subsequent pages must continue from this head.
    pub async fn bootstrap_current_head(
        &mut self,
        client: &OwnStationResultClient,
        stream: &CommitStreamRef,
    ) -> Result<()> {
        if self.heads.contains_key(stream) {
            return Err(protocol("live bootstrap would replace an accepted head"));
        }
        let expected = self
            .current_heads
            .get(stream)
            .cloned()
            .ok_or_else(|| protocol("live bootstrap has no installed current head"))?;
        self.restore_checkpoint_head(client, &expected).await
    }
    /// Re-admit a durable head using one exact original, never a bare cursor.
    pub async fn restore_checkpoint_head(
        &mut self,
        client: &OwnStationResultClient,
        expected: &CommitStreamHead,
    ) -> Result<()> {
        let before = expected
            .stream_position
            .checked_add(1)
            .ok_or_else(|| protocol("checkpoint position overflow"))?;
        let request = StreamScanRequest {
            realm_id: self.realm_id.clone(),
            stream_ref: expected.stream_ref.clone(),
            direction: StreamScanDirection::Before(Some(before)),
            limit: 1,
        };
        let response = client.scan_commit_stream(&request).await?;
        self.restore_bound_head(client, expected, response).await
    }

    pub async fn restore_bound_head(
        &mut self,
        client: &OwnStationResultClient,
        expected: &CommitStreamHead,
        response: BoundOwnStationResponse<StreamScanRequest, StreamScanOutcome>,
    ) -> Result<()> {
        self.check_context(response.session())?;
        if response.session() != client.session()? {
            return Err(protocol("checkpoint response belongs to another session"));
        }
        let request = response.request();
        let outcome = response.value()?;
        outcome
            .validate_for_request(request)
            .map_err(|error| protocol(&error.to_string()))?;
        let before = expected
            .stream_position
            .checked_add(1)
            .ok_or_else(|| protocol("checkpoint position overflow"))?;
        if request.realm_id != self.realm_id
            || request.stream_ref != expected.stream_ref
            || request.direction != StreamScanDirection::Before(Some(before))
            || request.limit != 1
            || outcome.committed_events.len() != 1
        {
            return Err(protocol(
                "checkpoint restoration is not one exact same-stream original",
            ));
        }
        let row = &outcome.committed_events[0];
        if head(row.commit()) != *expected {
            return Err(protocol(
                "checkpoint restoration changed its accepted original",
            ));
        }
        verify_row(client, row).await?;
        self.check_head(row.commit())?;
        response.value()?;
        client.check_session()?;
        self.context = Some(response.session().clone());
        self.generations.insert(
            expected.stream_ref.clone(),
            row.commit().governance_generation,
        );
        self.heads
            .insert(expected.stream_ref.clone(), expected.clone());
        Ok(())
    }
    fn check_context(&self, session: &OwnStationSessionSnapshot) -> Result<()> {
        if self.context.as_ref().is_some_and(|saved| saved != session) {
            return Err(protocol(
                "ordinary replica belongs to another local session",
            ));
        }
        Ok(())
    }

    /// Exact historical anchor re-admitted through the current authenticated
    /// self read. The expected four-coordinate reference comes from a durable
    /// local checkpoint, never from the pending MLS Commit's asserted payload.
    pub async fn restore_bound_anchor(
        &mut self,
        client: &OwnStationResultClient,
        expected: &CommittedEventRef,
        response: BoundOwnStationResponse<EventId, CommittedEventView>,
    ) -> Result<()> {
        self.check_context(response.session())?;
        if response.session() != client.session()?
            || response.request() != &expected.event_id
            || !expected.matches(response.value()?)
        {
            return Err(protocol(
                "ordinary historical anchor differs from its exact checkpoint",
            ));
        }
        let row = response.value()?;
        if !matches!(row, CommittedEventView::Full(_)) {
            return Err(protocol(
                "withheld anchor cannot supply an MLS historical base",
            ));
        }
        verify_get_candidate(client, expected, row).await?;
        let commit = row.commit();
        if commit.realm_id != self.realm_id {
            return Err(protocol("ordinary anchor belongs to another Realm"));
        }
        self.check_head(commit)?;
        response.value()?;
        client.check_session()?;
        self.context = Some(response.session().clone());
        self.generations
            .insert(commit.stream_ref.clone(), commit.governance_generation);
        self.heads.insert(commit.stream_ref.clone(), head(commit));
        Ok(())
    }

    pub async fn apply_bound_scan(
        &mut self,
        client: &OwnStationResultClient,
        response: BoundOwnStationResponse<StreamScanRequest, StreamScanOutcome>,
    ) -> Result<OwnStationScanPage> {
        self.check_context(response.session())?;
        if response.session() != client.session()? {
            return Err(protocol(
                "ordinary scan is from another authenticated session",
            ));
        }
        let request = response.request();
        let outcome = response.value()?;
        outcome
            .validate_for_request(request)
            .map_err(|error| protocol(&error.to_string()))?;
        if request.realm_id != self.realm_id {
            return Err(protocol("ordinary scan belongs to another Realm"));
        }
        let StreamScanDirection::After(after) = request.direction else {
            return Err(protocol("ordinary replica requires a forward scan"));
        };
        let saved = self.heads.get(&request.stream_ref);
        if saved.map(|value| value.stream_position) != after {
            return Err(protocol(
                "ordinary scan does not resume its saved independent head",
            ));
        }
        let mut previous_id = saved.map(|value| value.commit_id.clone());
        let mut position = match saved {
            Some(value) => value
                .stream_position
                .checked_add(1)
                .ok_or_else(|| protocol("stream position overflow"))?,
            None => 0,
        };
        let mut generation = self
            .generations
            .get(&request.stream_ref)
            .copied()
            .unwrap_or(0);
        let cap = if let Some(snapshot) = &self.snapshot {
            let cap = snapshot
                .visible_stream_heads
                .iter()
                .find(|value| value.stream_ref == request.stream_ref)
                .ok_or_else(|| protocol("scan stream is absent from installed current cut"))?;
            if outcome
                .readable_floor
                .as_ref()
                .map(|floor| floor.oldest_position)
                != snapshot
                    .retention_and_history_floor
                    .stream_floors
                    .iter()
                    .find(|floor| floor.stream_ref == request.stream_ref)
                    .map(|floor| floor.oldest_position)
            {
                return Err(protocol(
                    "ordinary scan and installed current have different history floors",
                ));
            }
            Some((cap, snapshot.governance_generation))
        } else {
            if outcome
                .readable_floor
                .as_ref()
                .is_some_and(|floor| floor.oldest_position > 0)
            {
                return Err(protocol("limited history requires an exact snapshot basis"));
            }
            None
        };
        for row in &outcome.committed_events {
            let commit = row.commit();
            if commit.stream_position != position
                || commit.previous_commit_ref != previous_id
                || commit.governance_generation < generation
            {
                return Err(protocol(
                    "ordinary scan has a fork, gap, mixed generation or rollback",
                ));
            }
            if let Some((cap, current_generation)) = cap
                && (commit.governance_generation > current_generation
                    || commit.stream_position > cap.stream_position
                    || (commit.stream_position == cap.stream_position
                        && commit.commit_id != cap.commit_id))
            {
                return Err(protocol(
                    "ordinary scan exceeds or forks its exact current cut",
                ));
            }
            verify_row(client, row).await?;
            previous_id = Some(commit.commit_id.clone());
            position = position
                .checked_add(1)
                .ok_or_else(|| protocol("stream position overflow"))?;
            generation = commit.governance_generation;
        }
        response.value()?;
        client.check_session()?;
        if let Some(last) = outcome.committed_events.last() {
            self.heads
                .insert(request.stream_ref.clone(), head(last.commit()));
            self.generations
                .insert(request.stream_ref.clone(), generation);
        }
        self.context = Some(response.session().clone());
        Ok(OwnStationScanPage { response })
    }

    pub fn install_bound_snapshot<Q>(
        &mut self,
        response: &BoundOwnStationResponse<Q, RealmStateSnapshot>,
    ) -> Result<()> {
        self.check_context(response.session())?;
        let snapshot = response.value()?;
        validate_snapshot(snapshot, &self.realm_id)?;
        if self
            .snapshot
            .as_ref()
            .is_some_and(|old| snapshot.governance_generation < old.governance_generation)
        {
            return Err(protocol("ordinary current generation rollback"));
        }
        for incoming in &snapshot.visible_stream_heads {
            if self.heads.get(&incoming.stream_ref).is_some_and(|old| {
                incoming.stream_position < old.stream_position
                    || (incoming.stream_position == old.stream_position
                        && incoming.commit_id != old.commit_id)
            }) {
                return Err(protocol(
                    "ordinary current cut is behind or forks accepted history",
                ));
            }
            if self
                .current_heads
                .get(&incoming.stream_ref)
                .is_some_and(|old| {
                    incoming.stream_position < old.stream_position
                        || (incoming.stream_position == old.stream_position
                            && incoming.commit_id != old.commit_id)
                })
            {
                return Err(protocol("ordinary current head rollback or fork"));
            }
        }
        for incoming in &snapshot.visible_stream_heads {
            self.current_heads
                .insert(incoming.stream_ref.clone(), incoming.clone());
        }
        self.context = Some(response.session().clone());
        self.snapshot = Some(snapshot.clone());
        // Snapshot heads are current coverage, not downloaded predecessors.
        Ok(())
    }

    pub fn install_bound_floor_predecessor(
        &mut self,
        stream_ref: &CommitStreamRef,
        basis: &StreamWindowStartBasis,
        floor: &ReadableFloor,
        response: BoundOwnStationResponse<(RealmId, RealmSnapshotId), RealmStateSnapshot>,
        dependencies: &BTreeMap<CommittedEventRef, OwnStationWindowDependency>,
    ) -> Result<OwnStationFloorSnapshot> {
        self.check_context(response.session())?;
        basis
            .validate()
            .map_err(|error| protocol(&error.to_string()))?;
        let snapshot = response.value()?;
        validate_snapshot(snapshot, &self.realm_id)?;
        if response.request() != &(self.realm_id.clone(), basis.snapshot_ref.clone())
            || snapshot.snapshot_id != basis.snapshot_ref
            || snapshot.governance_generation != basis.governance_generation
            || self.heads.contains_key(stream_ref)
        {
            return Err(protocol(
                "ordinary floor basis does not name its exact unused snapshot",
            ));
        }
        let target = snapshot
            .visible_stream_heads
            .iter()
            .find(|head| &head.stream_ref == stream_ref)
            .ok_or_else(|| protocol("snapshot omits floor stream"))?;
        if target.commit_id != basis.anchor_commit_ref
            || target.stream_position != basis.anchor_position
            || floor.oldest_position > target.stream_position
            || !snapshot
                .retention_and_history_floor
                .stream_floors
                .iter()
                .any(|value| {
                    value.stream_ref == *stream_ref
                        && value.oldest_position == floor.oldest_position
                })
        {
            return Err(protocol("ordinary floor basis mixes head, floor or stream"));
        }
        for dependency in basis.accepted_dependency_refs.iter().flatten() {
            if dependency.stream_ref == *stream_ref
                || dependency.stream_ref.realm_id() != &self.realm_id
            {
                return Err(protocol("floor dependency has wrong scope"));
            }
            let cap = snapshot
                .visible_stream_heads
                .iter()
                .find(|head| head.stream_ref == dependency.stream_ref)
                .ok_or_else(|| protocol("dependency has no current covering head"))?;
            let original = dependencies
                .get(dependency)
                .ok_or_else(|| protocol("floor dependency lacks original accepted history"))?;
            let row = original.response.value()?;
            let commit = row.commit();
            if original.response.session() != response.session()
                || original.response.request() != &dependency.event_id
                || !dependency.matches(row)
                || !matches!(row, CommittedEventView::Full(_))
                || commit.governance_generation > basis.governance_generation
                || commit.stream_position > cap.stream_position
                || (commit.stream_position == cap.stream_position
                    && commit.commit_id != cap.commit_id)
                || !snapshot
                    .retention_and_history_floor
                    .stream_floors
                    .iter()
                    .any(|floor| {
                        floor.stream_ref == dependency.stream_ref
                            && floor.oldest_position <= commit.stream_position
                    })
            {
                return Err(protocol(
                    "floor dependency is not covered by its exact snapshot",
                ));
            }
        }
        response.value()?;
        self.context = Some(response.session().clone());
        self.generations
            .insert(stream_ref.clone(), snapshot.governance_generation);
        self.heads.insert(stream_ref.clone(), target.clone());
        Ok(OwnStationFloorSnapshot {
            response,
            stream_ref: stream_ref.clone(),
        })
    }

    fn check_head(&self, commit: &arkret_wire::RealmCommit) -> Result<()> {
        if self.heads.get(&commit.stream_ref).is_some_and(|old| {
            commit.stream_position < old.stream_position
                || (commit.stream_position == old.stream_position
                    && commit.commit_id != old.commit_id)
        }) || self
            .generations
            .get(&commit.stream_ref)
            .is_some_and(|old| commit.governance_generation < *old)
        {
            return Err(protocol(
                "ordinary historical anchor rolls back or forks its saved stream",
            ));
        }
        Ok(())
    }
}

fn head(commit: &arkret_wire::RealmCommit) -> CommitStreamHead {
    CommitStreamHead {
        stream_ref: commit.stream_ref.clone(),
        stream_position: commit.stream_position,
        commit_id: commit.commit_id.clone(),
    }
}

fn validate_snapshot(snapshot: &RealmStateSnapshot, realm: &RealmId) -> Result<()> {
    crate::replica::validate_snapshot(snapshot, realm)?;
    let mut body = serde_json::to_value(snapshot).map_err(|error| protocol(&error.to_string()))?;
    let object = body
        .as_object_mut()
        .ok_or_else(|| protocol("snapshot is not an object"))?;
    object.remove("snapshot_id");
    object.remove("signature");
    let bytes = arkret_canonical::canonical_json_bytes(&body)
        .map_err(|error| protocol(&error.to_string()))?;
    if snapshot.snapshot_id != RealmSnapshotId::from_digest(arkret_canonical::sha256_bytes(&bytes))
    {
        return Err(protocol("ordinary snapshot content address mismatch"));
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum OriginalSource {
    Ordinary,
    // A bound self acceptance is only a candidate until the historical key
    // resolves its original device authorization on this exact PCR stream.
    BoundSelfHumanPcr,
    BoundSelfAgentPcrGenesis,
}

async fn verify_row(client: &OwnStationResultClient, row: &CommittedEventView) -> Result<()> {
    verify_row_from_source(client, row, OriginalSource::Ordinary).await
}

async fn verify_row_from_source(
    client: &OwnStationResultClient,
    row: &CommittedEventView,
    source: OriginalSource,
) -> Result<()> {
    row.validate_shape()
        .map_err(|error| protocol(&error.to_string()))?;
    row.commit()
        .verify_commit_id_matches_content()
        .map_err(|error| protocol(&error.to_string()))?;
    let CommittedEventView::Full(full) = row else {
        return Ok(());
    };
    let event = &full.event;
    let suite = event.realm_id.digest_suite_code().digest_suite();
    event
        .verify_event_id_matches_content_with_digest_suite(suite)
        .map_err(|error| protocol(&error.to_string()))?;
    let human = event
        .verify_producer_proof_self_consistency(suite)
        .map_err(|error| protocol(&error.to_string()))?;
    let proof = event
        .producer_proof
        .as_ref()
        .ok_or_else(|| protocol("disclosed Event has no producer proof"))?;
    if matches!(event.actual_signer(), arkret_wire::ActorId::Service { .. })
        && event.applet_id.is_some()
    {
        let selector = SignerKeyQuerySelector::HistoricalEvent {
            sender: HistoricalSignerKeyQuerySender::Service {
                actor: event.actual_signer().clone(),
                verification_method: proof.verification_method.clone(),
                committed_event_ref: CommittedEventRef {
                    event_id: event.event_id.clone(),
                    commit_id: full.commit.commit_id.clone(),
                    stream_ref: full.commit.stream_ref.clone(),
                    stream_position: full.commit.stream_position,
                },
            },
        };
        let request = SignerKeysQueryRequestBody {
            request_id: request_id()?,
            realm_id: event.realm_id.clone(),
            recipient_account_id: client.session()?.account_id().clone(),
            queries: vec![selector],
        };
        let outcome = client.signer_keys_query(&request).await?;
        outcome
            .value()?
            .validate_for_request(&request)
            .map_err(|e| protocol(&e.to_string()))?;
        let Some(SignerKeyQueryOutcome::HistoricalServiceResolved {
            key, accepted_at, ..
        }) = outcome.value()?.results.first()
        else {
            return Err(protocol(
                "exact historical Service signing key is unavailable",
            ));
        };
        let fact = arkret_models_collaboration::authority_commit::ServiceHistoricalSignerFact {
            event_id: event.event_id.clone(),
            actor: event.actual_signer().clone(),
            verification_method: proof.verification_method.clone(),
            key: key.clone(),
            accepted_at: *accepted_at,
        };
        fact.validate_commit_binding(full, suite)
            .map_err(|e| protocol(&e.to_string()))?;
        let material = arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: arkret_canonical::base64url_decode(key.public_key_b64u.as_str())
                .map_err(|e| protocol(&e.to_string()))?,
        };
        let bytes = arkret_signatures::EventProofBuilder::new()
            .envelope_bytes(event)
            .map_err(|e| protocol(&e.to_string()))?;
        arkret_signatures::verify_ed25519_detached_jws_proof_with_digest_suite(
            proof,
            &bytes,
            &event.actor_id,
            &material,
            suite,
        )
        .map_err(|e| protocol(&e.to_string()))?;
        client.check_session()?;
        return Ok(());
    }
    if event.actual_signer().as_account_id().is_none() {
        // A service-generated franking original may be retained in an
        // ordinary timeline. This verifies its content/proof consistency and
        // exact Service method controller, not the dedicated franking
        // signature or portable Service evidence. A franking consumer must
        // still run its registered historical Service proof verifier.
        if event.kind != arkret_wire::EventKind::ModerationFrankingProof {
            return Err(protocol(
                "unsupported Service producer in ordinary consumption",
            ));
        }
        proof
            .validate_production()
            .map_err(|error| protocol(&error.to_string()))?;
        client.check_session()?;
        return Ok(());
    }
    let reference = CommittedEventRef {
        event_id: event.event_id.clone(),
        commit_id: full.commit.commit_id.clone(),
        stream_ref: full.commit.stream_ref.clone(),
        stream_position: full.commit.stream_position,
    };
    // Scan/get originals require the ordinary Human fact digest. Bound self
    // PCR acceptance uses its recipient-limited historical source instead;
    // neither path grants native PCR audit or history access.
    if source == OriginalSource::Ordinary
        && human.is_some()
        && full.commit.producer_signer_fact_digest.is_none()
    {
        return Err(protocol(
            "original ordinary Human signer source is unavailable",
        ));
    }
    let sender = if let Some(human) = &human {
        HistoricalSignerKeyQuerySender::AccountDevice {
            actor: arkret_wire::ActorId::account(human.account_id.clone()),
            device_id: human.device_id.clone(),
            verification_method: proof.verification_method.clone(),
            committed_event_ref: reference,
        }
    } else {
        HistoricalSignerKeyQuerySender::Agent {
            actor: event.actual_signer().clone(),
            verification_method: proof.verification_method.clone(),
            committed_event_ref: reference,
        }
    };
    let request = SignerKeysQueryRequestBody {
        request_id: request_id()?,
        realm_id: event.realm_id.clone(),
        recipient_account_id: client.session()?.account_id().clone(),
        queries: vec![SignerKeyQuerySelector::HistoricalEvent { sender }],
    };
    let outcome = client.signer_keys_query(&request).await?;
    outcome
        .value()?
        .validate_for_request(&request)
        .map_err(|error| protocol(&error.to_string()))?;
    let Some(SignerKeyQueryOutcome::HistoricalResolved {
        key, accepted_at, ..
    }) = outcome.value()?.results.first()
    else {
        return Err(protocol(
            "exact historical producer signing key is unavailable",
        ));
    };
    if source == OriginalSource::BoundSelfHumanPcr
        && key.authorization_ref.stream_ref != full.commit.stream_ref
    {
        return Err(protocol(
            "bound self Human acceptance lacks its original same-PCR authorization",
        ));
    }
    if let Some(human) = human.filter(|_| source == OriginalSource::Ordinary) {
        let fact = arkret_models_collaboration::authority_commit::HumanHistoricalSignerFact {
            event_id: event.event_id.clone(),
            actor: event.actual_signer().clone(),
            device_id: human.device_id,
            verification_method: proof.verification_method.clone(),
            key: key.clone(),
            accepted_at: *accepted_at,
        };
        fact.validate_event_binding(event, suite)
            .map_err(|error| protocol(&error.to_string()))?;
        if source == OriginalSource::Ordinary
            && full.commit.producer_signer_fact_digest.as_ref()
                != Some(
                    &fact
                        .digest()
                        .map_err(|error| protocol(&error.to_string()))?,
                )
        {
            return Err(protocol(
                "ordinary Human source differs from original Commit fact digest",
            ));
        }
    }
    let material = arkret_signatures::PublicKeyMaterial::Ed25519Raw {
        bytes: arkret_canonical::base64url_decode(key.public_key_b64u.as_str())
            .map_err(|error| protocol(&error.to_string()))?,
    };
    let bytes = arkret_signatures::EventProofBuilder::new()
        .envelope_bytes(event)
        .map_err(|error| protocol(&error.to_string()))?;
    arkret_signatures::verify_ed25519_detached_jws_proof_with_digest_suite(
        proof,
        &bytes,
        &event.actor_id,
        &material,
        suite,
    )
    .map_err(|error| protocol(&error.to_string()))?;
    client.check_session()?;
    Ok(())
}

fn request_id() -> Result<RequestId> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|error| protocol(&error.to_string()))?;
    let millis = chrono::Utc::now().timestamp_millis().max(0) as u64;
    bytes[..6].copy_from_slice(&millis.to_be_bytes()[2..]);
    bytes[6] = (bytes[6] & 15) | 0x70;
    bytes[8] = (bytes[8] & 63) | 0x80;
    let hex = bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    RequestId::new(format!(
        "ak:request:{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    ))
    .map_err(|error| protocol(&error.to_string()))
}

fn protocol(message: &str) -> Error {
    Error::Protocol(message.into())
}

/// Consume only a real authenticated acceptance paired with its frozen request.
/// This verifies originals without granting a history read or advancing a head.
pub async fn consume_bound_submission(
    client: &OwnStationResultClient,
    request: &SelfAuthoritySubmitRequest,
    response: BoundOwnStationResponse<SelfAuthoritySubmitRequest, SelfAuthoritySubmitOutcome>,
) -> Result<BoundOwnStationResponse<SelfAuthoritySubmitRequest, SelfAuthoritySubmitOutcome>> {
    if response.session() != client.session()? || response.request() != request {
        return Err(protocol(
            "ordinary acceptance differs from its source or frozen request",
        ));
    }
    let accepted = crate::authority::accepted_items(response.request(), response.value()?)?;
    for original in accepted {
        // Only this real response/frozen single-Event acceptance establishes
        // the self source. Scan and disclosed Full callers retain Ordinary.
        let source = bound_self_submission_source(client, request, &original)?;
        verify_row_from_source(client, &CommittedEventView::Full(original), source).await?;
        response.value()?;
    }
    client.check_session()?;
    response.value()?;
    Ok(response)
}

fn bound_self_submission_source(
    client: &OwnStationResultClient,
    request: &SelfAuthoritySubmitRequest,
    original: &arkret_wire::CommittedEventFullView,
) -> Result<OriginalSource> {
    let source = bound_self_agent_pcr_genesis_source(client, request, original)?;
    if source != OriginalSource::Ordinary || original.commit.producer_signer_fact_digest.is_some() {
        return Ok(source);
    }
    let SelfAuthoritySubmitRequest::Event(submission) = request else {
        return Ok(OriginalSource::Ordinary);
    };
    let event = &submission.event;
    let recipient = client.session()?.account_id();
    if &original.event != event
        || event.actor_id.as_account_id() != Some(recipient)
        || event.actual_signer().as_account_id() != Some(recipient)
        || event
            .human_device_producer()
            .map_err(|error| protocol(&error.to_string()))?
            .is_none()
        || event.scope_ref
            != (arkret_wire::ScopeRef::Realm {
                realm_id: event.realm_id.clone(),
            })
        || original.commit.stream_ref
            != (CommitStreamRef::Realm {
                realm_id: event.realm_id.clone(),
            })
    {
        return Ok(OriginalSource::Ordinary);
    }
    // This does not classify an arbitrary no-digest business acceptance as
    // PCR. verify_row_from_source still requires the exact historical result
    // to bind the original device authorization to this same Realm stream.
    // No current lookup, PCR scan or Event-kind exception supplies that fact.
    Ok(OriginalSource::BoundSelfHumanPcr)
}

// This classifies a source, never supplies historical authority. The existing
// exact HistoricalEvent query must still resolve the immutable self-admission
// fact (including original provision/controller/delegation) or fail closed.
fn bound_self_agent_pcr_genesis_source(
    client: &OwnStationResultClient,
    request: &SelfAuthoritySubmitRequest,
    original: &arkret_wire::CommittedEventFullView,
) -> Result<OriginalSource> {
    let SelfAuthoritySubmitRequest::Event(submission) = request else {
        return Ok(OriginalSource::Ordinary);
    };
    let event = &submission.event;
    if event.kind != arkret_wire::EventKind::RealmCreate {
        return Ok(OriginalSource::Ordinary);
    }
    let payload: arkret_models_collaboration::events_payloads::realm::RealmCreatePayload =
        serde_json::from_value(
            serde_json::to_value(&event.payload).map_err(|error| protocol(&error.to_string()))?,
        )
        .map_err(|error| protocol(&error.to_string()))?;
    payload
        .object
        .validate()
        .map_err(|error| protocol(&error.to_string()))?;
    if payload.object.purpose
        != arkret_models_collaboration::events_payloads::realm::RealmPurpose::AgentControl
    {
        return Ok(OriginalSource::Ordinary);
    }
    let session = client.session()?;
    let controller = session.account_id();
    let Some(agent) = event.actor_id.as_account_id() else {
        return Err(protocol(
            "bound Agent PCR genesis has no full Agent Account",
        ));
    };
    if &original.event != event
        || event
            .human_device_producer()
            .map_err(|error| protocol(&error.to_string()))?
            .is_none()
        || submission.approval_signatures.is_some()
        || event.actual_signer().as_account_id() != Some(controller)
        || event
            .executed_by
            .as_ref()
            .and_then(|actor| actor.as_account_id())
            != Some(controller)
        || agent.station_id != controller.station_id
        || agent.principal_id == controller.principal_id
        || event.realm_id != RealmId::from_event_id(&event.event_id)
        || event.scope_ref != arkret_wire::ScopeRef::RealmGenesis
        || original.commit.stream_ref
            != (arkret_wire::CommitStreamRef::Realm {
                realm_id: event.realm_id.clone(),
            })
        || original.commit.stream_position != 0
        || original.commit.previous_commit_ref.is_some()
        || event.authorization_ref.is_none()
        || payload.object.governance_station_id != controller.station_id
        || payload
            .object
            .initial_resolution
            .as_ref()
            .map(|resolution| arkret_wire::project_did_to_core_id(&resolution.did))
            .transpose()
            .map_err(|error| protocol(&error.to_string()))?
            .as_ref()
            != Some(&agent.principal_id)
        || original.commit.producer_signer_fact_digest.is_some()
    {
        return Err(protocol(
            "bound Agent PCR genesis differs from its exact authenticated self source",
        ));
    }
    Ok(OriginalSource::BoundSelfAgentPcrGenesis)
}

/// Independently validate one disclosed historical original without advancing
/// any replay head. This is useful for exact MLS predecessor recovery.
pub async fn consume_bound_event(
    client: &OwnStationResultClient,
    expected: &CommittedEventRef,
    response: BoundOwnStationResponse<EventId, CommittedEventView>,
) -> Result<BoundOwnStationResponse<EventId, CommittedEventView>> {
    if response.session() != client.session()?
        || response.request() != &expected.event_id
        || !expected.matches(response.value()?)
        || !matches!(response.value()?, CommittedEventView::Full(_))
    {
        return Err(protocol(
            "ordinary exact Event differs from requested original",
        ));
    }
    verify_get_candidate(client, expected, response.value()?).await?;
    response.value()?;
    Ok(response)
}

async fn verify_get_candidate(
    client: &OwnStationResultClient,
    expected: &CommittedEventRef,
    candidate: &CommittedEventView,
) -> Result<()> {
    let before = expected
        .stream_position
        .checked_add(1)
        .ok_or_else(|| protocol("historical row position overflow"))?;
    let request = StreamScanRequest {
        realm_id: expected.stream_ref.realm_id().clone(),
        stream_ref: expected.stream_ref.clone(),
        direction: StreamScanDirection::Before(Some(before)),
        limit: 1,
    };
    let scan = client.scan_commit_stream(&request).await?;
    let scan = consume_bound_scan_row(client, expected, scan).await?;
    if scan.value()?.committed_events.first() != Some(candidate) {
        return Err(protocol(
            "GET candidate differs from exact accepted stream original",
        ));
    }
    Ok(())
}

/// Consume one actual per-stream `stream_row` original, the registered input
/// for an exact historical producer signer selector.
pub async fn consume_bound_scan_row(
    client: &OwnStationResultClient,
    expected: &CommittedEventRef,
    response: BoundOwnStationResponse<StreamScanRequest, StreamScanOutcome>,
) -> Result<BoundOwnStationResponse<StreamScanRequest, StreamScanOutcome>> {
    let request = response.request();
    let before = expected
        .stream_position
        .checked_add(1)
        .ok_or_else(|| protocol("historical row position overflow"))?;
    if response.session() != client.session()?
        || request.realm_id != *expected.stream_ref.realm_id()
        || request.stream_ref != expected.stream_ref
        || request.direction != StreamScanDirection::Before(Some(before))
        || request.limit != 1
    {
        return Err(protocol(
            "historical producer input is not its exact same-stream read",
        ));
    }
    let [row] = response.value()?.committed_events.as_slice() else {
        return Err(protocol(
            "historical producer input requires one original stream row",
        ));
    };
    if !expected.matches(row) || !matches!(row, CommittedEventView::Full(_)) {
        return Err(protocol(
            "historical stream row is withheld or differs from exact reference",
        ));
    }
    verify_row(client, row).await?;
    response.value()?;
    Ok(response)
}

pub fn consume_bound_snapshot<Q>(
    response: &BoundOwnStationResponse<Q, RealmStateSnapshot>,
    realm: &RealmId,
) -> Result<()> {
    validate_snapshot(response.value()?, realm)
}

/// A typed mode result derived only from an actual authenticated response.
/// Both production paths retain their genuine source until consumption; a
/// snapshot Present row is not reconstructed into a synthetic SDK response.
pub struct OwnStationAgentInteraction {
    value: arkret_models_collaboration::exact_current_results::ExactCurrentResultsReadOutcome,
    source: OwnStationAgentInteractionSource,
}

enum OwnStationAgentInteractionSource {
    Snapshot(Box<BoundOwnStationResponse<RealmId, RealmStateSnapshot>>),
    Exact {
        before: Box<BoundOwnStationResponse<RealmId, RealmStateSnapshot>>,
        response: Box<BoundOwnStationResponse<
            (arkret_models_collaboration::exact_current_results::ExactCurrentResultsReadRequestBody, u64),
            arkret_models_collaboration::exact_current_results::ExactCurrentResultsReadOutcome,
        >>,
        after: Box<BoundOwnStationResponse<RealmId, RealmStateSnapshot>>,
    },
}

impl OwnStationAgentInteraction {
    pub fn value(
        &self,
    ) -> arkret_http_client::Result<
        &arkret_models_collaboration::exact_current_results::ExactCurrentResultsReadOutcome,
    > {
        match &self.source {
            OwnStationAgentInteractionSource::Snapshot(snapshot) => {
                snapshot.value()?;
            }
            OwnStationAgentInteractionSource::Exact {
                before,
                response,
                after,
            } => {
                before.value()?;
                response.value()?;
                after.value()?;
            }
        }
        Ok(&self.value)
    }

    pub fn into_value(
        self,
    ) -> arkret_http_client::Result<
        arkret_models_collaboration::exact_current_results::ExactCurrentResultsReadOutcome,
    > {
        self.value()?;
        Ok(self.value)
    }
}

/// Exact Agent mode read through its authenticated own Station, fenced by
/// original snapshots before and after. No governance endpoint discovery.
pub async fn read_own_station_agent_interaction(
    client: &OwnStationResultClient,
    realm: &RealmId,
    agent: &arkret_wire::AccountId,
) -> Result<OwnStationAgentInteraction> {
    use arkret_models_collaboration::agent_interaction::AgentInteractionExactCurrentSelector;
    use arkret_models_collaboration::exact_current_results::{
        ExactCurrentResultSelector, ExactCurrentResultsReadOutcome,
        ExactCurrentResultsReadRequestBody,
    };
    let before = client.snapshot_head(realm).await?;
    consume_bound_snapshot(&before, realm)?;
    let request = ExactCurrentResultsReadRequestBody {
        realm_id: realm.clone(),
        selector: ExactCurrentResultSelector::AgentInteraction(
            AgentInteractionExactCurrentSelector::new(agent.clone()),
        ),
    };
    let snapshot = before.value()?;
    if let Some(value) = crate::agent_interaction::present_from_snapshot(&request, snapshot)? {
        before.value()?;
        return Ok(OwnStationAgentInteraction {
            value,
            source: OwnStationAgentInteractionSource::Snapshot(Box::new(before)),
        });
    }
    let stream = CommitStreamRef::Realm {
        realm_id: realm.clone(),
    };
    let expected = snapshot
        .visible_stream_heads
        .iter()
        .find(|head| head.stream_ref == stream)
        .ok_or_else(|| protocol("Agent mode snapshot omits Realm head"))?;
    let result = client
        .exact_current_result(&request, snapshot.governance_generation)
        .await?;
    let after = client.snapshot_head(realm).await?;
    consume_bound_snapshot(&after, realm)?;
    let after_value = after.value()?;
    let (generation, result_head) = match result.value()? {
        ExactCurrentResultsReadOutcome::Present {
            governance_generation,
            effective_stream_head,
            ..
        }
        | ExactCurrentResultsReadOutcome::NeverWritten {
            governance_generation,
            effective_stream_head,
            ..
        } => (*governance_generation, effective_stream_head),
    };
    if before.session() != after.session()
        || generation != snapshot.governance_generation
        || generation != after_value.governance_generation
        || result_head != expected
        || after_value
            .visible_stream_heads
            .iter()
            .find(|head| head.stream_ref == stream)
            != Some(expected)
    {
        return Err(protocol("ordinary Agent mode read crossed a current cut"));
    }
    result.value()?;
    Ok(OwnStationAgentInteraction {
        value: result.value()?.clone(),
        source: OwnStationAgentInteractionSource::Exact {
            before: Box::new(before),
            response: Box::new(result),
            after: Box::new(after),
        },
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use std::io::{Read, Write};
    use std::sync::Arc;

    use arkret_http_client::own_station_results::{
        OwnStationSessionSnapshot, OwnStationSessionSource,
    };

    use super::*;

    struct Source(OwnStationSessionSnapshot);
    impl OwnStationSessionSource for Source {
        fn snapshot(&self) -> arkret_http_client::Result<OwnStationSessionSnapshot> {
            Ok(self.0.clone())
        }
    }
    fn client(
        bodies: Vec<serde_json::Value>,
    ) -> (OwnStationResultClient, std::thread::JoinHandle<()>) {
        let (client, server, _) = observed_client(bodies);
        (client, server)
    }
    pub(crate) fn observed_client(
        bodies: Vec<serde_json::Value>,
    ) -> (
        OwnStationResultClient,
        std::thread::JoinHandle<()>,
        Arc<std::sync::Mutex<Vec<String>>>,
    ) {
        let observed = Arc::new(std::sync::Mutex::new(Vec::new()));
        let server_observed = observed.clone();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}/", listener.local_addr().unwrap());
        let station = arkret_wire::DidCoreId::new("ak:did_core:web:station.example").unwrap();
        let binding = arkret_models_discovery::StationConnectionBinding {
            service_id: station.clone(),
            base_url: base.clone(),
            trust_domain: arkret_wire::TrustDomainId::new("ak:trust_domain:station.example")
                .unwrap(),
            auth_metadata: arkret_models_discovery::AuthMetadata::minimal(),
        };
        let snapshot = OwnStationSessionSnapshot::new(
            binding.clone(),
            arkret_wire::AccountId::new(
                arkret_wire::DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
                station.clone(),
            ),
            station,
            arkret_wire::SessionGrantId::from_issuance_digest([3; 32]),
            0,
            "test-grant".into(),
        )
        .unwrap()
        .with_provider_identity(Default::default());
        let raw = arkret_http_client::ClientBuilder::new(url::Url::parse(&base).unwrap())
            .allow_insecure_localhost()
            .auth(arkret_http_client::Auth::Bearer("test-grant".into()))
            .build()
            .unwrap();
        let server = std::thread::spawn(move || {
            for body in bodies {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(std::time::Duration::from_secs(10)))
                    .unwrap();
                let mut buffer = [0; 16384];
                let count = stream.read(&mut buffer).unwrap();
                let mut request_bytes = buffer[..count].to_vec();
                let header_end = loop {
                    if let Some(index) = request_bytes
                        .windows(4)
                        .position(|bytes| bytes == b"\r\n\r\n")
                    {
                        break index + 4;
                    }
                    let count = stream.read(&mut buffer).unwrap();
                    assert!(count > 0);
                    request_bytes.extend_from_slice(&buffer[..count]);
                };
                let headers =
                    String::from_utf8_lossy(&request_bytes[..header_end]).to_ascii_lowercase();
                let body_len = headers
                    .lines()
                    .find_map(|line| {
                        line.strip_prefix("content-length:")
                            .map(|value| value.trim().parse::<usize>().unwrap())
                    })
                    .unwrap_or(0);
                while request_bytes.len() < header_end + body_len {
                    let count = stream.read(&mut buffer).unwrap();
                    assert!(count > 0);
                    request_bytes.extend_from_slice(&buffer[..count]);
                }
                assert!(headers.contains("authorization: bearer test-grant"));
                server_observed
                    .lock()
                    .unwrap()
                    .push(headers.lines().next().unwrap().to_owned());
                let body = if let Some(key) = body.get("__service_key") {
                    let request: SignerKeysQueryRequestBody =
                        serde_json::from_slice(&request_bytes[header_end..header_end + body_len])
                            .unwrap();
                    let selector = request.queries[0].clone();
                    assert!(matches!(
                        selector,
                        SignerKeyQuerySelector::HistoricalEvent {
                            sender: HistoricalSignerKeyQuerySender::Service { .. }
                        }
                    ));
                    let result = if body
                        .get("__unavailable")
                        .and_then(serde_json::Value::as_bool)
                        == Some(true)
                    {
                        SignerKeyQueryOutcome::Unavailable { selector }
                    } else {
                        SignerKeyQueryOutcome::HistoricalServiceResolved {
                            selector,
                            key: serde_json::from_value(key.clone()).unwrap(),
                            accepted_at: crate::test_fixtures::at(3),
                        }
                    };
                    serde_json::to_value(arkret_models_identity::SignerKeysQueryOutcome {
                        request_id: request.request_id,
                        realm_id: request.realm_id,
                        recipient_account_id: request.recipient_account_id,
                        results: vec![result],
                    })
                    .unwrap()
                } else if let Some(key) = body.get("__signer_key") {
                    let request: SignerKeysQueryRequestBody =
                        serde_json::from_slice(&request_bytes[header_end..header_end + body_len])
                            .unwrap();
                    let key: arkret_models_identity::signer_key_operations::ResolvedSignerKey =
                        serde_json::from_value(key.clone()).unwrap();
                    let mut selector = request.queries[0].clone();
                    if let Some(expected) = body.get("__expected_native_target") {
                        let SignerKeyQuerySelector::HistoricalEvent {
                            sender:
                                HistoricalSignerKeyQuerySender::AccountDevice {
                                    actor,
                                    committed_event_ref,
                                    ..
                                },
                        } = &selector
                        else {
                            panic!("native self source must never use current selector")
                        };
                        assert_eq!(actor.as_account_id(), Some(&request.recipient_account_id));
                        assert_eq!(
                            serde_json::to_value(committed_event_ref).unwrap(),
                            *expected
                        );
                        assert_ne!(committed_event_ref, &key.authorization_ref);
                    }

                    if body
                        .get("__wrong_historical_target")
                        .and_then(serde_json::Value::as_bool)
                        == Some(true)
                        && let SignerKeyQuerySelector::HistoricalEvent {
                            sender:
                                arkret_models_identity::HistoricalSignerKeyQuerySender::AccountDevice {
                                    committed_event_ref,
                                    ..
                                },
                        } = &mut selector
                    {
                        committed_event_ref.stream_position += 1;
                    }
                    if body
                        .get("__wrong_historical_device")
                        .and_then(serde_json::Value::as_bool)
                        == Some(true)
                        && let SignerKeyQuerySelector::HistoricalEvent {
                            sender: HistoricalSignerKeyQuerySender::AccountDevice { device_id, .. },
                        } = &mut selector
                    {
                        *device_id = arkret_wire::DeviceId::new(
                            "ak:device:0196419b-0000-7000-8000-000000000002",
                        )
                        .unwrap();
                    }
                    serde_json::to_value(
                        arkret_models_identity::signer_key_operations::SignerKeysQueryOutcome {
                            request_id: request.request_id,
                            realm_id: request.realm_id,
                            recipient_account_id: request.recipient_account_id,
                            results: vec![if body
                                .get("__unavailable")
                                .and_then(serde_json::Value::as_bool)
                                == Some(true)
                            {
                                SignerKeyQueryOutcome::Unavailable { selector }
                            } else {
                                SignerKeyQueryOutcome::HistoricalResolved {
                                    selector,
                                    key,
                                    accepted_at: if body
                                        .get("__distinct_authorization_time")
                                        .and_then(serde_json::Value::as_bool)
                                        == Some(true)
                                    {
                                        crate::test_fixtures::at(4)
                                    } else {
                                        crate::test_fixtures::at(1)
                                    },
                                }
                            }],
                        },
                    )
                    .unwrap()
                } else if let Some(expected) = body.get("__expected_submission") {
                    let received: serde_json::Value =
                        serde_json::from_slice(&request_bytes[header_end..header_end + body_len])
                            .unwrap();
                    assert_eq!(
                        &received, expected,
                        "replay must retain its frozen signed Event"
                    );
                    body["__accepted"].clone()
                } else {
                    body
                };
                let bytes = serde_json::to_vec(&body).unwrap();
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
                    bytes.len()
                );
                stream.write_all(header.as_bytes()).unwrap();
                stream.write_all(&bytes).unwrap();
            }
        });
        (
            OwnStationResultClient::new(raw, binding, Arc::new(Source(snapshot))).unwrap(),
            server,
            observed,
        )
    }

    fn commit(
        position: u64,
        previous: Option<arkret_wire::RealmCommitId>,
    ) -> arkret_wire::RealmCommit {
        let event = crate::test_fixtures::event(
            4,
            arkret_wire::EventKind::RealmCreate,
            serde_json::json!({}),
        );
        let mut value =
            crate::test_fixtures::commit(4, &event, crate::test_fixtures::realm_stream(), position);
        value.previous_commit_ref = previous;
        let mut body = serde_json::to_value(&value).unwrap();
        body.as_object_mut().unwrap().remove("commit_id");
        body.as_object_mut().unwrap().remove("signature");
        value.commit_id = arkret_wire::RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
            arkret_canonical::canonical_json_bytes(&body).unwrap(),
        ));
        value
    }
    fn withheld(commit: arkret_wire::RealmCommit) -> serde_json::Value {
        serde_json::json!({"commit":commit,"event_disclosure":{"status":"withheld"}})
    }

    #[test]
    fn own_station_bound_factory_rejects_wrong_account_station_or_enrolled_origin() {
        // Host authentication is supplied by the existing live session source;
        // neither a viewer/profile row nor a caller-defined epoch can replace it.
        let station = arkret_wire::DidCoreId::new("ak:did_core:web:station.example").unwrap();
        let other = arkret_wire::DidCoreId::new("ak:did_core:web:other.example").unwrap();
        let binding = arkret_models_discovery::StationConnectionBinding {
            service_id: station.clone(),
            base_url: "http://127.0.0.1:32123/".into(),
            trust_domain: arkret_wire::TrustDomainId::new("ak:trust_domain:station.example")
                .unwrap(),
            auth_metadata: arkret_models_discovery::AuthMetadata::minimal(),
        };
        let account = arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            station.clone(),
        );
        assert!(
            OwnStationSessionSnapshot::new(
                binding.clone(),
                arkret_wire::AccountId::new(account.principal_id.clone(), other),
                station.clone(),
                arkret_wire::SessionGrantId::from_issuance_digest([3; 32]),
                0,
                "test-grant".into(),
            )
            .is_err()
        );
        let session = OwnStationSessionSnapshot::new(
            binding.clone(),
            account,
            station,
            arkret_wire::SessionGrantId::from_issuance_digest([3; 32]),
            0,
            "test-grant".into(),
        )
        .unwrap()
        .with_provider_identity(Default::default());
        let wrong_origin = arkret_http_client::ClientBuilder::new(
            url::Url::parse("http://127.0.0.1:32124/").unwrap(),
        )
        .allow_insecure_localhost()
        .auth(arkret_http_client::Auth::Bearer("test-grant".into()))
        .build()
        .unwrap();
        assert!(
            OwnStationResultClient::new(wrong_origin, binding, Arc::new(Source(session))).is_err()
        );
    }

    #[tokio::test]
    async fn own_station_full_producer_actual_signature_and_exact_historical_query() {
        use arkret_signatures::{Ed25519DetachedJwsSigner, SignEventOptions, sign_event};
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[41; 32]);
        let method = format!(
            "did:web:alice.example#{}",
            crate::test_fixtures::device_id().as_str()
        );
        let mut event = crate::test_fixtures::event(
            4,
            arkret_wire::EventKind::MessageCreate,
            serde_json::json!({
                "strand_id": "ak:strand:AXh0mpVGb536xVxbSPfM4Wc_1WuXAxTYgmtXEncKM9T0",
                "track_name": "discussion",
                "content": {"kind": "ak.content.text", "body": "producer fixture"}
            }),
        );
        event.actor_id = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            arkret_wire::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        ));
        event.producer_proof = None;
        let mut authored = arkret_wire::AuthoredEvent::finalize_with_digest_suite(
            event,
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap();
        sign_event(
            &mut authored,
            &Ed25519DetachedJwsSigner::new(signing_key.clone(), method),
            SignEventOptions::new().with_created_at(crate::test_fixtures::at(0)),
        )
        .unwrap();
        let event = authored.into_event();
        let mut accepted = commit(7, Some(arkret_wire::RealmCommitId::from_digest([6; 32])));
        accepted.event_ref = event.event_id.clone();
        accepted.committed_at = crate::test_fixtures::at(2);
        let mut body = serde_json::to_value(&accepted).unwrap();
        body.as_object_mut().unwrap().remove("commit_id");
        body.as_object_mut().unwrap().remove("signature");
        accepted.commit_id = arkret_wire::RealmCommitId::from_digest(
            arkret_canonical::sha256_bytes(arkret_canonical::canonical_json_bytes(&body).unwrap()),
        );
        let mut reference = CommittedEventRef {
            event_id: event.event_id.clone(),
            commit_id: accepted.commit_id.clone(),
            stream_ref: accepted.stream_ref.clone(),
            stream_position: 7,
        };
        let mut authorization = commit(0, None);
        authorization.realm_id = arkret_wire::RealmId::from_event_id(&authorization.event_ref);
        authorization.stream_ref = arkret_wire::CommitStreamRef::Realm {
            realm_id: authorization.realm_id.clone(),
        };
        let mut authorization_body = serde_json::to_value(&authorization).unwrap();
        authorization_body
            .as_object_mut()
            .unwrap()
            .remove("commit_id");
        authorization_body
            .as_object_mut()
            .unwrap()
            .remove("signature");
        authorization.commit_id =
            arkret_wire::RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
                arkret_canonical::canonical_json_bytes(&authorization_body).unwrap(),
            ));
        let authorization_ref = CommittedEventRef {
            event_id: authorization.event_ref.clone(),
            commit_id: authorization.commit_id.clone(),
            stream_ref: authorization.stream_ref.clone(),
            stream_position: authorization.stream_position,
        };
        let original_key = arkret_models_identity::ResolvedSignerKey {
            public_key_b64u: arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
                signing_key.verifying_key().as_bytes(),
            ))
            .unwrap(),
            authorization_ref: authorization_ref.clone(),
            revision: arkret_wire::CurrentRevision {
                commit_id: authorization.commit_id.clone(),
                stream_position: 0,
            },
            governance_generation: 0,
        };
        let original_fact =
            arkret_models_collaboration::authority_commit::HumanHistoricalSignerFact {
                event_id: event.event_id.clone(),
                actor: event.actual_signer().clone(),
                device_id: crate::test_fixtures::device_id(),
                verification_method: event
                    .producer_proof
                    .as_ref()
                    .unwrap()
                    .verification_method
                    .clone(),
                key: original_key,
                accepted_at: crate::test_fixtures::at(1),
            };
        original_fact
            .validate_event_binding(&event, arkret_canonical::DigestSuite::Sha256)
            .unwrap();
        accepted.producer_signer_fact_digest = Some(original_fact.digest().unwrap());
        let mut body = serde_json::to_value(&accepted).unwrap();
        body.as_object_mut().unwrap().remove("commit_id");
        body.as_object_mut().unwrap().remove("signature");
        accepted.commit_id = arkret_wire::RealmCommitId::from_digest(
            arkret_canonical::sha256_bytes(arkret_canonical::canonical_json_bytes(&body).unwrap()),
        );
        reference.commit_id = accepted.commit_id.clone();
        assert_ne!(authorization_ref, reference);
        assert_ne!(authorization.committed_at, accepted.committed_at);
        for valid_key in [true, false] {
            let public_key = if valid_key {
                signing_key.verifying_key()
            } else {
                ed25519_dalek::SigningKey::from_bytes(&[42; 32]).verifying_key()
            };
            let key = arkret_models_identity::signer_key_operations::ResolvedSignerKey {
                public_key_b64u: arkret_wire::Base64UrlString::new(
                    arkret_canonical::base64url_encode(public_key.as_bytes()),
                )
                .unwrap(),
                authorization_ref: authorization_ref.clone(),
                revision: arkret_wire::CurrentRevision {
                    commit_id: authorization.commit_id.clone(),
                    stream_position: 0,
                },
                governance_generation: 0,
            };
            let (client, server) = client(vec![
                serde_json::json!({"commit":accepted,"event":event}),
                serde_json::json!({
                    "committed_events":[{"commit":accepted,"event":event}],
                    "readable_floor": ReadableFloor {
                        oldest_position: 7,
                        floor_commit_id: accepted.commit_id.clone(),
                        floor_reason: arkret_wire::ReadableFloorReason::MembershipJoin,
                    },
                    "truncated":false
                }),
                serde_json::json!({"__signer_key":key}),
            ]);
            let mut replica = OwnStationReplica::new(event.realm_id.clone());
            let response = client.committed_event_get(&event.event_id).await.unwrap();
            let result = replica
                .restore_bound_anchor(&client, &reference, response)
                .await;
            assert_eq!(
                result.is_ok(),
                valid_key,
                "real detached producer signature gate: {result:?}"
            );
            assert_eq!(
                replica.head(&accepted.stream_ref).is_some(),
                valid_key,
                "failed proof must not publish a head"
            );
            server.join().unwrap();
        }
        assert_bounded_window_dependencies(&event, &accepted, &original_fact.key).await;
        let mut legacy = accepted.clone();
        legacy.producer_signer_fact_digest = None;
        let mut legacy_body = serde_json::to_value(&legacy).unwrap();
        legacy_body.as_object_mut().unwrap().remove("commit_id");
        legacy_body.as_object_mut().unwrap().remove("signature");
        legacy.commit_id = arkret_wire::RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
            arkret_canonical::canonical_json_bytes(&legacy_body).unwrap(),
        ));
        let legacy_ref = CommittedEventRef {
            commit_id: legacy.commit_id.clone(),
            ..reference.clone()
        };
        let (source, server) = client(vec![
            serde_json::json!({"commit":legacy,"event":event}),
            serde_json::json!({"committed_events":[{"commit":legacy,"event":event}],"readable_floor":{"oldest_position":7,"floor_commit_id":legacy.commit_id,"floor_reason":"membership_join"},"truncated":false}),
        ]);
        let mut legacy_replica = OwnStationReplica::new(event.realm_id.clone());
        let original = source.committed_event_get(&event.event_id).await.unwrap();
        let error = legacy_replica
            .restore_bound_anchor(&source, &legacy_ref, original)
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("original ordinary Human signer source is unavailable")
        );
        assert!(legacy_replica.context.is_none());
        assert!(legacy_replica.heads.is_empty() && legacy_replica.generations.is_empty());
        server.join().unwrap();
        // A real source-bound self acceptance is sufficient: no scan response
        // exists in this server, and this operation owns no replica mutation.
        for refusal in [
            "none",
            "wrong_key",
            "wrong_historical_target",
            "wrong_request",
            "wrong_session",
            "commit_content",
            "event_content",
        ] {
            let mut frozen_event = event.clone();
            if refusal == "event_content" {
                frozen_event.payload.insert(
                    "content".into(),
                    serde_json::json!({"kind":"ak.content.text","body":"tampered"}),
                );
            }
            let request = SelfAuthoritySubmitRequest::Event(
                arkret_wire::EventAdmissionSubmission::new(frozen_event),
            );
            let mut supplied = accepted.clone();
            if refusal == "commit_content" {
                supplied.committed_at = crate::test_fixtures::at(3);
            }
            let outcome = SelfAuthoritySubmitOutcome::Ordinary(
                arkret_wire::AuthoritySubmitOutcome::Accepted {
                    status: arkret_wire::AuthorityCommitStatus::Committed,
                    commit: supplied,
                },
            );
            let mut bodies = vec![serde_json::to_value(outcome).unwrap()];
            if matches!(refusal, "none" | "wrong_key" | "wrong_historical_target") {
                let public_key = if refusal != "wrong_key" {
                    signing_key.verifying_key()
                } else {
                    ed25519_dalek::SigningKey::from_bytes(&[42; 32]).verifying_key()
                };
                let key = arkret_models_identity::ResolvedSignerKey {
                    public_key_b64u: arkret_wire::Base64UrlString::new(
                        arkret_canonical::base64url_encode(public_key.as_bytes()),
                    )
                    .unwrap(),
                    authorization_ref: authorization_ref.clone(),
                    revision: arkret_wire::CurrentRevision {
                        commit_id: authorization.commit_id.clone(),
                        stream_position: 0,
                    },
                    governance_generation: 0,
                };
                bodies.push(serde_json::json!({"__signer_key":key,"__wrong_historical_target":refusal == "wrong_historical_target"}));
            }
            let (source, server) = client(bodies);
            let response = source
                .submit_to_realm_authority(
                    &request,
                    &arkret_http_client::ClientRequestOptions::default(),
                )
                .await
                .unwrap();
            let mut expected = request.clone();
            if refusal == "wrong_request" {
                let SelfAuthoritySubmitRequest::Event(value) = &mut expected else {
                    unreachable!()
                };
                value.event.created_at = crate::test_fixtures::at(3);
            }
            let replica = OwnStationReplica::new(event.realm_id.clone());
            let result = if refusal == "wrong_session" {
                let (foreign, idle) = client(vec![]);
                idle.join().unwrap();
                consume_bound_submission(&foreign, &expected, response).await
            } else {
                consume_bound_submission(&source, &expected, response).await
            };
            assert_eq!(
                result.is_ok(),
                refusal == "none",
                "bound acceptance gate: {refusal}"
            );
            assert!(
                replica.head(&accepted.stream_ref).is_none(),
                "acceptance consumption never advances history"
            );
            server.join().unwrap();
        }
    }

    async fn assert_bounded_window_dependencies(
        event: &arkret_wire::Event,
        accepted: &arkret_wire::RealmCommit,
        key: &arkret_models_identity::ResolvedSignerKey,
    ) {
        let reference = CommittedEventRef {
            event_id: event.event_id.clone(),
            commit_id: accepted.commit_id.clone(),
            stream_ref: accepted.stream_ref.clone(),
            stream_position: accepted.stream_position,
        };
        let circle = CommitStreamRef::Circle {
            realm_id: event.realm_id.clone(),
            circle_id: arkret_wire::CircleId::from_event_id(&event.event_id),
        };
        let sidecar = CommitStreamRef::Sidecar {
            realm_id: event.realm_id.clone(),
            sidecar_id: arkret_wire::SidecarId::from_event_id(&event.event_id),
        };
        for stream in [circle, sidecar] {
            for failure in ["none", "withheld", "wrong_ref", "wrong_key"] {
                let anchor = CommitStreamHead {
                    stream_ref: stream.clone(),
                    stream_position: 9,
                    commit_id: arkret_wire::RealmCommitId::from_digest([9; 32]),
                };
                let mut tail = commit(10, Some(anchor.commit_id.clone()));
                tail.stream_ref = stream.clone();
                tail = seal_native_fixture_commit(tail);
                let old = snapshot_at_floor(vec![head(accepted), anchor.clone()], 7);
                let current = snapshot_at_floor(vec![head(accepted), head(&tail)], 7);
                let mut dependency = reference.clone();
                if failure == "wrong_ref" {
                    dependency.commit_id = arkret_wire::RealmCommitId::from_digest([90; 32]);
                }
                let basis = StreamWindowStartBasis {
                    anchor_position: anchor.stream_position,
                    anchor_commit_ref: anchor.commit_id,
                    snapshot_ref: old.snapshot_id.clone(),
                    governance_generation: 0,
                    accepted_dependency_refs: Some(vec![dependency]),
                };
                let window =
                    arkret_models_collaboration::sync_frames::account_sync::RealmStreamWindow {
                        stream_ref: stream.clone(),
                        head_commit_ref: tail.commit_id.clone(),
                        next_position: 11,
                        limited: true,
                        window_limit: 1,
                        complete: true,
                        preview_only: None,
                        window_start_basis: Some(basis),
                        e2ee_epoch: None,
                    };
                let original = serde_json::json!({"commit":accepted,"event":event});
                let mut bodies = vec![
                    serde_json::to_value(current).unwrap(),
                    serde_json::to_value(old).unwrap(),
                    if failure == "withheld" {
                        withheld(accepted.clone())
                    } else {
                        original.clone()
                    },
                ];
                if !matches!(failure, "withheld" | "wrong_ref") {
                    bodies.push(serde_json::json!({"committed_events":[original],"readable_floor":{
                        "oldest_position":7,"floor_commit_id":accepted.commit_id,"floor_reason":"membership_join"},"truncated":false}));
                    let mut key = key.clone();
                    if failure == "wrong_key" {
                        key.public_key_b64u =
                            arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
                                ed25519_dalek::SigningKey::from_bytes(&[42; 32])
                                    .verifying_key()
                                    .as_bytes(),
                            ))
                            .unwrap();
                    }
                    bodies.push(serde_json::json!({"__signer_key":key}));
                }
                if failure == "none" {
                    bodies.push(serde_json::json!({"committed_events":[withheld(tail.clone())],"readable_floor":{
                        "oldest_position":7,"floor_commit_id":arkret_wire::RealmCommitId::from_digest([7;32]),"floor_reason":"membership_join"},"truncated":false}));
                }
                let (source, server, observed) = observed_client(bodies);
                let current = source.snapshot_head(&event.realm_id).await.unwrap();
                let mut replica = OwnStationReplica::new(event.realm_id.clone());
                let outcome = crate::history_recovery::window_pages(
                    &source,
                    &event.realm_id,
                    &current,
                    &mut replica,
                    &window,
                )
                .await;
                assert_eq!(outcome.is_ok(), failure == "none", "{stream:?} {failure}");
                assert!(
                    replica.head(&accepted.stream_ref).is_none(),
                    "dependency admission must never advance another stream"
                );
                if failure == "none" {
                    let pages = outcome.unwrap().unwrap();
                    assert_eq!(pages.len(), 1);
                    assert_eq!(pages[0].rows().unwrap()[0].commit(), &tail);
                    assert_eq!(replica.head(&stream), Some(&head(&tail)));
                } else {
                    assert!(replica.head(&stream).is_none());
                }
                server.join().unwrap();
                let requests = observed.lock().unwrap();
                assert_eq!(
                    requests.len(),
                    match failure {
                        "none" => 6,
                        "wrong_key" => 5,
                        _ => 3,
                    },
                    "exact dependency admission must stay bounded independently of the missing prefix: {requests:?}"
                );
            }
        }
    }

    // Transport-source fixture: original authorization coordinates are fixed
    // independently of the target. This exercises real bound HTTP decoding,
    // historical query, content IDs and Device Ed, not a PG admission/archive.
    fn native_self_genesis_fixture(
        controller_name: &str,
    ) -> (
        arkret_wire::Event,
        arkret_wire::RealmCommit,
        arkret_models_identity::ResolvedSignerKey,
    ) {
        use arkret_models_collaboration::events_payloads::realm::{RealmGenesis, RealmPurpose};
        use arkret_signatures::{Ed25519DetachedJwsSigner, SignEventOptions, sign_event};
        let station = arkret_wire::DidCoreId::new("ak:did_core:web:station.example").unwrap();
        let controller = arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new(format!("ak:did_core:web:{controller_name}.example"))
                .unwrap(),
            station.clone(),
        );
        let endpoint = url::Url::parse("https://agent.example/").unwrap();
        let next_key = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
            ed25519_dalek::SigningKey::from_bytes(&[45; 32])
                .verifying_key()
                .as_bytes(),
        );
        let inception = arkret_signatures::webvh::prepare_agent_inception(
            &arkret_signatures::webvh::AgentInceptionInput {
                principal_endpoint: &endpoint,
                local_id: "fixture-agent",
                controller_principal_id: &controller.principal_id,
                version_time: crate::test_fixtures::at(0),
                root_seed: &[44; 32],
                next_root_public_key_multibase: &next_key,
            },
        )
        .unwrap();
        let agent_did = arkret_wire::Did::new(inception.did.clone()).unwrap();
        let agent_core = arkret_wire::project_did_to_core_id(&agent_did).unwrap();
        let object = RealmGenesis::new(
            RealmPurpose::AgentControl,
            arkret_wire::GenesisSalt::new("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap(),
            arkret_wire::TrustDomainId::new("ak:trust_domain:station.example").unwrap(),
            arkret_wire::SecurityClass::Standard,
            station.clone(),
            arkret_wire::JoinRule::Invite,
            arkret_wire::HistoryAccess::SinceJoin,
            arkret_wire::Discoverability::Listed,
            None,
            Some(arkret_models_identity::ResolutionCommitment {
                did: agent_did.clone(),
                method_history_head: arkret_canonical::canonical_sha256(&inception.log_entry)
                    .unwrap(),
                version_id: inception.log_entry["versionId"].as_str().unwrap().into(),
            }),
        )
        .unwrap();
        let payload =
            arkret_models_collaboration::events_payloads::realm::RealmCreatePayload::new(object)
                .to_value()
                .unwrap();
        let mut event =
            crate::test_fixtures::event(91, arkret_wire::EventKind::RealmCreate, payload);
        event.actor_id =
            arkret_wire::ActorId::account(arkret_wire::AccountId::new(agent_core, station));
        event.executed_by = Some(arkret_wire::ActorId::account(controller));
        event.authorization_ref = Some(arkret_wire::AuthorizationRef::from(
            arkret_wire::DidUrl::new(format!("{}#managed-controller", agent_did.as_str())).unwrap(),
        ));
        event.scope_ref = arkret_wire::ScopeRef::RealmGenesis;
        event.created_at = crate::test_fixtures::at(2);
        event.producer_proof = None;
        let mut authored = arkret_wire::AuthoredEvent::finalize_with_digest_suite(
            event,
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap();
        let key = ed25519_dalek::SigningKey::from_bytes(&[41; 32]);
        sign_event(
            &mut authored,
            &Ed25519DetachedJwsSigner::new(
                key.clone(),
                format!(
                    "did:web:{controller_name}.example#{}",
                    crate::test_fixtures::device_id().as_str()
                ),
            ),
            SignEventOptions::new().with_created_at(crate::test_fixtures::at(2)),
        )
        .unwrap();
        let event = authored.into_event();
        let accepted = seal_native_fixture_commit(crate::test_fixtures::commit(
            91,
            &event,
            arkret_wire::CommitStreamRef::Realm {
                realm_id: event.realm_id.clone(),
            },
            0,
        ));
        // Three independent coordinates: original device authorization,
        // original authorizing cut revision and native genesis target.
        let authorization_event =
            arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [81; 32]);
        let authorization_commit = arkret_wire::RealmCommitId::from_digest([82; 32]);
        let revision_commit = arkret_wire::RealmCommitId::from_digest([83; 32]);
        let historical = arkret_models_identity::ResolvedSignerKey {
            public_key_b64u: arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
                key.verifying_key().as_bytes(),
            ))
            .unwrap(),
            authorization_ref: CommittedEventRef {
                event_id: authorization_event.clone(),
                commit_id: authorization_commit,
                stream_ref: arkret_wire::CommitStreamRef::Realm {
                    realm_id: RealmId::from_event_id(&authorization_event),
                },
                stream_position: 0,
            },
            revision: arkret_wire::CurrentRevision {
                commit_id: revision_commit,
                stream_position: 1,
            },
            governance_generation: 0,
        };
        (event, accepted, historical)
    }
    fn seal_native_fixture_commit(
        mut commit: arkret_wire::RealmCommit,
    ) -> arkret_wire::RealmCommit {
        commit.committed_at = crate::test_fixtures::at(3);
        let mut body = serde_json::to_value(&commit).unwrap();
        body.as_object_mut().unwrap().remove("commit_id");
        body.as_object_mut().unwrap().remove("signature");
        commit.commit_id = arkret_wire::RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
            arkret_canonical::canonical_json_bytes(&body).unwrap(),
        ));
        let mut unsigned = serde_json::to_value(&commit).unwrap();
        unsigned.as_object_mut().unwrap().remove("signature");
        commit.signature = arkret_signatures::detached_object::sign_detached_object(
            &unsigned,
            arkret_wire::DetachedSignatureContext::RealmCommit,
            arkret_wire::DidUrl::new("did:web:station.example#notary").unwrap(),
            commit.committed_at,
            &ed25519_dalek::SigningKey::from_bytes(&[43; 32]),
        )
        .unwrap();
        commit
    }

    fn native_human_pcr_successor_fixture(
        kind: arkret_wire::EventKind,
        account_name: &str,
        foreign_station: bool,
    ) -> (
        arkret_wire::Event,
        arkret_wire::RealmCommit,
        arkret_models_identity::ResolvedSignerKey,
    ) {
        use arkret_models_collaboration::events_payloads::key_backup::{
            ControllerBackupTrustAnchor, UnsignedKeyBackupActiveSeries,
        };
        use arkret_signatures::{Ed25519DetachedJwsSigner, SignEventOptions, sign_event};
        use ed25519_dalek::Signer as _;

        let (genesis, _, mut historical) = native_self_genesis_fixture(account_name);
        let mut actor = genesis.executed_by.unwrap();
        if foreign_station {
            actor = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                actor.as_account_id().unwrap().principal_id.clone(),
                arkret_wire::DidCoreId::new("ak:did_core:web:other.example").unwrap(),
            ));
        }
        let realm = historical.authorization_ref.stream_ref.realm_id().clone();
        historical.authorization_ref.stream_position = 1;
        historical.revision.stream_position = 2;
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[41; 32]);
        let method = arkret_wire::DidUrl::new(format!(
            "did:web:{account_name}.example#{}",
            crate::test_fixtures::device_id().as_str(),
        ))
        .unwrap();
        let payload = match kind {
            arkret_wire::EventKind::KeyBackupActiveSeries => {
                let unsigned = UnsignedKeyBackupActiveSeries::new(
                    actor.clone(),
                    serde_json::from_value(serde_json::json!("secret_storage")).unwrap(),
                    arkret_wire::BackupSeriesId::new(
                        "ak:backup_series:0196419b-0000-7000-8000-000000000010",
                    )
                    .unwrap(),
                    1,
                    vec![],
                    historical.revision.commit_id.clone(),
                    crate::test_fixtures::at(2),
                    method.clone(),
                    ControllerBackupTrustAnchor {
                        authorize_event_id: historical.authorization_ref.event_id.clone(),
                        generation_ref: 1,
                    },
                )
                .unwrap();
                let signature = signing_key.sign(&unsigned.signing_payload_bytes().unwrap());
                serde_json::to_value(
                    unsigned
                        .attach_signature(
                            arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
                                signature.to_bytes(),
                            ))
                            .unwrap(),
                        )
                        .unwrap(),
                )
                .unwrap()
            }
            arkret_wire::EventKind::DeviceRevoke => {
                let payload: arkret_models_collaboration::events_payloads::device_identity::DeviceRevokePayload =
                    serde_json::from_value(serde_json::json!({
                        "device_id": "ak:device:0196419b-0000-7000-8000-000000000002",
                        "revoked_by": crate::test_fixtures::device_id(),
                        "revoked_at": "2026-09-16T00:00:02.000Z",
                        "reason": "security_rotation",
                    })).unwrap();
                payload.validate().unwrap();
                serde_json::to_value(payload).unwrap()
            }
            _ => unreachable!(),
        };
        let mut event = crate::test_fixtures::event(92, kind, payload);
        event.actor_id = actor;
        event.realm_id = realm.clone();
        event.scope_ref = arkret_wire::ScopeRef::Realm {
            realm_id: realm.clone(),
        };
        event.created_at = crate::test_fixtures::at(2);
        event.producer_proof = None;
        let mut authored = arkret_wire::AuthoredEvent::finalize_with_digest_suite(
            event,
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap();
        sign_event(
            &mut authored,
            &Ed25519DetachedJwsSigner::new(signing_key, method.to_string()),
            SignEventOptions::new().with_created_at(crate::test_fixtures::at(2)),
        )
        .unwrap();
        let event = authored.into_event();
        let mut commit =
            crate::test_fixtures::commit(92, &event, CommitStreamRef::Realm { realm_id: realm }, 3);
        commit.previous_commit_ref = Some(historical.revision.commit_id.clone());
        (event, seal_native_fixture_commit(commit), historical)
    }

    #[tokio::test]
    async fn ordinary_applet_service_consumption_verifies_the_original_ed25519_and_minimal_binding()
    {
        use arkret_models_collaboration::authority_commit::ServiceHistoricalSignerFact;
        use arkret_models_identity::ServiceHistoricalSigningKey;
        let suite = arkret_canonical::DigestSuite::Sha256;
        let mut event = crate::test_fixtures::event(
            71,
            arkret_wire::EventKind::MessageCreate,
            serde_json::json!({"content":{"kind":"ak.content.text","body":"original Service"}}),
        );
        let coordinate = |byte| CommittedEventRef {
            event_id: arkret_wire::EventId::from_digest(suite, [byte; 32]),
            commit_id: arkret_wire::RealmCommitId::from_digest([byte; 32]),
            stream_ref: crate::test_fixtures::realm_stream(),
            stream_position: 0,
        };
        event.applet_id = Some(
            arkret_wire::AppletId::new("ak:applet:019b0000-0000-7000-8000-000000000071").unwrap(),
        );
        event.authorization_ref =
            Some(arkret_wire::GrantId::from_event_id(&coordinate(72).event_id).into());
        let method = arkret_wire::DidUrl::new("did:web:alice.example#producer").unwrap();
        event.producer_proof = None;
        let mut authored =
            arkret_wire::AuthoredEvent::finalize_with_digest_suite(event, suite).unwrap();
        arkret_signatures::sign_event(
            &mut authored,
            &arkret_signatures::Ed25519DetachedJwsSigner::from_seed([73; 32], method.to_string()),
            arkret_signatures::SignEventOptions::new().with_created_at(crate::test_fixtures::at(0)),
        )
        .unwrap();
        let event = authored.into_event();
        let fact = ServiceHistoricalSignerFact {
            event_id: event.event_id.clone(),
            actor: event.actual_signer().clone(),
            verification_method: method,
            key: ServiceHistoricalSigningKey {
                public_key_b64u: arkret_wire::Base64UrlString::new(
                    arkret_canonical::base64url_encode(
                        ed25519_dalek::SigningKey::from_bytes(&[73; 32])
                            .verifying_key()
                            .as_bytes(),
                    ),
                )
                .unwrap(),
                applet_id: event.applet_id.clone().unwrap(),
                registration_epoch: arkret_wire::Hash::new(format!("sha256:{}", "74".repeat(32)))
                    .unwrap(),
                registration_ref: coordinate(71),
                authorization_ref: coordinate(72),
                effective_scope: event.scope_ref.clone(),
            },
            accepted_at: crate::test_fixtures::at(3),
        };
        let mut accepted =
            crate::test_fixtures::commit(75, &event, crate::test_fixtures::realm_stream(), 2);
        accepted.producer_signer_fact_digest = Some(fact.digest().unwrap());
        let full = arkret_wire::CommittedEventFullView {
            event,
            commit: seal_native_fixture_commit(accepted),
        };
        for refusal in [
            "none",
            "unavailable",
            "wrong_key",
            "wrong_epoch",
            "wrong_grant",
        ] {
            let mut key = fact.key.clone();
            match refusal {
                "wrong_key" => {
                    key.public_key_b64u =
                        arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
                            ed25519_dalek::SigningKey::from_bytes(&[76; 32])
                                .verifying_key()
                                .as_bytes(),
                        ))
                        .unwrap()
                }
                "wrong_epoch" => {
                    key.registration_epoch =
                        arkret_wire::Hash::new(format!("sha256:{}", "76".repeat(32))).unwrap()
                }
                "wrong_grant" => key.authorization_ref = coordinate(76),
                _ => {}
            }
            let (client, server, observed) = observed_client(vec![
                serde_json::json!({"__service_key":key,"__unavailable":refusal=="unavailable"}),
            ]);
            let result = verify_row(&client, &CommittedEventView::Full(full.clone())).await;
            assert_eq!(result.is_ok(), refusal == "none", "{refusal}: {result:?}");
            server.join().unwrap();
            assert_eq!(observed.lock().unwrap().len(), 1);
        }
    }

    #[tokio::test]
    async fn bound_self_human_pcr_successors_verify_original_authorization_and_exact_replay() {
        for kind in [
            arkret_wire::EventKind::KeyBackupActiveSeries,
            arkret_wire::EventKind::DeviceRevoke,
        ] {
            for refusal in [
                "none",
                "replay",
                "unavailable",
                "wrong_key",
                "wrong_target",
                "wrong_device",
                "ordinary_authorization",
                "wrong_account",
                "wrong_station",
                "wrong_request",
                "wrong_session",
                "wrong_slot",
                "commit_content",
                "event_content",
                "wrong_digest",
            ] {
                let (event, mut accepted, mut key) = native_human_pcr_successor_fixture(
                    kind.clone(),
                    if refusal == "wrong_account" {
                        "bob"
                    } else {
                        "alice"
                    },
                    refusal == "wrong_station",
                );
                let mut event = event;
                if refusal == "event_content" {
                    event.created_at = crate::test_fixtures::at(4);
                }
                if refusal == "wrong_slot" {
                    accepted.event_ref = arkret_wire::EventId::from_digest(
                        arkret_canonical::DigestSuite::Sha256,
                        [98; 32],
                    );
                }
                if refusal == "wrong_digest" {
                    accepted.producer_signer_fact_digest = Some(
                        arkret_wire::Hash::new(format!("sha256:{}", "00".repeat(32))).unwrap(),
                    );
                }
                accepted = seal_native_fixture_commit(accepted);
                if refusal == "commit_content" {
                    accepted.committed_at = crate::test_fixtures::at(4);
                }
                if refusal == "wrong_key" {
                    key.public_key_b64u =
                        arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
                            ed25519_dalek::SigningKey::from_bytes(&[42; 32])
                                .verifying_key()
                                .as_bytes(),
                        ))
                        .unwrap();
                }
                if refusal == "ordinary_authorization" {
                    key.authorization_ref.stream_ref = CommitStreamRef::Realm {
                        realm_id: RealmId::from_event_id(&arkret_wire::EventId::from_digest(
                            arkret_canonical::DigestSuite::Sha256,
                            [95; 32],
                        )),
                    };
                }
                let needs_query = matches!(
                    refusal,
                    "none"
                        | "replay"
                        | "unavailable"
                        | "wrong_key"
                        | "wrong_target"
                        | "wrong_device"
                        | "ordinary_authorization"
                        | "wrong_digest"
                );
                let request = SelfAuthoritySubmitRequest::Event(
                    arkret_wire::EventAdmissionSubmission::new(event.clone()),
                );
                let outcome = SelfAuthoritySubmitOutcome::Ordinary(
                    arkret_wire::AuthoritySubmitOutcome::Accepted {
                        status: arkret_wire::AuthorityCommitStatus::Committed,
                        commit: accepted.clone(),
                    },
                );
                let mut bodies = vec![serde_json::json!({
                    "__expected_submission": request, "__accepted": outcome,
                })];
                if needs_query {
                    bodies.push(serde_json::json!({
                        "__signer_key": key,
                        "__expected_native_target": CommittedEventRef {
                            event_id: event.event_id.clone(), commit_id: accepted.commit_id.clone(),
                            stream_ref: accepted.stream_ref.clone(), stream_position: accepted.stream_position,
                        },
                        "__unavailable": refusal == "unavailable",
                        "__wrong_historical_target": refusal == "wrong_target",
                        "__wrong_historical_device": refusal == "wrong_device",
                    }));
                }
                let passes = matches!(refusal, "none" | "replay");
                if refusal == "replay" {
                    bodies.extend(bodies.clone());
                }
                let (source, server, observed) = observed_client(bodies);
                for _ in 0..if refusal == "replay" { 2 } else { 1 } {
                    let fetched = source
                        .submit_to_realm_authority(
                            &request,
                            &arkret_http_client::ClientRequestOptions::default(),
                        )
                        .await;
                    if fetched.is_err() {
                        assert!(!passes, "{kind:?}: {refusal}");
                        continue;
                    }
                    let response = fetched.unwrap();
                    let mut expected = request.clone();
                    if refusal == "wrong_request" {
                        let SelfAuthoritySubmitRequest::Event(value) = &mut expected else {
                            unreachable!()
                        };
                        value.event.created_at = crate::test_fixtures::at(4);
                    }
                    let result = if refusal == "wrong_session" {
                        let (foreign, idle) = client(vec![]);
                        idle.join().unwrap();
                        consume_bound_submission(&foreign, &expected, response).await
                    } else {
                        consume_bound_submission(&source, &expected, response).await
                    };
                    assert_eq!(result.is_ok(), passes, "{kind:?}: {refusal}: {result:?}");
                    if passes {
                        assert_eq!(result.unwrap().into_value().unwrap(), outcome);
                    }
                }
                server.join().unwrap();
                let observed = observed.lock().unwrap();
                assert_eq!(
                    observed.len(),
                    if refusal == "replay" {
                        4
                    } else if needs_query {
                        2
                    } else {
                        1
                    }
                );
                assert!(
                    observed
                        .iter()
                        .all(|line| line.starts_with("post /_arkret/self/events ")
                            || line.starts_with("post /_arkret/self/signer-keys/query ")),
                    "self acceptance must not open current or PCR scan operations"
                );
            }
        }
    }

    #[tokio::test]
    async fn bound_self_agent_genesis_actual_historical_ed_and_closed_source_refusals() {
        for refusal in [
            "none",
            "unavailable",
            "bad_ed",
            "wrong_target",
            "wrong_session",
            "wrong_request",
            "wrong_account",
            "wrong_slot",
            "nonzero_position",
            "distinct_authorization_time",
        ] {
            let (event, mut accepted, mut key) =
                native_self_genesis_fixture(if refusal == "wrong_account" {
                    "bob"
                } else {
                    "alice"
                });
            if refusal == "wrong_slot" {
                accepted.event_ref = arkret_wire::EventId::from_digest(
                    arkret_canonical::DigestSuite::Sha256,
                    [98; 32],
                );
            }
            if refusal == "nonzero_position" {
                accepted.stream_position = 1;
                accepted.previous_commit_ref =
                    Some(arkret_wire::RealmCommitId::from_digest([99; 32]));
            }
            accepted = seal_native_fixture_commit(accepted);
            let request = SelfAuthoritySubmitRequest::Event(
                arkret_wire::EventAdmissionSubmission::new(event.clone()),
            );
            let outcome = SelfAuthoritySubmitOutcome::Ordinary(
                arkret_wire::AuthoritySubmitOutcome::Accepted {
                    status: arkret_wire::AuthorityCommitStatus::Committed,
                    commit: accepted.clone(),
                },
            );
            let needs_query = matches!(
                refusal,
                "none" | "unavailable" | "bad_ed" | "wrong_target" | "distinct_authorization_time"
            );
            if refusal == "bad_ed" {
                key.public_key_b64u =
                    arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
                        ed25519_dalek::SigningKey::from_bytes(&[42; 32])
                            .verifying_key()
                            .as_bytes(),
                    ))
                    .unwrap();
            }
            let mut bodies = vec![serde_json::to_value(outcome).unwrap()];
            if needs_query {
                bodies.push(serde_json::json!({"__signer_key":key,"__expected_native_target":CommittedEventRef{event_id:event.event_id.clone(),commit_id:accepted.commit_id.clone(),stream_ref:accepted.stream_ref.clone(),stream_position:accepted.stream_position},"__distinct_authorization_time":refusal=="distinct_authorization_time","__unavailable":refusal=="unavailable","__wrong_historical_target":refusal=="wrong_target"}));
            }
            let (source, server, observed) = observed_client(bodies);
            let fetched = source
                .submit_to_realm_authority(
                    &request,
                    &arkret_http_client::ClientRequestOptions::default(),
                )
                .await;
            if refusal == "wrong_slot" && fetched.is_err() {
                server.join().unwrap();
                assert_eq!(observed.lock().unwrap().len(), 1);
                continue;
            }
            let response = fetched.unwrap();
            let mut expected = request.clone();
            if refusal == "wrong_request" {
                let SelfAuthoritySubmitRequest::Event(value) = &mut expected else {
                    unreachable!()
                };
                value.event.created_at = crate::test_fixtures::at(4);
            }
            let result = if refusal == "wrong_session" {
                let (foreign, idle) = client(vec![]);
                idle.join().unwrap();
                consume_bound_submission(&foreign, &expected, response).await
            } else {
                consume_bound_submission(&source, &expected, response).await
            };
            assert_eq!(
                result.is_ok(),
                matches!(refusal, "none" | "distinct_authorization_time"),
                "closed self genesis source: {refusal}"
            );
            if refusal == "unavailable" {
                assert!(
                    result
                        .unwrap_err()
                        .to_string()
                        .contains("exact historical producer signing key is unavailable")
                );
            }
            server.join().unwrap();
            let observed = observed.lock().unwrap();
            assert_eq!(observed.len(), if needs_query { 2 } else { 1 });
            assert!(observed[0].starts_with("post /_arkret/self/events "));
            if needs_query {
                assert!(observed[1].starts_with("post /_arkret/self/signer-keys/query "));
            }
            assert!(
                !observed
                    .iter()
                    .any(|path| path.contains("scan") || path.contains("current"))
            );
            // This consumer takes no replica/install capability. These
            // transport tests do not claim before/after existing-head proof.
        }
    }

    #[tokio::test]
    async fn native_genesis_disclosed_full_remains_ordinary_missing_digest_unavailable() {
        let (event, accepted, _) = native_self_genesis_fixture("alice");
        let (source, server, observed) = observed_client(vec![
            serde_json::json!({"event":event,"commit":accepted}),
            serde_json::json!({
                "committed_events": [{"event":event,"commit":accepted}],
                "readable_floor": ReadableFloor {
                    oldest_position: 0,
                    floor_commit_id: accepted.commit_id.clone(),
                    floor_reason: arkret_wire::ReadableFloorReason::StreamStart,
                },
                "truncated": false,
            }),
        ]);
        let reference = CommittedEventRef {
            event_id: event.event_id.clone(),
            commit_id: accepted.commit_id.clone(),
            stream_ref: accepted.stream_ref.clone(),
            stream_position: 0,
        };
        let response = source.committed_event_get(&event.event_id).await.unwrap();
        let error = consume_bound_event(&source, &reference, response)
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("original ordinary Human signer source is unavailable")
        );
        server.join().unwrap();
        let observed = observed.lock().unwrap();
        assert_eq!(
            observed.len(),
            2,
            "GET must confirm its exact original scan row"
        );
        assert!(observed[0].starts_with("get /_arkret/self/committed-events/"));
        assert!(observed[1].starts_with("post /_arkret/self/streams/scan "));
        assert!(
            !observed
                .iter()
                .any(|path| path.contains("signer-keys") || path.contains("current")),
            "no historical or current key lookup for ordinary missing digest"
        );
    }

    #[tokio::test]
    async fn own_station_actual_scan_content_ids_continuity_and_withheld_mls_anchor() {
        let first = commit(0, None);
        let second = commit(1, Some(first.commit_id.clone()));
        let wrong = commit(2, Some(first.commit_id.clone()));
        let bodies = vec![
            serde_json::json!({"committed_events":[withheld(first.clone()),withheld(second.clone())],"readable_floor":{"oldest_position":0,"floor_commit_id":first.commit_id,"floor_reason":"stream_start"},"truncated":false}),
            serde_json::json!({"committed_events":[withheld(wrong)],"truncated":false}),
            withheld(second.clone()),
        ];
        let (client, server) = client(bodies);
        let mut replica = OwnStationReplica::new(crate::test_fixtures::realm_id());
        let request = StreamScanRequest {
            realm_id: crate::test_fixtures::realm_id(),
            stream_ref: crate::test_fixtures::realm_stream(),
            direction: StreamScanDirection::After(None),
            limit: 2,
        };
        let page = replica
            .apply_bound_scan(&client, client.scan_commit_stream(&request).await.unwrap())
            .await
            .unwrap();
        assert_eq!(page.rows().unwrap().len(), 2);
        assert_eq!(replica.head(&request.stream_ref).unwrap(), &head(&second));
        let next = StreamScanRequest {
            direction: StreamScanDirection::After(Some(1)),
            ..request.clone()
        };
        assert!(
            replica
                .apply_bound_scan(&client, client.scan_commit_stream(&next).await.unwrap())
                .await
                .is_err()
        );
        assert_eq!(replica.head(&request.stream_ref).unwrap(), &head(&second));
        let mut recovery = OwnStationReplica::new(crate::test_fixtures::realm_id());
        let reference = CommittedEventRef {
            event_id: second.event_ref.clone(),
            commit_id: second.commit_id.clone(),
            stream_ref: second.stream_ref.clone(),
            stream_position: second.stream_position,
        };
        let response = client
            .committed_event_get(&reference.event_id)
            .await
            .unwrap();
        let error = recovery
            .restore_bound_anchor(&client, &reference, response)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("withheld"));
        assert!(recovery.head(&request.stream_ref).is_none());
        server.join().unwrap();
    }

    // Migrated from the retired raw-context consumer. Every response below
    // comes through the real HTTP Bound factory; no public Account/epoch pair
    // can manufacture an accepted page.
    #[tokio::test]
    async fn own_station_bound_scan_preserves_originals_and_all_state_on_refusal() {
        let first = commit(0, None);
        let second = commit(1, Some(first.commit_id.clone()));
        let current = snapshot(vec![head(&second)]);
        let outcome = serde_json::json!({
            "committed_events": [withheld(first.clone()), withheld(second.clone())],
            "readable_floor": {"oldest_position":0,"floor_commit_id":first.commit_id,"floor_reason":"stream_start"},
            "truncated":false
        });
        let mut corrupted = second.clone();
        corrupted.committed_at += chrono::Duration::seconds(1);
        let bad = serde_json::json!({
            "committed_events": [withheld(first.clone()), withheld(corrupted)],
            "readable_floor": {"oldest_position":0,"floor_commit_id":first.commit_id,"floor_reason":"stream_start"},
            "truncated":false
        });
        let empty = serde_json::json!({
            "committed_events":[],
            "readable_floor":{"oldest_position":0,"floor_commit_id":first.commit_id,"floor_reason":"stream_start"},
            "truncated":false
        });
        let substituted = snapshot(vec![CommitStreamHead {
            commit_id: first.commit_id.clone(),
            ..head(&second)
        }]);
        let (client, server) = client(vec![
            serde_json::to_value(&current).unwrap(),
            bad,
            outcome.clone(),
            outcome,
            serde_json::to_value(substituted).unwrap(),
            empty.clone(),
        ]);
        let mut replica = OwnStationReplica::new(first.realm_id.clone());
        replica
            .install_bound_snapshot(&client.snapshot_head(&first.realm_id).await.unwrap())
            .unwrap();
        let state = |replica: &OwnStationReplica| {
            (
                replica.context.clone(),
                replica.heads.clone(),
                replica.current_heads.clone(),
                replica.generations.clone(),
                replica.snapshot.clone(),
            )
        };
        let before = state(&replica);
        let request = StreamScanRequest {
            realm_id: first.realm_id.clone(),
            stream_ref: first.stream_ref.clone(),
            direction: StreamScanDirection::After(None),
            limit: 2,
        };
        assert!(
            replica
                .apply_bound_scan(&client, client.scan_commit_stream(&request).await.unwrap())
                .await
                .is_err()
        );
        assert!(state(&replica) == before);
        let page = replica
            .apply_bound_scan(&client, client.scan_commit_stream(&request).await.unwrap())
            .await
            .unwrap();
        assert_eq!(
            page.rows()
                .unwrap()
                .iter()
                .map(|row| row.commit().commit_id.clone())
                .collect::<Vec<_>>(),
            vec![first.commit_id.clone(), second.commit_id.clone()]
        );
        let installed = state(&replica);
        assert!(
            replica
                .apply_bound_scan(&client, client.scan_commit_stream(&request).await.unwrap())
                .await
                .is_err()
        );
        assert!(state(&replica) == installed);
        assert!(
            replica
                .install_bound_snapshot(&client.snapshot_head(&first.realm_id).await.unwrap())
                .is_err()
        );
        assert!(state(&replica) == installed);
        let tail = StreamScanRequest {
            direction: StreamScanDirection::After(Some(1)),
            ..request
        };
        let (other, other_server) = self::client(vec![empty]);
        assert!(
            replica
                .apply_bound_scan(&other, other.scan_commit_stream(&tail).await.unwrap())
                .await
                .is_err()
        );
        assert!(state(&replica) == installed);
        let page = replica
            .apply_bound_scan(&client, client.scan_commit_stream(&tail).await.unwrap())
            .await
            .unwrap();
        assert!(page.rows().unwrap().is_empty());
        assert!(state(&replica) == installed);
        other_server.join().unwrap();
        server.join().unwrap();
    }

    #[tokio::test]
    async fn own_station_generic_withheld_checkpoint_restores_and_continues_without_accepting_forks()
     {
        let first = commit(0, None);
        let checkpoint = commit(1, Some(first.commit_id.clone()));
        let next = commit(2, Some(checkpoint.commit_id.clone()));
        let fork = commit(2, Some(first.commit_id.clone()));
        let (client, server) = client(vec![
            serde_json::json!({"committed_events":[withheld(checkpoint.clone())],"truncated":true}),
            serde_json::json!({"committed_events":[withheld(next.clone())],"truncated":false}),
            serde_json::json!({"committed_events":[withheld(fork.clone())],"truncated":true}),
            serde_json::json!({"committed_events":[withheld(fork.clone())],"truncated":true}),
        ]);
        let mut replica = OwnStationReplica::new(checkpoint.realm_id.clone());
        replica
            .restore_checkpoint_head(&client, &head(&checkpoint))
            .await
            .unwrap();
        assert_eq!(
            replica.head(&checkpoint.stream_ref),
            Some(&head(&checkpoint))
        );
        let request = StreamScanRequest {
            realm_id: next.realm_id.clone(),
            stream_ref: next.stream_ref.clone(),
            direction: StreamScanDirection::After(Some(checkpoint.stream_position)),
            limit: 1,
        };
        let page = replica
            .apply_bound_scan(&client, client.scan_commit_stream(&request).await.unwrap())
            .await
            .unwrap();
        assert_eq!(page.rows().unwrap().len(), 1);
        assert_eq!(replica.head(&next.stream_ref), Some(&head(&next)));
        let mismatch = replica
            .restore_checkpoint_head(&client, &head(&next))
            .await
            .unwrap_err();
        assert!(
            mismatch
                .to_string()
                .contains("changed its accepted original")
        );
        assert_eq!(replica.head(&next.stream_ref), Some(&head(&next)));
        let error = replica
            .restore_checkpoint_head(&client, &head(&fork))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("fork"));
        assert_eq!(replica.head(&next.stream_ref), Some(&head(&next)));
        server.join().unwrap();
    }

    #[tokio::test]
    async fn own_station_live_bootstrap_admits_only_current_original_and_continuous_tail() {
        let origin = commit(0, None);
        let anchor = commit(5, Some(origin.commit_id.clone()));
        let next = commit(6, Some(anchor.commit_id.clone()));
        let floor = ReadableFloor {
            oldest_position: 5,
            floor_commit_id: anchor.commit_id.clone(),
            floor_reason: arkret_wire::ReadableFloorReason::MembershipJoin,
        };
        let (client, server) = client(vec![
            serde_json::to_value(snapshot_at_floor(vec![head(&anchor)], 5)).unwrap(),
            serde_json::json!({"committed_events":[withheld(anchor.clone())],"readable_floor":floor,"truncated":false}),
            serde_json::to_value(snapshot_at_floor(vec![head(&next)], 5)).unwrap(),
            serde_json::json!({"committed_events":[withheld(next.clone())],"readable_floor":floor,"truncated":false}),
        ]);
        let mut replica = OwnStationReplica::new(anchor.realm_id.clone());
        assert!(
            replica
                .bootstrap_current_head(&client, &anchor.stream_ref)
                .await
                .is_err()
        );
        replica
            .install_bound_snapshot(&client.snapshot_head(&anchor.realm_id).await.unwrap())
            .unwrap();
        assert!(replica.head(&anchor.stream_ref).is_none());
        replica
            .bootstrap_current_head(&client, &anchor.stream_ref)
            .await
            .unwrap();
        assert_eq!(replica.head(&anchor.stream_ref), Some(&head(&anchor)));
        assert!(
            replica
                .bootstrap_current_head(&client, &anchor.stream_ref)
                .await
                .is_err()
        );
        replica
            .install_bound_snapshot(&client.snapshot_head(&anchor.realm_id).await.unwrap())
            .unwrap();
        let request = StreamScanRequest {
            realm_id: anchor.realm_id.clone(),
            stream_ref: anchor.stream_ref.clone(),
            direction: StreamScanDirection::After(Some(anchor.stream_position)),
            limit: 1,
        };
        let page = replica
            .apply_bound_scan(&client, client.scan_commit_stream(&request).await.unwrap())
            .await
            .unwrap();
        assert_eq!(page.rows().unwrap().len(), 1);
        assert_eq!(page.rows().unwrap()[0].commit().commit_id, next.commit_id);
        assert_eq!(replica.head(&anchor.stream_ref), Some(&head(&next)));
        server.join().unwrap();
    }

    #[tokio::test]
    async fn own_station_empty_limited_scan_cannot_invent_floor_anchor() {
        let (client, server) = client(vec![
            serde_json::json!({"committed_events":[],"readable_floor":{"oldest_position":7,"floor_commit_id":arkret_wire::RealmCommitId::from_digest([7;32]),"floor_reason":"membership_join"},"truncated":false}),
        ]);
        let request = StreamScanRequest {
            realm_id: crate::test_fixtures::realm_id(),
            stream_ref: crate::test_fixtures::realm_stream(),
            direction: StreamScanDirection::After(None),
            limit: 1,
        };
        let mut replica = OwnStationReplica::new(request.realm_id.clone());
        let response = client
            .scan_commit_stream(&request)
            .await
            .expect("valid closed ReadableFloor must reach the consumer gate");
        let error = replica
            .apply_bound_scan(&client, response)
            .await
            .err()
            .unwrap();
        assert!(error.to_string().contains("limited history"));
        assert!(replica.head(&request.stream_ref).is_none());
        server.join().unwrap();
    }

    #[tokio::test]
    async fn own_station_scan_race_requires_a_fresh_covering_bound_current() {
        let first = commit(0, None);
        let second = commit(1, Some(first.commit_id.clone()));
        let old = snapshot(vec![head(&first)]);
        let current = snapshot(vec![head(&second)]);
        let page = serde_json::json!({
            "committed_events": [withheld(first.clone()), withheld(second.clone())],
            "readable_floor": {"oldest_position":0,"floor_commit_id":first.commit_id,"floor_reason":"stream_start"},
            "truncated":false
        });
        let (client, server) = client(vec![
            serde_json::to_value(old).unwrap(),
            page.clone(),
            page,
            serde_json::to_value(current).unwrap(),
        ]);
        let mut replica = OwnStationReplica::new(first.realm_id.clone());
        replica
            .install_bound_snapshot(&client.snapshot_head(&first.realm_id).await.unwrap())
            .unwrap();
        let request = StreamScanRequest {
            realm_id: first.realm_id.clone(),
            stream_ref: first.stream_ref.clone(),
            direction: StreamScanDirection::After(None),
            limit: 2,
        };
        let stale_page = client.scan_commit_stream(&request).await.unwrap();
        let error = replica
            .apply_bound_scan(&client, stale_page)
            .await
            .err()
            .expect("the pre-scan current must reject a later Commit");
        assert!(
            error
                .to_string()
                .contains("exceeds or forks its exact current cut")
        );
        assert!(replica.head(&request.stream_ref).is_none());
        let page = client.scan_commit_stream(&request).await.unwrap();
        replica
            .install_bound_snapshot(&client.snapshot_head(&first.realm_id).await.unwrap())
            .unwrap();
        let admitted = replica.apply_bound_scan(&client, page).await.unwrap();
        assert_eq!(admitted.rows().unwrap().len(), 2);
        assert_eq!(replica.head(&request.stream_ref), Some(&head(&second)));
        server.join().unwrap();
    }

    fn snapshot(heads: Vec<CommitStreamHead>) -> RealmStateSnapshot {
        snapshot_at_floor(heads, 0)
    }

    fn snapshot_at_floor(
        mut heads: Vec<CommitStreamHead>,
        oldest_position: u64,
    ) -> RealmStateSnapshot {
        heads.sort_by(|left, right| left.stream_ref.cmp(&right.stream_ref));
        let mut value = RealmStateSnapshot {
            snapshot_id: RealmSnapshotId::from_digest([1; 32]),
            realm_id: crate::test_fixtures::realm_id(),
            governance_generation: 0,
            retention_and_history_floor: arkret_wire::RetentionAndHistoryFloor {
                history_access: arkret_wire::HistoryAccess::SinceJoin,
                stream_floors: heads
                    .iter()
                    .map(|head| arkret_wire::StreamHistoryFloor {
                        stream_ref: head.stream_ref.clone(),
                        oldest_position,
                    })
                    .collect(),
            },
            visible_stream_heads: heads,
            current_state_entries: vec![],
            created_at: crate::test_fixtures::at(1),
            signature: crate::test_fixtures::detached_signature(
                arkret_wire::DetachedSignatureContext::RealmSnapshot,
            ),
        };
        let mut body = serde_json::to_value(&value).unwrap();
        body.as_object_mut().unwrap().remove("snapshot_id");
        body.as_object_mut().unwrap().remove("signature");
        value.snapshot_id = RealmSnapshotId::from_digest(arkret_canonical::sha256_bytes(
            arkret_canonical::canonical_json_bytes(&body).unwrap(),
        ));
        value
    }

    #[tokio::test]
    async fn own_station_current_watermark_survives_hidden_stream_and_empty_cut_mismatch() {
        let realm_head = head(&commit(0, None));
        let stream = CommitStreamRef::Sidecar {
            realm_id: crate::test_fixtures::realm_id(),
            sidecar_id: arkret_wire::SidecarId::from_event_id(&EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                [6; 32],
            )),
        };
        let first = CommitStreamHead {
            stream_ref: stream.clone(),
            stream_position: 10,
            commit_id: arkret_wire::RealmCommitId::from_digest([10; 32]),
        };
        let lower = CommitStreamHead {
            stream_ref: stream.clone(),
            stream_position: 9,
            commit_id: arkret_wire::RealmCommitId::from_digest([9; 32]),
        };
        let (client, server) = client(vec![
            serde_json::to_value(snapshot(vec![realm_head.clone(), first.clone()])).unwrap(),
            serde_json::json!({"committed_events":[],"readable_floor":ReadableFloor { oldest_position: 7, floor_commit_id: arkret_wire::RealmCommitId::from_digest([7;32]), floor_reason: arkret_wire::ReadableFloorReason::MembershipJoin },"truncated":false}),
            serde_json::to_value(snapshot(vec![realm_head.clone()])).unwrap(),
            serde_json::to_value(snapshot(vec![realm_head, lower])).unwrap(),
        ]);
        let mut replica = OwnStationReplica::new(crate::test_fixtures::realm_id());
        replica
            .install_bound_snapshot(&client.snapshot_head(&replica.realm_id).await.unwrap())
            .unwrap();
        let request = StreamScanRequest {
            realm_id: replica.realm_id.clone(),
            stream_ref: stream.clone(),
            direction: StreamScanDirection::After(None),
            limit: 1,
        };
        let error = replica
            .apply_bound_scan(&client, client.scan_commit_stream(&request).await.unwrap())
            .await
            .err()
            .unwrap();
        assert!(error.to_string().contains("different history floors"));
        replica
            .install_bound_snapshot(&client.snapshot_head(&replica.realm_id).await.unwrap())
            .unwrap();
        let old = replica.snapshot().unwrap().snapshot_id.clone();
        assert!(
            replica
                .install_bound_snapshot(&client.snapshot_head(&replica.realm_id).await.unwrap())
                .is_err()
        );
        assert_eq!(replica.snapshot().unwrap().snapshot_id, old);
        assert!(
            replica.head(&stream).is_none(),
            "current coverage never invents a replay predecessor"
        );
        server.join().unwrap();
    }

    #[test]
    fn result_consumption_roles_27_registered_policy_cases() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!("../../arkret-spec/spec/v1/artifacts/fixtures/governance-result-consumption-roles-fixture.json")).unwrap();
        let contract: serde_json::Value = serde_json::from_str(include_str!(
            "../../arkret-spec/spec/v1/artifacts/registry/contract-registry.json"
        ))
        .unwrap();
        let roles = &contract["did_evidence_boundary_registry"]["governance_result_consumption_contract"]
            ["roles"];
        let cases = fixture["cases"].as_array().unwrap();
        assert_eq!(cases.len(), 27);
        for case in cases {
            let policy = &roles[case["role"].as_str().unwrap()];
            let sorted = |value: &serde_json::Value| {
                value
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|value| value.as_str().unwrap().to_owned())
                    .collect::<std::collections::BTreeSet<_>>()
            };
            let accepted = !policy.is_null()
                && case["source"] == policy["input"]
                && case["method_history_verifier"] == policy["method_history_verifier"]
                && case["live_did_discovery"] == false
                && case["portable"] == false
                && sorted(&case["checks"]) == sorted(&policy["checks"]);
            assert_eq!(
                if accepted { "accept" } else { "reject" },
                case["expected"].as_str().unwrap(),
                "registered semantic role policy: {}",
                case["name"]
            );
        }
        // This is the registered semantic policy fixture only. Actual HTTP,
        // producer crypto, durable sessions and MLS have separate tests.
    }
}
