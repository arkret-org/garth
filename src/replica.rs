//! Client-side state for independent Realm, Circle, and Sidecar commit streams.

use std::collections::{BTreeMap, BTreeSet};

use arkret_identity::{
    RealmAuthorityFreshness, RealmAuthorityKeyDirectory, verify_realm_authority_bundle,
};
use arkret_models_collaboration::sync_frames::account_sync::StreamWindowStartBasis;
use arkret_wire::{
    AuthorityBundleRequest, CommitStreamHead, CommitStreamRef, CommittedEventView, HistoryAccess,
    ReadableFloor, RealmAuthorityBundle, RealmId, RealmSnapshotId, RealmStateSnapshot,
    StreamScanDirection, StreamScanOutcome, StreamScanRequest, TypedCurrentResult,
};

use crate::{Error, Result};

#[derive(Clone, Debug, Default, PartialEq)]
pub struct StreamReplica {
    pub head: Option<CommitStreamHead>,
    pub items: Vec<CommittedEventView>,
}

/// A scan page that crossed the fresh authority-chain and per-item signature
/// gate. Only [`RealmReplica::apply_verified_scan`] constructs this carrier.
#[derive(Clone, Debug, PartialEq)]
pub struct VerifiedScanPage {
    rows: Vec<CommittedEventView>,
}

/// Current rows committed by one exact signed snapshot whose head is the
/// committed-prefix anchor immediately before a limited stream window's first
/// verified row. The carrier contains no rows from another stream and cannot
/// be constructed from shape-only staging.
#[derive(Clone, Debug, PartialEq)]
pub struct VerifiedFloorSnapshot {
    rows: Vec<TypedCurrentResult>,
    head: CommitStreamHead,
    governance_generation: u64,
    history_access: HistoryAccess,
}

impl VerifiedFloorSnapshot {
    pub fn rows(&self) -> &[TypedCurrentResult] {
        &self.rows
    }

    pub fn into_rows(self) -> Vec<TypedCurrentResult> {
        self.rows
    }

    pub fn head(&self) -> &CommitStreamHead {
        &self.head
    }

    pub fn governance_generation(&self) -> u64 {
        self.governance_generation
    }

    /// The signed cut's `retention_and_history_floor.history_access`.
    pub fn history_access(&self) -> HistoryAccess {
        self.history_access
    }
}

impl VerifiedScanPage {
    pub fn rows(&self) -> &[CommittedEventView] {
        &self.rows
    }

    pub fn into_rows(self) -> Vec<CommittedEventView> {
        self.rows
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct RealmReplica {
    pub realm_id: RealmId,
    pub authority: Option<RealmAuthorityBundle>,
    pub snapshot: Option<RealmStateSnapshot>,
    pub streams: BTreeMap<CommitStreamRef, StreamReplica>,
    authority_request: Option<AuthorityBundleRequest>,
    verified_streams: BTreeMap<CommitStreamRef, StreamReplica>,
}

impl RealmReplica {
    pub fn new(realm_id: RealmId) -> Self {
        Self {
            realm_id,
            authority: None,
            snapshot: None,
            streams: BTreeMap::new(),
            authority_request: None,
            verified_streams: BTreeMap::new(),
        }
    }

    /// Shape-only staging data. This does not establish authority and cannot
    /// enable [`Self::apply_verified_scan`].
    pub fn install_authority(&mut self, bundle: RealmAuthorityBundle) -> Result<()> {
        bundle.validate_shape()?;
        if bundle.realm_id != self.realm_id {
            return Err(Error::Protocol(
                "authority bundle belongs to another Realm".to_owned(),
            ));
        }
        self.streams
            .entry(bundle.realm_stream_head.stream_ref.clone())
            .or_default()
            .head = Some(bundle.realm_stream_head.clone());
        self.authority = Some(bundle);
        self.authority_request = None;
        self.verified_streams.clear();
        Ok(())
    }

    /// Install only a fresh, nonce-bound, cryptographically verified authority
    /// chain. The request nonce must be the one the caller actually issued.
    pub fn install_verified_authority(
        &mut self,
        request: &AuthorityBundleRequest,
        bundle: RealmAuthorityBundle,
        freshness: &RealmAuthorityFreshness,
        keys: &dyn RealmAuthorityKeyDirectory,
    ) -> Result<()> {
        request.validate()?;
        if request.realm_id != self.realm_id
            || bundle.realm_id != self.realm_id
            || freshness.expected_nonce != request.nonce
        {
            return Err(Error::Protocol(
                "authority bundle does not bind the requested Realm and nonce".to_owned(),
            ));
        }
        verify_realm_authority_bundle(&bundle, freshness, keys)
            .map_err(|error| Error::Protocol(error.to_string()))?;
        // The bundle's current Realm head is an authority cut, not the local
        // replay tail. Installing it as a downloaded stream head would make a
        // genesis scan look like a replay or allow a forged resume anchor.
        self.authority = Some(bundle);
        self.authority_request = Some(request.clone());
        self.verified_streams.clear();
        Ok(())
    }

    /// Install only the signed stream heads of an exact snapshot as verified
    /// replay predecessors. Current rows in the snapshot are not projected by
    /// this API. The caller must have obtained the complete snapshot and must
    /// bind `expected_snapshot_id` to its formal reference; a shape-only
    /// `install_snapshot` can never populate `verified_streams`.
    /// A historical generation is permitted only for an exact by-ref read
    /// proven by the installed current authority chain. The current `/head`
    /// surface must use [`Self::install_verified_current_snapshot_heads`].
    pub fn install_verified_snapshot_heads(
        &mut self,
        snapshot: &RealmStateSnapshot,
        expected_snapshot_id: &RealmSnapshotId,
        freshness: &RealmAuthorityFreshness,
        keys: &dyn RealmAuthorityKeyDirectory,
    ) -> Result<()> {
        let authority = self.authority.as_ref().ok_or_else(|| {
            Error::Protocol("snapshot has no installed verified authority".to_owned())
        })?;
        let request = self
            .authority_request
            .as_ref()
            .ok_or_else(|| Error::Protocol("snapshot has no issued authority nonce".to_owned()))?;
        if request.nonce != freshness.expected_nonce {
            return Err(Error::Protocol(
                "snapshot freshness nonce changed".to_owned(),
            ));
        }
        let verified = verify_realm_authority_bundle(authority, freshness, keys)
            .map_err(|error| Error::Protocol(error.to_string()))?;
        validate_snapshot(snapshot, &self.realm_id)?;
        if &snapshot.snapshot_id != expected_snapshot_id || snapshot.created_at > freshness.now {
            return Err(Error::Protocol(
                "snapshot reference, generation, or time mismatch".to_owned(),
            ));
        }
        let mut identity =
            serde_json::to_value(snapshot).map_err(|error| Error::Protocol(error.to_string()))?;
        let object = identity
            .as_object_mut()
            .ok_or_else(|| Error::Protocol("snapshot is not an object".to_owned()))?;
        object.remove("signature");
        object.remove("snapshot_id");
        let identity_bytes = arkret_canonical::canonical_json_bytes(&identity)
            .map_err(|error| Error::Protocol(error.to_string()))?;
        let derived_id =
            RealmSnapshotId::from_digest(arkret_canonical::sha256_bytes(&identity_bytes));
        if snapshot.snapshot_id != derived_id {
            return Err(Error::Protocol(
                "snapshot ID differs from canonical identity body".to_owned(),
            ));
        }
        let signer_did = arkret_identity::verification_method_did(
            snapshot.signature.verification_method.as_str(),
        )
        .map_err(|error| Error::Protocol(error.to_string()))?;
        let signer = arkret_wire::project_did_to_core_id(&signer_did)
            .map_err(|error| Error::Protocol(error.to_string()))?;
        if verified.authority_service_at(snapshot.governance_generation) != Some(&signer) {
            return Err(Error::Protocol(
                "snapshot signer is not the Station at its governance generation".to_owned(),
            ));
        }
        let key = keys
            .public_key(&snapshot.signature.verification_method)
            .ok_or_else(|| {
                Error::Protocol("snapshot signing method has no verified key".to_owned())
            })?;
        let unsigned = arkret_canonical::unsigned_value(snapshot, &["signature"])
            .map_err(|error| Error::Protocol(error.to_string()))?;
        arkret_signatures::detached_object::verify_detached_object_signature(
            &snapshot.signature,
            &unsigned,
            arkret_wire::DetachedSignatureContext::RealmSnapshot,
            &key,
        )
        .map_err(|error| Error::Protocol(error.to_string()))?;
        if !self.verified_streams.is_empty() {
            return Err(Error::Protocol(
                "snapshot cannot replace an established verified replay head".to_owned(),
            ));
        }
        let mut heads = BTreeMap::new();
        for head in &snapshot.visible_stream_heads {
            heads.insert(
                head.stream_ref.clone(),
                StreamReplica {
                    head: Some(head.clone()),
                    items: Vec::new(),
                },
            );
        }
        self.verified_streams = heads;
        Ok(())
    }

    /// Verify a current `/head` snapshot. Unlike an exact historical by-ref
    /// snapshot, its generation must equal the fresh bundle's current term.
    pub fn install_verified_current_snapshot_heads(
        &mut self,
        snapshot: &RealmStateSnapshot,
        freshness: &RealmAuthorityFreshness,
        keys: &dyn RealmAuthorityKeyDirectory,
    ) -> Result<()> {
        if self
            .authority
            .as_ref()
            .map(|bundle| bundle.current_generation)
            != Some(snapshot.governance_generation)
        {
            return Err(Error::Protocol(
                "current snapshot has another governance generation".to_owned(),
            ));
        }
        self.install_verified_snapshot_heads(snapshot, &snapshot.snapshot_id, freshness, keys)
    }

    /// Admit a limited stream window anchored to one exact signed snapshot
    /// head. The basis names the committed prefix: its anchor is the signed
    /// head itself, the window starts right after it, and the anchor must not
    /// lie before the caller's readable floor. The subsequent verified scan
    /// resumes after the signed head and must extend its exact Commit. A
    /// position-0 window and a window starting exactly at a nonzero readable
    /// floor carry no basis; the latter stays preview-only.
    pub fn install_verified_floor_predecessor(
        &mut self,
        stream_ref: &CommitStreamRef,
        basis: &StreamWindowStartBasis,
        floor: &ReadableFloor,
        snapshot: &RealmStateSnapshot,
        freshness: &RealmAuthorityFreshness,
        keys: &dyn RealmAuthorityKeyDirectory,
    ) -> Result<VerifiedFloorSnapshot> {
        basis
            .validate()
            .map_err(|error| Error::Protocol(error.to_string()))?;
        let head = snapshot
            .visible_stream_heads
            .iter()
            .find(|head| &head.stream_ref == stream_ref)
            .ok_or_else(|| Error::Protocol("snapshot omits the floor stream head".to_owned()))?;
        let anchored = basis.anchor_position == head.stream_position
            && basis.anchor_commit_ref == head.commit_id
            && floor.oldest_position <= head.stream_position;
        if !anchored
            || basis.snapshot_ref != snapshot.snapshot_id
            || basis.governance_generation != snapshot.governance_generation
        {
            return Err(Error::Protocol(
                "snapshot window basis does not anchor the limited stream window".to_owned(),
            ));
        }
        // A product installer may consume only rows whose single source
        // stream is this signed predecessor. Multi-stream snapshots need a
        // per-stream verified witness set and remain outside this narrow API.
        if snapshot.visible_stream_heads.len() != 1
            || snapshot.current_state_entries.iter().any(|row| {
                let source = match row {
                    TypedCurrentResult::Value {
                        source_stream_ref, ..
                    }
                    | TypedCurrentResult::MessageReactions {
                        source_stream_ref, ..
                    } => source_stream_ref,
                };
                source != stream_ref
            })
        {
            return Err(Error::Protocol(
                "floor snapshot current rows require one exact source stream".to_owned(),
            ));
        }
        self.install_verified_snapshot_heads(snapshot, &basis.snapshot_ref, freshness, keys)?;
        Ok(VerifiedFloorSnapshot {
            rows: snapshot.current_state_entries.clone(),
            head: head.clone(),
            governance_generation: snapshot.governance_generation,
            history_access: snapshot.retention_and_history_floor.history_access,
        })
    }

    pub fn install_snapshot(&mut self, snapshot: RealmStateSnapshot) -> Result<()> {
        validate_snapshot(&snapshot, &self.realm_id)?;
        for head in &snapshot.visible_stream_heads {
            self.streams
                .entry(head.stream_ref.clone())
                .or_default()
                .head = Some(head.clone());
        }
        self.snapshot = Some(snapshot);
        Ok(())
    }

    /// Shape-only legacy staging. Its public `streams` are not verified input
    /// for [`Self::apply_verified_scan`] or any authority-sensitive projection.
    pub fn apply_scan(
        &mut self,
        request: &StreamScanRequest,
        outcome: StreamScanOutcome,
    ) -> Result<()> {
        outcome.validate_for_request(request)?;
        if request.realm_id != self.realm_id {
            return Err(Error::Protocol(
                "stream scan belongs to another Realm".to_owned(),
            ));
        }
        let StreamScanDirection::After(after_position) = request.direction else {
            return Err(Error::Protocol(
                "replica tail staging requires a forward scan".to_owned(),
            ));
        };
        let replica = self.streams.entry(request.stream_ref.clone()).or_default();
        if let Some(existing) = &replica.head
            && after_position != Some(existing.stream_position)
        {
            return Err(Error::Protocol(
                "stream tail must resume exactly after the installed head".to_owned(),
            ));
        }
        if let Some(last) = outcome.committed_events.last() {
            let commit = last.commit();
            replica.head = Some(CommitStreamHead {
                stream_ref: commit.stream_ref.clone(),
                stream_position: commit.stream_position,
                commit_id: commit.commit_id.clone(),
            });
        }
        replica.items.extend(outcome.committed_events);
        Ok(())
    }

    /// Verify every Commit (and every disclosed Event's content binding)
    /// against a fresh authority chain before storing or returning any row.
    /// An empty page never advances the verified tail.
    pub fn apply_verified_scan(
        &mut self,
        request: &StreamScanRequest,
        outcome: StreamScanOutcome,
        freshness: &RealmAuthorityFreshness,
        keys: &dyn RealmAuthorityKeyDirectory,
    ) -> Result<VerifiedScanPage> {
        outcome.validate_for_request(request)?;
        if request.realm_id != self.realm_id {
            return Err(Error::Protocol(
                "stream scan belongs to another Realm".to_owned(),
            ));
        }
        let authority = self.authority.as_ref().ok_or_else(|| {
            Error::Protocol("scan has no installed verified authority bundle".to_owned())
        })?;
        let authority_request = self
            .authority_request
            .as_ref()
            .ok_or_else(|| Error::Protocol("scan has no authority request nonce".to_owned()))?;
        if freshness.expected_nonce != authority_request.nonce {
            return Err(Error::Protocol("scan freshness nonce changed".to_owned()));
        }
        let verified = verify_realm_authority_bundle(authority, freshness, keys)
            .map_err(|error| Error::Protocol(error.to_string()))?;
        if request.stream_ref == authority.realm_stream_head.stream_ref {
            for item in &outcome.committed_events {
                let commit = item.commit();
                if commit.stream_position > authority.realm_stream_head.stream_position
                    || (commit.stream_position == authority.realm_stream_head.stream_position
                        && commit.commit_id != authority.realm_stream_head.commit_id)
                {
                    return Err(Error::Protocol(
                        "scan Realm Commit lies beyond the verified authority cut".to_owned(),
                    ));
                }
            }
        }
        let StreamScanDirection::After(after_position) = request.direction else {
            return Err(Error::Protocol(
                "verified replica tail requires a forward scan".to_owned(),
            ));
        };
        let existing = self
            .verified_streams
            .get(&request.stream_ref)
            .and_then(|stream| stream.head.as_ref());
        match (existing, after_position) {
            (Some(head), Some(position)) if head.stream_position == position => {
                if let Some(first) = outcome.committed_events.first()
                    && first.commit().previous_commit_ref.as_ref() != Some(&head.commit_id)
                {
                    return Err(Error::Protocol(
                        "scan first Commit does not extend the installed head".to_owned(),
                    ));
                }
            }
            (None, None) => {}
            _ => {
                return Err(Error::Protocol(
                    "scan has no verified predecessor anchor".to_owned(),
                ));
            }
        }
        // Verify the complete page before mutating any head or item. Withheld
        // rows still carry a signed Commit but no producer Event to verify.
        for item in &outcome.committed_events {
            let result = match item {
                CommittedEventView::Full(full) => verified.verify_committed_item(full, keys),
                CommittedEventView::Withheld(withheld) => {
                    verified.verify_commit(&withheld.commit, keys)
                }
            };
            result.map_err(|error| Error::Protocol(error.to_string()))?;
        }
        let accepted = outcome.committed_events;
        let replica = self
            .verified_streams
            .entry(request.stream_ref.clone())
            .or_default();
        if let Some(last) = accepted.last() {
            let commit = last.commit();
            replica.head = Some(CommitStreamHead {
                stream_ref: commit.stream_ref.clone(),
                stream_position: commit.stream_position,
                commit_id: commit.commit_id.clone(),
            });
        }
        replica.items.extend(accepted.iter().cloned());
        Ok(VerifiedScanPage { rows: accepted })
    }

    /// The locally verified tail for one independent stream. Shape-only
    /// `streams` and snapshot heads never populate this index.
    pub fn verified_head(&self, stream_ref: &CommitStreamRef) -> Option<&CommitStreamHead> {
        self.verified_streams
            .get(stream_ref)
            .and_then(|stream| stream.head.as_ref())
    }
}

fn validate_snapshot(snapshot: &RealmStateSnapshot, realm_id: &RealmId) -> Result<()> {
    if &snapshot.realm_id != realm_id
        || snapshot.visible_stream_heads.is_empty()
        || !snapshot
            .visible_stream_heads
            .windows(2)
            .all(|pair| pair[0].stream_ref < pair[1].stream_ref)
        || snapshot
            .visible_stream_heads
            .iter()
            .any(|head| head.stream_ref.realm_id() != realm_id)
        || snapshot.signature.context != arkret_wire::DetachedSignatureContext::RealmSnapshot
    {
        return Err(Error::Protocol(
            "Realm snapshot must carry sorted independent stream heads and a snapshot signature"
                .to_owned(),
        ));
    }
    // The signed cut names exactly the visible streams. A floor for another
    // stream (or a repeated/missing floor) cannot be a predecessor for any
    // of these heads, even when the Station signature is valid.
    let mut floors = BTreeMap::new();
    for floor in &snapshot.retention_and_history_floor.stream_floors {
        if floor.stream_ref.realm_id() != realm_id
            || floors
                .insert(&floor.stream_ref, floor.oldest_position)
                .is_some()
        {
            return Err(Error::Protocol(
                "Realm snapshot has a foreign or repeated stream floor".to_owned(),
            ));
        }
    }
    if floors.len() != snapshot.visible_stream_heads.len()
        || snapshot.visible_stream_heads.iter().any(|head| {
            floors
                .get(&head.stream_ref)
                .is_none_or(|oldest| *oldest > head.stream_position)
        })
    {
        return Err(Error::Protocol(
            "Realm snapshot floors do not cover its visible heads".to_owned(),
        ));
    }
    let mut subjects = BTreeSet::new();
    let mut commits = BTreeMap::new();
    for row in &snapshot.current_state_entries {
        let (selector, source_stream_ref, revision) = match row {
            arkret_wire::TypedCurrentResult::Value {
                selector,
                source_stream_ref,
                revision,
                ..
            }
            | arkret_wire::TypedCurrentResult::MessageReactions {
                selector,
                source_stream_ref,
                revision,
                ..
            } => (selector, source_stream_ref, revision),
        };
        if source_stream_ref.realm_id() != realm_id
            || snapshot
                .visible_stream_heads
                .iter()
                .find(|head| &head.stream_ref == source_stream_ref)
                .is_none_or(|head| {
                    revision.stream_position > head.stream_position
                        || (revision.stream_position == head.stream_position
                            && revision.commit_id != head.commit_id)
                })
        {
            return Err(Error::Protocol(
                "Realm snapshot current row has no visible covering stream head".to_owned(),
            ));
        }
        // One stream position names exactly one accepted Commit.
        if let Some(previous) = commits.insert(
            (source_stream_ref, revision.stream_position),
            &revision.commit_id,
        ) && previous != &revision.commit_id
        {
            return Err(Error::Protocol(
                "Realm snapshot rows name two Commits at one stream position".to_owned(),
            ));
        }
        let bytes = arkret_canonical::canonical_json_bytes(selector)
            .map_err(|error| Error::Protocol(error.to_string()))?;
        if !subjects.insert(bytes) {
            return Err(Error::Protocol(
                "Realm snapshot repeats a typed current subject".to_owned(),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use arkret_identity::{RealmAuthorityFreshness, RealmAuthorityKeyMap};
    use arkret_signatures::PublicKeyMaterial;
    use arkret_signatures::detached_object::sign_detached_object;
    use arkret_wire::{
        CommittedEventFullView, DetachedSignatureContext, Did, DidUrl, EventKind, ReadableFloor,
        ReadableFloorReason, RealmAuthorityCurrentAssertion, RealmCommit, RealmCommitAuthorityRef,
        ScopeRef, project_did_to_core_id,
    };
    use chrono::{Duration, Utc};
    use ed25519_dalek::SigningKey;

    use super::*;

    #[test]
    fn verified_scan_rejects_uninstalled_authority_without_changing_any_replica_state() {
        let realm_id = crate::test_fixtures::realm_id();
        let stream_ref = crate::test_fixtures::realm_stream();
        let event = crate::test_fixtures::event(
            21,
            EventKind::MessageCreate,
            serde_json::json!({
                "strand_id": "ak:strand:AXh0mpVGb536xVxbSPfM4Wc_1WuXAxTYgmtXEncKM9T0",
                "track_name": "discussion",
                "content": {"kind": "ak.content.text", "body": "must not appear"}
            }),
        );
        let commit = crate::test_fixtures::commit(21, &event, stream_ref.clone(), 0);
        let floor_commit_id = commit.commit_id.clone();
        let outcome = StreamScanOutcome {
            committed_events: vec![CommittedEventView::Full(CommittedEventFullView {
                commit,
                event,
            })],
            readable_floor: Some(ReadableFloor {
                oldest_position: 0,
                floor_commit_id,
                floor_reason: ReadableFloorReason::StreamStart,
            }),
            truncated: false,
        };
        let request = StreamScanRequest {
            realm_id: realm_id.clone(),
            stream_ref,
            direction: StreamScanDirection::After(None),
            limit: 1,
        };
        let freshness = RealmAuthorityFreshness::new(
            crate::test_fixtures::at(2),
            arkret_wire::Base64UrlString::new("AAAAAAAAAAAAAAAAAAAAAA").unwrap(),
        );
        let mut replica = RealmReplica::new(realm_id);
        let before = replica.clone();

        assert!(
            replica
                .apply_verified_scan(&request, outcome, &freshness, &RealmAuthorityKeyMap::new())
                .is_err()
        );
        assert_eq!(replica, before);
    }

    #[test]
    fn verified_scan_rejects_bad_late_commit_atomically_then_accepts_signed_page() {
        let route = crate::service_route_material::test_fixture::current_web_route_fixture(
            "station-a.example",
            "station",
            0xA1,
        );
        let now = Utc::now();
        let realm_id = crate::test_fixtures::realm_id();
        let stream_ref = crate::test_fixtures::realm_stream();
        let method = DidUrl::new("did:web:station-a.example#signing-1").unwrap();
        let station =
            project_did_to_core_id(&Did::new("did:web:station-a.example").unwrap()).unwrap();
        let keys = RealmAuthorityKeyMap::new().with_key(
            &method,
            PublicKeyMaterial::Ed25519Raw {
                bytes: route.signing_key.verifying_key().to_bytes().to_vec(),
            },
        );
        let scope = ScopeRef::Realm {
            realm_id: realm_id.clone(),
        };
        let genesis = arkret_wire::test_support::raw_event_at(
            EventKind::RealmCreate.as_str(),
            scope.clone(),
            arkret_wire::DidCoreId::new("ak:did_core:web:founder.example").unwrap(),
            station.clone(),
            serde_json::json!({}),
            now - Duration::seconds(2),
        )
        .unwrap();
        let ordinary = arkret_wire::test_support::raw_event_at(
            EventKind::MessageCreate.as_str(),
            scope,
            arkret_wire::DidCoreId::new("ak:did_core:web:founder.example").unwrap(),
            station.clone(),
            serde_json::json!({}),
            now - Duration::seconds(1),
        )
        .unwrap();
        let seal = |mut commit: RealmCommit, key: &SigningKey| {
            let unsigned =
                arkret_canonical::canonical::unsigned_value(&commit, &["signature"]).unwrap();
            commit.signature = sign_detached_object(
                &unsigned,
                DetachedSignatureContext::RealmCommit,
                method.clone(),
                now,
                key,
            )
            .unwrap();
            commit
        };
        let mut genesis_commit = crate::test_fixtures::commit(1, &genesis, stream_ref.clone(), 0);
        genesis_commit.authority_ref =
            RealmCommitAuthorityRef::GenesisOrChangeEvent(genesis.event_id.clone());
        let genesis_commit = seal(genesis_commit, &route.signing_key);
        let mut ordinary_commit = crate::test_fixtures::commit(2, &ordinary, stream_ref.clone(), 1);
        ordinary_commit.authority_ref =
            RealmCommitAuthorityRef::GenesisOrChangeEvent(genesis.event_id.clone());
        let ordinary_commit = seal(ordinary_commit, &route.signing_key);
        let head = CommitStreamHead {
            stream_ref: stream_ref.clone(),
            stream_position: 1,
            commit_id: ordinary_commit.commit_id.clone(),
        };
        let snapshot_head = head.clone();
        let nonce = arkret_wire::Base64UrlString::new("BBBBBBBBBBBBBBBBBBBBBB").unwrap();
        let mut assertion = RealmAuthorityCurrentAssertion {
            realm_id: realm_id.clone(),
            current_generation: 0,
            current_service_id: station.clone(),
            last_handoff_ref: None,
            realm_stream_head: head.clone(),
            nonce: nonce.clone(),
            expires_at: now + Duration::minutes(5),
            signature: crate::test_fixtures::detached_signature(
                DetachedSignatureContext::RealmAuthorityCurrentAssertion,
            ),
        };
        let unsigned =
            arkret_canonical::canonical::unsigned_value(&assertion, &["signature"]).unwrap();
        assertion.signature = sign_detached_object(
            &unsigned,
            DetachedSignatureContext::RealmAuthorityCurrentAssertion,
            method.clone(),
            now,
            &route.signing_key,
        )
        .unwrap();
        let bundle = RealmAuthorityBundle {
            realm_id: realm_id.clone(),
            genesis_event: genesis.clone(),
            genesis_commit: genesis_commit.clone(),
            authority_transitions: vec![],
            current_generation: 0,
            current_service_id: station,
            current_route_record: serde_json::to_value(&route.resolution).unwrap(),
            realm_stream_head: head,
            bundle_issued_at: now,
            current_assertion: assertion,
        };
        let authority_request = AuthorityBundleRequest {
            realm_id: realm_id.clone(),
            nonce: nonce.clone(),
        };
        let freshness = RealmAuthorityFreshness::new(now, nonce);
        let mut replica = RealmReplica::new(realm_id.clone());
        replica
            .install_verified_authority(&authority_request, bundle, &freshness, &keys)
            .unwrap();
        let mut snapshot = RealmStateSnapshot {
            snapshot_id: RealmSnapshotId::from_digest([0; 32]),
            realm_id: realm_id.clone(),
            governance_generation: 0,
            visible_stream_heads: vec![snapshot_head.clone()],
            current_state_entries: Vec::new(),
            retention_and_history_floor: arkret_wire::RetentionAndHistoryFloor {
                history_access: arkret_wire::HistoryAccess::AllHistoryForCurrentMembers,
                stream_floors: vec![arkret_wire::StreamHistoryFloor {
                    stream_ref: stream_ref.clone(),
                    oldest_position: 0,
                }],
            },
            created_at: now,
            signature: crate::test_fixtures::detached_signature(
                DetachedSignatureContext::RealmSnapshot,
            ),
        };
        let mut identity = serde_json::to_value(&snapshot).unwrap();
        identity.as_object_mut().unwrap().remove("signature");
        identity.as_object_mut().unwrap().remove("snapshot_id");
        snapshot.snapshot_id = RealmSnapshotId::from_digest(arkret_canonical::sha256_bytes(
            &arkret_canonical::canonical_json_bytes(&identity).unwrap(),
        ));
        snapshot.signature = sign_detached_object(
            &arkret_canonical::unsigned_value(&snapshot, &["signature"]).unwrap(),
            DetachedSignatureContext::RealmSnapshot,
            method.clone(),
            now,
            &route.signing_key,
        )
        .unwrap();
        let sign_snapshot = |snapshot: &mut RealmStateSnapshot| {
            let mut identity = serde_json::to_value(&*snapshot).unwrap();
            identity.as_object_mut().unwrap().remove("signature");
            identity.as_object_mut().unwrap().remove("snapshot_id");
            snapshot.snapshot_id = RealmSnapshotId::from_digest(arkret_canonical::sha256_bytes(
                &arkret_canonical::canonical_json_bytes(&identity).unwrap(),
            ));
            snapshot.signature = sign_detached_object(
                &arkret_canonical::unsigned_value(snapshot, &["signature"]).unwrap(),
                DetachedSignatureContext::RealmSnapshot,
                method.clone(),
                now,
                &route.signing_key,
            )
            .unwrap();
        };
        let row = arkret_wire::TypedCurrentResult::Value {
            selector: arkret_wire::CurrentSelector::RealmProfile,
            source_stream_ref: stream_ref.clone(),
            revision: arkret_wire::CurrentRevision {
                commit_id: ordinary_commit.commit_id.clone(),
                stream_position: 1,
            },
            value: serde_json::json!({}),
        };
        for mut malformed in [
            {
                let mut value = snapshot.clone();
                value.retention_and_history_floor.stream_floors.clear();
                value
            },
            {
                let mut value = snapshot.clone();
                value.retention_and_history_floor.stream_floors[0].oldest_position = 2;
                value
            },
            {
                let mut value = snapshot.clone();
                let floor = value.retention_and_history_floor.stream_floors[0].clone();
                value.retention_and_history_floor.stream_floors.push(floor);
                value
            },
            {
                let mut value = snapshot.clone();
                value.current_state_entries = vec![row.clone(), row.clone()];
                value
            },
            {
                let mut value = snapshot.clone();
                let mut wrong_source = row.clone();
                let arkret_wire::TypedCurrentResult::Value {
                    source_stream_ref, ..
                } = &mut wrong_source
                else {
                    unreachable!()
                };
                *source_stream_ref = CommitStreamRef::Realm {
                    realm_id: arkret_wire::RealmId::new(
                        "ak:realm:AfTcej7ZFNg8uTbkOiUJT0KN1F_c9l1fmtil65CUwncm",
                    )
                    .unwrap(),
                };
                value.current_state_entries = vec![wrong_source];
                value
            },
            {
                let mut value = snapshot.clone();
                let mut other_head_commit = row.clone();
                let arkret_wire::TypedCurrentResult::Value { revision, .. } =
                    &mut other_head_commit
                else {
                    unreachable!()
                };
                revision.commit_id = genesis_commit.commit_id.clone();
                value.current_state_entries = vec![other_head_commit];
                value
            },
            {
                let mut value = snapshot.clone();
                let mut first = row.clone();
                let mut second = row.clone();
                for (row, commit) in [(&mut first, [0x61; 32]), (&mut second, [0x62; 32])] {
                    let arkret_wire::TypedCurrentResult::Value { revision, .. } = row else {
                        unreachable!()
                    };
                    revision.stream_position = 0;
                    revision.commit_id = arkret_wire::RealmCommitId::from_digest(commit);
                }
                let arkret_wire::TypedCurrentResult::Value { selector, .. } = &mut second else {
                    unreachable!()
                };
                *selector = arkret_wire::CurrentSelector::RealmDiscovery;
                value.current_state_entries = vec![first, second];
                value
            },
            {
                let mut value = snapshot.clone();
                let mut future_row = row.clone();
                let arkret_wire::TypedCurrentResult::Value { revision, .. } = &mut future_row
                else {
                    unreachable!()
                };
                revision.stream_position = snapshot_head.stream_position + 1;
                value.current_state_entries = vec![future_row];
                value
            },
        ] {
            sign_snapshot(&mut malformed);
            let before = replica.clone();
            assert!(
                replica
                    .install_verified_snapshot_heads(
                        &malformed,
                        &malformed.snapshot_id,
                        &freshness,
                        &keys,
                    )
                    .is_err()
            );
            assert_eq!(replica, before);
        }
        let mut snapshot_replica = replica.clone();
        snapshot_replica
            .install_verified_snapshot_heads(&snapshot, &snapshot.snapshot_id, &freshness, &keys)
            .unwrap();
        assert_eq!(
            snapshot_replica.verified_head(&stream_ref),
            Some(&snapshot_head)
        );
        let mut current_snapshot_replica = replica.clone();
        current_snapshot_replica
            .install_verified_current_snapshot_heads(&snapshot, &freshness, &keys)
            .unwrap();
        assert_eq!(
            current_snapshot_replica.verified_head(&stream_ref),
            Some(&snapshot_head)
        );
        let mut older_term_snapshot = snapshot.clone();
        older_term_snapshot.governance_generation = 1;
        assert!(
            replica
                .clone()
                .install_verified_current_snapshot_heads(&older_term_snapshot, &freshness, &keys)
                .is_err()
        );
        let wrong_nonce = RealmAuthorityFreshness::new(
            now,
            arkret_wire::Base64UrlString::new("CCCCCCCCCCCCCCCCCCCCCC").unwrap(),
        );
        assert!(
            snapshot_replica
                .install_verified_snapshot_heads(
                    &snapshot,
                    &snapshot.snapshot_id,
                    &wrong_nonce,
                    &keys,
                )
                .is_err()
        );
        assert!(
            snapshot_replica
                .install_verified_snapshot_heads(
                    &snapshot,
                    &snapshot.snapshot_id,
                    &freshness,
                    &RealmAuthorityKeyMap::new(),
                )
                .is_err()
        );
        // A committed-prefix basis whose anchor is the signed head itself and
        // whose head is not earlier than the caller readable floor.
        let basis = StreamWindowStartBasis {
            anchor_position: snapshot_head.stream_position,
            anchor_commit_ref: snapshot_head.commit_id.clone(),
            snapshot_ref: snapshot.snapshot_id.clone(),
            governance_generation: snapshot.governance_generation,
            accepted_dependency_refs: None,
        };
        let restricted_floor = ReadableFloor {
            oldest_position: snapshot_head.stream_position,
            floor_commit_id: snapshot_head.commit_id.clone(),
            floor_reason: ReadableFloorReason::MembershipJoin,
        };
        let mut current_snapshot = snapshot.clone();
        let genesis_head = CommitStreamHead {
            stream_ref: stream_ref.clone(),
            stream_position: 0,
            commit_id: genesis_commit.commit_id.clone(),
        };
        let genesis_value = arkret_models_collaboration::events_payloads::realm::RealmGenesis::new(
            arkret_models_collaboration::events_payloads::realm::RealmPurpose::Collaboration,
            arkret_wire::GenesisSalt::new("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap(),
            arkret_wire::TrustDomainId::new("ak:trust_domain:server.example").unwrap(),
            arkret_wire::SecurityClass::Standard,
            arkret_wire::DidCoreId::new("ak:did_core:web:station-a.example").unwrap(),
            arkret_wire::JoinRule::Invite,
            arkret_wire::HistoryAccess::SinceJoin,
            arkret_wire::Discoverability::Listed,
            None,
            None,
        )
        .unwrap();
        let genesis_revision = arkret_wire::CurrentRevision {
            commit_id: genesis_commit.commit_id.clone(),
            stream_position: 0,
        };
        let signed_rows = vec![
            arkret_wire::TypedCurrentResult::Value {
                selector: arkret_wire::CurrentSelector::RealmGenesis,
                source_stream_ref: stream_ref.clone(),
                revision: genesis_revision.clone(),
                value: serde_json::to_value(genesis_value).unwrap(),
            },
            arkret_wire::TypedCurrentResult::Value {
                selector: arkret_wire::CurrentSelector::RealmAuthorityRoot,
                source_stream_ref: stream_ref.clone(),
                revision: genesis_revision,
                value: serde_json::json!({
                    "controller_actor_id": genesis.actor_id.clone(),
                    "controller_epoch": 0,
                    "authority_generation": 0,
                }),
            },
        ];
        current_snapshot.visible_stream_heads = vec![genesis_head.clone()];
        current_snapshot.current_state_entries = signed_rows.clone();
        sign_snapshot(&mut current_snapshot);
        // A snapshot whose head precedes the caller readable floor has no
        // Commit of the readable range before the window; a window starting
        // exactly at a nonzero floor carries no basis and stays preview-only.
        let floor_start_basis = StreamWindowStartBasis {
            anchor_position: 1,
            anchor_commit_ref: ordinary_commit.commit_id.clone(),
            snapshot_ref: current_snapshot.snapshot_id.clone(),
            governance_generation: current_snapshot.governance_generation,
            accepted_dependency_refs: None,
        };
        let floor_start = ReadableFloor {
            oldest_position: 1,
            floor_commit_id: ordinary_commit.commit_id.clone(),
            floor_reason: ReadableFloorReason::MembershipJoin,
        };
        let before_floor_start = replica.clone();
        assert!(
            replica
                .install_verified_floor_predecessor(
                    &stream_ref,
                    &floor_start_basis,
                    &floor_start,
                    &current_snapshot,
                    &freshness,
                    &keys,
                )
                .is_err()
        );
        assert_eq!(replica, before_floor_start);
        // The basis names the signed head itself; the caller may read the
        // whole prefix, so the stream-start floor is admitted.
        let prefix_basis = StreamWindowStartBasis {
            anchor_position: 0,
            anchor_commit_ref: genesis_commit.commit_id.clone(),
            snapshot_ref: current_snapshot.snapshot_id.clone(),
            governance_generation: 0,
            accepted_dependency_refs: None,
        };
        let prefix_floor = ReadableFloor {
            oldest_position: 0,
            floor_commit_id: genesis_commit.commit_id.clone(),
            floor_reason: ReadableFloorReason::StreamStart,
        };
        let mut bad_signature = current_snapshot.clone();
        bad_signature.signature =
            crate::test_fixtures::detached_signature(DetachedSignatureContext::RealmSnapshot);
        let before_bad_signature = replica.clone();
        assert!(
            replica
                .install_verified_floor_predecessor(
                    &stream_ref,
                    &prefix_basis,
                    &prefix_floor,
                    &bad_signature,
                    &freshness,
                    &keys,
                )
                .is_err()
        );
        assert_eq!(replica, before_bad_signature);
        let mut prefix_replica = replica.clone();
        let prefix_carrier = prefix_replica
            .install_verified_floor_predecessor(
                &stream_ref,
                &prefix_basis,
                &prefix_floor,
                &current_snapshot,
                &freshness,
                &keys,
            )
            .unwrap();
        assert_eq!(prefix_carrier.rows(), signed_rows);
        assert_eq!(prefix_carrier.head(), &genesis_head);
        assert_eq!(
            prefix_carrier.history_access(),
            arkret_wire::HistoryAccess::AllHistoryForCurrentMembers
        );
        assert_eq!(
            prefix_replica.verified_head(&stream_ref),
            Some(&genesis_head)
        );
        let prefix_tail = StreamScanRequest {
            realm_id: realm_id.clone(),
            stream_ref: stream_ref.clone(),
            direction: StreamScanDirection::After(Some(0)),
            limit: 1,
        };
        let prefix_page = prefix_replica
            .apply_verified_scan(
                &prefix_tail,
                StreamScanOutcome {
                    committed_events: vec![CommittedEventView::Full(CommittedEventFullView {
                        commit: ordinary_commit.clone(),
                        event: ordinary.clone(),
                    })],
                    readable_floor: Some(prefix_floor.clone()),
                    truncated: false,
                },
                &freshness,
                &keys,
            )
            .unwrap();
        assert_eq!(prefix_page.rows().len(), 1);
        for (forged_basis, forged_floor) in [
            {
                let mut value = prefix_basis.clone();
                value.anchor_position = 1;
                (value, prefix_floor.clone())
            },
            {
                let mut value = prefix_basis.clone();
                value.anchor_commit_ref = ordinary_commit.commit_id.clone();
                (value, prefix_floor.clone())
            },
            {
                let mut value = prefix_basis.clone();
                value.governance_generation = 1;
                (value, prefix_floor.clone())
            },
            (prefix_basis.clone(), {
                let mut value = prefix_floor.clone();
                value.oldest_position = 1;
                value.floor_commit_id = ordinary_commit.commit_id.clone();
                value.floor_reason = ReadableFloorReason::MembershipJoin;
                value
            }),
        ] {
            let mut forged_replica = replica.clone();
            let before = forged_replica.clone();
            assert!(
                forged_replica
                    .install_verified_floor_predecessor(
                        &stream_ref,
                        &forged_basis,
                        &forged_floor,
                        &current_snapshot,
                        &freshness,
                        &keys,
                    )
                    .is_err()
            );
            assert_eq!(forged_replica, before);
        }
        let mut floor_replica = replica.clone();
        floor_replica
            .install_verified_floor_predecessor(
                &stream_ref,
                &basis,
                &restricted_floor,
                &snapshot,
                &freshness,
                &keys,
            )
            .unwrap();
        assert_eq!(
            floor_replica.verified_head(&stream_ref),
            Some(&snapshot_head)
        );
        let mut forged_basis = basis.clone();
        forged_basis.anchor_commit_ref = arkret_wire::RealmCommitId::from_digest([0x77; 32]);
        let before = floor_replica.clone();
        assert!(
            floor_replica
                .install_verified_floor_predecessor(
                    &stream_ref,
                    &forged_basis,
                    &restricted_floor,
                    &snapshot,
                    &freshness,
                    &keys,
                )
                .is_err()
        );
        assert_eq!(floor_replica, before);
        for forged in [
            {
                let mut value = snapshot.clone();
                value.snapshot_id = RealmSnapshotId::from_digest([9; 32]);
                value
            },
            {
                let mut value = snapshot.clone();
                value.governance_generation = 1;
                value
            },
            {
                let mut value = snapshot.clone();
                value.signature.signed_digest =
                    arkret_wire::Hash::new(format!("sha256:{}", "f".repeat(64))).unwrap();
                value
            },
        ] {
            let before = snapshot_replica.clone();
            assert!(
                snapshot_replica
                    .install_verified_snapshot_heads(
                        &forged,
                        &snapshot.snapshot_id,
                        &freshness,
                        &keys
                    )
                    .is_err()
            );
            assert_eq!(snapshot_replica, before);
        }
        let request = StreamScanRequest {
            realm_id,
            stream_ref: stream_ref.clone(),
            direction: StreamScanDirection::After(None),
            limit: 2,
        };
        let floor_commit_id = genesis_commit.commit_id.clone();
        let outcome = StreamScanOutcome {
            committed_events: vec![
                CommittedEventView::Full(CommittedEventFullView {
                    commit: genesis_commit,
                    event: genesis,
                }),
                CommittedEventView::Full(CommittedEventFullView {
                    commit: ordinary_commit,
                    event: ordinary,
                }),
            ],
            readable_floor: Some(ReadableFloor {
                oldest_position: 0,
                floor_commit_id,
                floor_reason: ReadableFloorReason::StreamStart,
            }),
            truncated: false,
        };
        let mut forged = outcome.clone();
        let CommittedEventView::Full(second) = &mut forged.committed_events[1] else {
            unreachable!()
        };
        second.commit.signature.signed_digest =
            arkret_wire::Hash::new(format!("sha256:{}", "f".repeat(64))).unwrap();
        let before = replica.clone();
        assert!(
            replica
                .apply_verified_scan(&request, forged, &freshness, &keys)
                .is_err()
        );
        assert_eq!(replica, before);
        assert!(replica.verified_head(&stream_ref).is_none());

        let accepted = replica
            .apply_verified_scan(&request, outcome, &freshness, &keys)
            .unwrap();
        assert_eq!(accepted.rows().len(), 2);
        assert_eq!(
            replica.verified_head(&stream_ref).unwrap().stream_position,
            1
        );
    }
}
