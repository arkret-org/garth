//! Client-side state for independent Realm, Circle, and Sidecar commit streams.

use std::collections::{BTreeMap, BTreeSet};

use arkret_identity::{
    RealmAuthorityFreshness, RealmAuthorityKeyDirectory, verify_realm_authority_bundle,
};
use arkret_models_collaboration::sync_frames::account_sync::StreamWindowStartBasis;
use arkret_wire::{
    AuthorityBundleRequest, CommitStreamHead, CommitStreamRef, CommittedEventView, HistoryAccess,
    ReadableFloor, RealmAuthorityBundle, RealmCommit, RealmId, RealmSnapshotId, RealmStateSnapshot,
    StreamScanDirection, StreamScanOutcome, StreamScanRequest, TypedCurrentRow,
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
    authority_context: [u8; 32],
}

/// Current rows committed by one exact signed snapshot whose head is the
/// committed-prefix anchor immediately before a limited stream window's first
/// verified row. The carrier contains only rows sourced from that stream, even
/// when the signed snapshot covers several independent streams.
#[derive(Clone, Debug, PartialEq)]
pub struct VerifiedFloorSnapshot {
    rows: Vec<TypedCurrentRow>,
    head: CommitStreamHead,
    governance_generation: u64,
    history_access: HistoryAccess,
}

impl VerifiedFloorSnapshot {
    pub fn rows(&self) -> &[TypedCurrentRow] {
        &self.rows
    }

    pub fn into_rows(self) -> Vec<TypedCurrentRow> {
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
    verified_anchors: BTreeMap<CommitStreamRef, RealmCommit>,
}

impl RealmReplica {
    fn authority_context(&self) -> Result<[u8; 32]> {
        let bundle = self
            .authority
            .as_ref()
            .ok_or_else(|| Error::Protocol("missing verified authority".to_owned()))?;
        let request = self
            .authority_request
            .as_ref()
            .ok_or_else(|| Error::Protocol("missing authority request".to_owned()))?;
        let value = serde_json::to_value((request, bundle))
            .map_err(|error| Error::Protocol(error.to_string()))?;
        let bytes = arkret_canonical::canonical_json_bytes(&value)
            .map_err(|error| Error::Protocol(error.to_string()))?;
        Ok(arkret_canonical::sha256_bytes(&bytes))
    }
    pub fn new(realm_id: RealmId) -> Self {
        Self {
            realm_id,
            authority: None,
            snapshot: None,
            streams: BTreeMap::new(),
            authority_request: None,
            verified_streams: BTreeMap::new(),
            verified_anchors: BTreeMap::new(),
        }
    }

    /// Isolate a second verified scan under the same nonce-bound authority
    /// without carrying any previously installed stream predecessors.
    pub fn fork_verified_authority(&self) -> Result<Self> {
        if self.authority_request.is_none() || self.authority.is_none() {
            return Err(Error::Protocol(
                "replica has no verified authority".to_owned(),
            ));
        }
        let mut fork = Self::new(self.realm_id.clone());
        fork.authority = self.authority.clone();
        fork.authority_request = self.authority_request.clone();
        Ok(fork)
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
        self.verified_anchors.clear();
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
        self.verified_anchors.clear();
        Ok(())
    }

    /// Refresh the nonce-bound current authority without losing independently
    /// verified stream predecessors. A fresh assertion cannot roll back or
    /// replace the already authenticated genesis/handoff chain.
    pub fn refresh_verified_authority(
        &mut self,
        request: &AuthorityBundleRequest,
        bundle: RealmAuthorityBundle,
        freshness: &RealmAuthorityFreshness,
        keys: &dyn RealmAuthorityKeyDirectory,
    ) -> Result<()> {
        let mut candidate = Self::new(self.realm_id.clone());
        candidate.install_verified_authority(request, bundle, freshness, keys)?;
        let incoming = candidate.authority.as_ref().expect("installed authority");
        if let Some(previous) = self
            .authority
            .as_ref()
            .filter(|_| self.authority_request.is_some())
        {
            if incoming.genesis_event != previous.genesis_event
                || incoming.genesis_commit != previous.genesis_commit
                || incoming.current_generation < previous.current_generation
                || !incoming
                    .authority_transitions
                    .starts_with(&previous.authority_transitions)
            {
                return Err(Error::Protocol(
                    "fresh authority replaces the verified lineage".to_owned(),
                ));
            }
            if incoming.realm_stream_head.stream_position
                < previous.realm_stream_head.stream_position
            {
                return Err(Error::AuthorityCutBehind);
            }
            if incoming.realm_stream_head.stream_position
                == previous.realm_stream_head.stream_position
                && incoming.realm_stream_head.commit_id != previous.realm_stream_head.commit_id
            {
                return Err(Error::Protocol(
                    "fresh authority forks the installed Realm head".to_owned(),
                ));
            }
        }
        if let Some(head) = self.verified_head(&incoming.realm_stream_head.stream_ref) {
            if head.stream_position > incoming.realm_stream_head.stream_position {
                return Err(Error::AuthorityCutBehind);
            }
            if head.stream_position == incoming.realm_stream_head.stream_position
                && head.commit_id != incoming.realm_stream_head.commit_id
            {
                return Err(Error::Protocol(
                    "fresh authority forks the verified Realm tail".to_owned(),
                ));
            }
        }
        self.authority = candidate.authority;
        self.authority_request = candidate.authority_request;
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
    /// floor carry no basis; the latter stays preview-only. Nonempty accepted
    /// dependencies require complete verified genesis-to-signed-head scans
    /// under this replica's exact nonce-bound authority context.
    pub fn install_verified_floor_predecessor(
        &mut self,
        stream_ref: &CommitStreamRef,
        basis: &StreamWindowStartBasis,
        floor: &ReadableFloor,
        snapshot: &RealmStateSnapshot,
        verification: (&RealmAuthorityFreshness, &dyn RealmAuthorityKeyDirectory),
        dependency_pages: &BTreeMap<CommitStreamRef, Vec<VerifiedScanPage>>,
    ) -> Result<VerifiedFloorSnapshot> {
        let (freshness, keys) = verification;
        // Verify the whole signed object, including all visible heads and
        // rows, on an isolated replica. Only this stream's predecessor is
        // imported: another stream may name another historical snapshot and
        // must never inherit this head or its replay cursor.
        let mut candidate = Self::new(self.realm_id.clone());
        candidate.authority = self.authority.clone();
        candidate.authority_request = self.authority_request.clone();
        candidate.install_verified_snapshot_heads(
            snapshot,
            &basis.snapshot_ref,
            freshness,
            keys,
        )?;
        self.finish_floor_predecessor(
            candidate,
            stream_ref,
            basis,
            floor,
            snapshot,
            dependency_pages,
        )
    }

    fn finish_floor_predecessor(
        &mut self,
        mut candidate: Self,
        stream_ref: &CommitStreamRef,
        basis: &StreamWindowStartBasis,
        floor: &ReadableFloor,
        snapshot: &RealmStateSnapshot,
        dependency_pages: &BTreeMap<CommitStreamRef, Vec<VerifiedScanPage>>,
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
        if self.verified_head(stream_ref).is_some() {
            return Err(Error::Protocol(
                "floor snapshot cannot replace an established verified stream head".to_owned(),
            ));
        }
        for dependency in basis.accepted_dependency_refs.iter().flatten() {
            if dependency.stream_ref == *stream_ref
                || dependency.stream_ref.realm_id() != &self.realm_id
            {
                return Err(Error::Protocol(
                    "floor dependency names the wrong stream or Realm".to_owned(),
                ));
            }
            let signed_head = snapshot
                .visible_stream_heads
                .iter()
                .find(|head| head.stream_ref == dependency.stream_ref)
                .ok_or_else(|| {
                    Error::Protocol("floor dependency has no signed stream head".to_owned())
                })?;
            let pages = dependency_pages
                .get(&dependency.stream_ref)
                .ok_or_else(|| {
                    Error::Protocol("floor dependency has no verified scan".to_owned())
                })?;
            let authority_context = self.authority_context()?;
            if pages
                .iter()
                .any(|page| page.authority_context != authority_context)
            {
                return Err(Error::Protocol(
                    "floor dependency uses another authority context".to_owned(),
                ));
            }
            let mut previous: Option<(arkret_wire::RealmCommitId, u64)> = None;
            let mut found = false;
            let mut reached_head = false;
            for row in pages.iter().flat_map(|page| page.rows()) {
                let commit = row.commit();
                let expected_position = match &previous {
                    Some((_, position)) => position.checked_add(1).ok_or_else(|| {
                        Error::Protocol("floor dependency position overflow".to_owned())
                    })?,
                    None => 0,
                };
                if commit.realm_id != self.realm_id
                    || commit.stream_ref != dependency.stream_ref
                    || commit.stream_position != expected_position
                    || commit.previous_commit_ref != previous.as_ref().map(|(id, _)| id.clone())
                    || commit.governance_generation > basis.governance_generation
                {
                    return Err(Error::Protocol(
                        "floor dependency scan is not a verified prefix".to_owned(),
                    ));
                }
                if commit.stream_position == dependency.stream_position {
                    found = matches!(row, CommittedEventView::Full(_)) && dependency.matches(row);
                }
                if commit.stream_position == signed_head.stream_position {
                    reached_head = commit.commit_id == signed_head.commit_id;
                    break;
                }
                previous = Some((commit.commit_id.clone(), commit.stream_position));
            }
            if !found || !reached_head {
                return Err(Error::Protocol(
                    "floor dependency is not in the signed accepted prefix".to_owned(),
                ));
            }
        }
        let predecessor = candidate
            .verified_streams
            .remove(stream_ref)
            .ok_or_else(|| {
                Error::Protocol("verified snapshot omits the floor stream head".to_owned())
            })?;
        self.verified_streams
            .insert(stream_ref.clone(), predecessor);
        Ok(VerifiedFloorSnapshot {
            rows: snapshot
                .current_state_entries
                .iter()
                .filter(|row| match row {
                    TypedCurrentRow::Value {
                        source_stream_ref, ..
                    } => source_stream_ref == stream_ref,
                })
                .cloned()
                .collect(),
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
                if commit.stream_position > authority.realm_stream_head.stream_position {
                    // Known-tenure rows must still authenticate before this
                    // is treated as a concurrent append. A new tenure first
                    // needs its independently verified authority chain.
                    if commit.governance_generation <= authority.current_generation {
                        let result = match item {
                            CommittedEventView::Full(full) => {
                                verified.verify_committed_item(full, keys)
                            }
                            CommittedEventView::Withheld(withheld) => {
                                verified.verify_commit(&withheld.commit, keys)
                            }
                        };
                        result.map_err(|error| Error::Protocol(error.to_string()))?;
                    }
                    return Err(Error::AuthorityCutBehind);
                }
                if commit.stream_position == authority.realm_stream_head.stream_position
                    && commit.commit_id != authority.realm_stream_head.commit_id
                {
                    return Err(Error::Protocol(
                        "scan Realm Commit forks the verified authority head".to_owned(),
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
        let authority_context = self.authority_context()?;
        let accepted = outcome.committed_events;
        let replica = self
            .verified_streams
            .entry(request.stream_ref.clone())
            .or_default();
        if let Some(last) = accepted.last() {
            let commit = last.commit();
            self.verified_anchors
                .insert(request.stream_ref.clone(), commit.clone());
            replica.head = Some(CommitStreamHead {
                stream_ref: commit.stream_ref.clone(),
                stream_position: commit.stream_position,
                commit_id: commit.commit_id.clone(),
            });
        }
        replica.items.extend(accepted.iter().cloned());
        Ok(VerifiedScanPage {
            rows: accepted,
            authority_context,
        })
    }

    /// The locally verified tail for one independent stream. Shape-only
    /// `streams` and snapshot heads never populate this index.
    pub fn verified_head(&self, stream_ref: &CommitStreamRef) -> Option<&CommitStreamHead> {
        self.verified_streams
            .get(stream_ref)
            .and_then(|stream| stream.head.as_ref())
    }

    /// The signed predecessor retained after the durable rows are released.
    pub fn verified_anchor(&self, stream_ref: &CommitStreamRef) -> Option<&RealmCommit> {
        self.verified_anchors.get(stream_ref)
    }

    /// Reverify a persisted signed Commit under this request's fresh authority.
    /// A bare head or a cached authority result cannot enter this boundary.
    pub fn restore_verified_anchor(
        &mut self,
        commit: &RealmCommit,
        freshness: &RealmAuthorityFreshness,
        keys: &dyn RealmAuthorityKeyDirectory,
    ) -> Result<()> {
        let authority = self
            .authority
            .as_ref()
            .ok_or_else(|| Error::Protocol("anchor has no fresh authority".to_owned()))?;
        let request = self
            .authority_request
            .as_ref()
            .ok_or_else(|| Error::Protocol("anchor has no authority nonce".to_owned()))?;
        if freshness.expected_nonce != request.nonce || commit.realm_id != self.realm_id {
            return Err(Error::Protocol(
                "anchor does not bind the fresh Realm request".to_owned(),
            ));
        }
        let verified = verify_realm_authority_bundle(authority, freshness, keys)
            .map_err(|error| Error::Protocol(error.to_string()))?;
        verified
            .verify_commit(commit, keys)
            .map_err(|error| Error::Protocol(error.to_string()))?;
        if commit.stream_ref == authority.realm_stream_head.stream_ref {
            if commit.stream_position > authority.realm_stream_head.stream_position {
                return Err(Error::AuthorityCutBehind);
            }
            if commit.stream_position == authority.realm_stream_head.stream_position
                && commit.commit_id != authority.realm_stream_head.commit_id
            {
                return Err(Error::Protocol(
                    "signed anchor forks the fresh Realm head".to_owned(),
                ));
            }
        }
        let head = CommitStreamHead {
            stream_ref: commit.stream_ref.clone(),
            stream_position: commit.stream_position,
            commit_id: commit.commit_id.clone(),
        };
        if let Some(existing) = self.verified_head(&commit.stream_ref)
            && (head.stream_position < existing.stream_position
                || (head.stream_position == existing.stream_position && head != *existing))
        {
            return Err(Error::Protocol(
                "signed anchor replaces an already verified predecessor".to_owned(),
            ));
        }
        self.verified_streams
            .entry(commit.stream_ref.clone())
            .or_default()
            .head = Some(head);
        self.verified_anchors
            .insert(commit.stream_ref.clone(), commit.clone());
        Ok(())
    }

    /// Retire only this stream's predecessor for an authorized floor rebuild.
    /// Other independent streams retain their continuous verified heads.
    pub fn reset_verified_stream(&mut self, stream_ref: &CommitStreamRef) {
        self.verified_streams.remove(stream_ref);
        self.verified_anchors.remove(stream_ref);
    }

    /// Projection owns the durable rows. A live follower needs only its exact
    /// verified heads after the checkpoint; retaining all rows would grow with
    /// the complete history and make each candidate clone unbounded.
    pub fn release_verified_rows(&mut self) {
        for stream in self.verified_streams.values_mut() {
            stream.items.clear();
        }
    }
}

pub(crate) fn validate_snapshot(snapshot: &RealmStateSnapshot, realm_id: &RealmId) -> Result<()> {
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
            arkret_wire::TypedCurrentRow::Value {
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
        let seal = |mut commit: RealmCommit, key: &SigningKey| {
            commit.commit_id =
                arkret_wire::RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
                    arkret_canonical::canonical_json_bytes(
                        &arkret_canonical::canonical::unsigned_value(
                            &commit,
                            &["commit_id", "signature"],
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                ));
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
        let ordinary = arkret_wire::test_support::raw_event_at(
            EventKind::RealmGovernanceStationChange.as_str(),
            scope,
            arkret_wire::DidCoreId::new("ak:did_core:web:founder.example").unwrap(),
            station.clone(),
            serde_json::json!({
                "expected_governance_generation": 0,
                "expected_realm_stream_commit_id": genesis_commit.commit_id,
                "new_governance_station_id": "ak:did_core:web:station-b.example"
            }),
            now - Duration::seconds(1),
        )
        .unwrap();
        let mut ordinary_commit = crate::test_fixtures::commit(2, &ordinary, stream_ref.clone(), 1);
        ordinary_commit.authority_ref =
            RealmCommitAuthorityRef::GenesisOrChangeEvent(genesis.event_id.clone());
        ordinary_commit.previous_commit_ref = Some(genesis_commit.commit_id.clone());
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
            arkret_canonical::canonical_json_bytes(&identity).unwrap(),
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
                arkret_canonical::canonical_json_bytes(&identity).unwrap(),
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
        let row = arkret_wire::TypedCurrentRow::Value {
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
                let arkret_wire::TypedCurrentRow::Value {
                    source_stream_ref, ..
                } = &mut wrong_source;
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
                let arkret_wire::TypedCurrentRow::Value { revision, .. } = &mut other_head_commit;
                revision.commit_id = genesis_commit.commit_id.clone();
                value.current_state_entries = vec![other_head_commit];
                value
            },
            {
                let mut value = snapshot.clone();
                let mut first = row.clone();
                let mut second = row.clone();
                for (row, commit) in [(&mut first, [0x61; 32]), (&mut second, [0x62; 32])] {
                    let arkret_wire::TypedCurrentRow::Value { revision, .. } = row;
                    revision.stream_position = 0;
                    revision.commit_id = arkret_wire::RealmCommitId::from_digest(commit);
                }
                let arkret_wire::TypedCurrentRow::Value { selector, .. } = &mut second;
                *selector = arkret_wire::CurrentSelector::RealmDiscovery;
                value.current_state_entries = vec![first, second];
                value
            },
            {
                let mut value = snapshot.clone();
                let mut future_row = row.clone();
                let arkret_wire::TypedCurrentRow::Value { revision, .. } = &mut future_row;
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
            arkret_wire::TypedCurrentRow::Value {
                selector: arkret_wire::CurrentSelector::RealmGenesis,
                source_stream_ref: stream_ref.clone(),
                revision: genesis_revision.clone(),
                value: serde_json::to_value(genesis_value).unwrap(),
            },
            arkret_wire::TypedCurrentRow::Value {
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
                    (&freshness, &keys),
                    &BTreeMap::new(),
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
                    (&freshness, &keys),
                    &BTreeMap::new(),
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
                (&freshness, &keys),
                &BTreeMap::new(),
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
        let circle_id = arkret_wire::CircleId::from_event_id(&genesis.event_id);
        let circle_stream = CommitStreamRef::Circle {
            realm_id: realm_id.clone(),
            circle_id: circle_id.clone(),
        };
        let circle_head = CommitStreamHead {
            stream_ref: circle_stream.clone(),
            stream_position: 0,
            commit_id: arkret_wire::RealmCommitId::from_digest([0x44; 32]),
        };
        let sidecar_stream = CommitStreamRef::Sidecar {
            realm_id: realm_id.clone(),
            sidecar_id: arkret_wire::SidecarId::from_event_id(&genesis.event_id),
        };
        let sidecar_head = CommitStreamHead {
            stream_ref: sidecar_stream.clone(),
            stream_position: 0,
            commit_id: arkret_wire::RealmCommitId::from_digest([0x55; 32]),
        };
        let circle_row = TypedCurrentRow::Value {
            selector: arkret_wire::CurrentSelector::Circle { circle_id },
            source_stream_ref: circle_stream.clone(),
            revision: arkret_wire::CurrentRevision {
                commit_id: circle_head.commit_id.clone(),
                stream_position: 0,
            },
            value: serde_json::json!({"state": "active"}),
        };
        let mut multi = current_snapshot.clone();
        multi.visible_stream_heads.push(circle_head.clone());
        multi.visible_stream_heads.push(sidecar_head.clone());
        multi
            .retention_and_history_floor
            .stream_floors
            .push(arkret_wire::StreamHistoryFloor {
                stream_ref: circle_stream.clone(),
                oldest_position: 0,
            });
        multi
            .retention_and_history_floor
            .stream_floors
            .push(arkret_wire::StreamHistoryFloor {
                stream_ref: sidecar_stream.clone(),
                oldest_position: 0,
            });
        multi.current_state_entries.push(circle_row.clone());
        sign_snapshot(&mut multi);
        let circle_basis = StreamWindowStartBasis {
            anchor_position: 0,
            anchor_commit_ref: circle_head.commit_id.clone(),
            snapshot_ref: multi.snapshot_id.clone(),
            governance_generation: multi.governance_generation,
            accepted_dependency_refs: None,
        };
        let circle_floor = ReadableFloor {
            oldest_position: 0,
            floor_commit_id: circle_head.commit_id.clone(),
            floor_reason: ReadableFloorReason::StreamStart,
        };
        let mut dependency_replica = replica.fork_verified_authority().unwrap();
        let genesis_page = dependency_replica
            .apply_verified_scan(
                &StreamScanRequest {
                    realm_id: realm_id.clone(),
                    stream_ref: stream_ref.clone(),
                    direction: StreamScanDirection::After(None),
                    limit: 2,
                },
                StreamScanOutcome {
                    committed_events: vec![CommittedEventView::Full(CommittedEventFullView {
                        commit: genesis_commit.clone(),
                        event: genesis.clone(),
                    })],
                    readable_floor: Some(prefix_floor.clone()),
                    truncated: true,
                },
                &freshness,
                &keys,
            )
            .unwrap();
        let ordinary_page = dependency_replica
            .apply_verified_scan(
                &StreamScanRequest {
                    realm_id: realm_id.clone(),
                    stream_ref: stream_ref.clone(),
                    direction: StreamScanDirection::After(Some(0)),
                    limit: 1,
                },
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
        let proof = BTreeMap::from([(
            stream_ref.clone(),
            vec![genesis_page.clone(), ordinary_page.clone()],
        )]);
        let accepted_ref = arkret_wire::CommittedEventRef {
            event_id: ordinary.event_id.clone(),
            commit_id: ordinary_commit.commit_id.clone(),
            stream_ref: stream_ref.clone(),
            stream_position: 1,
        };
        let mut dependency_snapshot = multi.clone();
        dependency_snapshot.visible_stream_heads[0] = snapshot_head.clone();
        sign_snapshot(&mut dependency_snapshot);
        let mut dependent_basis = circle_basis.clone();
        dependent_basis.snapshot_ref = dependency_snapshot.snapshot_id.clone();
        dependent_basis.accepted_dependency_refs = Some(vec![accepted_ref.clone()]);
        let mut dependency_install = replica.clone();
        dependency_install
            .install_verified_floor_predecessor(
                &circle_stream,
                &dependent_basis,
                &circle_floor,
                &dependency_snapshot,
                (&freshness, &keys),
                &proof,
            )
            .unwrap();
        assert_eq!(
            dependency_install.verified_head(&circle_stream),
            Some(&circle_head)
        );
        for wrong in [
            {
                let mut value = accepted_ref.clone();
                value.commit_id = arkret_wire::RealmCommitId::from_digest([0xee; 32]);
                value
            },
            {
                let mut value = accepted_ref.clone();
                value.stream_position = 0;
                value
            },
            {
                let mut value = accepted_ref.clone();
                value.stream_ref = circle_stream.clone();
                value
            },
        ] {
            let mut basis = circle_basis.clone();
            basis.snapshot_ref = dependency_snapshot.snapshot_id.clone();
            basis.accepted_dependency_refs = Some(vec![wrong.clone()]);
            let mut candidate = replica.clone();
            let before = candidate.clone();
            assert!(
                candidate
                    .install_verified_floor_predecessor(
                        &circle_stream,
                        &basis,
                        &circle_floor,
                        &multi,
                        (&freshness, &keys),
                        &proof,
                    )
                    .is_err()
            );
            assert_eq!(candidate, before);
        }
        let short_proof = BTreeMap::from([(stream_ref.clone(), vec![genesis_page])]);
        assert!(
            replica
                .clone()
                .install_verified_floor_predecessor(
                    &circle_stream,
                    &dependent_basis,
                    &circle_floor,
                    &dependency_snapshot,
                    (&freshness, &keys),
                    &short_proof,
                )
                .is_err()
        );
        let mut wrong_context = proof.clone();
        wrong_context.get_mut(&stream_ref).unwrap()[0].authority_context = [0xff; 32];
        assert!(
            replica
                .clone()
                .install_verified_floor_predecessor(
                    &circle_stream,
                    &dependent_basis,
                    &circle_floor,
                    &dependency_snapshot,
                    (&freshness, &keys),
                    &wrong_context,
                )
                .is_err()
        );
        let mut multi_replica = replica.clone();
        let mut invented_dependency = circle_basis.clone();
        invented_dependency.accepted_dependency_refs = Some(vec![arkret_wire::CommittedEventRef {
            event_id: genesis.event_id.clone(),
            commit_id: arkret_wire::RealmCommitId::from_digest([0xee; 32]),
            stream_ref: stream_ref.clone(),
            stream_position: 999,
        }]);
        let before_dependency = multi_replica.clone();
        assert!(
            multi_replica
                .install_verified_floor_predecessor(
                    &circle_stream,
                    &invented_dependency,
                    &circle_floor,
                    &dependency_snapshot,
                    (&freshness, &keys),
                    &BTreeMap::new(),
                )
                .is_err()
        );
        assert_eq!(multi_replica, before_dependency);
        let circle_slice = multi_replica
            .install_verified_floor_predecessor(
                &circle_stream,
                &circle_basis,
                &circle_floor,
                &multi,
                (&freshness, &keys),
                &BTreeMap::new(),
            )
            .unwrap();
        assert_eq!(circle_slice.rows(), &[circle_row]);
        assert_eq!(
            multi_replica.verified_head(&circle_stream),
            Some(&circle_head)
        );
        assert_eq!(multi_replica.verified_head(&stream_ref), None);
        assert_eq!(multi_replica.verified_head(&sidecar_stream), None);
        let sidecar_slice = multi_replica
            .install_verified_floor_predecessor(
                &sidecar_stream,
                &StreamWindowStartBasis {
                    anchor_position: 0,
                    anchor_commit_ref: sidecar_head.commit_id.clone(),
                    snapshot_ref: multi.snapshot_id.clone(),
                    governance_generation: multi.governance_generation,
                    accepted_dependency_refs: None,
                },
                &ReadableFloor {
                    oldest_position: 0,
                    floor_commit_id: sidecar_head.commit_id.clone(),
                    floor_reason: ReadableFloorReason::StreamStart,
                },
                &multi,
                (&freshness, &keys),
                &BTreeMap::new(),
            )
            .unwrap();
        assert!(sidecar_slice.rows().is_empty());
        assert_eq!(
            multi_replica.verified_head(&sidecar_stream),
            Some(&sidecar_head)
        );
        let mut realm_basis = prefix_basis.clone();
        realm_basis.snapshot_ref = multi.snapshot_id.clone();
        let realm_slice = multi_replica
            .install_verified_floor_predecessor(
                &stream_ref,
                &realm_basis,
                &prefix_floor,
                &multi,
                (&freshness, &keys),
                &BTreeMap::new(),
            )
            .unwrap();
        assert_eq!(realm_slice.rows(), signed_rows);
        assert_eq!(
            multi_replica.verified_head(&circle_stream),
            Some(&circle_head)
        );
        assert_eq!(
            multi_replica.verified_head(&sidecar_stream),
            Some(&sidecar_head)
        );
        assert_eq!(
            multi_replica.verified_head(&stream_ref),
            Some(&genesis_head)
        );
        for (seed, scoped_stream, scoped_floor) in [
            (0x45, circle_stream.clone(), circle_floor.clone()),
            (
                0x56,
                sidecar_stream.clone(),
                ReadableFloor {
                    oldest_position: 0,
                    floor_commit_id: sidecar_head.commit_id.clone(),
                    floor_reason: ReadableFloorReason::StreamStart,
                },
            ),
        ] {
            let scoped_scope = match &scoped_stream {
                CommitStreamRef::Circle {
                    realm_id,
                    circle_id,
                } => ScopeRef::Circle {
                    realm_id: realm_id.clone(),
                    circle_id: circle_id.clone(),
                },
                CommitStreamRef::Sidecar {
                    realm_id,
                    sidecar_id,
                } => ScopeRef::Sidecar {
                    realm_id: realm_id.clone(),
                    sidecar_id: sidecar_id.clone(),
                },
                _ => unreachable!(),
            };
            let scoped_event = arkret_wire::test_support::raw_event_at(
                EventKind::MessageCreate.as_str(),
                scoped_scope,
                arkret_wire::DidCoreId::new("ak:did_core:web:founder.example").unwrap(),
                project_did_to_core_id(&Did::new("did:web:station-a.example").unwrap()).unwrap(),
                serde_json::json!({}),
                now - Duration::seconds(1),
            )
            .unwrap();
            let mut scoped_commit =
                crate::test_fixtures::commit(seed, &scoped_event, scoped_stream.clone(), 1);
            scoped_commit.authority_ref =
                RealmCommitAuthorityRef::GenesisOrChangeEvent(genesis.event_id.clone());
            scoped_commit.previous_commit_ref = Some(scoped_floor.floor_commit_id.clone());
            let scoped_commit = seal(scoped_commit, &route.signing_key);
            let page = multi_replica
                .apply_verified_scan(
                    &StreamScanRequest {
                        realm_id: realm_id.clone(),
                        stream_ref: scoped_stream.clone(),
                        direction: StreamScanDirection::After(Some(0)),
                        limit: 1,
                    },
                    StreamScanOutcome {
                        committed_events: vec![CommittedEventView::Full(CommittedEventFullView {
                            commit: scoped_commit.clone(),
                            event: scoped_event,
                        })],
                        readable_floor: Some(scoped_floor.clone()),
                        truncated: false,
                    },
                    &freshness,
                    &keys,
                )
                .unwrap();
            assert_eq!(page.rows()[0].commit().commit_id, scoped_commit.commit_id);
            if scoped_stream == circle_stream {
                let verified_tail = dependency_install
                    .apply_verified_scan(
                        &StreamScanRequest {
                            realm_id: realm_id.clone(),
                            stream_ref: circle_stream.clone(),
                            direction: StreamScanDirection::After(Some(0)),
                            limit: 1,
                        },
                        StreamScanOutcome {
                            committed_events: page.rows().to_vec(),
                            readable_floor: Some(scoped_floor.clone()),
                            truncated: false,
                        },
                        &freshness,
                        &keys,
                    )
                    .unwrap();
                assert_eq!(verified_tail.rows().len(), 1);
                assert_eq!(
                    dependency_install
                        .verified_head(&circle_stream)
                        .map(|head| head.stream_position),
                    Some(1)
                );
            }
            assert_eq!(
                multi_replica
                    .verified_head(&scoped_stream)
                    .map(|head| head.stream_position),
                Some(1)
            );
        }
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
                        (&freshness, &keys),
                        &BTreeMap::new(),
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
                (&freshness, &keys),
                &BTreeMap::new(),
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
                    (&freshness, &keys),
                    &BTreeMap::new(),
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
        let handoff_change = CommittedEventFullView {
            commit: ordinary_commit.clone(),
            event: ordinary.clone(),
        };
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
        // A concurrent append after the authority read is not a fork. The
        // old cut must publish nothing, and a fresh signed cut must verify
        // the same page before it can advance the replica.
        let current_bundle = replica.authority.as_ref().unwrap().clone();
        let mut earlier_bundle = current_bundle.clone();
        earlier_bundle.realm_stream_head = CommitStreamHead {
            stream_ref: stream_ref.clone(),
            stream_position: 0,
            commit_id: outcome.committed_events[0].commit().commit_id.clone(),
        };
        earlier_bundle.current_assertion.realm_stream_head =
            earlier_bundle.realm_stream_head.clone();
        earlier_bundle.current_assertion.signature = sign_detached_object(
            &arkret_canonical::unsigned_value(&earlier_bundle.current_assertion, &["signature"])
                .unwrap(),
            DetachedSignatureContext::RealmAuthorityCurrentAssertion,
            method.clone(),
            now,
            &route.signing_key,
        )
        .unwrap();
        let mut racing_replica = RealmReplica::new(request.realm_id.clone());
        racing_replica
            .install_verified_authority(&authority_request, earlier_bundle, &freshness, &keys)
            .unwrap();
        let before = racing_replica.clone();
        let error = racing_replica
            .apply_verified_scan(&request, outcome.clone(), &freshness, &keys)
            .unwrap_err();
        assert!(matches!(error, Error::AuthorityCutBehind));
        assert_eq!(
            crate::classify_error(&error),
            crate::RunErrorClass::RetryableTransport
        );
        assert_eq!(racing_replica, before);
        let mut forged_future = outcome.clone();
        let CommittedEventView::Full(second) = &mut forged_future.committed_events[1] else {
            unreachable!()
        };
        second.commit.signature.signed_digest =
            arkret_wire::Hash::new(format!("sha256:{}", "f".repeat(64))).unwrap();
        let error = racing_replica
            .apply_verified_scan(&request, forged_future, &freshness, &keys)
            .unwrap_err();
        assert!(matches!(error, Error::Protocol(_)));
        assert_eq!(racing_replica, before);
        racing_replica
            .install_verified_authority(&authority_request, current_bundle, &freshness, &keys)
            .unwrap();
        assert_eq!(
            racing_replica
                .apply_verified_scan(&request, outcome.clone(), &freshness, &keys)
                .unwrap()
                .rows()
                .len(),
            2
        );

        let mut fork = outcome.clone();
        let CommittedEventView::Full(second) = &mut fork.committed_events[1] else {
            unreachable!()
        };
        second.commit.commit_id = arkret_wire::RealmCommitId::from_digest([0x77; 32]);
        let before = replica.clone();
        let error = replica
            .apply_verified_scan(&request, fork, &freshness, &keys)
            .unwrap_err();
        assert!(matches!(error, Error::Protocol(_)));
        assert_eq!(
            crate::classify_error(&error),
            crate::RunErrorClass::ProtocolViolation
        );
        assert_eq!(replica, before);

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
            .apply_verified_scan(&request, outcome.clone(), &freshness, &keys)
            .unwrap();
        assert_eq!(accepted.rows().len(), 2);
        assert_eq!(
            replica.verified_head(&stream_ref).unwrap().stream_position,
            1
        );

        // A fresh nonce does not require downloading the authenticated prefix
        // again; a refresh still verifies the complete authority chain.
        let mut refreshed = replica.authority.as_ref().unwrap().clone();
        let renewed_nonce = arkret_wire::Base64UrlString::new("DDDDDDDDDDDDDDDDDDDDDD").unwrap();
        refreshed.current_assertion.nonce = renewed_nonce.clone();
        refreshed.current_assertion.signature = sign_detached_object(
            &arkret_canonical::unsigned_value(&refreshed.current_assertion, &["signature"])
                .unwrap(),
            DetachedSignatureContext::RealmAuthorityCurrentAssertion,
            method.clone(),
            now,
            &route.signing_key,
        )
        .unwrap();
        let renewed_request = AuthorityBundleRequest {
            realm_id: request.realm_id.clone(),
            nonce: renewed_nonce.clone(),
        };
        let renewed_freshness = RealmAuthorityFreshness::new(now, renewed_nonce);
        replica
            .refresh_verified_authority(
                &renewed_request,
                refreshed.clone(),
                &renewed_freshness,
                &keys,
            )
            .unwrap();
        assert_eq!(replica.verified_head(&stream_ref), Some(&snapshot_head));
        let before = replica.clone();
        assert!(
            replica
                .refresh_verified_authority(&renewed_request, refreshed.clone(), &freshness, &keys)
                .is_err()
        );
        assert_eq!(replica, before);
        assert!(
            replica
                .refresh_verified_authority(
                    &renewed_request,
                    refreshed.clone(),
                    &renewed_freshness,
                    &RealmAuthorityKeyMap::new()
                )
                .is_err()
        );
        assert_eq!(replica, before);
        let mut forked = refreshed.clone();
        forked.realm_stream_head.commit_id = arkret_wire::RealmCommitId::from_digest([0x71; 32]);
        forked.current_assertion.realm_stream_head = forked.realm_stream_head.clone();
        forked.current_assertion.signature = sign_detached_object(
            &arkret_canonical::unsigned_value(&forked.current_assertion, &["signature"]).unwrap(),
            DetachedSignatureContext::RealmAuthorityCurrentAssertion,
            method.clone(),
            now,
            &route.signing_key,
        )
        .unwrap();
        assert!(
            replica
                .refresh_verified_authority(&renewed_request, forked, &renewed_freshness, &keys)
                .is_err()
        );
        assert_eq!(replica, before);
        replica.release_verified_rows();
        let anchor = replica.verified_anchor(&stream_ref).unwrap().clone();
        let mut reloaded = RealmReplica::new(request.realm_id.clone());
        assert!(
            reloaded
                .restore_verified_anchor(&anchor, &renewed_freshness, &keys)
                .is_err()
        );
        reloaded
            .install_verified_authority(&renewed_request, refreshed, &renewed_freshness, &keys)
            .unwrap();
        let before = reloaded.clone();
        assert!(
            reloaded
                .restore_verified_anchor(&anchor, &freshness, &keys)
                .is_err()
        );
        assert_eq!(reloaded, before);
        let mut forged_anchor = anchor.clone();
        forged_anchor.signature.signed_digest =
            arkret_wire::Hash::new(format!("sha256:{}", "f".repeat(64))).unwrap();
        assert!(
            reloaded
                .restore_verified_anchor(&forged_anchor, &renewed_freshness, &keys)
                .is_err()
        );
        assert_eq!(reloaded, before);
        reloaded
            .restore_verified_anchor(&anchor, &renewed_freshness, &keys)
            .unwrap();
        assert_eq!(reloaded.verified_head(&stream_ref), Some(&snapshot_head));
        let continuation = StreamScanRequest {
            direction: StreamScanDirection::After(Some(snapshot_head.stream_position)),
            ..request.clone()
        };
        let empty = StreamScanOutcome {
            committed_events: vec![],
            ..outcome
        };
        assert!(
            replica
                .apply_verified_scan(&continuation, empty.clone(), &renewed_freshness, &keys)
                .unwrap()
                .rows()
                .is_empty()
        );
        assert_eq!(replica.verified_head(&stream_ref), Some(&snapshot_head));
        assert!(
            reloaded
                .apply_verified_scan(&continuation, empty, &renewed_freshness, &keys)
                .unwrap()
                .rows()
                .is_empty()
        );
        assert_eq!(reloaded.verified_anchor(&stream_ref), Some(&anchor));

        // A genuinely signed successor term preserves the verified old-term
        // tail. Missing hops, missing successor keys and rollback cannot
        // alter that tail, even when the Realm position has not changed.
        let successor = crate::service_route_material::test_fixture::current_web_route_fixture(
            "station-b.example",
            "station",
            0xB2,
        );
        let successor_method = DidUrl::new("did:web:station-b.example#signing-1").unwrap();
        let successor_id =
            project_did_to_core_id(&Did::new("did:web:station-b.example").unwrap()).unwrap();
        let mut handoff_snapshot = multi.clone();
        for head in &mut handoff_snapshot.visible_stream_heads {
            *head = if head.stream_ref == stream_ref {
                snapshot_head.clone()
            } else {
                multi_replica
                    .verified_head(&head.stream_ref)
                    .unwrap()
                    .clone()
            };
        }
        sign_snapshot(&mut handoff_snapshot);
        let mut handoff = arkret_wire::RealmAuthorityHandoff {
            handoff_id: arkret_wire::RealmAuthorityHandoffId::from_digest([0x31; 32]),
            realm_id: request.realm_id.clone(),
            from_generation: 0,
            to_generation: 1,
            from_service_id: reloaded
                .authority
                .as_ref()
                .unwrap()
                .current_service_id
                .clone(),
            to_service_id: successor_id.clone(),
            final_stream_heads_digest: arkret_wire::Hash::new(
                arkret_canonical::canonical::canonical_sha256(
                    &handoff_snapshot.visible_stream_heads,
                )
                .unwrap(),
            )
            .unwrap(),
            snapshot_ref: handoff_snapshot.snapshot_id.clone(),
            historical_signer_facts_digest: Some(
                arkret_models_collaboration::authority_commit::historical_signer_facts_digest(&[])
                    .unwrap(),
            ),
            change_event_ref: handoff_change.event.event_id.clone(),
            change_commit_id: handoff_change.commit.commit_id.clone(),
            old_authority_signature: crate::test_fixtures::detached_signature(
                DetachedSignatureContext::RealmAuthorityHandoffOld,
            ),
            new_authority_acceptance_signature: crate::test_fixtures::detached_signature(
                DetachedSignatureContext::RealmAuthorityHandoffNewAcceptance,
            ),
        };
        let unsigned = arkret_canonical::unsigned_value(
            &handoff,
            &[
                "old_authority_signature",
                "new_authority_acceptance_signature",
            ],
        )
        .unwrap();
        handoff.old_authority_signature = sign_detached_object(
            &unsigned,
            DetachedSignatureContext::RealmAuthorityHandoffOld,
            method.clone(),
            now,
            &route.signing_key,
        )
        .unwrap();
        handoff.new_authority_acceptance_signature = sign_detached_object(
            &unsigned,
            DetachedSignatureContext::RealmAuthorityHandoffNewAcceptance,
            successor_method.clone(),
            now,
            &successor.signing_key,
        )
        .unwrap();
        let mut successor_bundle = reloaded.authority.as_ref().unwrap().clone();
        successor_bundle
            .authority_transitions
            .push(arkret_wire::RealmAuthorityTransition {
                change_event: handoff_change.event,
                change_commit: handoff_change.commit,
                handoff: handoff.clone(),
            });
        successor_bundle.current_generation = 1;
        successor_bundle.current_service_id = successor_id.clone();
        successor_bundle.current_route_record =
            serde_json::to_value(&successor.resolution).unwrap();
        successor_bundle.current_assertion.current_generation = 1;
        successor_bundle.current_assertion.current_service_id = successor_id;
        successor_bundle.current_assertion.last_handoff_ref = Some(handoff.handoff_id.clone());
        let successor_request = AuthorityBundleRequest {
            realm_id: request.realm_id.clone(),
            nonce: arkret_wire::Base64UrlString::new("EEEEEEEEEEEEEEEEEEEEEE").unwrap(),
        };
        let successor_freshness =
            RealmAuthorityFreshness::new(now, successor_request.nonce.clone());
        successor_bundle.current_assertion.nonce = successor_request.nonce.clone();
        successor_bundle.current_assertion.signature = sign_detached_object(
            &arkret_canonical::unsigned_value(&successor_bundle.current_assertion, &["signature"])
                .unwrap(),
            DetachedSignatureContext::RealmAuthorityCurrentAssertion,
            successor_method.clone(),
            now,
            &successor.signing_key,
        )
        .unwrap();
        let successor_keys = keys.clone().with_key(
            &successor_method,
            PublicKeyMaterial::Ed25519Raw {
                bytes: successor.signing_key.verifying_key().to_bytes().to_vec(),
            },
        );
        arkret_models_collaboration::authority_commit::AuthorityHandoffRequest {
            handoff: handoff.clone(),
            final_stream_heads: handoff_snapshot.visible_stream_heads.clone(),
            snapshot: handoff_snapshot,
            authority_bundle: successor_bundle.clone(),
            historical_signer_facts: Some(Vec::new()),
        }
        .validate_shape()
        .unwrap();
        let independent_heads = multi_replica.verified_streams.clone();
        multi_replica
            .refresh_verified_authority(
                &successor_request,
                successor_bundle.clone(),
                &successor_freshness,
                &successor_keys,
            )
            .unwrap();
        assert_eq!(multi_replica.verified_streams, independent_heads);
        let before_handoff = reloaded.clone();
        let mut missing_hop = successor_bundle.clone();
        missing_hop.authority_transitions.clear();
        assert!(
            reloaded
                .refresh_verified_authority(
                    &successor_request,
                    missing_hop,
                    &successor_freshness,
                    &successor_keys
                )
                .is_err()
        );
        assert_eq!(reloaded, before_handoff);
        assert!(
            reloaded
                .refresh_verified_authority(
                    &successor_request,
                    successor_bundle.clone(),
                    &successor_freshness,
                    &keys
                )
                .is_err()
        );
        assert_eq!(reloaded, before_handoff);
        reloaded
            .refresh_verified_authority(
                &successor_request,
                successor_bundle,
                &successor_freshness,
                &successor_keys,
            )
            .unwrap();
        assert_eq!(reloaded.verified_anchor(&stream_ref), Some(&anchor));
        let after_handoff = reloaded.clone();
        assert!(
            reloaded
                .refresh_verified_authority(
                    &renewed_request,
                    before_handoff.authority.unwrap(),
                    &renewed_freshness,
                    &keys
                )
                .is_err()
        );
        assert_eq!(reloaded, after_handoff);
        let successor_event = arkret_wire::test_support::raw_event_at(
            EventKind::MessageCreate.as_str(),
            ScopeRef::Realm {
                realm_id: request.realm_id.clone(),
            },
            arkret_wire::DidCoreId::new("ak:did_core:web:founder.example").unwrap(),
            reloaded
                .authority
                .as_ref()
                .unwrap()
                .current_service_id
                .clone(),
            serde_json::json!({}),
            now,
        )
        .unwrap();
        let mut successor_commit =
            crate::test_fixtures::commit(3, &successor_event, stream_ref.clone(), 2);
        successor_commit.governance_generation = 1;
        successor_commit.authority_ref = RealmCommitAuthorityRef::Handoff(handoff.handoff_id);
        successor_commit.committed_at = now;
        successor_commit.previous_commit_ref = Some(snapshot_head.commit_id.clone());
        successor_commit.commit_id =
            arkret_wire::RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
                arkret_canonical::canonical_json_bytes(
                    &arkret_canonical::unsigned_value(
                        &successor_commit,
                        &["commit_id", "signature"],
                    )
                    .unwrap(),
                )
                .unwrap(),
            ));
        successor_commit.signature = sign_detached_object(
            &arkret_canonical::unsigned_value(&successor_commit, &["signature"]).unwrap(),
            DetachedSignatureContext::RealmCommit,
            successor_method.clone(),
            now,
            &successor.signing_key,
        )
        .unwrap();
        let mut appended_bundle = reloaded.authority.as_ref().unwrap().clone();
        appended_bundle.realm_stream_head = CommitStreamHead {
            stream_ref: stream_ref.clone(),
            stream_position: 2,
            commit_id: successor_commit.commit_id.clone(),
        };
        appended_bundle.current_assertion.realm_stream_head =
            appended_bundle.realm_stream_head.clone();
        let appended_request = AuthorityBundleRequest {
            realm_id: request.realm_id.clone(),
            nonce: arkret_wire::Base64UrlString::new("FFFFFFFFFFFFFFFFFFFFFF").unwrap(),
        };
        let appended_freshness = RealmAuthorityFreshness::new(now, appended_request.nonce.clone());
        appended_bundle.current_assertion.nonce = appended_request.nonce.clone();
        appended_bundle.current_assertion.signature = sign_detached_object(
            &arkret_canonical::unsigned_value(&appended_bundle.current_assertion, &["signature"])
                .unwrap(),
            DetachedSignatureContext::RealmAuthorityCurrentAssertion,
            successor_method,
            now,
            &successor.signing_key,
        )
        .unwrap();
        reloaded
            .refresh_verified_authority(
                &appended_request,
                appended_bundle,
                &appended_freshness,
                &successor_keys,
            )
            .unwrap();
        let accepted_tail = reloaded
            .apply_verified_scan(
                &continuation,
                StreamScanOutcome {
                    committed_events: vec![CommittedEventView::Full(CommittedEventFullView {
                        commit: successor_commit.clone(),
                        event: successor_event,
                    })],
                    readable_floor: Some(ReadableFloor {
                        oldest_position: 0,
                        floor_commit_id: reloaded
                            .authority
                            .as_ref()
                            .unwrap()
                            .genesis_commit
                            .commit_id
                            .clone(),
                        floor_reason: ReadableFloorReason::StreamStart,
                    }),
                    truncated: false,
                },
                &appended_freshness,
                &successor_keys,
            )
            .unwrap();
        assert_eq!(accepted_tail.rows().len(), 1);
        assert_eq!(
            reloaded.verified_anchor(&stream_ref),
            Some(&successor_commit)
        );
    }
}
