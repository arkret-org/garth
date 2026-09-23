//! Client-side state for independent Realm, Circle, and Sidecar commit streams.

use std::collections::BTreeMap;

use arkret_identity::{
    RealmAuthorityFreshness, RealmAuthorityKeyDirectory, verify_realm_authority_bundle,
};
use arkret_wire::{
    AuthorityBundleRequest, CommitStreamHead, CommitStreamRef, CommittedEventView,
    RealmAuthorityBundle, RealmId, RealmStateSnapshot, StreamScanOutcome, StreamScanRequest,
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
        let replica = self.streams.entry(request.stream_ref.clone()).or_default();
        if let Some(existing) = &replica.head
            && request.after_position != Some(existing.stream_position)
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
        let existing = self
            .verified_streams
            .get(&request.stream_ref)
            .and_then(|stream| stream.head.as_ref());
        match (existing, request.after_position) {
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
    Ok(())
}

#[cfg(test)]
mod tests {
    use arkret_identity::{RealmAuthorityFreshness, RealmAuthorityKeyMap};
    use arkret_wire::{CommittedEventFullView, EventKind};
    use chrono::Duration;

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
        let outcome = StreamScanOutcome {
            committed_events: vec![CommittedEventView::Full(CommittedEventFullView {
                commit,
                event,
            })],
            truncated: false,
        };
        let request = StreamScanRequest {
            realm_id: realm_id.clone(),
            stream_ref,
            after_position: None,
            limit: 1,
        };
        let freshness = RealmAuthorityFreshness::new(
            crate::test_fixtures::at(2),
            arkret_wire::Base64UrlString::new("AAAAAAAAAAAAAAAAAAAAAA").unwrap(),
            Duration::minutes(1),
        )
        .unwrap();
        let mut replica = RealmReplica::new(realm_id);
        let before = replica.clone();

        assert!(
            replica
                .apply_verified_scan(&request, outcome, &freshness, &RealmAuthorityKeyMap::new())
                .is_err()
        );
        assert_eq!(replica, before);
    }
}
