//! Client-side state for independent Realm, Circle, and Sidecar commit streams.

use std::collections::BTreeMap;

use arkret_wire::{
    CommitStreamHead, CommitStreamRef, CommittedEventView, RealmAuthorityBundle, RealmId,
    RealmStateSnapshot, StreamScanOutcome, StreamScanRequest,
};

use crate::{Error, Result};

#[derive(Clone, Debug, Default, PartialEq)]
pub struct StreamReplica {
    pub head: Option<CommitStreamHead>,
    pub items: Vec<CommittedEventView>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct RealmReplica {
    pub realm_id: RealmId,
    pub authority: Option<RealmAuthorityBundle>,
    pub snapshot: Option<RealmStateSnapshot>,
    pub streams: BTreeMap<CommitStreamRef, StreamReplica>,
}

impl RealmReplica {
    pub fn new(realm_id: RealmId) -> Self {
        Self {
            realm_id,
            authority: None,
            snapshot: None,
            streams: BTreeMap::new(),
        }
    }

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
