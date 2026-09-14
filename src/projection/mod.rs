use std::collections::{BTreeMap, BTreeSet};

use crate::protocol::{Event, EventId, RealmId, Result};

mod current_results;
mod realm_merge;
mod seal_view;
mod security_state;
mod sidecar;
mod sidecar_exchange;

pub use current_results::{
    CurrentCoverageCleanup, CurrentInstallPlan, CurrentRealmProgress, TimelineSegmentInstall,
    TimelineWindowLevel, TimelineWindowPlan, TimelineWindowProgress, plan_current_entry,
    plan_current_install, plan_timeline_window,
};
pub use realm_merge::{RealmProjectionFrame, reconcile_realm_projection};
pub use seal_view::LocalSealView;
pub use security_state::{
    encryption_profile_is_encrypted, non_empty_string, projection_for_scope_id,
    realm_authority_root_controller_for_realm, realm_authority_root_value_for_realm,
    realm_projection_is_encrypted, realm_projection_security_state,
    security_projection_for_scope_id, strand_projection_security_state, string_field,
};
pub use sidecar::{
    SidecarProjectionFold, SidecarTimelineEvent, SidecarTimelineItem, merge_sidecar_timeline,
};
pub use sidecar_exchange::{
    SidecarExchangeAgentFact, SidecarExchangeCacheDecision, SidecarExchangeControlFact,
    SidecarExchangeFoldScope, SidecarExchangeRequestFact, evaluate_sidecar_exchange_cache,
    fold_sidecar_exchange, fold_sidecar_exchange_for_current_admission,
};

pub trait RealmEventProjector {
    fn apply_domain_events(&mut self, realm_id: &RealmId, events: &[Event]) -> Result<()>;
}

/// Order-independent accepted Event set for one Realm projection mount.
///
/// This type deliberately carries no resolved object value. `causal_heads`
/// below is the Realm Event-DAG frontier, not a Cell-register projection;
/// registered causal-register Cells are resolved by the SDK's deterministic
/// `(depth, EventId)` rule.
#[derive(Clone, Debug)]
pub struct RealmProjectionState {
    pub realm_id: RealmId,
    causal_heads: BTreeSet<EventId>,
    accepted_events: BTreeMap<EventId, Event>,
}

impl RealmProjectionState {
    pub fn causal_heads(&self) -> impl ExactSizeIterator<Item = &EventId> {
        self.causal_heads.iter()
    }

    pub fn accepted_events(&self) -> impl ExactSizeIterator<Item = &Event> {
        self.accepted_events.values()
    }
}

#[derive(Clone, Debug)]
pub struct ProjectionMount {
    state: RealmProjectionState,
}

impl ProjectionMount {
    pub fn new(realm_id: RealmId) -> Self {
        Self {
            state: RealmProjectionState {
                realm_id,
                causal_heads: BTreeSet::new(),
                accepted_events: BTreeMap::new(),
            },
        }
    }

    pub fn state(&self) -> &RealmProjectionState {
        &self.state
    }

    pub fn apply_events(&mut self, events: &[Event]) -> Result<()> {
        let mut batch_events = BTreeMap::new();
        for event in events {
            if event.realm_id != self.state.realm_id {
                return Err(arkret_wire::WireError::Protocol(
                    "projection Event belongs to a different Realm".to_owned(),
                )
                .into());
            }
            if let Some(existing) = self.state.accepted_events.get(&event.event_id) {
                if existing != event {
                    return Err(arkret_wire::WireError::Protocol(
                        "projection Event id collision".to_owned(),
                    )
                    .into());
                }
                continue;
            }
            if let Some(existing) = batch_events.insert(event.event_id.clone(), event) {
                if existing != event {
                    return Err(arkret_wire::WireError::Protocol(
                        "projection batch contains an Event id collision".to_owned(),
                    )
                    .into());
                }
            }
            for previous in &event.prev_refs {
                if !self.state.accepted_events.contains_key(previous)
                    && !batch_events.contains_key(previous)
                    && !events
                        .iter()
                        .any(|candidate| &candidate.event_id == previous)
                {
                    return Err(arkret_wire::WireError::Protocol(format!(
                        "missing causal dependency: {previous}"
                    ))
                    .into());
                }
            }
        }
        let mut causally_available = self
            .state
            .accepted_events
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>();
        let mut unresolved = batch_events.keys().cloned().collect::<BTreeSet<_>>();
        while !unresolved.is_empty() {
            let ready = unresolved
                .iter()
                .filter(|event_id| {
                    batch_events[*event_id]
                        .prev_refs
                        .iter()
                        .all(|previous| causally_available.contains(previous))
                })
                .cloned()
                .collect::<Vec<_>>();
            if ready.is_empty() {
                return Err(arkret_wire::WireError::Protocol(
                    "projection batch contains a causal cycle".to_owned(),
                )
                .into());
            }
            for event_id in ready {
                unresolved.remove(&event_id);
                causally_available.insert(event_id);
            }
        }
        let mut inserted = Vec::new();
        for event in events {
            if self.state.accepted_events.contains_key(&event.event_id) {
                continue;
            }
            self.state.causal_heads.insert(event.event_id.clone());
            self.state
                .accepted_events
                .insert(event.event_id.clone(), event.clone());
            inserted.push(event);
        }
        for event in inserted {
            for previous in &event.prev_refs {
                self.state.causal_heads.remove(previous);
            }
        }
        Ok(())
    }

    pub fn apply_events_with_domain<P>(&mut self, events: &[Event], projector: &mut P) -> Result<()>
    where
        P: RealmEventProjector,
    {
        self.apply_events(events)?;
        projector.apply_domain_events(&self.state.realm_id, events)
    }
}

impl RealmEventProjector for () {
    fn apply_domain_events(&mut self, _realm_id: &RealmId, _events: &[Event]) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::RealmId;

    #[derive(Default)]
    struct CountingProjector {
        calls: usize,
        last_realm: Option<RealmId>,
        last_len: usize,
    }

    impl RealmEventProjector for CountingProjector {
        fn apply_domain_events(&mut self, realm_id: &RealmId, events: &[Event]) -> Result<()> {
            self.calls += 1;
            self.last_realm = Some(realm_id.clone());
            self.last_len = events.len();
            Ok(())
        }
    }

    fn realm_id() -> RealmId {
        RealmId::new("ak:realm:AfF-hFqRoMbajXkPapH-xaq0xwK-UKt2ph2zTs9JZRAO").unwrap()
    }

    #[test]
    fn retains_the_event_set_then_runs_the_domain_projector() {
        let realm_id = realm_id();
        let mut mount = ProjectionMount::new(realm_id.clone());
        let mut projector = CountingProjector::default();

        mount.apply_events_with_domain(&[], &mut projector).unwrap();

        assert_eq!(mount.state().realm_id, realm_id);
        assert_eq!(projector.calls, 1);
        assert_eq!(projector.last_realm.as_ref(), Some(&realm_id));
        assert_eq!(projector.last_len, 0);
    }
}
