use std::collections::{BTreeMap, BTreeSet};

use crate::protocol::models::{
    AgentSidecarDisplayMode, AgentSidecarExchangeOrigin, AgentSidecarExchangeProjection,
    AgentSidecarProjectionProvenance, AgentSidecarViewState,
};
use crate::protocol::{EventId, RealmId, Result, StrandId};

/// Incremental controller-private Sidecar projection registry.
///
/// View states remain encrypted Account Data and fold by LWW stamp. Exchange
/// projections are deterministic local Event-fold outputs
/// ([`super::sidecar_exchange::fold_sidecar_exchange`]): they never arrive
/// over the account stream, never merge across devices, and each refold
/// replaces the cached entry wholesale (`zh/models/sidecar.md` §7.2.4).
#[derive(Clone, Debug, Default)]
pub struct SidecarProjectionFold {
    view_states: BTreeMap<(String, String, String), AgentSidecarViewState>,
    exchanges: BTreeMap<String, AgentSidecarExchangeProjection>,
}

impl SidecarProjectionFold {
    pub fn apply_view_state(&mut self, value: AgentSidecarViewState) -> bool {
        let key = (
            value.controller_id.to_string(),
            value.context_ref.realm_id.to_string(),
            value.context_ref.strand_id.to_string(),
        );
        let should_replace = self.view_states.get(&key).is_none_or(|current| {
            (
                value.updated_hlc.to_string(),
                value.origin_device_id.to_string(),
            ) > (
                current.updated_hlc.to_string(),
                current.origin_device_id.to_string(),
            )
        });
        if should_replace {
            self.view_states.insert(key, value);
        }
        should_replace
    }

    /// Install one deterministic Event-fold result. There is no LWW and no
    /// cross-device merge: the fold of the local accepted history is always
    /// authoritative for its exchange, so the entry is replaced wholesale.
    pub fn apply_folded_exchange(&mut self, value: AgentSidecarExchangeProjection) -> Result<()> {
        value.validate()?;
        self.exchanges.insert(value.exchange_id.to_string(), value);
        Ok(())
    }

    /// Drop one cached exchange (e.g. after a failed cache frontier check).
    /// The projection is always rebuildable from private history.
    pub fn remove_exchange(&mut self, exchange_id: &str) -> Option<AgentSidecarExchangeProjection> {
        self.exchanges.remove(exchange_id)
    }

    pub fn view_state(
        &self,
        controller_id: &str,
        realm_id: &RealmId,
        strand_id: &StrandId,
    ) -> Option<&AgentSidecarViewState> {
        self.view_states.get(&(
            controller_id.to_owned(),
            realm_id.to_string(),
            strand_id.to_string(),
        ))
    }

    pub fn exchanges_for_track<'a>(
        &'a self,
        realm_id: &'a RealmId,
        strand_id: &'a StrandId,
        track_name: &'a str,
    ) -> impl Iterator<Item = &'a AgentSidecarExchangeProjection> + 'a {
        self.exchanges.values().filter(move |exchange| {
            exchange.source_track_ref.realm_id == *realm_id
                && exchange.source_track_ref.strand_id == *strand_id
                && exchange.source_track_ref.track_name == track_name
        })
    }

    pub fn merge_timeline<T: Clone>(
        &self,
        realm_id: &RealmId,
        strand_id: &StrandId,
        track_name: &str,
        mode: AgentSidecarDisplayMode,
        shared: &[SidecarTimelineEvent<T>],
        private: &[SidecarTimelineEvent<T>],
    ) -> Vec<SidecarTimelineItem<T>> {
        merge_sidecar_timeline(
            self.exchanges_for_track(realm_id, strand_id, track_name),
            mode,
            shared,
            private,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SidecarTimelineEvent<T> {
    pub event_id: EventId,
    /// Canonical HLC string. Canonical HLC lexical order is chronological.
    pub hlc: String,
    pub track_name: String,
    pub value: T,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SidecarTimelineItem<T> {
    pub event_id: EventId,
    pub provenance: AgentSidecarProjectionProvenance,
    pub value: T,
}

#[derive(Clone, Debug)]
struct EchoOrder {
    anchor: Option<String>,
    source_hlc: String,
    exchange_id: String,
}

/// Deterministically merge one Track's shared timeline with the controller's
/// private Sidecar timeline. Source-routed events are inserted immediately
/// after their shared frontier anchor; echoes with an unsynchronized anchor
/// remain pending until that anchor is present.
/// Event-id dedupe guarantees a private Event never renders once as native
/// content and again as an account-data echo.
pub fn merge_sidecar_timeline<'a, T: Clone>(
    exchanges: impl IntoIterator<Item = &'a AgentSidecarExchangeProjection>,
    mode: AgentSidecarDisplayMode,
    shared: &[SidecarTimelineEvent<T>],
    private: &[SidecarTimelineEvent<T>],
) -> Vec<SidecarTimelineItem<T>> {
    let track_name = private
        .first()
        .map(|event| event.track_name.as_str())
        .or_else(|| shared.first().map(|event| event.track_name.as_str()));
    let mut echo_order = BTreeMap::<String, EchoOrder>::new();
    for exchange in exchanges {
        if exchange.origin != AgentSidecarExchangeOrigin::SourceTrackRouted
            || track_name.is_some_and(|track| exchange.source_track_ref.track_name != track)
        {
            continue;
        }
        let order = EchoOrder {
            anchor: exchange
                .source_frontier_anchor
                .as_ref()
                .map(ToString::to_string),
            source_hlc: exchange.source_hlc.to_string(),
            exchange_id: exchange.exchange_id.to_string(),
        };
        for event_id in std::iter::once(&exchange.private_request_event_id)
            .chain(exchange.user_facing_response_event_ids.iter())
        {
            echo_order.insert(event_id.to_string(), order.clone());
        }
    }

    let mut private_events = private.iter().collect::<Vec<_>>();
    private_events.sort_by(|left, right| {
        left.hlc
            .cmp(&right.hlc)
            .then_with(|| left.event_id.as_str().cmp(right.event_id.as_str()))
    });
    if mode == AgentSidecarDisplayMode::SidecarOnly {
        return unique_private_items(private_events, &echo_order, false);
    }

    let mut shared_events = shared.iter().collect::<Vec<_>>();
    shared_events.sort_by(|left, right| {
        left.hlc
            .cmp(&right.hlc)
            .then_with(|| left.event_id.as_str().cmp(right.event_id.as_str()))
    });
    let shared_ids = shared_events
        .iter()
        .map(|event| event.event_id.to_string())
        .collect::<BTreeSet<_>>();
    let mut anchored = BTreeMap::<String, Vec<&SidecarTimelineEvent<T>>>::new();
    let mut chronological = Vec::new();
    for event in private_events {
        match echo_order.get(event.event_id.as_str()) {
            Some(order) => match order.anchor.as_ref() {
                Some(anchor) if shared_ids.contains(anchor) => {
                    anchored.entry(anchor.clone()).or_default().push(event);
                }
                Some(_) => {}
                None => chronological.push(event),
            },
            None => chronological.push(event),
        }
    }
    for events in anchored.values_mut() {
        events.sort_by(|left, right| {
            let left_order = &echo_order[left.event_id.as_str()];
            let right_order = &echo_order[right.event_id.as_str()];
            (
                &left_order.source_hlc,
                &left_order.exchange_id,
                left.event_id.as_str(),
            )
                .cmp(&(
                    &right_order.source_hlc,
                    &right_order.exchange_id,
                    right.event_id.as_str(),
                ))
        });
    }

    let mut output = Vec::with_capacity(shared_events.len() + private.len());
    let mut seen = BTreeSet::new();
    let mut chronological = chronological.into_iter().peekable();
    for shared_event in shared_events {
        while chronological
            .peek()
            .is_some_and(|private_event| private_event.hlc <= shared_event.hlc)
        {
            push_private(
                &mut output,
                &mut seen,
                chronological.next().unwrap(),
                &echo_order,
            );
        }
        if seen.insert(shared_event.event_id.to_string()) {
            output.push(SidecarTimelineItem {
                event_id: shared_event.event_id.clone(),
                provenance: AgentSidecarProjectionProvenance::Shared,
                value: shared_event.value.clone(),
            });
        }
        if let Some(events) = anchored.remove(shared_event.event_id.as_str()) {
            for event in events {
                push_private(&mut output, &mut seen, event, &echo_order);
            }
        }
    }
    for event in chronological {
        push_private(&mut output, &mut seen, event, &echo_order);
    }
    output
}

fn unique_private_items<T: Clone>(
    events: Vec<&SidecarTimelineEvent<T>>,
    echo_order: &BTreeMap<String, EchoOrder>,
    echo_provenance: bool,
) -> Vec<SidecarTimelineItem<T>> {
    let mut output = Vec::with_capacity(events.len());
    let mut seen = BTreeSet::new();
    for event in events {
        if seen.insert(event.event_id.to_string()) {
            output.push(SidecarTimelineItem {
                event_id: event.event_id.clone(),
                provenance: if echo_provenance && echo_order.contains_key(event.event_id.as_str()) {
                    AgentSidecarProjectionProvenance::PrivateEcho
                } else {
                    AgentSidecarProjectionProvenance::Private
                },
                value: event.value.clone(),
            });
        }
    }
    output
}

fn push_private<T: Clone>(
    output: &mut Vec<SidecarTimelineItem<T>>,
    seen: &mut BTreeSet<String>,
    event: &SidecarTimelineEvent<T>,
    echo_order: &BTreeMap<String, EchoOrder>,
) {
    if seen.insert(event.event_id.to_string()) {
        output.push(SidecarTimelineItem {
            event_id: event.event_id.clone(),
            provenance: if echo_order.contains_key(event.event_id.as_str()) {
                AgentSidecarProjectionProvenance::PrivateEcho
            } else {
                AgentSidecarProjectionProvenance::Private
            },
            value: event.value.clone(),
        });
    }
}

#[cfg(test)]
mod tests {
    use crate::protocol::models::{
        AgentSidecarExchangeCompletionPolicy, AgentSidecarExchangeFoldedFrontier,
        AgentSidecarExchangeId, AgentSidecarExchangeProjectionSchema, AgentSidecarExchangeStatus,
        AgentSidecarSourceTrackRef, agent_sidecar_exchange_event_set_digest,
    };
    use crate::protocol::{Did, Hlc, NonEmptyString, SidecarId};

    use super::*;

    fn event_id(suffix: &str) -> EventId {
        EventId::new(format!(
            "ak:event:01964137-0000-7000-8000-0000000000{suffix}"
        ))
        .unwrap()
    }

    fn event(suffix: &str, hlc: &str, value: &'static str) -> SidecarTimelineEvent<&'static str> {
        SidecarTimelineEvent {
            event_id: event_id(suffix),
            hlc: hlc.to_owned(),
            track_name: "discussion".to_owned(),
            value,
        }
    }

    fn projection(anchor: EventId, private_event: EventId) -> AgentSidecarExchangeProjection {
        let addressed_agent = Did::new("did:webvh:z6mkfixture:assistant.agents.example").unwrap();
        AgentSidecarExchangeProjection {
            schema: AgentSidecarExchangeProjectionSchema::V1,
            controller_id: Did::new("did:web:example.com:users:alice").unwrap(),
            sidecar_id: SidecarId::new(
                "ak:sidecar:01964137-0000-7000-8000-000000000032".to_owned(),
            )
            .unwrap(),
            private_strand_id: StrandId::new(
                "ak:strand:01964137-0000-7000-8000-000000000033".to_owned(),
            )
            .unwrap(),
            exchange_id: AgentSidecarExchangeId::new("Abcdefghijklmnopqrstuv").unwrap(),
            origin: AgentSidecarExchangeOrigin::SourceTrackRouted,
            source_track_ref: AgentSidecarSourceTrackRef {
                realm_id: RealmId::new("ak:realm:01964137-0000-7000-8000-000000000030".to_owned())
                    .unwrap(),
                strand_id: StrandId::new(
                    "ak:strand:01964137-0000-7000-8000-000000000031".to_owned(),
                )
                .unwrap(),
                track_name: "discussion".to_owned(),
            },
            source_frontier_anchor: Some(anchor),
            source_hlc: Hlc::new("01970e589d21-0001-a13f9c2e").unwrap(),
            client_order_key: NonEmptyString::new("device-1-1").unwrap(),
            addressed_agent_ids: vec![addressed_agent.clone()],
            completion_policy: AgentSidecarExchangeCompletionPolicy::Coordinator,
            coordinator_agent_id: addressed_agent,
            coordinator_assignment_event_id: private_event.clone(),
            participating_agent_ids: Vec::new(),
            private_request_event_id: private_event.clone(),
            user_facing_response_event_ids: Vec::new(),
            status: AgentSidecarExchangeStatus::Delivered,
            failure_reason_code: None,
            terminal_event_id: None,
            folded_frontier: AgentSidecarExchangeFoldedFrontier {
                event_ids: vec![private_event.clone()],
                event_set_digest: agent_sidecar_exchange_event_set_digest(&[private_event])
                    .unwrap(),
                max_hlc: Hlc::new("01970e589d21-0002-a13f9c2e").unwrap(),
            },
        }
    }

    #[test]
    fn merged_timeline_anchors_echo_and_dedupes_by_event_id() {
        let anchor = event_id("34");
        let private_id = event_id("35");
        let response_id = event_id("36");
        let mut projection = projection(anchor.clone(), private_id.clone());
        projection.user_facing_response_event_ids = vec![response_id.clone()];
        projection.status = AgentSidecarExchangeStatus::Complete;
        projection.terminal_event_id = Some(event_id("38"));
        let shared = vec![event("34", "01970e589d21-0001-a13f9c2e", "shared")];
        let private = vec![
            event("35", "01970e589d21-0002-a13f9c2e", "echo"),
            event("35", "01970e589d21-0002-a13f9c2e", "duplicate"),
            event("36", "01970e589d21-0003-a13f9c2e", "response"),
            event("37", "01970e589d21-0004-a13f9c2e", "internal"),
        ];

        let merged = merge_sidecar_timeline(
            [&projection],
            AgentSidecarDisplayMode::ContextMerged,
            &shared,
            &private,
        );
        assert_eq!(merged.len(), 4);
        assert_eq!(merged[0].event_id, anchor);
        assert_eq!(merged[1].event_id, private_id);
        assert_eq!(
            merged[1].provenance,
            AgentSidecarProjectionProvenance::PrivateEcho
        );
        assert_eq!(
            merged[2].provenance,
            AgentSidecarProjectionProvenance::PrivateEcho
        );
        assert_eq!(merged[2].event_id, response_id);
        assert_eq!(
            merged[3].provenance,
            AgentSidecarProjectionProvenance::Private
        );
        assert_eq!(merged[3].event_id, event_id("37"));

        let private_only = merge_sidecar_timeline(
            [&projection],
            AgentSidecarDisplayMode::SidecarOnly,
            &shared,
            &private,
        );
        assert_eq!(private_only.len(), 3);
        assert!(
            private_only
                .iter()
                .all(|item| { item.provenance == AgentSidecarProjectionProvenance::Private })
        );
    }

    #[test]
    fn merged_timeline_holds_echo_until_its_anchor_arrives() {
        let missing_anchor = event_id("34");
        let private_id = event_id("35");
        let projection = projection(missing_anchor, private_id.clone());
        let private = vec![
            event("35", "01970e589d21-0002-a13f9c2e", "echo"),
            event("36", "01970e589d21-0003-a13f9c2e", "native"),
        ];

        let merged = merge_sidecar_timeline(
            [&projection],
            AgentSidecarDisplayMode::ContextMerged,
            &[],
            &private,
        );
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].event_id, event_id("36"));

        let private_only = merge_sidecar_timeline(
            [&projection],
            AgentSidecarDisplayMode::SidecarOnly,
            &[],
            &private,
        );
        assert_eq!(private_only.len(), 2);
        assert_eq!(private_only[0].event_id, private_id);
    }

    #[test]
    fn folded_exchange_replaces_wholesale_without_lww() {
        let mut fold = SidecarProjectionFold::default();
        let initial = projection(event_id("34"), event_id("35"));
        fold.apply_folded_exchange(initial.clone()).unwrap();

        // A refold of the same exchange always wins: there is no HLC or
        // client_order_key race between devices because the cache is local.
        let mut refolded = initial.clone();
        refolded.participating_agent_ids =
            vec![Did::new("did:webvh:z6mkfixture:assistant.agents.example").unwrap()];
        fold.apply_folded_exchange(refolded.clone()).unwrap();
        let realm_id = RealmId::new("ak:realm:01964137-0000-7000-8000-000000000030").unwrap();
        let strand_id = StrandId::new("ak:strand:01964137-0000-7000-8000-000000000031").unwrap();
        let stored = fold
            .exchanges_for_track(&realm_id, &strand_id, "discussion")
            .next()
            .unwrap();
        assert_eq!(stored.participating_agent_ids.len(), 1);

        let mut invalid = initial;
        invalid.status = AgentSidecarExchangeStatus::Complete;
        assert!(fold.apply_folded_exchange(invalid).is_err());
        assert!(
            fold.remove_exchange("Abcdefghijklmnopqrstuv").is_some(),
            "cache entries are disposable"
        );
    }

    #[test]
    fn same_anchor_echoes_order_by_source_hlc_then_exchange_id() {
        let anchor = event_id("34");
        let earlier_event = event_id("35");
        let later_event = event_id("36");
        let mut earlier = projection(anchor.clone(), earlier_event.clone());
        earlier.exchange_id = AgentSidecarExchangeId::new("Aabcdefghijklmnopqrstu").unwrap();
        earlier.client_order_key = NonEmptyString::new("z-device-order").unwrap();
        let mut later = projection(anchor.clone(), later_event.clone());
        later.exchange_id = AgentSidecarExchangeId::new("Babcdefghijklmnopqrstu").unwrap();
        later.client_order_key = NonEmptyString::new("a-device-order").unwrap();
        let shared = vec![event("34", "01970e589d21-0001-a13f9c2e", "shared")];
        let private = vec![
            event("36", "01970e589d21-0002-a13f9c2e", "later"),
            event("35", "01970e589d21-0002-a13f9c2e", "earlier"),
        ];

        let merged = merge_sidecar_timeline(
            [&later, &earlier],
            AgentSidecarDisplayMode::ContextMerged,
            &shared,
            &private,
        );
        assert_eq!(
            merged
                .iter()
                .map(|item| item.event_id.clone())
                .collect::<Vec<_>>(),
            vec![anchor, earlier_event, later_event]
        );
    }

    #[test]
    fn long_history_merge_handles_ten_thousand_shared_and_two_thousand_private_events() {
        fn indexed_event(index: usize, track_name: &str) -> SidecarTimelineEvent<usize> {
            SidecarTimelineEvent {
                event_id: EventId::new(format!("ak:event:01964137-0000-7000-8000-{index:012x}"))
                    .unwrap(),
                hlc: format!("{:012x}-0001-a13f9c2e", 0x0197_0e58_9d21_u64 + index as u64),
                track_name: track_name.to_owned(),
                value: index,
            }
        }

        let shared = (0..10_000)
            .map(|index| indexed_event(index, "discussion"))
            .collect::<Vec<_>>();
        let private = (10_000..12_000)
            .map(|index| indexed_event(index, "discussion"))
            .collect::<Vec<_>>();

        let merged = merge_sidecar_timeline(
            std::iter::empty::<&AgentSidecarExchangeProjection>(),
            AgentSidecarDisplayMode::ContextMerged,
            &shared,
            &private,
        );
        assert_eq!(merged.len(), 12_000);
        assert_eq!(
            merged
                .iter()
                .filter(|item| item.provenance == AgentSidecarProjectionProvenance::Shared)
                .count(),
            10_000
        );
        assert_eq!(merged.first().map(|item| item.value), Some(0));
        assert_eq!(merged.last().map(|item| item.value), Some(11_999));

        let private_only = merge_sidecar_timeline(
            std::iter::empty::<&AgentSidecarExchangeProjection>(),
            AgentSidecarDisplayMode::SidecarOnly,
            &shared,
            &private,
        );
        assert_eq!(private_only.len(), 2_000);
        assert!(private_only.iter().all(|item| {
            item.provenance == AgentSidecarProjectionProvenance::Private && item.value >= 10_000
        }));
    }
}
