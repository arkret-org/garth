//! Deterministic Sidecar exchange Event fold (`zh/models/sidecar.md` §7.2.4).
//!
//! Exchange truth lives only in accepted native Sidecar Events:
//! the controller request binding, validated Agent binding Events, and
//! controller-authored durable control Events. This module folds those facts
//! into the controller-device-local `AgentSidecarExchangeProjection` cache.
//! Nothing here reads or writes Account Data, and given the same accepted
//! Event set every conforming device MUST produce a bit-identical projection.
//!
//! Callers are responsible for the decrypt-side gates of §7.2.2 checks 1–2:
//! every fact passed in MUST already come from an Event whose effective scope
//! is this exact Sidecar and whose source context matches the projection,
//! with a binding that passed closed-schema validation.

use std::collections::{BTreeMap, BTreeSet};

use crate::protocol::models::{
    AgentSidecarEventExchangeBinding, AgentSidecarExchangeBindingRole,
    AgentSidecarExchangeCompletionPolicy, AgentSidecarExchangeControl,
    AgentSidecarExchangeControlAction, AgentSidecarExchangeFoldedFrontier, AgentSidecarExchangeId,
    AgentSidecarExchangeOrigin, AgentSidecarExchangeProjection,
    AgentSidecarExchangeProjectionSchema, AgentSidecarExchangeRequestContext,
    AgentSidecarExchangeStatus, agent_sidecar_exchange_event_set_digest,
};
use crate::protocol::{DidCoreId, Error, EventId, Hlc, NonEmptyString, Result, SidecarId};

/// Immutable identity of the fold target. All facts are validated against it.
#[derive(Clone, Debug)]
pub struct SidecarExchangeFoldScope {
    pub controller_id: DidCoreId,
    pub sidecar_id: SidecarId,
}

/// A decrypted controller `role=request` binding Event.
#[derive(Clone, Debug)]
pub struct SidecarExchangeRequestFact {
    pub event_id: EventId,
    pub hlc: Hlc,
    pub actor_id: DidCoreId,
    /// Accepted controller actor-chain sequence of the carrying Event.
    pub actor_seq: u64,
    /// Canonical Event digest used only for same-sequence sibling
    /// resolution (bytewise max wins).
    pub event_digest: String,
    pub exchange_id: AgentSidecarExchangeId,
    pub context: AgentSidecarExchangeRequestContext,
}

/// A decrypted Agent `role=user_facing_response|internal` binding Event.
#[derive(Clone, Debug)]
pub struct SidecarExchangeAgentFact {
    pub event_id: EventId,
    pub hlc: Hlc,
    pub actor_id: DidCoreId,
    pub binding: AgentSidecarEventExchangeBinding,
    /// Top-level `refs[role=after]` targets of the carrying Event.
    pub refs_after: Vec<EventId>,
}

/// A decrypted `ak.agent.sidecar.exchange.control` Event.
#[derive(Clone, Debug)]
pub struct SidecarExchangeControlFact {
    pub event_id: EventId,
    pub hlc: Hlc,
    pub actor_id: DidCoreId,
    pub actor_seq: u64,
    pub event_digest: String,
    /// Top-level `refs[role=after]` targets of the carrying Event. §7.2.3
    /// requires an `after` ref for every `basis_event_ids` entry; controls
    /// whose outer refs do not cover their plaintext basis are invalid.
    pub refs_after: Vec<EventId>,
    pub control: AgentSidecarExchangeControl,
}

/// Whether a persisted local cache may be used against the currently
/// verified local Event history (`zh/models/sidecar.md` §7.2.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SidecarExchangeCacheDecision {
    /// The cache commits to exactly the local contributing Event set.
    Fresh,
    /// Every cache head is causally dominated by the local verified history;
    /// refold from the local set (the deterministic fold makes this cheap).
    Refold,
    /// The cache references Events the local history has not verified: the
    /// frontiers are incomparable. Backfill the union history and refold.
    /// HLC/LWW winner selection is forbidden.
    BackfillRequired,
}

/// Compare a persisted cache frontier against the locally verified
/// contributing Event-id set. `local_event_ids` MUST be the complete set of
/// fold-participating accepted Event ids currently verified on this device.
pub fn evaluate_sidecar_exchange_cache(
    cache: &AgentSidecarExchangeFoldedFrontier,
    local_event_ids: &BTreeSet<EventId>,
) -> Result<SidecarExchangeCacheDecision> {
    cache.validate()?;
    let local_digest = agent_sidecar_exchange_event_set_digest(
        &local_event_ids.iter().cloned().collect::<Vec<_>>(),
    )?;
    if local_digest == cache.event_set_digest {
        return Ok(SidecarExchangeCacheDecision::Fresh);
    }
    if cache
        .event_ids
        .iter()
        .all(|head| local_event_ids.contains(head))
    {
        Ok(SidecarExchangeCacheDecision::Refold)
    } else {
        Ok(SidecarExchangeCacheDecision::BackfillRequired)
    }
}

struct CanonicalRequest<'a> {
    fact: &'a SidecarExchangeRequestFact,
}

/// §7.2.1 canonical request selection: controller-authored facts only, lowest
/// accepted `actor_seq` survives; same-sequence siblings resolve to the
/// bytewise-max `event_digest`. Higher-sequence duplicates of the same
/// `exchange_id` are retry duplicates and never fold.
fn select_canonical_request<'a>(
    scope: &SidecarExchangeFoldScope,
    exchange_id: &AgentSidecarExchangeId,
    requests: &'a [SidecarExchangeRequestFact],
) -> Result<Option<CanonicalRequest<'a>>> {
    let mut canonical: Option<&SidecarExchangeRequestFact> = None;
    for fact in requests {
        if fact.actor_id != scope.controller_id || fact.exchange_id != *exchange_id {
            continue;
        }
        if fact.context.validate().is_err() {
            continue;
        }
        canonical = Some(match canonical {
            None => fact,
            Some(current) => {
                if (fact.actor_seq, ReverseBytes(&fact.event_digest))
                    < (current.actor_seq, ReverseBytes(&current.event_digest))
                {
                    fact
                } else {
                    current
                }
            }
        });
    }
    Ok(canonical.map(|fact| CanonicalRequest { fact }))
}

/// Orders bytewise-descending so that `(actor_seq asc, digest desc)` can be
/// expressed with a single tuple comparison.
#[derive(PartialEq, Eq)]
struct ReverseBytes<'a>(&'a str);

impl PartialOrd for ReverseBytes<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ReverseBytes<'_> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        other.0.as_bytes().cmp(self.0.as_bytes())
    }
}

/// Fold one exchange from accepted private-Strand facts into the local
/// projection cache DTO. Returns `Ok(None)` when no canonical controller
/// request exists yet. Fails with a protocol error when a terminal control
/// references Events missing from the supplied facts — the caller MUST then
/// backfill the union history instead of guessing.
pub fn fold_sidecar_exchange(
    scope: &SidecarExchangeFoldScope,
    exchange_id: &AgentSidecarExchangeId,
    requests: &[SidecarExchangeRequestFact],
    agent_facts: &[SidecarExchangeAgentFact],
    controls: &[SidecarExchangeControlFact],
) -> Result<Option<AgentSidecarExchangeProjection>> {
    let Some(canonical) = select_canonical_request(scope, exchange_id, requests)? else {
        return Ok(None);
    };
    let request = canonical.fact;
    let context = &request.context;
    let addressed: BTreeSet<&DidCoreId> = context.addressed_agent_ids.iter().collect();

    // §7.2.2 Agent binding validation. Facts arrive scope/strand-verified;
    // the fold enforces binding integrity, exchange identity, actor
    // eligibility, causal request refs, and Event-id idempotence.
    let mut responses: BTreeMap<String, &SidecarExchangeAgentFact> = BTreeMap::new();
    let mut participating: BTreeSet<DidCoreId> = BTreeSet::new();
    let mut accepted_agent_facts: BTreeMap<String, &SidecarExchangeAgentFact> = BTreeMap::new();
    for fact in agent_facts {
        // Checks 1–4: exchange-scoped fact, valid closed binding, verbatim
        // exchange id, canonical request reference, non-controller actor.
        if fact.binding.validate().is_err()
            || fact.binding.exchange_id != *exchange_id
            || fact.binding.request_event_id.as_ref() != Some(&request.event_id)
            || fact.actor_id == scope.controller_id
        {
            continue;
        }
        let role = fact.binding.role;
        if !matches!(
            role,
            AgentSidecarExchangeBindingRole::UserFacingResponse
                | AgentSidecarExchangeBindingRole::Internal
        ) {
            continue;
        }
        if accepted_agent_facts
            .insert(fact.event_id.to_string(), fact)
            .is_some()
        {
            continue;
        }
        // Checks 1–4 passed: the actor joins the bookkeeping union whether or
        // not it is addressed or causally well-formed (§7.2.2: participation
        // accrues outside checks 5/6/7). Echo eligibility additionally
        // requires an addressed actor (check 5), role=user_facing_response
        // (check 6), and a top-level after-ref to the request (check 7).
        participating.insert(fact.actor_id.clone());
        if role == AgentSidecarExchangeBindingRole::UserFacingResponse
            && addressed.contains(&fact.actor_id)
            && fact.refs_after.contains(&request.event_id)
        {
            responses.insert(fact.event_id.to_string(), fact);
        }
    }

    // §7.2.3 control fold: controller-authored accepted chain order only.
    let mut control_groups: BTreeMap<u64, Vec<&SidecarExchangeControlFact>> = BTreeMap::new();
    for fact in controls {
        if fact.actor_id != scope.controller_id
            || fact.control.validate().is_err()
            || fact.control.exchange_id != *exchange_id
            || fact.control.request_event_id != request.event_id
        {
            continue;
        }
        control_groups.entry(fact.actor_seq).or_default().push(fact);
    }
    let mut coordinator = context.effective_coordinator()?.clone();
    let mut coordinator_assignment_event_id = request.event_id.clone();
    let mut terminal: Option<&SidecarExchangeControlFact> = None;
    let mut terminal_closure: BTreeSet<String> = BTreeSet::new();
    let mut accepted_controls: Vec<&SidecarExchangeControlFact> = Vec::new();
    for (_, mut group) in control_groups {
        // Same-sequence siblings resolve to the bytewise-max event digest;
        // the losers stay auditable but never fold.
        group.sort_by(|left, right| {
            left.event_digest
                .as_bytes()
                .cmp(right.event_digest.as_bytes())
        });
        let fact = group.pop().expect("group is non-empty");
        if terminal.is_some() {
            continue;
        }
        // §7.2.3 basis validation (every control): the outer Event refs MUST
        // carry role=after for every basis entry, every basis head must be a
        // locally verified exchange fact, and the canonical request must be
        // covered by the basis causal closure. Unknown basis heads mean the
        // local history is incomplete: backfill, never guess. A basis that
        // points at a locally known-but-rejected Event also surfaces here as
        // unknown; callers keep the previous cache and treat the exchange as
        // pending backfill rather than inventing a terminal state.
        if fact
            .control
            .basis_event_ids
            .iter()
            .any(|basis| !fact.refs_after.contains(basis))
        {
            // Invalid producer output (missing after-ref): skip the control.
            continue;
        }
        let known: BTreeSet<&str> = accepted_agent_facts
            .keys()
            .map(String::as_str)
            .chain(std::iter::once(request.event_id.as_str()))
            .chain(accepted_controls.iter().map(|fact| fact.event_id.as_str()))
            .collect();
        if fact
            .control
            .basis_event_ids
            .iter()
            .any(|basis| !known.contains(basis.as_str()))
        {
            return Err(Error::Protocol(
                "Sidecar control basis is not covered by local verified history; backfill required"
                    .to_owned(),
            ));
        }
        let closure = basis_causal_closure(fact, &accepted_agent_facts, &accepted_controls);
        if !closure.contains(request.event_id.as_str()) {
            // §7.2.3: the canonical request MUST be causally covered.
            continue;
        }
        match fact.control.action {
            AgentSidecarExchangeControlAction::ReassignCoordinator => {
                let expected = fact
                    .control
                    .expected_coordinator_agent_id
                    .as_ref()
                    .expect("validated");
                let next = fact
                    .control
                    .coordinator_agent_id
                    .as_ref()
                    .expect("validated");
                // `next` must be addressed; authoring-time eligibility is a
                // controller-authoring obligation the deterministic fold has
                // no lifecycle input to re-check.
                if *expected == coordinator && addressed.contains(next) {
                    coordinator = next.clone();
                    coordinator_assignment_event_id = fact.event_id.clone();
                    accepted_controls.push(fact);
                }
            }
            _ => {
                // §7.2.3: a terminal's response_event_ids must be EXACTLY the
                // basis-covered validated user-facing response set. Any
                // mismatch in either direction invalidates the control.
                let listed: BTreeSet<&str> = fact
                    .control
                    .response_event_ids
                    .as_ref()
                    .expect("terminal controls carry response_event_ids")
                    .iter()
                    .map(EventId::as_str)
                    .collect();
                let covered_validated: BTreeSet<&str> = responses
                    .keys()
                    .map(String::as_str)
                    .filter(|response_id| closure.contains(*response_id))
                    .collect();
                if listed != covered_validated {
                    continue;
                }
                terminal = Some(fact);
                terminal_closure = closure;
                accepted_controls.push(fact);
            }
        }
    }

    // Assemble the fold-participating Event set and the response list.
    let mut fold_ids: BTreeSet<EventId> = BTreeSet::new();
    fold_ids.insert(request.event_id.clone());
    let mut response_facts: Vec<&SidecarExchangeAgentFact>;
    match terminal {
        Some(terminal_fact) => {
            let terminal_responses = terminal_fact
                .control
                .response_event_ids
                .as_ref()
                .expect("terminal controls carry response_event_ids");
            response_facts = Vec::with_capacity(terminal_responses.len());
            for response_id in terminal_responses {
                let fact = responses
                    .get(response_id.as_str())
                    .expect("exactness validated above");
                response_facts.push(fact);
            }
            // Only Agent facts covered by the terminal basis closure fold;
            // concurrent or later Events stay private audit history.
            for (event_id, fact) in &accepted_agent_facts {
                if terminal_closure.contains(event_id.as_str()) {
                    fold_ids.insert(fact.event_id.clone());
                }
            }
            for fact in &accepted_controls {
                fold_ids.insert(fact.event_id.clone());
            }
        }
        None => {
            response_facts = responses.values().copied().collect();
            for fact in accepted_agent_facts.values() {
                fold_ids.insert(fact.event_id.clone());
            }
            for fact in &accepted_controls {
                fold_ids.insert(fact.event_id.clone());
            }
        }
    }
    response_facts.sort_by(|left, right| {
        (left.hlc.to_string(), left.event_id.to_string())
            .cmp(&(right.hlc.to_string(), right.event_id.to_string()))
    });
    let user_facing_response_event_ids: Vec<EventId> = response_facts
        .iter()
        .map(|fact| fact.event_id.clone())
        .collect();

    let (status, failure_reason_code, terminal_event_id) = match terminal {
        Some(terminal_fact) => {
            let outcome = terminal_fact
                .control
                .terminal_result()?
                .expect("terminal action");
            (
                outcome.status,
                outcome
                    .failure_reason_code
                    .map(NonEmptyString::new)
                    .transpose()
                    .map_err(|_| {
                        Error::Protocol(
                            "Sidecar terminal failure code must be non-empty".to_owned(),
                        )
                    })?,
                Some(terminal_fact.event_id.clone()),
            )
        }
        None if user_facing_response_event_ids.is_empty() => {
            (AgentSidecarExchangeStatus::Delivered, None, None)
        }
        None => (AgentSidecarExchangeStatus::Responding, None, None),
    };

    let folded_frontier = build_frontier(
        &fold_ids,
        request,
        &accepted_agent_facts,
        &accepted_controls,
    )?;
    let projection = AgentSidecarExchangeProjection {
        schema: AgentSidecarExchangeProjectionSchema::V1,
        controller_id: scope.controller_id.clone(),
        sidecar_id: scope.sidecar_id.clone(),
        exchange_id: exchange_id.clone(),
        origin: AgentSidecarExchangeOrigin::SourceTrackRouted,
        source_track_ref: context.source_track_ref.clone(),
        source_event_id: context.source_event_id.clone(),
        source_hlc: context.source_hlc.clone(),
        client_order_key: context.client_order_key.clone(),
        addressed_agent_ids: context.addressed_agent_ids.clone(),
        completion_policy: AgentSidecarExchangeCompletionPolicy::Coordinator,
        coordinator_agent_id: coordinator,
        coordinator_assignment_event_id,
        participating_agent_ids: participating.into_iter().collect(),
        private_request_event_id: request.event_id.clone(),
        user_facing_response_event_ids,
        status,
        failure_reason_code,
        terminal_event_id,
        folded_frontier,
    };
    projection.validate()?;
    Ok(Some(projection))
}

/// Apply the current authorization gate before using historical Sidecar facts
/// for a new Agent action. The deterministic history fold itself deliberately
/// remains usable for audit/display after later revocation; it must never be
/// mistaken for current admission authority.
pub fn fold_sidecar_exchange_for_current_admission(
    admission: &crate::runtime_journey::ParticipationAdmissionFacts,
    required_action: crate::runtime_journey::ParticipationAction,
    scope: &SidecarExchangeFoldScope,
    exchange_id: &AgentSidecarExchangeId,
    requests: &[SidecarExchangeRequestFact],
    agent_facts: &[SidecarExchangeAgentFact],
    controls: &[SidecarExchangeControlFact],
) -> Result<Option<AgentSidecarExchangeProjection>> {
    if !admission.allows(required_action)? {
        return Err(Error::Protocol(
            "current participation admission denies the Sidecar action".to_owned(),
        ));
    }
    fold_sidecar_exchange(scope, exchange_id, requests, agent_facts, controls)
}

/// Walk the causal edges of known exchange facts starting from a control's
/// basis heads: Agent facts contribute their `refs[role=after]` targets and
/// previously accepted controls contribute their own `basis_event_ids`.
/// Every reached Event id is causally covered by that basis within the
/// exchange fact set.
fn basis_causal_closure(
    control: &SidecarExchangeControlFact,
    agent_facts: &BTreeMap<String, &SidecarExchangeAgentFact>,
    accepted_controls: &[&SidecarExchangeControlFact],
) -> BTreeSet<String> {
    let control_edges: BTreeMap<&str, &SidecarExchangeControlFact> = accepted_controls
        .iter()
        .map(|fact| (fact.event_id.as_str(), *fact))
        .collect();
    let mut covered: BTreeSet<String> = BTreeSet::new();
    let mut queue: Vec<String> = control
        .control
        .basis_event_ids
        .iter()
        .map(ToString::to_string)
        .collect();
    while let Some(event_id) = queue.pop() {
        if !covered.insert(event_id.clone()) {
            continue;
        }
        if let Some(fact) = agent_facts.get(&event_id) {
            for parent in &fact.refs_after {
                queue.push(parent.to_string());
            }
        }
        if let Some(fact) = control_edges.get(event_id.as_str()) {
            for parent in &fact.control.basis_event_ids {
                queue.push(parent.to_string());
            }
        }
    }
    covered
}

/// Maximal causal heads of the fold-participating set: every participating
/// Event id that no other participating fact references via `refs[role=after]`
/// (controls contribute their `basis_event_ids` as edges). Sorted by Event id
/// UTF-8 byte order per the projection schema.
fn build_frontier(
    fold_ids: &BTreeSet<EventId>,
    request: &SidecarExchangeRequestFact,
    agent_facts: &BTreeMap<String, &SidecarExchangeAgentFact>,
    controls: &[&SidecarExchangeControlFact],
) -> Result<AgentSidecarExchangeFoldedFrontier> {
    let mut referenced: BTreeSet<String> = BTreeSet::new();
    for fact in agent_facts.values() {
        if fold_ids.contains(&fact.event_id) {
            for parent in &fact.refs_after {
                referenced.insert(parent.to_string());
            }
        }
    }
    for fact in controls {
        if fold_ids.contains(&fact.event_id) {
            for parent in &fact.control.basis_event_ids {
                referenced.insert(parent.to_string());
            }
        }
    }
    let event_ids: Vec<EventId> = fold_ids
        .iter()
        .filter(|event_id| !referenced.contains(event_id.as_str()))
        .cloned()
        .collect();
    let mut max_hlc = request.hlc.clone();
    for fact in agent_facts.values() {
        if fold_ids.contains(&fact.event_id) && fact.hlc.to_string() > max_hlc.to_string() {
            max_hlc = fact.hlc.clone();
        }
    }
    for fact in controls {
        if fold_ids.contains(&fact.event_id) && fact.hlc.to_string() > max_hlc.to_string() {
            max_hlc = fact.hlc.clone();
        }
    }
    let all_ids: Vec<EventId> = fold_ids.iter().cloned().collect();
    Ok(AgentSidecarExchangeFoldedFrontier {
        event_ids,
        event_set_digest: agent_sidecar_exchange_event_set_digest(&all_ids)?,
        max_hlc,
    })
}

#[cfg(test)]
mod tests {
    use crate::protocol::models::AgentSidecarExchangeControlSchema;
    use crate::protocol::models::AgentSidecarSourceTrackRef;
    use crate::protocol::{RealmId, StrandId};

    use super::*;

    fn event_id(suffix: u32) -> EventId {
        let mut digest = [0_u8; 32];
        digest[28..].copy_from_slice(&suffix.to_be_bytes());
        EventId::from_digest(arkret_canonical::DigestSuite::Sha256, digest)
    }

    fn hlc(counter: u32) -> Hlc {
        Hlc::new(format!("01970e589d21-{counter:04x}-a13f9c2e")).unwrap()
    }

    fn controller() -> DidCoreId {
        DidCoreId::new("ak:did_core:webvh:z6mkcontroller:example.com:users:alice").unwrap()
    }

    fn agent_s() -> DidCoreId {
        DidCoreId::new("ak:did_core:webvh:z6mkassistant:assistant.agents.example").unwrap()
    }

    fn agent_t() -> DidCoreId {
        DidCoreId::new("ak:did_core:webvh:z6mkreviewer:reviewer.agents.example").unwrap()
    }

    fn scope() -> SidecarExchangeFoldScope {
        SidecarExchangeFoldScope {
            controller_id: controller(),
            sidecar_id: SidecarId::from_event_id(&event_id(0x32)),
        }
    }

    fn exchange_id() -> AgentSidecarExchangeId {
        AgentSidecarExchangeId::new("Abcdefghijklmnopqrstuv").unwrap()
    }

    fn context(
        addressed: Vec<DidCoreId>,
        coordinator: Option<DidCoreId>,
    ) -> AgentSidecarExchangeRequestContext {
        AgentSidecarExchangeRequestContext {
            source_track_ref: AgentSidecarSourceTrackRef {
                realm_id: RealmId::new("ak:realm:AWk_ywNSTc6WhrGkRSaK84HThnFXKBAy3vQ_RLJZ4kCY")
                    .unwrap(),
                strand_id: StrandId::from_event_id(&event_id(0x31)),
                track_name: "discussion".to_owned(),
            },
            source_hlc: hlc(1),
            client_order_key: NonEmptyString::new("device-1-1").unwrap(),
            addressed_agent_ids: addressed,
            completion_policy: AgentSidecarExchangeCompletionPolicy::Coordinator,
            coordinator_agent_id: coordinator,
            source_event_id: None,
        }
    }

    fn request_fact(suffix: u32, actor_seq: u64, digest: &str) -> SidecarExchangeRequestFact {
        SidecarExchangeRequestFact {
            event_id: event_id(suffix),
            hlc: hlc(1),
            actor_id: controller(),
            actor_seq,
            event_digest: digest.to_owned(),
            exchange_id: exchange_id(),
            context: context(vec![agent_s(), agent_t()], Some(agent_s())),
        }
    }

    fn canonical_event_identity(
        actor_seq: u64,
        counter: u32,
        kind: &str,
        payload: serde_json::Value,
        refs_after: &[EventId],
    ) -> (EventId, String) {
        let created_at = chrono::DateTime::parse_from_rfc3339("2026-07-29T00:00:00.000Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let mut event = arkret_wire::test_support::raw_event_at(
            kind,
            arkret_wire::ScopeRef::Realm {
                realm_id: RealmId::new(
                    "ak:realm:AWk_ywNSTc6WhrGkRSaK84HThnFXKBAy3vQ_RLJZ4kCY".to_owned(),
                )
                .unwrap(),
            },
            controller(),
            actor_seq,
            hlc(counter),
            payload,
            created_at,
        )
        .unwrap();
        event.refs.extend(
            refs_after
                .iter()
                .map(|event_id| arkret_wire::EventRef::new(event_id.to_string(), "after")),
        );
        event.refresh_content_bound_identity().unwrap();
        let digest = event.event_digest().unwrap();
        (event.event_id, digest)
    }

    fn canonical_request_fact(
        suffix: u32,
        actor_seq: u64,
        body: &str,
    ) -> SidecarExchangeRequestFact {
        let mut fact = request_fact(suffix, actor_seq, "");
        let (event_id, event_digest) = canonical_event_identity(
            actor_seq,
            1,
            arkret_wire::EventKind::MessageCreate.as_str(),
            serde_json::json!({
                "strand_id": StrandId::from_event_id(&event_id(0x33)),
                "track_name": "discussion",
                "content": {"kind": "ak.content.text", "body": body},
                "exchange_binding": AgentSidecarEventExchangeBinding::request(
                    exchange_id(),
                    fact.context.clone(),
                )
                .unwrap()
            }),
            &[],
        );
        fact.event_id = event_id;
        fact.event_digest = event_digest;
        fact
    }

    fn canonical_control_fact(
        suffix: u32,
        actor_seq: u64,
        control: AgentSidecarExchangeControl,
    ) -> SidecarExchangeControlFact {
        let mut fact = control_fact(suffix, actor_seq, "", control.clone());
        let (event_id, event_digest) = canonical_event_identity(
            actor_seq,
            0x40 + suffix,
            arkret_wire::EventKind::AgentSidecarExchangeControl.as_str(),
            serde_json::json!({
                "strand_id": StrandId::from_event_id(&event_id(0x33)),
                "control": control
            }),
            &fact.refs_after,
        );
        fact.event_id = event_id;
        fact.event_digest = event_digest;
        fact
    }

    fn agent_fact(
        suffix: u32,
        counter: u32,
        actor: DidCoreId,
        role: AgentSidecarExchangeBindingRole,
        request_suffix: u32,
    ) -> SidecarExchangeAgentFact {
        agent_fact_for_request(suffix, counter, actor, role, event_id(request_suffix))
    }

    fn agent_fact_for_request(
        suffix: u32,
        counter: u32,
        actor: DidCoreId,
        role: AgentSidecarExchangeBindingRole,
        request_event_id: EventId,
    ) -> SidecarExchangeAgentFact {
        let binding = match role {
            AgentSidecarExchangeBindingRole::UserFacingResponse => {
                AgentSidecarEventExchangeBinding::user_facing_response(
                    exchange_id(),
                    request_event_id.clone(),
                )
                .unwrap()
            }
            AgentSidecarExchangeBindingRole::Internal => {
                AgentSidecarEventExchangeBinding::internal(exchange_id(), request_event_id.clone())
                    .unwrap()
            }
            AgentSidecarExchangeBindingRole::Request => unreachable!(),
        };
        SidecarExchangeAgentFact {
            event_id: event_id(suffix),
            hlc: hlc(counter),
            actor_id: actor,
            binding,
            refs_after: vec![request_event_id],
        }
    }

    fn control_fact(
        suffix: u32,
        actor_seq: u64,
        digest: &str,
        control: AgentSidecarExchangeControl,
    ) -> SidecarExchangeControlFact {
        SidecarExchangeControlFact {
            event_id: event_id(suffix),
            hlc: hlc(0x20 + suffix),
            actor_id: controller(),
            actor_seq,
            event_digest: digest.to_owned(),
            refs_after: control.basis_event_ids.clone(),
            control,
        }
    }

    fn close_control(basis: Vec<EventId>, responses: Vec<EventId>) -> AgentSidecarExchangeControl {
        close_control_for_request(event_id(0x34), basis, responses)
    }

    fn close_control_for_request(
        request_event_id: EventId,
        basis: Vec<EventId>,
        responses: Vec<EventId>,
    ) -> AgentSidecarExchangeControl {
        AgentSidecarExchangeControl {
            schema: AgentSidecarExchangeControlSchema::V1,
            exchange_id: exchange_id(),
            request_event_id,
            basis_event_ids: basis,
            action: AgentSidecarExchangeControlAction::Close,
            response_event_ids: Some(responses),
            failure_reason_code: None,
            expected_coordinator_agent_id: None,
            coordinator_agent_id: None,
        }
    }

    #[test]
    fn request_only_folds_to_delivered_with_request_frontier() {
        let projection = fold_sidecar_exchange(
            &scope(),
            &exchange_id(),
            &[request_fact(0x34, 5, "aa")],
            &[],
            &[],
        )
        .unwrap()
        .unwrap();
        assert_eq!(projection.status, AgentSidecarExchangeStatus::Delivered);
        assert_eq!(projection.coordinator_agent_id, agent_s());
        assert_eq!(projection.coordinator_assignment_event_id, event_id(0x34));
        assert_eq!(projection.folded_frontier.event_ids, vec![event_id(0x34)]);
        assert!(projection.participating_agent_ids.is_empty());
    }

    #[test]
    fn canonical_request_prefers_lowest_actor_seq_then_max_digest() {
        let requests = vec![
            canonical_request_fact(0x40, 7, "higher sequence retry"),
            canonical_request_fact(0x41, 5, "same sequence left"),
            canonical_request_fact(0x42, 5, "same sequence right"),
        ];
        let expected = requests[1..]
            .iter()
            .max_by(|left, right| {
                left.event_digest
                    .as_bytes()
                    .cmp(right.event_digest.as_bytes())
            })
            .unwrap()
            .event_id
            .clone();
        let projection = fold_sidecar_exchange(&scope(), &exchange_id(), &requests, &[], &[])
            .unwrap()
            .unwrap();
        assert_eq!(
            projection.private_request_event_id, expected,
            "same-sequence sibling resolves to bytewise-max digest; higher seq is a retry duplicate"
        );
        let reversed = fold_sidecar_exchange(
            &scope(),
            &exchange_id(),
            &requests.iter().cloned().rev().collect::<Vec<_>>(),
            &[],
            &[],
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            serde_json::to_vec(&projection).unwrap(),
            serde_json::to_vec(&reversed).unwrap(),
            "request sibling resolution must be byte-identical across arrival order"
        );
    }

    #[test]
    fn internal_only_stays_delivered_and_tracks_participation() {
        let facts = vec![agent_fact(
            0x35,
            2,
            agent_t(),
            AgentSidecarExchangeBindingRole::Internal,
            0x34,
        )];
        let projection = fold_sidecar_exchange(
            &scope(),
            &exchange_id(),
            &[request_fact(0x34, 1, "aa")],
            &facts,
            &[],
        )
        .unwrap()
        .unwrap();
        assert_eq!(projection.status, AgentSidecarExchangeStatus::Delivered);
        assert_eq!(projection.participating_agent_ids, vec![agent_t()]);
        assert!(projection.user_facing_response_event_ids.is_empty());
    }

    #[test]
    fn responses_require_addressed_actor_causal_ref_and_dedupe() {
        let request = request_fact(0x34, 1, "aa");
        let valid = agent_fact(
            0x35,
            2,
            agent_s(),
            AgentSidecarExchangeBindingRole::UserFacingResponse,
            0x34,
        );
        let mut unaddressed = agent_fact(
            0x36,
            3,
            DidCoreId::new("ak:did_core:webvh:z6mkstranger:stranger.agents.example").unwrap(),
            AgentSidecarExchangeBindingRole::UserFacingResponse,
            0x34,
        );
        unaddressed.refs_after = vec![event_id(0x34)];
        let mut missing_ref = agent_fact(
            0x37,
            4,
            agent_t(),
            AgentSidecarExchangeBindingRole::UserFacingResponse,
            0x34,
        );
        missing_ref.refs_after = vec![];
        let controller_response = SidecarExchangeAgentFact {
            actor_id: controller(),
            ..agent_fact(
                0x38,
                5,
                agent_s(),
                AgentSidecarExchangeBindingRole::UserFacingResponse,
                0x34,
            )
        };
        let duplicate = valid.clone();
        let projection = fold_sidecar_exchange(
            &scope(),
            &exchange_id(),
            &[request],
            &[
                valid,
                duplicate,
                unaddressed,
                missing_ref,
                controller_response,
            ],
            &[],
        )
        .unwrap()
        .unwrap();
        assert_eq!(projection.status, AgentSidecarExchangeStatus::Responding);
        assert_eq!(
            projection.user_facing_response_event_ids,
            vec![event_id(0x35)],
            "unaddressed/unreferenced/controller/duplicate responses never echo"
        );
        assert!(
            projection.participating_agent_ids.contains(
                &DidCoreId::new("ak:did_core:webvh:z6mkstranger:stranger.agents.example").unwrap()
            ),
            "non-addressed actors passing checks 1-4 still join the bookkeeping union"
        );
    }

    #[test]
    fn terminal_close_with_responses_completes_and_scopes_fold_to_basis() {
        let request = request_fact(0x34, 1, "aa");
        let response = agent_fact(
            0x35,
            2,
            agent_s(),
            AgentSidecarExchangeBindingRole::UserFacingResponse,
            0x34,
        );
        // Concurrent internal Event not covered by the terminal basis.
        let late_internal = agent_fact(
            0x39,
            9,
            agent_t(),
            AgentSidecarExchangeBindingRole::Internal,
            0x34,
        );
        let control = control_fact(
            0x36,
            2,
            "cc",
            close_control(vec![event_id(0x35)], vec![event_id(0x35)]),
        );
        let projection = fold_sidecar_exchange(
            &scope(),
            &exchange_id(),
            &[request],
            &[response, late_internal],
            &[control],
        )
        .unwrap()
        .unwrap();
        assert_eq!(projection.status, AgentSidecarExchangeStatus::Complete);
        assert_eq!(projection.terminal_event_id, Some(event_id(0x36)));
        assert_eq!(
            projection.user_facing_response_event_ids,
            vec![event_id(0x35)]
        );
        assert!(
            !projection
                .folded_frontier
                .event_ids
                .contains(&event_id(0x39)),
            "Events outside the terminal basis closure stay private audit history"
        );
        assert_eq!(
            projection.folded_frontier.event_ids,
            vec![event_id(0x36)],
            "the control covers request and response, leaving one causal head"
        );
    }

    #[test]
    fn empty_terminal_actions_map_to_spec_failure_reason_codes() {
        let request = request_fact(0x34, 1, "aa");
        let cases = [
            (
                AgentSidecarExchangeControlAction::Close,
                None,
                "controller_closed_empty",
            ),
            (
                AgentSidecarExchangeControlAction::Cancel,
                None,
                "controller_cancelled",
            ),
            (
                AgentSidecarExchangeControlAction::Fail,
                Some("agent_deactivated"),
                "agent_deactivated",
            ),
        ];
        for (action, fail_code, expected) in cases {
            let mut control = close_control(vec![event_id(0x34)], vec![]);
            control.action = action;
            control.failure_reason_code = fail_code.map(|code| NonEmptyString::new(code).unwrap());
            let projection = fold_sidecar_exchange(
                &scope(),
                &exchange_id(),
                std::slice::from_ref(&request),
                &[],
                &[control_fact(0x36, 2, "cc", control)],
            )
            .unwrap()
            .unwrap();
            assert_eq!(projection.status, AgentSidecarExchangeStatus::Failed);
            assert_eq!(
                projection
                    .failure_reason_code
                    .as_ref()
                    .map(|code| code.as_str()),
                Some(expected)
            );
            assert!(projection.user_facing_response_event_ids.is_empty());
        }
    }

    #[test]
    fn first_valid_terminal_absorbs_later_controls_and_siblings_resolve_by_digest() {
        let request = canonical_request_fact(0x34, 1, "request");
        let request_event_id = request.event_id.clone();
        let response = agent_fact_for_request(
            0x35,
            2,
            agent_s(),
            AgentSidecarExchangeBindingRole::UserFacingResponse,
            request_event_id.clone(),
        );
        let sibling_left = canonical_control_fact(
            0x36,
            2,
            close_control_for_request(
                request_event_id.clone(),
                vec![event_id(0x35)],
                vec![event_id(0x35)],
            ),
        );
        let sibling_right = canonical_control_fact(
            0x37,
            2,
            close_control_for_request(
                request_event_id.clone(),
                vec![event_id(0x35)],
                vec![event_id(0x35)],
            ),
        );
        let expected_terminal = [&sibling_left, &sibling_right]
            .into_iter()
            .max_by(|left, right| {
                left.event_digest
                    .as_bytes()
                    .cmp(right.event_digest.as_bytes())
            })
            .unwrap()
            .event_id
            .clone();
        let mut reassign =
            close_control_for_request(request_event_id, vec![event_id(0x35)], vec![]);
        reassign.action = AgentSidecarExchangeControlAction::ReassignCoordinator;
        reassign.response_event_ids = None;
        reassign.expected_coordinator_agent_id = Some(agent_s());
        reassign.coordinator_agent_id = Some(agent_t());
        let post_terminal = canonical_control_fact(0x38, 3, reassign);
        let projection = fold_sidecar_exchange(
            &scope(),
            &exchange_id(),
            &[request],
            &[response],
            &[post_terminal, sibling_right, sibling_left],
        )
        .unwrap()
        .unwrap();
        assert_eq!(projection.status, AgentSidecarExchangeStatus::Complete);
        assert_eq!(projection.terminal_event_id, Some(expected_terminal));
        assert_eq!(
            projection.coordinator_agent_id,
            agent_s(),
            "post-terminal reassign is absorbed"
        );
    }

    #[test]
    fn matching_reassign_updates_coordinator_and_assignment_event() {
        let request = request_fact(0x34, 1, "aa");
        let mut reassign = close_control(vec![event_id(0x34)], vec![]);
        reassign.action = AgentSidecarExchangeControlAction::ReassignCoordinator;
        reassign.response_event_ids = None;
        reassign.expected_coordinator_agent_id = Some(agent_s());
        reassign.coordinator_agent_id = Some(agent_t());
        let mut stale = close_control(vec![event_id(0x34)], vec![]);
        stale.action = AgentSidecarExchangeControlAction::ReassignCoordinator;
        stale.response_event_ids = None;
        stale.expected_coordinator_agent_id = Some(agent_s());
        stale.coordinator_agent_id = Some(agent_t());
        let projection = fold_sidecar_exchange(
            &scope(),
            &exchange_id(),
            &[request],
            &[],
            &[
                control_fact(0x36, 2, "cc", reassign),
                // Second reassign with a stale expected coordinator is ignored.
                control_fact(0x37, 3, "dd", stale),
            ],
        )
        .unwrap()
        .unwrap();
        assert_eq!(projection.coordinator_agent_id, agent_t());
        assert_eq!(
            projection.coordinator_assignment_event_id,
            event_id(0x36),
            "assignment id becomes the accepted reassign control Event id"
        );
    }

    #[test]
    fn participation_accrues_without_causal_ref_but_echo_does_not() {
        let request = request_fact(0x34, 1, "aa");
        let mut missing_ref = agent_fact(
            0x35,
            2,
            agent_s(),
            AgentSidecarExchangeBindingRole::UserFacingResponse,
            0x34,
        );
        missing_ref.refs_after = Vec::new();
        let projection =
            fold_sidecar_exchange(&scope(), &exchange_id(), &[request], &[missing_ref], &[])
                .unwrap()
                .unwrap();
        assert_eq!(
            projection.participating_agent_ids,
            vec![agent_s()],
            "checks 1-4 alone accrue participation (§7.2.2)"
        );
        assert!(
            projection.user_facing_response_event_ids.is_empty(),
            "echo additionally requires the causal request ref (check 7)"
        );
        assert_eq!(projection.status, AgentSidecarExchangeStatus::Delivered);
    }

    #[test]
    fn terminal_response_set_must_exactly_match_basis_covered_responses() {
        let request = request_fact(0x34, 1, "aa");
        let response = agent_fact(
            0x35,
            2,
            agent_s(),
            AgentSidecarExchangeBindingRole::UserFacingResponse,
            0x34,
        );
        // Empty close whose basis covers a validated response: invalid in
        // §7.2.3 ("exactly the basis-covered validated set"), so the
        // exchange stays responding instead of forking to failed.
        let invalid_empty_close =
            control_fact(0x36, 3, "cc", close_control(vec![event_id(0x35)], vec![]));
        let projection = fold_sidecar_exchange(
            &scope(),
            &exchange_id(),
            std::slice::from_ref(&request),
            std::slice::from_ref(&response),
            &[invalid_empty_close],
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            projection.status,
            AgentSidecarExchangeStatus::Responding,
            "an inexact terminal response set invalidates the control"
        );

        // Listing a response outside the basis closure is equally invalid.
        let uncovered_listing = control_fact(
            0x37,
            4,
            "dd",
            close_control(vec![event_id(0x34)], vec![event_id(0x35)]),
        );
        let projection = fold_sidecar_exchange(
            &scope(),
            &exchange_id(),
            std::slice::from_ref(&request),
            std::slice::from_ref(&response),
            &[uncovered_listing],
        )
        .unwrap()
        .unwrap();
        assert_eq!(projection.status, AgentSidecarExchangeStatus::Responding);
    }

    #[test]
    fn control_without_after_refs_for_basis_is_invalid() {
        let request = request_fact(0x34, 1, "aa");
        let mut missing_refs =
            control_fact(0x36, 2, "cc", close_control(vec![event_id(0x34)], vec![]));
        missing_refs.refs_after = Vec::new();
        let projection = fold_sidecar_exchange(
            &scope(),
            &exchange_id(),
            std::slice::from_ref(&request),
            &[],
            &[missing_refs],
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            projection.status,
            AgentSidecarExchangeStatus::Delivered,
            "outer refs must carry role=after for every basis entry (§7.2.3)"
        );
    }

    #[test]
    fn basis_closure_traverses_accepted_control_edges() {
        let request = request_fact(0x34, 1, "aa");
        let response = agent_fact(
            0x35,
            2,
            agent_s(),
            AgentSidecarExchangeBindingRole::UserFacingResponse,
            0x34,
        );
        // Intermediate reassign whose basis covers the response; the later
        // terminal's basis only names the reassign control, so coverage of
        // both the request and the response flows through the control edge.
        let mut reassign = close_control(vec![event_id(0x35)], vec![]);
        reassign.action = AgentSidecarExchangeControlAction::ReassignCoordinator;
        reassign.response_event_ids = None;
        reassign.expected_coordinator_agent_id = Some(agent_s());
        reassign.coordinator_agent_id = Some(agent_t());
        let reassign_fact = control_fact(0x36, 2, "cc", reassign);
        let close = control_fact(
            0x37,
            3,
            "dd",
            close_control(vec![event_id(0x36)], vec![event_id(0x35)]),
        );
        let projection = fold_sidecar_exchange(
            &scope(),
            &exchange_id(),
            std::slice::from_ref(&request),
            std::slice::from_ref(&response),
            &[reassign_fact, close],
        )
        .unwrap()
        .unwrap();
        assert_eq!(projection.status, AgentSidecarExchangeStatus::Complete);
        assert_eq!(
            projection.user_facing_response_event_ids,
            vec![event_id(0x35)]
        );
        assert_eq!(projection.coordinator_agent_id, agent_t());
    }

    #[test]
    fn terminal_with_uncovered_basis_demands_backfill() {
        let request = request_fact(0x34, 1, "aa");
        let control = control_fact(0x36, 2, "cc", close_control(vec![event_id(0x99)], vec![]));
        assert!(
            fold_sidecar_exchange(&scope(), &exchange_id(), &[request], &[], &[control]).is_err(),
            "unknown basis heads mean incomparable history: backfill, never guess"
        );
    }

    #[test]
    fn fold_is_deterministic_across_input_permutations() {
        let request = canonical_request_fact(0x34, 1, "canonical request");
        let request_event_id = request.event_id.clone();
        let response_a = agent_fact_for_request(
            0x35,
            3,
            agent_s(),
            AgentSidecarExchangeBindingRole::UserFacingResponse,
            request_event_id.clone(),
        );
        let response_b = agent_fact_for_request(
            0x36,
            2,
            agent_t(),
            AgentSidecarExchangeBindingRole::UserFacingResponse,
            request_event_id.clone(),
        );
        let internal = agent_fact_for_request(
            0x37,
            4,
            agent_t(),
            AgentSidecarExchangeBindingRole::Internal,
            request_event_id.clone(),
        );
        let forward = fold_sidecar_exchange(
            &scope(),
            &exchange_id(),
            std::slice::from_ref(&request),
            &[response_a.clone(), response_b.clone(), internal.clone()],
            &[],
        )
        .unwrap()
        .unwrap();
        let reversed = fold_sidecar_exchange(
            &scope(),
            &exchange_id(),
            &[request],
            &[internal, response_b, response_a],
            &[],
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            serde_json::to_vec(&forward).unwrap(),
            serde_json::to_vec(&reversed).unwrap(),
            "device replay must be bit-identical"
        );
        assert_eq!(
            forward.user_facing_response_event_ids,
            vec![event_id(0x36), event_id(0x35)],
            "responses order by (HLC, Event id) bytes, not arrival"
        );
        assert_eq!(forward.folded_frontier, reversed.folded_frontier);
        let union_ids = [
            request_event_id,
            event_id(0x35),
            event_id(0x36),
            event_id(0x37),
        ];
        assert_eq!(
            forward.folded_frontier.event_set_digest,
            agent_sidecar_exchange_event_set_digest(&union_ids).unwrap(),
            "frontier digest must cover the complete union history"
        );
    }

    #[test]
    fn cache_decisions_never_use_lww() {
        let request = request_fact(0x34, 1, "aa");
        let projection = fold_sidecar_exchange(&scope(), &exchange_id(), &[request], &[], &[])
            .unwrap()
            .unwrap();
        let local: BTreeSet<EventId> = [event_id(0x34)].into_iter().collect();
        assert_eq!(
            evaluate_sidecar_exchange_cache(&projection.folded_frontier, &local).unwrap(),
            SidecarExchangeCacheDecision::Fresh
        );
        let advanced: BTreeSet<EventId> = [event_id(0x34), event_id(0x35)].into_iter().collect();
        assert_eq!(
            evaluate_sidecar_exchange_cache(&projection.folded_frontier, &advanced).unwrap(),
            SidecarExchangeCacheDecision::Refold
        );
        let disjoint: BTreeSet<EventId> = [event_id(0x99)].into_iter().collect();
        assert_eq!(
            evaluate_sidecar_exchange_cache(&projection.folded_frontier, &disjoint).unwrap(),
            SidecarExchangeCacheDecision::BackfillRequired
        );
    }
}
