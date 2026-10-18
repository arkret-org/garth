//! Exact historical Agent signer resolution over accepted host candidates.
//! Current keys never substitute for a committed Event's historical method.

use std::collections::BTreeMap;

use arkret_models_identity::signer_key_operations::{
    HistoricalSignerKeyQuerySender, SignerKeyQueryOutcome, SignerKeyQuerySelector,
    SignerKeysQueryRequestBody,
};
use arkret_signatures::PublicKeyMaterial;
use arkret_wire::{AccountId, ActorId, Did, DidCoreId, DidUrl, RealmId};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub trait HistoricalAgentKeyPort: crate::MaybeSendSync {
    fn recipient(&self) -> Option<AccountId>;
    fn generation(&self) -> u64;
    fn candidates(&self) -> Vec<HistoricalAgentEventCandidate>;
    fn cached_keys(&self, actor: &ActorId, method: &DidUrl) -> Vec<CachedHistoricalAgentSignerKey>;
    fn store_if_current(
        &self,
        recipient: &AccountId,
        generation: u64,
        entry: CachedHistoricalAgentSignerKey,
    ) -> std::result::Result<bool, String>;
}

#[derive(Default)]
pub struct HistoricalKeyResolution {
    pub changed: bool,
    pub errors: Vec<String>,
}

pub async fn resolve_historical_agent_keys(
    http: &arkret_http_client::Client,
    port: &impl HistoricalAgentKeyPort,
    clock: &impl crate::HostClock,
) -> HistoricalKeyResolution {
    let mut report = HistoricalKeyResolution::default();
    let Some(recipient) = port.recipient() else {
        return report;
    };
    let generation = port.generation();
    let mut pending_by_realm = BTreeMap::<RealmId, Vec<EventAgentSelector>>::new();
    for candidate in port.candidates() {
        if pending_by_realm.values().map(Vec::len).sum::<usize>() >= 64 {
            break;
        }
        if !candidate.authority_chain_verified || candidate.recipient_account_id != recipient {
            continue;
        }
        let Some(selector) =
            selector_from_candidate(&candidate, &candidate.accepted_event, &recipient.station_id)
        else {
            continue;
        };
        let resolved = port
            .cached_keys(&selector.agent_actor_id, &selector.verification_method)
            .iter()
            .any(|entry| historical_key(entry, &selector, &recipient).is_some());
        if !resolved {
            pending_by_realm
                .entry(selector.realm_id.clone())
                .or_default()
                .push(selector);
        }
    }
    for (realm_id, pending) in pending_by_realm {
        let request = SignerKeysQueryRequestBody {
            request_id: arkret_wire::RequestId::new_v7_at(
                clock.now().timestamp_millis().max(0) as u64
            ),
            realm_id,
            recipient_account_id: recipient.clone(),
            queries: pending.iter().map(query_selector).collect(),
        };
        let outcome = match http.signer_keys_query(&request).await {
            Ok(outcome) => outcome,
            Err(error) => {
                report.errors.push(error.to_string());
                continue;
            }
        };
        for result in outcome.results {
            let SignerKeyQueryOutcome::HistoricalResolved {
                selector,
                key,
                accepted_at,
            } = result
            else {
                continue;
            };
            let Some(selected) = pending
                .iter()
                .find(|candidate| query_selector(candidate) == selector)
            else {
                continue;
            };
            let entry = CachedHistoricalAgentSignerKey {
                recipient_account_id: recipient.clone(),
                realm_id: selected.realm_id.clone(),
                target_ref: selected.target_ref.clone(),
                receiver_id: selected.receiver_id.clone(),
                accepted_at,
                actor: selected.agent_actor_id.clone(),
                verification_method: selected.verification_method.clone(),
                public_key_b64u: key.public_key_b64u,
                authorization_ref: key.authorization_ref,
                revision: key.revision,
                governance_generation: key.governance_generation,
                cached_at_unix_ms: clock.now().timestamp_millis().max(0) as u64,
            };
            let Some(public_key) = historical_key(&entry, selected, &recipient) else {
                continue;
            };
            if !verify_event_producer(selected, &public_key) {
                continue;
            }
            match port.store_if_current(&recipient, generation, entry) {
                Ok(changed) => report.changed |= changed,
                Err(error) => report.errors.push(error),
            }
        }
    }
    report
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalAgentEventCandidate {
    /// Older persisted candidates came from shape-only rows. Missing means
    /// untrusted and is never used as a signer-key query target.
    #[serde(default)]
    pub authority_chain_verified: bool,
    pub recipient_account_id: arkret_wire::AccountId,
    pub realm_id: arkret_wire::RealmId,
    pub target_ref: arkret_wire::CommittedEventRef,
    pub accepted_event: arkret_wire::Event,
    pub agent_actor_id: arkret_wire::ActorId,
    pub agent_id: arkret_wire::DidCoreId,
    pub verification_method: arkret_wire::DidUrl,
    pub receiver_id: arkret_wire::DidCoreId,
    pub indexed_at_unix_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CachedHistoricalAgentSignerKey {
    pub recipient_account_id: arkret_wire::AccountId,
    pub realm_id: arkret_wire::RealmId,
    pub target_ref: arkret_wire::CommittedEventRef,
    pub receiver_id: arkret_wire::DidCoreId,
    pub accepted_at: chrono::DateTime<chrono::Utc>,
    pub actor: arkret_wire::ActorId,
    pub verification_method: arkret_wire::DidUrl,
    pub public_key_b64u: arkret_wire::Base64UrlString,
    pub authorization_ref: arkret_wire::CommittedEventRef,
    pub revision: arkret_wire::CurrentRevision,
    pub governance_generation: u64,
    pub cached_at_unix_ms: u64,
}

#[derive(Clone)]
pub struct EventAgentSelector {
    pub accepted_event: arkret_wire::Event,
    pub realm_id: RealmId,
    pub agent_actor_id: arkret_wire::ActorId,
    pub agent_id: DidCoreId,
    pub verification_method: DidUrl,
    pub target_ref: arkret_wire::CommittedEventRef,
    pub receiver_id: DidCoreId,
}

pub fn query_selector(selector: &EventAgentSelector) -> SignerKeyQuerySelector {
    SignerKeyQuerySelector::HistoricalEvent {
        sender: HistoricalSignerKeyQuerySender::Agent {
            actor: selector.agent_actor_id.clone(),
            verification_method: selector.verification_method.clone(),
            committed_event_ref: selector.target_ref.clone(),
        },
    }
}

pub fn historical_key(
    entry: &CachedHistoricalAgentSignerKey,
    selector: &EventAgentSelector,
    recipient: &arkret_wire::AccountId,
) -> Option<[u8; 32]> {
    if entry.recipient_account_id != *recipient
        || entry.realm_id != selector.realm_id
        || entry.target_ref != selector.target_ref
        || entry.receiver_id != selector.receiver_id
        || entry.actor != selector.agent_actor_id
        || entry.verification_method != selector.verification_method
        || entry.authorization_ref.stream_position > entry.revision.stream_position
    {
        return None;
    }
    arkret_canonical::base64url_decode(entry.public_key_b64u.as_str().as_bytes())
        .ok()?
        .try_into()
        .ok()
}

pub fn verify_event_producer(selector: &EventAgentSelector, key: &[u8; 32]) -> bool {
    let event = &selector.accepted_event;
    let Some(proof) = event.producer_proof.as_ref() else {
        return false;
    };
    if proof.verification_method != selector.verification_method
        || did_from_method_for_actor(&proof.verification_method, &selector.agent_id).is_none()
    {
        return false;
    }
    let Ok(envelope) = serde_json::to_value(event) else {
        return false;
    };
    let Ok(preimage) = arkret_wire::event_digest_preimage(&envelope) else {
        return false;
    };
    let Ok(suite) = event.event_id.event_digest().digest_suite() else {
        return false;
    };
    let Ok(bytes) = arkret_canonical::canonical_json_bytes(&preimage) else {
        return false;
    };
    arkret_signatures::verify_ed25519_detached_jws_proof_with_digest_suite(
        proof,
        &bytes,
        &event.actor_id,
        &PublicKeyMaterial::Ed25519Raw {
            bytes: key.to_vec(),
        },
        suite,
    )
    .is_ok()
}

pub fn event_agent_identity(envelope: &Value) -> Option<(arkret_wire::Event, DidCoreId, DidUrl)> {
    let event: arkret_wire::Event = serde_json::from_value(envelope.clone()).ok()?;
    if event.actual_signer().as_account_id().is_none()
        || event.account_device_producer().ok().flatten().is_some()
    {
        return None;
    }
    let frozen_agent_evidence = event.producer_proof.is_some();
    if event.applet_id.is_some() || (event.executed_by.is_none() && !frozen_agent_evidence) {
        return None;
    }
    let agent_id = event
        .executed_by
        .as_ref()
        .unwrap_or(&event.actor_id)
        .signing_principal_id()
        .clone();
    let proof = event.producer_proof.as_ref()?;
    let verification_method = proof
        .verification_method
        .as_str()
        .split_once('#')
        .and_then(|(controller, _)| Did::new(controller.to_owned()).ok())
        .and_then(|did| arkret_identifiers::project_did_to_core_id(&did).ok())
        .filter(|controller| controller == &agent_id)
        .map(|_| proof)
        .map(|proof| proof.verification_method.clone())?;
    Some((event, agent_id, verification_method))
}

pub fn actor_id_from_full(did: &Did) -> Option<DidCoreId> {
    arkret_identifiers::project_did_to_core_id(did).ok()
}

pub fn did_from_method_for_actor(method: &DidUrl, actor_id: &DidCoreId) -> Option<Did> {
    let did = Did::new(method.as_str().split_once('#')?.0.to_owned()).ok()?;
    (actor_id_from_full(&did).as_ref() == Some(actor_id)).then_some(did)
}

pub fn selector_from_committed_event(
    event: arkret_wire::Event,
    target_ref: arkret_wire::CommittedEventRef,
    receiver_id: &DidCoreId,
) -> Option<EventAgentSelector> {
    let (event, agent_id, verification_method) =
        event_agent_identity(&serde_json::to_value(event).ok()?)?;
    let realm_id = event.realm_id.clone();
    if target_ref.event_id != event.event_id || target_ref.stream_ref.realm_id() != &realm_id {
        return None;
    }
    let suite = event.event_id.event_digest().digest_suite().ok()?;
    event
        .validate_proof_bindings_with_digest_suite(suite)
        .ok()?;
    Some(EventAgentSelector {
        accepted_event: event.clone(),
        realm_id,
        agent_actor_id: event
            .executed_by
            .as_ref()
            .unwrap_or(&event.actor_id)
            .clone(),
        agent_id,
        verification_method,
        target_ref,
        receiver_id: receiver_id.clone(),
    })
}

pub fn selector_from_candidate(
    candidate: &HistoricalAgentEventCandidate,
    event: &arkret_wire::Event,
    receiver_id: &DidCoreId,
) -> Option<EventAgentSelector> {
    if &candidate.accepted_event != event || &candidate.receiver_id != receiver_id {
        return None;
    }
    let selector =
        selector_from_committed_event(event.clone(), candidate.target_ref.clone(), receiver_id)?;
    (selector.realm_id == candidate.realm_id
        && selector.agent_actor_id == candidate.agent_actor_id
        && selector.agent_id == candidate.agent_id
        && selector.verification_method == candidate.verification_method)
        .then_some(selector)
}
