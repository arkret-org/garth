//! Holder-private PCR Genesis consumption. This local carrier is neither a
//! portable governance proof nor a replacement for native admission checks.

use arkret_http_client::own_station_results::{BoundOwnStationResponse, OwnStationStateClient};
use arkret_models_identity::{
    CurrentPrincipalRequestBody, CurrentPrincipalResponseBody, PrincipalRegistrationAnchor,
    ResolutionCommitment, ResolutionMethodHistoryEvidence,
};
use arkret_wire::{
    AccountId, CommitStreamRef, CommittedEventFullView, CommittedEventRef, CommittedEventView,
    EventId, GenesisGovernance, PcrGenesisUnit, RealmCommitAuthorityRef, RealmId, ScopeRef,
    StreamScanDirection, StreamScanRequestBody, StreamScanResponseBody,
};

use super::protocol;
use crate::Result;

#[cfg(test)]
#[path = "pcr_history_tests.rs"]
mod tests;

type Principal = BoundOwnStationResponse<CurrentPrincipalRequestBody, CurrentPrincipalResponseBody>;
type Original = BoundOwnStationResponse<EventId, CommittedEventView>;
type Scan = BoundOwnStationResponse<StreamScanRequestBody, StreamScanResponseBody>;

/// Only the authenticated read below constructs this context. Keeping the
/// complete originals and registration material avoids reusable verified flags.
pub struct OwnStationHumanPcrGenesis {
    source: OwnStationStateClient,
    principal: Principal,
    original: Original,
    founding: Scan,
    unit: PcrGenesisUnit,
    anchor: PrincipalRegistrationAnchor,
}

/// A holder-private original tied to its live registered PCR and actual Full
/// stream row. This is not a portable authorization or a current MLS state.
pub struct OwnStationHumanPcrEvent<'a> {
    pcr: &'a OwnStationHumanPcrGenesis,
    original: CommittedEventFullView,
    successor: Option<Scan>,
}

impl OwnStationHumanPcrEvent<'_> {
    pub fn full(&self) -> Result<&CommittedEventFullView> {
        self.pcr.check()?;
        if let Some(source) = &self.successor {
            source.value()?;
        }
        Ok(&self.original)
    }

    pub fn reference(&self) -> Result<CommittedEventRef> {
        let full = self.full()?;
        Ok(CommittedEventRef {
            event_id: full.event.event_id.clone(),
            commit_id: full.commit.commit_id.clone(),
            stream_ref: full.commit.stream_ref.clone(),
            stream_position: full.commit.stream_position,
        })
    }
}

impl OwnStationHumanPcrGenesis {
    fn check(&self) -> Result<()> {
        self.source.check_session()?;
        self.principal.value()?;
        self.original.value()?;
        self.founding.value()?;
        Ok(())
    }

    pub fn account(&self) -> Result<&AccountId> {
        self.check()?;
        Ok(&self.principal.value()?.account_id)
    }

    pub fn realm(&self) -> Result<&RealmId> {
        self.check()?;
        Ok(&self.principal.value()?.principal_control_realm_id)
    }

    pub fn genesis(&self) -> Result<&CommittedEventFullView> {
        self.check()?;
        match self.original.value()? {
            CommittedEventView::Full(full) => Ok(full),
            _ => Err(protocol("PCR Genesis original is withheld")),
        }
    }

    pub fn unit(&self) -> Result<&PcrGenesisUnit> {
        self.check()?;
        Ok(&self.unit)
    }

    pub fn registration_verification_anchor(&self) -> Result<&PrincipalRegistrationAnchor> {
        self.check()?;
        Ok(&self.anchor)
    }

    /// Resolve one original without restoring old private MLS state or
    /// installing its historical authorization as current. The founding pair
    /// already has independent registration/root and Device-possession proofs.
    /// Successors require the exact scan row and original self-admission key.
    pub async fn read_original(&self, event_id: &EventId) -> Result<OwnStationHumanPcrEvent<'_>> {
        self.check()?;
        for row in &self.founding.value()?.committed_events {
            if let CommittedEventView::Full(full) = row
                && &full.event.event_id == event_id
            {
                return Ok(OwnStationHumanPcrEvent {
                    pcr: self,
                    original: full.clone(),
                    successor: None,
                });
            }
        }
        let candidate = self.source.committed_event_get(event_id).await?;
        self.check()?;
        let CommittedEventView::Full(full) = candidate.value()? else {
            return Err(protocol("PCR historical original is withheld"));
        };
        let realm = self.realm()?;
        let stream = CommitStreamRef::Realm {
            realm_id: realm.clone(),
        };
        let genesis = self.genesis()?;
        if candidate.session() != self.principal.session()
            || candidate.request() != event_id
            || full.event.event_id != *event_id
            || full.event.realm_id != *realm
            || full.event.scope_ref
                != (ScopeRef::Realm {
                    realm_id: realm.clone(),
                })
            || full.event.actual_signer().as_account_id() != Some(self.account()?)
            || full.commit.event_ref != *event_id
            || full.commit.stream_ref != stream
            || full.commit.stream_position < 2
            || full.commit.governance_generation != 0
            || full.commit.authority_ref != genesis.commit.authority_ref
        {
            return Err(protocol(
                "historical original is outside this registered Human PCR",
            ));
        }
        let before = full
            .commit
            .stream_position
            .checked_add(1)
            .ok_or_else(|| protocol("PCR original position overflow"))?;
        let request = StreamScanRequestBody {
            realm_id: realm.clone(),
            stream_ref: stream,
            direction: StreamScanDirection::Before(Some(before)),
            limit: 1,
        };
        let successor = self.source.scan_commit_stream(&request).await?;
        self.check()?;
        let [row] = successor.value()?.committed_events.as_slice() else {
            return Err(protocol(
                "PCR historical source requires one exact Full stream row",
            ));
        };
        if successor.session() != self.principal.session() || row != candidate.value()? {
            return Err(protocol(
                "PCR GET differs from its exact accepted scan original",
            ));
        }
        super::verify_row_from_source(&self.source, row, super::OriginalSource::HumanPcrHistory)
            .await?;
        self.check()?;
        candidate.value()?;
        successor.value()?;
        Ok(OwnStationHumanPcrEvent {
            pcr: self,
            original: full.clone(),
            successor: Some(successor),
        })
    }
}

/// Resolve only this live Account's registered Human PCR. No caller-provided
/// PCR id, current DID key, imported private MLS state or general audit role
/// can manufacture the returned local original-read context.
pub async fn read_own_station_human_pcr_genesis(
    source: &OwnStationStateClient,
    principal: BoundOwnStationResponse<CurrentPrincipalRequestBody, CurrentPrincipalResponseBody>,
) -> Result<OwnStationHumanPcrGenesis> {
    if principal.session() != source.session()?
        || &principal.request().account_id != source.session()?.account_id()
    {
        return Err(protocol(
            "PCR lookup belongs to another accepted Station or Account session",
        ));
    }
    let current = principal.value()?;
    let account = &current.account_id;
    let realm = &current.principal_control_realm_id;
    let event_id = EventId::from_digest(
        realm.digest_suite_code().digest_suite(),
        realm.digest_bytes(),
    );
    let original = source.committed_event_get(&event_id).await?;
    let CommittedEventView::Full(full) = original.value()? else {
        return Err(protocol("PCR Genesis original is withheld"));
    };
    full.validate_shape()?;
    full.commit.validate_content_address()?;
    full.event
        .verify_event_id_matches_content_with_digest_suite(arkret_canonical::DigestSuite::Sha256)?;
    let stream = CommitStreamRef::Realm {
        realm_id: realm.clone(),
    };
    if original.session() != principal.session()
        || full.event.event_id != event_id
        || full.event.realm_id != *realm
        || full.event.scope_ref != ScopeRef::RealmGenesis
        || full.commit.event_ref != event_id
        || full.commit.stream_ref != stream
        || full.commit.stream_position != 0
        || full.commit.previous_commit_ref.is_some()
        || full.commit.governance_generation != 0
        || full.commit.authority_ref != RealmCommitAuthorityRef::GenesisOrChangeEvent(event_id)
        || !matches!(GenesisGovernance::from_genesis(&full.event)?, GenesisGovernance::Human(ref holder) if holder == account)
    {
        return Err(protocol(
            "PCR founding original differs from the registered complete Account",
        ));
    }
    let founding_request = StreamScanRequestBody {
        realm_id: realm.clone(),
        stream_ref: stream,
        direction: StreamScanDirection::After(None),
        limit: 2,
    };
    let founding = source.scan_commit_stream(&founding_request).await?;
    let [
        CommittedEventView::Full(create),
        CommittedEventView::Full(authorize),
    ] = founding.value()?.committed_events.as_slice()
    else {
        return Err(protocol(
            "PCR founding read requires both complete original Events",
        ));
    };
    if founding.session() != principal.session()
        || create != full
        || authorize
            .commit
            .validate_successor_of(&create.commit)
            .is_err()
        || authorize.commit.stream_position != 1
        || authorize.commit.governance_generation != 0
        || authorize.commit.authority_ref != create.commit.authority_ref
        || founding
            .value()?
            .readable_floor
            .as_ref()
            .is_none_or(|floor| {
                floor.oldest_position != 0 || floor.floor_commit_id != create.commit.commit_id
            })
    {
        return Err(protocol(
            "PCR founding unit has a gap, wrong floor or another accepted source",
        ));
    }
    authorize.validate_shape()?;
    authorize.commit.validate_content_address()?;
    let unit = PcrGenesisUnit::new(create.event.clone(), authorize.event.clone())?;
    let payload: arkret_models_collaboration::events_payloads::RealmCreatePayload =
        serde_json::from_value(serde_json::to_value(&create.event.payload)?)?;
    let target = payload
        .object
        .initial_resolution
        .as_ref()
        .ok_or_else(|| protocol("PCR Genesis omits its original resolution commitment"))?;
    let anchor = registration_anchor(source, target).await?;
    arkret_identity::verify_pcr_genesis_events(
        &unit,
        &anchor,
        &arkret_wire::ActorId::account(account.clone()),
    )
    .map_err(|error| protocol(&error.to_string()))?;
    source.check_session()?;
    principal.value()?;
    original.value()?;
    founding.value()?;
    Ok(OwnStationHumanPcrGenesis {
        source: source.clone(),
        principal,
        original,
        founding,
        unit,
        anchor,
    })
}

async fn registration_anchor(
    source: &OwnStationStateClient,
    target: &ResolutionCommitment,
) -> Result<PrincipalRegistrationAnchor> {
    let http = source.http_client()?;
    let document = http
        .identity_document(target.did.as_str(), Some(&target.version_id))
        .await?;
    source.check_session()?;
    let (history, witnesses) = match document.method_evidence {
        Some(ResolutionMethodHistoryEvidence::WebvhLog {
            log_entries,
            witness_records,
            ..
        }) => (log_entries, witness_records),
        Some(_) => {
            return Err(protocol(
                "PCR registration evidence is not native did:webvh history",
            ));
        }
        None => {
            // The log operation is an independent registered source of raw
            // native entries. Missing required witness proofs still fail in
            // the native verifier; a registry receipt cannot substitute.
            let mut cursor = None;
            let mut seen = std::collections::BTreeSet::new();
            let mut entries = Vec::new();
            loop {
                let page = http
                    .identity_log(target.did.as_str(), cursor.as_deref(), Some(200))
                    .await?;
                source.check_session()?;
                if page.did != target.did
                    || page.method != arkret_models_identity::DidMethodUri::Webvh
                    || page.native_history != Some(true)
                {
                    return Err(protocol(
                        "PCR registration log belongs to another DID or method",
                    ));
                }
                let found = page.entries.iter().any(|entry| {
                    entry.get("versionId").and_then(serde_json::Value::as_str)
                        == Some(target.version_id.as_str())
                });
                entries.extend(page.entries);
                if found || !page.has_more {
                    break;
                }
                let next = page.next_cursor.ok_or_else(|| {
                    protocol("PCR registration log is truncated without a cursor")
                })?;
                if !seen.insert(next.clone()) {
                    return Err(protocol("PCR registration log repeats a continuation"));
                }
                cursor = Some(next);
            }
            (entries, Vec::new())
        }
    };
    arkret_identity::recover_principal_registration_anchor(target, &history, &witnesses)
        .map_err(|error| protocol(&error.to_string()))
}
