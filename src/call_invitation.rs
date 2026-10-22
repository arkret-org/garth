//! Fresh holder-private full-value Consent consumption for one ringing cut.

use arkret_http_client::own_station_results::{
    BoundOwnStationResponse, ConsentCurrentReadAuthority, OwnStationResultClient,
};
use arkret_models_collaboration::call_invitation::CallInvitationEnvelope;
use arkret_models_collaboration::consent_operations::{
    ConsentCurrentReadOutcome, ConsentCurrentReadRequestBody,
};
use arkret_wire::{AccountId, ActorId, CommitStreamHead, RealmId};
use chrono::{DateTime, Utc};

use crate::{Error, Result};

/// Retains the genuine authenticated response and targeted current rows for
/// precisely one product attempt. It cannot be cloned into an admission cache.
pub struct HolderCallConsent {
    response: BoundOwnStationResponse<ConsentCurrentReadRequestBody, ConsentCurrentReadOutcome>,
    invitation: CallInvitationEnvelope,
    authority_generation: u64,
}

fn invalid(message: &str) -> Error {
    Error::Protocol(message.into())
}

fn check_heads(
    snapshot: &ConsentCurrentReadOutcome,
    generation: Option<u64>,
    known: &[CommitStreamHead],
) -> Result<()> {
    if generation.is_some_and(|generation| generation > snapshot.governance_generation) {
        return Err(invalid(
            "holder Consent current read rolls back authority generation",
        ));
    }
    for previous in known {
        let current = &snapshot.effective_stream_head;
        if current.stream_ref != previous.stream_ref {
            continue;
        }
        if current.stream_position < previous.stream_position
            || (current.stream_position == previous.stream_position
                && current.commit_id != previous.commit_id)
        {
            return Err(invalid(
                "holder Consent current read rolls back a known current cut",
            ));
        }
    }
    Ok(())
}

/// Previously observed holder authority used to reject a stale current read.
pub struct HolderConsentKnownCut<'a> {
    pub governance_generation: Option<u64>,
    pub stream_heads: &'a [CommitStreamHead],
}

pub async fn read_holder_call_consent(
    client: &OwnStationResultClient,
    holder: &AccountId,
    pcr: &RealmId,
    authority: &ConsentCurrentReadAuthority,
    invitation: &CallInvitationEnvelope,
    nonce: String,
    known: HolderConsentKnownCut<'_>,
) -> Result<HolderCallConsent> {
    if &invitation.holder_account_id != holder {
        return Err(invalid("call Consent read names another holder"));
    }
    let request = ConsentCurrentReadRequestBody {
        holder_account_id: holder.clone(),
        peer: arkret_models_collaboration::events_payloads::consent::ConsentPeer::Actor {
            actor_id: invitation.inviter_actor_id.clone(),
        },
        audience_actor_id: ActorId::service(holder.station_id.clone()),
        nonce,
    };
    let response = client.consent_current(&request, pcr, authority).await?;
    if response.session().account_id() != holder {
        return Err(invalid(
            "call Consent response belongs to another authenticated account",
        ));
    }
    let snapshot = response.value()?;
    snapshot.validate_for_request(&request, authority.generation(), Utc::now())?;
    if &snapshot.realm_id != pcr {
        return Err(invalid(
            "Consent current read belongs to another holder PCR",
        ));
    }
    check_heads(snapshot, known.governance_generation, known.stream_heads)?;
    response.value()?;
    Ok(HolderCallConsent {
        response,
        invitation: invitation.clone(),
        authority_generation: authority.generation(),
    })
}

impl HolderCallConsent {
    pub fn source(
        &self,
    ) -> &BoundOwnStationResponse<ConsentCurrentReadRequestBody, ConsentCurrentReadOutcome> {
        &self.response
    }
    pub fn authority_generation(&self) -> Result<u64> {
        self.response.value()?;
        Ok(self.authority_generation)
    }
    /// Consume once at the actual product cut, after taking the caller's latest
    /// installed/observed high-water. Fresh full values never overwrite a
    /// known later replacement. The requested concrete scope is evaluated locally.
    pub fn permits(
        self,
        current_generation: Option<u64>,
        current_heads: &[CommitStreamHead],
        now: DateTime<Utc>,
    ) -> Result<bool> {
        let snapshot = self.response.value()?;
        snapshot.validate_for_request(self.response.request(), self.authority_generation, now)?;
        check_heads(snapshot, current_generation, current_heads)?;
        if self.invitation.expires_at <= now {
            return Ok(false);
        }
        Ok(self.invitation.media.is_nonempty()
            && snapshot.permits(
                self.response.request(),
                self.invitation.media.consent_scope(),
                now,
            ))
    }
}
