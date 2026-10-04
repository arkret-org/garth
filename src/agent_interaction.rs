//! Exact Agent mode observations fenced by fresh verified governing heads.
use arkret_models_collaboration::agent_interaction::AgentInteractionExactCurrentSelector;
use arkret_models_collaboration::exact_current_results::{
    ExactCurrentResultSelector, ExactCurrentResultsReadOutcome, ExactCurrentResultsReadRequestBody,
};
use arkret_wire::{
    AccountId, AuthorityBundleRequest, Base64UrlString, RealmAuthorityBundle, RealmId,
};

use crate::{AuthorityClient, Error, RealmReplica, Result};

async fn authority_with_nonce(
    http: &arkret_http_client::Client,
    realm: &RealmId,
    replica: &mut RealmReplica,
) -> Result<(RealmAuthorityBundle, Base64UrlString)> {
    let mut nonce = [0; 32];
    getrandom::fill(&mut nonce).map_err(|e| Error::Protocol(e.to_string()))?;
    let request = AuthorityBundleRequest {
        realm_id: realm.clone(),
        nonce: Base64UrlString::new(arkret_canonical::base64url_encode(nonce))
            .map_err(|e| Error::Protocol(e.to_string()))?,
    };
    let client = AuthorityClient::new(http.clone());
    let bundle = client.resolve_authority(&request).await?;
    let keys = crate::fetch_historical_station_key_directory(http, &bundle, None, None).await?;
    let freshness =
        arkret_identity::RealmAuthorityFreshness::new(chrono::Utc::now(), request.nonce.clone());
    replica.install_verified_authority(&request, bundle.clone(), &freshness, &keys)?;
    Ok((bundle, request.nonce))
}

async fn authority(
    http: &arkret_http_client::Client,
    realm: &RealmId,
    replica: &mut RealmReplica,
) -> Result<RealmAuthorityBundle> {
    Ok(authority_with_nonce(http, realm, replica).await?.0)
}

pub async fn read_verified_agent_interaction(
    http: &arkret_http_client::Client,
    realm: &RealmId,
    agent: &AccountId,
) -> Result<ExactCurrentResultsReadOutcome> {
    let mut replica = RealmReplica::new(realm.clone());
    let before = authority(http, realm, &mut replica).await?;
    if http.describe().await?.service_id != before.current_service_id {
        return Err(Error::Protocol(
            "Agent mode endpoint is not the governing Station".into(),
        ));
    }
    let request = ExactCurrentResultsReadRequestBody {
        realm_id: realm.clone(),
        selector: ExactCurrentResultSelector::AgentInteraction(
            AgentInteractionExactCurrentSelector::new(agent.clone()),
        ),
    };
    let outcome = http
        .exact_current_result(&request, before.current_generation)
        .await?;
    outcome.validate_for_request(&request, before.current_generation)?;
    let after = authority(http, realm, &mut replica).await?;
    let (generation, head) = match &outcome {
        ExactCurrentResultsReadOutcome::Present {
            governance_generation,
            effective_stream_head,
            ..
        }
        | ExactCurrentResultsReadOutcome::NeverWritten {
            governance_generation,
            effective_stream_head,
            ..
        } => (*governance_generation, effective_stream_head),
    };
    if before.current_generation != after.current_generation
        || before.current_service_id != after.current_service_id
        || generation != after.current_generation
        || head != &before.realm_stream_head
        || head != &after.realm_stream_head
    {
        return Err(Error::Protocol(
            "Agent mode observation crossed governing tenure or an unconfirmed head".into(),
        ));
    }
    Ok(outcome)
}
