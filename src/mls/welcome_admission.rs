//! Which MLS Welcome deliveries a local endpoint may admit.
//!
//! A Welcome is a producer-signed recipient delivery object, not an Event and
//! not a commit-stream item. It is admissible only when it names this exact
//! `(realm, actor, endpoint)`, binds the accepted Commit Event it accompanies,
//! and carries its dedicated producer signature context. All of that is
//! wire-shape verification with no host state behind it, so every client
//! answers it identically.

use arkret_models_crypto::{
    KeyOperationSignature, KeyPackageClaimRecord, KeyPackagesClaimOutcome,
    KeyPackagesConsumeRequestBody, KeyPackagesConsumeUnsignedRequest, MlsCommitPayload,
    RecipientMlsDurableReceipt, RecipientMlsDurableSigner, keypackages_consume_signing_input,
};
use arkret_wire::{
    ActorId, Base64UrlString, DeviceId, DidCoreId, DidUrl, DomainSeparationId, Event, EventId,
    EventKind, MlsGroupId, MlsWelcomeDelivery, MlsWelcomeRecipientEndpoint, NonEmptyString,
    RealmId, ScopeRef,
};
use chrono::{DateTime, Utc};

use crate::{Error, Result};

/// The local endpoint a Welcome delivery must name to be admissible.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalMlsEndpoint {
    pub realm_id: RealmId,
    pub actor_id: ActorId,
    pub endpoint: MlsWelcomeRecipientEndpoint,
}

impl LocalMlsEndpoint {
    pub fn device(realm_id: RealmId, actor_id: ActorId, device_id: DeviceId) -> Self {
        Self {
            realm_id,
            actor_id,
            endpoint: MlsWelcomeRecipientEndpoint::Device { device_id },
        }
    }

    pub fn agent_runtime(
        realm_id: RealmId,
        actor_id: ActorId,
        verification_method: DidUrl,
    ) -> Self {
        Self {
            realm_id,
            actor_id,
            endpoint: MlsWelcomeRecipientEndpoint::AgentRuntime {
                verification_method,
            },
        }
    }
}

/// The canonical MLS group id of a scope. A Welcome never carries a group id
/// of its own: the group is a function of the effective scope.
pub fn mls_group_id_for_scope(scope: &ScopeRef) -> Result<MlsGroupId> {
    scope.canonical_mls_group_id().map_err(Error::from)
}

/// The canonical MLS group id of a Realm's default scope.
pub fn mls_group_id_for_realm(realm_id: &RealmId) -> Result<MlsGroupId> {
    mls_group_id_for_scope(&ScopeRef::Realm {
        realm_id: realm_id.clone(),
    })
}

/// True when a delivery is addressed to exactly this local endpoint.
pub fn welcome_matches_endpoint(welcome: &MlsWelcomeDelivery, endpoint: &LocalMlsEndpoint) -> bool {
    welcome.realm_id == endpoint.realm_id
        && welcome.recipient_actor_id == endpoint.actor_id
        && welcome.recipient_endpoint == endpoint.endpoint
}

/// Admit one Welcome delivery for this endpoint and the accepted Commit Event
/// it must bind. Anything that does not match fails closed.
pub fn admit_welcome(
    welcome: &MlsWelcomeDelivery,
    endpoint: &LocalMlsEndpoint,
    accepted_commit_event_id: &EventId,
) -> Result<()> {
    welcome.validate_shape()?;
    if !welcome_matches_endpoint(welcome, endpoint) {
        return Err(Error::Protocol(
            "MLS Welcome delivery is addressed to another endpoint".to_owned(),
        ));
    }
    if &welcome.commit_event_ref != accepted_commit_event_id {
        return Err(Error::Protocol(
            "MLS Welcome delivery does not bind the accepted Commit Event".to_owned(),
        ));
    }
    Ok(())
}

/// Keep only the deliveries addressed to this endpoint that bind the accepted
/// Commit Event, deduplicating on `welcome_id`.
pub fn retain_admissible_welcomes(
    welcomes: impl IntoIterator<Item = MlsWelcomeDelivery>,
    endpoint: &LocalMlsEndpoint,
    accepted_commit_event_id: &EventId,
) -> Vec<MlsWelcomeDelivery> {
    let mut seen = std::collections::BTreeSet::new();
    welcomes
        .into_iter()
        .filter(|welcome| admit_welcome(welcome, endpoint, accepted_commit_event_id).is_ok())
        .filter(|welcome| seen.insert(welcome.welcome_id.clone()))
        .collect()
}

/// The authenticated route used to read the recipient's original claim.
/// Realm authority must already have passed fresh, nonce-bound chain verification.
pub enum WelcomeClaimAuthority<'a> {
    AccountStation(&'a DidCoreId),
    Realm {
        current_station: &'a DidCoreId,
        authority: &'a arkret_identity::VerifiedRealmAuthority,
    },
}

impl<'a> From<&'a DidCoreId> for WelcomeClaimAuthority<'a> {
    fn from(station: &'a DidCoreId) -> Self {
        Self::AccountStation(station)
    }
}

/// The claim a Welcome names, verified before the Welcome is decrypted
/// (device-lifecycle.md §9 `claims/query` and §9.2.4, encryption-and-audit.md
/// §2.6.1).
///
/// `outcome` is the exact claim outcome this endpoint read from its own
/// Account Station or verified current Realm governor through
/// `ak.self.keys.keypackages.read.claim.v1`. The caller has verified the
/// original receipt signature with its issuer's authenticated historical key. `accepted_commit` is
/// the accepted `ak.mls.commit` the Welcome names and `endpoint_authorization` the endpoint's
/// current `ak.device.authorize` (or `ak.agent.key.authorize`) Event. The recomputed
/// `claims_digest`, the destination, the claim record's endpoint, KeyPackage
/// digest and authority, the receipt's requester, target, Realm and group,
/// and the claimed KeyPackage being one inline Add of the Commit must all
/// hold, or the Welcome stays undecrypted.
pub fn verify_welcome_claim<'a>(
    welcome: &MlsWelcomeDelivery,
    endpoint: &LocalMlsEndpoint,
    accepted_commit: &Event,
    outcome: &KeyPackagesClaimOutcome,
    authority: impl Into<WelcomeClaimAuthority<'a>>,
    endpoint_authorization: &EventId,
) -> Result<KeyPackageClaimRecord> {
    let refused = |detail: &str| Error::Protocol(format!("MLS Welcome claim: {detail}"));
    admit_welcome(welcome, endpoint, &accepted_commit.event_id)?;
    outcome
        .validate_shape()
        .map_err(|error| refused(&format!("claim outcome is invalid: {error}")))?;
    let receipt = &outcome.claim_receipt;
    match (&welcome.recipient_actor_id, authority.into()) {
        (ActorId::Account { account_id }, WelcomeClaimAuthority::AccountStation(station))
            if &receipt.destination_id == station && &account_id.station_id == station => {}
        (
            ActorId::Realm { realm_actor_id },
            WelcomeClaimAuthority::Realm {
                current_station,
                authority,
            },
        ) if realm_actor_id.realm_id == welcome.realm_id
            && authority.realm_id() == &realm_actor_id.realm_id
            && authority.current_service_id() == current_station
            && authority.authorizes_issuer_at(
                &receipt.destination_id,
                receipt.claim_authority_ref.as_ref(),
                receipt.claimed_at,
            ) => {}
        _ => {
            return Err(refused(
                "the claim issuer is not authorized for this endpoint",
            ));
        }
    }
    let record = outcome
        .claims
        .iter()
        .find(|record| record.claim_id == welcome.keypackage_claim_ref.as_str())
        .ok_or_else(|| refused("the outcome does not hold the Welcome's claim"))?;
    let (endpoint_matches, authorization) = match &welcome.recipient_endpoint {
        MlsWelcomeRecipientEndpoint::Device { device_id } => (
            record.device_id.as_ref() == Some(device_id)
                && record.agent_verification_method.is_none(),
            record.device_authorize_event_id.as_ref(),
        ),
        MlsWelcomeRecipientEndpoint::AgentRuntime {
            verification_method,
        } => (
            record.agent_verification_method.as_ref() == Some(verification_method)
                && record.device_id.is_none(),
            record.agent_key_authorize_event_id.as_ref(),
        ),
    };
    if record.actor_id != welcome.recipient_actor_id || !endpoint_matches {
        return Err(refused("the claim record names another endpoint"));
    }
    if authorization != Some(endpoint_authorization) {
        return Err(refused(
            "the claim record does not bind the endpoint's current authorization",
        ));
    }
    let keypackage = arkret_canonical::base64url_decode(&record.keypackage)
        .map_err(|_| refused("the claimed KeyPackage is not base64url"))?;
    if arkret_canonical::sha256_digest(&keypackage) != record.keypackage_ref {
        return Err(refused("the claimed KeyPackage does not match its digest"));
    }
    let request = &receipt.request;
    let target_matches = match (
        &request.target_account_id,
        &request.target_actor_id,
        &request.target_agent_id,
        &welcome.recipient_actor_id,
    ) {
        (Some(account), None, None, ActorId::Account { account_id }) => account == account_id,
        (None, Some(actor), None, ActorId::Realm { .. }) => actor == &welcome.recipient_actor_id,
        (None, None, Some(agent), ActorId::Account { account_id }) => {
            agent == &account_id.principal_id
        }
        _ => false,
    };
    let requester_matches = match (
        &request.requester_account_id,
        &request.requester_actor_id,
        &accepted_commit.actor_id,
    ) {
        (Some(account), None, ActorId::Account { account_id }) => account == account_id,
        (None, Some(actor), ActorId::Realm { realm_actor_id }) => {
            actor == &accepted_commit.actor_id && realm_actor_id.realm_id == welcome.realm_id
        }
        _ => false,
    };
    if accepted_commit.kind != EventKind::MlsCommit
        || request.intended_realm_id != welcome.realm_id
        || request.mls_group_id != mls_group_id_for_scope(&welcome.effective_scope)?
        || !requester_matches
        || !target_matches
    {
        return Err(refused(
            "the claim receipt does not bind the Commit's committer, this recipient, Realm and group",
        ));
    }
    let payload: MlsCommitPayload = serde_json::from_value(serde_json::Value::Object(
        accepted_commit.payload.clone().into_iter().collect(),
    ))
    .map_err(|error| refused(&format!("the accepted Commit payload is invalid: {error}")))?;
    payload.validate()?;
    if payload.governance_binding().effective_scope() != &welcome.effective_scope
        || accepted_commit.scope_ref != welcome.effective_scope
    {
        return Err(refused(
            "the Commit and Welcome have different effective scopes",
        ));
    }
    let commit_bytes = arkret_canonical::base64url_decode(payload.commit_bytes_b64())
        .map_err(|_| refused("the accepted Commit bytes are not base64url"))?;
    // An inline Add proposal carries the added KeyPackage's exact TLS
    // serialization inside the Commit's public content.
    if keypackage.is_empty()
        || !commit_bytes
            .windows(keypackage.len())
            .any(|window| window == keypackage.as_slice())
    {
        return Err(refused(
            "the accepted Commit does not add the claimed KeyPackage",
        ));
    }
    Ok(record.clone())
}

/// The signed `keypackages/consume` command a Welcome's endpoint sends once
/// the group state the Welcome joined is durable (device-lifecycle.md §9
/// consume, decision 0121).
///
/// `outcome` is the claim outcome the Welcome was verified against
/// ([`verify_welcome_claim`]); the receipt names its claim request and the
/// claimed KeyPackage, this endpoint's `local_station`, the scope's group,
/// `joined_epoch` (the accepted Commit's next epoch) and the delivery's
/// [`MlsWelcomeDelivery::durable_receipt_digest`]. `sign` signs one input
/// under the endpoint key `recipient` names and is used for the receipt and
/// then the command, so both carry the same endpoint signature.
pub fn signed_welcome_consume(
    welcome: &MlsWelcomeDelivery,
    outcome: &KeyPackagesClaimOutcome,
    recipient: RecipientMlsDurableSigner,
    local_station: &DidCoreId,
    joined_epoch: u64,
    durable_at: DateTime<Utc>,
    sign: impl Fn(&str, &[u8]) -> Result<KeyOperationSignature>,
) -> Result<KeyPackagesConsumeRequestBody> {
    let refused = |detail: &str| Error::Protocol(format!("MLS Welcome consume: {detail}"));
    let record = outcome
        .claims
        .iter()
        .find(|record| record.claim_id == welcome.keypackage_claim_ref.as_str())
        .ok_or_else(|| refused("the outcome does not hold the Welcome's claim"))?;
    outcome
        .validate_shape()
        .map_err(|e| refused(&e.to_string()))?;
    if local_station != &outcome.claim_receipt.destination_id {
        return Err(refused(
            "durable receipt must preserve the original claim destination",
        ));
    }
    let signer_matches = match (
        &recipient,
        &welcome.recipient_actor_id,
        &welcome.recipient_endpoint,
    ) {
        (
            RecipientMlsDurableSigner::Device {
                recipient_account_id,
                recipient_device_id,
                ..
            },
            ActorId::Account { account_id },
            MlsWelcomeRecipientEndpoint::Device { device_id },
        ) => recipient_account_id == account_id && recipient_device_id == device_id,
        (
            RecipientMlsDurableSigner::RealmDevice {
                recipient_actor_id,
                recipient_device_id,
                ..
            },
            ActorId::Realm { .. },
            MlsWelcomeRecipientEndpoint::Device { device_id },
        ) => recipient_actor_id == &welcome.recipient_actor_id && recipient_device_id == device_id,
        (
            RecipientMlsDurableSigner::Agent {
                recipient_agent_id,
                recipient_agent_verification_method,
                agent_key_authorize_event_id,
            },
            ActorId::Account { account_id },
            MlsWelcomeRecipientEndpoint::AgentRuntime {
                verification_method,
            },
        ) => {
            recipient_agent_id == &account_id.principal_id
                && recipient_agent_verification_method == verification_method
                && record.agent_key_authorize_event_id.as_ref()
                    == Some(agent_key_authorize_event_id)
        }
        _ => false,
    };
    if !signer_matches || record.actor_id != welcome.recipient_actor_id {
        return Err(refused(
            "durable signer differs from the claimed Welcome endpoint",
        ));
    }
    let method = match &recipient {
        RecipientMlsDurableSigner::Device {
            device_verification_method,
            ..
        }
        | RecipientMlsDurableSigner::RealmDevice {
            device_verification_method,
            ..
        } => device_verification_method,
        RecipientMlsDurableSigner::Agent {
            recipient_agent_verification_method,
            ..
        } => recipient_agent_verification_method,
    }
    .as_str()
    .to_owned();
    let mut receipt = RecipientMlsDurableReceipt {
        domain: NonEmptyString::new(
            DomainSeparationId::MLS_RECIPIENT_DURABLE_RECEIPT_V1.to_owned(),
        )
        .map_err(&refused)?,
        claim_request_id: outcome.claim_request_id.clone(),
        key_package_ref: NonEmptyString::new(record.keypackage_ref.clone()).map_err(&refused)?,
        recipient,
        recipient_id: local_station.clone(),
        realm_id: welcome.realm_id.clone(),
        mls_group_id: mls_group_id_for_scope(&welcome.effective_scope)?,
        mls_epoch: joined_epoch,
        welcome_ref: welcome.welcome_id.clone(),
        welcome_digest: welcome.durable_receipt_digest()?,
        durable_at,
        // Replaced by the endpoint signature below; the signing input omits it.
        signature: KeyOperationSignature {
            kid: NonEmptyString::new(method.clone()).map_err(&refused)?,
            signature_algorithm: None,
            sig: Base64UrlString::new("AA".to_owned()).map_err(&refused)?,
        },
    };
    receipt.signature = sign(
        &method,
        &receipt
            .canonical_signing_bytes()
            .map_err(|error| refused(&error.to_string()))?,
    )?;
    receipt.validate_shape().map_err(refused)?;
    let unsigned = KeyPackagesConsumeUnsignedRequest {
        claim_id: welcome.keypackage_claim_ref.clone(),
        recipient_durable_receipt: receipt,
    };
    let signature = sign(
        &method,
        &keypackages_consume_signing_input(&unsigned)
            .map_err(|error| refused(&error.to_string()))?,
    )?;
    let request = unsigned.into_signed(signature);
    request.validate_shape().map_err(refused)?;
    Ok(request)
}

#[cfg(test)]
mod tests {
    use arkret_canonical::DigestSuite;
    use arkret_wire::{
        Base64UrlString, DetachedSignatureContext, KeypackageClaimId, MlsWelcomeDeliveryId,
    };

    use super::*;
    use crate::test_fixtures::{actor_id, at, detached_signature, device_id, realm_id};

    fn commit_event_id() -> EventId {
        EventId::from_digest(DigestSuite::Sha256, [6; 32])
    }

    fn welcome(suffix: &str) -> MlsWelcomeDelivery {
        MlsWelcomeDelivery {
            welcome_id: MlsWelcomeDeliveryId::new(format!(
                "ak:mls_welcome_delivery:0196419b-0000-7000-8000-00000000004{suffix}"
            ))
            .unwrap(),
            realm_id: realm_id(),
            effective_scope: ScopeRef::Realm {
                realm_id: realm_id(),
            },
            commit_event_ref: commit_event_id(),
            recipient_actor_id: actor_id(),
            recipient_endpoint: MlsWelcomeRecipientEndpoint::Device {
                device_id: device_id(),
            },
            keypackage_claim_ref: KeypackageClaimId::new(
                "ak:keypackage_claim:0196419b-0000-7000-8000-000000000050",
            )
            .unwrap(),
            ciphertext_b64: Base64UrlString::new("AQID").unwrap(),
            producer_proof: detached_signature(DetachedSignatureContext::MlsWelcomeDelivery),
        }
    }

    fn endpoint() -> LocalMlsEndpoint {
        LocalMlsEndpoint::device(realm_id(), actor_id(), device_id())
    }

    #[test]
    fn a_welcome_for_this_endpoint_and_commit_is_admitted() {
        admit_welcome(&welcome("0"), &endpoint(), &commit_event_id()).unwrap();
    }

    #[test]
    fn a_welcome_for_another_device_is_refused() {
        let mut other = welcome("0");
        other.recipient_endpoint = MlsWelcomeRecipientEndpoint::Device {
            device_id: DeviceId::new("ak:device:0196419b-0000-7000-8000-000000000002").unwrap(),
        };
        assert!(admit_welcome(&other, &endpoint(), &commit_event_id()).is_err());
    }

    #[test]
    fn a_welcome_that_does_not_bind_the_accepted_commit_is_refused() {
        let other_commit = EventId::from_digest(DigestSuite::Sha256, [7; 32]);
        assert!(admit_welcome(&welcome("0"), &endpoint(), &other_commit).is_err());
    }

    #[test]
    fn a_welcome_outside_its_realm_scope_is_refused() {
        let mut other = welcome("0");
        other.effective_scope = ScopeRef::RealmGenesis;
        assert!(admit_welcome(&other, &endpoint(), &commit_event_id()).is_err());
    }

    #[test]
    fn the_welcome_id_is_the_deduplication_key() {
        let admitted = retain_admissible_welcomes(
            [welcome("0"), welcome("0"), welcome("1")],
            &endpoint(),
            &commit_event_id(),
        );
        assert_eq!(admitted.len(), 2);
    }

    fn station() -> DidCoreId {
        DidCoreId::new("ak:did_core:web:recipient-station.example").unwrap()
    }

    fn recipient() -> ActorId {
        ActorId::account(arkret_wire::AccountId::new(
            DidCoreId::new("ak:did_core:web:bob.example").unwrap(),
            station(),
        ))
    }

    fn committer() -> arkret_wire::AccountId {
        arkret_wire::AccountId::new(
            DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            DidCoreId::new("ak:did_core:web:governance.example").unwrap(),
        )
    }

    fn authorization() -> EventId {
        EventId::from_digest(DigestSuite::Sha256, [8; 32])
    }

    const KEYPACKAGE: &[u8] = b"exact KeyPackage TLS bytes";

    /// The accepted Commit whose inline Add carries `added`.
    fn accepted_commit(added: &[u8]) -> Event {
        accepted_commit_in(realm_id(), added)
    }

    fn accepted_commit_in(realm: RealmId, added: &[u8]) -> Event {
        let binding = arkret_models_crypto::MlsGovernanceBindingPayload::realm(
            realm.clone(),
            Some(EventId::from_digest(DigestSuite::Sha256, [5; 32])),
            0,
            1,
            0,
        )
        .unwrap();
        let commit_bytes = [b"public-message:".as_slice(), added, b":tail"].concat();
        let envelope = arkret_models_crypto::MlsCommitEnvelope {
            group_id: binding.mls_group_id().unwrap(),
            epoch: 1,
            commit: arkret_canonical::base64url_encode(&commit_bytes),
            commit_digest: arkret_wire::Hash::new(arkret_canonical::sha256_digest(&commit_bytes))
                .unwrap(),
            ratchet_tree: None,
        };
        let payload = MlsCommitPayload::new(
            EventId::from_digest(DigestSuite::Sha256, [5; 32]),
            0,
            &envelope,
            binding,
        )
        .unwrap();
        let mut event = crate::test_fixtures::event(
            6,
            EventKind::MlsCommit,
            serde_json::to_value(payload).unwrap(),
        );
        event.actor_id = ActorId::account(committer());
        event.realm_id = realm.clone();
        event.scope_ref = ScopeRef::Realm { realm_id: realm };
        event
    }

    fn claim_record() -> KeyPackageClaimRecord {
        KeyPackageClaimRecord {
            claim_id: "ak:keypackage_claim:0196419b-0000-7000-8000-000000000050".to_owned(),
            keypackage_ref: arkret_canonical::sha256_digest(KEYPACKAGE),
            actor_id: recipient(),
            principal_id: DidCoreId::new("ak:did_core:web:bob.example").unwrap(),
            device_id: Some(device_id()),
            agent_id: None,
            agent_verification_method: None,
            keypackage: arkret_canonical::base64url_encode(KEYPACKAGE),
            capabilities: vec!["ak.content.v1".to_owned()],
            device_authorize_event_id: Some(authorization()),
            agent_key_authorize_event_id: None,
            expires_at: at(40),
            revocation_status: None,
            last_resort: None,
        }
    }

    /// The claim outcome as the recipient's Station first serialized it,
    /// with the receipt's `claims_digest` over `claims`.
    fn outcome(claims: Vec<KeyPackageClaimRecord>) -> KeyPackagesClaimOutcome {
        let claim_request_id = Base64UrlString::new("Y2xhaW0tcmVxdWVzdA").unwrap();
        let request = arkret_models_crypto::PeerKeyPackagesClaimUnsignedRequest {
            claim_request_id: claim_request_id.clone(),
            target_account_id: recipient().as_account_id().cloned(),
            target_actor_id: None,
            requester_account_id: Some(committer()),
            requester_actor_id: None,
            intended_realm_id: realm_id(),
            mls_group_id: mls_group_id_for_realm(&realm_id()).unwrap(),
            claim_purpose: arkret_models_crypto::PeerKeyPackageClaimPurpose::RealmMembership,
            required_capabilities: vec![arkret_wire::NonEmptyString::new("ak.content.v1").unwrap()],
            expires_at: at(30),
            target_device_ids: vec![device_id()],
            target_keypackage_ref: None,
            target_agent_id: None,
            target_agent_verification_method: None,
            target_agent_key_authorize_event_id: None,
            timeout_ms: None,
            strand_id: None,
            pair_key: None,
            last_resort_allowed: None,
        };
        KeyPackagesClaimOutcome {
            claim_request_id: claim_request_id.clone(),
            claim_receipt: arkret_models_crypto::PeerKeyPackageClaimReceipt {
                claim_request_id,
                request_digest: arkret_wire::Hash::new(format!("sha256:{}", "1".repeat(64)))
                    .unwrap(),
                claims_digest: arkret_wire::Hash::new(
                    arkret_canonical::canonical_sha256(&claims).unwrap(),
                )
                .unwrap(),
                source_id: DidCoreId::new("ak:did_core:web:governance.example").unwrap(),
                destination_id: station(),
                claim_authority_ref: None,
                request,
                claimed_at: at(10),
                expires_at: at(30),
                signature: arkret_models_crypto::KeyOperationSignature {
                    kid: arkret_wire::NonEmptyString::new(
                        "did:web:recipient-station.example#service",
                    )
                    .unwrap(),
                    signature_algorithm: None,
                    sig: Base64UrlString::new("AA").unwrap(),
                },
            },
            claims,
        }
    }

    fn recipient_welcome(commit: &Event) -> MlsWelcomeDelivery {
        MlsWelcomeDelivery {
            commit_event_ref: commit.event_id.clone(),
            recipient_actor_id: recipient(),
            ..welcome("0")
        }
    }

    fn recipient_endpoint() -> LocalMlsEndpoint {
        LocalMlsEndpoint::device(realm_id(), recipient(), device_id())
    }

    /// device-lifecycle.md §9.2.4: the claim read back from the recipient's
    /// own Station binds this endpoint, its current authorization, the
    /// KeyPackage, the committer, Realm and group, and the Commit's inline
    /// Add of exactly that KeyPackage.
    #[test]
    fn a_welcome_claim_read_from_the_own_station_is_verified_before_decrypting() {
        let commit = accepted_commit(KEYPACKAGE);
        let welcome = recipient_welcome(&commit);
        let record = verify_welcome_claim(
            &welcome,
            &recipient_endpoint(),
            &commit,
            &outcome(vec![claim_record()]),
            &station(),
            &authorization(),
        )
        .unwrap();
        assert_eq!(record.claim_id, welcome.keypackage_claim_ref.as_str());
        assert_eq!(record.keypackage_ref, claim_record().keypackage_ref);
    }

    /// A tampered claim record no longer matches the destination-signed
    /// `claims_digest`, and a receipt from another Station or naming another
    /// committer is refused.
    #[test]
    fn a_tampered_claim_receipt_refuses_the_welcome() {
        let commit = accepted_commit(KEYPACKAGE);
        let welcome = recipient_welcome(&commit);
        let verify = |outcome: &KeyPackagesClaimOutcome| {
            verify_welcome_claim(
                &welcome,
                &recipient_endpoint(),
                &commit,
                outcome,
                &station(),
                &authorization(),
            )
        };
        let mut tampered = outcome(vec![claim_record()]);
        tampered.claims[0].expires_at = at(50);
        let error = verify(&tampered).unwrap_err();
        assert!(
            error.to_string().contains("claim outcome is invalid"),
            "{error}"
        );
        let mut elsewhere = outcome(vec![claim_record()]);
        elsewhere.claim_receipt.destination_id =
            DidCoreId::new("ak:did_core:web:other-station.example").unwrap();
        assert!(verify(&elsewhere).is_err());
        let mut requester = outcome(vec![claim_record()]);
        requester.claim_receipt.request.requester_account_id = Some(arkret_wire::AccountId::new(
            DidCoreId::new("ak:did_core:web:mallory.example").unwrap(),
            DidCoreId::new("ak:did_core:web:governance.example").unwrap(),
        ));
        assert!(verify(&requester).is_err());
        assert!(
            verify_welcome_claim(
                &welcome,
                &recipient_endpoint(),
                &commit,
                &outcome(vec![claim_record()]),
                &station(),
                &EventId::from_digest(DigestSuite::Sha256, [9; 32]),
            )
            .is_err(),
            "a replaced device authorization is not the claimed endpoint's"
        );
    }

    /// A claim whose KeyPackage is not the one the accepted Commit adds is
    /// refused before the Welcome is decrypted.
    #[test]
    fn a_claim_the_commit_does_not_add_refuses_the_welcome() {
        let commit = accepted_commit(b"another KeyPackage entirely");
        let welcome = recipient_welcome(&commit);
        let error = verify_welcome_claim(
            &welcome,
            &recipient_endpoint(),
            &commit,
            &outcome(vec![claim_record()]),
            &station(),
            &authorization(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("does not add"), "{error}");
    }

    fn realm_actor(label: &str) -> ActorId {
        ActorId::realm(arkret_wire::RealmActorId {
            realm_id: realm_id(),
            principal_id: DidCoreId::new(format!("ak:did_core:webvh:z{label}")).unwrap(),
        })
    }

    #[test]
    fn realm_committer_is_bound_as_a_full_actor_for_an_ordinary_recipient() {
        let mut commit = accepted_commit(KEYPACKAGE);
        commit.actor_id = realm_actor("Committer");
        let welcome = recipient_welcome(&commit);
        let mut claims = outcome(vec![claim_record()]);
        claims.claim_receipt.request.requester_account_id = None;
        claims.claim_receipt.request.requester_actor_id = Some(commit.actor_id.clone());
        verify_welcome_claim(
            &welcome,
            &recipient_endpoint(),
            &commit,
            &claims,
            &station(),
            &authorization(),
        )
        .unwrap();
        let mut wrong = claims.clone();
        wrong.claim_receipt.request.requester_actor_id = Some(realm_actor("Other"));
        assert!(
            verify_welcome_claim(
                &welcome,
                &recipient_endpoint(),
                &commit,
                &wrong,
                &station(),
                &authorization()
            )
            .is_err()
        );
        let mut mixed = claims.clone();
        mixed.claim_receipt.request.requester_account_id = Some(committer());
        assert!(
            verify_welcome_claim(
                &welcome,
                &recipient_endpoint(),
                &commit,
                &mixed,
                &station(),
                &authorization()
            )
            .is_err()
        );
        let mut wrong_realm = claims;
        wrong_realm.claim_receipt.request.requester_actor_id =
            Some(ActorId::realm(arkret_wire::RealmActorId {
                realm_id: RealmId::from_event_id(&EventId::from_digest(
                    DigestSuite::Sha256,
                    [44; 32],
                )),
                principal_id: commit.actor_id.signing_principal_id().clone(),
            }));
        assert!(
            verify_welcome_claim(
                &welcome,
                &recipient_endpoint(),
                &commit,
                &wrong_realm,
                &station(),
                &authorization()
            )
            .is_err()
        );
    }

    #[test]
    fn realm_recipient_requires_verified_governance_and_preserves_original_claim_destination() {
        let commit = accepted_commit(KEYPACKAGE);
        let actor = realm_actor("Recipient");
        let mut welcome = recipient_welcome(&commit);
        welcome.recipient_actor_id = actor.clone();
        let mut record = claim_record();
        record.actor_id = actor.clone();
        record.principal_id = actor.signing_principal_id().clone();
        let mut claims = outcome(vec![record]);
        claims.claim_receipt.request.target_account_id = None;
        claims.claim_receipt.request.target_actor_id = Some(actor.clone());
        claims.claim_receipt.claim_authority_ref = Some(
            arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(authorization()),
        );
        let endpoint = LocalMlsEndpoint::device(realm_id(), actor.clone(), device_id());
        assert!(
            verify_welcome_claim(
                &welcome,
                &endpoint,
                &commit,
                &claims,
                &station(),
                &authorization()
            )
            .is_err()
        );
        let recipient = RecipientMlsDurableSigner::RealmDevice {
            recipient_actor_id: actor.clone(),
            recipient_device_id: device_id(),
            device_verification_method: DidUrl::new("did:webvh:zRecipient:host.example#device")
                .unwrap(),
        };
        let inputs = std::cell::RefCell::new(Vec::new());
        let command = signed_welcome_consume(
            &welcome,
            &claims,
            recipient.clone(),
            &station(),
            1,
            at(20),
            signer(&inputs),
        )
        .unwrap();
        assert_eq!(
            command.recipient_durable_receipt.recipient_id,
            claims.claim_receipt.destination_id
        );
        let successor = DidCoreId::new("ak:did_core:web:successor.example").unwrap();
        assert!(
            signed_welcome_consume(
                &welcome,
                &claims,
                recipient,
                &successor,
                1,
                at(20),
                signer(&inputs)
            )
            .is_err()
        );
        assert!(
            signed_welcome_consume(
                &welcome,
                &claims,
                device_signer(),
                &station(),
                1,
                at(20),
                signer(&inputs)
            )
            .is_err()
        );
    }

    #[test]
    fn consume_rejects_another_device_before_signing() {
        let commit = accepted_commit(KEYPACKAGE);
        let welcome = recipient_welcome(&commit);
        let mut recipient = device_signer();
        if let RecipientMlsDurableSigner::Device {
            recipient_device_id,
            ..
        } = &mut recipient
        {
            *recipient_device_id =
                DeviceId::new("ak:device:0196419b-0000-7000-8000-000000000099").unwrap();
        }
        let inputs = std::cell::RefCell::new(Vec::new());
        assert!(
            signed_welcome_consume(
                &welcome,
                &outcome(vec![claim_record()]),
                recipient,
                &station(),
                1,
                at(20),
                signer(&inputs)
            )
            .is_err()
        );
        assert!(inputs.into_inner().is_empty());
    }

    fn verified_governance() -> (
        arkret_identity::VerifiedRealmAuthority,
        arkret_wire::EventId,
    ) {
        use arkret_wire::{
            CommitStreamHead, DetachedSignatureContext, RealmAuthorityBundle,
            RealmAuthorityCurrentAssertion, RealmCommitAuthorityRef,
        };
        let now = chrono::Utc::now();
        let route = crate::service_route_material::test_fixture::current_web_route_fixture(
            "recipient-station.example",
            "station",
            81,
        );
        let method = DidUrl::new("did:web:recipient-station.example#signing-1").unwrap();
        let genesis = arkret_wire::test_support::raw_event_at(EventKind::RealmCreate.as_str(), ScopeRef::RealmGenesis,
            committer().principal_id, station(), serde_json::json!({"object":{"purpose":"collaboration","governance_station_id":station()}}),at(0)).unwrap();
        let realm = genesis.realm_id.clone();
        let commit = arkret_test_kit::authority_objects::signed_commit(
            &method,
            &route.signing_key,
            &genesis,
            0,
            None,
            genesis.event_id.clone(),
            None,
        )
        .unwrap();
        let head = CommitStreamHead {
            stream_ref: commit.stream_ref.clone(),
            stream_position: 0,
            commit_id: commit.commit_id.clone(),
        };
        let nonce = Base64UrlString::new("BBBBBBBBBBBBBBBBBBBBBB").unwrap();
        let mut assertion = RealmAuthorityCurrentAssertion {
            realm_id: realm.clone(),
            current_generation: 0,
            current_service_id: station(),
            last_handoff_ref: None,
            realm_stream_head: head.clone(),
            nonce: nonce.clone(),
            expires_at: now + chrono::Duration::minutes(1),
            signature: detached_signature(DetachedSignatureContext::RealmAuthorityCurrentAssertion),
        };
        assertion.signature = arkret_signatures::detached_object::sign_detached_object(
            &arkret_canonical::unsigned_value(&assertion, &["signature"]).unwrap(),
            DetachedSignatureContext::RealmAuthorityCurrentAssertion,
            method.clone(),
            now,
            &route.signing_key,
        )
        .unwrap();
        let bundle = RealmAuthorityBundle {
            realm_id: realm,
            genesis_event: genesis.clone(),
            genesis_commit: commit,
            authority_transitions: vec![],
            current_generation: 0,
            current_service_id: station(),
            current_route_record: serde_json::to_value(route.resolution).unwrap(),
            realm_stream_head: head,
            bundle_issued_at: now,
            current_assertion: assertion,
        };
        let keys = arkret_identity::RealmAuthorityKeyMap::new().with_key(
            &method,
            arkret_signatures::PublicKeyMaterial::Ed25519Raw {
                bytes: route.signing_key.verifying_key().as_bytes().to_vec(),
            },
        );
        let authority = arkret_identity::verify_realm_authority_bundle(
            &bundle,
            &arkret_identity::RealmAuthorityFreshness::new(now, nonce),
            &keys,
        )
        .unwrap();
        assert!(authority.binds_current_authority(
            0,
            &RealmCommitAuthorityRef::GenesisOrChangeEvent(genesis.event_id.clone())
        ));
        (authority, genesis.event_id)
    }

    #[test]
    fn realm_recipient_binds_claim_to_verified_governance_and_exact_tenure() {
        let (authority, genesis) = verified_governance();
        let realm = authority.realm_id().clone();
        let actor = ActorId::realm(arkret_wire::RealmActorId {
            realm_id: realm.clone(),
            principal_id: realm_actor("Recipient").signing_principal_id().clone(),
        });
        let commit = accepted_commit_in(realm.clone(), KEYPACKAGE);
        let mut welcome = recipient_welcome(&commit);
        welcome.realm_id = realm.clone();
        welcome.effective_scope = commit.scope_ref.clone();
        welcome.recipient_actor_id = actor.clone();
        let mut record = claim_record();
        record.actor_id = actor.clone();
        record.principal_id = actor.signing_principal_id().clone();
        let mut claims = outcome(vec![record]);
        claims.claim_receipt.request.target_account_id = None;
        claims.claim_receipt.request.target_actor_id = Some(actor.clone());
        claims.claim_receipt.request.intended_realm_id = realm.clone();
        claims.claim_receipt.request.mls_group_id = mls_group_id_for_realm(&realm).unwrap();
        claims.claim_receipt.claim_authority_ref = Some(
            arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(genesis),
        );
        let endpoint = LocalMlsEndpoint::device(realm, actor, device_id());
        let current = station();
        let verify = |claims: &KeyPackagesClaimOutcome, current_station: &DidCoreId| {
            verify_welcome_claim(
                &welcome,
                &endpoint,
                &commit,
                claims,
                WelcomeClaimAuthority::Realm {
                    current_station,
                    authority: &authority,
                },
                &authorization(),
            )
        };
        verify(&claims, &current).unwrap();
        let mut wrong = claims.clone();
        wrong.claim_receipt.claim_authority_ref = Some(
            arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(authorization()),
        );
        assert!(verify(&wrong, &current).is_err());
        wrong = claims.clone();
        wrong.claim_receipt.claimed_at = at(0) - chrono::Duration::seconds(1);
        assert!(verify(&wrong, &current).is_err());
        assert!(
            verify(
                &claims,
                &DidCoreId::new("ak:did_core:web:wrong-route.example").unwrap()
            )
            .is_err()
        );
    }

    fn device_signer() -> RecipientMlsDurableSigner {
        RecipientMlsDurableSigner::Device {
            recipient_account_id: recipient().as_account_id().cloned().unwrap(),
            recipient_device_id: device_id(),
            device_verification_method: DidUrl::new("did:web:bob.example#device").unwrap(),
        }
    }

    /// Signs with one fixed Ed25519 key and records every signed input.
    fn signer(
        inputs: &std::cell::RefCell<Vec<Vec<u8>>>,
    ) -> impl Fn(&str, &[u8]) -> Result<KeyOperationSignature> + '_ {
        use ed25519_dalek::Signer as _;
        let key = ed25519_dalek::SigningKey::from_bytes(&[42; 32]);
        move |method, input| {
            inputs.borrow_mut().push(input.to_vec());
            Ok(KeyOperationSignature {
                kid: NonEmptyString::new(method.to_owned()).unwrap(),
                signature_algorithm: Some(NonEmptyString::new("Ed25519").unwrap()),
                sig: Base64UrlString::new(arkret_canonical::base64url_encode(
                    key.sign(input).to_bytes(),
                ))
                .unwrap(),
            })
        }
    }

    /// decision 0121: the consume command's durable receipt names the claim
    /// the Welcome was verified against, this Station, the scope's group, the
    /// joined epoch and the delivery's durable receipt digest, and both the
    /// receipt and the command carry the endpoint signature over their exact
    /// signing inputs.
    #[test]
    fn the_welcome_consume_command_binds_the_durable_join() {
        let commit = accepted_commit(KEYPACKAGE);
        let welcome = recipient_welcome(&commit);
        let claims = outcome(vec![claim_record()]);
        let inputs = std::cell::RefCell::new(Vec::new());
        let request = signed_welcome_consume(
            &welcome,
            &claims,
            device_signer(),
            &station(),
            1,
            at(20),
            signer(&inputs),
        )
        .unwrap();
        let receipt = &request.recipient_durable_receipt;
        assert_eq!(request.claim_id, welcome.keypackage_claim_ref);
        assert_eq!(receipt.claim_request_id, claims.claim_request_id);
        assert_eq!(
            receipt.key_package_ref.as_str(),
            claim_record().keypackage_ref
        );
        assert_eq!(receipt.recipient_id, station());
        assert_eq!(receipt.realm_id, realm_id());
        assert_eq!(
            receipt.mls_group_id,
            mls_group_id_for_scope(&welcome.effective_scope).unwrap()
        );
        assert_eq!(receipt.mls_epoch, 1);
        assert_eq!(receipt.welcome_ref, welcome.welcome_id);
        assert_eq!(
            receipt.welcome_digest,
            welcome.durable_receipt_digest().unwrap()
        );
        let inputs = inputs.into_inner();
        assert_eq!(
            inputs,
            vec![
                receipt.canonical_signing_bytes().unwrap(),
                keypackages_consume_signing_input(&request.unsigned()).unwrap(),
            ]
        );
        let key = ed25519_dalek::SigningKey::from_bytes(&[42; 32]).verifying_key();
        for (input, signature) in inputs.iter().zip([&receipt.signature, &request.signature]) {
            let bytes = arkret_canonical::base64url_decode(signature.sig.as_str()).unwrap();
            let signature = ed25519_dalek::Signature::from_slice(&bytes).unwrap();
            assert!(key.verify_strict(input, &signature).is_ok());
        }
    }

    /// A Welcome whose claim the outcome does not hold never yields a consume command.
    #[test]
    fn a_welcome_consume_needs_its_claim_and_an_endpoint_key() {
        let commit = accepted_commit(KEYPACKAGE);
        let welcome = recipient_welcome(&commit);
        let inputs = std::cell::RefCell::new(Vec::new());
        assert!(
            signed_welcome_consume(
                &welcome,
                &outcome(Vec::new()),
                device_signer(),
                &station(),
                1,
                at(20),
                signer(&inputs),
            )
            .is_err()
        );
        assert!(inputs.into_inner().is_empty());
    }

    #[test]
    fn a_scope_determines_its_own_canonical_group_id() {
        let realm_group = mls_group_id_for_realm(&realm_id()).unwrap();
        assert!(!realm_group.is_empty());
        assert_eq!(
            realm_group,
            mls_group_id_for_scope(&ScopeRef::Realm {
                realm_id: realm_id()
            })
            .unwrap()
        );
    }
}
