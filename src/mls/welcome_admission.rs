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

/// The claim a Welcome names, verified before the Welcome is decrypted
/// (device-lifecycle.md §9 `claims/query` and §9.2.4, encryption-and-audit.md
/// §2.6.1).
///
/// `outcome` is the exact claim outcome this endpoint read from its own
/// Account Station through `ak.self.keys.keypackages.read.claim.v1`, whose
/// `claim_receipt` signature the caller has already verified under that
/// Station's service key. `accepted_commit` is the accepted `ak.mls.commit`
/// the Welcome names and `endpoint_authorization` the endpoint's current
/// `ak.device.authorize` (or `ak.agent.key.authorize`) Event. The recomputed
/// `claims_digest`, the destination, the claim record's endpoint, KeyPackage
/// digest and authority, the receipt's requester, target, Realm and group,
/// and the claimed KeyPackage being one inline Add of the Commit must all
/// hold, or the Welcome stays undecrypted.
pub fn verify_welcome_claim(
    welcome: &MlsWelcomeDelivery,
    endpoint: &LocalMlsEndpoint,
    accepted_commit: &Event,
    outcome: &KeyPackagesClaimOutcome,
    local_station: &DidCoreId,
    endpoint_authorization: &EventId,
) -> Result<KeyPackageClaimRecord> {
    let refused = |detail: &str| Error::Protocol(format!("MLS Welcome claim: {detail}"));
    admit_welcome(welcome, endpoint, &accepted_commit.event_id)?;
    outcome
        .validate_shape()
        .map_err(|error| refused(&format!("claim outcome is invalid: {error}")))?;
    let receipt = &outcome.claim_receipt;
    let recipient = welcome
        .recipient_actor_id
        .as_account_id()
        .ok_or_else(|| refused("the recipient is not an Account"))?;
    if &receipt.destination_id != local_station || &recipient.station_id != local_station {
        return Err(refused("the claim was not made at this endpoint's Station"));
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
    let target_matches = match (&request.target_account_id, &request.target_agent_id) {
        (Some(account), None) => account == recipient,
        (None, Some(agent_id)) => agent_id == &recipient.principal_id,
        _ => false,
    };
    if accepted_commit.kind != EventKind::MlsCommit
        || request.intended_realm_id != welcome.realm_id
        || request.mls_group_id != mls_group_id_for_scope(&welcome.effective_scope)?
        || request.requester_account_id.as_ref() != accepted_commit.actor_id.as_account_id()
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
    let method = match &recipient {
        RecipientMlsDurableSigner::Device {
            device_verification_method,
            ..
        } => device_verification_method,
        RecipientMlsDurableSigner::Agent {
            recipient_agent_verification_method,
            ..
        } => recipient_agent_verification_method,
        RecipientMlsDurableSigner::MinimalMetadataPairwise { .. } => {
            return Err(refused(
                "a pairwise endpoint never consumes a Welcome claim",
            ));
        }
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
        let binding = arkret_models_crypto::MlsGovernanceBindingPayload::realm(
            realm_id(),
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
            pairwise_verification_method: None,
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
            requester_account_id: Some(committer()),
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
            target_pairwise_verification_method: None,
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

    /// A Welcome whose claim the outcome does not hold, or a pairwise
    /// endpoint, never yields a consume command.
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
        assert!(
            signed_welcome_consume(
                &welcome,
                &outcome(vec![claim_record()]),
                RecipientMlsDurableSigner::MinimalMetadataPairwise {
                    recipient_pairwise_verification_method: DidUrl::new(
                        "did:web:bob.example#pairwise"
                    )
                    .unwrap(),
                },
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
