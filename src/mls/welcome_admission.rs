//! Which MLS Welcome deliveries a local endpoint may admit.
//!
//! A Welcome is a producer-signed recipient delivery object, not an Event and
//! not a commit-stream item. It is admissible only when it names this exact
//! `(realm, actor, endpoint)`, binds the accepted Commit Event it accompanies,
//! and carries its dedicated producer signature context. All of that is
//! wire-shape verification with no host state behind it, so every client
//! answers it identically.

use arkret_wire::{
    ActorId, DeviceId, DidUrl, EventId, MlsWelcomeDelivery, MlsWelcomeRecipientEndpoint, RealmId,
    ScopeRef,
};

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
pub fn mls_group_id_for_scope(scope: &ScopeRef) -> Result<String> {
    scope.canonical_mls_group_id().map_err(Error::from)
}

/// The canonical MLS group id of a Realm's default scope.
pub fn mls_group_id_for_realm(realm_id: &RealmId) -> Result<String> {
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

#[cfg(test)]
mod tests {
    use arkret_canonical::DigestSuite;
    use arkret_wire::{
        Base64UrlString, DetachedSignatureContext, KeypackageClaimId, MlsWelcomeDeliveryId,
    };

    use super::*;
    use crate::test_fixtures::{actor_id, detached_signature, device_id, realm_id};

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
