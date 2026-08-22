use std::collections::BTreeSet;

use arkret_canonical::canonical::{canonical_json_bytes, canonical_sha256};
use arkret_models_collaboration::history_key::{
    EventCandidateBinding, EventCandidateBindingKey, EventCandidateBindingOutcome,
    HistoryCandidateMaterialKey, HistoryCandidateMaterialRecord, HistoryCandidateOriginAttribution,
};
use arkret_wire::{Hash, HistoryEffectiveScope};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::store::{SecretClass, SecretDurability, SecureKeyStore};
use crate::{Error, PutSecretOptions, Result};

pub const MAX_RESIDENT_HISTORY_CANDIDATES_PER_EPOCH: usize = 8;
pub const MAX_HISTORY_ORIGINS_PER_MATERIAL: usize = 4;
pub const MAX_HISTORY_ORIGINS_PER_QUOTA_DOMAIN: usize = 64;
pub const MAX_HISTORY_ORIGINS_PER_EPOCH: usize = 256;
pub const MAX_HISTORY_EVENT_BINDINGS_PER_EPOCH: usize = 256;
pub const HISTORY_CANDIDATE_ATTRIBUTION_LIFETIME_SECONDS: i64 = 2_592_000;

const HISTORY_CANDIDATE_SECRET_PREFIX: &str = "arkret/history-candidate/v1/";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryCandidateMaterialIndex {
    pub material_key: HistoryCandidateMaterialKey,
    pub material_received_sequence: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryCandidateStoreSnapshot {
    pub next_material_received_sequence: u64,
    pub materials: Vec<HistoryCandidateMaterialIndex>,
    pub origins: Vec<HistoryCandidateOriginAttribution>,
    pub event_bindings: Vec<EventCandidateBinding>,
}

pub trait HistoryCandidateStateStore {
    fn load_history_candidate_state(&self) -> Result<HistoryCandidateStoreSnapshot>;

    fn save_history_candidate_state(
        &mut self,
        snapshot: &HistoryCandidateStoreSnapshot,
    ) -> Result<()>;
}

#[derive(Clone, Debug, Default)]
pub struct MemoryHistoryCandidateStateStore {
    snapshot: HistoryCandidateStoreSnapshot,
}

impl MemoryHistoryCandidateStateStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl HistoryCandidateStateStore for MemoryHistoryCandidateStateStore {
    fn load_history_candidate_state(&self) -> Result<HistoryCandidateStoreSnapshot> {
        Ok(self.snapshot.clone())
    }

    fn save_history_candidate_state(
        &mut self,
        snapshot: &HistoryCandidateStoreSnapshot,
    ) -> Result<()> {
        self.snapshot = snapshot.clone();
        Ok(())
    }
}

pub struct HistoryCandidateEngine<S> {
    store: S,
}

impl<S> HistoryCandidateEngine<S>
where
    S: HistoryCandidateStateStore,
{
    pub fn new(store: S) -> Self {
        Self { store }
    }

    pub fn store(&self) -> &S {
        &self.store
    }

    pub fn store_mut(&mut self) -> &mut S {
        &mut self.store
    }

    pub fn into_store(self) -> S {
        self.store
    }

    pub fn event_binding(
        &self,
        event_binding_key: &EventCandidateBindingKey,
        candidate_digest: &Hash,
    ) -> Result<Option<EventCandidateBinding>> {
        Ok(self
            .store
            .load_history_candidate_state()?
            .event_bindings
            .into_iter()
            .find(|binding| {
                &binding.event_binding_key == event_binding_key
                    && &binding.candidate_digest == candidate_digest
            }))
    }

    pub async fn receive_external_candidate(
        &mut self,
        secure_store: &dyn SecureKeyStore,
        material_key: HistoryCandidateMaterialKey,
        secret: &[u8],
        attribution: HistoryCandidateOriginAttribution,
        now: DateTime<Utc>,
    ) -> Result<bool> {
        material_key.validate()?;
        attribution.validate()?;
        if origin_parts(&attribution)?.0 != &material_key {
            return Err(Error::Protocol(
                "history candidate attribution material key does not match".to_owned(),
            ));
        }
        if origin_parts(&attribution)?.4 <= now {
            return Err(Error::Protocol(
                "history candidate attribution is expired".to_owned(),
            ));
        }
        let actual_digest = Hash::new(arkret_wire::canonical::sha256_digest(secret))?;
        if actual_digest != material_key.candidate_digest {
            return Err(Error::Protocol(
                "history candidate digest does not match exact secret bytes".to_owned(),
            ));
        }

        let mut snapshot = self.store.load_history_candidate_state()?;
        prune_and_bound_origins(&mut snapshot.origins, &attribution, now)?;
        let already_resident = snapshot
            .materials
            .iter()
            .any(|metadata| metadata.material_key == material_key);
        let origin_retained = snapshot
            .origins
            .iter()
            .any(|origin| same_origin_identity(origin, &attribution).unwrap_or(false));
        if !already_resident && !origin_retained {
            self.store.save_history_candidate_state(&snapshot)?;
            return Ok(false);
        }

        let secret_key = history_candidate_secret_key(&material_key)?;
        if already_resident {
            let stored = secure_store.get_secret_bytes(&secret_key)?.ok_or_else(|| {
                Error::Protocol("resident history candidate bytes are missing".to_owned())
            })?;
            if stored.as_slice() != secret {
                return Err(Error::Protocol(
                    "history candidate digest collision or secure-store mismatch".to_owned(),
                ));
            }
        } else {
            let sequence = snapshot.next_material_received_sequence;
            snapshot.next_material_received_sequence =
                sequence.checked_add(1).ok_or_else(|| {
                    Error::Protocol("history candidate sequence exhausted".to_owned())
                })?;
            secure_store
                .put_secret(
                    &secret_key,
                    secret,
                    PutSecretOptions {
                        durability: SecretDurability::DurableBeforeReturn,
                        class: SecretClass::MlsSecret,
                    },
                )
                .await?;
            snapshot.materials.push(HistoryCandidateMaterialIndex {
                material_key: material_key.clone(),
                material_received_sequence: sequence,
            });
        }

        let evicted = select_material_eviction(&snapshot, &material_key)?;
        if let Some(victim) = &evicted {
            snapshot
                .materials
                .retain(|metadata| metadata.material_key != victim.material_key);
        }
        self.store.save_history_candidate_state(&snapshot)?;
        if let Some(victim) = evicted {
            secure_store.delete_secret(&history_candidate_secret_key(&victim.material_key)?)?;
        }
        Ok(snapshot
            .materials
            .iter()
            .any(|metadata| metadata.material_key == material_key))
    }

    pub fn record_event_binding(
        &mut self,
        binding: EventCandidateBinding,
        now: DateTime<Utc>,
    ) -> Result<()> {
        validate_binding(&binding)?;
        let mut snapshot = self.store.load_history_candidate_state()?;
        snapshot
            .event_bindings
            .retain(|entry| entry.expires_at > now);
        if let Some(existing) = snapshot.event_bindings.iter().find(|entry| {
            entry.event_binding_key == binding.event_binding_key
                && entry.candidate_digest == binding.candidate_digest
        }) {
            if existing != &binding {
                return Err(Error::IdempotencyConflict(format!(
                    "history-event-candidate:{}:{}",
                    binding.event_binding_key.event_id, binding.candidate_digest
                )));
            }
        } else {
            snapshot.event_bindings.push(binding.clone());
        }
        retain_canonical_bindings(
            &mut snapshot.event_bindings,
            |entry| same_binding_epoch(entry, &binding),
            MAX_HISTORY_EVENT_BINDINGS_PER_EPOCH,
        )?;
        self.store.save_history_candidate_state(&snapshot)
    }

    pub fn candidates_for_epoch(
        &self,
        secure_store: &dyn SecureKeyStore,
        effective_scope: &HistoryEffectiveScope,
        mls_group_id: &str,
        epoch: u64,
    ) -> Result<Vec<HistoryCandidateMaterialRecord>> {
        let mut metadata = self
            .store
            .load_history_candidate_state()?
            .materials
            .into_iter()
            .filter(|entry| {
                same_scope_group_epoch(&entry.material_key, effective_scope, mls_group_id, epoch)
            })
            .collect::<Vec<_>>();
        metadata.sort_by(|left, right| {
            left.material_received_sequence
                .cmp(&right.material_received_sequence)
                .then_with(|| {
                    canonical_json_bytes(&left.material_key.candidate_digest)
                        .expect("validated candidate digest canonicalizes")
                        .cmp(
                            &canonical_json_bytes(&right.material_key.candidate_digest)
                                .expect("validated candidate digest canonicalizes"),
                        )
                })
        });
        metadata
            .into_iter()
            .map(|metadata| {
                let secret = secure_store
                    .get_secret_bytes(&history_candidate_secret_key(&metadata.material_key)?)?
                    .ok_or_else(|| {
                        Error::Protocol("resident history candidate bytes are missing".to_owned())
                    })?;
                let actual_digest =
                    Hash::new(arkret_wire::canonical::sha256_digest(secret.as_slice()))?;
                if actual_digest != metadata.material_key.candidate_digest {
                    return Err(Error::Protocol(
                        "resident history candidate digest does not match exact secret bytes"
                            .to_owned(),
                    ));
                }
                let record = HistoryCandidateMaterialRecord {
                    material_key: metadata.material_key,
                    secret_b64u: arkret_wire::base64url::base64url_encode(secret.as_slice()),
                    material_received_sequence: metadata.material_received_sequence,
                };
                record.validate()?;
                Ok(record)
            })
            .collect()
    }
}

fn history_candidate_secret_key(material_key: &HistoryCandidateMaterialKey) -> Result<String> {
    material_key.validate()?;
    Ok(format!(
        "{HISTORY_CANDIDATE_SECRET_PREFIX}{}",
        canonical_sha256(material_key)?
    ))
}

fn same_scope_group_epoch(
    material_key: &HistoryCandidateMaterialKey,
    effective_scope: &HistoryEffectiveScope,
    mls_group_id: &str,
    epoch: u64,
) -> bool {
    material_key.effective_scope == *effective_scope
        && material_key.mls_group_id == mls_group_id
        && material_key.epoch == epoch
}

type OriginParts<'a> = (
    &'a HistoryCandidateMaterialKey,
    &'static str,
    Vec<u8>,
    Vec<u8>,
    DateTime<Utc>,
);

fn origin_parts(origin: &HistoryCandidateOriginAttribution) -> Result<OriginParts<'_>> {
    match origin {
        HistoryCandidateOriginAttribution::ResponseSender {
            material_key,
            origin_quota_domain,
            origin_ref,
            expires_at,
            ..
        } => Ok((
            material_key,
            "response_sender",
            canonical_json_bytes(origin_quota_domain)?,
            canonical_json_bytes(origin_ref)?,
            *expires_at,
        )),
        HistoryCandidateOriginAttribution::RrkArchive {
            material_key,
            origin_quota_domain,
            origin_ref,
            expires_at,
            ..
        } => Ok((
            material_key,
            "rrk_archive",
            canonical_json_bytes(origin_quota_domain)?,
            canonical_json_bytes(origin_ref)?,
            *expires_at,
        )),
        HistoryCandidateOriginAttribution::PortableBackup {
            material_key,
            origin_quota_domain,
            origin_ref,
            expires_at,
            ..
        } => Ok((
            material_key,
            "portable_backup",
            canonical_json_bytes(origin_quota_domain)?,
            canonical_json_bytes(origin_ref)?,
            *expires_at,
        )),
    }
}

fn same_origin_identity(
    left: &HistoryCandidateOriginAttribution,
    right: &HistoryCandidateOriginAttribution,
) -> Result<bool> {
    let (left_key, left_domain, left_quota, left_ref, _) = origin_parts(left)?;
    let (right_key, right_domain, right_quota, right_ref, _) = origin_parts(right)?;
    Ok(left_key == right_key
        && left_domain == right_domain
        && left_quota == right_quota
        && left_ref == right_ref)
}

fn same_origin_quota_domain(
    left: &HistoryCandidateOriginAttribution,
    right: &HistoryCandidateOriginAttribution,
) -> Result<bool> {
    let (left_key, left_domain, left_quota, ..) = origin_parts(left)?;
    let (right_key, right_domain, right_quota, ..) = origin_parts(right)?;
    Ok(left_key.effective_scope == right_key.effective_scope
        && left_key.mls_group_id == right_key.mls_group_id
        && left_key.epoch == right_key.epoch
        && left_domain == right_domain
        && left_quota == right_quota)
}

fn canonical_origin_sort_key(origin: &HistoryCandidateOriginAttribution) -> Result<Vec<u8>> {
    let (material_key, domain, quota_domain, origin_ref, expires_at) = origin_parts(origin)?;
    canonical_json_bytes(&serde_json::json!([
        expires_at,
        material_key.candidate_digest,
        domain,
        serde_json::from_slice::<serde_json::Value>(&quota_domain)?,
        serde_json::from_slice::<serde_json::Value>(&origin_ref)?,
    ]))
    .map_err(Into::into)
}

fn retain_canonical_origins(
    origins: &mut Vec<HistoryCandidateOriginAttribution>,
    mut belongs_to_set: impl FnMut(&HistoryCandidateOriginAttribution) -> Result<bool>,
    maximum: usize,
) -> Result<()> {
    let mut members = origins
        .iter()
        .enumerate()
        .filter_map(|(index, origin)| match belongs_to_set(origin) {
            Ok(true) => Some(canonical_origin_sort_key(origin).map(|key| (key, index))),
            Ok(false) => None,
            Err(error) => Some(Err(error)),
        })
        .collect::<Result<Vec<_>>>()?;
    if members.len() <= maximum {
        return Ok(());
    }
    members.sort_by(|left, right| left.0.cmp(&right.0));
    let rejected = members
        .into_iter()
        .skip(maximum)
        .map(|(_, index)| index)
        .collect::<BTreeSet<_>>();
    let mut index = 0usize;
    origins.retain(|_| {
        let keep = !rejected.contains(&index);
        index += 1;
        keep
    });
    Ok(())
}

fn prune_and_bound_origins(
    origins: &mut Vec<HistoryCandidateOriginAttribution>,
    inserted: &HistoryCandidateOriginAttribution,
    now: DateTime<Utc>,
) -> Result<()> {
    origins.retain(|origin| origin_parts(origin).is_ok_and(|parts| parts.4 > now));
    if !origins
        .iter()
        .any(|origin| same_origin_identity(origin, inserted).unwrap_or(false))
    {
        origins.push(inserted.clone());
    }
    let material_key = origin_parts(inserted)?.0.clone();
    retain_canonical_origins(
        origins,
        |origin| Ok(origin_parts(origin)?.0 == &material_key),
        MAX_HISTORY_ORIGINS_PER_MATERIAL,
    )?;
    retain_canonical_origins(
        origins,
        |origin| same_origin_quota_domain(origin, inserted),
        MAX_HISTORY_ORIGINS_PER_QUOTA_DOMAIN,
    )?;
    retain_canonical_origins(
        origins,
        |origin| {
            let key = origin_parts(origin)?.0;
            Ok(same_scope_group_epoch(
                key,
                &material_key.effective_scope,
                &material_key.mls_group_id,
                material_key.epoch,
            ))
        },
        MAX_HISTORY_ORIGINS_PER_EPOCH,
    )
}

fn validate_binding(binding: &EventCandidateBinding) -> Result<()> {
    HistoryCandidateMaterialKey {
        effective_scope: binding.event_binding_key.effective_scope.clone(),
        mls_group_id: binding.event_binding_key.mls_group_id.clone(),
        epoch: binding.event_binding_key.epoch,
        candidate_digest: binding.candidate_digest.clone(),
    }
    .validate()?;
    if binding
        .event_binding_key
        .verified_sender_domain
        .trim()
        .is_empty()
    {
        return Err(Error::Protocol(
            "history candidate binding sender domain is empty".to_owned(),
        ));
    }
    if binding
        .expires_at
        .signed_duration_since(binding.first_observed_at)
        != Duration::seconds(HISTORY_CANDIDATE_ATTRIBUTION_LIFETIME_SECONDS)
    {
        return Err(Error::Protocol(
            "history candidate binding expiry must equal first_observed_at plus 2592000 seconds"
                .to_owned(),
        ));
    }
    Ok(())
}

fn same_binding_epoch(left: &EventCandidateBinding, right: &EventCandidateBinding) -> bool {
    left.event_binding_key.effective_scope == right.event_binding_key.effective_scope
        && left.event_binding_key.mls_group_id == right.event_binding_key.mls_group_id
        && left.event_binding_key.epoch == right.event_binding_key.epoch
}

fn binding_sort_key(binding: &EventCandidateBinding) -> Result<Vec<u8>> {
    canonical_json_bytes(&serde_json::json!([
        binding.expires_at,
        binding.event_binding_key.event_id,
        binding.event_binding_key.event_digest,
        binding.event_binding_key.verified_sender_domain,
        binding.candidate_digest,
        binding.outcome,
    ]))
    .map_err(Into::into)
}

fn retain_canonical_bindings(
    bindings: &mut Vec<EventCandidateBinding>,
    mut belongs_to_set: impl FnMut(&EventCandidateBinding) -> bool,
    maximum: usize,
) -> Result<()> {
    let mut members = bindings
        .iter()
        .enumerate()
        .filter(|(_, binding)| belongs_to_set(binding))
        .map(|(index, binding)| binding_sort_key(binding).map(|key| (key, index)))
        .collect::<Result<Vec<_>>>()?;
    if members.len() <= maximum {
        return Ok(());
    }
    members.sort_by(|left, right| left.0.cmp(&right.0));
    let rejected = members
        .into_iter()
        .skip(maximum)
        .map(|(_, index)| index)
        .collect::<BTreeSet<_>>();
    let mut index = 0usize;
    bindings.retain(|_| {
        let keep = !rejected.contains(&index);
        index += 1;
        keep
    });
    Ok(())
}

fn select_material_eviction(
    snapshot: &HistoryCandidateStoreSnapshot,
    inserted_key: &HistoryCandidateMaterialKey,
) -> Result<Option<HistoryCandidateMaterialIndex>> {
    let mut resident = snapshot
        .materials
        .iter()
        .filter(|metadata| {
            same_scope_group_epoch(
                &metadata.material_key,
                &inserted_key.effective_scope,
                &inserted_key.mls_group_id,
                inserted_key.epoch,
            )
        })
        .map(|metadata| {
            let success_bound = snapshot.event_bindings.iter().any(|binding| {
                binding.outcome == EventCandidateBindingOutcome::Success
                    && binding.candidate_digest == metadata.material_key.candidate_digest
                    && binding.event_binding_key.effective_scope
                        == metadata.material_key.effective_scope
                    && binding.event_binding_key.mls_group_id == metadata.material_key.mls_group_id
                    && binding.event_binding_key.epoch == metadata.material_key.epoch
            });
            Ok((
                success_bound,
                metadata.material_received_sequence,
                canonical_json_bytes(&metadata.material_key.candidate_digest)?,
                metadata.clone(),
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    if resident.len() <= MAX_RESIDENT_HISTORY_CANDIDATES_PER_EPOCH {
        return Ok(None);
    }
    resident.sort_by(|left, right| {
        left.0
            .cmp(&right.0)
            .then_with(|| left.1.cmp(&right.1))
            .then_with(|| left.2.cmp(&right.2))
    });
    Ok(resident.into_iter().next().map(|entry| entry.3))
}

#[cfg(test)]
mod tests {
    use super::*;
    use arkret_models_collaboration::history_key::{
        HistoryResponseId, ResponseSenderOriginRef, ResponseSenderQuotaDomain,
    };
    use arkret_wire::{EventId, HistoryEffectiveScope, RealmId};

    fn hash(byte: char) -> Hash {
        Hash::new(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
    }

    fn scope() -> HistoryEffectiveScope {
        HistoryEffectiveScope::Realm {
            realm_id: RealmId::new("ak:realm:AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
                .unwrap(),
        }
    }

    #[tokio::test]
    async fn candidate_store_is_event_local_and_does_not_promote_epoch_winner() {
        let secret_store = crate::MemorySecureKeyStore::new();
        let mut engine = HistoryCandidateEngine::new(MemoryHistoryCandidateStateStore::new());
        let now = Utc::now();
        let secret = [7_u8; 32];
        let digest = Hash::new(arkret_wire::canonical::sha256_digest(secret)).unwrap();
        let effective_scope = scope();
        let key = HistoryCandidateMaterialKey {
            mls_group_id: effective_scope.canonical_mls_group_id().unwrap(),
            effective_scope,
            epoch: 4,
            candidate_digest: digest.clone(),
        };
        let attribution = HistoryCandidateOriginAttribution::ResponseSender {
            material_key: key.clone(),
            origin_quota_domain: ResponseSenderQuotaDomain {
                source_sender_domain: "ak:device:sender".to_owned(),
            },
            origin_ref: ResponseSenderOriginRef {
                response_id: HistoryResponseId::new(
                    "ak:history_response:019a0000-0000-7000-8000-000000000001",
                )
                .unwrap(),
                source_record_digest: hash('1'),
            },
            first_observed_at: now,
            expires_at: now + Duration::seconds(HISTORY_CANDIDATE_ATTRIBUTION_LIFETIME_SECONDS),
        };
        assert!(
            engine
                .receive_external_candidate(&secret_store, key.clone(), &secret, attribution, now,)
                .await
                .unwrap()
        );
        let binding_key = EventCandidateBindingKey {
            effective_scope: key.effective_scope.clone(),
            mls_group_id: key.mls_group_id.clone(),
            epoch: key.epoch,
            event_id: EventId::new("ak:event:AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
                .unwrap(),
            event_digest: hash('2'),
            verified_sender_domain: "ak:device:sender".to_owned(),
        };
        engine
            .record_event_binding(
                EventCandidateBinding {
                    event_binding_key: binding_key.clone(),
                    candidate_digest: digest.clone(),
                    outcome: EventCandidateBindingOutcome::Failure,
                    first_observed_at: now,
                    expires_at: now
                        + Duration::seconds(HISTORY_CANDIDATE_ATTRIBUTION_LIFETIME_SECONDS),
                },
                now,
            )
            .unwrap();
        assert_eq!(
            engine
                .event_binding(&binding_key, &digest)
                .unwrap()
                .unwrap()
                .outcome,
            EventCandidateBindingOutcome::Failure
        );
        assert_eq!(
            engine
                .candidates_for_epoch(
                    &secret_store,
                    &key.effective_scope,
                    &key.mls_group_id,
                    key.epoch,
                )
                .unwrap()
                .len(),
            1
        );
    }
}
