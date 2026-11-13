//! Immutable local intent and historical ACK records, never current capabilities.

use arkret_http_client::own_station_device_results::{
    BoundOwnStationDeviceResponse, OwnStationDeviceClient,
};
use arkret_models_crypto::RealmActorBackupPutResponseBody;

use super::*;

type PutAcknowledgement = BoundOwnStationDeviceResponse<KeyBackup, RealmActorBackupPutResponseBody>;
type UnlockedHead = BoundOwnStationDeviceResponse<
    arkret_models_crypto::RealmActorDeviceKeyBackupUnlockProof,
    arkret_models_crypto::RealmActorBackupUnlockResponseBody,
>;

/// Local authoring inputs, deliberately not a serializable protocol carrier.
/// The manager must have maintained the exact scope's series before this call.
pub struct NativeRootPublicationParameters<'a> {
    pub operation: &'a str,
    pub root: &'a ContentRootBackupEntry,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub author: arkret_crypto::backup::KeyBackupAuthBinding,
    pub domain_separation: arkret_models_crypto::KeyBackupDomainSeparation,
    pub authority: &'a arkret_identity::VerifiedRealmAuthority,
    pub station_resolution: &'a arkret_models_identity::AuthenticatedServiceResolution,
    pub authority_keys: &'a (dyn arkret_identity::RealmAuthorityKeyDirectory + Sync),
}

enum PublicationEvidence {
    Put(Box<PutAcknowledgement>),
    Head(Box<UnlockedHead>),
}

/// A live bound owning-Station result, never reconstructed from the journal.
/// Using the refs rechecks the original SDK context, including late retirement.
pub struct NativeRootPublicationOutcome {
    evidence: PublicationEvidence,
}

impl NativeRootPublicationOutcome {
    pub fn backup_refs(&self) -> Result<Vec<BackupId>> {
        let backup_id = match &self.evidence {
            PublicationEvidence::Put(response) => response.value()?.backup_id.clone(),
            PublicationEvidence::Head(response) => response.value()?.backup.backup_id.clone(),
        };
        Ok(vec![backup_id])
    }

    pub fn original_packet(&self) -> Result<&KeyBackup> {
        match &self.evidence {
            PublicationEvidence::Put(response) => {
                response.value()?;
                Ok(response.request())
            }
            PublicationEvidence::Head(response) => Ok(&response.value()?.backup),
        }
    }
}

fn check_native_publisher_context(
    client: &OwnStationDeviceClient,
    vault: &ContentRootVault<'_>,
    root: &ContentRootBackupEntry,
) -> Result<()> {
    let context = client.context()?;
    if context.actor_id() != vault.subject
        || context.effective_scope() != &root.root_context.effective_scope
        || !matches!(vault.endpoint, MlsWelcomeRecipientEndpoint::Device {device_id} if device_id == context.device_id())
    {
        return Err(rejected(
            "native publisher differs from its bound actor, Device or exact root scope",
        ));
    }
    Ok(())
}

fn request_nonce() -> Result<String> {
    let mut bytes = [0; 32];
    getrandom::fill(&mut bytes).map_err(rejected)?;
    Ok(arkret_canonical::base64url_encode(bytes))
}

/// Repair a previously frozen intent by sending its exact original bytes.
/// Credential/generation validity is rechecked by the bound transport/Station;
/// no new business, epoch, recipient or preparation cut is evaluated first.
pub async fn retry_native_root_publication(
    client: &OwnStationDeviceClient,
    vault: &ContentRootVault<'_>,
    operation: &str,
    root: &ContentRootBackupEntry,
) -> Result<Option<NativeRootPublicationHistory>> {
    check_native_publisher_context(client, vault, root)?;
    let packet = match vault.native_root_publication_state(operation, root).await? {
        NativeRootPublicationState::Unprepared => return Ok(None),
        NativeRootPublicationState::Frozen { packet } => *packet,
        NativeRootPublicationState::Recorded { history } => history.packet,
    };
    let acknowledgement = put_frozen_native_root(client, vault, operation, root, packet).await?;
    // Repair is intentionally history-only, even though the transport used a
    // fresh bound response. It does not select today's series for business.
    let PublicationEvidence::Put(response) = acknowledgement.evidence else {
        unreachable!("exact PUT repair cannot produce a head result")
    };
    Ok(Some(NativeRootPublicationHistory {
        packet: response.request().clone(),
        response: response.value()?.clone(),
    }))
}

/// Repair all original intents registered for a business operation. Roots and
/// packets are loaded from the durable vault; no new MLS or prepare cut is read.
/// The returned history cannot be used as a current publication capability.
pub async fn retry_frozen_native_root_publication(
    client: &OwnStationDeviceClient,
    vault: &ContentRootVault<'_>,
    operation: &str,
) -> Result<Vec<NativeRootPublicationHistory>> {
    let mut intents = vault.native_publication_intents(operation).await?;
    // Low-level callers may have frozen an explicit operation directly.
    if vault.frozen_backup(operation).await?.is_some() {
        intents.push(operation.to_owned());
    }
    let mut repaired = Vec::new();
    for intent in intents {
        let Some(packet) = vault.frozen_backup(&intent).await? else {
            // The index is durable before freezing, so a crash may leave an
            // entry without a packet. There was no network PUT for that entry.
            continue;
        };
        vault.native_requester_matches(&packet)?;
        let [item] = packet.contents.as_slice() else {
            return Err(rejected("native repair does not contain exactly one root"));
        };
        let reference = item
            .root_ref
            .as_ref()
            .ok_or_else(|| rejected("native repair has no root reference"))?;
        let root = vault
            .root(reference)
            .await?
            .ok_or_else(|| rejected("native repair lost its durable original root"))?;
        if let Some(history) = retry_native_root_publication(client, vault, &intent, &root).await? {
            repaired.push(history);
        }
    }
    Ok(repaired)
}

fn current_publication_intent(
    operation: &str,
    context: &arkret_http_client::own_station_device_results::OwnStationDeviceSnapshot,
    root: &ContentRootBackupEntry,
    input: &arkret_models_crypto::ContentBackupNextPrepareInput,
    head: &arkret_models_crypto::RealmActorBackupSeriesHeadResponseBody,
) -> Result<String> {
    if operation.is_empty() {
        return Err(rejected("native publication operation is empty"));
    }
    let cut = serde_json::json!({
        "operation":operation,"actor_id":context.actor_id(),
        "device_id":context.device_id(),"authorization_event_ref":context.authorization_event_id(),
        "root_context":root.root_context,"root_ref":root.root_ref,
        "next_prepare_input":input,"head":head,
    });
    Ok(arkret_canonical::canonical_sha256(&cut)?)
}

async fn put_frozen_native_root(
    client: &OwnStationDeviceClient,
    vault: &ContentRootVault<'_>,
    operation: &str,
    root: &ContentRootBackupEntry,
    packet: KeyBackup,
) -> Result<NativeRootPublicationOutcome> {
    let digest = arkret_canonical::canonical_sha256(&packet)?;
    let idempotency = format!("arkret-key-backup-{}", digest.trim_start_matches("sha256:"));
    let response = client.put_native_key_backup(&packet, &idempotency).await?;
    vault
        .record_native_ack_after_bound_put(operation, root, &response)
        .await?;
    response.value()?;
    Ok(NativeRootPublicationOutcome {
        evidence: PublicationEvidence::Put(Box::new(response)),
    })
}

/// Publish through the single native Device lane. The Device consumes the
/// manager's selected series and echoes the bound prepare input; it never
/// creates a pointer, obtains an archive private key or installs active MLS.
pub async fn publish_native_content_root(
    client: &OwnStationDeviceClient,
    vault: &ContentRootVault<'_>,
    parameters: NativeRootPublicationParameters<'_>,
    sign: impl FnOnce(&[u8]) -> arkret_crypto::Result<Vec<u8>>,
) -> Result<NativeRootPublicationOutcome> {
    use arkret_models_crypto::{
        RealmActorBackupHeadQuery, RealmActorBackupIssueUnlockChallengeRequestBody,
        RealmActorBackupUnlockChallengeKind, RealmActorBackupUnlockChallengePurpose,
    };
    check_native_publisher_context(client, vault, parameters.root)?;
    vault.retain_root(parameters.root).await?;
    let context = client.context()?;
    if parameters.author.device_id != *context.device_id()
        || parameters.author.device_authorize_event_id != *context.authorization_event_id()
    {
        return Err(rejected("native signer is not the bound original Device"));
    }
    let actor = context
        .actor_id()
        .as_realm_actor_id()
        .ok_or_else(|| rejected("native publisher has no complete Realm actor"))?
        .clone();
    let prepare = client
        .realm_actor_backup_prepare_input(
            request_nonce()?,
            parameters.authority,
            parameters.station_resolution,
            parameters.authority_keys,
        )
        .await?;
    let input = prepare.value()?.clone();
    let circle = match context.effective_scope() {
        ScopeRef::Realm { .. } => None,
        ScopeRef::Circle { circle_id, .. } => Some(circle_id.clone()),
        _ => return Err(rejected("native backup has no exact Realm/Circle scope")),
    };
    let head = client
        .native_key_backup_head(&RealmActorBackupHeadQuery::new(actor.clone(), circle))
        .await?;
    let head_value = head.value()?;
    if head.context() != prepare.context()
        || head_value.active_series.secret_storage.series_id() != Some(&input.active_series_id)
        || head_value.active_series.manager_ref != input.auth_binding.manager_ref
        || head_value.active_series.recipient_ref != input.auth_binding.recipient_ref
    {
        return Err(rejected(
            "native head and bound prepare input have different manager, recipient or selected series",
        ));
    }
    let intent = current_publication_intent(
        parameters.operation,
        context,
        parameters.root,
        &input,
        head_value,
    )?;
    // Series recovery_ref is a historical source; a benign current recovery.set
    // does not rotate a series. The actual current input is echoed unchanged.
    let predecessor = if let Some(item) = head_value.items.first() {
        let request = RealmActorBackupIssueUnlockChallengeRequestBody {
            request_id: arkret_wire::Base64UrlString::new(request_nonce()?).map_err(rejected)?,
            kind: RealmActorBackupUnlockChallengeKind::RealmActorDevice,
            purpose: RealmActorBackupUnlockChallengePurpose::SeriesPredecessor,
            realm_actor_id: actor.clone(),
            effective_scope: parameters.root.root_context.effective_scope.clone(),
            envelope_digest: item.admission.envelope_digest.clone(),
        };
        let challenge = client
            .issue_native_key_backup_unlock_challenge(&item.metadata.backup_id, &request)
            .await?;
        let unlocked = client.unlock_native_key_backup(&challenge).await?;
        let original = unlocked.value()?;
        if unlocked.context() != prepare.context()
            || original.backup.series_id != input.active_series_id
            || original.backup.backup_id != item.metadata.backup_id
            || arkret_canonical::canonical_json_bytes(&original.admission)?
                != arkret_canonical::canonical_json_bytes(&item.admission)?
        {
            return Err(rejected(
                "native unlocked predecessor differs from its selected exact head",
            ));
        }
        if original.backup.contents.len() == 1
            && original.backup.contents[0].root_ref.as_ref() == Some(&parameters.root.root_ref)
            && original.backup.contents[0].root_context.as_ref()
                == Some(&parameters.root.root_context)
        {
            prepare.value()?;
            head.value()?;
            return Ok(NativeRootPublicationOutcome {
                evidence: PublicationEvidence::Head(Box::new(unlocked)),
            });
        }
        Some(original.backup.clone())
    } else {
        None
    };
    let (series_sequence, supersedes) = match predecessor {
        Some(original) => (
            original
                .series_sequence
                .checked_add(1)
                .ok_or_else(|| rejected("native backup sequence exhausted"))?,
            Some((
                original.backup_id.clone(),
                Hash::new(arkret_canonical::sha256_digest(
                    original.signing_payload_bytes().map_err(rejected)?,
                ))
                .map_err(rejected)?,
            )),
        ),
        None => (0, None),
    };
    prepare.value()?;
    head.value()?;
    vault
        .register_native_publication_intent(parameters.operation, &intent)
        .await?;
    let frozen = match vault
        .native_root_publication_state(&intent, parameters.root)
        .await?
    {
        NativeRootPublicationState::Unprepared => None,
        NativeRootPublicationState::Frozen { packet } => Some(*packet),
        NativeRootPublicationState::Recorded { history } => Some(history.packet),
    };
    if let Some(packet) = frozen {
        // This intent includes the actual current input and predecessor cut.
        // A different series, recovery declaration or epoch gets another key.
        if packet.series_id != input.active_series_id
            || packet.auth_binding.as_ref() != Some(&input.auth_binding)
            || packet.series_sequence != series_sequence
            || packet.supersedes_id.as_ref() != supersedes.as_ref().map(|value| &value.0)
            || packet.supersedes_digest.as_ref() != supersedes.as_ref().map(|value| &value.1)
        {
            return Err(rejected(
                "frozen native intent differs from the current selected cut",
            ));
        }
        return put_frozen_native_root(client, vault, &intent, parameters.root, packet).await;
    }
    let packet = arkret_crypto::content_history::RealmActorContentRootBackupDraft {
        backup_id: super::super::backup_series::fresh_backup_id()?,
        realm_actor_id: actor,
        created_at: parameters.created_at,
        author: parameters.author,
        prepare_input: input,
        domain_separation: parameters.domain_separation,
        series_sequence,
        supersedes,
    }
    .seal(parameters.root.clone(), sign)
    .map_err(rejected)?;
    let packet = vault
        .freeze_native_root_publication(&intent, parameters.root, &packet)
        .await?;
    put_frozen_native_root(client, vault, &intent, parameters.root, packet).await
}

/// A committed local state. A recorded ACK is historical data, not permission to
/// use today's recipient, author an Event, or reconstruct a bound SDK response.
pub enum NativeRootPublicationState {
    Unprepared,
    Frozen {
        packet: Box<KeyBackup>,
    },
    Recorded {
        history: Box<NativeRootPublicationHistory>,
    },
}

/// History-only material read from the private durable journal. This type has
/// no public constructor or Deserialize implementation and is not an SDK proof.
pub struct NativeRootPublicationHistory {
    packet: KeyBackup,
    response: RealmActorBackupPutResponseBody,
}

impl NativeRootPublicationHistory {
    pub fn packet(&self) -> &KeyBackup {
        &self.packet
    }

    pub fn response(&self) -> &RealmActorBackupPutResponseBody {
        &self.response
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeRootPublicationRecord {
    root_ref: Hash,
    root_context: ContentRootContext,
    response: RealmActorBackupPutResponseBody,
}

fn same_packet(left: &KeyBackup, right: &KeyBackup) -> Result<bool> {
    Ok(arkret_canonical::canonical_json_bytes(left)?
        == arkret_canonical::canonical_json_bytes(right)?)
}

fn original_packet_matches_ack(
    root: &ContentRootBackupEntry,
    packet: &KeyBackup,
    response: &RealmActorBackupPutResponseBody,
) -> Result<()> {
    arkret_signatures::realm_actor_content_backup::verify_realm_actor_backup_packet(
        packet,
        &response.admission,
    )
    .map_err(rejected)?;
    if response.backup_id != packet.backup_id
        || response.ciphertext_digest != packet.ciphertext_digest
        || packet.contents.len() != 1
        || packet.contents[0].root_ref.as_ref() != Some(&root.root_ref)
        || packet.contents[0].root_context.as_ref() != Some(&root.root_context)
    {
        return Err(rejected(
            "historical native ACK differs from the retained root or original packet",
        ));
    }
    Ok(())
}

impl ContentRootVault<'_> {
    async fn native_publication_intents(&self, operation: &str) -> Result<Vec<String>> {
        if operation.is_empty() {
            return Err(rejected("native publication operation is empty"));
        }
        let key = self.key(
            "content-root-backup",
            ("native-publication-intents", operation),
        )?;
        self.store
            .read_secret_bytes_durable(&key)
            .await
            .map_err(rejected)?
            .map(|bytes| serde_json::from_slice(bytes.as_slice()).map_err(Error::from))
            .transpose()
            .map(Option::unwrap_or_default)
    }

    async fn register_native_publication_intent(
        &self,
        operation: &str,
        intent: &str,
    ) -> Result<()> {
        let key = self.key(
            "content-root-backup",
            ("native-publication-intents", operation),
        )?;
        for _ in 0..CAS_ATTEMPTS {
            let previous = self
                .store
                .read_secret_bytes_durable(&key)
                .await
                .map_err(rejected)?;
            let mut intents: Vec<String> = previous
                .as_ref()
                .map(|bytes| serde_json::from_slice(bytes.as_slice()))
                .transpose()?
                .unwrap_or_default();
            if intents.iter().any(|existing| existing == intent) {
                return Ok(());
            }
            intents.push(intent.to_owned());
            intents.sort();
            let next = serde_json::to_vec(&intents)?;
            if self
                .store
                .compare_exchange_secret_bytes_durable(
                    &key,
                    previous.as_ref().map(|bytes| bytes.as_slice()),
                    &next,
                )
                .await
                .map_err(rejected)?
            {
                return Ok(());
            }
        }
        Err(rejected("native publication intent index contended"))
    }

    fn native_requester_matches(&self, packet: &KeyBackup) -> Result<()> {
        let MlsWelcomeRecipientEndpoint::Device { device_id } = self.endpoint else {
            return Err(rejected("native root publisher requires a Device endpoint"));
        };
        if self.subject.as_realm_actor_id().is_none()
            || &packet.actor_id != self.subject
            || packet.device_id.as_ref() != Some(device_id)
            || packet.signature_proof.device_id.as_ref() != Some(device_id)
        {
            return Err(rejected(
                "frozen native PUT belongs to another original requester",
            ));
        }
        Ok(())
    }

    /// Freeze the actual signed native packet before sending it. The operation
    /// identity remains stable through a lost response, restart and exact retry.
    pub async fn freeze_native_root_publication(
        &self,
        operation: &str,
        root: &ContentRootBackupEntry,
        packet: &KeyBackup,
    ) -> Result<KeyBackup> {
        self.native_requester_matches(packet)?;
        Self::validate_root(root)?;
        if packet.contents.len() != 1
            || packet.contents[0].root_ref.as_ref() != Some(&root.root_ref)
            || packet.contents[0].root_context.as_ref() != Some(&root.root_context)
            || self.root(&root.root_ref).await?.as_ref() != Some(root)
        {
            return Err(rejected(
                "native intent differs from its durably retained original root",
            ));
        }
        self.freeze_backup(operation, packet).await
    }

    /// Reopen the local intent without a current authority claim. Callers must
    /// use a fresh bound native read or a valid original-requester exact PUT to
    /// recover any SDK current capability. This method cannot issue one.
    pub async fn native_root_publication_state(
        &self,
        operation: &str,
        root: &ContentRootBackupEntry,
    ) -> Result<NativeRootPublicationState> {
        Self::validate_root(root)?;
        let packet = self.frozen_backup(operation).await?;
        let key = self.key(
            "content-root-backup",
            ("native-put-ack", operation, &root.root_ref),
        )?;
        let record = self
            .store
            .read_secret_bytes_durable(&key)
            .await
            .map_err(rejected)?;
        let Some(packet) = packet else {
            if record.is_some() {
                return Err(rejected(
                    "native ACK journal has no durable frozen original",
                ));
            }
            return Ok(NativeRootPublicationState::Unprepared);
        };
        self.native_requester_matches(&packet)?;
        if self.root(&root.root_ref).await?.as_ref() != Some(root)
            || packet.contents.len() != 1
            || packet.contents[0].root_ref.as_ref() != Some(&root.root_ref)
            || packet.contents[0].root_context.as_ref() != Some(&root.root_context)
        {
            return Err(rejected(
                "reopened native intent has another root or original state",
            ));
        }
        let Some(record) = record else {
            return Ok(NativeRootPublicationState::Frozen {
                packet: Box::new(packet),
            });
        };
        let record: NativeRootPublicationRecord = serde_json::from_slice(record.as_slice())?;
        if record.root_ref != root.root_ref || record.root_context != root.root_context {
            return Err(rejected("native ACK journal changed its retained root"));
        }
        original_packet_matches_ack(root, &packet, &record.response)?;
        Ok(NativeRootPublicationState::Recorded {
            history: Box::new(NativeRootPublicationHistory {
                packet,
                response: record.response,
            }),
        })
    }

    // The production ACK write requires an actual SDK bound response. The
    // history-only storage implementation cannot construct that response.
    async fn record_native_ack_after_bound_put(
        &self,
        operation: &str,
        root: &ContentRootBackupEntry,
        acknowledgement: &PutAcknowledgement,
    ) -> Result<()> {
        self.commit_native_publication_history(
            operation,
            root,
            acknowledgement.request(),
            acknowledgement.value()?,
        )
        .await?;
        acknowledgement.value()?;
        Ok(())
    }

    async fn commit_native_publication_history(
        &self,
        operation: &str,
        root: &ContentRootBackupEntry,
        packet: &KeyBackup,
        response: &RealmActorBackupPutResponseBody,
    ) -> Result<()> {
        self.native_requester_matches(packet)?;
        original_packet_matches_ack(root, packet, response)?;
        let frozen = self
            .frozen_backup(operation)
            .await?
            .ok_or_else(|| rejected("native PUT ACK has no durably frozen original"))?;
        if !same_packet(&frozen, packet)? || self.root(&root.root_ref).await?.as_ref() != Some(root)
        {
            return Err(rejected(
                "native ACK differs from its frozen original intent",
            ));
        }
        let key = self.key(
            "content-root-backup",
            ("native-put-ack", operation, &root.root_ref),
        )?;
        let record = NativeRootPublicationRecord {
            root_ref: root.root_ref.clone(),
            root_context: root.root_context.clone(),
            response: response.clone(),
        };
        let bytes = serde_json::to_vec(&record)?;
        for _ in 0..CAS_ATTEMPTS {
            match self.native_root_publication_state(operation, root).await? {
                NativeRootPublicationState::Recorded { history } => {
                    if !same_packet(history.packet(), packet)?
                        || arkret_canonical::canonical_json_bytes(&history.response().admission)?
                            != arkret_canonical::canonical_json_bytes(&response.admission)?
                    {
                        return Err(rejected(
                            "native ACK conflicts with the immutable original receipt",
                        ));
                    }
                    return Ok(());
                }
                NativeRootPublicationState::Frozen { .. } => {}
                NativeRootPublicationState::Unprepared => {
                    return Err(rejected("native frozen intent disappeared"));
                }
            }
            if self
                .store
                .compare_exchange_secret_bytes_durable(&key, None, &bytes)
                .await
                .map_err(rejected)?
            {
                return Ok(());
            }
        }
        Err(rejected("native ACK journal contended"))
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests;
