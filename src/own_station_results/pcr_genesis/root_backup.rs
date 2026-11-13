//! History-only import of an already held root block. Ciphertext possession
//! does not grant API access, membership or permission to restore old current.

use std::collections::BTreeSet;

use arkret_event_draft::EventContentEnvelopesExt as _;
use arkret_models_collaboration::events_payloads::DeviceAuthorizePayload;
use arkret_models_crypto::{
    BackupKind, EncryptedEnvelopeEncryptionContext, KeyBackup, KeyBackupSignatureAlgorithm,
    RecoveryMethod, RecoveryPolicySetPayload, RecoverySignatureAlgorithm, SecretStorageEntry,
    recovery_policy_signature_transcript_bytes,
};
use arkret_wire::{ActorId, DeviceId, EventKind, Hash, MlsWelcomeRecipientEndpoint, ScopeRef};

use super::OwnStationHumanPcrEvent;
use crate::mls::content_roots::ContentRootVault;
use crate::{Result, SecureKeyStore};

#[cfg(test)]
mod tests;

fn protocol(detail: impl std::fmt::Display) -> crate::Error {
    super::protocol(&format!("PCR history root: {detail}"))
}

impl OwnStationHumanPcrEvent<'_> {
    pub(super) fn validate_history_selection(&self, root_refs: &[Hash]) -> Result<()> {
        let source = self.full()?;
        if source.event.scope_ref
            != (ScopeRef::Realm {
                realm_id: self.pcr.realm()?.clone(),
            })
            || root_refs.is_empty()
            || root_refs.len() > 256
            || root_refs.iter().collect::<BTreeSet<_>>().len() != root_refs.len()
        {
            return Err(protocol("root selection differs from its holder PCR"));
        }
        let carriers = source.event.event_content_envelopes()?;
        if root_refs.iter().any(|root| {
            !carriers.iter().any(|carrier| {
                let EncryptedEnvelopeEncryptionContext::EpochContent { protection, .. } =
                    &carrier.envelope.encryption_context;
                protection.root_refs.contains(root)
            })
        }) {
            return Err(protocol(
                "root import is outside original signed protection",
            ));
        }
        Ok(())
    }

    /// Import only selected, original-protected R values into this endpoint's
    /// durable history vault. No old signer, SSK or private MLS state is read
    /// or installed. The caller obtains remote ciphertext through the separate
    /// current-device content_history challenge; locally held bytes need none.
    pub async fn import_content_root_backup(
        &self,
        backup: &KeyBackup,
        policy_original: &OwnStationHumanPcrEvent<'_>,
        backup_hpke_private_key: &[u8; 32],
        current_device: &DeviceId,
        root_refs: &[Hash],
        store: &dyn SecureKeyStore,
    ) -> Result<Vec<Hash>> {
        let source = self.full()?;
        let policy_full = policy_original.full()?;
        self.validate_history_selection(root_refs)?;
        if !std::ptr::eq(self.pcr, policy_original.pcr) {
            return Err(protocol(
                "root import differs from its holder PCR or selection",
            ));
        }
        let carriers = source.event.event_content_envelopes()?;
        let account = self.pcr.account()?;
        let actor = ActorId::account(account.clone());
        backup.validate()?;
        if backup.actor_id != actor
            || backup.backup_kind != BackupKind::SecretStorage
            || backup.custodian_actor_id.is_some()
            || backup.custody_authorization_ref.is_some()
            || backup
                .signature_proof
                .agent_authorization_event_ref
                .is_some()
            || backup.signature_proof.signature_algorithm != KeyBackupSignatureAlgorithm::Ed25519
            || policy_full.event.kind != EventKind::PolicySet
        {
            return Err(protocol(
                "root backup subject, author or original policy differs",
            ));
        }
        let policy_payload: RecoveryPolicySetPayload =
            serde_json::from_value(serde_json::to_value(&policy_full.event.payload)?)?;
        let policy = &policy_payload.value;
        if policy.account_id != *account
            || policy_payload.policy_id != policy.policy_id
            || policy.signature_proof.signature_algorithm != RecoverySignatureAlgorithm::Ed25519
            || policy_full
                .event
                .producer_proof
                .as_ref()
                .is_none_or(|proof| {
                    proof.verification_method != policy.signature_proof.verification_method
                })
        {
            return Err(protocol(
                "root policy differs from its exact original Device producer",
            ));
        }
        arkret_signatures::proof::verify_ed25519_raw_transcript_signature(
            &recovery_policy_signature_transcript_bytes(policy)?,
            policy.signature_proof.signature.as_str(),
            policy_original.producer_signing_key()?,
        )
        .map_err(protocol)?;
        backup.validate_recovery_recipient(policy, backup.created_at)?;
        let recipient = backup
            .encryption
            .recipient_key_ref
            .as_deref()
            .ok_or_else(|| protocol("root backup has no recovery HPKE recipient"))?;
        let public =
            arkret_crypto::hpke::x25519_public_key(backup_hpke_private_key).map_err(protocol)?;
        let multikey = arkret_crypto::identity_root::x25519_public_multikey(&public);
        if !policy.methods.iter().any(|method| match method {
            RecoveryMethod::RecoveryUnlock { keys } => keys.iter().any(|key| {
                key.backup_hpke.key_agreement_ref.as_str() == recipient
                    && key.backup_hpke.public_key_multibase == multikey
            }),
            _ => false,
        }) {
            return Err(protocol(
                "provided recovery material differs from original backup HPKE",
            ));
        }
        let authorization_id = backup
            .signature_proof
            .device_authorize_event_id
            .as_ref()
            .ok_or_else(|| protocol("root backup has no original Device authorization"))?;
        let authorization = self.pcr.read_original(authorization_id).await?;
        let authorization_full = authorization.full()?;
        if authorization_full.event.kind != EventKind::DeviceAuthorize {
            return Err(protocol(
                "root backup signing source is not DeviceAuthorize",
            ));
        }
        let device: DeviceAuthorizePayload =
            serde_json::from_value(serde_json::to_value(&authorization_full.event.payload)?)?;
        arkret_signatures::verify_device_authorize_possession(&device, account)
            .map_err(protocol)?;
        let method = format!(
            "{}#{}",
            self.pcr.principal.value()?.resolution_projection.did,
            device.device_id
        );
        if backup.signature_proof.device_id.as_ref() != Some(&device.device_id)
            || backup
                .device_id
                .as_ref()
                .is_some_and(|id| id != &device.device_id)
            || backup.signature_proof.verification_method.as_str() != method
            || backup.created_at < device.not_before
            || device
                .expires_at
                .flatten()
                .is_some_and(|expiry| backup.created_at >= expiry)
        {
            return Err(protocol(
                "root backup differs from its original signing Device instance",
            ));
        }
        let signing_key = arkret_signatures::PublicKeyMaterial::Ed25519Multibase {
            value: device
                .device_public_key_did
                .as_str()
                .strip_prefix("did:key:")
                .ok_or_else(|| protocol("root backup signing Device key is not did:key"))?
                .to_owned(),
        };
        let bag = arkret_crypto::content_history::open_content_root_backup(
            backup,
            backup_hpke_private_key,
            |bytes, proof| {
                arkret_signatures::proof::verify_ed25519_raw_transcript_signature(
                    bytes,
                    proof.signature.as_str(),
                    &signing_key,
                )
                .map_err(|error| arkret_crypto::Error::Protocol(error.to_string()))
            },
        )
        .map_err(protocol)?;
        // All entries and the complete index are checked before any retention.
        let mut selected = Vec::new();
        for item in &bag.items {
            let SecretStorageEntry::ContentRoot(root) = item else {
                return Err(protocol("root import contains another secret class"));
            };
            if !root_refs.contains(&root.root_ref) {
                continue;
            }
            if root.root_context.effective_scope != source.event.scope_ref
                || root.root_context.backup_strategy_ref != self.pcr.genesis()?.event.event_id
            {
                return Err(protocol(
                    "selected root differs from its original PCR strategy",
                ));
            }
            for carrier in &carriers {
                let EncryptedEnvelopeEncryptionContext::EpochContent {
                    epoch,
                    group_state_ref,
                    root_ref,
                    ..
                } = &carrier.envelope.encryption_context;
                if root_ref == &root.root_ref
                    && (*epoch != root.root_context.epoch
                        || group_state_ref != &root.root_context.group_state_ref)
                {
                    return Err(protocol(
                        "root epoch differs from its original encrypted carrier",
                    ));
                }
            }
            selected.push(root);
        }
        if selected.len() != root_refs.len() {
            return Err(protocol(
                "root block does not contain the complete requested selection",
            ));
        }
        self.full()?;
        policy_original.full()?;
        authorization.full()?;
        let endpoint = MlsWelcomeRecipientEndpoint::Device {
            device_id: current_device.clone(),
        };
        let vault = ContentRootVault::new(store, &actor, &endpoint);
        for root in selected {
            vault.retain_root(root).await?;
            self.full()?;
            policy_original.full()?;
        }
        Ok(root_refs.to_vec())
    }
}
