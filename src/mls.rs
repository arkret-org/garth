//! Host-neutral MLS installation queue and provider-opaque local state.

#[path = "mls/backup_selection.rs"]
pub mod backup_selection;
#[path = "mls/backup_series.rs"]
pub mod backup_series;
#[path = "mls/key_package.rs"]
pub mod key_package;
#[path = "mls/self_preservation.rs"]
pub mod self_preservation;
#[path = "mls/status.rs"]
pub mod status;
#[path = "mls/welcome_admission.rs"]
pub mod welcome_admission;

use std::collections::VecDeque;
use std::future::Future;
use std::sync::{Arc, Mutex};

use arkret_models_crypto::{MlsCommitEnvelope, MlsGroupStateRecord, MlsWelcomeEnvelope};
use arkret_wire::{CommittedEventRef, DeviceId};
pub use backup_selection::{
    active_series_id, carries_item_kind, recovery_public_key_backup_present,
    recovery_setup_prompt_required, select_active_series_tail,
    select_active_series_tail_for_recipient_method, summaries_in_active_series,
};
pub use backup_series::{fresh_backup_id, series_supersedes_digest, verify_series_chain};
pub use key_package::{KEY_PACKAGE_LOW_WATER, MlsKeyPackageInventoryStore, key_package_deficit};
pub use self_preservation::{
    SELF_PRESERVATION_JITTER_SLOTS, SELF_PRESERVATION_MAX_EPOCH_AGE_DAYS,
    SELF_PRESERVATION_MAX_EPOCH_APP_MESSAGES, idle_self_update_jitter_passed,
    should_force_epoch_advance,
};
pub use status::{InstalledMlsEpoch, MlsRuntimeError, MlsRuntimeStatus, installed_mls_epoch};
pub use welcome_admission::{
    LocalMlsEndpoint, admit_welcome, mls_group_id_for_realm, mls_group_id_for_scope,
    retain_admissible_welcomes, welcome_matches_endpoint,
};
use zeroize::Zeroizing;

use crate::{
    Error, MaybeSend, MaybeSendSync, PutSecretOptions, Result, SecretClass, SecretDurability,
    SecureKeyStore, SecureKeyStoreError,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AcceptedMlsArtifact {
    Welcome(MlsWelcomeEnvelope),
    Commit(MlsCommitEnvelope),
}

impl AcceptedMlsArtifact {
    pub fn group_id(&self) -> &str {
        match self {
            Self::Welcome(value) => &value.group_id,
            Self::Commit(value) => &value.group_id,
        }
    }

    pub fn epoch(&self) -> u64 {
        match self {
            Self::Welcome(value) => value.epoch,
            Self::Commit(value) => value.epoch,
        }
    }
}

/// An MLS artifact becomes installable only after its producer Event has an
/// exact authority-commit coordinate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueuedMlsInstall {
    pub accepted_ref: CommittedEventRef,
    pub artifact: AcceptedMlsArtifact,
}

pub trait MlsInstaller: MaybeSendSync {
    fn install<'a>(
        &'a self,
        queued: &'a QueuedMlsInstall,
    ) -> impl Future<Output = Result<MlsGroupStateRecord>> + MaybeSend + 'a;
}

pub trait MlsLocalStateStore: Clone + MaybeSendSync + 'static {
    fn load<'a>(
        &'a self,
        group_id: &'a str,
    ) -> impl Future<Output = Result<Option<MlsGroupStateRecord>>> + MaybeSend + 'a;
    fn save(&self, state: MlsGroupStateRecord)
    -> impl Future<Output = Result<()>> + MaybeSend + '_;
    fn remove<'a>(&'a self, group_id: &'a str)
    -> impl Future<Output = Result<()>> + MaybeSend + 'a;
}

#[derive(Clone, Debug, Default)]
pub struct MemoryMlsLocalStateStore {
    states: Arc<Mutex<std::collections::BTreeMap<String, MlsGroupStateRecord>>>,
}

impl MlsLocalStateStore for MemoryMlsLocalStateStore {
    async fn load(&self, group_id: &str) -> Result<Option<MlsGroupStateRecord>> {
        Ok(self.states.lock().unwrap().get(group_id).cloned())
    }

    async fn save(&self, state: MlsGroupStateRecord) -> Result<()> {
        self.states
            .lock()
            .unwrap()
            .insert(state.group_id.as_str().to_owned(), state);
        Ok(())
    }

    async fn remove(&self, group_id: &str) -> Result<()> {
        self.states.lock().unwrap().remove(group_id);
        Ok(())
    }
}

/// Provider-opaque MLS checkpoints persisted in the host's secret store.
#[derive(Clone, Debug)]
pub struct SecureMlsLocalStateStore<S> {
    secure_store: S,
    namespace: String,
}

impl<S> SecureMlsLocalStateStore<S> {
    pub fn new(secure_store: S, namespace: impl Into<String>) -> Self {
        Self {
            secure_store,
            namespace: namespace.into(),
        }
    }

    fn storage_key(&self, group_id: &str) -> String {
        format!(
            "{}/group/{}",
            self.namespace,
            arkret_canonical::sha256_base64url(group_id.as_bytes())
        )
    }
}

impl<S> MlsLocalStateStore for SecureMlsLocalStateStore<S>
where
    S: SecureKeyStore + Clone,
{
    async fn load(&self, group_id: &str) -> Result<Option<MlsGroupStateRecord>> {
        self.secure_store
            .get_secret_bytes(&self.storage_key(group_id))
            .map_err(Error::from)?
            .map(|bytes| serde_json::from_slice(bytes.as_slice()).map_err(Error::from))
            .transpose()
    }

    async fn save(&self, state: MlsGroupStateRecord) -> Result<()> {
        if state.group_id.is_empty() {
            return Err(Error::Protocol(
                "MLS local state requires a non-empty group id".to_owned(),
            ));
        }
        let key = self.storage_key(&state.group_id);
        let bytes = Zeroizing::new(serde_json::to_vec(&state)?);
        self.secure_store
            .put_secret(
                &key,
                &bytes,
                PutSecretOptions {
                    durability: SecretDurability::DurableBeforeReturn,
                    class: SecretClass::MlsSecret,
                },
            )
            .await
            .map_err(Error::from)
    }

    async fn remove(&self, group_id: &str) -> Result<()> {
        match self
            .secure_store
            .delete_secret_durable(&self.storage_key(group_id))
            .await
        {
            Ok(()) | Err(SecureKeyStoreError::NotFound) => Ok(()),
            Err(error) => Err(Error::from(error)),
        }
    }
}

/// Device MLS secret material, separated from serialized group checkpoints.
#[derive(Clone, Debug)]
pub struct MlsDeviceSecretStore<S> {
    secure_store: S,
    namespace: String,
}

impl<S: SecureKeyStore> MlsDeviceSecretStore<S> {
    pub fn new(secure_store: S, namespace: impl Into<String>) -> Self {
        Self {
            secure_store,
            namespace: namespace.into(),
        }
    }

    fn storage_key(&self, device_id: &DeviceId) -> String {
        format!(
            "{}/device/{}",
            self.namespace,
            crate::device_storage_digest(device_id)
        )
    }

    pub async fn save(&self, device_id: &DeviceId, secret: &[u8]) -> Result<()> {
        if secret.is_empty() {
            return Err(Error::Protocol(
                "MLS device secret must not be empty".to_owned(),
            ));
        }
        self.secure_store
            .put_secret(
                &self.storage_key(device_id),
                secret,
                PutSecretOptions {
                    durability: SecretDurability::DurableBeforeReturn,
                    class: SecretClass::MlsSecret,
                },
            )
            .await
            .map_err(Error::from)
    }

    pub fn load(&self, device_id: &DeviceId) -> Result<Option<Zeroizing<Vec<u8>>>> {
        Ok(self
            .secure_store
            .get_secret_bytes(&self.storage_key(device_id))
            .map_err(Error::from)?
            .map(|bytes| Zeroizing::new(bytes.as_slice().to_vec())))
    }

    pub async fn remove(&self, device_id: &DeviceId) -> Result<()> {
        match self
            .secure_store
            .delete_secret_durable(&self.storage_key(device_id))
            .await
        {
            Ok(()) | Err(SecureKeyStoreError::NotFound) => Ok(()),
            Err(error) => Err(Error::from(error)),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct MlsInstallQueue {
    pending: VecDeque<QueuedMlsInstall>,
}

impl MlsInstallQueue {
    pub fn enqueue(&mut self, queued: QueuedMlsInstall) -> Result<()> {
        if queued.artifact.group_id().is_empty() {
            return Err(crate::Error::Protocol(
                "MLS install requires a non-empty group id".to_owned(),
            ));
        }
        self.pending.push_back(queued);
        Ok(())
    }

    pub fn pending(&self) -> impl Iterator<Item = &QueuedMlsInstall> {
        self.pending.iter()
    }

    /// Persist installed provider state before removing the queued artifact.
    pub async fn install_next<I, S>(
        &mut self,
        installer: &I,
        states: &S,
    ) -> Result<Option<MlsGroupStateRecord>>
    where
        I: MlsInstaller + ?Sized,
        S: MlsLocalStateStore,
    {
        let Some(queued) = self.pending.front() else {
            return Ok(None);
        };
        let state = installer.install(queued).await?;
        if state.group_id.as_str() != queued.artifact.group_id()
            || state.epoch < queued.artifact.epoch()
        {
            return Err(crate::Error::Protocol(
                "MLS installer returned state for a different group or older epoch".to_owned(),
            ));
        }
        states.save(state.clone()).await?;
        self.pending.pop_front();
        Ok(Some(state))
    }
}

#[cfg(test)]
mod tests {
    use arkret_models_crypto::MlsEndpointIdentity;
    use arkret_wire::{
        AccountId, ActorId, CommitStreamRef, DidCoreId, EventId, Hash, MlsGroupId, RealmCommitId,
        RealmId,
    };
    use chrono::TimeZone;

    use super::*;

    const GROUP_ID: &str = "QjKOSorlqs3IquY7OikTUTy_Z0mMiL0X2mK4jAOT4R4";

    fn device_id() -> DeviceId {
        DeviceId::new("ak:device:0196419b-0000-7000-8000-000000000001").unwrap()
    }

    fn state(group_id: &str, epoch: u64) -> MlsGroupStateRecord {
        let principal_id = DidCoreId::new("ak:did_core:web:alice.example").unwrap();
        MlsGroupStateRecord {
            group_id: MlsGroupId::new(group_id.to_owned()).unwrap(),
            actor_id: ActorId::account(AccountId::new(
                principal_id.clone(),
                DidCoreId::new("ak:did_core:web:station.example").unwrap(),
            )),
            endpoint: MlsEndpointIdentity::human_device(principal_id, device_id()),
            epoch,
            serialized_state: vec![1, 2, 3, u8::try_from(epoch).unwrap()],
            updated_at: chrono::Utc.with_ymd_and_hms(2026, 9, 16, 0, 0, 0).unwrap(),
        }
    }

    fn accepted_ref(seed: u8) -> CommittedEventRef {
        let event_id = EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [seed; 32]);
        CommittedEventRef {
            event_id: event_id.clone(),
            commit_id: RealmCommitId::from_digest([seed.wrapping_add(1); 32]),
            stream_ref: CommitStreamRef::Realm {
                realm_id: RealmId::from_event_id(&event_id),
            },
            stream_position: 1,
        }
    }

    fn welcome(group_id: &str, epoch: u64) -> AcceptedMlsArtifact {
        AcceptedMlsArtifact::Welcome(MlsWelcomeEnvelope {
            group_id: MlsGroupId::new(group_id.to_owned()).unwrap(),
            epoch,
            recipient: MlsEndpointIdentity::human_device(
                DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
                device_id(),
            ),
            welcome: "AQID".to_owned(),
            welcome_hash: Hash::new(format!("sha256:{}", "11".repeat(32))).unwrap(),
            ratchet_tree: None,
        })
    }

    #[derive(Clone, Debug)]
    struct Installer {
        result: Option<MlsGroupStateRecord>,
    }

    impl MlsInstaller for Installer {
        async fn install(&self, _queued: &QueuedMlsInstall) -> Result<MlsGroupStateRecord> {
            self.result
                .clone()
                .ok_or_else(|| Error::Protocol("provider rejected Welcome".to_owned()))
        }
    }

    #[tokio::test]
    async fn secure_local_checkpoint_round_trips_provider_state() {
        let secure = crate::MemorySecureKeyStore::new();
        let store = SecureMlsLocalStateStore::new(secure, "mls-test");
        let expected = state(GROUP_ID, 4);
        store.save(expected.clone()).await.unwrap();
        assert_eq!(store.load(GROUP_ID).await.unwrap(), Some(expected));
        store.remove(GROUP_ID).await.unwrap();
        assert!(store.load(GROUP_ID).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn device_secret_round_trips_and_removes() {
        let store = MlsDeviceSecretStore::new(crate::MemorySecureKeyStore::new(), "mls-test");
        let device_id = device_id();
        store.save(&device_id, b"device secret").await.unwrap();
        assert_eq!(
            store.load(&device_id).unwrap().unwrap().as_slice(),
            b"device secret"
        );
        store.remove(&device_id).await.unwrap();
        assert!(store.load(&device_id).unwrap().is_none());
    }

    #[tokio::test]
    async fn failed_welcome_install_remains_queued() {
        let mut queue = MlsInstallQueue::default();
        queue
            .enqueue(QueuedMlsInstall {
                accepted_ref: accepted_ref(3),
                artifact: welcome(GROUP_ID, 4),
            })
            .unwrap();
        let installer = Installer { result: None };
        assert!(
            queue
                .install_next(&installer, &MemoryMlsLocalStateStore::default())
                .await
                .is_err()
        );
        assert_eq!(queue.pending().count(), 1);
    }

    #[tokio::test]
    async fn welcome_dequeues_only_after_checkpoint_is_saved() {
        let mut queue = MlsInstallQueue::default();
        queue
            .enqueue(QueuedMlsInstall {
                accepted_ref: accepted_ref(3),
                artifact: welcome(GROUP_ID, 4),
            })
            .unwrap();
        let expected = state(GROUP_ID, 4);
        let installer = Installer {
            result: Some(expected.clone()),
        };
        let store = MemoryMlsLocalStateStore::default();
        assert_eq!(
            queue.install_next(&installer, &store).await.unwrap(),
            Some(expected.clone())
        );
        assert_eq!(store.load(GROUP_ID).await.unwrap(), Some(expected));
        assert_eq!(queue.pending().count(), 0);
    }

    #[tokio::test]
    async fn older_installed_epoch_does_not_consume_queue_entry() {
        let mut queue = MlsInstallQueue::default();
        queue
            .enqueue(QueuedMlsInstall {
                accepted_ref: accepted_ref(3),
                artifact: welcome(GROUP_ID, 4),
            })
            .unwrap();
        let installer = Installer {
            result: Some(state(GROUP_ID, 3)),
        };
        assert!(
            queue
                .install_next(&installer, &MemoryMlsLocalStateStore::default())
                .await
                .is_err()
        );
        assert_eq!(queue.pending().count(), 1);
    }
}
