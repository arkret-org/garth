//! Typed MLS-runtime readiness status and the installed-epoch read.
//!
//! Scope content is plaintext before this endpoint accepted its own
//! `ak.mls.genesis`, and is irreversibly activated to standard RFC 9420
//! afterwards. A client therefore has to distinguish three answers: the local
//! provider has installed an epoch, the Station's signed snapshot confirms no
//! accepted genesis exists, and nothing authoritative has arrived yet. The
//! third one is not a licence to guess.

use arkret_models_crypto::MlsGroupStateRecord;

use crate::store::SecureKeyStoreError;

/// What this device knows about one MLS group's installed epoch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InstalledMlsEpoch {
    /// The local provider holds installed state at this epoch.
    Installed { group_id: String, epoch: u64 },
    /// An authoritative answer: this endpoint has no accepted MLS genesis, so
    /// this scope is still plaintext.
    NoAcceptedGenesis,
    /// Nothing authoritative has been delivered yet. Never collapse this into
    /// [`Self::NoAcceptedGenesis`]: "not delivered" is not "definitely none".
    Pending,
}

impl InstalledMlsEpoch {
    pub fn epoch(&self) -> Option<u64> {
        match self {
            Self::Installed { epoch, .. } => Some(*epoch),
            _ => None,
        }
    }

    pub fn is_encrypted(&self) -> bool {
        matches!(self, Self::Installed { .. })
    }
}

/// Read the installed epoch from durable local provider state.
///
/// `genesis_accepted` is the Station-confirmed answer for this endpoint:
/// `Some(false)` is authoritative, `None` means not delivered yet.
pub fn installed_mls_epoch(
    local_state: Option<&MlsGroupStateRecord>,
    genesis_accepted: Option<bool>,
) -> InstalledMlsEpoch {
    match (local_state, genesis_accepted) {
        (Some(state), _) => InstalledMlsEpoch::Installed {
            group_id: state.group_id.as_str().to_owned(),
            epoch: state.epoch,
        },
        (None, Some(false)) => InstalledMlsEpoch::NoAcceptedGenesis,
        (None, _) => InstalledMlsEpoch::Pending,
    }
}

/// Readiness of the MLS runtime on this device.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MlsRuntimeStatus {
    Ready,
    Pending(String),
    RecoveryRequired(String),
    Denied(String),
    MissingWelcome,
    MissingDeviceSecret(String),
    CheckpointRestoreFailed(String),
}

impl MlsRuntimeStatus {
    pub fn user_message(&self) -> String {
        match self {
            Self::Ready => "MLS state ready".to_owned(),
            Self::Pending(reason) => format!("MLS state is not converged yet: {reason}"),
            Self::RecoveryRequired(reason) => format!("MLS recovery is required: {reason}"),
            Self::Denied(reason) => format!("MLS operation was denied: {reason}"),
            Self::MissingWelcome => {
                "MLS state is not ready on this device yet; wait for the Welcome delivery that accompanies the next accepted Commit.".to_owned()
            }
            Self::MissingDeviceSecret(reason) => {
                format!("device MLS secret unavailable: {reason}")
            }
            Self::CheckpointRestoreFailed(reason) => {
                format!("the stored MLS checkpoint could not be restored ({reason}); restore this device from its encrypted key backup.")
            }
        }
    }
}

/// Failures the MLS client paths report, each mapped to one status.
#[derive(Debug)]
pub enum MlsRuntimeError {
    EmptyPlaintext,
    MissingWelcome,
    DeviceSecret(SecureKeyStoreError),
    Identity(String),
    Genesis(String),
    Welcome(String),
    CheckpointRestore(String),
    /// The Station-confirmed roster differs from the installed local group, or
    /// a verified binding transition is still pending. Encrypted writes pause
    /// instead of riding the old epoch.
    EncryptionTransitionPending,
    Commit(String),
    Encrypt(String),
    Decrypt(String),
    Backup(String),
    BackupDecode(String),
    Serialize(String),
    Export(String),
}

impl MlsRuntimeError {
    pub fn status(&self) -> MlsRuntimeStatus {
        match self {
            Self::EmptyPlaintext => MlsRuntimeStatus::Denied("plaintext is empty".to_owned()),
            Self::MissingWelcome => MlsRuntimeStatus::MissingWelcome,
            Self::DeviceSecret(error) => MlsRuntimeStatus::MissingDeviceSecret(error.to_string()),
            Self::Identity(reason) | Self::Welcome(reason) | Self::CheckpointRestore(reason) => {
                MlsRuntimeStatus::CheckpointRestoreFailed(reason.clone())
            }
            Self::Genesis(reason) | Self::Commit(reason) => {
                MlsRuntimeStatus::Pending(reason.clone())
            }
            Self::EncryptionTransitionPending => {
                MlsRuntimeStatus::Pending("encryption transition".to_owned())
            }
            Self::Backup(reason) | Self::BackupDecode(reason) => {
                MlsRuntimeStatus::RecoveryRequired(reason.clone())
            }
            Self::Encrypt(reason)
            | Self::Decrypt(reason)
            | Self::Serialize(reason)
            | Self::Export(reason) => MlsRuntimeStatus::Denied(reason.clone()),
        }
    }

    pub fn user_message(&self) -> String {
        self.status().user_message()
    }
}

#[cfg(test)]
mod tests {
    use arkret_models_crypto::MlsEndpointIdentity;
    use arkret_wire::{AccountId, ActorId, DidCoreId, MlsGroupId};

    use super::*;
    use crate::test_fixtures::{at, device_id};

    const GROUP_ID: &str = "QjKOSorlqs3IquY7OikTUTy_Z0mMiL0X2mK4jAOT4R4";

    fn state(epoch: u64) -> MlsGroupStateRecord {
        let principal_id = DidCoreId::new("ak:did_core:web:alice.example").unwrap();
        MlsGroupStateRecord {
            group_id: MlsGroupId::new(GROUP_ID).unwrap(),
            actor_id: ActorId::account(AccountId::new(
                principal_id.clone(),
                DidCoreId::new("ak:did_core:web:station.example").unwrap(),
            )),
            endpoint: MlsEndpointIdentity::human_device(principal_id, device_id()),
            epoch,
            serialized_state: vec![1, 2, 3],
            updated_at: at(0),
        }
    }

    #[test]
    fn installed_local_state_reports_its_epoch() {
        assert_eq!(
            installed_mls_epoch(Some(&state(7)), None),
            InstalledMlsEpoch::Installed {
                group_id: GROUP_ID.to_owned(),
                epoch: 7
            }
        );
    }

    #[test]
    fn an_undelivered_answer_never_masquerades_as_no_genesis() {
        assert_eq!(installed_mls_epoch(None, None), InstalledMlsEpoch::Pending);
        assert_eq!(
            installed_mls_epoch(None, Some(false)),
            InstalledMlsEpoch::NoAcceptedGenesis
        );
        assert!(!InstalledMlsEpoch::Pending.is_encrypted());
    }

    #[test]
    fn a_missing_device_secret_is_reported_as_its_own_status() {
        let error = MlsRuntimeError::DeviceSecret(SecureKeyStoreError::NotFound);
        assert!(matches!(
            error.status(),
            MlsRuntimeStatus::MissingDeviceSecret(_)
        ));
        assert!(error.user_message().contains("device MLS secret"));
    }

    #[test]
    fn a_pending_encryption_transition_never_reads_as_ready() {
        assert_eq!(
            MlsRuntimeError::EncryptionTransitionPending.status(),
            MlsRuntimeStatus::Pending("encryption transition".to_owned())
        );
    }
}
