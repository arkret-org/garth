//! Typed MLS-runtime readiness status and error surface.

use crate::store::SecureKeyStoreError;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MlsRuntimeStatus {
    Ready,
    Pending(String),
    RecoveryRequired(String),
    Denied(String),
    MissingWelcome,
    MissingDeviceSecret(String),
    SnapshotDecryptFailed(String),
    UnsupportedTarget,
}

impl MlsRuntimeStatus {
    pub fn user_message(&self) -> String {
        match self {
            Self::Ready => "MLS state ready".to_owned(),
            Self::Pending(reason) => format!("MLS state convergence is pending: {reason}"),
            Self::RecoveryRequired(reason) => format!("MLS recovery is required: {reason}"),
            Self::Denied(reason) => format!("MLS operation was denied: {reason}"),
            Self::MissingWelcome => {
                "MLS state is not ready on this device yet; wait for an MLS Welcome or restore this device's encrypted MLS history backup.".to_owned()
            }
            Self::MissingDeviceSecret(reason) => {
                format!("device MLS snapshot secret unavailable: {reason}")
            }
            Self::SnapshotDecryptFailed(reason) => {
                format!("stored MLS history could not be decrypted ({reason}); restore your encrypted MLS history with your 24-word Recovery Key.")
            }
            Self::UnsupportedTarget => {
                "MLS runtime unavailable (internal error)".to_owned()
            }
        }
    }
}

#[derive(Debug)]
pub enum MlsRuntimeError {
    EmptyPlaintext,
    MissingWelcome,
    DeviceSecret(SecureKeyStoreError),
    Identity(String),
    Genesis(String),
    Welcome(String),
    SnapshotRestore(String),
    /// A complete sync roster hint differs from the local MLS group, or a
    /// verified §2.4.1 binding transition is still pending. Encrypted
    /// application writes must pause instead of using the old epoch.
    EncryptionTransitionPending,
    /// §2.10: the verified current Realm content-scheme projection is not yet
    /// available. Sending must pause instead of guessing a wire scheme.
    EncryptionPolicyPending,
    Commit(String),
    Encrypt(String),
    Decrypt(String),
    Backup(String),
    BackupDecode(String),
    Serialize(String),
    Export(String),
    Salt(String),
}

impl MlsRuntimeError {
    pub fn status(&self) -> MlsRuntimeStatus {
        match self {
            Self::EmptyPlaintext => MlsRuntimeStatus::Denied("plaintext is empty".to_owned()),
            Self::MissingWelcome => MlsRuntimeStatus::MissingWelcome,
            Self::DeviceSecret(err) => MlsRuntimeStatus::MissingDeviceSecret(err.to_string()),
            Self::Identity(reason) | Self::Welcome(reason) => {
                MlsRuntimeStatus::SnapshotDecryptFailed(reason.clone())
            }
            Self::SnapshotRestore(reason) => {
                MlsRuntimeStatus::SnapshotDecryptFailed(reason.clone())
            }
            Self::Genesis(reason) | Self::Commit(reason) => {
                MlsRuntimeStatus::Pending(reason.clone())
            }
            Self::EncryptionTransitionPending => {
                MlsRuntimeStatus::Pending("encryption transition".to_owned())
            }
            Self::EncryptionPolicyPending => {
                MlsRuntimeStatus::Pending("encryption policy".to_owned())
            }
            Self::Backup(reason) | Self::BackupDecode(reason) => {
                MlsRuntimeStatus::RecoveryRequired(reason.clone())
            }
            Self::Encrypt(reason)
            | Self::Decrypt(reason)
            | Self::Serialize(reason)
            | Self::Export(reason)
            | Self::Salt(reason) => MlsRuntimeStatus::Denied(reason.clone()),
        }
    }

    pub fn user_message(&self) -> String {
        match self {
            Self::EmptyPlaintext => "internal: no MLS plaintext values to encrypt".to_owned(),
            Self::MissingWelcome | Self::DeviceSecret(_) | Self::SnapshotRestore(_) => {
                self.status().user_message()
            }
            Self::Identity(reason) => format!("MLS identity unavailable: {reason}"),
            Self::Genesis(reason) => format!("MLS initial group setup failed: {reason}"),
            Self::Welcome(reason) => format!("MLS Welcome could not be applied: {reason}"),
            Self::EncryptionTransitionPending => "encryption_transition_pending: the synced Realm roster and verified local MLS group have not converged; wait for the admission commit and Welcome delivery".to_owned(),
            Self::EncryptionPolicyPending => "encryption_policy_pending: the Realm content scheme is not projected yet; wait for verified policy sync before sending".to_owned(),
            Self::Commit(reason) => format!("MLS commit failed: {reason}"),
            Self::Encrypt(reason) => format!("MLS payload encryption failed: {reason}"),
            Self::Decrypt(reason) => format!("MLS payload decryption failed: {reason}"),
            Self::Backup(reason) => format!("MLS history backup failed: {reason}"),
            Self::BackupDecode(reason) => format!("MLS history backup is invalid: {reason}"),
            Self::Serialize(reason) => {
                format!("MLS encrypted payload serialization failed: {reason}")
            }
            Self::Export(reason) => format!("MLS state export failed: {reason}"),
            Self::Salt(reason) => format!("MLS snapshot salt generation failed: {reason}"),
        }
    }
}
