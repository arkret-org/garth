//! Shared MLS admission, checkpoints and runtime helpers.

pub mod accepted_artifact;
pub mod backup_selection;
pub mod backup_series;
pub mod checkpoint;
pub mod checkpoint_port;
pub mod content_history;
pub mod content_roots;
pub mod creator;
pub mod key_package;
pub mod membership;
pub mod self_preservation;
pub mod status;
pub mod welcome_admission;

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
    LocalMlsEndpoint, WelcomeClaimAuthority, admit_welcome, mls_group_id_for_realm,
    mls_group_id_for_scope, retain_admissible_welcomes, signed_welcome_consume,
    verify_welcome_claim, welcome_matches_endpoint,
};

/// What one install attempt did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MlsInstallOutcome {
    /// Provider state advanced and was persisted with its accepted Event.
    Applied,
    /// This device already holds an equal-or-newer epoch for the group.
    AlreadyCurrent,
    /// The transition's base epoch is not installed yet, so it stays pending.
    BaseEpochMissing,
}
