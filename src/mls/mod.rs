//! Host-neutral MLS client runtime pieces.
//!
//! Everything here is decided by the protocol rather than by a host: the at-rest
//! snapshot envelope, the account-scoped snapshot-secret and KeyPackage-state
//! keying, the commit preconditions an `ak.mls.commit` MUST carry, the
//! key-backup series chain, and the readiness/error taxonomy those paths report.
//!
//! What is deliberately NOT here: anything that needs the SDK MLS engine
//! (creating, restoring or committing a live group), and anything that needs a
//! host's durable state store or transport. Those stay in the host so this
//! module keeps to `MaybeSendSync` data and the [`crate::store::SecureKeyStore`]
//! port.

pub mod backup_selection;
pub mod backup_series;
pub mod commit_preconditions;
pub mod device_secret;
pub mod local_checkpoint;
pub mod self_preservation;
pub mod status;
pub mod welcome_admission;

pub use backup_selection::{
    active_series_id_for_backup_class, all_mls_account_secret_backups, backup_created_at,
    backup_series_id, is_mls_account_secret_backup, is_mls_history_backup,
    is_mls_private_plaintext_backup, is_passphrase_account_secret_backup,
    is_recovery_public_key_account_secret_backup, iter_backup_bodies,
    latest_mls_history_backups_by_scope, mls_account_secret_backup_version,
    select_mls_account_secret_backup, select_mls_account_secret_recovery_public_key_backup,
    select_mls_history_backups, select_mls_private_plaintext_backup,
    select_preferred_mls_account_secret_backup,
};
pub use backup_series::{
    backup_series_seq, fresh_backup_id, series_supersedes_digest, verify_series_chain,
};
pub use commit_preconditions::mls_commit_preconditions;
pub use device_secret::{
    ACCOUNT_MLS_SECRET_CURRENT_VERSION, AccountMlsSecretRotation, StoredAccountMlsSecret,
    account_mls_secret_key, account_mls_secret_key_for_version, account_mls_secret_verified,
    create_device_hpke_keypair_durable, delete_mls_key_package_identity_state,
    delete_mls_pairwise_key_package_publish_marker, ensure_account_mls_secret_durable,
    ensure_existing_account_mls_secret_durable, load_account_mls_secret,
    load_device_checkpoint_secret, load_device_hpke_keypair, load_device_hpke_private_key,
    load_mls_key_package_identity_state, load_mls_key_package_inventory,
    load_mls_pairwise_key_package_publish_marker, load_or_create_account_mls_secret,
    mark_account_mls_secret_verified, mls_key_package_consume_request_key,
    mls_key_package_identity_state_key, mls_key_package_inventory_key,
    mls_pairwise_key_package_publish_marker_key, prepare_account_mls_secret_rotation,
    replace_account_mls_secret_version, store_account_mls_secret, store_account_mls_secret_version,
    store_mls_key_package_identity_state, store_mls_key_package_identity_state_durable,
    store_mls_key_package_inventory, store_mls_pairwise_key_package_publish_marker,
    x25519_public_from_private,
};
pub use local_checkpoint::{
    AEAD_VERSION_CHACHA20_POLY1305, EnvelopeError, MLS_ENVELOPE_MAGIC, MlsLocalCheckpointEnvelope,
    decrypt_envelope, decrypt_with_epoch_check, encrypt_state,
};
pub use self_preservation::{
    SELF_PRESERVATION_JITTER_SLOTS, SELF_PRESERVATION_MAX_EPOCH_AGE_DAYS,
    SELF_PRESERVATION_MAX_EPOCH_APP_MESSAGES, canonical_mls_remove_membership_frontier,
    idle_self_update_jitter_passed, should_force_epoch_advance,
};
pub use status::{MlsRuntimeError, MlsRuntimeStatus};
pub use welcome_admission::{
    AcceptedWelcomeCandidate, accepted_welcome_candidate, device_authorization_from_record,
    device_revoked, merge_accepted_welcome_candidates_for_local_endpoint,
    merge_accepted_welcomes_for_local_endpoint, mls_group_id_for_realm,
    mls_welcome_batch_is_exclusively_for_realm, mls_welcome_message_matches_realm,
    recovery_public_key_secret_storage_backup_present, recovery_setup_prompt_required,
    retain_mls_welcomes_for_realm,
};
