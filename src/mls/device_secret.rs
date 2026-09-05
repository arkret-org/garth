//! Account- and device-scoped MLS checkpoint-secret management.
//!
//! The checkpoint secret is account-scoped and shared by every device of the
//! account; it is recoverable via the user's recovery passphrase. The `_local`
//! rotation helpers prepare new wrapping material without mutating local state
//! so callers can upload server-side backups before committing.

use std::collections::BTreeMap;

use arkret_wire::{AccountId, DeviceId};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use super::local_checkpoint::{self, MlsLocalCheckpointEnvelope};
use super::status::MlsRuntimeError;
use crate::store::{
    SecureKeyStore, SecureKeyStoreError, account_id_storage_digest, device_storage_digest,
};

// Secret-store key prefixes. These are at-rest addresses, not names: every
// secret already written by a shipped client lives under them, so they keep
// their original spelling after the move out of the host crate. Renaming one
// would orphan the stored secret and read as "device has no MLS material".
/// Storage-key prefix for the account-scoped checkpoint secret.
///
/// The literal keeps its original spelling for the same reason
/// [`super::local_checkpoint::MLS_ENVELOPE_MAGIC`] does: it addresses secrets
/// already written to every device's key store, so renaming it orphans them.
/// At-rest keys are not wire names.
const ACCOUNT_MLS_SECRET_PREFIX: &str = "inkson.mls_snapshot.account_secret";
const ACCOUNT_MLS_SECRET_VERIFIED_MARKER: &str = "verified";
pub const ACCOUNT_MLS_SECRET_CURRENT_VERSION: u32 = 1;
const ACCOUNT_MLS_SECRET_MAX_SCAN_VERSION: u32 = 32;
const MLS_KEY_PACKAGE_IDENTITY_STATE_PREFIX: &str = "inkson.mls_key_package.identity_state.v1";
const MLS_KEY_PACKAGE_CONSUME_REQUEST_PREFIX: &str = "inkson.mls_key_package.consume_request.v1";
const MLS_KEY_PACKAGE_INVENTORY_PREFIX: &str = "inkson.mls_key_package.inventory.v1";
const MLS_PAIRWISE_KEY_PACKAGE_PUBLISH_MARKER_PREFIX: &str =
    "inkson.mls_key_package.pairwise_publish_marker.v1";
/// Per-(account authority, device) X25519 keypair used to open HPKE-sealed history-key
/// recovery records addressed to this device.
///
/// The receiver should eventually advertise (and open with)
/// the X25519 init-key private half of its published MLS KeyPackage so a
/// source can seal proactively at admission time from the claim alone.
/// OpenMLS does not surface that raw private scalar through the current SDK,
/// so we mint a dedicated, persisted device HPKE keypair instead. A history-key
/// request binds the corresponding public key through its sealed response capability.
const DEVICE_HPKE_PRIVATE_KEY_PREFIX: &str = "inkson.device_hpke_x25519.private.v1";

/// Stored account-scoped MLS checkpoint secret plus the local key version that
/// carried it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredAccountMlsSecret {
    pub version: u32,
    pub secret: String,
}

/// Local account-scoped secret rotation material. The network upload path uses
/// `new_secret` to wrap the new account-secret backup, then commits this
/// material locally once the server-side backups have landed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountMlsSecretRotation {
    pub previous_version: u32,
    pub new_version: u32,
    pub new_secret: String,
    pub rewrapped_checkpoints: BTreeMap<String, MlsLocalCheckpointEnvelope>,
    /// COR-12: realms whose checkpoint could not be decrypted with the previous
    /// secret (corrupt / format-drifted local data) and were therefore SKIPPED
    /// instead of aborting the whole rotation. `(realm_id, error)` pairs so the
    /// caller can surface a partial-success report. Empty on a clean rotation.
    pub failed_realms: Vec<(String, String)>,
}

/// Account-scoped storage key for a specific MLS checkpoint-secret version.
pub fn account_mls_secret_key_for_version(
    authority: &AccountId,
    version: u32,
) -> Result<String, SecureKeyStoreError> {
    let authority_digest = account_id_storage_digest(authority)?;
    Ok(format!(
        "{ACCOUNT_MLS_SECRET_PREFIX}.v{version}.{authority_digest}"
    ))
}

/// Default write key for the account-scoped MLS checkpoint secret shared by every
/// device of the account. Recoverable via the user's recovery passphrase.
pub fn account_mls_secret_key(authority: &AccountId) -> Result<String, SecureKeyStoreError> {
    account_mls_secret_key_for_version(authority, ACCOUNT_MLS_SECRET_CURRENT_VERSION)
}

fn validate_account_secret(secret: &str) -> Result<(), SecureKeyStoreError> {
    if secret.trim().is_empty() {
        return Err(SecureKeyStoreError::Backend(
            "account MLS secret must not be empty".to_owned(),
        ));
    }
    Ok(())
}

/// Store (or overwrite) a specific version of the account-scoped MLS checkpoint
/// secret.
pub fn store_account_mls_secret_version(
    store: &dyn SecureKeyStore,
    authority: &AccountId,
    version: u32,
    secret: &str,
) -> Result<(), SecureKeyStoreError> {
    if version == 0 || version > ACCOUNT_MLS_SECRET_MAX_SCAN_VERSION {
        return Err(SecureKeyStoreError::Backend(format!(
            "account MLS secret version {version} is outside the supported scan range"
        )));
    }
    validate_account_secret(secret)?;
    store.store_secret(
        &account_mls_secret_key_for_version(authority, version)?,
        secret,
    )
}

/// Replace all locally-known account MLS secret versions with one recovered
/// from the server backup.
///
/// Recovery must win over a stale local secret that may have been generated by
/// a previous incomplete bootstrap. Since [`load_account_mls_secret`] picks the
/// highest version, keeping a newer-but-wrong local version would make the
/// recovered backup ineffective.
pub fn replace_account_mls_secret_version(
    store: &dyn SecureKeyStore,
    authority: &AccountId,
    version: u32,
    secret: &str,
) -> Result<(), SecureKeyStoreError> {
    if version == 0 || version > ACCOUNT_MLS_SECRET_MAX_SCAN_VERSION {
        return Err(SecureKeyStoreError::Backend(format!(
            "account MLS secret version {version} is outside the supported scan range"
        )));
    }
    validate_account_secret(secret)?;
    store.store_secret(
        &account_mls_secret_key_for_version(authority, version)?,
        secret,
    )?;
    for existing_version in 1..=ACCOUNT_MLS_SECRET_MAX_SCAN_VERSION {
        if existing_version != version {
            store.delete_secret(&account_mls_secret_key_for_version(
                authority,
                existing_version,
            )?)?;
        }
    }
    Ok(())
}

/// Store (or overwrite) the default/current account-scoped MLS checkpoint secret.
/// Used by [`load_or_create_account_mls_secret`] on first creation and by the
/// recovery import path after unwrapping the recovery vault.
pub fn store_account_mls_secret(
    store: &dyn SecureKeyStore,
    authority: &AccountId,
    secret: &str,
) -> Result<(), SecureKeyStoreError> {
    store_account_mls_secret_version(store, authority, ACCOUNT_MLS_SECRET_CURRENT_VERSION, secret)
}

/// Load the highest local account-secret version currently present.
pub fn load_account_mls_secret(
    store: &dyn SecureKeyStore,
    authority: &AccountId,
) -> Result<Option<StoredAccountMlsSecret>, SecureKeyStoreError> {
    for version in (1..=ACCOUNT_MLS_SECRET_MAX_SCAN_VERSION).rev() {
        let key = account_mls_secret_key_for_version(authority, version)?;
        if let Some(secret) = store.get_secret(&key)?
            && !secret.trim().is_empty()
        {
            return Ok(Some(StoredAccountMlsSecret { version, secret }));
        }
    }
    Ok(None)
}

fn account_mls_secret_verified_key(authority: &AccountId) -> Result<String, SecureKeyStoreError> {
    let authority_digest = account_id_storage_digest(authority)?;
    Ok(format!(
        "{ACCOUNT_MLS_SECRET_PREFIX}.{ACCOUNT_MLS_SECRET_VERIFIED_MARKER}.v1.{authority_digest}"
    ))
}

/// Mark the active account secret as proven to belong to the server recovery
/// chain. Only a successful backup upload or recovery import may set this.
pub fn mark_account_mls_secret_verified(
    store: &dyn SecureKeyStore,
    authority: &AccountId,
) -> Result<(), SecureKeyStoreError> {
    store.store_secret(&account_mls_secret_verified_key(authority)?, "verified")
}

/// Whether this device has proved that its local account secret belongs to
/// the server recovery chain. A freshly generated bootstrap secret is false.
pub fn account_mls_secret_verified(
    store: &dyn SecureKeyStore,
    authority: &AccountId,
) -> Result<bool, SecureKeyStoreError> {
    Ok(store
        .get_secret(&account_mls_secret_verified_key(authority)?)?
        .as_deref()
        == Some("verified"))
}

fn generate_account_mls_secret() -> Result<String, SecureKeyStoreError> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes)
        .map_err(|err| SecureKeyStoreError::Backend(format!("getrandom: {err}")))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

/// Load (or create) the account-scoped MLS checkpoint secret.
///
/// Resolution order:
///   a. the highest existing versioned account secret is returned as-is;
///   b. otherwise a fresh random 32-byte secret is generated, stored under the
///      current account key, and returned.
pub fn load_or_create_account_mls_secret(
    store: &dyn SecureKeyStore,
    authority: &AccountId,
) -> Result<String, SecureKeyStoreError> {
    if let Some(existing) = load_account_mls_secret(store, authority)? {
        return Ok(existing.secret);
    }
    let secret = generate_account_mls_secret()?;
    store_account_mls_secret(store, authority, &secret)?;
    Ok(secret)
}

/// Load-or-create the account MLS secret and await its durable persistence.
///
/// [`load_or_create_account_mls_secret`] writes through the sync store surface;
/// on wasm the IndexedDB commit behind that write is a detached background task
/// that a page unload silently drops. State persisted under this secret
/// (the creator's epoch-0 checkpoint, a first applied Welcome) goes through the
/// durable-awaiting account-state writer, so the secret could reach disk AFTER
/// the checkpoint it wraps — or never. A reload in that window leaves a checkpoint
/// no local secret can open, which reads as "no account MLS secret" and
/// dead-locks every later encrypted write on this device. Callers that are
/// about to persist secret-wrapped state must use this variant so the secret
/// is durably stored first.
pub async fn ensure_account_mls_secret_durable(
    store: &dyn SecureKeyStore,
    authority: &AccountId,
) -> Result<String, SecureKeyStoreError> {
    if let Some(existing) = load_account_mls_secret(store, authority)? {
        // Re-commit the already-visible value: if the creation-time background
        // write was lost to an unload, this is the retry that lands it.
        store
            .store_secret_durable(
                &account_mls_secret_key_for_version(authority, existing.version)?,
                &existing.secret,
            )
            .await?;
        return Ok(existing.secret);
    }
    let secret = generate_account_mls_secret()?;
    store
        .store_secret_durable(&account_mls_secret_key(authority)?, &secret)
        .await?;
    // Concurrent first-creation is last-write-wins on the store; re-read so
    // every caller converges on the value that actually landed.
    if let Some(landed) = load_account_mls_secret(store, authority)? {
        return Ok(landed.secret);
    }
    Ok(secret)
}

/// Re-commit an existing account MLS secret durably without creating one.
///
/// Returning devices and Welcome consumers must recover the account recovery
/// unit when the secret is absent. Minting here would create a second wrapping
/// root that cannot open the account's existing snapshots or backups.
pub async fn ensure_existing_account_mls_secret_durable(
    store: &dyn SecureKeyStore,
    authority: &AccountId,
) -> Result<String, SecureKeyStoreError> {
    let existing =
        load_account_mls_secret(store, authority)?.ok_or(SecureKeyStoreError::NotFound)?;
    store
        .store_secret_durable(
            &account_mls_secret_key_for_version(authority, existing.version)?,
            &existing.secret,
        )
        .await?;
    Ok(existing.secret)
}

pub fn mls_key_package_identity_state_key(
    authority: &AccountId,
    device_id: &DeviceId,
    key_package_id: &str,
) -> Result<String, SecureKeyStoreError> {
    let key_package = key_package_id.trim();
    if key_package.is_empty() {
        return Err(SecureKeyStoreError::Backend(
            "key_package_id is required for MLS KeyPackage identity state".to_owned(),
        ));
    }
    let scope = account_device_storage_suffix(authority, device_id)?;
    let key_package = secure_key_component(key_package, "key_package_id")?;
    Ok(format!(
        "{MLS_KEY_PACKAGE_IDENTITY_STATE_PREFIX}.{scope}.{key_package}"
    ))
}

/// Durable exact-replay slot for one KeyPackage claim's signed consume body.
///
/// The service's idempotency key is `claim_id`: once a consume body has been
/// accepted, changing even `durable_at` makes a later delivery a conflicting
/// request. Keep the first signed body scoped to the exact account and device
/// so Welcome redelivery can resend identical canonical bytes after restart.
pub fn mls_key_package_consume_request_key(
    authority: &AccountId,
    device_id: &DeviceId,
    claim_id: &str,
) -> Result<String, SecureKeyStoreError> {
    let scope = account_device_storage_suffix(authority, device_id)?;
    let claim = secure_key_component(claim_id, "claim_id")?;
    Ok(format!(
        "{MLS_KEY_PACKAGE_CONSUME_REQUEST_PREFIX}.{scope}.{claim}"
    ))
}

/// Non-durable KeyPackage identity-state write.
///
/// Production writes go through [`store_mls_key_package_identity_state_durable`]:
/// publishing a KeyPackage whose private identity state is not yet committed
/// strands the claimer. This synchronous form exists for host test fixtures that
/// seed the store outside an async context, which is why it is public rather
/// than `#[cfg(test)]` — the fixtures live in the consuming crate.
pub fn store_mls_key_package_identity_state(
    store: &dyn SecureKeyStore,
    authority: &AccountId,
    device_id: &DeviceId,
    key_package_id: &str,
    serialized_state: &[u8],
) -> Result<(), SecureKeyStoreError> {
    if serialized_state.is_empty() {
        return Err(SecureKeyStoreError::Backend(
            "MLS KeyPackage identity state must not be empty".to_owned(),
        ));
    }
    let key = mls_key_package_identity_state_key(authority, device_id, key_package_id)?;
    let encoded = URL_SAFE_NO_PAD.encode(serialized_state);
    store.store_secret(&key, &encoded)
}

/// Durable variant of the KeyPackage identity-state write. Production must use
/// this one: a published KeyPackage whose private identity state is not yet
/// committed strands the claimer.
pub async fn store_mls_key_package_identity_state_durable(
    store: &dyn SecureKeyStore,
    authority: &AccountId,
    device_id: &DeviceId,
    key_package_id: &str,
    serialized_state: &[u8],
) -> Result<(), SecureKeyStoreError> {
    if serialized_state.is_empty() {
        return Err(SecureKeyStoreError::Backend(
            "MLS KeyPackage identity state must not be empty".to_owned(),
        ));
    }
    let key = mls_key_package_identity_state_key(authority, device_id, key_package_id)?;
    store
        .store_secret_durable(&key, &URL_SAFE_NO_PAD.encode(serialized_state))
        .await
}

pub fn load_mls_key_package_identity_state(
    store: &dyn SecureKeyStore,
    authority: &AccountId,
    device_id: &DeviceId,
    key_package_id: &str,
) -> Result<Option<Vec<u8>>, SecureKeyStoreError> {
    let key = mls_key_package_identity_state_key(authority, device_id, key_package_id)?;
    let secret = store.get_secret(&key)?;
    let Some(secret) = secret else {
        return Ok(None);
    };
    let trimmed = secret.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    URL_SAFE_NO_PAD
        .decode(trimmed.as_bytes())
        .map(Some)
        .map_err(|err| {
            SecureKeyStoreError::Backend(format!("decode MLS KeyPackage identity state: {err}"))
        })
}

pub fn delete_mls_key_package_identity_state(
    store: &dyn SecureKeyStore,
    authority: &AccountId,
    device_id: &DeviceId,
    key_package_id: &str,
) -> Result<(), SecureKeyStoreError> {
    let key = mls_key_package_identity_state_key(authority, device_id, key_package_id)?;
    store.delete_secret(&key)
}

fn secure_key_component(value: &str, label: &str) -> Result<String, SecureKeyStoreError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(SecureKeyStoreError::Backend(format!(
            "{label} is required for MLS KeyPackage publish marker"
        )));
    }
    Ok(URL_SAFE_NO_PAD.encode(trimmed.as_bytes()))
}

fn account_device_storage_suffix(
    authority: &AccountId,
    device_id: &DeviceId,
) -> Result<String, SecureKeyStoreError> {
    let authority = account_id_storage_digest(authority)?;
    let device = device_storage_digest(device_id);
    Ok(format!("{authority}.{device}"))
}

pub fn mls_key_package_inventory_key(
    authority: &AccountId,
    device_id: &DeviceId,
) -> Result<String, SecureKeyStoreError> {
    let scope = account_device_storage_suffix(authority, device_id)?;
    Ok(format!("{MLS_KEY_PACKAGE_INVENTORY_PREFIX}.{scope}"))
}

pub fn store_mls_key_package_inventory(
    store: &dyn SecureKeyStore,
    authority: &AccountId,
    device_id: &DeviceId,
    inventory: &arkret_models_crypto::LocalMlsKeyPackageInventory,
) -> Result<(), SecureKeyStoreError> {
    let key = mls_key_package_inventory_key(authority, device_id)?;
    let encoded = serde_json::to_string(inventory)
        .map_err(|error| SecureKeyStoreError::Backend(error.to_string()))?;
    store.store_secret(&key, &encoded)
}

pub fn load_mls_key_package_inventory(
    store: &dyn SecureKeyStore,
    authority: &AccountId,
    device_id: &DeviceId,
) -> Result<arkret_models_crypto::LocalMlsKeyPackageInventory, SecureKeyStoreError> {
    let key = mls_key_package_inventory_key(authority, device_id)?;
    let Some(encoded) = store.get_secret(&key)? else {
        return Ok(arkret_models_crypto::LocalMlsKeyPackageInventory {
            endpoint: arkret_models_crypto::MlsEndpointIdentity::human_device(
                authority.principal_id.clone(),
                device_id.clone(),
            ),
            entries: std::collections::BTreeMap::new(),
        });
    };
    let inventory: arkret_models_crypto::LocalMlsKeyPackageInventory =
        serde_json::from_str(&encoded).map_err(|error| {
            SecureKeyStoreError::Backend(format!("invalid MLS inventory: {error}"))
        })?;
    let expected = arkret_models_crypto::MlsEndpointIdentity::human_device(
        authority.principal_id.clone(),
        device_id.clone(),
    );
    if inventory.endpoint != expected {
        return Err(SecureKeyStoreError::Backend(
            "MLS inventory endpoint does not match the active authority and device".to_owned(),
        ));
    }
    Ok(inventory)
}

pub fn mls_pairwise_key_package_publish_marker_key(
    authority: &AccountId,
    device_id: &DeviceId,
    realm_id: &arkret_wire::RealmId,
) -> Result<String, SecureKeyStoreError> {
    let scope = account_device_storage_suffix(authority, device_id)?;
    let realm = secure_key_component(realm_id.as_str(), "realm_id")?;
    Ok(format!(
        "{MLS_PAIRWISE_KEY_PACKAGE_PUBLISH_MARKER_PREFIX}.{scope}.{realm}"
    ))
}

pub fn store_mls_pairwise_key_package_publish_marker(
    store: &dyn SecureKeyStore,
    authority: &AccountId,
    device_id: &DeviceId,
    realm_id: &arkret_wire::RealmId,
    key_package_id: &str,
) -> Result<(), SecureKeyStoreError> {
    let key_package_id = key_package_id.trim();
    if key_package_id.is_empty() {
        return Err(SecureKeyStoreError::Backend(
            "key_package_id is required for pairwise MLS KeyPackage publish marker".to_owned(),
        ));
    }
    let key = mls_pairwise_key_package_publish_marker_key(authority, device_id, realm_id)?;
    store.store_secret(&key, key_package_id)
}

pub fn load_mls_pairwise_key_package_publish_marker(
    store: &dyn SecureKeyStore,
    authority: &AccountId,
    device_id: &DeviceId,
    realm_id: &arkret_wire::RealmId,
) -> Result<Option<String>, SecureKeyStoreError> {
    let key = mls_pairwise_key_package_publish_marker_key(authority, device_id, realm_id)?;
    Ok(store
        .get_secret(&key)?
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty()))
}

pub fn delete_mls_pairwise_key_package_publish_marker(
    store: &dyn SecureKeyStore,
    authority: &AccountId,
    device_id: &DeviceId,
    realm_id: &arkret_wire::RealmId,
) -> Result<(), SecureKeyStoreError> {
    let key = mls_pairwise_key_package_publish_marker_key(authority, device_id, realm_id)?;
    store.delete_secret(&key)
}

/// Load (without creating) the snapshot secret for an account authority.
///
/// Delegates to the account-scoped secret. `device_id` no longer scopes the
/// stored key.
pub fn load_device_checkpoint_secret(
    store: &dyn SecureKeyStore,
    authority: &AccountId,
    _device_id: &DeviceId,
) -> Result<String, SecureKeyStoreError> {
    if let Some(existing) = load_account_mls_secret(store, authority)? {
        return Ok(existing.secret);
    }
    Err(SecureKeyStoreError::NotFound)
}

/// Prepare a local account-secret rotation without mutating local state.
///
/// Each persisted MLS snapshot is decrypted with the current account secret and
/// re-encrypted with a newly-generated secret. Callers upload the returned
/// backups first, then call [`commit_account_mls_secret_rotation`] so local
/// state and the secret store advance together.
pub fn prepare_account_mls_secret_rotation(
    store: &dyn SecureKeyStore,
    authority: &AccountId,
    snapshots: &BTreeMap<String, MlsLocalCheckpointEnvelope>,
) -> Result<AccountMlsSecretRotation, MlsRuntimeError> {
    let previous_secret = load_account_mls_secret(store, authority)
        .map_err(MlsRuntimeError::DeviceSecret)?
        .ok_or(MlsRuntimeError::DeviceSecret(SecureKeyStoreError::NotFound))?;
    let new_version = previous_secret
        .version
        .saturating_add(1)
        .max(ACCOUNT_MLS_SECRET_CURRENT_VERSION);
    if new_version > ACCOUNT_MLS_SECRET_MAX_SCAN_VERSION {
        return Err(MlsRuntimeError::DeviceSecret(SecureKeyStoreError::Backend(
            format!("account MLS secret version {new_version} exceeds supported scan range"),
        )));
    }
    let new_secret = generate_account_mls_secret().map_err(MlsRuntimeError::DeviceSecret)?;
    let mut rewrapped_checkpoints = BTreeMap::new();
    let mut failed_realms = Vec::new();
    for (realm_id, snapshot) in snapshots {
        // COR-12: one corrupt / format-drifted realm snapshot MUST NOT block the
        // rotation of every other realm (and the recovery / re-wrap flows that
        // depend on it). Record the failure and skip, mirroring the welcome-apply
        // path's "per-item failure does not abort the batch" model. The secret
        // still rotates for all decryptable realms.
        let plaintext = match local_checkpoint::decrypt_envelope(snapshot, &previous_secret.secret)
        {
            Ok(plaintext) => plaintext,
            Err(err) => {
                tracing::warn!(
                    %realm_id,
                    error = %err,
                    "skip realm during account-secret rotation: snapshot did not decrypt with previous secret"
                );
                failed_realms.push((realm_id.clone(), err.to_string()));
                continue;
            }
        };
        let mut salt = [0u8; 16];
        getrandom::fill(&mut salt).map_err(|err| MlsRuntimeError::Salt(err.to_string()))?;
        // Re-wrapping does not advance the epoch — carry the epoch-start clock
        // so a secret rotation never resets the §2.9 minimal-metadata 1h cap.
        let rotated = local_checkpoint::encrypt_state(
            &snapshot.realm_id,
            &snapshot.group_id,
            snapshot.epoch,
            &plaintext,
            &new_secret,
            &salt,
        )
        .carry_epoch_started_at(snapshot);
        rewrapped_checkpoints.insert(realm_id.clone(), rotated);
    }
    Ok(AccountMlsSecretRotation {
        previous_version: previous_secret.version,
        new_version,
        new_secret,
        rewrapped_checkpoints,
        failed_realms,
    })
}

/// Storage key for this device's history-recovery HPKE X25519 private key.
fn device_hpke_private_key_key(
    authority: &AccountId,
    device_id: &DeviceId,
) -> Result<String, SecureKeyStoreError> {
    let scope = account_device_storage_suffix(authority, device_id)?;
    Ok(format!("{DEVICE_HPKE_PRIVATE_KEY_PREFIX}.{scope}"))
}

/// Generate this device's HPKE X25519 keypair and await the private-key commit.
///
/// Unconditional: it always mints and stores fresh material. The host composes
/// it with [`load_device_hpke_keypair`] under its own single-flight guard,
/// because "only one creator wins" needs an async lock from the host runtime
/// and this crate binds no runtime. Advertising the public half before the
/// private half is durable would strand a peer's ciphertext, so the durable
/// write is awaited here.
pub async fn create_device_hpke_keypair_durable(
    store: &dyn SecureKeyStore,
    authority: &AccountId,
    device_id: &DeviceId,
) -> Result<DeviceHpkeKeypair, SecureKeyStoreError> {
    let key = device_hpke_private_key_key(authority, device_id)?;
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed)
        .map_err(|error| SecureKeyStoreError::Backend(format!("getrandom: {error}")))?;
    let private_key = seed.to_vec();
    let public_key = x25519_public_from_private(&private_key)?;
    store
        .store_secret_durable(&key, &URL_SAFE_NO_PAD.encode(&private_key))
        .await?;
    Ok((private_key, public_key))
}

/// A raw X25519 keypair as `(private, public)` bytes.
pub type DeviceHpkeKeypair = (Vec<u8>, Vec<u8>);

/// The stored device HPKE keypair, when this device already has one.
pub fn load_device_hpke_keypair(
    store: &dyn SecureKeyStore,
    authority: &AccountId,
    device_id: &DeviceId,
) -> Result<Option<DeviceHpkeKeypair>, SecureKeyStoreError> {
    let Some(private_key) = load_device_hpke_private_key(store, authority, device_id)? else {
        return Ok(None);
    };
    let public_key = x25519_public_from_private(&private_key)?;
    Ok(Some((private_key, public_key)))
}

/// Load (without creating) this device's HPKE X25519 private key, if present.
pub fn load_device_hpke_private_key(
    store: &dyn SecureKeyStore,
    authority: &AccountId,
    device_id: &DeviceId,
) -> Result<Option<Vec<u8>>, SecureKeyStoreError> {
    let key = device_hpke_private_key_key(authority, device_id)?;
    let Some(secret) = store.get_secret(&key)? else {
        return Ok(None);
    };
    let trimmed = secret.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    URL_SAFE_NO_PAD
        .decode(trimmed.as_bytes())
        .map(Some)
        .map_err(|err| {
            SecureKeyStoreError::Backend(format!("decode device HPKE private key: {err}"))
        })
}

/// Derive the raw 32-byte X25519 public key for a raw 32-byte private key.
pub fn x25519_public_from_private(private_key: &[u8]) -> Result<Vec<u8>, SecureKeyStoreError> {
    let scalar: [u8; 32] = private_key.try_into().map_err(|_| {
        SecureKeyStoreError::Backend(format!(
            "device HPKE private key must be 32 bytes, got {}",
            private_key.len()
        ))
    })?;
    let secret = x25519_dalek::StaticSecret::from(scalar);
    let public = x25519_dalek::PublicKey::from(&secret);
    Ok(public.as_bytes().to_vec())
}

#[cfg(test)]
mod tests;
