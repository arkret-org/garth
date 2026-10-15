//! Scope-keyed checkpoint installation. Hosts own storage, secrets and session
//! fences; the engine owns the stage -> durable -> publish ordering.

use std::future::Future;

use arkret_models_crypto::KeyPackagesConsumeRequestBody;
use arkret_wire::{EventId, ScopeRef};

use super::checkpoint::MlsLocalCheckpointEnvelope;
use crate::{Error, MaybeSend, Result};

pub fn scope_checkpoint_key(scope: &ScopeRef) -> std::result::Result<String, String> {
    String::from_utf8(
        scope
            .canonical_effective_scope_key_bytes()
            .map_err(|error| error.to_string())?,
    )
    .map_err(|error| format!("MLS scope key is not UTF-8: {error}"))
}

/// Preserve the v1 host keyspace: Realm/Circle are keyed by scope; Sidecar
/// checkpoints additionally distinguish their group incarnation.
pub fn scope_checkpoint_key_for_group(
    scope: &ScopeRef,
    group_id: &str,
) -> std::result::Result<String, String> {
    let key = scope_checkpoint_key(scope)?;
    if matches!(scope, ScopeRef::Sidecar { .. }) {
        let group_id = group_id.trim();
        if group_id.is_empty() {
            return Err("Sidecar MLS storage requires mls_group_id".into());
        }
        Ok(format!("{key}\u{1f}{group_id}"))
    } else {
        Ok(key)
    }
}

pub struct MlsCheckpointInstall {
    pub scope: ScopeRef,
    pub checkpoint: MlsLocalCheckpointEnvelope,
    pub accepted_event_id: EventId,
    /// Persist in the same unit as a joined checkpoint; send only after
    /// durability. A retry retains these exact signed bytes.
    pub consume: Option<KeyPackagesConsumeRequestBody>,
}

pub trait MlsCheckpointPort: MaybeSend {
    type Staged: MlsCheckpointStage;

    /// Capture the session fence and release every host store borrow before
    /// returning. The stage owns the host's cancellation semantics; retained
    /// checkpoint/consume tuples must never be delivered before durability.
    fn stage(self, install: MlsCheckpointInstall) -> Result<Self::Staged>;
}

pub trait MlsCheckpointStage: MaybeSend {
    fn make_durable(&mut self) -> impl Future<Output = Result<()>> + MaybeSend;

    /// Recheck the captured session before publishing readiness. A cancelled
    /// future never calls this method; a durable checkpoint may be recovered
    /// on restart without claiming it was published in the retired session.
    fn publish(self) -> Result<()>;
}

pub async fn install_checkpoint<P: MlsCheckpointPort>(
    port: P,
    install: MlsCheckpointInstall,
) -> Result<()> {
    if install.scope.realm_id_opt().map(|id| id.as_str())
        != Some(install.checkpoint.realm_id.as_str())
        || install.checkpoint.group_id.is_empty()
    {
        return Err(Error::Protocol(
            "MLS checkpoint belongs to another scope".into(),
        ));
    }
    scope_checkpoint_key_for_group(&install.scope, &install.checkpoint.group_id)
        .map_err(Error::Protocol)?;
    let mut staged = port.stage(install)?;
    staged.make_durable().await?;
    staged.publish()
}
