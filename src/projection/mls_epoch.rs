//! Reader for the installed `ak.component.mls.epoch.v1` current value.
//!
//! `current-result-registry.json` registers the family as `delivery="current"`,
//! `state_model="sequenced_state"`, `value_shape="register"` with
//! `value_mls_epoch = anyOf[null, mls_epoch_head]`. The value is the group's
//! reducer-effective winner tuple, which is where a client learns the
//! create-locked `content_scheme` after `GenesisAccepted`.
//!
//! The cell is addressed by the registered composite subject
//! `(effective scope id, mls_group_id)`, so a Realm group and every Circle
//! group inside that Realm own distinct cells and the enclosing Realm's
//! current view can carry all of them at once.

use arkret_models_crypto::MlsEpochHead;
use arkret_state::mls_cells::mls_epoch_cell_id;
use arkret_wire::ScopeRef;
use serde_json::Value;

use crate::{Error, Result};

/// What the local current view knows about one MLS group's accepted epoch.
///
/// `Pending` and `NoAcceptedGenesis` are deliberately distinct. A `null` value
/// is a delivered, confirmed answer — the Station says this group has no
/// accepted MLS Genesis — while an absent selector means the client simply has
/// not been told yet. Collapsing the two would let "not delivered" masquerade
/// as "definitely no group", which is exactly the guess the create-locked
/// binding rules forbid.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InstalledMlsEpoch {
    /// No installed value for this scope's epoch cell. Stay paused.
    Pending,
    /// Installed `null`: no accepted MLS Genesis exists for this group.
    NoAcceptedGenesis,
    /// Installed winner tuple of the group's latest accepted transition.
    Accepted(Box<MlsEpochHead>),
}

impl InstalledMlsEpoch {
    /// The group's create-locked content scheme, or `None` while the accepted
    /// binding is unknown or absent.
    pub fn content_scheme(&self) -> Option<arkret_wire::ContentScheme> {
        match self {
            Self::Accepted(head) => Some(head.content_scheme),
            Self::Pending | Self::NoAcceptedGenesis => None,
        }
    }
}

/// Read the installed `ak.component.mls.epoch.v1` value for `effective_scope`
/// out of its enclosing Realm's projection body.
pub fn installed_mls_epoch(body: &Value, effective_scope: &ScopeRef) -> Result<InstalledMlsEpoch> {
    let mls_group_id = effective_scope
        .canonical_mls_group_id()
        .map_err(|error| Error::Protocol(format!("MLS epoch scope has no group id: {error}")))?;
    let cell = mls_epoch_cell_id(effective_scope, &mls_group_id)
        .map_err(|error| Error::Protocol(format!("MLS epoch cell id invalid: {error:?}")))?;
    let Some(value) = super::installed_scoped_cell_value(body, effective_scope, cell.as_str())
    else {
        return Ok(InstalledMlsEpoch::Pending);
    };
    if value.is_null() {
        return Ok(InstalledMlsEpoch::NoAcceptedGenesis);
    }
    let head: MlsEpochHead = serde_json::from_value(value.clone()).map_err(|error| {
        Error::Protocol(format!("installed MLS epoch head is invalid: {error}"))
    })?;
    head.validate().map_err(|error| {
        Error::Protocol(format!("installed MLS epoch head is invalid: {error}"))
    })?;
    if head.effective_scope != *effective_scope || head.mls_group_id.as_str() != mls_group_id {
        return Err(Error::Protocol(
            "installed MLS epoch head names a different group".to_owned(),
        ));
    }
    Ok(InstalledMlsEpoch::Accepted(Box::new(head)))
}

#[cfg(test)]
mod tests {
    use arkret_wire::{CircleId, RealmId};
    use serde_json::json;

    use super::*;

    const REALM: &str = "ak:realm:AYw-PHWIOTuZhm-EenZx-cCbOziC8pNCrh10oRfqiEmN";
    const CIRCLE: &str = "ak:circle:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
    const EVENT: &str = "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";

    fn realm_scope() -> ScopeRef {
        ScopeRef::Realm {
            realm_id: RealmId::new(REALM).unwrap(),
        }
    }

    fn circle_scope() -> ScopeRef {
        ScopeRef::Circle {
            realm_id: RealmId::new(REALM).unwrap(),
            circle_id: CircleId::new(CIRCLE).unwrap(),
        }
    }

    fn entry(scope: &ScopeRef, value: Value) -> Value {
        let group_id = scope.canonical_mls_group_id().unwrap();
        json!({
            "selector": {"scope_ref": scope, "cell_id": mls_epoch_cell_id(scope, &group_id).unwrap()},
            "target": {"kind": "realm"},
            "revision": 1,
            "result": {"status": "value", "value": value},
        })
    }

    fn head(scope: &ScopeRef, content_scheme: &str) -> Value {
        let transition_ref = arkret_wire::EventId::new(EVENT).unwrap();
        let digest = transition_ref.event_digest();
        json!({
            "transition_ref": transition_ref,
            "transition_event_digest": digest,
            "mls_transition_digest": digest,
            "effective_scope": scope,
            "mls_group_id": scope.canonical_mls_group_id().unwrap(),
            "previous_epoch": 0,
            "next_epoch": 0,
            "content_scheme": content_scheme,
        })
    }

    #[test]
    fn an_absent_selector_is_pending_and_a_null_value_is_not() {
        let empty = json!({"current": {"entries": []}});
        assert_eq!(
            installed_mls_epoch(&empty, &realm_scope()).unwrap(),
            InstalledMlsEpoch::Pending
        );
        let delivered = json!({"current": {"entries": [entry(&realm_scope(), Value::Null)]}});
        assert_eq!(
            installed_mls_epoch(&delivered, &realm_scope()).unwrap(),
            InstalledMlsEpoch::NoAcceptedGenesis
        );
        assert_eq!(
            installed_mls_epoch(&delivered, &realm_scope())
                .unwrap()
                .content_scheme(),
            None
        );
    }

    #[test]
    fn realm_and_circle_groups_read_their_own_cells() {
        let body = json!({"current": {"entries": [
            entry(&realm_scope(), head(&realm_scope(), "mls_rfc9420")),
            entry(&circle_scope(), head(&circle_scope(), "mls_exporter_aead_v1")),
        ]}});
        assert_eq!(
            installed_mls_epoch(&body, &realm_scope())
                .unwrap()
                .content_scheme(),
            Some(arkret_wire::ContentScheme::MlsRfc9420)
        );
        assert_eq!(
            installed_mls_epoch(&body, &circle_scope())
                .unwrap()
                .content_scheme(),
            Some(arkret_wire::ContentScheme::MlsExporterAeadV1)
        );
    }

    #[test]
    fn a_head_for_another_group_is_rejected_instead_of_borrowed() {
        let body = json!({"current": {"entries": [
            entry(&circle_scope(), head(&realm_scope(), "mls_exporter_aead_v1")),
        ]}});
        assert!(installed_mls_epoch(&body, &circle_scope()).is_err());
        assert_eq!(
            installed_mls_epoch(&body, &realm_scope()).unwrap(),
            InstalledMlsEpoch::Pending
        );
    }
}
