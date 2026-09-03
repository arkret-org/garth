//! MLS Governance Binding helpers (`ak.profile.mls_governance_binding.full.v1`).
//!
//! Spec: `authz/event-auth-state-resolution.md` §9.3.1 plus the registered
//! `ak.mls.commit` reducer contract. Every MLS commit MUST
//! carry preconditions binding it to:
//! 1. the previous complete MLS epoch winner tuple (`mls_epoch_cell.head_eq(previous_epoch_head)`)
//!    — racing commits fail closed.
//! 2. the previous key-schedule governance binding
//!    (`key_schedule_cell.head_eq(previous_governance_binding)`) — both CAS registers advance from
//!    an exact, accepted predecessor.
//!
//! What the commit *writes* is no longer producer-authored. v1 deleted the
//! standalone Move object and its `effects[]` channel: the three governance
//! cells an `ak.mls.commit` advances (epoch / key schedule) are
//! derived by the receiver from the registered reducer contract over the signed
//! `kind + payload`. Preconditions stay on the Event and stay producer-signed,
//! so only they are built here.
//!
//! Both cells are addressed by the composite subject
//! `(effective scope id, payload.mls_group_id)`.

use arkret_models_crypto::MlsGovernanceBindingPayload;
use arkret_state::mls_cells::{key_schedule_cell_id, mls_epoch_cell_id};
use arkret_wire::{ContentScheme, EventId, Hash, Precondition, Predicate, PredicateOp, ScopeRef};
use serde_json::Value;

use crate::{Error, Result};

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct MlsEpochHead {
    transition_ref: EventId,
    transition_event_digest: Hash,
    mls_transition_digest: Hash,
    effective_scope: ScopeRef,
    mls_group_id: String,
    previous_epoch: Option<u64>,
    next_epoch: u64,
    content_scheme: ContentScheme,
}

/// The exact predecessor preconditions an `ak.mls.commit` Event MUST carry.
///
/// Both are addressed by the registered composite `cell_subject`
/// `(effective scope id, payload.mls_group_id)` of the cells the commit goes
/// on to write.
pub fn mls_commit_preconditions(
    effective_scope: &ScopeRef,
    mls_group_id: &str,
    prev_epoch: u64,
    base_group_state_ref: &EventId,
    previous_governance_binding: &MlsGovernanceBindingPayload,
    previous_epoch_head: Value,
) -> Result<Vec<Precondition>> {
    let epoch_cell = mls_epoch_cell_id(effective_scope, mls_group_id)
        .map_err(|error| Error::Protocol(format!("mls epoch cell id invalid: {error:?}")))?;
    let key_schedule_cell = key_schedule_cell_id(effective_scope, mls_group_id)
        .map_err(|error| Error::Protocol(format!("key schedule cell id invalid: {error:?}")))?;
    let decoded_head: MlsEpochHead =
        serde_json::from_value(previous_epoch_head.clone()).map_err(|error| {
            Error::Protocol(format!("previous MLS epoch Cell head is invalid: {error}"))
        })?;
    if decoded_head.transition_ref != *base_group_state_ref
        || decoded_head.effective_scope != *effective_scope
        || decoded_head.mls_group_id != mls_group_id
        || decoded_head.next_epoch != prev_epoch
        || decoded_head.content_scheme != previous_governance_binding.content_scheme()
    {
        return Err(Error::Protocol(
            "previous MLS epoch Cell head does not match the Commit predecessor".to_owned(),
        ));
    }
    let _ = (
        decoded_head.transition_event_digest,
        decoded_head.mls_transition_digest,
        decoded_head.previous_epoch,
    );
    Ok(vec![
        Precondition {
            cell_id: epoch_cell,
            predicate: Predicate {
                op: PredicateOp::HeadEq,
                value: Some(previous_epoch_head),
                values: None,
                predicate_id: None,
            },
        },
        Precondition {
            cell_id: key_schedule_cell,
            predicate: Predicate {
                op: PredicateOp::HeadEq,
                value: Some(serde_json::to_value(previous_governance_binding).map_err(
                    |error| Error::Protocol(format!("governance binding encode failed: {error}")),
                )?),
                values: None,
                predicate_id: None,
            },
        },
    ])
}

#[cfg(test)]
mod tests {
    use arkret_wire::{CORE_REDUCER_PROFILE, ProfileId, RealmId, composite_subject};

    use super::*;

    fn governance_binding() -> MlsGovernanceBindingPayload {
        let root =
            Hash::new("sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
                .unwrap();
        MlsGovernanceBindingPayload::realm(
            RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19".to_owned())
                .unwrap(),
            "mls-group-1",
            7,
            7,
            root,
            ContentScheme::MlsRfc9420,
            None,
            ProfileId::MLS_GOVERNANCE_BINDING_FULL_V1,
            CORE_REDUCER_PROFILE,
        )
        .unwrap()
    }

    /// The pre-v1 assertion was "two preconditions and three producer
    /// `effects[]`". v1 keeps the preconditions on the Event and derives the
    /// three writes from the registry, so the precondition half is asserted
    /// here; the write half is asserted against the registered contract by the
    /// host's governance-proof verifier, which is where the projection is
    /// actually consumed.
    #[test]
    fn commit_preconditions_bind_both_cas_predecessors_by_composite_subject() {
        let previous_binding = governance_binding();
        let scope = ScopeRef::Realm {
            realm_id: RealmId::new("ak:realm:AYw-PHWIOTuZhm-EenZx-cCbOziC8pNCrh10oRfqiEmN")
                .unwrap(),
        };
        let group_id = scope.canonical_mls_group_id().unwrap();
        let transition_ref =
            EventId::new("ak:event:AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned())
                .unwrap();
        let previous_epoch_head = serde_json::json!({
            "transition_ref": transition_ref,
            "transition_event_digest": format!("sha256:{}", "1".repeat(64)),
            "mls_transition_digest": format!("sha256:{}", "2".repeat(64)),
            "effective_scope": scope,
            "mls_group_id": group_id,
            "previous_epoch": 6,
            "next_epoch": 7,
            "content_scheme": "mls_rfc9420"
        });
        let preconditions = mls_commit_preconditions(
            &scope,
            &group_id,
            7,
            &transition_ref,
            &previous_binding,
            previous_epoch_head.clone(),
        )
        .unwrap();

        assert_eq!(preconditions.len(), 2);
        assert!(preconditions[0].cell_id.as_str().contains("mls.epoch"));
        assert_eq!(preconditions[0].predicate.op, PredicateOp::HeadEq);
        assert_eq!(preconditions[0].predicate.value, Some(previous_epoch_head));
        assert!(preconditions[1].cell_id.as_str().contains("key_schedule"));
        assert_eq!(preconditions[1].predicate.op, PredicateOp::HeadEq);
        assert_eq!(
            preconditions[1].predicate.value,
            Some(serde_json::to_value(&previous_binding).unwrap())
        );

        // The subject is the registry composite digest, never the bare group
        // id: addressing these cells by group id alone yields a cell no
        // reducer ever writes.
        let expected_subject = composite_subject(&[
            "ak:realm:AYw-PHWIOTuZhm-EenZx-cCbOziC8pNCrh10oRfqiEmN",
            group_id.as_str(),
        ])
        .unwrap();
        assert!(
            preconditions[0]
                .cell_id
                .as_str()
                .ends_with(&expected_subject)
        );
        assert!(
            preconditions[1]
                .cell_id
                .as_str()
                .ends_with(&expected_subject)
        );
        assert!(
            !preconditions[0]
                .cell_id
                .as_str()
                .ends_with(group_id.as_str())
        );
    }

    #[test]
    fn commit_preconditions_reject_the_stale_scalar_epoch_shape() {
        let previous_binding = governance_binding();
        let scope = previous_binding.effective_scope().clone();
        let group_id = previous_binding.mls_group_id().to_owned();
        let transition_ref =
            EventId::new("ak:event:AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned())
                .unwrap();
        assert!(
            mls_commit_preconditions(
                &scope,
                &group_id,
                7,
                &transition_ref,
                &previous_binding,
                Value::from(7u64),
            )
            .is_err()
        );
    }
}
