//! Capability authority over a verified MLS governance checkpoint.
//!
//! The Signal receive rail and every other consumer of an
//! `MlsGovernanceVerificationCheckpoint` has to answer one question from the
//! checkpoint alone: is this actor authorized for this Realm action at this
//! Seal basis? The answer is the registered-cell materialization of the
//! authority-root cell plus every capability-grant cell the checkpoint carries,
//! folded through the shared authority-chain rules. It reads nothing but the
//! checkpoint, so it belongs to every client rather than to one host.

use arkret_policy::authz::authority::Grant;
use arkret_state::CellRegistry;
use arkret_state::mls_governance_proof::MlsGovernanceVerificationCheckpoint;
use arkret_wire::{ActorId, CellRef, GrantId, SealBasis};
use serde_json::Value;

use crate::Result;

pub async fn verified_checkpoint_actor_has_realm_action(
    checkpoint: &MlsGovernanceVerificationCheckpoint,
    basis: &SealBasis,
    actor: &ActorId,
    action: &str,
    now: chrono::DateTime<chrono::Utc>,
    registry: &dyn CellRegistry,
    audits: &arkret_schema::CapabilityAuthorityAuditIndex,
) -> Result<bool> {
    let root_cell = CellRef::new(arkret_wire::cell::REALM_AUTHORITY_ROOT_CELL.to_owned())?;
    let grant_ids = checkpoint
        .accepted_events
        .iter()
        .filter(|event| event.kind == arkret_wire::EventKind::CapabilityGrant)
        .map(|event| GrantId::from_event_id(&event.event_id))
        .collect::<std::collections::BTreeSet<_>>();
    let mut cells = vec![root_cell.clone()];
    for grant_id in &grant_ids {
        cells.push(CellRef::new(arkret_wire::cell::subject_cell(
            arkret_wire::CellFamilyId::CAPABILITY_GRANT_V1,
            grant_id.as_str(),
        ))?);
    }
    let values = arkret_state::mls_governance_proof::materialize_registered_cell_values_at_basis_from_verified_checkpoint(
        checkpoint,
        basis,
        &cells,
        registry,
        |event, digest_suite| arkret_schema::project_registered_cell_writes_with_authority_resolver(
            event,
            digest_suite,
            &|parent_id| audits.resolve(parent_id),
        ).map_err(|error| error.to_string()),
    )
    .await?;
    let root = values.get(&root_cell).and_then(|value| {
        serde_json::from_value::<arkret_policy::realm_bootstrap::RealmAuthorityRootValue>(
            value.clone(),
        )
        .ok()
    });
    if root.as_ref().map(|root| &root.controller_actor_id) == Some(actor)
        && arkret_schema::capability_action(arkret_wire::CapabilityActionId::REALM_OWNER)
            .is_some_and(|descriptor| descriptor.grant_authority_actions.contains(&action))
    {
        return Ok(true);
    }

    let mut grants = Vec::new();
    for (grant_id, cell) in grant_ids.iter().zip(cells.iter().skip(1)) {
        if let Some(grant) = grant_from_materialized_value(
            grant_id.as_str(),
            checkpoint.realm_id.as_str(),
            values.get(cell),
            now,
        ) {
            grants.push(grant);
        }
    }
    Ok(grants.iter().any(|grant| {
        grant.subject_id == *actor
            && grant.realm_id == checkpoint.realm_id.as_str()
            && grant.actions.iter().any(|candidate| candidate == action)
            && grant.resource == "realm"
            && !grant.revoked
            && grant.created_at <= now
            && !arkret_policy::authz::authority::is_grant_expired(grant, now)
            && arkret_policy::authz::authority::authority_chain_intact(
                &grants,
                &grant.grant_id,
                now,
            )
    }))
}

fn grant_from_materialized_value(
    grant_id: &str,
    realm_id: &str,
    value: Option<&Value>,
    now: chrono::DateTime<chrono::Utc>,
) -> Option<Grant> {
    let items = value?.as_array()?;
    let last = items.last()?;
    let body = last.get("value").unwrap_or(last);
    let body = body.get("grant").unwrap_or(body);
    // The canonical capability payload is scoped by its Event envelope and
    // therefore normally omits `grant.realm_id`.  A materializer may carry the
    // derived field, but it must never be allowed to redirect the grant.
    if body
        .get("realm_id")
        .and_then(Value::as_str)
        .is_some_and(|candidate| candidate != realm_id)
    {
        return None;
    }
    let resources = body.get("resources")?.as_array()?;
    let covers_realm = resources.iter().any(|resource| {
        resource.get("kind").and_then(Value::as_str) == Some("realm")
            && resource
                .get("realm_id")
                .and_then(Value::as_str)
                .is_none_or(|candidate| candidate == realm_id)
    });
    if !covers_realm {
        return None;
    }
    let not_yet_valid = body
        .get("constraints")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|constraint| constraint.get("not_before").and_then(Value::as_str))
        .filter_map(|instant| chrono::DateTime::parse_from_rfc3339(instant).ok())
        .any(|instant| now < instant.with_timezone(&chrono::Utc));
    let revoked = not_yet_valid
        || items.iter().any(|item| {
            let value = item.get("value").unwrap_or(item);
            let grant = value.get("grant").unwrap_or(value);
            grant.get("revoked_at").is_some() || grant.get("revoked_by").is_some()
        });
    Some(Grant {
        grant_id: grant_id.to_owned(),
        realm_id: realm_id.to_owned(),
        issuer_id: serde_json::from_value(body.get("issuer_id")?.clone()).ok()?,
        subject_id: serde_json::from_value(body.get("subject")?.clone()).ok()?,
        resource: "realm".to_owned(),
        actions: serde_json::from_value(body.get("actions")?.clone()).ok()?,
        constraints: serde_json::from_value(
            body.get("constraints")
                .cloned()
                .unwrap_or_else(|| Value::Array(Vec::new())),
        )
        .ok()?,
        revoked,
        created_at: body
            .get("issued_at")
            .and_then(Value::as_str)
            .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())?
            .with_timezone(&chrono::Utc),
        issuer_authority_refs: serde_json::from_value(body.get("issuer_authority_refs")?.clone())
            .ok()?,
        authority_depth: body.get("authority_depth").and_then(Value::as_u64),
        authority_root_refs: serde_json::from_value(
            body.get("authority_root_refs")
                .cloned()
                .unwrap_or_else(|| Value::Array(Vec::new())),
        )
        .ok()?,
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn at(seconds: i64) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::from_timestamp(seconds, 0).unwrap()
    }

    fn materialized_moderation_grant(realm_id: &str) -> Value {
        json!([{
            "tag": "ak:event:AZVgkcivLIz2PjwUcjuT5bTb6295nnowDbSQak0QfNCa:0",
            "value": {"grant": {
                "issuer_id": {
                    "kind": "service",
                    "service_id": "ak:did_core:web:owner.example"
                },
                "subject": {
                    "kind": "service",
                    "service_id": "ak:did_core:web:moderator.example"
                },
                "actions": ["ak.call.moderate"],
                "resources": [{"kind": "realm", "realm_id": realm_id}],
                "constraints": [],
                "issuer_authority_refs": [{
                    "kind": "realm_root",
                    "realm_id": realm_id,
                    "cell_ref": "ak:cell:ak.component.realm.authority_root.v1:null",
                    "controller_epoch_at_issuance": 0,
                    "authority_generation": 0
                }],
                "authority_root_refs": [{
                    "kind": "realm_root",
                    "realm_id": realm_id,
                    "cell_ref": "ak:cell:ak.component.realm.authority_root.v1:null",
                    "authority_generation": 0
                }],
                "authority_depth": 1,
                "issued_at": "2026-01-01T00:00:00.000Z"
            }}
        }])
    }

    #[test]
    fn materialized_grant_uses_event_realm_when_payload_omits_it() {
        let realm_id = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
        let value = materialized_moderation_grant(realm_id);
        let grant = grant_from_materialized_value(
            "ak:grant:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
            realm_id,
            Some(&value),
            at(0),
        )
        .expect("the canonical grant payload is scoped by its accepted Event");
        assert_eq!(grant.realm_id, realm_id);
        assert_eq!(grant.resource, "realm");
        assert_eq!(grant.actions, ["ak.call.moderate"]);
        assert!(!grant.revoked);
    }

    #[test]
    fn materialized_grant_rejects_a_conflicting_derived_realm() {
        let realm_id = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
        let mut value = materialized_moderation_grant(realm_id);
        value[0]["value"]["grant"]["realm_id"] =
            json!("ak:realm:AUF95cBdCJMIioPdGG19CvDlHGFIr71C5klRdg_SvcxC");
        assert!(
            grant_from_materialized_value(
                "ak:grant:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
                realm_id,
                Some(&value),
                at(0),
            )
            .is_none()
        );
    }
}
