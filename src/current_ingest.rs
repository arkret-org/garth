//! Shared current-cut validation and committed Event decoding. The SDK owns
//! registered values and reducers; hosts own their durable product indexes.

use std::collections::{BTreeMap, BTreeSet};

use arkret_wire::{CommitStreamRef, CommittedEventView};

use crate::{ClientEvent, CommittedDelta, DecodedInbound, InboundDecoder};

fn protocol(error: impl std::fmt::Display) -> crate::Error {
    crate::Error::Protocol(error.to_string())
}

fn closed_discovery_value(payload: serde_json::Value) -> crate::Result<serde_json::Value> {
    let discovery: arkret_models_collaboration::governance::realm_lifecycle::RealmDiscoveryPayload =
        serde_json::from_value(payload.clone())
            .map_err(|error| crate::Error::Protocol(error.to_string()))?;
    if discovery
        .to_value()
        .map_err(|error| crate::Error::Protocol(error.to_string()))?
        != payload
    {
        return Err(crate::Error::Protocol(
            "floor discovery is not the closed payload".to_owned(),
        ));
    }
    payload
        .get("value")
        .cloned()
        .ok_or_else(|| crate::Error::Protocol("floor discovery omits its value".to_owned()))
}

fn closed_join_rule_value(
    policy: Option<&serde_json::Value>,
    payload: serde_json::Value,
) -> crate::Result<serde_json::Value> {
    let Some(policy) = policy else {
        return Err(crate::Error::Protocol(
            "floor join rule has no verified policy bundle predecessor".to_owned(),
        ));
    };
    let rule: arkret_models_collaboration::governance::realm_lifecycle::RealmJoinRulePayload =
        serde_json::from_value(payload.clone())
            .map_err(|error| crate::Error::Protocol(error.to_string()))?;
    if rule
        .to_value()
        .map_err(|error| crate::Error::Protocol(error.to_string()))?
        != payload
    {
        return Err(crate::Error::Protocol(
            "floor join rule is not the closed payload".to_owned(),
        ));
    }
    let value = payload
        .get("value")
        .cloned()
        .ok_or_else(|| crate::Error::Protocol("floor join rule omits its value".to_owned()))?;
    // join-policy.md §2: a restricted entry mode needs at least one automatic
    // gate in the same signed cut's policy bundle. The Station evaluated the
    // gates at admission; the client only checks the signed rows agree.
    if value == "restricted" || value == "knock_restricted" {
        let bundle: arkret_models_collaboration::events_payloads::RealmPolicyBundlePayload =
            serde_json::from_value(policy.clone()).map_err(protocol)?;
        let automatic = bundle.join_policy.is_some_and(|join_policy| {
            join_policy.gates.iter().any(|gate| {
                matches!(
                    gate,
                    arkret_models_collaboration::events_payloads::join_policy::JoinPolicyGate::ClaimRequired { .. }
                        | arkret_models_collaboration::events_payloads::join_policy::JoinPolicyGate::ChallengeResponse { .. }
                        | arkret_models_collaboration::events_payloads::join_policy::JoinPolicyGate::ParentMembership { .. }
                )
            })
        });
        if !automatic {
            return Err(crate::Error::Protocol(
                "floor restricted join rule has no automatic join gate in the signed cut"
                    .to_owned(),
            ));
        }
    }
    Ok(value)
}

pub fn closed_current_value<T>(value: &serde_json::Value, family: &str) -> crate::Result<T>
where
    T: serde::de::DeserializeOwned + serde::Serialize,
{
    let parsed: T = serde_json::from_value(value.clone())
        .map_err(|error| protocol(format!("signed {family} row: {error}")))?;
    if serde_json::to_value(&parsed).map_err(protocol)? != *value {
        return Err(protocol(format!(
            "signed {family} row is not its closed value"
        )));
    }
    Ok(parsed)
}

pub fn validate_floor_product_rows(
    realm_id: &arkret_wire::RealmId,
    signed_head: &arkret_wire::CommitStreamHead,
    history_access: arkret_wire::HistoryAccess,
    rows: &[arkret_wire::TypedCurrentRow],
    genesis_revision: &arkret_wire::CurrentRevision,
    genesis_object: &serde_json::Value,
    genesis_actor: &arkret_wire::ActorId,
) -> crate::Result<()> {
    arkret_models_collaboration::exact_current_results::validate_calendar_current_pairs(
        realm_id, rows,
    )
    .map_err(protocol)?;
    use arkret_wire::CurrentSelector;
    let realm_stream = CommitStreamRef::Realm {
        realm_id: realm_id.clone(),
    };
    let policy = rows.iter().find_map(|row| match row {
        arkret_wire::TypedCurrentRow::Value {
            selector: CurrentSelector::RealmPolicyBundle,
            value,
            ..
        } => Some(value),
        _ => None,
    });
    let mut genesis = false;
    let mut direct_conversation = false;
    let mut history_at_genesis = false;
    let mut bindings = Vec::new();
    let mut root = false;
    let mut strands = BTreeMap::new();
    let mut default_strand = None;
    let mut messages = Vec::new();
    let mut spaces = BTreeMap::new();
    let mut space_parents = BTreeMap::new();
    let mut space_policies = BTreeSet::new();
    let mut positions = Vec::new();
    let mut selectors = BTreeSet::new();
    for row in rows {
        let arkret_wire::TypedCurrentRow::Value {
            selector,
            source_stream_ref,
            revision,
            value,
        } = row;
        if !selectors.insert(arkret_canonical::canonical_json_bytes(selector).map_err(protocol)?) {
            return Err(protocol("signed floor repeats a current selector"));
        }
        if source_stream_ref != &realm_stream
            || revision.stream_position > signed_head.stream_position
            || (revision.stream_position == signed_head.stream_position
                && revision.commit_id != signed_head.commit_id)
        {
            return Err(protocol(
                "signed floor row source is not the signed Realm stream prefix",
            ));
        }
        let genesis_projection = matches!(selector, CurrentSelector::RealmGenesis);
        let authority_root = matches!(selector, CurrentSelector::RealmAuthorityRoot);
        // A Direct Conversation genesis also writes `realm_history_access`
        // `null -> since_join` in its own covering Commit
        // (`models/realm-and-space.md` 2.5.1 step 5).
        let genesis_history =
            matches!(selector, CurrentSelector::RealmHistoryAccess) && revision == genesis_revision;
        if !genesis_history
            && !authority_root
            && genesis_projection != (revision == genesis_revision)
        {
            return Err(protocol(
                "signed floor row revision differs from its genesis covering Commit",
            ));
        }
        match selector {
            CurrentSelector::RealmGenesis => {
                let parsed: arkret_models_collaboration::events_payloads::RealmGenesis =
                    closed_current_value(value, "realm_genesis")?;
                parsed.validate().map_err(protocol)?;
                // A Collaboration Realm is founded with genesis purpose
                // `collaboration` or `direct_conversation`
                // (`models/realm-and-space.md` 2.8.2).
                if !matches!(
                    parsed.purpose,
                    arkret_models_collaboration::events_payloads::RealmPurpose::Collaboration
                        | arkret_models_collaboration::events_payloads::RealmPurpose::DirectConversation
                ) || genesis_object != value
                {
                    return Err(protocol(
                        "signed genesis row is not the verified collaboration genesis object",
                    ));
                }
                direct_conversation =
                    parsed.purpose == arkret_models_collaboration::events_payloads::RealmPurpose::DirectConversation;
                genesis = true;
            }
            CurrentSelector::RealmAuthorityRoot => {
                let parsed: arkret_wire::RealmAuthorityRootValue =
                    closed_current_value(value, "realm_authority_root")?;
                parsed.validate().map_err(protocol)?;
                if revision.stream_position == 0 && revision != genesis_revision {
                    return Err(protocol(
                        "signed authority root has a different genesis covering Commit",
                    ));
                }
                // Owner transfers and authority resets update this current value;
                // only its genesis revision fixes the initial creator and counters.
                if revision == genesis_revision
                    && *value
                        != serde_json::json!({
                                    "controller_actor_id": genesis_actor,
                                    "controller_epoch": 0,
                                    "authority_generation": 0,
                        "authority_event_ref": realm_id.event_id(),
                                })
                {
                    return Err(protocol(
                        "signed authority root is not the generation-zero creator controller",
                    ));
                }
                root = true;
            }
            CurrentSelector::ScopeReadReceiptPolicy { scope_ref } => {
                if source_stream_ref.scope_ref() != *scope_ref {
                    return Err(protocol("receipt policy source differs from its scope"));
                }
                closed_current_value::<
                    arkret_models_collaboration::events_payloads::ReadReceiptPolicyPayload,
                >(value, "scope_read_receipt_policy")?
                .validate()
                .map_err(protocol)?;
            }
            CurrentSelector::RealmProfile => {
                let parsed: arkret_models_collaboration::events_payloads::RealmProfile =
                    closed_current_value(value, "realm_profile")?;
                if parsed.to_value().map_err(protocol)? != *value {
                    return Err(protocol("signed Realm profile is not its closed value"));
                }
            }
            CurrentSelector::RealmPolicyBundle => {
                let parsed: arkret_models_collaboration::events_payloads::RealmPolicyBundlePayload =
                    closed_current_value(value, "realm_policy_bundle")?;
                if parsed.policy_revision == 0 {
                    return Err(protocol("signed policy bundle has no policy revision"));
                }
            }
            CurrentSelector::RealmJoinRule => {
                closed_join_rule_value(policy, serde_json::json!({ "value": value }))?;
            }
            CurrentSelector::RealmHistoryAccess => {
                let parsed: arkret_wire::HistoryAccess =
                    closed_current_value(value, "realm_history_access")?;
                if parsed != history_access {
                    return Err(protocol(
                        "signed history access differs from the signed history floor",
                    ));
                }
                if genesis_history {
                    if parsed != arkret_wire::HistoryAccess::SinceJoin {
                        return Err(protocol(
                            "genesis history access is not the Direct Conversation since_join",
                        ));
                    }
                    history_at_genesis = true;
                }
            }
            CurrentSelector::RealmDiscovery => {
                closed_discovery_value(serde_json::json!({ "value": value }))?;
            }
            CurrentSelector::RealmAlias => {
                closed_current_value::<
                    arkret_models_collaboration::governance::realm_governance::RealmAliasPayload,
                >(value, "realm_alias")?
                .validate()
                .map_err(protocol)?;
            }
            CurrentSelector::RealmPlaintextVisibleServices => {
                closed_current_value::<
                    arkret_models_collaboration::governance::plaintext_visibility::PlaintextVisibleServicesPayload,
                >(value, "realm_plaintext_visible_services")?;
            }
            CurrentSelector::MessageRevision { message_id } => {
                // The chain's current carrier: its create, or the revise that
                // replaced it, which must name this same Message.
                if value.get("message_id").is_some() {
                    let parsed: arkret_models_collaboration::events_payloads::message::MessageRevisePayload =
                        closed_current_value(value, "message_revision")?;
                    if &parsed.message_id != message_id {
                        return Err(protocol("signed message revision names another Message"));
                    }
                } else {
                    let parsed: arkret_models_collaboration::events_payloads::MessageCreatePayload =
                        closed_current_value(value, "message_revision")?;
                    messages.push((parsed.strand_id, revision.stream_position));
                }
            }
            CurrentSelector::Pin { pin_scope } => {
                // Assertions retain payloads, not the effective roster. Event
                // kinds and causal history still determine add/remove/reorder.
                closed_current_value::<
                    arkret_models_collaboration::objects::productivity::PinCurrentValue,
                >(value, "pin")?
                .validate_for_scope(pin_scope)
                .map_err(protocol)?;
            }
            CurrentSelector::MessageReactions { target_ref } => {
                // This row retains assertions, not actor membership. The chat
                // fold still requires signed Events in a verified prefix.
                arkret_wire::MessageId::new(target_ref.as_str()).map_err(protocol)?;
                closed_current_value::<
                    arkret_models_collaboration::events_payloads::reaction::MessageReactionsCurrentValue,
                >(value, "message_reactions")?
                .validate_for_target(target_ref)
                .map_err(protocol)?;
            }
            CurrentSelector::ObjectRedaction { target_ref } => {
                // Message termination and Event field cropping are independent
                // subjects. Hosts retain the latter for their original-byte
                // disclosure gates; never retype it into a Message tombstone.
                if arkret_wire::MessageId::new(target_ref.as_str()).is_err()
                    && arkret_wire::EventId::new(target_ref.as_str()).is_err()
                {
                    return Err(protocol(
                        "signed object redaction subject has no product installer",
                    ));
                }
                closed_current_value::<
                    arkret_models_collaboration::events_payloads::redaction::ObjectRedactionCurrentValue,
                >(value, "object_redaction")?
                .validate_for_subject(target_ref)
                .map_err(protocol)?;
            }
            CurrentSelector::MemberIdentityUpdates { member_id, segment } => {
                // This family is Realm-local; the enclosing stream gate rejects
                // a Circle source. Preserve every exact signed update payload.
                closed_current_value::<arkret_models_identity::MemberIdentityUpdatesCurrentValue>(
                    value,
                    "member_identity_updates",
                )?
                .validate_for_tuple(realm_id, member_id, *segment)
                .map_err(protocol)?;
            }
            CurrentSelector::AppletRegistration { applet_id } => {
                let registration = closed_current_value::<
                    arkret_models_integration::AppletRegistrationPayload,
                >(value, "applet_registration")?;
                if &registration.applet_id != applet_id {
                    return Err(protocol(
                        "signed Applet registration differs from its selector",
                    ));
                }
            }
            CurrentSelector::MemberState { .. } => {
                closed_current_value::<arkret_wire::MemberStateCurrent>(value, "member_state")?;
            }
            CurrentSelector::Sidecar { sidecar_id } => {
                // The Sidecar object is created in the parent Realm stream;
                // its private context, exchanges and MLS retain their own stream.
                let sidecar: arkret_models_collaboration::agent_sidecar::AgentSidecar =
                    closed_current_value(value, "sidecar")?;
                sidecar.validate_shape().map_err(protocol)?;
                if sidecar.id != *sidecar_id || sidecar.realm_id != *realm_id {
                    return Err(protocol(
                        "signed Sidecar differs from its parent Realm subject",
                    ));
                }
            }
            CurrentSelector::Circle { circle_id } => {
                // Circle configuration is created in the parent Realm stream.
                // Membership and MLS state retain their own Circle stream.
                let circle: arkret_models_collaboration::governance::circle::Circle =
                    closed_current_value(value, "circle")?;
                if circle.id.as_ref() != Some(circle_id)
                    || circle.realm_id != *realm_id
                    || circle.schema != arkret_wire::SchemaId::CIRCLE_V1
                {
                    return Err(protocol(
                        "signed Circle differs from its parent Realm subject",
                    ));
                }
            }
            CurrentSelector::Strand { strand_id } => {
                let parsed: arkret_models_collaboration::objects::strand::Strand =
                    closed_current_value(value, "strand")?;
                if parsed.id.as_ref() != Some(strand_id)
                    || parsed.schema != arkret_wire::SchemaId::STRAND_V1
                    || parsed.realm_id != *realm_id
                    || parsed.scope_circle_id.is_some()
                {
                    return Err(protocol(
                        "signed Strand row is not a Realm-scoped Strand of this Realm",
                    ));
                }
                strands.insert(strand_id.clone(), revision.stream_position);
            }
            CurrentSelector::CalendarScheduleSource { .. } => {
                let parsed: arkret_wire::CalendarScheduleSourceValue =
                    closed_current_value(value, "calendar_schedule_source")?;
                parsed
                    .validate_for_current(realm_id, source_stream_ref, revision)
                    .map_err(protocol)?;
            }
            CurrentSelector::Relation {
                primary_conflict_domain,
            } => {
                let relation: arkret_wire::relation::Relation =
                    closed_current_value(value, "relation")?;
                relation
                    .validate_current_for_domain(realm_id, primary_conflict_domain)
                    .map_err(protocol)?;
                if relation.scope_circle_id.is_some() {
                    return Err(protocol("signed Realm floor contains a Circle Relation"));
                }
            }
            CurrentSelector::MlsGroup { scope_ref } => {
                let group: arkret_wire::MlsGroupCurrent = closed_current_value(value, "mls_group")?;
                if scope_ref
                    != &(arkret_wire::ScopeRef::Realm {
                        realm_id: realm_id.clone(),
                    })
                    || group.effective_scope != *scope_ref
                    || group.covered_key_access_revision > group.current_key_access_revision
                {
                    return Err(protocol(
                        "signed MLS group differs from its Realm selector or key-access cut",
                    ));
                }
            }
            CurrentSelector::Space { space_id } => {
                let space: arkret_models_collaboration::objects::space::Space =
                    closed_current_value(value, "space")?;
                space.validate().map_err(protocol)?;
                if space.id.as_ref() != Some(space_id)
                    || space.schema != arkret_wire::SchemaId::SPACE_V1
                    || space.realm_id != *realm_id
                    || space.scope_circle_id.is_some()
                    || space.parent_space_id.is_some()
                    || space.child_scope_policy.is_some()
                {
                    return Err(protocol(
                        "signed Space metadata differs from its registered Realm subject",
                    ));
                }
                spaces.insert(space_id.clone(), space);
            }
            CurrentSelector::SpaceParent { space_id } => {
                let parent = value
                    .as_object()
                    .filter(|object| object.len() == 1)
                    .and_then(|object| object.get("parent_space_id"))
                    .ok_or_else(|| {
                        protocol("signed Space parent is not its one-member closed value")
                    })?;
                let parent: Option<arkret_wire::SpaceId> =
                    serde_json::from_value(parent.clone()).map_err(protocol)?;
                space_parents.insert(space_id.clone(), parent);
            }
            CurrentSelector::SpaceChildScopePolicy { space_id } => {
                closed_current_value::<
                    Option<arkret_models_collaboration::objects::space::ChildScopePolicy>,
                >(value, "space_child_scope_policy")?;
                space_policies.insert(space_id.clone());
            }
            CurrentSelector::StrandPosition {
                board_space_id,
                strand_id,
            } => {
                let position: Option<
                    arkret_models_collaboration::objects::strand::StrandPositionCurrent,
                > = closed_current_value(value, "strand_position")?;
                if position.as_ref().is_some_and(|position| {
                    !(1..=128).contains(&position.rank.len())
                        || !position
                            .rank
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric())
                }) {
                    return Err(protocol(
                        "signed Strand position has an invalid canonical rank",
                    ));
                }
                positions.push((board_space_id.clone(), strand_id.clone(), position));
            }
            CurrentSelector::InviteLifecycle { .. } => {
                closed_current_value::<arkret_wire::InviteState>(value, "invite_lifecycle")?;
            }
            CurrentSelector::InviteDirectedInvitee { .. } => {
                closed_current_value::<arkret_models_collaboration::governance::membership_invite::InviteDirectedInviteeValue>(
                    value, "invite_directed_invitee",
                )?;
            }
            CurrentSelector::InviteLiveTarget { .. } => {
                closed_current_value::<arkret_models_collaboration::governance::membership_invite::InviteLiveTargetValue>(
                    value, "invite_live_target",
                )?;
            }
            CurrentSelector::Policy { policy_id } => {
                let policy: arkret_models_collaboration::governance::operation_wire::PolicySetValue =
                    closed_current_value(value, "policy")?;
                policy.validate().map_err(protocol)?;
                if policy.policy_id() != policy_id
                    || matches!(&policy,
                        arkret_models_collaboration::governance::operation_wire::PolicySetValue::Governance(value)
                            if value.realm_id.as_ref().is_some_and(|id| id != realm_id))
                {
                    return Err(protocol(
                        "signed Policy differs from its registered Realm subject",
                    ));
                }
            }
            CurrentSelector::CapabilityGrant { grant_id } => {
                let grant: arkret_models_collaboration::governance::grant_constraint::CapabilityGrant =
                    closed_current_value(value, "capability_grant")?;
                if &grant.id != grant_id
                    || grant.realm_id.as_ref() != Some(realm_id)
                    || grant.schema != arkret_wire::SchemaId::CAPABILITY_V1
                {
                    return Err(protocol(
                        "signed Capability Grant differs from its registered Realm subject",
                    ));
                }
            }
            CurrentSelector::RealmSetDefaultStrand => {
                let member = value
                    .as_object()
                    .filter(|object| object.len() == 1)
                    .and_then(|object| object.get("default_strand_id"))
                    .ok_or_else(|| {
                        protocol("signed default Strand is not its one-member closed value")
                    })?;
                let pointer: Option<arkret_wire::StrandId> =
                    serde_json::from_value(member.clone()).map_err(protocol)?;
                default_strand = Some((pointer, revision.stream_position));
            }
            CurrentSelector::StrandWatch { .. } => {
                // This authenticated snapshot row remains typed current state.
                // Only the separate exact read can supply a self-watch CAS preimage.
                closed_current_value::<
                    arkret_models_collaboration::strand_watch_operations::StrandWatchCurrentValue,
                >(value, "strand_watch")?;
            }
            CurrentSelector::Rsvp { occurrence, .. } => {
                let entry: arkret_models_collaboration::objects::productivity::RsvpEntry =
                    closed_current_value(value, "rsvp")?;
                entry.validate().map_err(protocol)?;
                if let Some(occurrence) = occurrence {
                    arkret_models_collaboration::objects::productivity::validate_canonical_occurrence_key(
                        occurrence,
                    )
                    .map_err(protocol)?;
                }
            }
            CurrentSelector::AgentInteraction { .. } => {
                // The signed Realm cut authenticates this registered mode row.
                // Ownership and mode authorization remain exact-read decisions.
                closed_current_value::<
                    arkret_models_collaboration::agent_interaction::AgentInteractionCurrentValue,
                >(value, "agent_interaction")?;
            }
            CurrentSelector::CallState { .. } => {
                // Install the authenticated lifecycle axis as current state.
                // Its create null predecessor is distinct from an Event delta;
                // current readiness still requires the complete signed cut.
                let current: arkret_models_collaboration::events_payloads::call::CallStateCurrentValue =
                    closed_current_value(value, "call_state")?;
                current.validate().map_err(protocol)?;
            }
            CurrentSelector::CallFocus { call_id }
            | CurrentSelector::CallRoster { call_id }
            | CurrentSelector::CallModeration { call_id } => {
                if !rows.iter().any(|row| {
                    matches!(row,
                        arkret_wire::TypedCurrentRow::Value {
                            selector: CurrentSelector::CallState {call_id: found},
                            source_stream_ref: stream, ..
                        } if found == call_id && stream == source_stream_ref
                    )
                }) {
                    return Err(protocol(
                        "signed Call axis has no lifecycle in its exact scope",
                    ));
                }
                match selector {
                    CurrentSelector::CallFocus { .. } => {
                        closed_current_value::<
                            arkret_models_collaboration::events_payloads::call::CallFocus,
                        >(value, "call_focus")?;
                    }
                    CurrentSelector::CallRoster { .. } => {
                        let roster: arkret_models_collaboration::events_payloads::call::CallRosterCurrentValue =
                            closed_current_value(value, "call_roster")?;
                        roster
                            .validate_for_axis(source_stream_ref, revision)
                            .map_err(protocol)?;
                        let CurrentSelector::CallRoster { call_id } = selector else {
                            unreachable!()
                        };
                        arkret_signatures::media::verify_call_roster_bindings(
                            realm_id, call_id, &roster,
                        )
                        .map_err(protocol)?;
                    }
                    _ => {
                        let moderation: arkret_models_collaboration::events_payloads::call::CallModerationCurrentValue =
                            closed_current_value(value, "call_moderation")?;
                        moderation
                            .validate_for_axis(source_stream_ref, revision)
                            .map_err(protocol)?;
                    }
                }
            }
            CurrentSelector::RealmMediaService => {
                let descriptor: arkret_models_collaboration::events_payloads::realm::RealmMediaServiceValue =
                    closed_current_value(value, "realm_media_service")?;
                descriptor.validate().map_err(protocol)?;
            }
            CurrentSelector::ModerationFrankingProof { event_id } => {
                // This is authenticated current state of the receipt, not an
                // independently verified moderation evidence package. Garth
                // has already verified the Station's signed snapshot cut.
                let proof: arkret_models_collaboration::events_payloads::moderation::FrankingProof =
                    closed_current_value(value, "moderation_franking_proof")?;
                if proof.realm_id != *realm_id
                    || proof.event_id != *event_id
                    || !(16..=256).contains(&proof.replay_nonce.len())
                    || !proof
                        .replay_nonce
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
                    || proof.signature.is_empty()
                {
                    return Err(protocol(
                        "signed franking receipt differs from its Realm, target Event or closed proof shape",
                    ));
                }
            }
            CurrentSelector::DirectConversationBinding { pair_key } => {
                // The pair's endorsement set: one binding digest, and every
                // endorsement binds this pair inside this Realm
                // (`identity/contact-and-direct-conversation.md` 8.3).
                let binding: arkret_models_collaboration::events_payloads::direct_conversation::DirectConversationBindingCurrentValue =
                    closed_current_value(value, "direct_conversation_binding")?;
                binding.binding_digest().map_err(protocol)?;
                if binding.endorsements.iter().any(|entry| {
                    &entry.value.pair_key != pair_key || entry.value.realm_id != *realm_id
                }) {
                    return Err(protocol(
                        "signed Direct Conversation binding names another pair or Realm",
                    ));
                }
                bindings.push(pair_key.clone());
            }
            _ => {
                return Err(protocol(format!(
                    "signed floor current family {selector:?} has no product installer"
                )));
            }
        }
    }
    if spaces.keys().collect::<BTreeSet<_>>() != space_parents.keys().collect::<BTreeSet<_>>()
        || spaces.keys().collect::<BTreeSet<_>>() != space_policies.iter().collect::<BTreeSet<_>>()
    {
        return Err(protocol(
            "signed Space cut omits a registered structural sibling",
        ));
    }
    for space_id in spaces.keys() {
        let mut parent = space_parents.get(space_id).and_then(Option::as_ref);
        let mut visited = BTreeSet::from([space_id]);
        while let Some(id) = parent {
            if !visited.insert(id) || !spaces.contains_key(id) {
                return Err(protocol("signed Space parent chain is missing or cyclic"));
            }
            parent = space_parents.get(id).and_then(Option::as_ref);
        }
    }
    for (board_id, strand_id, position) in positions {
        if !strands.contains_key(&strand_id)
            || spaces
                .get(&board_id)
                .is_none_or(|space| space.kind != "board")
            || position.as_ref().is_some_and(|position| {
                spaces
                    .get(&position.list_space_id)
                    .is_none_or(|space| space.kind != "list")
            })
        {
            return Err(protocol(
                "signed Strand position has no matching Board, List or Strand in its Realm cut",
            ));
        }
    }
    if let Some((Some(strand_id), _)) = &default_strand
        && !strands.contains_key(strand_id)
    {
        return Err(protocol(
            "signed default Strand names no Strand in the signed cut",
        ));
    }
    // A later metadata/lifecycle update legitimately advances Strand current
    // beyond older messages and the default pointer. Creation order belongs
    // to verified original Commits, not this mutable current row's revision.
    if messages
        .iter()
        .any(|(strand_id, _)| !strands.contains_key(strand_id))
    {
        return Err(protocol("signed message names no Strand in the signed cut"));
    }
    if history_at_genesis && !direct_conversation {
        return Err(protocol(
            "signed history access at genesis belongs only to a Direct Conversation genesis",
        ));
    }
    if !bindings.is_empty() && (!direct_conversation || bindings.len() > 1) {
        return Err(protocol(
            "signed Direct Conversation binding is not the one binding of a Direct Conversation Realm",
        ));
    }
    if genesis && root {
        Ok(())
    } else {
        Err(protocol(
            "signed floor snapshot omits collaboration genesis current",
        ))
    }
}

pub fn committed_views_to_client_events(
    realm_id: &arkret_wire::RealmId,
    committed_events: Vec<CommittedEventView>,
) -> crate::Result<Vec<ClientEvent>> {
    let decoder = InboundDecoder::new();
    let mut batch = Vec::with_capacity(committed_events.len());
    for item in committed_events {
        let delta = CommittedDelta::from_committed_event_view(realm_id.clone(), item)?;
        // Every verified reducer input reaches the product ingests: message
        // families decoded, all other kinds (Space, Strand, membership,
        // moderation, RSVP) as the Event itself.
        if let Some(event) = delta.event() {
            match decoder.try_decode_event(event.clone())? {
                DecodedInbound::Message(message) => batch.push(ClientEvent::Message(message)),
                DecodedInbound::Event(event) => batch.push(ClientEvent::Event(event)),
            }
        }
        batch.push(ClientEvent::Committed(delta));
    }
    Ok(batch)
}

pub fn validate_current_product(
    snapshot: &arkret_wire::RealmStateSnapshot,
    realm: &arkret_wire::RealmId,
) -> crate::Result<()> {
    for row in &snapshot.current_state_entries {
        let arkret_wire::TypedCurrentRow::Value {
            selector,
            source_stream_ref,
            revision,
            value,
        } = row;
        if let arkret_wire::CurrentSelector::ScopeReadReceiptPolicy { scope_ref } = selector {
            if scope_ref.realm_id_opt() != Some(realm) {
                return Err(protocol("receipt policy belongs to another Realm"));
            }
            let current =
                arkret_models_collaboration::events_payloads::ScopeReadReceiptPolicyCurrent {
                    selector: selector.clone(),
                    source_stream_ref: source_stream_ref.clone(),
                    revision: revision.clone(),
                    value: closed_current_value(value, "scope_read_receipt_policy")?,
                };
            current.validate().map_err(protocol)?;
        }
    }
    let stream = CommitStreamRef::Realm {
        realm_id: realm.clone(),
    };
    let head = snapshot
        .visible_stream_heads
        .iter()
        .find(|head| head.stream_ref == stream)
        .ok_or_else(|| protocol("own Station snapshot omits Realm coverage"))?;
    let rows = snapshot
        .current_state_entries
        .iter()
        .filter(|row| matches!(row, arkret_wire::TypedCurrentRow::Value { source_stream_ref, .. } if source_stream_ref == &stream))
        .cloned()
        .collect::<Vec<_>>();
    let (object, revision) = rows
        .iter()
        .find_map(|row| match row {
            arkret_wire::TypedCurrentRow::Value {
                selector: arkret_wire::CurrentSelector::RealmGenesis,
                value,
                revision,
                ..
            } => Some((value, revision)),
            _ => None,
        })
        .ok_or_else(|| protocol("own Station complete cut omits typed Realm Genesis"))?;
    if revision.stream_position != 0 {
        return Err(protocol("typed Genesis is not at the Realm origin"));
    }
    let root = rows
        .iter()
        .find_map(|row| match row {
            arkret_wire::TypedCurrentRow::Value {
                selector: arkret_wire::CurrentSelector::RealmAuthorityRoot,
                value,
                ..
            } => Some(value),
            _ => None,
        })
        .ok_or_else(|| protocol("own Station cut omits typed authority root"))?;
    let actor: arkret_wire::ActorId = serde_json::from_value(
        root.get("controller_actor_id")
            .cloned()
            .ok_or_else(|| protocol("typed root lacks its full controller"))?,
    )
    .map_err(protocol)?;
    validate_floor_product_rows(
        realm,
        head,
        snapshot.retention_and_history_floor.history_access,
        &rows,
        revision,
        object,
        &actor,
    )
}

#[cfg(test)]
mod tests {
    use arkret_wire::{CurrentRevision, CurrentSelector, RealmCommitId, TypedCurrentRow};
    use serde_json::json;

    use super::*;

    #[test]
    fn signed_agent_policy_floor_preserves_sync_and_rejects_subject_rebinding() {
        let realm = crate::test_fixtures::realm_id();
        let actor = crate::test_fixtures::actor_id();
        let stream = CommitStreamRef::Realm {
            realm_id: realm.clone(),
        };
        let genesis = serde_json::to_value(
            arkret_models_collaboration::events_payloads::realm::RealmGenesis::new(
                arkret_models_collaboration::events_payloads::realm::RealmPurpose::Collaboration,
                arkret_wire::GenesisSalt::new("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
                    .unwrap(),
                arkret_wire::TrustDomainId::new("ak:trust_domain:server.example").unwrap(),
                arkret_wire::SecurityClass::Standard,
                arkret_wire::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
                arkret_wire::JoinRule::Invite,
                arkret_wire::HistoryAccess::SinceJoin,
                arkret_wire::Discoverability::Listed,
                None,
                None,
            )
            .unwrap(),
        )
        .unwrap();
        let origin = CurrentRevision {
            commit_id: RealmCommitId::from_digest([1; 32]),
            stream_position: 0,
        };
        let revision = CurrentRevision {
            commit_id: RealmCommitId::from_digest([2; 32]),
            stream_position: 1,
        };
        let head = arkret_wire::CommitStreamHead {
            stream_ref: stream.clone(),
            stream_position: 1,
            commit_id: revision.commit_id.clone(),
        };
        let policy_id =
            arkret_wire::PolicyId::new("ak:policy:0196419b-0000-7000-8000-000000000001").unwrap();
        let policy = json!({
            "schema":"ak.schema.policy.v1", "id":policy_id, "realm_id":realm,
            "policy_kind":"agent", "rules":[{"kind":"agent", "rule_id":"owned_join", "effect":"allow", "agent_target":{"kind":"all"}, "agent_operations":["join"]}],
            "default_effect":"deny", "created_by":actor, "created_at":"2026-09-16T00:00:00.000Z"
        });
        let rows = vec![
            TypedCurrentRow::Value {
                selector: CurrentSelector::RealmGenesis,
                source_stream_ref: stream.clone(),
                revision: origin.clone(),
                value: genesis.clone(),
            },
            TypedCurrentRow::Value {
                selector: CurrentSelector::RealmAuthorityRoot,
                source_stream_ref: stream.clone(),
                revision: origin.clone(),
                value: json!({"controller_actor_id":actor,"controller_epoch":0,"authority_generation":0,"authority_event_ref":realm.event_id()}),
            },
            TypedCurrentRow::Value {
                selector: CurrentSelector::Policy {
                    policy_id: policy_id.clone(),
                },
                source_stream_ref: stream,
                revision,
                value: policy,
            },
        ];
        let validate = |rows: &[TypedCurrentRow]| {
            validate_floor_product_rows(
                &realm,
                &head,
                arkret_wire::HistoryAccess::SinceJoin,
                rows,
                &origin,
                &genesis,
                &actor,
            )
        };
        validate(&rows).unwrap();
        for (field, value) in [
            (
                "id",
                json!("ak:policy:0196419b-0000-7000-8000-000000000002"),
            ),
            (
                "realm_id",
                json!(arkret_wire::RealmId::from_event_id(
                    &arkret_wire::EventId::from_digest(
                        arkret_canonical::DigestSuite::Sha256,
                        [9; 32]
                    )
                )),
            ),
            ("schema", json!("ak.schema.unknown.v1")),
        ] {
            let mut changed = rows.clone();
            let TypedCurrentRow::Value { value: policy, .. } = &mut changed[2] else {
                unreachable!()
            };
            policy[field] = value;
            assert!(
                validate(&changed).is_err(),
                "accepted Policy rebinding: {field}"
            );
        }
    }
}
