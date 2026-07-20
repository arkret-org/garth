use super::*;
use crate::models::{CandidateError, CandidateValidationContext, MemberDeliveryBindingCandidate};

/// Realm membership operations.
impl Realm {
    /// Create a join operation and update local membership state to joined.
    ///
    /// Spec (commit 0a5ab85) requires `actor_id` + `delivery_status` on
    /// `membership=join`, with `delivery_binding` mandatory when
    /// `delivery_status=routable`. This convenience helper builds an
    /// unroutable join (membership without a concrete delivery target).
    /// Use [`Self::create_join_with_binding`] for the routable path.
    pub fn join_realm(&self) -> Result<Operation> {
        let operation = self.create_join_operation()?;
        self.base_client
            .update_realm_membership_state(&self.realm_id, RealmMembershipState::Joined)?;
        Ok(operation)
    }

    /// Create a routable join operation that carries a concrete
    /// `member_delivery_binding`. Returns an error if the binding is
    /// internally inconsistent (see [`MemberDeliveryBinding::validate`]).
    pub fn join_realm_with_binding(&self, binding: MemberDeliveryBinding) -> Result<Operation> {
        binding.validate()?;
        let operation = self.create_join_with_binding(binding)?;
        self.base_client
            .update_realm_membership_state(&self.realm_id, RealmMembershipState::Joined)?;
        Ok(operation)
    }

    /// Create a leave operation and update local membership state to left.
    pub fn leave_realm(&self) -> Result<Operation> {
        let operation = self.create_leave_operation()?;
        self.base_client
            .update_realm_membership_state(&self.realm_id, RealmMembershipState::Left)?;
        Ok(operation)
    }

    /// Build an invite operation from a validated
    /// [`MemberDeliveryBindingCandidate`].
    ///
    /// The candidate MUST come from `ak.find.directory.query.resolve_handle(intent="invite")`
    /// or a trusted issuer's signed payload. Per `identity-handles.md` §3.7
    /// the SDK only accepts a candidate or an already-materialised
    /// [`MemberDeliveryBinding`] at this entry point. The candidate is
    /// re-validated against `audience = target Realm id` and `now` before
    /// the operation is emitted; reducer-side Join Policy still applies
    /// independently.
    pub fn invite_with_candidate(
        &self,
        candidate: &MemberDeliveryBindingCandidate,
        role: Option<String>,
    ) -> Result<Operation> {
        let ctx = CandidateValidationContext::new(self.realm_id.as_str().to_owned());
        candidate.validate(&ctx).map_err(map_candidate_err)?;

        let _session_meta = self
            .base_client
            .session_meta()
            .ok_or_else(|| crate::Error::Protocol("no session".to_owned()))?;

        let operation_id = OperationId::new(generate_id("ak:operation:"))?;
        let digest = match candidate.claim_digest.as_ref() {
            Some(claim_digest) => claim_digest.clone(),
            None => Hash::new(candidate.canonical_sha256().map_err(map_candidate_err)?)?,
        };
        let mut payload = InviteCreatePayload::new(
            InviteId::new(generate_id("ak:invite:"))?,
            candidate.subject_id.clone(),
            InviteDeliveryTarget::principal_server(
                candidate
                    .member_delivery_binding
                    .recipient_service_id
                    .clone(),
            ),
            digest,
            candidate.expires_at,
        );
        if let Some(role) = role {
            payload = payload.with_extension("role", Value::String(role))?;
        }

        Ok(Operation::create(
            operation_id,
            self.realm_id()?,
            arkret_core::events::EventKind::INVITE_CREATE,
            payload.to_value()?,
        ))
    }

    /// Build a `member_add` (`ak.member.state{membership=join}`) operation
    /// from a validated [`MemberDeliveryBindingCandidate`].
    ///
    /// Reducer-side Join Policy still applies (the candidate is input, not
    /// authority). On success the payload carries the spec membership fields
    /// plus a fully constructed `delivery_binding` so the reducer can land it
    /// as `ak.member.state{join}.delivery_binding` directly.
    pub fn member_add_with_candidate(
        &self,
        candidate: &MemberDeliveryBindingCandidate,
    ) -> Result<Operation> {
        let ctx = CandidateValidationContext::new(self.realm_id.as_str().to_owned());
        candidate.validate(&ctx).map_err(map_candidate_err)?;

        let binding = candidate_to_delivery_binding(candidate)?;
        binding.validate()?;

        let _session_meta = self
            .base_client
            .session_meta()
            .ok_or_else(|| crate::Error::Protocol("no session".to_owned()))?;

        let operation_id = OperationId::new(generate_id("ak:operation:"))?;
        let payload = MembershipPayload {
            membership: MembershipPayloadState::Join,
            strand_id: None,
            realm_id: Some(self.realm_id()?),
            actor_id: Some(candidate.subject_id.clone()),
            delivery_status: Some(DeliveryStatus::Routable),
            delivery_binding: Some(binding),
            gate_proofs: Vec::new(),
            via_service_ids: Vec::new(),
            reason: None,
            invite_ref: None,
        };

        Ok(Operation::create(
            operation_id,
            self.realm_id()?,
            arkret_core::events::EventKind::MEMBER_STATE,
            payload.to_value()?,
        ))
    }

    /// Create a join operation for the current user to join this Realm.
    ///
    /// Produces an `unroutable` join — used when the current actor does
    /// not yet have an admissible delivery binding for this Realm. The
    /// reducer is expected to accept the membership but suppress
    /// Realm-scoped delivery until a rebind (`routable`) is issued.
    pub fn create_join_operation(&self) -> Result<Operation> {
        let session_meta = self
            .base_client
            .session_meta()
            .ok_or_else(|| crate::Error::Protocol("no session".to_owned()))?;

        let operation_id = OperationId::new(generate_id("ak:operation:"))?;
        let payload = MembershipPayload {
            membership: MembershipPayloadState::Join,
            strand_id: None,
            realm_id: Some(self.realm_id()?),
            actor_id: Some(session_meta.user_id),
            delivery_status: Some(DeliveryStatus::Unroutable),
            delivery_binding: None,
            gate_proofs: Vec::new(),
            via_service_ids: Vec::new(),
            reason: None,
            invite_ref: None,
        };

        Ok(Operation::create(
            operation_id,
            self.realm_id()?,
            arkret_core::events::EventKind::MEMBER_STATE,
            payload.to_value()?,
        ))
    }

    /// Create a `routable` join operation that carries a concrete
    /// [`MemberDeliveryBinding`]. The binding is serialised onto the
    /// `ak.member.state{join}` payload under `delivery_binding` per
    /// `event-payload.schema.json#/$defs/membership_payload`.
    pub fn create_join_with_binding(&self, binding: MemberDeliveryBinding) -> Result<Operation> {
        let session_meta = self
            .base_client
            .session_meta()
            .ok_or_else(|| crate::Error::Protocol("no session".to_owned()))?;

        let operation_id = OperationId::new(generate_id("ak:operation:"))?;
        let payload = MembershipPayload {
            membership: MembershipPayloadState::Join,
            strand_id: None,
            realm_id: Some(self.realm_id()?),
            actor_id: Some(session_meta.user_id),
            delivery_status: Some(DeliveryStatus::Routable),
            delivery_binding: Some(binding),
            gate_proofs: Vec::new(),
            via_service_ids: Vec::new(),
            reason: None,
            invite_ref: None,
        };

        Ok(Operation::create(
            operation_id,
            self.realm_id()?,
            arkret_core::events::EventKind::MEMBER_STATE,
            payload.to_value()?,
        ))
    }

    /// Create a leave operation for the current user to leave this Realm.
    pub fn create_leave_operation(&self) -> Result<Operation> {
        let session_meta = self
            .base_client
            .session_meta()
            .ok_or_else(|| crate::Error::Protocol("no session".to_owned()))?;

        let operation_id = OperationId::new(generate_id("ak:operation:"))?;
        let payload = MembershipPayload {
            membership: MembershipPayloadState::Leave,
            strand_id: None,
            realm_id: Some(self.realm_id()?),
            actor_id: Some(session_meta.user_id),
            delivery_status: None,
            delivery_binding: None,
            gate_proofs: Vec::new(),
            via_service_ids: Vec::new(),
            reason: None,
            invite_ref: None,
        };

        Ok(Operation::create(
            operation_id,
            self.realm_id()?,
            arkret_core::events::EventKind::MEMBER_STATE,
            payload.to_value()?,
        ))
    }

    /// Create a ban operation for a user in this Realm.
    pub fn ban(&self, user_id: Did, reason: Option<String>) -> Result<Operation> {
        let _session_meta = self
            .base_client
            .session_meta()
            .ok_or_else(|| crate::Error::Protocol("no session".to_owned()))?;

        let operation_id = OperationId::new(generate_id("ak:operation:"))?;
        let payload = MembershipPayload {
            membership: MembershipPayloadState::Ban,
            strand_id: None,
            realm_id: Some(self.realm_id()?),
            actor_id: Some(user_id),
            delivery_status: None,
            delivery_binding: None,
            gate_proofs: Vec::new(),
            via_service_ids: Vec::new(),
            reason,
            invite_ref: None,
        };

        Ok(Operation::create(
            operation_id,
            self.realm_id()?,
            arkret_core::events::EventKind::MEMBER_STATE,
            payload.to_value()?,
        ))
    }

    /// Create an unban operation for a user in this Realm.
    pub fn unban(&self, user_id: Did) -> Result<Operation> {
        let _session_meta = self
            .base_client
            .session_meta()
            .ok_or_else(|| crate::Error::Protocol("no session".to_owned()))?;

        let operation_id = OperationId::new(generate_id("ak:operation:"))?;
        let payload = MembershipPayload {
            membership: MembershipPayloadState::Invite,
            strand_id: None,
            realm_id: Some(self.realm_id()?),
            actor_id: Some(user_id),
            delivery_status: None,
            delivery_binding: None,
            gate_proofs: Vec::new(),
            via_service_ids: Vec::new(),
            reason: None,
            invite_ref: None,
        };

        Ok(Operation::create(
            operation_id,
            self.realm_id()?,
            arkret_core::events::EventKind::MEMBER_STATE,
            payload.to_value()?,
        ))
    }
}

/// Materialise the candidate's `member_delivery_binding` into a fully formed
/// [`MemberDeliveryBinding`]. Callers MUST still run
/// [`MemberDeliveryBinding::validate`] before using the binding — this
/// helper only translates field-for-field; it does not enforce conditional
/// `binding_source` constraints (that is the reducer / validator's job).
fn candidate_to_delivery_binding(
    candidate: &MemberDeliveryBindingCandidate,
) -> Result<MemberDeliveryBinding> {
    use crate::models::{
        BindingScope, BindingSource, DeliveryMode, HandleHintBindingSource, RecipientServiceType,
    };

    let hint = &candidate.member_delivery_binding;
    let binding_source = match hint.binding_source {
        HandleHintBindingSource::Explicit => BindingSource::Explicit,
        HandleHintBindingSource::Invite => BindingSource::Invite,
        HandleHintBindingSource::JoinPolicy => BindingSource::JoinPolicy,
        HandleHintBindingSource::OrganizationPolicy => BindingSource::OrganizationPolicy,
        HandleHintBindingSource::RealmPolicy => BindingSource::RealmPolicy,
    };
    let delivery_modes: std::collections::BTreeSet<DeliveryMode> = if hint.delivery_modes.is_empty()
    {
        [
            DeliveryMode::Events,
            DeliveryMode::Sync,
            DeliveryMode::ToDevice,
            DeliveryMode::KeyPackages,
        ]
        .into_iter()
        .collect()
    } else {
        hint.delivery_modes.iter().copied().collect()
    };
    let service_acceptance_ref = hint
        .service_acceptance_ref
        .as_ref()
        .map(|id| EventId::new(id.clone()))
        .transpose()?;
    let policy_event_ref = hint
        .policy_event_ref
        .as_ref()
        .map(|id| EventId::new(id.clone()))
        .transpose()?;

    Ok(MemberDeliveryBinding {
        recipient_service_id: hint.recipient_service_id.clone(),
        recipient_service_type: RecipientServiceType::PrincipalServer,
        binding_scope: BindingScope::Realm,
        binding_source,
        delivery_modes,
        service_endpoint: None,
        did_document_digest: None,
        resolved_at: Utc::now(),
        service_acceptance_ref,
        holder_proof_ref: None,
        policy_event_ref,
        expires_at: Some(candidate.expires_at),
    })
}

/// Map a [`CandidateError`] into the SDK's generic [`crate::Error`] surface
/// so the builder methods can stay `Result<Operation>`.
fn map_candidate_err(err: CandidateError) -> crate::Error {
    crate::Error::Protocol(err.to_string())
}
