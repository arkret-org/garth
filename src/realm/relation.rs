use super::*;

/// Input for creating a relation operation.
#[derive(Clone, Debug)]
pub struct RelationOperationInput {
    pub relation_kind: RelationKind,
    pub from_ref: String,
    pub to_ref: String,
    pub fields: BTreeMap<String, Value>,
}

impl RelationOperationInput {
    pub fn new(
        relation_kind: RelationKind,
        from_ref: impl Into<String>,
        to_ref: impl Into<String>,
    ) -> Self {
        Self {
            relation_kind,
            from_ref: from_ref.into(),
            to_ref: to_ref.into(),
            fields: BTreeMap::new(),
        }
    }
}

/// Relation operations within a space.
impl Realm {
    /// Create a relation creation operation.
    pub fn create_relation_operation(&self, input: RelationOperationInput) -> Result<Operation> {
        let _session_meta = self
            .base_client
            .session_meta()
            .ok_or_else(|| crate::Error::Protocol("no session".to_owned()))?;

        if !input.fields.is_empty() {
            return Err(crate::Error::Protocol(
                "relation create payload does not support fields".to_owned(),
            ));
        }

        let operation_id = OperationId::new(generate_id("ak:operation:"))?;
        let payload =
            RelationCreatePayload::new(input.relation_kind.as_str(), input.from_ref, input.to_ref);

        Ok(Operation::create(
            operation_id,
            self.realm_id()?,
            arkret_core::events::EventKind::RELATION_CREATE,
            payload.to_value()?,
        ))
    }

    /// Create a relation delete operation.
    pub fn delete_relation_operation(&self, relation_id: RelationId) -> Result<Operation> {
        let _session_meta = self
            .base_client
            .session_meta()
            .ok_or_else(|| crate::Error::Protocol("no session".to_owned()))?;

        let operation_id = OperationId::new(generate_id("ak:operation:"))?;
        let payload = json!({ "relation_id": relation_id.as_str() });

        Ok(Operation::create(
            operation_id,
            self.realm_id()?,
            arkret_core::events::EventKind::RELATION_TOMBSTONE,
            payload,
        ))
    }
}
