use super::*;

/// Optional Space (container) create metadata accepted by
/// [`Realm::create_space_operation_with_metadata`].
#[derive(Clone, Debug, Default, PartialEq)]
pub struct SpaceCreateMetadata {
    pub parent_space_id: Option<String>,
    pub summary: Option<String>,
    pub rank: Option<String>,
    pub schema_refs: Vec<String>,
    pub fields: BTreeMap<String, Value>,
    pub labels: Vec<String>,
}

/// Optional Space (container) patch metadata accepted by
/// [`Realm::update_space_operation_with_metadata`].
#[derive(Clone, Debug, Default, PartialEq)]
pub struct SpaceUpdateMetadata {
    pub kind: Option<String>,
    pub summary: Option<String>,
    pub rank: Option<String>,
    pub schema_refs: Option<Vec<String>>,
    pub fields: Option<BTreeMap<String, Value>>,
    pub labels: Option<Vec<String>>,
}

impl Realm {
    /// Create a spec-shaped `ak.space.create` operation.
    pub fn create_space_operation(
        &self,
        kind: impl Into<String>,
        title: impl Into<String>,
        parent_space_id: Option<String>,
        rank: Option<String>,
        fields: BTreeMap<String, Value>,
    ) -> Result<Operation> {
        self.create_space_operation_with_metadata(
            kind,
            title,
            SpaceCreateMetadata {
                parent_space_id,
                rank,
                fields,
                ..Default::default()
            },
        )
    }

    /// Create a spec-shaped `ak.space.create` operation with extended Space (container) fields.
    pub fn create_space_operation_with_metadata(
        &self,
        kind: impl Into<String>,
        title: impl Into<String>,
        metadata: SpaceCreateMetadata,
    ) -> Result<Operation> {
        let session_meta = self
            .base_client
            .session_meta()
            .ok_or_else(|| crate::Error::Protocol("no session".to_owned()))?;

        let space_id = SpaceId::new(generate_id("ak:space:"))?;
        let operation_id = OperationId::new(generate_id("ak:operation:"))?;
        let mut object = Space::new(
            space_id.clone(),
            self.realm_id()?,
            kind,
            title,
            session_meta.user_id,
        );

        if let Some(parent_space_id) = metadata.parent_space_id {
            object.parent_space_id = Some(SpaceId::new(parent_space_id)?);
        }
        if let Some(summary) = metadata.summary {
            object.summary = Some(summary);
        }
        if let Some(rank) = metadata.rank {
            object.rank = Some(rank);
        }
        object.schema_refs = metadata.schema_refs;
        object.fields = metadata.fields;
        object.labels = metadata.labels;

        let mut operation = Operation::create(
            operation_id,
            self.realm_id()?,
            arkret_core::events::EventKind::SPACE_CREATE,
            ObjectCreatePayload::new(object).to_value()?,
        );
        operation.object_id = Some(space_id.as_str().to_owned());
        Ok(operation)
    }

    /// Create a spec-shaped `ak.space.update` operation.
    pub fn update_space_operation(
        &self,
        space_id: SpaceId,
        title: Option<String>,
        fields: Option<BTreeMap<String, Value>>,
    ) -> Result<Operation> {
        self.update_space_operation_with_metadata(
            space_id,
            title,
            SpaceUpdateMetadata {
                fields,
                ..Default::default()
            },
        )
    }

    /// Create a spec-shaped `ak.space.update` operation with extended Space (container) fields.
    pub fn update_space_operation_with_metadata(
        &self,
        space_id: SpaceId,
        title: Option<String>,
        metadata: SpaceUpdateMetadata,
    ) -> Result<Operation> {
        self.base_client
            .session_meta()
            .ok_or_else(|| crate::Error::Protocol("no session".to_owned()))?;

        let operation_id = OperationId::new(generate_id("ak:operation:"))?;
        let mut patch = Patch::new();
        if let Some(title) = title {
            patch.insert("title", title)?;
        }
        if let Some(kind) = metadata.kind {
            patch.insert("kind", kind)?;
        }
        if let Some(summary) = metadata.summary {
            patch.insert("summary", summary)?;
        }
        if let Some(rank) = metadata.rank {
            patch.insert("rank", rank)?;
        }
        if let Some(schema_refs) = metadata.schema_refs {
            patch.insert(
                "schema_refs",
                payload_value(&schema_refs, "space schema refs")?,
            )?;
        }
        if let Some(fields) = metadata.fields {
            patch.insert("fields", payload_value(&fields, "space fields")?)?;
        }
        if let Some(labels) = metadata.labels {
            patch.insert("labels", payload_value(&labels, "space labels")?)?;
        }

        let payload = SpacePatchPayload {
            space_id: space_id.clone(),
            patch,
            expected_state_digest: None,
        };
        let mut operation = Operation::create(
            operation_id,
            self.realm_id()?,
            arkret_core::events::EventKind::SPACE_UPDATE,
            payload_value(&payload, "space patch payload")?,
        );
        operation.operation_type = OperationType::Update;
        operation.object_id = Some(space_id.as_str().to_owned());
        Ok(operation)
    }

    /// Create a `ak.space.parent` operation.
    pub fn set_space_parent_operation(
        &self,
        space_id: SpaceId,
        parent_space_id: SpaceId,
    ) -> Result<Operation> {
        self.base_client
            .session_meta()
            .ok_or_else(|| crate::Error::Protocol("no session".to_owned()))?;

        let operation_id = OperationId::new(generate_id("ak:operation:"))?;
        let payload = SpaceParentPayload {
            space_id: space_id.clone(),
            parent_space_id: Some(parent_space_id),
            expected_parent_space_id: None,
        };
        let mut operation = Operation::create(
            operation_id,
            self.realm_id()?,
            arkret_core::events::EventKind::SPACE_PARENT,
            payload_value(&payload, "space parent payload")?,
        );
        operation.operation_type = OperationType::Update;
        operation.object_id = Some(space_id.as_str().to_owned());
        Ok(operation)
    }

    /// Create a `ak.space.archive` operation.
    pub fn archive_space_operation(&self, space_id: SpaceId) -> Result<Operation> {
        self.space_lifecycle_operation(
            space_id,
            arkret_core::events::EventKind::SPACE_ARCHIVE,
            OperationType::Update,
        )
    }

    /// Create a `ak.space.restore` operation (`archived -> active`).
    /// Reducer rejects with `space_not_archived` when current state is not archived.
    pub fn restore_space_operation(&self, space_id: SpaceId) -> Result<Operation> {
        self.space_lifecycle_operation(
            space_id,
            arkret_core::events::EventKind::SPACE_RESTORE,
            OperationType::Update,
        )
    }

    /// Create a `ak.space.tombstone` operation.
    pub fn tombstone_space_operation(&self, space_id: SpaceId) -> Result<Operation> {
        self.space_lifecycle_operation(
            space_id,
            arkret_core::events::EventKind::SPACE_TOMBSTONE,
            OperationType::Delete,
        )
    }

    fn space_lifecycle_operation(
        &self,
        space_id: SpaceId,
        kind: &str,
        operation_type: OperationType,
    ) -> Result<Operation> {
        self.base_client
            .session_meta()
            .ok_or_else(|| crate::Error::Protocol("no session".to_owned()))?;

        let operation_id = OperationId::new(generate_id("ak:operation:"))?;
        let payload = if kind == arkret_core::events::EventKind::SPACE_TOMBSTONE {
            payload_value(
                &SpaceObjectTombstonePayload {
                    space_id: space_id.clone(),
                    reason: None,
                    replacement_space: None,
                    replacement_event: None,
                    effective_at: None,
                },
                "space tombstone payload",
            )?
        } else {
            payload_value(
                &SpaceStateTransitionPayload {
                    space_id: space_id.clone(),
                    reason: None,
                    effective_at: None,
                },
                "space state transition payload",
            )?
        };
        let mut operation = Operation::create(operation_id, self.realm_id()?, kind, payload);
        operation.operation_type = operation_type;
        operation.object_id = Some(space_id.as_str().to_owned());
        Ok(operation)
    }
}
