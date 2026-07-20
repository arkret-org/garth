use super::*;

/// Morph operations within a space.
impl Realm {
    /// Create a Morph creation operation.
    pub fn create_morph_operation(
        &self,
        morph_type: impl Into<String>,
        title: Option<String>,
        summary: Option<String>,
        content: Option<ContentBlock>,
        fields: BTreeMap<String, Value>,
    ) -> Result<Operation> {
        let session_meta = self
            .base_client
            .session_meta()
            .ok_or_else(|| crate::Error::Protocol("no session".to_owned()))?;

        let morph_id = MorphId::new(generate_id("ak:morph:"))?;
        let operation_id = OperationId::new(generate_id("ak:operation:"))?;

        let mut object = Morph::new(morph_id, self.realm_id()?, morph_type, session_meta.user_id);

        if let Some(title) = title {
            object = object.with_metadata_title(title);
        }
        if let Some(summary) = summary {
            object
                .metadata
                .get_or_insert_with(ObjectMetadata::default)
                .summary = Some(summary);
        }
        if let Some(content) = content {
            object.content = Some(content);
        }
        object.fields = fields;

        Ok(Operation::create(
            operation_id,
            self.realm_id()?,
            arkret_core::events::EventKind::MORPH_CREATE,
            ObjectCreatePayload::new(object).to_value()?,
        ))
    }

    /// Create a Morph update operation.
    pub fn update_morph_operation(
        &self,
        morph_id: MorphId,
        title: Option<String>,
        summary: Option<String>,
        content: Option<ContentBlock>,
        fields: Option<BTreeMap<String, Value>>,
    ) -> Result<Operation> {
        let _session_meta = self
            .base_client
            .session_meta()
            .ok_or_else(|| crate::Error::Protocol("no session".to_owned()))?;

        let operation_id = OperationId::new(generate_id("ak:operation:"))?;
        let mut patch = Patch::new();

        if let Some(title) = title {
            patch.insert("metadata.title", title)?;
        }
        if let Some(summary) = summary {
            patch.insert("metadata.summary", summary)?;
        }
        if let Some(content) = content {
            patch.insert("content", payload_value(&content, "morph content")?)?;
        }
        if let Some(fields) = fields {
            patch.insert("fields", payload_value(&fields, "morph fields")?)?;
        }

        let mut operation = Operation::create(
            operation_id,
            self.realm_id()?,
            arkret_core::events::EventKind::MORPH_UPDATE,
            MorphUpdatePayload::for_morph(morph_id.clone(), patch)?.to_value()?,
        );
        operation.operation_type = OperationType::Update;
        operation.object_id = Some(morph_id.as_str().to_owned());
        Ok(operation)
    }

    /// Create a Morph archive operation.
    pub fn archive_morph_operation(&self, morph_id: MorphId) -> Result<Operation> {
        let _session_meta = self
            .base_client
            .session_meta()
            .ok_or_else(|| crate::Error::Protocol("no session".to_owned()))?;

        let operation_id = OperationId::new(generate_id("ak:operation:"))?;
        let mut operation = Operation::create(
            operation_id,
            self.realm_id()?,
            arkret_core::events::EventKind::MORPH_ARCHIVE,
            ObjectLifecyclePayload::new(morph_id.as_str().to_owned())
                .with_target_state("archived")
                .to_value()?,
        );
        operation.operation_type = OperationType::Delete;
        operation.object_id = Some(morph_id.as_str().to_owned());
        Ok(operation)
    }
}
