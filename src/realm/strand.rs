use super::*;

/// Optional Strand create metadata accepted by [`Space::create_strand_operation_with_metadata`].
#[derive(Clone, Debug, Default, PartialEq)]
pub struct StrandCreateMetadata {
    pub content: Option<ContentBlock>,
    pub encrypted_content: Option<crate::EncryptedEnvelope>,
    pub encrypted_metadata: Option<crate::EncryptedEnvelope>,
    pub tracks: BTreeMap<String, crate::StrandTrackConfig>,
    /// AKP-0007 — optional Circle that defines this Strand's encryption scope.
    pub scope_circle_id: Option<arkret_core::CircleId>,
}

/// Optional Strand patch metadata accepted by [`Space::update_strand_operation_with_metadata`].
#[derive(Clone, Debug, Default, PartialEq)]
pub struct StrandUpdateMetadata {
    pub content: Option<ContentBlock>,
    pub encrypted_content: Option<crate::EncryptedEnvelope>,
    pub encrypted_metadata: Option<crate::EncryptedEnvelope>,
    pub tracks: Option<BTreeMap<String, crate::StrandTrackConfig>>,
}

impl Realm {
    /// Create a spec-shaped `ak.strand.create` operation.
    pub fn create_strand_operation(
        &self,
        title: impl Into<String>,
        summary: Option<String>,
        fields: BTreeMap<String, Value>,
    ) -> Result<Operation> {
        self.create_strand_operation_with_metadata(
            title,
            summary,
            fields,
            StrandCreateMetadata::default(),
        )
    }

    /// Create a spec-shaped `ak.strand.create` operation with extended Strand fields.
    pub fn create_strand_operation_with_metadata(
        &self,
        title: impl Into<String>,
        summary: Option<String>,
        fields: BTreeMap<String, Value>,
        metadata: StrandCreateMetadata,
    ) -> Result<Operation> {
        let session_meta = self
            .base_client
            .session_meta()
            .ok_or_else(|| crate::Error::Protocol("no session".to_owned()))?;

        let strand_id = StrandId::new(generate_id("ak:strand:"))?;
        let operation_id = OperationId::new(generate_id("ak:operation:"))?;
        let tracks = if metadata.tracks.is_empty() {
            default_strand_tracks()
        } else {
            metadata.tracks
        };

        let mut strand_metadata = crate::models::StrandMetadata {
            title: Some(title.into()),
            ..Default::default()
        };
        if let Some(summary) = summary {
            strand_metadata.summary = Some(summary);
        }
        strand_metadata.fields = fields;

        let mut object = StrandCreateObject::new(strand_id, self.realm_id()?, session_meta.user_id);
        object.metadata = Some(strand_metadata);
        object.tracks = tracks;

        if let Some(content) = metadata.content {
            object.content = Some(content);
        }
        if let Some(encrypted_content) = metadata.encrypted_content {
            object.encrypted_content = Some(encrypted_content);
        }
        if let Some(encrypted_metadata) = metadata.encrypted_metadata {
            object.encrypted_metadata = Some(encrypted_metadata);
        }
        if let Some(scope_circle_id) = metadata.scope_circle_id {
            object.scope_circle_id = Some(scope_circle_id);
        }

        Ok(Operation::create(
            operation_id,
            self.realm_id()?,
            arkret_core::events::EventKind::STRAND_CREATE,
            ObjectCreatePayload::new(object).to_value()?,
        ))
    }

    /// Create a spec-shaped `ak.strand.update` operation.
    pub fn update_strand_operation(
        &self,
        strand_id: StrandId,
        title: Option<String>,
        summary: Option<String>,
        fields: Option<BTreeMap<String, Value>>,
    ) -> Result<Operation> {
        self.update_strand_operation_with_metadata(
            strand_id,
            title,
            summary,
            fields,
            StrandUpdateMetadata::default(),
        )
    }

    /// Create a spec-shaped `ak.strand.update` operation with extended Strand fields.
    pub fn update_strand_operation_with_metadata(
        &self,
        strand_id: StrandId,
        title: Option<String>,
        summary: Option<String>,
        fields: Option<BTreeMap<String, Value>>,
        metadata: StrandUpdateMetadata,
    ) -> Result<Operation> {
        self.base_client
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
        if let Some(fields) = fields {
            patch.insert(
                "metadata.fields",
                payload_value(&fields, "strand metadata fields")?,
            )?;
        }
        if let Some(content) = metadata.content {
            patch.insert("content", payload_value(&content, "strand content")?)?;
            patch.insert("encrypted_content", Value::Null)?;
        }
        if let Some(encrypted_content) = metadata.encrypted_content {
            patch.insert(
                "encrypted_content",
                payload_value(&encrypted_content, "strand encrypted content")?,
            )?;
            patch.insert("content", Value::Null)?;
        }
        if let Some(encrypted_metadata) = metadata.encrypted_metadata {
            patch.insert(
                "encrypted_metadata",
                payload_value(&encrypted_metadata, "strand encrypted metadata")?,
            )?;
            patch.insert("metadata", Value::Null)?;
        }
        if let Some(tracks) = metadata.tracks {
            patch.insert("tracks", payload_value(&tracks, "strand tracks")?)?;
        }

        let mut operation = Operation::create(
            operation_id,
            self.realm_id()?,
            arkret_core::events::EventKind::STRAND_UPDATE,
            StrandPatchPayload::for_strand(strand_id.clone(), patch)?.to_value()?,
        );
        operation.operation_type = OperationType::Update;
        operation.object_id = Some(strand_id.as_str().to_owned());
        Ok(operation)
    }

    /// Create a Strand archive operation.
    pub fn archive_strand_operation(&self, strand_id: StrandId) -> Result<Operation> {
        self.strand_lifecycle_operation(
            strand_id,
            arkret_core::events::EventKind::STRAND_ARCHIVE,
            OperationType::Delete,
        )
    }

    /// Create a Strand restore operation.
    pub fn restore_strand_operation(&self, strand_id: StrandId) -> Result<Operation> {
        self.strand_lifecycle_operation(
            strand_id,
            arkret_core::events::EventKind::STRAND_RESTORE,
            OperationType::Update,
        )
    }

    fn strand_lifecycle_operation(
        &self,
        strand_id: StrandId,
        kind: &str,
        operation_type: OperationType,
    ) -> Result<Operation> {
        self.base_client
            .session_meta()
            .ok_or_else(|| crate::Error::Protocol("no session".to_owned()))?;

        let operation_id = OperationId::new(generate_id("ak:operation:"))?;
        let target_state = if kind == arkret_core::events::EventKind::STRAND_RESTORE {
            "active"
        } else {
            "archived"
        };
        let payload = ObjectLifecyclePayload::new(strand_id.as_str().to_owned())
            .with_target_state(target_state)
            .to_value()?;
        let mut operation = Operation::create(operation_id, self.realm_id()?, kind, payload);
        operation.operation_type = operation_type;
        operation.object_id = Some(strand_id.as_str().to_owned());
        Ok(operation)
    }

    /// Create a `ak.strand.move` operation.
    pub fn move_strand_operation(
        &self,
        strand_id: StrandId,
        board_space_id: SpaceId,
        target_space_id: SpaceId,
        rank: impl Into<String>,
        expected_position: Option<Value>,
    ) -> Result<Operation> {
        self.base_client
            .session_meta()
            .ok_or_else(|| crate::Error::Protocol("no session".to_owned()))?;

        let operation_id = OperationId::new(generate_id("ak:operation:"))?;
        let mut payload =
            StrandMovePayload::new(board_space_id, strand_id.clone(), target_space_id, rank);
        if let Some(expected_position) = expected_position {
            payload = payload.with_expected_position(decode_payload::<StrandMoveExpectedPosition>(
                expected_position,
                "strand move expected position",
            )?);
        }

        let mut operation = Operation::create(
            operation_id,
            self.realm_id()?,
            arkret_core::events::EventKind::STRAND_MOVE,
            payload.to_value()?,
        );
        operation.operation_type = OperationType::Update;
        operation.object_id = Some(strand_id.as_str().to_owned());
        Ok(operation)
    }

    /// Create a `ak.strand.reorder` operation.
    pub fn reorder_strand_operation(
        &self,
        strand_id: StrandId,
        board_space_id: SpaceId,
        space_id: SpaceId,
        rank: impl Into<String>,
        expected_position: Option<Value>,
    ) -> Result<Operation> {
        self.base_client
            .session_meta()
            .ok_or_else(|| crate::Error::Protocol("no session".to_owned()))?;

        let operation_id = OperationId::new(generate_id("ak:operation:"))?;
        let mut payload =
            StrandReorderPayload::new(board_space_id, strand_id.clone(), space_id, rank);
        if let Some(expected_position) = expected_position {
            payload =
                payload.with_expected_position(decode_payload::<StrandReorderExpectedPosition>(
                    expected_position,
                    "strand reorder expected position",
                )?);
        }

        let mut operation = Operation::create(
            operation_id,
            self.realm_id()?,
            arkret_core::events::EventKind::STRAND_REORDER,
            payload.to_value()?,
        );
        operation.operation_type = OperationType::Update;
        operation.object_id = Some(strand_id.as_str().to_owned());
        Ok(operation)
    }
}

fn default_strand_tracks() -> BTreeMap<String, crate::StrandTrackConfig> {
    let mut tracks = BTreeMap::new();
    tracks.insert(
        crate::STRAND_TRACK_NAME_SYNTHESIS.to_owned(),
        crate::StrandTrackConfig::synthesis(),
    );
    tracks
}
