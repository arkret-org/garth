//! High-level Realm client API for the Garth Arkret v1 runtime.
//!
//! This module hosts the security-boundary client handle (`Realm`). It
//! provides a high-level interface for working with Realms and their contained
//! Spaces, including Morph management, relations, timeline operations, and
//! membership.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde_json::{Value, json};

use crate::base::{BaseClient, RealmMembershipState};
use crate::media::{Attachment, MediaMetadata};
use crate::models::{
    BlobRef, ContentBlock, DeliveryStatus, Did, EventId, FieldFilter, Filter, FilterOp, Hash,
    InviteCreatePayload, InviteDeliveryTarget, InviteId, MemberDeliveryBinding, MembershipPayload,
    MembershipPayloadState, MessageCreatePayload, MessageId, MessageRedactPayload,
    MessageRevisePayload, Morph, MorphId, MorphUpdatePayload, NullsOrder, ObjectCreatePayload,
    ObjectLifecyclePayload, ObjectMetadata, ObjectState, Operation, OperationId, OperationType,
    Patch, Relation, RelationCreatePayload, RelationId, RelationKind, RelationState, SortDirection,
    SortSpec, Space, SpaceObjectTombstonePayload, SpaceParentPayload, SpacePatchPayload,
    SpaceStateTransitionPayload, Strand, StrandCreateObject, StrandMoveExpectedPosition,
    StrandMovePayload, StrandPatchPayload, StrandReorderExpectedPosition, StrandReorderPayload,
};
use crate::resolver::RealmState;
use crate::{RealmId, Result, SpaceId, StrandId};

pub mod bootstrap;
mod helpers;
mod membership;
mod morph;
mod payload;
mod query;
mod relation;
mod space;
/// Generate a new UUIDv7-based wire ID with the given Arkret typed prefix.
mod strand;
#[cfg(test)]
mod tests;

use helpers::*;
use payload::*;
pub use relation::RelationOperationInput;
pub use space::{SpaceCreateMetadata, SpaceUpdateMetadata};
pub use strand::{StrandCreateMetadata, StrandUpdateMetadata};

fn generate_id(prefix: &str) -> String {
    format!("{prefix}{}", uuid::Uuid::now_v7())
}

/// Morph query options applied to the local resolved state.
#[derive(Clone, Debug, Default)]
pub struct MorphQuery {
    /// Morph types to include. Empty means all types.
    pub morph_types: Vec<String>,
    /// Filters combined with AND semantics.
    pub filters: Vec<Filter>,
    /// Sort specifications applied in order.
    pub order_by: Vec<SortSpec>,
    /// Maximum result count.
    pub limit: Option<usize>,
}

/// Aggregated Morph counts.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MorphAggregation {
    /// Total number of Morph objects considered.
    pub total: usize,
    /// Counts grouped by Morph type.
    pub by_type: BTreeMap<String, usize>,
    /// Counts grouped by requested field keys.
    pub by_field: BTreeMap<String, BTreeMap<String, usize>>,
}

/// Relation graph traversal order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GraphTraversal {
    /// Breadth-first traversal.
    BreadthFirst,
    /// Depth-first traversal.
    DepthFirst,
}

/// Morph state at a historical version.
#[derive(Clone, Debug, PartialEq)]
pub struct MorphVersion {
    /// Morph ID.
    pub morph_id: MorphId,
    /// Version number, starting at 0 for creation.
    pub version: u64,
    /// Event that produced this version.
    pub event_id: EventId,
    /// Time the version was produced.
    pub updated_at: DateTime<Utc>,
    /// Morph title at this version.
    pub title: Option<String>,
    /// Morph content at this version.
    pub content: Option<ContentBlock>,
    /// Morph fields at this version.
    pub fields: BTreeMap<String, Value>,
    /// Morph object state at this version.
    pub state: Option<ObjectState>,
}

/// Field-level diff between two Morph versions.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MorphVersionDiff {
    /// Title changed.
    pub title_changed: bool,
    /// Content changed.
    pub content_changed: bool,
    /// Field keys added in the target version.
    pub added_fields: Vec<String>,
    /// Field keys removed in the target version.
    pub removed_fields: Vec<String>,
    /// Field keys present in both versions with different values.
    pub changed_fields: Vec<String>,
}

/// Input for batch Morph creation.
#[derive(Clone, Debug)]
pub struct BatchCreateMorph {
    pub morph_type: String,
    pub title: Option<String>,
    pub summary: Option<String>,
    pub content: Option<ContentBlock>,
    pub fields: BTreeMap<String, Value>,
}

/// Input for batch Morph update.
#[derive(Clone, Debug)]
pub struct BatchUpdateMorph {
    pub morph_id: MorphId,
    pub title: Option<String>,
    pub summary: Option<String>,
    pub content: Option<ContentBlock>,
    pub fields: Option<BTreeMap<String, Value>>,
}

/// High-level Realm client providing business logic operations.
///
/// This client handle is the security-boundary surface. Its
/// `*_space_operation*` helpers and `spaces()` accessors operate on contained
/// Space container objects.
#[derive(Clone)]
pub struct Realm {
    /// Realm ID
    pub realm_id: RealmId,
    /// Base client reference
    base_client: Arc<BaseClient>,
    /// Current Realm reducer state.
    state: Arc<RealmState>,
}

impl Realm {
    /// Create a new Realm client.
    pub fn new(realm_id: RealmId, base_client: Arc<BaseClient>) -> Self {
        let state = if let Some(client_realm) = base_client.get_realm(&realm_id) {
            Arc::new(client_realm.realm_state)
        } else {
            Arc::new(RealmState::new(realm_id.clone()))
        };

        Self {
            realm_id,
            base_client,
            state,
        }
    }

    /// Get the Realm ID.
    pub fn id(&self) -> &RealmId {
        &self.realm_id
    }

    /// Canonical Realm scope for operations emitted by this client.
    pub fn realm_id(&self) -> Result<RealmId> {
        Ok(self.realm_id.clone())
    }

    /// Get the current Realm state.
    pub fn state(&self) -> &RealmState {
        &self.state
    }

    /// Refresh the Realm state from the base client.
    pub fn refresh_state(&mut self) -> Result<()> {
        if let Some(client_realm) = self.base_client.get_realm(&self.realm_id) {
            self.state = Arc::new(client_realm.realm_state);
        }
        Ok(())
    }

    /// Check if the user is a member of this Realm.
    pub fn is_joined(&self) -> bool {
        if let Some(client_realm) = self.base_client.get_realm(&self.realm_id) {
            client_realm.state == RealmMembershipState::Joined
        } else {
            false
        }
    }

    /// Check if the user has been invited to this Realm.
    pub fn is_invited(&self) -> bool {
        if let Some(client_realm) = self.base_client.get_realm(&self.realm_id) {
            client_realm.state == RealmMembershipState::Invited
        } else {
            false
        }
    }

    /// Check if the user has left this Realm.
    pub fn is_left(&self) -> bool {
        if let Some(client_realm) = self.base_client.get_realm(&self.realm_id) {
            client_realm.state == RealmMembershipState::Left
        } else {
            false
        }
    }

    /// Get notification count for this Realm.
    pub fn notification_count(&self) -> u64 {
        if let Some(client_realm) = self.base_client.get_realm(&self.realm_id) {
            client_realm.notification_count
        } else {
            0
        }
    }

    /// Get highlight count for this Realm.
    pub fn highlight_count(&self) -> u64 {
        if let Some(client_realm) = self.base_client.get_realm(&self.realm_id) {
            client_realm.highlight_count
        } else {
            0
        }
    }

    /// Get the read marker for this Realm.
    pub fn read_marker(&self) -> Option<String> {
        self.base_client.read_marker(&self.realm_id)
    }

    /// Set the read marker for this Realm.
    pub fn set_read_marker(&self, marker: String) -> Result<()> {
        self.base_client.set_read_marker(&self.realm_id, marker)
    }

    /// Get all Morph objects in this Realm.
    pub fn morphs(&self) -> BTreeMap<String, Morph> {
        self.state.morphs.clone()
    }

    /// Get all Spaces (containers) in this realm.
    pub fn spaces(&self) -> BTreeMap<String, Space> {
        self.state.spaces.clone()
    }

    /// Get a specific Space (container) by ID.
    pub fn get_space(&self, space_id: &SpaceId) -> Option<Space> {
        self.state.spaces.get(space_id.as_str()).cloned()
    }

    /// Find Spaces (containers) by kind.
    pub fn find_spaces_by_kind(&self, kind: &str) -> Vec<Space> {
        self.state
            .spaces
            .values()
            .filter(|space| space.kind == kind)
            .cloned()
            .collect()
    }

    /// Get all strands in this space.
    pub fn strands(&self) -> BTreeMap<String, Strand> {
        self.state.subjects.clone()
    }

    /// Get a specific strand by ID.
    pub fn get_strand(&self, strand_id: &StrandId) -> Option<Strand> {
        self.state.subjects.get(strand_id.as_str()).cloned()
    }

    /// Find strands that have a track with the given profile.
    pub fn find_strands_by_track_profile(&self, track_profile: &str) -> Vec<Strand> {
        self.state
            .subjects
            .values()
            .filter(|strand| {
                strand
                    .tracks
                    .values()
                    .any(|track| track.profile.as_deref() == Some(track_profile))
            })
            .cloned()
            .collect()
    }

    /// Return active default view relations for a strand.
    pub fn strand_default_views(&self, strand_id: &StrandId) -> Vec<Relation> {
        self.state
            .relations
            .values()
            .filter(|relation| {
                relation.relation_kind == RelationKind::HasDefaultView
                    && relation.from_ref == strand_id.as_str()
                    && relation_is_active(relation)
            })
            .cloned()
            .collect()
    }

    /// Get a specific Morph by ID.
    pub fn get_morph(&self, morph_id: &MorphId) -> Option<Morph> {
        self.state.morphs.get(morph_id.as_str()).cloned()
    }

    /// Find Morph objects by type.
    pub fn find_morphs_by_type(&self, morph_type: &str) -> Vec<Morph> {
        self.state
            .morphs
            .values()
            .filter(|morph| morph.morph_type == morph_type)
            .cloned()
            .collect()
    }

    /// Find Morph objects by field value.
    pub fn find_morphs_by_field(&self, field_key: &str, field_value: &Value) -> Vec<Morph> {
        self.state
            .morphs
            .values()
            .filter(|morph| {
                morph
                    .fields
                    .get(field_key)
                    .map(|v| v == field_value)
                    .unwrap_or(false)
            })
            .cloned()
            .collect()
    }

    /// Get all relations in this space.
    pub fn relations(&self) -> BTreeMap<String, Relation> {
        self.state.relations.clone()
    }

    /// Get a specific relation by ID.
    pub fn get_relation(&self, relation_id: &RelationId) -> Option<Relation> {
        self.state.relations.get(relation_id.as_str()).cloned()
    }

    /// Find relations by kind.
    pub fn find_relations_by_kind(&self, relation_kind: RelationKind) -> Vec<Relation> {
        self.state
            .relations
            .values()
            .filter(|r| r.relation_kind == relation_kind)
            .cloned()
            .collect()
    }

    /// Find relations from a typed object reference.
    pub fn find_relations_from_ref(&self, object_ref: &str) -> Vec<Relation> {
        self.state
            .relations
            .values()
            .filter(|r| r.from_ref == object_ref)
            .cloned()
            .collect()
    }

    /// Find relations to a typed object reference.
    pub fn find_relations_to_ref(&self, object_ref: &str) -> Vec<Relation> {
        self.state
            .relations
            .values()
            .filter(|r| r.to_ref == object_ref)
            .cloned()
            .collect()
    }

    /// Get the causal frontier (most recent event IDs).
    pub fn frontier(&self) -> Vec<EventId> {
        self.state.frontier.clone()
    }

    /// Create a snapshot of the current space state.
    pub fn snapshot(&self) -> Result<crate::StateSnapshot> {
        // `arkret-state` returns `arkret_wire::WireError`; bridge into the
        // SDK's `crate::protocol::Error` via the `?` From conversion.
        Ok(self.state.snapshot()?)
    }

    /// Apply events to update the space state.
    pub fn apply_events(&self, events: Vec<crate::models::Event>) -> Result<()> {
        self.base_client.process_events(&self.realm_id, events)
    }

    /// Create a local message send operation using a structured message content object.
    pub fn send_message(&self, content: ContentBlock) -> Result<Operation> {
        self.base_client.whoami()?;
        let operation_id = OperationId::new(generate_id("ak:operation:"))?;
        let strand_id = StrandId::new(generate_id("ak:strand:"))?;
        let payload = MessageCreatePayload::with_content(strand_id, "discussion", content)
            .with_message_id(generate_id("ak:message:"))
            .to_value()?;
        Ok(Operation::create(
            operation_id,
            self.realm_id()?,
            crate::protocol::events::EventKind::MESSAGE_CREATE,
            payload,
        ))
    }

    /// Create a local plain-text message send operation.
    pub fn send_text(&self, body: impl Into<String>) -> Result<Operation> {
        self.send_message(ContentBlock::text(body))
    }

    /// Create a local message edit operation.
    pub fn edit_message(&self, message_id: MessageId, content: Value) -> Result<Operation> {
        self.base_client.whoami()?;
        let operation_id = OperationId::new(generate_id("ak:operation:"))?;
        let payload = MessageRevisePayload {
            message_id: Some(message_id.clone()),
            target_ref: None,
            revision_of: None,
            track_name: None,
            content: Some(content_block_from_value(content)?),
            encrypted_content: None,
            metadata: None,
            encrypted_metadata: None,
            reason: None,
        };
        let mut operation = Operation::create(
            operation_id,
            self.realm_id()?,
            crate::protocol::events::EventKind::MESSAGE_REVISE,
            payload_value(&payload, "message revise payload")?,
        );
        operation.object_id = Some(message_id.as_str().to_owned());
        Ok(operation)
    }

    /// Create a local message redaction operation.
    pub fn redact_message(
        &self,
        message_id: MessageId,
        reason: Option<String>,
    ) -> Result<Operation> {
        self.base_client.whoami()?;
        let operation_id = OperationId::new(generate_id("ak:operation:"))?;
        let payload = MessageRedactPayload {
            message_id: Some(message_id.clone()),
            target_ref: None,
            event_id: None,
            target_event_id: None,
            track_name: None,
            reason,
            preserve: None,
        };
        let mut operation = Operation::create(
            operation_id,
            self.realm_id()?,
            crate::protocol::events::EventKind::MESSAGE_REDACT,
            payload_value(&payload, "message redact payload")?,
        );
        operation.operation_type = OperationType::Redact;
        operation.object_id = Some(message_id.as_str().to_owned());
        Ok(operation)
    }

    /// Upload media into the base client's local in-memory media store.
    pub fn upload_media(
        &self,
        bytes: impl AsRef<[u8]>,
        media_type: impl Into<String>,
        filename: Option<String>,
    ) -> Result<MediaMetadata> {
        self.base_client.upload_media(bytes, media_type, filename)
    }

    /// Download media from the base client's local in-memory media store.
    pub fn download_media(&self, blob_ref: &BlobRef) -> Option<Vec<u8>> {
        self.base_client.download_media(blob_ref)
    }

    /// Upload an attachment into the base client's local in-memory media store.
    pub fn upload_attachment(
        &self,
        id: impl Into<String>,
        filename: impl Into<String>,
        media_type: impl Into<String>,
        bytes: impl AsRef<[u8]>,
    ) -> Result<Attachment> {
        self.base_client
            .upload_attachment(id, filename, media_type, bytes)
    }
}
