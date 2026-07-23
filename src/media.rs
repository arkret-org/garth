//! Client-owned local media cache and attachment helpers.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{BlobRef, Did, RealmId, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MediaVisibility {
    Public,
    RealmBound,
    ActorPrivate,
    DeviceBound,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediaAccess {
    pub visibility: MediaVisibility,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediaMetadata {
    pub blob_ref: BlobRef,
    pub sha256: String,
    pub size_bytes: u64,
    pub media_type: String,
    pub filename: Option<String>,
    pub uploaded_by: Did,
    pub uploaded_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    pub access: MediaAccess,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attachment {
    pub id: String,
    pub blob_ref: BlobRef,
    pub filename: String,
    pub media_type: String,
    pub size_bytes: u64,
}

#[derive(Clone, Debug, Default)]
pub struct MemoryBlobStore {
    blobs: BTreeMap<BlobRef, Vec<u8>>,
    metadata: BTreeMap<BlobRef, MediaMetadata>,
    attachments: BTreeMap<String, Attachment>,
}

impl MemoryBlobStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn upload(
        &mut self,
        bytes: impl AsRef<[u8]>,
        media_type: impl Into<String>,
        filename: Option<String>,
        uploaded_by: Did,
    ) -> Result<MediaMetadata> {
        let bytes = bytes.as_ref();
        let digest = arkret_canonical::sha256_hex(bytes);
        let blob_ref = BlobRef::new(format!("ak:blob:sha256:{digest}"))?;
        let metadata = MediaMetadata {
            blob_ref: blob_ref.clone(),
            sha256: digest,
            size_bytes: bytes.len() as u64,
            media_type: media_type.into(),
            filename,
            uploaded_by,
            uploaded_at: Utc::now(),
            realm_id: None,
            access: MediaAccess {
                visibility: MediaVisibility::Public,
            },
        };
        self.blobs.insert(blob_ref.clone(), bytes.to_vec());
        self.metadata.insert(blob_ref, metadata.clone());
        Ok(metadata)
    }

    pub fn download(&self, blob_ref: &BlobRef) -> Option<&[u8]> {
        self.blobs.get(blob_ref).map(Vec::as_slice)
    }

    pub fn upload_attachment(
        &mut self,
        id: impl Into<String>,
        filename: impl Into<String>,
        media_type: impl Into<String>,
        bytes: impl AsRef<[u8]>,
        uploaded_by: Did,
    ) -> Result<Attachment> {
        let filename = filename.into();
        let media_type = media_type.into();
        let metadata = self.upload(
            bytes.as_ref(),
            media_type.clone(),
            Some(filename.clone()),
            uploaded_by,
        )?;
        let attachment = Attachment {
            id: id.into(),
            blob_ref: metadata.blob_ref,
            filename,
            media_type,
            size_bytes: metadata.size_bytes,
        };
        self.attachments
            .insert(attachment.id.clone(), attachment.clone());
        Ok(attachment)
    }
}
