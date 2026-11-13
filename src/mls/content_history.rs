//! Encrypted, endpoint-separated custody for exact history exchanges.
//! These records never establish native read, issuer or original authority.

use arkret_event_draft::EventPayloadExt as _;
use arkret_models_crypto::{
    AttachmentContentKeyContext, ContentEndpoint, ContentRootContext, EventContentMaterial,
    HistoryGrant, HistoryGrantEntry, HistoryKeySelector,
};
use arkret_wire::{
    ActorId, CommittedEventRef, Event, EventId, EventKind, Hash, MlsWelcomeRecipientEndpoint,
    ScopeRef,
};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::{Error, Result, SecureKeyStore};

fn rejected(error: impl std::fmt::Display) -> Error {
    Error::Protocol(error.to_string())
}

pub fn is_history_exchange_vault_key(key: &str) -> bool {
    [
        "history-request/v1/",
        "history-content-key/v1/",
        "history-grant-outbox/v1/",
    ]
    .iter()
    .any(|prefix| key.starts_with(prefix) || key.contains(&format!(".{prefix}")))
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingHistoryRequest {
    event: Event,
    private_key_base64url: Option<String>,
}

impl Drop for PendingHistoryRequest {
    fn drop(&mut self) {
        if let Some(key) = &mut self.private_key_base64url {
            key.zeroize();
        }
    }
}

impl PendingHistoryRequest {
    pub fn new(event: Event, private_key: &[u8]) -> Result<Self> {
        let value = Self {
            event,
            private_key_base64url: Some(arkret_canonical::base64url_encode(private_key)),
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<()> {
        if self.event.kind != EventKind::MlsHistoryRequest
            || self.event.executed_by.is_some()
            || self.event.authorization_ref.is_some()
        {
            return Err(rejected(
                "history request must be exact self-authored endpoint proof",
            ));
        }
        let request = self.event.as_mls_history_request().map_err(rejected)?;
        let suite = self.event.realm_id.digest_suite_code().digest_suite();
        self.event
            .verify_event_id_matches_content_with_digest_suite(suite)
            .map_err(rejected)?;
        self.event
            .verify_producer_proof_self_consistency(suite)
            .map_err(rejected)?;
        if request.history_cut.stream_ref
            != arkret_wire::CommitStreamRef::from_scope(
                &self.event.scope_ref,
                Some(self.event.realm_id.clone()),
            )
            .map_err(rejected)?
        {
            return Err(rejected("history request cut belongs to another scope"));
        }
        if request.recipient.actor_id != self.event.actor_id {
            return Err(rejected("history request actor differs"));
        }
        if let Some(key) = &self.private_key_base64url {
            let private =
                Zeroizing::new(arkret_canonical::base64url_decode(key).map_err(rejected)?);
            let public = arkret_crypto::hpke::x25519_public_key(&private).map_err(rejected)?;
            if arkret_canonical::base64url_encode(public) != request.recipient_hpke_key_base64url {
                return Err(rejected(
                    "history request private key differs from its signed public key",
                ));
            }
        }
        Ok(())
    }

    pub fn event(&self) -> &Event {
        &self.event
    }
    pub fn has_private_key(&self) -> bool {
        self.private_key_base64url.is_some()
    }

    pub fn open_entry(
        &self,
        grant: &HistoryGrant,
        entry: &HistoryGrantEntry,
        at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Zeroizing<Vec<u8>>> {
        self.validate()?;
        let request = self.event.as_mls_history_request().map_err(rejected)?;
        request
            .validate_at(self.event.created_at, at)
            .map_err(rejected)?;
        grant
            .validate_for_request(&self.event.event_id, &request)
            .map_err(rejected)?;
        if !grant.entries.contains(entry) {
            return Err(rejected("history entry is not in its original grant"));
        }
        let private = self
            .private_key_base64url
            .as_ref()
            .ok_or_else(|| rejected("history request has been consumed"))?;
        let private =
            Zeroizing::new(arkret_canonical::base64url_decode(private).map_err(rejected)?);
        arkret_crypto::content_history::open_history_key(
            grant,
            &entry.selector,
            &private,
            &entry.sealed_key_base64url,
        )
        .map_err(rejected)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RetainedHistoryKeyContext {
    Body {
        material: EventContentMaterial,
    },
    Attachment {
        root_context: ContentRootContext,
        context: AttachmentContentKeyContext,
    },
}

impl RetainedHistoryKeyContext {
    pub fn root_context(&self) -> &ContentRootContext {
        match self {
            Self::Body { material } => &material.content_context.root_context,
            Self::Attachment { root_context, .. } => root_context,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetainedHistoryContentKey {
    pub source: CommittedEventRef,
    pub content_path: String,
    pub context: RetainedHistoryKeyContext,
    pub key_commitment: Hash,
    key_base64url: String,
}

impl Drop for RetainedHistoryContentKey {
    fn drop(&mut self) {
        self.key_base64url.zeroize();
    }
}

impl RetainedHistoryContentKey {
    pub fn new(
        source: CommittedEventRef,
        content_path: String,
        context: RetainedHistoryKeyContext,
        key_commitment: Hash,
        key: &[u8],
    ) -> Result<Self> {
        let value = Self {
            source,
            content_path,
            context,
            key_commitment,
            key_base64url: arkret_canonical::base64url_encode(key),
        };
        value.key()?;
        Ok(value)
    }

    pub fn key(&self) -> Result<Zeroizing<Vec<u8>>> {
        HistoryKeySelector::ContentKey {
            source_event_ref: self.source.event_id.clone(),
            content_path: self.content_path.clone(),
        }
        .validate()
        .map_err(rejected)?;
        let key = Zeroizing::new(
            arkret_canonical::base64url_decode(&self.key_base64url).map_err(rejected)?,
        );
        let scope = &self.context.root_context().effective_scope;
        if self.source.stream_ref
            != arkret_wire::CommitStreamRef::from_scope(scope, Some(scope.realm_id().clone()))
                .map_err(rejected)?
        {
            return Err(rejected(
                "history key original stream differs from its context",
            ));
        }
        let expected = match &self.context {
            RetainedHistoryKeyContext::Body { material } if key.len() == 16 => {
                material.content_context.validate().map_err(rejected)?;
                if material.key_commitment != self.key_commitment {
                    return Err(rejected(
                        "history body commitment differs from original material",
                    ));
                }
                arkret_crypto::key_commitment::content_key_commitment_sha256(
                    &material.content_context,
                    &key,
                )
                .map_err(rejected)?
            }
            RetainedHistoryKeyContext::Attachment {
                root_context,
                context,
            } if key.len() == 32 => {
                root_context.validate().map_err(rejected)?;
                context.validate().map_err(rejected)?;
                if context.effective_scope != root_context.effective_scope
                    || context.genesis_event_ref != root_context.genesis_event_ref
                    || context.epoch != root_context.epoch
                {
                    return Err(rejected(
                        "history attachment context differs from its public epoch",
                    ));
                }
                arkret_crypto::key_commitment::content_key_commitment_sha256(context, &key)
                    .map_err(rejected)?
            }
            _ => return Err(rejected("history selected key has the wrong width")),
        };
        if expected != self.key_commitment {
            return Err(rejected("history selected key commitment mismatch"));
        }
        Ok(key)
    }
}

#[cfg(test)]
mod tests;

pub struct HistoryExchangeVault<'a> {
    store: &'a dyn SecureKeyStore,
    actor: &'a ActorId,
    endpoint: &'a MlsWelcomeRecipientEndpoint,
}

impl<'a> HistoryExchangeVault<'a> {
    pub fn new(
        store: &'a dyn SecureKeyStore,
        actor: &'a ActorId,
        endpoint: &'a MlsWelcomeRecipientEndpoint,
    ) -> Self {
        Self {
            store,
            actor,
            endpoint,
        }
    }

    fn key(&self, class: &str, selector: impl Serialize) -> Result<String> {
        Ok(format!(
            "{class}/v1/{}",
            arkret_canonical::sha256_digest(arkret_canonical::canonical_json_bytes(&(
                self.actor,
                self.endpoint,
                selector
            ))?)
        ))
    }

    fn require_recipient(&self, recipient: &ContentEndpoint) -> Result<()> {
        if &recipient.actor_id != self.actor || &recipient.endpoint != self.endpoint {
            return Err(rejected("history custody belongs to another endpoint"));
        }
        Ok(())
    }

    pub async fn request(&self, scope: &ScopeRef) -> Result<Option<PendingHistoryRequest>> {
        let bytes = self
            .store
            .read_secret_bytes_durable(&self.key("history-request", scope)?)
            .await
            .map_err(rejected)?;
        let value: Option<PendingHistoryRequest> = bytes
            .map(|value| serde_json::from_slice(value.as_slice()))
            .transpose()?;
        if let Some(value) = &value {
            value.validate()?;
            self.require_recipient(
                &value
                    .event
                    .as_mls_history_request()
                    .map_err(rejected)?
                    .recipient,
            )?;
        }
        Ok(value)
    }

    /// Commit the fresh private key and frozen original before any publication.
    /// A concurrent valid request wins without publishing the losing candidate.
    pub async fn freeze_request(
        &self,
        candidate: PendingHistoryRequest,
        at: chrono::DateTime<chrono::Utc>,
    ) -> Result<PendingHistoryRequest> {
        candidate.validate()?;
        let request = candidate.event.as_mls_history_request().map_err(rejected)?;
        self.require_recipient(&request.recipient)?;
        request
            .validate_at(candidate.event.created_at, at)
            .map_err(rejected)?;
        let key = self.key("history-request", &candidate.event.scope_ref)?;
        let replacement = Zeroizing::new(serde_json::to_vec(&candidate)?);
        for _ in 0..8 {
            let previous = self
                .store
                .read_secret_bytes_durable(&key)
                .await
                .map_err(rejected)?;
            if let Some(previous) = &previous {
                let old: PendingHistoryRequest = serde_json::from_slice(previous.as_slice())?;
                old.validate()?;
                let old_request = old.event.as_mls_history_request().map_err(rejected)?;
                if old.has_private_key()
                    && old_request.recipient == request.recipient
                    && old_request.validate_at(old.event.created_at, at).is_ok()
                {
                    return Ok(old);
                }
            }
            if self
                .store
                .compare_exchange_secret_bytes_durable(
                    &key,
                    previous.as_ref().map(|value| value.as_slice()),
                    &replacement,
                )
                .await
                .map_err(rejected)?
            {
                return Ok(candidate);
            }
        }
        Err(rejected("history request custody contended"))
    }

    pub async fn consume_request(&self, scope: &ScopeRef, expected_event: &EventId) -> Result<()> {
        let key = self.key("history-request", scope)?;
        for _ in 0..8 {
            let Some(previous) = self
                .store
                .read_secret_bytes_durable(&key)
                .await
                .map_err(rejected)?
            else {
                return Ok(());
            };
            let mut value: PendingHistoryRequest = serde_json::from_slice(previous.as_slice())?;
            if &value.event.event_id != expected_event || !value.has_private_key() {
                return Ok(());
            }
            if let Some(mut private) = value.private_key_base64url.take() {
                private.zeroize();
            }
            let replacement = Zeroizing::new(serde_json::to_vec(&value)?);
            if self
                .store
                .compare_exchange_secret_bytes_durable(
                    &key,
                    Some(previous.as_slice()),
                    &replacement,
                )
                .await
                .map_err(rejected)?
            {
                return Ok(());
            }
        }
        Err(rejected("history request consumption contended"))
    }

    pub fn cached_key(
        &self,
        source: &EventId,
        content_path: &str,
    ) -> Result<Option<RetainedHistoryContentKey>> {
        let key = self.key("history-content-key", (source, content_path))?;
        let value: Option<RetainedHistoryContentKey> = self
            .store
            .get_secret_bytes(&key)
            .map_err(rejected)?
            .map(|value| serde_json::from_slice(value.as_slice()))
            .transpose()?;
        if let Some(value) = &value {
            if &value.source.event_id != source || value.content_path != content_path {
                return Err(rejected("history selected key source differs"));
            }
            value.key()?;
        }
        Ok(value)
    }

    /// Load immutable key custody from the committed backend before a cold
    /// projection. Its no-op CAS also hydrates a backend's local read cache;
    /// it cannot resurrect an entry removed since the durable observation.
    pub async fn read_key(
        &self,
        source: &EventId,
        content_path: &str,
    ) -> Result<Option<RetainedHistoryContentKey>> {
        let key = self.key("history-content-key", (source, content_path))?;
        for _ in 0..8 {
            let Some(bytes) = self
                .store
                .read_secret_bytes_durable(&key)
                .await
                .map_err(rejected)?
            else {
                return Ok(None);
            };
            let value: RetainedHistoryContentKey = serde_json::from_slice(bytes.as_slice())?;
            if &value.source.event_id != source || value.content_path != content_path {
                return Err(rejected("history selected key source differs"));
            }
            value.key()?;
            if self
                .store
                .get_secret_bytes(&key)
                .map_err(rejected)?
                .is_some()
                || self
                    .store
                    .compare_exchange_secret_bytes_durable(
                        &key,
                        Some(bytes.as_slice()),
                        bytes.as_slice(),
                    )
                    .await
                    .map_err(rejected)?
            {
                return Ok(Some(value));
            }
        }
        Err(rejected("history key hydration contended"))
    }

    /// The caller independently verifies original Commit, public attribution,
    /// exact selection and current read authority before retaining this key.
    pub async fn retain_key(&self, value: &RetainedHistoryContentKey) -> Result<()> {
        value.key()?;
        let key = self.key(
            "history-content-key",
            (&value.source.event_id, &value.content_path),
        )?;
        let replacement = Zeroizing::new(serde_json::to_vec(value)?);
        for _ in 0..8 {
            let previous = self
                .store
                .read_secret_bytes_durable(&key)
                .await
                .map_err(rejected)?;
            if let Some(previous) = &previous {
                let old: RetainedHistoryContentKey = serde_json::from_slice(previous.as_slice())?;
                old.key()?;
                if old.source != value.source
                    || old.context != value.context
                    || old.key_commitment != value.key_commitment
                    || old.key()? != value.key()?
                {
                    return Err(rejected(
                        "immutable history key conflicts with its original",
                    ));
                }
                return Ok(());
            }
            if self
                .store
                .compare_exchange_secret_bytes_durable(&key, None, &replacement)
                .await
                .map_err(rejected)?
            {
                return Ok(());
            }
        }
        Err(rejected("history key retention contended"))
    }

    pub async fn frozen_grant(
        &self,
        request: &EventId,
        selectors: &[HistoryKeySelector],
        candidate: Option<&Event>,
    ) -> Result<Option<Event>> {
        let key = self.key("history-grant-outbox", (request, selectors))?;
        for _ in 0..8 {
            if let Some(bytes) = self
                .store
                .read_secret_bytes_durable(&key)
                .await
                .map_err(rejected)?
            {
                let event: Event = serde_json::from_slice(bytes.as_slice())?;
                let grant = event.as_mls_history_grant().map_err(rejected)?;
                if &grant.recipient_key_event_ref != request
                    || grant
                        .entries
                        .iter()
                        .map(|entry| &entry.selector)
                        .ne(selectors.iter())
                {
                    return Err(rejected("frozen history grant selection differs"));
                }
                return Ok(Some(event));
            }
            let Some(candidate) = candidate else {
                return Ok(None);
            };
            let grant = candidate.as_mls_history_grant().map_err(rejected)?;
            if &candidate.actor_id != self.actor
                || &grant.recipient_key_event_ref != request
                || grant
                    .entries
                    .iter()
                    .map(|entry| &entry.selector)
                    .ne(selectors.iter())
            {
                return Err(rejected("history grant differs from its frozen intent"));
            }
            let bytes = serde_json::to_vec(candidate)?;
            if self
                .store
                .compare_exchange_secret_bytes_durable(&key, None, &bytes)
                .await
                .map_err(rejected)?
            {
                return Ok(Some(candidate.clone()));
            }
        }
        Err(rejected("history grant outbox contended"))
    }
}
