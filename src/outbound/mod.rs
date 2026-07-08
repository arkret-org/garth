use cokret::{
    ContentBlock, Did, EventEnvelope, GrantId, Hlc, MessageCreatePayload, OP_MESSAGE_CREATE,
    Operation, OperationEnvelope, OperationEnvelopeBuilder, OperationEventConversion, OperationId,
    OperationKindRegistry, RealmId, Result, StrandId, new_prefixed_uuid7,
};
use serde_json::Value;

#[derive(Clone, Debug)]
pub struct OutboundBuilder {
    registry: OperationKindRegistry,
}

impl Default for OutboundBuilder {
    fn default() -> Self {
        Self {
            registry: OperationKindRegistry::default(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutboundCommandContext {
    pub actor_id: Did,
    pub actor_seq: u64,
    pub hlc: Hlc,
    pub deps: Vec<OperationId>,
    pub authz_ref: Option<GrantId>,
}

impl OutboundCommandContext {
    pub fn new(actor_id: Did, actor_seq: u64, hlc: Hlc) -> Self {
        Self {
            actor_id,
            actor_seq,
            hlc,
            deps: Vec::new(),
            authz_ref: None,
        }
    }

    pub fn with_dependency(mut self, dependency: OperationId) -> Self {
        self.deps.push(dependency);
        self
    }

    pub fn with_authz_ref(mut self, authz_ref: GrantId) -> Self {
        self.authz_ref = Some(authz_ref);
        self
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessageCreateOptions {
    pub operation_id: Option<OperationId>,
    pub strand_id: Option<StrandId>,
    pub message_id: Option<String>,
    pub track_name: String,
    pub reply_to: Option<String>,
}

impl Default for MessageCreateOptions {
    fn default() -> Self {
        Self {
            operation_id: None,
            strand_id: None,
            message_id: None,
            track_name: "discussion".to_owned(),
            reply_to: None,
        }
    }
}

impl MessageCreateOptions {
    pub fn with_operation_id(mut self, operation_id: OperationId) -> Self {
        self.operation_id = Some(operation_id);
        self
    }

    pub fn with_strand_id(mut self, strand_id: StrandId) -> Self {
        self.strand_id = Some(strand_id);
        self
    }

    pub fn with_message_id(mut self, message_id: impl Into<String>) -> Self {
        self.message_id = Some(message_id.into());
        self
    }

    pub fn with_track_name(mut self, track_name: impl Into<String>) -> Self {
        self.track_name = track_name.into();
        self
    }

    pub fn with_reply_to(mut self, reply_to: impl Into<String>) -> Self {
        self.reply_to = Some(reply_to.into());
        self
    }
}

impl OutboundBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_registry(registry: OperationKindRegistry) -> Self {
        Self { registry }
    }

    pub fn message_create_operation(&self, realm_id: RealmId, content: Value) -> Result<Operation> {
        self.message_create_operation_with(realm_id, MessageCreateOptions::default(), content)
    }

    pub fn text_message_operation(
        &self,
        realm_id: RealmId,
        body: impl Into<String>,
    ) -> Result<Operation> {
        self.text_message_operation_with(realm_id, MessageCreateOptions::default(), body)
    }

    pub fn text_message_operation_with(
        &self,
        realm_id: RealmId,
        options: MessageCreateOptions,
        body: impl Into<String>,
    ) -> Result<Operation> {
        self.message_create_operation_with(realm_id, options, ContentBlock::text(body).to_value()?)
    }

    pub fn message_create_operation_with(
        &self,
        realm_id: RealmId,
        options: MessageCreateOptions,
        content: Value,
    ) -> Result<Operation> {
        let operation_id = options
            .operation_id
            .clone()
            .unwrap_or(OperationId::new(new_prefixed_uuid7("ck:operation:"))?);
        let payload = self.message_create_payload(options, content)?.to_value()?;
        Ok(Operation::create(
            operation_id,
            realm_id,
            OP_MESSAGE_CREATE,
            payload,
        ))
    }

    pub fn message_create_envelope(
        &self,
        realm_id: RealmId,
        context: OutboundCommandContext,
        content: Value,
    ) -> Result<OperationEnvelope> {
        self.message_create_envelope_with(
            realm_id,
            context,
            MessageCreateOptions::default(),
            content,
        )
    }

    pub fn message_create_envelope_with(
        &self,
        realm_id: RealmId,
        context: OutboundCommandContext,
        options: MessageCreateOptions,
        content: Value,
    ) -> Result<OperationEnvelope> {
        let operation = self.message_create_operation_with(realm_id, options, content)?;
        self.command_envelope(operation, context)
    }

    pub fn command_envelope(
        &self,
        operation: Operation,
        context: OutboundCommandContext,
    ) -> Result<OperationEnvelope> {
        let mut builder = OperationEnvelopeBuilder::new(
            operation.operation_id,
            operation.realm_id,
            context.actor_id,
            operation.object_type,
            context.actor_seq,
            context.hlc,
        )
        .with_payload(operation.payload);

        for dependency in context.deps {
            builder = builder.with_dependency(dependency);
        }
        if let Some(target_ref) = operation.object_id {
            builder = builder.with_target_ref(target_ref);
        }
        if let Some(authz_ref) = context.authz_ref {
            builder = builder.with_authz_ref(authz_ref);
        }

        builder.build(&self.registry)
    }

    pub fn event_from_envelope(
        &self,
        envelope: OperationEnvelope,
        conversion: OperationEventConversion,
    ) -> Result<EventEnvelope> {
        envelope.into_event_envelope(conversion)
    }

    fn message_create_payload(
        &self,
        options: MessageCreateOptions,
        content: Value,
    ) -> Result<MessageCreatePayload> {
        let strand_id = options
            .strand_id
            .unwrap_or(StrandId::new(new_prefixed_uuid7("ck:strand:"))?);
        let message_id = options
            .message_id
            .unwrap_or_else(|| new_prefixed_uuid7("ck:message:"));
        let mut payload =
            MessageCreatePayload::with_content(strand_id, options.track_name, content)
                .with_message_id(message_id);
        if let Some(reply_to) = options.reply_to {
            payload = payload.with_reply_to(reply_to);
        }
        Ok(payload)
    }
}

#[cfg(test)]
mod tests {
    use cokret::{EventId, EventRef};

    use super::*;

    fn realm_id() -> RealmId {
        RealmId::new("ck:realm:01904100-0000-7000-8000-000000000001").unwrap()
    }

    fn actor_id() -> Did {
        Did::new("did:webvh:z6mkfixture:alice.example").unwrap()
    }

    fn hlc() -> Hlc {
        Hlc::new("01970e589d21-0004-a13f9c2e").unwrap()
    }

    #[test]
    fn text_message_operation_builds_spec_payload() {
        let builder = OutboundBuilder::new();
        let options = MessageCreateOptions::default()
            .with_operation_id(
                OperationId::new("ck:operation:01904100-0000-7000-8000-000000000010").unwrap(),
            )
            .with_strand_id(
                StrandId::new("ck:strand:01904100-0000-7000-8000-000000000011").unwrap(),
            )
            .with_message_id("ck:message:01904100-0000-7000-8000-000000000012");

        let operation = builder
            .text_message_operation_with(realm_id(), options, "hello")
            .unwrap();

        assert_eq!(operation.realm_id, realm_id());
        assert_eq!(operation.object_type, OP_MESSAGE_CREATE);
        assert_eq!(
            operation.operation_id.as_str(),
            "ck:operation:01904100-0000-7000-8000-000000000010"
        );
        assert_eq!(
            operation.payload["strand_id"],
            "ck:strand:01904100-0000-7000-8000-000000000011"
        );
        assert_eq!(
            operation.payload["message_id"],
            "ck:message:01904100-0000-7000-8000-000000000012"
        );
        assert_eq!(operation.payload["track_name"], "discussion");
        assert_eq!(operation.payload["content"]["kind"], "ck.content.text");
        assert_eq!(operation.payload["content"]["body"], "hello");
    }

    #[test]
    fn command_envelope_carries_hlc_and_dependencies() {
        let builder = OutboundBuilder::new();
        let options = MessageCreateOptions::default()
            .with_operation_id(
                OperationId::new("ck:operation:01904100-0000-7000-8000-000000000020").unwrap(),
            )
            .with_strand_id(
                StrandId::new("ck:strand:01904100-0000-7000-8000-000000000021").unwrap(),
            );
        let context = OutboundCommandContext::new(actor_id(), 7, hlc())
            .with_dependency(
                OperationId::new("ck:operation:01904100-0000-7000-8000-000000000022").unwrap(),
            )
            .with_authz_ref(GrantId::new("ck:grant:01904100-0000-7000-8000-000000000023").unwrap());

        let envelope = builder
            .message_create_envelope_with(
                realm_id(),
                context,
                options,
                ContentBlock::text("hello").to_value().unwrap(),
            )
            .unwrap();

        assert_eq!(envelope.kind, OP_MESSAGE_CREATE);
        assert_eq!(envelope.actor_id, actor_id());
        assert_eq!(envelope.causal.actor_seq, 7);
        assert_eq!(envelope.causal.hlc, hlc());
        assert_eq!(envelope.causal.deps.len(), 1);
        assert_eq!(
            envelope.authz_ref.as_ref().unwrap().as_str(),
            "ck:grant:01904100-0000-7000-8000-000000000023"
        );

        let event = builder
            .event_from_envelope(
                envelope,
                OperationEventConversion::default()
                    .with_prev_ref(
                        EventId::new("ck:event:01904100-0000-7000-8000-000000000024").unwrap(),
                    )
                    .with_authorized_by_ref(
                        GrantId::new("ck:grant:01904100-0000-7000-8000-000000000023").unwrap(),
                    ),
            )
            .unwrap();

        assert_eq!(event.kind, OP_MESSAGE_CREATE);
        assert_eq!(event.actor_id, actor_id());
        assert_eq!(event.hlc, hlc());
        assert_eq!(event.prev_refs.len(), 1);
        assert_eq!(
            event.refs,
            vec![EventRef::authorized_by_grant(
                GrantId::new("ck:grant:01904100-0000-7000-8000-000000000023").unwrap()
            )]
        );
    }
}
