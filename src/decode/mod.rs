use cokret_core::events::kinds;
use cokret_core::{Event, MessageEventPayload, Result};

#[derive(Clone, Debug)]
pub struct DecodedMessage {
    pub event: Event,
    pub payload: MessageEventPayload,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DecodedNotification {
    pub event: Event,
}

#[derive(Clone, Debug)]
pub enum DecodedInbound {
    Message(DecodedMessage),
    Notification(DecodedNotification),
    Event(Event),
}

#[derive(Clone, Debug, Default)]
pub struct InboundDecoder;

impl InboundDecoder {
    pub fn new() -> Self {
        Self
    }

    pub fn decode_event(&self, event: Event) -> DecodedInbound {
        match self.try_decode_event(event.clone()) {
            Ok(decoded) => decoded,
            Err(_) => DecodedInbound::Event(event),
        }
    }

    pub fn try_decode_event(&self, event: Event) -> Result<DecodedInbound> {
        match event.kind.as_str() {
            kinds::MESSAGE_CREATE
            | kinds::MESSAGE_REVISE
            | kinds::MESSAGE_REDACT
            | kinds::REACTION_ADD
            | kinds::REACTION_REMOVE => {
                let payload = event.as_message_event_payload()?;
                Ok(DecodedInbound::Message(DecodedMessage { event, payload }))
            }
            "ck.notification.create" | "ck.notification.dismiss" => {
                Ok(DecodedInbound::Notification(DecodedNotification { event }))
            }
            _ => Ok(DecodedInbound::Event(event)),
        }
    }
}

#[cfg(test)]
mod tests {
    use cokret_core::events::kinds;
    use cokret_core::{Did, Event, Hlc, MessageEventPayload, RealmId};
    use serde_json::{Value, json};

    use super::*;

    fn realm_id() -> RealmId {
        RealmId::new("ck:realm:01904100-0000-7000-8000-000000000001").unwrap()
    }

    fn actor_id() -> Did {
        Did::new("did:webvh:z6mkfixture:alice.example").unwrap()
    }

    fn event(kind: &str, payload: Value) -> Event {
        Event::new(
            kind,
            realm_id(),
            actor_id(),
            1,
            Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
            payload,
        )
        .unwrap()
    }

    #[test]
    fn decoder_parses_message_create_payload() {
        let inbound = InboundDecoder::new()
            .try_decode_event(event(
                kinds::MESSAGE_CREATE,
                json!({
                    "strand_id": "ck:strand:01904100-0000-7000-8000-000000000002",
                    "track_name": "discussion",
                    "content": {"kind": "ck.content.text", "body": "hello"}
                }),
            ))
            .unwrap();

        match inbound {
            DecodedInbound::Message(message) => match message.payload {
                MessageEventPayload::Create(payload) => {
                    assert_eq!(payload.track_name, "discussion");
                }
                other => panic!("unexpected payload: {other:?}"),
            },
            other => panic!("unexpected decode result: {other:?}"),
        }
    }

    #[test]
    fn decoder_parses_reaction_payloads_as_message_events() {
        let inbound = InboundDecoder::new()
            .try_decode_event(event(
                kinds::REACTION_ADD,
                json!({
                    "target_ref": "ck:event:01904100-0000-7000-8000-000000000099",
                    "key": "+1"
                }),
            ))
            .unwrap();

        match inbound {
            DecodedInbound::Message(message) => match message.payload {
                MessageEventPayload::ReactionAdd(payload) => assert_eq!(payload.key, "+1"),
                other => panic!("unexpected payload: {other:?}"),
            },
            other => panic!("unexpected decode result: {other:?}"),
        }
    }

    #[test]
    fn try_decode_event_rejects_invalid_standard_message_payload() {
        let result = InboundDecoder::new().try_decode_event(event(
            kinds::MESSAGE_CREATE,
            json!({"content": {"kind": "ck.content.text", "body": "missing strand"}}),
        ));

        assert!(result.is_err());
    }
}
