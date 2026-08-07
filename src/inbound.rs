use crate::protocol::{Event, Result};
use arkret_event_draft::{EventPayloadExt, MessageEventPayload};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecodedMessage {
    pub event: Event,
    pub payload: MessageEventPayload,
}

#[derive(Clone, Debug)]
pub enum DecodedInbound {
    Message(Box<DecodedMessage>),
    Event(Box<Event>),
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
            Err(_) => DecodedInbound::Event(Box::new(event)),
        }
    }

    pub fn try_decode_event(&self, event: Event) -> Result<DecodedInbound> {
        match event.kind.as_str() {
            arkret_wire::EventKind::MESSAGE_CREATE
            | arkret_wire::EventKind::MESSAGE_REVISE
            | arkret_wire::EventKind::MESSAGE_REDACT
            | arkret_wire::EventKind::REACTION_ADD
            | arkret_wire::EventKind::REACTION_REMOVE => {
                let payload = event.as_message_event_payload()?;
                Ok(DecodedInbound::Message(Box::new(DecodedMessage {
                    event,
                    payload,
                })))
            }
            _ => Ok(DecodedInbound::Event(Box::new(event))),
        }
    }
}

#[cfg(test)]
mod tests {
    use arkret_wire::{Did, EventId, Hlc, RealmId, ScopeRef, StrandId};
    use serde_json::{Value, json};

    use super::*;

    fn event(kind: &str, payload: Value) -> Event {
        Event::new(
            kind,
            ScopeRef::Realm {
                realm_id: RealmId::new("ak:realm:01904100-0000-7000-8000-000000000001").unwrap(),
            },
            Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
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
                arkret_wire::EventKind::MESSAGE_CREATE,
                json!({
                    "strand_id": StrandId::from_event_id(&EventId::from_digest(
                        arkret_canonical::DigestSuite::Sha256,
                        [2; 32],
                    )),
                    "track_name": "discussion",
                    "content": {"kind": "ak.content.text", "body": "hello"}
                }),
            ))
            .unwrap();

        match inbound {
            DecodedInbound::Message(message) => match message.payload {
                MessageEventPayload::Create(payload) => {
                    assert_eq!(payload.track_name, "discussion")
                }
                other => panic!("unexpected payload: {other:?}"),
            },
            other => panic!("unexpected decode result: {other:?}"),
        }
    }

    #[test]
    fn decoder_rejects_invalid_standard_message_payload() {
        let result = InboundDecoder::new().try_decode_event(event(
            arkret_wire::EventKind::MESSAGE_CREATE,
            json!({"content": {"kind": "ak.content.text", "body": "missing strand"}}),
        ));

        assert!(result.is_err());
    }
}
