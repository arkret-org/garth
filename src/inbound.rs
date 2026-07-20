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
            arkret_wire::events::kinds::EventKind::MESSAGE_CREATE
            | arkret_wire::events::kinds::EventKind::MESSAGE_REVISE
            | arkret_wire::events::kinds::EventKind::MESSAGE_REDACT
            | arkret_wire::events::kinds::EventKind::REACTION_ADD
            | arkret_wire::events::kinds::EventKind::REACTION_REMOVE => {
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
