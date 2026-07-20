use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::models::ContentBlock;
use crate::{Error, Result};

pub(super) fn payload_value<T: Serialize>(payload: &T, context: &str) -> Result<Value> {
    serde_json::to_value(payload)
        .map_err(|err| Error::Protocol(format!("{context} serialize: {err}")))
}

pub(super) fn decode_payload<T: DeserializeOwned>(value: Value, context: &str) -> Result<T> {
    serde_json::from_value(value).map_err(|err| Error::Protocol(format!("{context} decode: {err}")))
}

pub(super) fn content_block_from_value(mut content: Value) -> Result<ContentBlock> {
    if let Value::Object(map) = &mut content {
        map.entry("kind".to_owned())
            .or_insert_with(|| Value::String("ak.content.text".to_owned()));
    }
    decode_payload(content, "message content block")
}
