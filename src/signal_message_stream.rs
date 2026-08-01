//! Client-side projection for decrypted `ak.message.stream` Signal payloads.

use std::collections::BTreeMap;

use chrono::{DateTime, Duration, Utc};

use serde_json::Value;

use crate::MaybeSendSync;

use crate::protocol::{
    DeviceId, Did, Error, Event, EventKind, MAX_MESSAGE_STREAM_LIFETIME_SECONDS,
    MAX_MESSAGE_STREAM_PREVIEW_BYTES, MAX_MESSAGE_STREAMS_PER_DEVICE,
    MESSAGE_STREAM_STALLED_AFTER_SECONDS, MessageCreatePayload, MessageId, MessageStreamFormat,
    MessageStreamFrame, MessageStreamId, Result, ScopeRef, StrandId,
};

use crate::signal::SignalPlaintext;
use arkret_models_collaboration::signal_message_stream::MESSAGE_STREAM_KIND;

pub trait MessageStreamAuthorizer: MaybeSendSync {
    fn can_display(&self, plaintext: &SignalPlaintext, frame: &MessageStreamFrame) -> bool;
}

impl<F> MessageStreamAuthorizer for F
where
    F: Fn(&SignalPlaintext, &MessageStreamFrame) -> bool + MaybeSendSync,
{
    fn can_display(&self, plaintext: &SignalPlaintext, frame: &MessageStreamFrame) -> bool {
        self(plaintext, frame)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageStreamPreviewStatus {
    Active,
    Stalled,
    Aborted,
    Forked,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageStreamIgnoreReason {
    AwaitingInitialKeyframe,
    AwaitingHigherAttemptKeyframe,
    OlderAttempt,
    StaleSequence,
    DeltaGap,
    AttemptTerminated,
    DeviceDisplayLimit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageStreamApplyOutcome {
    Activated,
    Updated,
    Aborted,
    Forked,
    Ignored(MessageStreamIgnoreReason),
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct MessageStreamPreviewKey {
    sender_actor_id: Did,
    sender_device_id: DeviceId,
    message_id: MessageId,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessageStreamPreview {
    pub sender_actor_id: Did,
    pub sender_device_id: DeviceId,
    pub scope_ref: ScopeRef,
    pub strand_id: StrandId,
    pub message_id: MessageId,
    pub attempt: u32,
    pub highest_observed_attempt: u32,
    pub stream_id: MessageStreamId,
    pub format: MessageStreamFormat,
    pub text: String,
    pub truncated: bool,
    pub last_content_seq: u64,
    pub highest_observed_seq: u64,
    pub status: MessageStreamPreviewStatus,
    pub started_at: DateTime<Utc>,
    pub last_valid_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Default)]
pub struct MessageStreamProjection {
    previews: BTreeMap<MessageStreamPreviewKey, MessageStreamPreview>,
}

impl MessageStreamProjection {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn apply(
        &mut self,
        plaintext: &SignalPlaintext,
        authorizer: &dyn MessageStreamAuthorizer,
        observed_at: DateTime<Utc>,
    ) -> Result<MessageStreamApplyOutcome> {
        if plaintext.kind != MESSAGE_STREAM_KIND {
            return Err(Error::Protocol(format!(
                "message stream projection received plaintext kind '{}'",
                plaintext.kind
            )));
        }
        let frame: MessageStreamFrame =
            serde_json::from_value(Value::Object(plaintext.body.clone().into_iter().collect()))
                .map_err(|error| {
                    Error::Protocol(format!("invalid message stream payload: {error}"))
                })?;
        frame
            .validate()
            .map_err(|error| Error::Protocol(error.to_string()))?;
        if frame.payload_sequence() != plaintext.payload_sequence {
            return Err(Error::Protocol(
                "message stream payload_sequence disagrees with admitted Signal plaintext"
                    .to_owned(),
            ));
        }
        if !authorizer.can_display(plaintext, &frame) {
            return Err(Error::Protocol(
                "message stream product authorization failed closed".to_owned(),
            ));
        }

        let key = MessageStreamPreviewKey {
            sender_actor_id: plaintext.actor_id.clone(),
            sender_device_id: plaintext.sender_device_id.clone(),
            message_id: frame.message_id().clone(),
        };
        let Some(existing) = self.previews.get_mut(&key) else {
            let MessageStreamFrame::Keyframe(keyframe) = frame else {
                return Ok(MessageStreamApplyOutcome::Ignored(
                    MessageStreamIgnoreReason::AwaitingInitialKeyframe,
                ));
            };
            if keyframe.seq != 0 {
                return Ok(MessageStreamApplyOutcome::Ignored(
                    MessageStreamIgnoreReason::AwaitingInitialKeyframe,
                ));
            }
            let active_for_device = self
                .previews
                .values()
                .filter(|preview| {
                    preview.sender_actor_id == plaintext.actor_id
                        && preview.sender_device_id == plaintext.sender_device_id
                        && preview.status != MessageStreamPreviewStatus::Aborted
                })
                .count();
            if active_for_device >= MAX_MESSAGE_STREAMS_PER_DEVICE {
                return Ok(MessageStreamApplyOutcome::Ignored(
                    MessageStreamIgnoreReason::DeviceDisplayLimit,
                ));
            }
            self.previews.insert(
                key,
                MessageStreamPreview {
                    sender_actor_id: plaintext.actor_id.clone(),
                    sender_device_id: plaintext.sender_device_id.clone(),
                    scope_ref: plaintext.scope_ref.clone(),
                    strand_id: keyframe.strand_id,
                    message_id: keyframe.message_id,
                    attempt: keyframe.attempt,
                    highest_observed_attempt: keyframe.attempt,
                    stream_id: keyframe.stream_id,
                    format: keyframe.format,
                    text: keyframe.text,
                    truncated: keyframe.truncated,
                    last_content_seq: keyframe.seq,
                    highest_observed_seq: keyframe.seq,
                    status: MessageStreamPreviewStatus::Active,
                    started_at: observed_at,
                    last_valid_at: observed_at,
                },
            );
            return Ok(MessageStreamApplyOutcome::Activated);
        };

        if existing.scope_ref != plaintext.scope_ref || existing.strand_id != *frame.strand_id() {
            return Err(Error::Protocol(
                "message stream scope or Strand changed for one Message identity".to_owned(),
            ));
        }

        existing.highest_observed_attempt = existing.highest_observed_attempt.max(frame.attempt());
        if frame.attempt() < existing.highest_observed_attempt {
            return Ok(MessageStreamApplyOutcome::Ignored(
                MessageStreamIgnoreReason::OlderAttempt,
            ));
        }
        if frame.attempt() > existing.attempt {
            let MessageStreamFrame::Keyframe(keyframe) = frame else {
                return Ok(MessageStreamApplyOutcome::Ignored(
                    MessageStreamIgnoreReason::AwaitingHigherAttemptKeyframe,
                ));
            };
            if keyframe.seq != 0 {
                return Ok(MessageStreamApplyOutcome::Ignored(
                    MessageStreamIgnoreReason::AwaitingHigherAttemptKeyframe,
                ));
            }
            *existing = MessageStreamPreview {
                sender_actor_id: plaintext.actor_id.clone(),
                sender_device_id: plaintext.sender_device_id.clone(),
                scope_ref: plaintext.scope_ref.clone(),
                strand_id: keyframe.strand_id,
                message_id: keyframe.message_id,
                attempt: keyframe.attempt,
                highest_observed_attempt: keyframe.attempt,
                stream_id: keyframe.stream_id,
                format: keyframe.format,
                text: keyframe.text,
                truncated: keyframe.truncated,
                last_content_seq: keyframe.seq,
                highest_observed_seq: keyframe.seq,
                status: MessageStreamPreviewStatus::Active,
                started_at: observed_at,
                last_valid_at: observed_at,
            };
            return Ok(MessageStreamApplyOutcome::Activated);
        }

        if existing.stream_id != *frame.stream_id() {
            existing.highest_observed_seq = existing.highest_observed_seq.max(frame.seq());
            existing.status = MessageStreamPreviewStatus::Forked;
            existing.last_valid_at = observed_at;
            return Ok(MessageStreamApplyOutcome::Forked);
        }
        existing.highest_observed_seq = existing.highest_observed_seq.max(frame.seq());
        if matches!(
            existing.status,
            MessageStreamPreviewStatus::Aborted | MessageStreamPreviewStatus::Forked
        ) {
            return Ok(MessageStreamApplyOutcome::Ignored(
                MessageStreamIgnoreReason::AttemptTerminated,
            ));
        }

        match frame {
            MessageStreamFrame::Keyframe(keyframe) => {
                if keyframe.seq <= existing.last_content_seq {
                    return Ok(MessageStreamApplyOutcome::Ignored(
                        MessageStreamIgnoreReason::StaleSequence,
                    ));
                }
                if keyframe.format != existing.format {
                    return Err(Error::Protocol(
                        "message stream format changed within one stream".to_owned(),
                    ));
                }
                existing.text = keyframe.text;
                existing.truncated = keyframe.truncated;
                existing.last_content_seq = keyframe.seq;
                existing.last_valid_at = observed_at;
                existing.status = MessageStreamPreviewStatus::Active;
                Ok(MessageStreamApplyOutcome::Updated)
            }
            MessageStreamFrame::Delta(delta) => {
                if delta.seq <= existing.last_content_seq {
                    return Ok(MessageStreamApplyOutcome::Ignored(
                        MessageStreamIgnoreReason::StaleSequence,
                    ));
                }
                if delta.base_seq != existing.last_content_seq {
                    return Ok(MessageStreamApplyOutcome::Ignored(
                        MessageStreamIgnoreReason::DeltaGap,
                    ));
                }
                if existing.text.len() + delta.text_append.len() > MAX_MESSAGE_STREAM_PREVIEW_BYTES
                {
                    return Err(Error::Protocol(
                        "message stream cumulative preview exceeds 16 KiB UTF-8".to_owned(),
                    ));
                }
                existing.text.push_str(&delta.text_append);
                existing.last_content_seq = delta.seq;
                existing.last_valid_at = observed_at;
                existing.status = MessageStreamPreviewStatus::Active;
                Ok(MessageStreamApplyOutcome::Updated)
            }
            MessageStreamFrame::Abort(_) => {
                existing.status = MessageStreamPreviewStatus::Aborted;
                existing.last_valid_at = observed_at;
                Ok(MessageStreamApplyOutcome::Aborted)
            }
        }
    }

    pub fn preview(
        &self,
        sender_actor_id: &Did,
        sender_device_id: &DeviceId,
        message_id: &MessageId,
    ) -> Option<&MessageStreamPreview> {
        self.previews.get(&MessageStreamPreviewKey {
            sender_actor_id: sender_actor_id.clone(),
            sender_device_id: sender_device_id.clone(),
            message_id: message_id.clone(),
        })
    }

    pub fn previews(&self) -> impl Iterator<Item = &MessageStreamPreview> {
        self.previews.values()
    }

    /// Bind an already schema/proof/authorization/reducer-accepted durable
    /// `ak.message.create` to its direct preview.
    ///
    /// `verified_sender_device_id` must be the device resolved and authorized
    /// from the final Event proof's `verification_method`.
    pub fn bind_verified_final(
        &mut self,
        event: &Event,
        verified_sender_device_id: &DeviceId,
    ) -> Result<Option<MessageStreamPreview>> {
        if event.kind != EventKind::MessageCreate {
            return Err(Error::Protocol(
                "message stream final binding requires ak.message.create".to_owned(),
            ));
        }
        if event.executed_by.is_some() {
            return Ok(None);
        }
        let payload: MessageCreatePayload =
            serde_json::from_value(Value::Object(event.payload.clone().into_iter().collect()))
                .map_err(|error| {
                    Error::Protocol(format!("invalid final message create payload: {error}"))
                })?;
        if payload.track_name != "discussion" {
            return Ok(None);
        }
        let message_id = MessageId::from_event_id(&event.event_id);
        let key = MessageStreamPreviewKey {
            sender_actor_id: event.actor_id.clone(),
            sender_device_id: verified_sender_device_id.clone(),
            message_id,
        };
        let Some(preview) = self.previews.get(&key) else {
            return Ok(None);
        };
        if preview.scope_ref != event.scope_ref || preview.strand_id != payload.strand_id {
            return Ok(None);
        }
        Ok(self.previews.remove(&key))
    }

    pub fn mark_stalled(&mut self, now: DateTime<Utc>) -> usize {
        let threshold = Duration::seconds(MESSAGE_STREAM_STALLED_AFTER_SECONDS as i64);
        let mut changed = 0;
        for preview in self.previews.values_mut() {
            if preview.status == MessageStreamPreviewStatus::Active
                && now - preview.last_valid_at >= threshold
            {
                preview.status = MessageStreamPreviewStatus::Stalled;
                changed += 1;
            }
        }
        changed
    }

    pub fn expire(&mut self, now: DateTime<Utc>) -> usize {
        let before = self.previews.len();
        let lifetime = Duration::seconds(MAX_MESSAGE_STREAM_LIFETIME_SECONDS as i64);
        self.previews
            .retain(|_, preview| now - preview.started_at < lifetime);
        before - self.previews.len()
    }
}

#[cfg(test)]
mod tests {
    use arkret_models_collaboration::signal_message_stream::{
        MessageStreamAbort, MessageStreamAbortReason, MessageStreamDelta, MessageStreamKeyframe,
    };

    use arkret_wire::{RealmId, SealId};

    use super::*;

    fn actor() -> Did {
        Did::new("did:webvh:z6mkfixture:alice.example").unwrap()
    }

    fn device() -> DeviceId {
        DeviceId::new("ak:device:01904100-0000-7000-8000-000000000001").unwrap()
    }

    fn strand() -> StrandId {
        StrandId::new("ak:strand:01904100-0000-7000-8000-000000000002").unwrap()
    }

    fn message() -> MessageId {
        MessageId::new("ak:message:01904100-0000-7000-8000-000000000003").unwrap()
    }

    fn stream(suffix: &str) -> MessageStreamId {
        MessageStreamId::new(format!(
            "ak:message_stream:01904100-0000-7000-8000-{suffix}"
        ))
        .unwrap()
    }

    fn at(seconds: i64) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-07-28T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
            + Duration::seconds(seconds)
    }

    fn plaintext(frame: MessageStreamFrame) -> SignalPlaintext {
        let payload_sequence = frame.payload_sequence();
        let kind = MESSAGE_STREAM_KIND.to_owned();
        let Value::Object(body) = serde_json::to_value(&frame).unwrap() else {
            unreachable!()
        };
        SignalPlaintext {
            kind,
            actor_id: actor(),
            payload_sequence,
            ttl_ms: None,
            payload: crate::protocol::SdkSignalPlaintext::MessageStream(frame),
            body: body.into_iter().collect(),
            sent_at: at(0),
            expires_at: at(30),
            scope_ref: ScopeRef::Realm {
                realm_id: RealmId::new("ak:realm:01904100-0000-7000-8000-000000000004").unwrap(),
            },
            seal_ref: SealId::new(format!("ak:seal:sha256:{}", "a".repeat(64))).unwrap(),
            sender_device_id: device(),
        }
    }

    fn allow(_: &SignalPlaintext, _: &MessageStreamFrame) -> bool {
        true
    }

    #[test]
    fn activates_updates_and_aborts_one_stream() {
        let stream_id = stream("000000000005");
        let keyframe = MessageStreamFrame::Keyframe(
            MessageStreamKeyframe::new(
                1,
                strand(),
                message(),
                0,
                stream_id.clone(),
                0,
                MessageStreamFormat::Plain,
                "hel",
                false,
            )
            .unwrap(),
        );
        let delta = MessageStreamFrame::Delta(
            MessageStreamDelta::new(2, strand(), message(), 0, stream_id.clone(), 1, 0, "lo")
                .unwrap(),
        );
        let abort = MessageStreamFrame::Abort(
            MessageStreamAbort::new(
                3,
                strand(),
                message(),
                0,
                stream_id,
                2,
                MessageStreamAbortReason::GenerationCancelled,
            )
            .unwrap(),
        );
        let mut projection = MessageStreamProjection::new();

        assert_eq!(
            projection
                .apply(&plaintext(keyframe), &allow, at(0))
                .unwrap(),
            MessageStreamApplyOutcome::Activated
        );
        assert_eq!(
            projection.apply(&plaintext(delta), &allow, at(1)).unwrap(),
            MessageStreamApplyOutcome::Updated
        );
        assert_eq!(
            projection.apply(&plaintext(abort), &allow, at(2)).unwrap(),
            MessageStreamApplyOutcome::Aborted
        );
        let preview = projection.preview(&actor(), &device(), &message()).unwrap();
        assert_eq!(preview.text, "hello");
        assert_eq!(preview.status, MessageStreamPreviewStatus::Aborted);
    }

    #[test]
    fn ignores_gap_then_accepts_a_later_keyframe() {
        let stream_id = stream("000000000005");
        let mut projection = MessageStreamProjection::new();
        let initial = MessageStreamFrame::Keyframe(
            MessageStreamKeyframe::new(
                1,
                strand(),
                message(),
                0,
                stream_id.clone(),
                0,
                MessageStreamFormat::Plain,
                "a",
                false,
            )
            .unwrap(),
        );
        projection
            .apply(&plaintext(initial), &allow, at(0))
            .unwrap();
        let gap = MessageStreamFrame::Delta(
            MessageStreamDelta::new(
                2,
                strand(),
                message(),
                0,
                stream_id.clone(),
                2,
                1,
                "lost-prefix",
            )
            .unwrap(),
        );
        assert_eq!(
            projection.apply(&plaintext(gap), &allow, at(1)).unwrap(),
            MessageStreamApplyOutcome::Ignored(MessageStreamIgnoreReason::DeltaGap)
        );
        let recovery = MessageStreamFrame::Keyframe(
            MessageStreamKeyframe::new(
                3,
                strand(),
                message(),
                0,
                stream_id,
                3,
                MessageStreamFormat::Plain,
                "recovered",
                false,
            )
            .unwrap(),
        );
        assert_eq!(
            projection
                .apply(&plaintext(recovery), &allow, at(2))
                .unwrap(),
            MessageStreamApplyOutcome::Updated
        );
        assert_eq!(
            projection
                .preview(&actor(), &device(), &message())
                .unwrap()
                .text,
            "recovered"
        );
    }

    #[test]
    fn freezes_on_same_attempt_stream_fork() {
        let mut projection = MessageStreamProjection::new();
        let initial = MessageStreamFrame::Keyframe(
            MessageStreamKeyframe::new(
                1,
                strand(),
                message(),
                0,
                stream("000000000005"),
                0,
                MessageStreamFormat::Plain,
                "a",
                false,
            )
            .unwrap(),
        );
        projection
            .apply(&plaintext(initial), &allow, at(0))
            .unwrap();
        let fork = MessageStreamFrame::Keyframe(
            MessageStreamKeyframe::new(
                2,
                strand(),
                message(),
                0,
                stream("000000000006"),
                1,
                MessageStreamFormat::Plain,
                "b",
                false,
            )
            .unwrap(),
        );

        assert_eq!(
            projection.apply(&plaintext(fork), &allow, at(1)).unwrap(),
            MessageStreamApplyOutcome::Forked
        );
        assert_eq!(
            projection
                .preview(&actor(), &device(), &message())
                .unwrap()
                .status,
            MessageStreamPreviewStatus::Forked
        );
    }

    #[test]
    fn marks_stalled_and_expires_at_protocol_deadlines() {
        let initial = MessageStreamFrame::Keyframe(
            MessageStreamKeyframe::new(
                1,
                strand(),
                message(),
                0,
                stream("000000000005"),
                0,
                MessageStreamFormat::Plain,
                "a",
                false,
            )
            .unwrap(),
        );
        let mut projection = MessageStreamProjection::new();
        projection
            .apply(&plaintext(initial), &allow, at(0))
            .unwrap();

        assert_eq!(projection.mark_stalled(at(29)), 0);
        assert_eq!(projection.mark_stalled(at(30)), 1);
        assert_eq!(projection.expire(at(599)), 0);
        assert_eq!(projection.expire(at(600)), 1);
    }
}
