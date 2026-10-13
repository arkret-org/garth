//! Client-side projection for decrypted `ak.message.stream` Signal payloads.
//!
//! These frames are transient previews on the encrypted Signal rail. They are
//! never durable Events and never touch a commit stream, so nothing here reads
//! or writes a stream position. The projection is keyed on the verified Signal
//! sequence domain — sender actor, sender endpoint and scope — which is the
//! same domain the receiver enforced the sequence high-water against.

use std::collections::BTreeMap;

use arkret_event_draft::MessageEventPayload;
pub use arkret_models_collaboration::signal_message_stream::{
    MAX_MESSAGE_STREAM_FRAMES_PER_SECOND, MAX_MESSAGE_STREAM_LIFETIME_SECONDS,
    MAX_MESSAGE_STREAM_PREVIEW_BYTES, MAX_MESSAGE_STREAMS_PER_DEVICE, MESSAGE_STREAM_KIND,
    MESSAGE_STREAM_STALLED_AFTER_SECONDS, MessageStreamAbort, MessageStreamAbortReason,
    MessageStreamDelta, MessageStreamFormat, MessageStreamFrame, MessageStreamKeyframe,
};
use arkret_models_collaboration::signal_plaintext::{
    SignalPlaintext, SignalSequenceDomain, SignalSequenceEndpoint,
};
use arkret_wire::{ActorId, Event, EventKind, MessageId, MessageStreamId, ScopeRef, StrandId};
use chrono::{DateTime, Duration, Utc};

use crate::{Error, MaybeSendSync, Result};

/// Product gate applied after structural admission. It fails closed: a frame
/// the host cannot authorize for display is refused rather than shown.
pub trait MessageStreamAuthorizer: MaybeSendSync {
    fn can_display(&self, domain: &SignalSequenceDomain, frame: &MessageStreamFrame) -> bool;
}

impl<F> MessageStreamAuthorizer for F
where
    F: Fn(&SignalSequenceDomain, &MessageStreamFrame) -> bool + MaybeSendSync,
{
    fn can_display(&self, domain: &SignalSequenceDomain, frame: &MessageStreamFrame) -> bool {
        self(domain, frame)
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
    sender_actor_id: ActorId,
    sender_endpoint: String,
    message_id: MessageId,
}

fn preview_key(
    sender_actor_id: &ActorId,
    sender_endpoint: &SignalSequenceEndpoint,
    message_id: &MessageId,
) -> Result<MessageStreamPreviewKey> {
    Ok(MessageStreamPreviewKey {
        sender_actor_id: sender_actor_id.clone(),
        sender_endpoint: serde_json::to_string(sender_endpoint)?,
        message_id: message_id.clone(),
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessageStreamPreview {
    pub sender_actor_id: ActorId,
    pub sender_endpoint: SignalSequenceEndpoint,
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

/// Transient per-device preview registry for one signed-in endpoint.
#[derive(Clone, Debug, Default)]
pub struct MessageStreamProjection {
    previews: BTreeMap<MessageStreamPreviewKey, MessageStreamPreview>,
}

impl MessageStreamProjection {
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply one admitted Signal plaintext. `domain` MUST come from the same
    /// verified envelope the sequence high-water was enforced against.
    pub fn apply_plaintext(
        &mut self,
        domain: &SignalSequenceDomain,
        plaintext: &SignalPlaintext,
        authorizer: &dyn MessageStreamAuthorizer,
        observed_at: DateTime<Utc>,
    ) -> Result<MessageStreamApplyOutcome> {
        let SignalPlaintext::MessageStream(frame) = plaintext else {
            return Err(Error::Protocol(
                "message stream projection received another Signal profile".to_owned(),
            ));
        };
        self.apply(domain, frame, authorizer, observed_at)
    }

    pub fn apply(
        &mut self,
        domain: &SignalSequenceDomain,
        frame: &MessageStreamFrame,
        authorizer: &dyn MessageStreamAuthorizer,
        observed_at: DateTime<Utc>,
    ) -> Result<MessageStreamApplyOutcome> {
        frame.validate()?;
        if !authorizer.can_display(domain, frame) {
            return Err(Error::Protocol(
                "message stream product authorization failed closed".to_owned(),
            ));
        }

        // A re-keyed Agent endpoint supersedes its own older key's previews.
        if matches!(domain.endpoint, SignalSequenceEndpoint::AgentKey { .. }) {
            self.previews.retain(|_, preview| {
                preview.sender_actor_id != domain.sender_actor_id
                    || !matches!(
                        preview.sender_endpoint,
                        SignalSequenceEndpoint::AgentKey { .. }
                    )
                    || preview.sender_endpoint == domain.endpoint
            });
        }

        let key = preview_key(
            &domain.sender_actor_id,
            &domain.endpoint,
            frame.message_id(),
        )?;
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
                    preview.sender_actor_id == domain.sender_actor_id
                        && preview.sender_endpoint == domain.endpoint
                        && preview.status != MessageStreamPreviewStatus::Aborted
                })
                .count();
            if active_for_device >= MAX_MESSAGE_STREAMS_PER_DEVICE {
                return Ok(MessageStreamApplyOutcome::Ignored(
                    MessageStreamIgnoreReason::DeviceDisplayLimit,
                ));
            }
            self.previews
                .insert(key, activated(domain, keyframe, observed_at));
            return Ok(MessageStreamApplyOutcome::Activated);
        };

        if existing.scope_ref != domain.scope_ref || existing.strand_id != *frame.strand_id() {
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
            *existing = activated(domain, keyframe, observed_at);
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
                existing.text = keyframe.text.clone();
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
                        "message stream cumulative preview exceeds its byte ceiling".to_owned(),
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
        sender_actor_id: &ActorId,
        sender_endpoint: &SignalSequenceEndpoint,
        message_id: &MessageId,
    ) -> Option<&MessageStreamPreview> {
        self.previews
            .get(&preview_key(sender_actor_id, sender_endpoint, message_id).ok()?)
    }

    /// Remove previews whose host has observed revoked or unavailable product authority.
    pub fn retain_previews(&mut self, mut eligible: impl FnMut(&MessageStreamPreview) -> bool) {
        self.previews.retain(|_, preview| eligible(preview));
    }

    pub fn previews(&self) -> impl Iterator<Item = &MessageStreamPreview> {
        self.previews.values()
    }

    /// Retire the preview a committed `ak.message.create` supersedes.
    ///
    /// `verified_sender_endpoint` must come from the committed Event's own
    /// verified signer evidence, not from the preview.
    pub fn bind_committed_final(
        &mut self,
        event: &Event,
        verified_sender_endpoint: &SignalSequenceEndpoint,
    ) -> Result<Option<MessageStreamPreview>> {
        if event.kind != EventKind::MessageCreate {
            return Err(Error::Protocol(
                "message stream final binding requires ak.message.create".to_owned(),
            ));
        }
        if event.executed_by.is_some() {
            return Ok(None);
        }
        let payload = match arkret_event_draft::EventPayloadExt::as_message_event_payload(event)? {
            MessageEventPayload::Create(payload) => payload,
            _ => return Ok(None),
        };
        let key = preview_key(
            &event.actor_id,
            verified_sender_endpoint,
            &MessageId::from_event_id(&event.event_id),
        )?;
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

fn activated(
    domain: &SignalSequenceDomain,
    keyframe: &arkret_models_collaboration::signal_message_stream::MessageStreamKeyframe,
    observed_at: DateTime<Utc>,
) -> MessageStreamPreview {
    MessageStreamPreview {
        sender_actor_id: domain.sender_actor_id.clone(),
        sender_endpoint: domain.endpoint.clone(),
        scope_ref: domain.scope_ref.clone(),
        strand_id: keyframe.strand_id.clone(),
        message_id: keyframe.message_id.clone(),
        attempt: keyframe.attempt,
        highest_observed_attempt: keyframe.attempt,
        stream_id: keyframe.stream_id.clone(),
        format: keyframe.format,
        text: keyframe.text.clone(),
        truncated: keyframe.truncated,
        last_content_seq: keyframe.seq,
        highest_observed_seq: keyframe.seq,
        status: MessageStreamPreviewStatus::Active,
        started_at: observed_at,
        last_valid_at: observed_at,
    }
}

#[cfg(test)]
mod tests {
    use arkret_canonical::DigestSuite;
    use arkret_models_collaboration::signal_message_stream::{
        MessageStreamAbort, MessageStreamAbortReason, MessageStreamDelta, MessageStreamKeyframe,
    };
    use arkret_wire::EventId;

    use super::*;
    use crate::test_fixtures::{actor_id, at, device_id, realm_id};

    fn allow_all(_: &SignalSequenceDomain, _: &MessageStreamFrame) -> bool {
        true
    }

    fn domain() -> SignalSequenceDomain {
        SignalSequenceDomain {
            sender_actor_id: actor_id(),
            endpoint: SignalSequenceEndpoint::AccountDevice {
                device_id: device_id(),
            },
            scope_ref: ScopeRef::Realm {
                realm_id: realm_id(),
            },
        }
    }

    fn strand() -> StrandId {
        StrandId::from_event_id(&EventId::from_digest(DigestSuite::Sha256, [2; 32]))
    }

    fn message_id() -> MessageId {
        MessageId::from_event_id(&EventId::from_digest(DigestSuite::Sha256, [3; 32]))
    }

    fn stream_id(suffix: &str) -> MessageStreamId {
        MessageStreamId::new(format!(
            "ak:message_stream:0196419b-0000-7000-8000-00000000006{suffix}"
        ))
        .unwrap()
    }

    fn keyframe(seq: u64, attempt: u32, stream: &str, text: &str) -> MessageStreamFrame {
        MessageStreamFrame::Keyframe(
            MessageStreamKeyframe::new(
                seq,
                strand(),
                message_id(),
                attempt,
                stream_id(stream),
                seq,
                MessageStreamFormat::Plain,
                text,
                false,
            )
            .unwrap(),
        )
    }

    fn delta(seq: u64, base_seq: u64, stream: &str, append: &str) -> MessageStreamFrame {
        MessageStreamFrame::Delta(
            MessageStreamDelta::new(
                seq,
                strand(),
                message_id(),
                0,
                stream_id(stream),
                seq,
                base_seq,
                append,
            )
            .unwrap(),
        )
    }

    #[test]
    fn a_delta_before_any_keyframe_is_ignored() {
        let mut projection = MessageStreamProjection::new();
        assert_eq!(
            projection
                .apply(&domain(), &delta(1, 0, "0", "hi"), &allow_all, at(0))
                .unwrap(),
            MessageStreamApplyOutcome::Ignored(MessageStreamIgnoreReason::AwaitingInitialKeyframe)
        );
        assert_eq!(projection.previews().count(), 0);
    }

    #[test]
    fn a_keyframe_then_contiguous_deltas_build_one_preview() {
        let mut projection = MessageStreamProjection::new();
        assert_eq!(
            projection
                .apply(&domain(), &keyframe(0, 0, "0", "he"), &allow_all, at(0))
                .unwrap(),
            MessageStreamApplyOutcome::Activated
        );
        assert_eq!(
            projection
                .apply(&domain(), &delta(1, 0, "0", "llo"), &allow_all, at(1))
                .unwrap(),
            MessageStreamApplyOutcome::Updated
        );
        let domain = domain();
        let preview = projection
            .preview(&domain.sender_actor_id, &domain.endpoint, &message_id())
            .unwrap();
        assert_eq!(preview.text, "hello");
        assert_eq!(preview.last_content_seq, 1);
    }

    #[test]
    fn a_delta_that_skips_a_sequence_is_ignored_rather_than_applied() {
        let mut projection = MessageStreamProjection::new();
        projection
            .apply(&domain(), &keyframe(0, 0, "0", "he"), &allow_all, at(0))
            .unwrap();
        assert_eq!(
            projection
                .apply(&domain(), &delta(3, 2, "0", "llo"), &allow_all, at(1))
                .unwrap(),
            MessageStreamApplyOutcome::Ignored(MessageStreamIgnoreReason::DeltaGap)
        );
    }

    #[test]
    fn a_second_stream_id_for_one_message_identity_forks_the_preview() {
        let mut projection = MessageStreamProjection::new();
        projection
            .apply(&domain(), &keyframe(0, 0, "0", "he"), &allow_all, at(0))
            .unwrap();
        assert_eq!(
            projection
                .apply(&domain(), &delta(1, 0, "1", "llo"), &allow_all, at(1))
                .unwrap(),
            MessageStreamApplyOutcome::Forked
        );
    }

    #[test]
    fn an_abort_terminates_the_attempt() {
        let mut projection = MessageStreamProjection::new();
        projection
            .apply(&domain(), &keyframe(0, 0, "0", "he"), &allow_all, at(0))
            .unwrap();
        let abort = MessageStreamFrame::Abort(
            MessageStreamAbort::new(
                1,
                strand(),
                message_id(),
                0,
                stream_id("0"),
                1,
                MessageStreamAbortReason::GenerationCancelled,
            )
            .unwrap(),
        );
        assert_eq!(
            projection
                .apply(&domain(), &abort, &allow_all, at(1))
                .unwrap(),
            MessageStreamApplyOutcome::Aborted
        );
        assert_eq!(
            projection
                .apply(&domain(), &delta(2, 1, "0", "llo"), &allow_all, at(2))
                .unwrap(),
            MessageStreamApplyOutcome::Ignored(MessageStreamIgnoreReason::AttemptTerminated)
        );
    }

    #[test]
    fn a_refused_authorization_fails_closed() {
        let mut projection = MessageStreamProjection::new();
        let deny = |_: &SignalSequenceDomain, _: &MessageStreamFrame| false;
        assert!(
            projection
                .apply(&domain(), &keyframe(0, 0, "0", "he"), &deny, at(0))
                .is_err()
        );
    }

    #[test]
    fn a_stale_preview_is_marked_then_expired() {
        let mut projection = MessageStreamProjection::new();
        projection
            .apply(&domain(), &keyframe(0, 0, "0", "he"), &allow_all, at(0))
            .unwrap();
        assert_eq!(
            projection.mark_stalled(
                at(0) + Duration::seconds(MESSAGE_STREAM_STALLED_AFTER_SECONDS as i64)
            ),
            1
        );
        assert_eq!(
            projection
                .expire(at(0) + Duration::seconds(MAX_MESSAGE_STREAM_LIFETIME_SECONDS as i64)),
            1
        );
        assert_eq!(projection.previews().count(), 0);
    }
}
