//! Admission and decryption for the current transient Signal rail.

use std::collections::BTreeMap;
use std::future::Future;

use arkret_models_collaboration::signal_plaintext::{
    SignalPlaintext, SignalSequenceDecision, SignalSequenceDomain, SignalSequenceHighWater,
    open_signal_plaintext,
};
use arkret_models_collaboration::{SignalDeliveryAuthority, SignalStreamFrame};
use arkret_signatures::{PublicKeyMaterial, verify_ed25519_signal_proof};
use arkret_wire::SignalEnvelope;
use chrono::{DateTime, Utc};

use crate::{Error, MaybeSend, MaybeSendSync, Result};

pub trait SignalDecryptor: MaybeSendSync {
    fn decrypt<'a>(
        &'a self,
        envelope: &'a SignalEnvelope,
    ) -> impl Future<Output = Result<Vec<u8>>> + MaybeSend + 'a;
}

pub trait SignalFrameSource {
    fn next_frame(
        &mut self,
    ) -> impl Future<Output = Result<Option<SignalStreamFrame>>> + MaybeSend + '_;
}

impl SignalFrameSource for arkret_http_client::SignalSubscribeFrameStream {
    async fn next_frame(&mut self) -> Result<Option<SignalStreamFrame>> {
        Ok(arkret_http_client::SignalSubscribeFrameStream::next_frame(self).await?)
    }
}

pub trait SignalSink: MaybeSendSync {
    fn handle(
        &self,
        outcome: SignalReceiveOutcome,
    ) -> impl Future<Output = Result<()>> + MaybeSend + '_;
}

#[derive(Clone, Debug, PartialEq)]
pub enum SignalReceiveOutcome {
    Accepted {
        /// The verified sender actor, endpoint and scope the sequence
        /// high-water was enforced against. Downstream projections key on this
        /// rather than re-deriving sender facts from the plaintext.
        domain: Box<SignalSequenceDomain>,
        /// Exact governance basis authenticated by the producer proof and AEAD.
        product_authority: Option<Box<arkret_models_collaboration::SignalProductAuthority>>,
        authority_commit_id: arkret_wire::RealmCommitId,
        parent_realm_authority_commit_id: Option<arkret_wire::RealmCommitId>,
        plaintext: SignalPlaintext,
        effective_expires_at: DateTime<Utc>,
    },
    StaleSequence,
    Expired,
}

#[derive(Clone, Debug, Default)]
pub struct SignalReceiver {
    high_waters: BTreeMap<String, SignalSequenceHighWater>,
}

impl SignalReceiver {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn receive<D: SignalDecryptor + ?Sized>(
        &mut self,
        envelope: &SignalEnvelope,
        delivery_authority: &SignalDeliveryAuthority,
        decryptor: &D,
        now: DateTime<Utc>,
    ) -> Result<SignalReceiveOutcome> {
        delivery_authority.validate_for_envelope(envelope)?;
        envelope.validate_structural()?;
        if envelope.expires_at <= now {
            return Ok(SignalReceiveOutcome::Expired);
        }

        let public_key = PublicKeyMaterial::Ed25519Raw {
            bytes: arkret_canonical::base64url_decode(
                delivery_authority.key.public_key_b64u.as_str(),
            )?,
        };
        verify_ed25519_signal_proof(envelope, &public_key)
            .map_err(|error| Error::Protocol(error.to_string()))?;

        let bytes = decryptor.decrypt(envelope).await?;
        let plaintext = open_signal_plaintext(&bytes)?;
        plaintext.bind_to_envelope(
            &envelope.sender_actor_id,
            envelope.sent_at,
            envelope.expires_at,
        )?;
        if plaintext.signal_class() != envelope.signal_class {
            return Err(Error::Protocol(
                "Signal plaintext class does not match its authenticated envelope".to_owned(),
            ));
        }

        let effective_expires_at =
            plaintext.effective_expires_at(envelope.sent_at, envelope.expires_at);
        if effective_expires_at <= now {
            return Ok(SignalReceiveOutcome::Expired);
        }

        let agent_key_digest = envelope
            .sender_device_id
            .is_none()
            .then(|| public_key.raw_ed25519_digest())
            .transpose()
            .map_err(|error| Error::Protocol(error.to_string()))?;
        let domain = SignalSequenceDomain::from_verified_envelope(envelope, agent_key_digest)?;
        let key = domain.canonical_key()?;
        let sequence = plaintext.signal_sequence();
        if matches!(
            self.high_waters.entry(key).or_default().observe(sequence),
            SignalSequenceDecision::Stale { .. }
        ) {
            return Ok(SignalReceiveOutcome::StaleSequence);
        }

        Ok(SignalReceiveOutcome::Accepted {
            domain: Box::new(domain),
            product_authority: delivery_authority.product_authority.clone(),
            authority_commit_id: envelope.authority_commit_id.clone(),
            parent_realm_authority_commit_id: envelope.parent_realm_authority_commit_id.clone(),
            plaintext,
            effective_expires_at,
        })
    }

    pub async fn run<S, D, K>(
        &mut self,
        source: &mut S,
        decryptor: &D,
        sink: &K,
    ) -> Result<SignalStreamStopReason>
    where
        S: SignalFrameSource + ?Sized,
        D: SignalDecryptor + ?Sized,
        K: SignalSink + ?Sized,
    {
        while let Some(frame) = source.next_frame().await? {
            match frame {
                SignalStreamFrame::Signal {
                    envelope,
                    delivery_authority,
                } => {
                    let outcome = self
                        .receive(
                            &envelope,
                            &delivery_authority,
                            decryptor,
                            chrono::Utc::now(),
                        )
                        .await?;
                    sink.handle(outcome).await?;
                }
                SignalStreamFrame::Heartbeat => {}
                SignalStreamFrame::Drain {
                    reconnect_after_ms, ..
                } => {
                    return Ok(SignalStreamStopReason::ReconnectAfter { reconnect_after_ms });
                }
                SignalStreamFrame::Unauthorized { reason } => {
                    return Ok(SignalStreamStopReason::Unauthorized { reason });
                }
            }
        }
        Ok(SignalStreamStopReason::Ended)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SignalStreamStopReason {
    Ended,
    ReconnectAfter { reconnect_after_ms: Option<u64> },
    Unauthorized { reason: Option<String> },
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    struct Source(VecDeque<SignalStreamFrame>);

    impl SignalFrameSource for Source {
        async fn next_frame(&mut self) -> Result<Option<SignalStreamFrame>> {
            Ok(self.0.pop_front())
        }
    }

    #[derive(Debug)]
    struct UnusedDecryptor;

    impl SignalDecryptor for UnusedDecryptor {
        async fn decrypt(&self, _envelope: &SignalEnvelope) -> Result<Vec<u8>> {
            Err(Error::Protocol(
                "test decryptor must not receive control frames".to_owned(),
            ))
        }
    }

    #[derive(Debug, Default)]
    struct CountingSink(AtomicUsize);

    impl SignalSink for CountingSink {
        async fn handle(&self, _outcome: SignalReceiveOutcome) -> Result<()> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[tokio::test]
    async fn heartbeat_is_ignored_and_drain_requests_reconnect() {
        let mut source = Source(VecDeque::from([
            SignalStreamFrame::Heartbeat,
            SignalStreamFrame::Drain {
                reason: Some("rotation".to_owned()),
                reconnect_after_ms: Some(250),
            },
        ]));
        let sink = CountingSink::default();
        let reason = SignalReceiver::new()
            .run(&mut source, &UnusedDecryptor, &sink)
            .await
            .unwrap();
        assert_eq!(
            reason,
            SignalStreamStopReason::ReconnectAfter {
                reconnect_after_ms: Some(250)
            }
        );
        assert_eq!(sink.0.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn unauthorized_frame_stops_without_decryption() {
        let mut source = Source(VecDeque::from([SignalStreamFrame::Unauthorized {
            reason: Some("grant_expired".to_owned()),
        }]));
        let sink = CountingSink::default();
        let reason = SignalReceiver::new()
            .run(&mut source, &UnusedDecryptor, &sink)
            .await
            .unwrap();
        assert_eq!(
            reason,
            SignalStreamStopReason::Unauthorized {
                reason: Some("grant_expired".to_owned())
            }
        );
        assert_eq!(sink.0.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn clean_stream_end_is_distinct_from_reconnect() {
        let mut source = Source(VecDeque::new());
        let reason = SignalReceiver::new()
            .run(&mut source, &UnusedDecryptor, &CountingSink::default())
            .await
            .unwrap();
        assert_eq!(reason, SignalStreamStopReason::Ended);
    }
}
