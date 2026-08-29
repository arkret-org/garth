//! Live receive rail for `ak.self.signal.stream.subscribe.v1` (`zh/sync/signal.md`
//! §4.1).
//!
//! The Signal rail is deliberately the poorest of the three subscribe surfaces:
//! it has no cursor, no catch-up, no ack and no durable delivery receipt, and a
//! reconnect only re-establishes live fanout. This driver therefore holds no
//! store handle at all — the only state it keeps across reconnects is the
//! [`SignalReceiver`] de-duplication window, which is a receiver obligation of
//! §2 rather than a resume position.
//!
//! Admission is entirely [`SignalReceiver::accept`]: structural contract,
//! wall-clock expiry, the current-directory device-authorization lookup, the
//! device proof, the AEAD open and the `(sender_device_id, scope_ref,
//! payload_sequence)` triple. A signal that fails any of them is dropped and
//! reported to the sink; §4.5 makes loss, duplication and reordering normal
//! input on this rail, so one bad envelope must not tear the connection down
//! and hand a sender a remote kill switch.

use std::future::Future;
use std::pin::Pin;

use chrono::{DateTime, Utc};

use crate::HostClock;
use crate::protocol::{Error, Result, SignalEnvelope, SignalStreamFrame};
use crate::signal::{SignalDecryptor, SignalPlaintext, SignalReceiver, SignalSenderKeyResolver};

// Native builds keep the boxed futures and the frame source `Send` so a host
// runtime can move the rail across worker threads, matching the realm stream.
// Wasm builds drop `Send` because browser futures are single-threaded.
#[cfg(not(target_arch = "wasm32"))]
pub type BoxSignalStreamFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

#[cfg(target_arch = "wasm32")]
pub type BoxSignalStreamFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + 'a>>;

#[cfg(not(target_arch = "wasm32"))]
pub trait SignalStreamFrameSource: Send {
    fn next_frame<'a>(&'a mut self) -> BoxSignalStreamFuture<'a, Option<SignalStreamFrame>>;
}

#[cfg(target_arch = "wasm32")]
pub trait SignalStreamFrameSource {
    fn next_frame<'a>(&'a mut self) -> BoxSignalStreamFuture<'a, Option<SignalStreamFrame>>;
}

/// Opener for the cursorless Signal receive rail.
///
/// There is no `after` parameter by construction: the operation registers no
/// durable cursor, so a transport that accepted one would be advertising a
/// catch-up guarantee the rail does not have.
pub trait SignalStreamTransport {
    #[cfg(not(target_arch = "wasm32"))]
    type Source: SignalStreamFrameSource + Send;

    #[cfg(target_arch = "wasm32")]
    type Source: SignalStreamFrameSource;

    fn open_signal_stream<'a>(&'a self) -> BoxSignalStreamFuture<'a, Self::Source>;
}

impl SignalStreamFrameSource for arkret_http_client::SignalSubscribeFrameStream {
    fn next_frame<'a>(&'a mut self) -> BoxSignalStreamFuture<'a, Option<SignalStreamFrame>> {
        Box::pin(async move { self.next_frame().await.map_err(Error::from) })
    }
}

impl SignalStreamTransport for arkret_http_client::Client {
    type Source = arkret_http_client::SignalSubscribeFrameStream;

    fn open_signal_stream<'a>(&'a self) -> BoxSignalStreamFuture<'a, Self::Source> {
        Box::pin(async move { self.signal_subscribe_frames().await.map_err(Error::from) })
    }
}

/// Why one Signal receive connection ended.
///
/// None of these carry a resume position: `drain` only bounds how soon the same
/// session/device may re-open the rail.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SignalStreamStopReason {
    StreamEnded,
    Drain {
        reconnect_after_ms: Option<u64>,
        reason: Option<String>,
    },
    Unauthorized {
        reason: Option<String>,
    },
}

/// Which side of the rail failed.
///
/// The split exists because the two need opposite recovery: a transport fault
/// is a reconnect, while a sink fault means the host could not durably take
/// what it was handed and retrying the connection would only lose more.
#[derive(Debug)]
pub enum SignalRunError {
    Transport(Error),
    Sink(Error),
}

impl SignalRunError {
    pub fn into_error(self) -> Error {
        match self {
            Self::Transport(error) | Self::Sink(error) => error,
        }
    }
}

pub type SignalRunResult<T> = std::result::Result<T, SignalRunError>;

/// Why an inbound envelope never reached the sink.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignalRejection {
    /// The envelope failed [`SignalReceiver::accept`]: structure, TTL, expiry,
    /// the current-directory sender authorization, the device proof, the AEAD
    /// open, the plaintext shape, or the §2 replay triple.
    Admission,
}

/// Host boundary for admitted Signal plaintext.
///
/// `deliver` runs after every check a receiver can make from the envelope and
/// the group state, so an implementation may project directly. Product-level
/// authorization that needs accepted state this crate does not hold (for
/// example re-checking `ak.message.stream.send` at `seal_ref`) still belongs to
/// the host, inside `deliver`.
pub trait SignalSink {
    /// Runs once per inbound envelope *before* admission, so a host can warm
    /// whatever state its synchronous [`SignalSenderKeyResolver`] reads.
    ///
    /// [`SignalReceiver::accept`] resolves the sender key before it touches
    /// the AEAD, and that resolution has to be synchronous; a host whose
    /// directory lookup is a network call would otherwise fail every first
    /// contact closed — which for call signalling means the invite that starts
    /// a session is the one that gets dropped.
    ///
    /// This hook decides nothing. Admission is still entirely
    /// [`SignalReceiver::accept`], and a host that leaves its cache cold here
    /// simply gets the envelope rejected as before.
    fn prepare_admission<'a>(&'a self, _envelope: &'a SignalEnvelope) -> impl Future<Output = ()> {
        async {}
    }

    /// The authenticated envelope is handed over with its plaintext because a
    /// product route may still need the outer header — the call rail, for
    /// example, re-verifies the device proof before it will ring a user.
    fn deliver<'a>(
        &'a self,
        envelope: &'a SignalEnvelope,
        plaintext: SignalPlaintext,
    ) -> impl Future<Output = Result<()>> + 'a;

    /// One dropped envelope. The rail keeps running; this exists so a host can
    /// surface a security diagnostic instead of losing the event silently.
    fn rejected(&self, _envelope: &SignalEnvelope, _rejection: SignalRejection, _error: &Error) {}

    /// A clock edge that carried no admitted signal: opening a connection, a
    /// keepalive frame, a clean end, or a transport failure.
    ///
    /// Signal-backed projections are TTL-shaped — a message-stream preview
    /// goes stalled after 30 seconds and is discarded after ten minutes
    /// (`signal.md` §7.4) — so they need a clock edge even when the producer
    /// has gone quiet, which is precisely when nothing else would wake them.
    /// Keepalives and reconnect lifecycle edges are the rail's own liveness
    /// cadence, so they are the right edges to use rather than a second timer
    /// the host has to keep alive. Implementations must tolerate repeated
    /// calls at the same or nearby instants and project expiry idempotently.
    fn idle(&self, _now: DateTime<Utc>) {}
}

/// The three host seams one Signal receive connection needs, grouped so their
/// order of use is fixed at construction: resolve the sender key, open the
/// AEAD, then deliver.
pub struct SignalReceiveHandlers<'a, R, D, S: ?Sized> {
    pub resolver: &'a R,
    pub decryptor: &'a D,
    pub sink: &'a S,
}

impl<'a, R, D, S: ?Sized> SignalReceiveHandlers<'a, R, D, S> {
    pub fn new(resolver: &'a R, decryptor: &'a D, sink: &'a S) -> Self {
        Self {
            resolver,
            decryptor,
            sink,
        }
    }
}

impl<R, D, S: ?Sized> Clone for SignalReceiveHandlers<'_, R, D, S> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<R, D, S: ?Sized> Copy for SignalReceiveHandlers<'_, R, D, S> {}

/// One Signal receive rail, reusable across reconnects.
///
/// The de-duplication window lives here rather than per connection: §2 keys it
/// on `(sender_device_id, scope_ref, payload_sequence)`, which a reconnect does
/// not reset, and a per-connection window would let a redelivered envelope back
/// in after any drain.
#[derive(Debug, Default)]
pub struct SignalStreamDriver {
    receiver: SignalReceiver,
}

impl SignalStreamDriver {
    pub fn new() -> Self {
        Self {
            receiver: SignalReceiver::new(),
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            receiver: SignalReceiver::with_capacity(capacity),
        }
    }

    /// Drain one Signal connection until a terminal control frame or EOF.
    ///
    /// The clock is read per envelope because a single connection stays open
    /// across many TTL windows; using the connection's open time would admit
    /// signals that expired mid-stream.
    pub async fn run<T, R, D, S, K>(
        &mut self,
        transport: &T,
        handlers: SignalReceiveHandlers<'_, R, D, S>,
        clock: &K,
    ) -> SignalRunResult<SignalStreamStopReason>
    where
        T: SignalStreamTransport + ?Sized,
        R: SignalSenderKeyResolver,
        D: SignalDecryptor,
        S: SignalSink + ?Sized,
        K: HostClock,
    {
        let mut source = match transport.open_signal_stream().await {
            Ok(source) => {
                // Establishing a fresh rail follows any reconnect/backoff and
                // is therefore a clock edge even before the server emits its
                // first heartbeat. This closes the gap where the previous
                // Drain arrived just before a presence TTL expired and the
                // next heartbeat would otherwise leave it stale for another
                // full interval.
                handlers.sink.idle(clock.now());
                source
            }
            Err(error) => {
                handlers.sink.idle(clock.now());
                return Err(SignalRunError::Transport(error));
            }
        };
        loop {
            let frame = match source.next_frame().await {
                Ok(frame) => frame,
                Err(error) => {
                    // A failed long-poll or stream is still a host clock edge.
                    // Presence and typing are TTL projections; skipping idle
                    // here leaves the final body online forever when a proxy
                    // aborts a quiet HTTP stream before any heartbeat frame.
                    handlers.sink.idle(clock.now());
                    return Err(SignalRunError::Transport(error));
                }
            };
            let Some(frame) = frame else {
                handlers.sink.idle(clock.now());
                return Ok(SignalStreamStopReason::StreamEnded);
            };
            match frame {
                SignalStreamFrame::Signal { envelope } => {
                    handlers.sink.prepare_admission(&envelope).await;
                    match self.receiver.accept(
                        &envelope,
                        handlers.resolver,
                        handlers.decryptor,
                        clock.now(),
                    ) {
                        Ok(plaintext) => handlers
                            .sink
                            .deliver(&envelope, plaintext)
                            .await
                            .map_err(SignalRunError::Sink)?,
                        Err(error) => {
                            handlers
                                .sink
                                .rejected(&envelope, SignalRejection::Admission, &error);
                        }
                    }
                }
                // Keepalive only. It advances no position because there is no
                // position on this rail to advance — but it is a clock edge
                // the host's TTL projections can use.
                SignalStreamFrame::Heartbeat => handlers.sink.idle(clock.now()),
                SignalStreamFrame::Drain {
                    reconnect_after_ms,
                    reason,
                } => {
                    handlers.sink.idle(clock.now());
                    return Ok(SignalStreamStopReason::Drain {
                        reconnect_after_ms,
                        reason,
                    });
                }
                SignalStreamFrame::Unauthorized { reason } => {
                    return Ok(SignalStreamStopReason::Unauthorized { reason });
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use arkret_wire::{DeviceId, DidUrl, EventId, Hash, RealmId, SealId};
    use chrono::{Duration, TimeZone};
    use ed25519_dalek::SigningKey;
    use serde_json::{Value, json};

    use super::*;
    use crate::protocol::signal::{SignalClass, SignalEncryptedPayload, SignalKeyRef, SignalProof};
    use crate::protocol::signatures::{PublicKeyMaterial, sign_ed25519_detached_jws};
    use crate::protocol::{DidCoreId, ScopeRef, canonical};

    #[derive(Clone, Copy)]
    struct FixedClock(DateTime<Utc>);

    impl HostClock for FixedClock {
        fn now(&self) -> DateTime<Utc> {
            self.0
        }
    }

    fn realm() -> RealmId {
        RealmId::new("ak:realm:AUhJ30wlw7UA5CWJk9HZUsDp0GyhA-QVSF565JjdtLul").unwrap()
    }

    fn actor() -> DidCoreId {
        DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap()
    }

    fn device() -> DeviceId {
        DeviceId::new("ak:device:01904100-0000-7000-8000-000000000005").unwrap()
    }

    fn sent_at() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, 28, 12, 0, 0).unwrap()
    }

    fn presence_plaintext(sequence: u64) -> Value {
        json!({
            "kind": "ak.presence",
            "actor_id": actor().as_str(),
            "state": "online",
            "payload_sequence": sequence,
            "ttl_ms": 30_000
        })
    }

    fn signed_signal(
        plaintext: Value,
        seed: [u8; 32],
    ) -> (SignalEnvelope, PublicKeyMaterial, Vec<u8>) {
        let plaintext_bytes = canonical::canonical_json_bytes(&plaintext).unwrap();
        let signing_key = SigningKey::from_bytes(&seed);
        let mut envelope = SignalEnvelope {
            realm_id: realm(),
            scope_ref: ScopeRef::Realm { realm_id: realm() },
            sender_actor_id: actor(),
            sender_device_id: device(),
            seal_ref: SealId::new(format!("ak:seal:sha256:{}", "a".repeat(64))).unwrap(),
            signal_class: SignalClass::Session,
            sent_at: sent_at(),
            expires_at: sent_at() + Duration::seconds(30),
            encrypted_payload: SignalEncryptedPayload {
                scheme: crate::protocol::signal::SIGNAL_AEAD_SCHEME.to_owned(),
                key_ref: SignalKeyRef {
                    algorithm: "MLS-EXPORTER-AEAD".to_owned(),
                    group_state_ref: EventId::from_digest(
                        arkret_canonical::DigestSuite::Sha256,
                        [0xcc; 32],
                    )
                    .to_string(),
                },
                purpose: crate::protocol::signal::SIGNAL_AEAD_PURPOSE.to_owned(),
                aead_profile: "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519".to_owned(),
                epoch: 7,
                nonce: "AAAAAAAAAAAAAAAA".to_owned(),
                ciphertext: "Q2lwaGVydGV4dFBsYWNlaG9sZGVy".to_owned(),
                aad_digest: Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
            },
            proof: SignalProof {
                kind: "detached_jws".to_owned(),
                verification_method: DidUrl::new(format!(
                    "did:webvh:z6mkfixture:alice.example#{}",
                    device()
                ))
                .unwrap(),
                envelope_digest: Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
                created_at: sent_at(),
                domain: None,
                audience: None,
                jws: "header..signature".to_owned(),
            },
        };
        envelope.encrypted_payload.aad_digest = envelope.expected_aad_digest().unwrap();
        envelope.proof.envelope_digest = envelope.envelope_digest().unwrap();
        let binding = envelope.proof_binding_bytes().unwrap();
        envelope.proof.jws = sign_ed25519_detached_jws(&signing_key, &binding).unwrap();
        let public_key = PublicKeyMaterial::Ed25519Raw {
            bytes: signing_key.verifying_key().to_bytes().to_vec(),
        };
        (envelope, public_key, plaintext_bytes)
    }

    struct VecSource {
        frames: VecDeque<Option<SignalStreamFrame>>,
    }

    impl SignalStreamFrameSource for VecSource {
        fn next_frame<'a>(&'a mut self) -> BoxSignalStreamFuture<'a, Option<SignalStreamFrame>> {
            let frame = self.frames.pop_front().flatten();
            Box::pin(async move { Ok(frame) })
        }
    }

    struct VecTransport {
        frames: Mutex<Option<Vec<Option<SignalStreamFrame>>>>,
    }

    impl VecTransport {
        fn new(frames: Vec<Option<SignalStreamFrame>>) -> Self {
            Self {
                frames: Mutex::new(Some(frames)),
            }
        }
    }

    impl SignalStreamTransport for VecTransport {
        type Source = VecSource;

        fn open_signal_stream<'a>(&'a self) -> BoxSignalStreamFuture<'a, Self::Source> {
            let frames = self.frames.lock().unwrap().take().unwrap_or_default();
            Box::pin(async move {
                Ok(VecSource {
                    frames: VecDeque::from(frames),
                })
            })
        }
    }

    struct FailingFrameSource;

    impl SignalStreamFrameSource for FailingFrameSource {
        fn next_frame<'a>(&'a mut self) -> BoxSignalStreamFuture<'a, Option<SignalStreamFrame>> {
            Box::pin(async move {
                Err(Error::Protocol(
                    "fixture signal stream was aborted".to_owned(),
                ))
            })
        }
    }

    struct FailingFrameTransport;

    impl SignalStreamTransport for FailingFrameTransport {
        type Source = FailingFrameSource;

        fn open_signal_stream<'a>(&'a self) -> BoxSignalStreamFuture<'a, Self::Source> {
            Box::pin(async move { Ok(FailingFrameSource) })
        }
    }

    struct FailingOpenTransport;

    impl SignalStreamTransport for FailingOpenTransport {
        type Source = VecSource;

        fn open_signal_stream<'a>(&'a self) -> BoxSignalStreamFuture<'a, Self::Source> {
            Box::pin(async move {
                Err(Error::Protocol(
                    "fixture signal stream could not open".to_owned(),
                ))
            })
        }
    }

    struct FixedDecryptor(Vec<u8>);

    impl SignalDecryptor for FixedDecryptor {
        fn open(&self, _envelope: &SignalEnvelope) -> Result<Vec<u8>> {
            Ok(self.0.clone())
        }
    }

    #[derive(Default)]
    struct RecordingSink {
        delivered: RefCell<Vec<SignalPlaintext>>,
        rejected: RefCell<Vec<String>>,
        order: RefCell<Vec<&'static str>>,
    }

    impl SignalSink for RecordingSink {
        fn prepare_admission<'a>(
            &'a self,
            _envelope: &'a SignalEnvelope,
        ) -> impl Future<Output = ()> {
            self.order.borrow_mut().push("prepare");
            async {}
        }

        fn deliver<'a>(
            &'a self,
            _envelope: &'a SignalEnvelope,
            plaintext: SignalPlaintext,
        ) -> impl Future<Output = Result<()>> + 'a {
            self.order.borrow_mut().push("deliver");
            self.delivered.borrow_mut().push(plaintext);
            async { Ok(()) }
        }

        fn rejected(&self, _envelope: &SignalEnvelope, rejection: SignalRejection, error: &Error) {
            assert_eq!(rejection, SignalRejection::Admission);
            self.order.borrow_mut().push("rejected");
            self.rejected.borrow_mut().push(error.to_string());
        }

        fn idle(&self, _now: DateTime<Utc>) {
            self.order.borrow_mut().push("idle");
        }
    }

    fn key_of(public_key: PublicKeyMaterial) -> impl SignalSenderKeyResolver {
        move |envelope: &SignalEnvelope| {
            Some(crate::signal::VerifiedSignalSenderKey::for_test(
                envelope,
                public_key.clone(),
            ))
        }
    }

    #[tokio::test]
    async fn admitted_signal_reaches_the_sink_and_drain_ends_the_connection() {
        let (envelope, public_key, plaintext) = signed_signal(presence_plaintext(1), [41; 32]);
        let transport = VecTransport::new(vec![
            Some(SignalStreamFrame::Heartbeat),
            Some(SignalStreamFrame::signal(envelope)),
            Some(SignalStreamFrame::Drain {
                reconnect_after_ms: Some(250),
                reason: Some("rotation".to_owned()),
            }),
            Some(SignalStreamFrame::Heartbeat),
        ]);
        let sink = RecordingSink::default();
        let resolver = key_of(public_key);
        let decryptor = FixedDecryptor(plaintext);

        let reason = SignalStreamDriver::new()
            .run(
                &transport,
                SignalReceiveHandlers::new(&resolver, &decryptor, &sink),
                &FixedClock(sent_at()),
            )
            .await
            .unwrap();

        assert_eq!(
            reason,
            SignalStreamStopReason::Drain {
                reconnect_after_ms: Some(250),
                reason: Some("rotation".to_owned())
            }
        );
        assert_eq!(sink.delivered.borrow().len(), 1);
        assert_eq!(sink.delivered.borrow()[0].payload_sequence, 1);
        assert!(sink.rejected.borrow().is_empty());
        // The warm-up hook must precede admission: a host whose sender-key
        // lookup is a network call resolves it here, and the synchronous
        // resolver inside `accept` then finds it. Keepalives and the drain are
        // clock edges for the host's TTL projections, which is the only thing
        // that wakes a preview whose producer went quiet.
        assert_eq!(
            *sink.order.borrow(),
            vec!["idle", "idle", "prepare", "deliver", "idle"]
        );
    }

    #[tokio::test]
    async fn transport_failure_advances_the_ttl_clock_before_reconnect() {
        let sink = RecordingSink::default();
        let resolver = |_envelope: &SignalEnvelope| None;
        let decryptor = FixedDecryptor(Vec::new());

        let error = SignalStreamDriver::new()
            .run(
                &FailingFrameTransport,
                SignalReceiveHandlers::new(&resolver, &decryptor, &sink),
                &FixedClock(sent_at()),
            )
            .await
            .unwrap_err();

        assert!(matches!(error, SignalRunError::Transport(_)));
        assert_eq!(
            *sink.order.borrow(),
            vec!["idle", "idle"],
            "a failed quiet stream must still expire presence/typing TTL projections"
        );
    }

    #[tokio::test]
    async fn open_failure_advances_the_ttl_clock_before_reconnect() {
        let sink = RecordingSink::default();
        let resolver = |_envelope: &SignalEnvelope| None;
        let decryptor = FixedDecryptor(Vec::new());

        let error = SignalStreamDriver::new()
            .run(
                &FailingOpenTransport,
                SignalReceiveHandlers::new(&resolver, &decryptor, &sink),
                &FixedClock(sent_at()),
            )
            .await
            .unwrap_err();

        assert!(matches!(error, SignalRunError::Transport(_)));
        assert_eq!(
            *sink.order.borrow(),
            vec!["idle"],
            "an open failure must still expire presence/typing TTL projections"
        );
    }

    #[tokio::test]
    async fn the_warm_up_hook_runs_even_for_an_envelope_that_is_then_rejected() {
        let (envelope, _, _) = signed_signal(presence_plaintext(1), [46; 32]);
        let transport = VecTransport::new(vec![Some(SignalStreamFrame::signal(envelope)), None]);
        let sink = RecordingSink::default();
        // The host could not resolve the sender at all; admission still fails
        // closed, and the hook must not have been skipped on the way there.
        let resolver = |_: &SignalEnvelope| None;
        let decryptor = FixedDecryptor(Vec::new());

        SignalStreamDriver::new()
            .run(
                &transport,
                SignalReceiveHandlers::new(&resolver, &decryptor, &sink),
                &FixedClock(sent_at()),
            )
            .await
            .unwrap();

        assert_eq!(
            *sink.order.borrow(),
            vec!["idle", "prepare", "rejected", "idle"]
        );
    }

    #[tokio::test]
    async fn a_rejected_envelope_is_dropped_without_ending_the_connection() {
        // The first envelope is signed by a key the resolver will not return,
        // so it fails the proof check; the second is well-formed. §4.5 makes
        // loss normal input, so one bad sender must not close the rail.
        let (bad_envelope, _, _) = signed_signal(presence_plaintext(1), [42; 32]);
        let (good_envelope, public_key, plaintext) = signed_signal(presence_plaintext(2), [43; 32]);
        let transport = VecTransport::new(vec![
            Some(SignalStreamFrame::signal(bad_envelope)),
            Some(SignalStreamFrame::signal(good_envelope)),
            None,
        ]);
        let sink = RecordingSink::default();
        let resolver = key_of(public_key);
        let decryptor = FixedDecryptor(plaintext);

        let reason = SignalStreamDriver::new()
            .run(
                &transport,
                SignalReceiveHandlers::new(&resolver, &decryptor, &sink),
                &FixedClock(sent_at()),
            )
            .await
            .unwrap();

        assert_eq!(reason, SignalStreamStopReason::StreamEnded);
        assert_eq!(sink.delivered.borrow().len(), 1);
        assert_eq!(sink.delivered.borrow()[0].payload_sequence, 2);
        assert_eq!(sink.rejected.borrow().len(), 1);
    }

    #[tokio::test]
    async fn the_dedup_window_survives_a_reconnect() {
        let (envelope, public_key, plaintext) = signed_signal(presence_plaintext(1), [44; 32]);
        let sink = RecordingSink::default();
        let resolver = key_of(public_key);
        let decryptor = FixedDecryptor(plaintext);
        let mut driver = SignalStreamDriver::new();
        let handlers = SignalReceiveHandlers::new(&resolver, &decryptor, &sink);
        let clock = FixedClock(sent_at());

        for _ in 0..2 {
            let transport = VecTransport::new(vec![
                Some(SignalStreamFrame::signal(envelope.clone())),
                None,
            ]);
            driver.run(&transport, handlers, &clock).await.unwrap();
        }

        assert_eq!(sink.delivered.borrow().len(), 1);
        assert_eq!(sink.rejected.borrow().len(), 1);
        assert!(sink.rejected.borrow()[0].contains("already delivered"));
    }

    #[tokio::test]
    async fn an_unauthorized_control_frame_is_terminal() {
        let transport = VecTransport::new(vec![Some(SignalStreamFrame::Unauthorized {
            reason: Some("revoked".to_owned()),
        })]);
        let sink = RecordingSink::default();
        let resolver = |_: &SignalEnvelope| None;
        let decryptor = FixedDecryptor(Vec::new());

        let reason = SignalStreamDriver::new()
            .run(
                &transport,
                SignalReceiveHandlers::new(&resolver, &decryptor, &sink),
                &FixedClock(sent_at()),
            )
            .await
            .unwrap();

        assert_eq!(
            reason,
            SignalStreamStopReason::Unauthorized {
                reason: Some("revoked".to_owned())
            }
        );
    }

    #[tokio::test]
    async fn an_envelope_that_expired_mid_stream_is_evaluated_against_the_current_instant() {
        let (envelope, public_key, plaintext) = signed_signal(presence_plaintext(1), [45; 32]);
        let transport = VecTransport::new(vec![Some(SignalStreamFrame::signal(envelope)), None]);
        let sink = RecordingSink::default();
        let resolver = key_of(public_key);
        let decryptor = FixedDecryptor(plaintext);

        SignalStreamDriver::new()
            .run(
                &transport,
                SignalReceiveHandlers::new(&resolver, &decryptor, &sink),
                // The connection opened at `sent_at`; this envelope is read
                // after its TTL window closed.
                &FixedClock(sent_at() + Duration::seconds(31)),
            )
            .await
            .unwrap();

        assert!(sink.delivered.borrow().is_empty());
        assert!(sink.rejected.borrow()[0].contains("already expired"));
    }
}
