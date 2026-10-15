//! Identical native/wasm inputs for shared host boundaries.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use arkret_wire::{EventId, ScopeRef};
use garth::mls::checkpoint::{EnvelopeError, MlsLocalCheckpointEnvelope, decrypt_with_epoch_check};
use garth::mls::checkpoint_port::{
    MlsCheckpointInstall, MlsCheckpointPort, MlsCheckpointStage, install_checkpoint,
    scope_checkpoint_key, scope_checkpoint_key_for_group,
};

fn checkpoint() -> MlsLocalCheckpointEnvelope {
    serde_json::from_str(include_str!("fixtures/checkpoint-v1.json")).unwrap()
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn general_event_signing_freezes_non_message_intent_and_retry_bytes() {
    use arkret_signatures::{Ed25519DetachedJwsSigner, SignEventOptions, sign_event};
    use arkret_wire::{ActorId, AuthoredEvent, DidCoreId, Event, EventKind};
    use garth::event_authoring::{EventAuthoringSession, event_submission};
    let seed = EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [4; 32]);
    let realm = arkret_wire::RealmId::from_event_id(&seed);
    let unsigned = AuthoredEvent::finalize_with_digest_suite(
        Event {
            event_id: seed,
            kind: EventKind::RealmFreeze,
            realm_id: realm.clone(),
            scope_ref: ScopeRef::Realm { realm_id: realm },
            actor_id: ActorId::service(DidCoreId::new("ak:did_core:web:alice.example").unwrap()),
            executed_by: None,
            authorization_ref: None,
            applet_id: None,
            external_ref: None,
            created_at: chrono::DateTime::from_timestamp(1_790_000_000, 0).unwrap(),
            semantic_refs: Vec::new(),
            producer_proof: None,
            payload: serde_json::from_value(serde_json::json!({"reason":"maintenance"})).unwrap(),
        },
        arkret_canonical::DigestSuite::Sha256,
    )
    .unwrap();
    let sign = |event: &mut AuthoredEvent| {
        sign_event(
            event,
            &Ed25519DetachedJwsSigner::new(
                ed25519_dalek::SigningKey::from_bytes(&[9; 32]),
                "did:web:alice.example#key-1",
            ),
            SignEventOptions::new(),
        )
        .map_err(|error| garth::Error::Protocol(error.to_string()))
    };
    assert!(event_submission(&unsigned).is_err());
    let signed = EventAuthoringSession::new(unsigned.clone())
        .unwrap()
        .sign_with(sign)
        .unwrap();
    assert_eq!(signed.event_id, unsigned.event_id);
    assert_eq!(signed.payload, unsigned.payload);
    let first = event_submission(&signed).unwrap();
    let retry = event_submission(&signed).unwrap();
    assert_eq!(
        arkret_canonical::canonical_json_bytes(&first.request).unwrap(),
        arkret_canonical::canonical_json_bytes(&retry.request).unwrap()
    );
    assert!(
        EventAuthoringSession::new(unsigned)
            .unwrap()
            .sign_with(|event| {
                let mut changed = event.event().clone();
                changed
                    .payload
                    .insert("reason".into(), serde_json::json!("rewritten"));
                *event = AuthoredEvent::finalize_with_digest_suite(
                    changed,
                    arkret_canonical::DigestSuite::Sha256,
                )?;
                sign(event)
            })
            .unwrap_err()
            .to_string()
            .contains("rewrote the frozen intent")
    );
}

fn install() -> MlsCheckpointInstall {
    MlsCheckpointInstall {
        scope: ScopeRef::Realm {
            realm_id: checkpoint().realm_id.parse().unwrap(),
        },
        checkpoint: checkpoint(),
        accepted_event_id: EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [9; 32]),
        consume: None,
    }
}

fn poll<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn v1_checkpoint_bytes_and_error_categories_are_portable() {
    let envelope = checkpoint();
    assert_eq!(
        decrypt_with_epoch_check(&envelope, "portable-checkpoint-fixture", 7).unwrap(),
        b"opaque RFC 9420 provider checkpoint"
    );
    assert!(matches!(
        decrypt_with_epoch_check(&envelope, "wrong", 7),
        Err(EnvelopeError::SecretMismatch)
    ));
    assert!(matches!(
        decrypt_with_epoch_check(&envelope, "portable-checkpoint-fixture", 8),
        Err(EnvelopeError::OutdatedCheckpoint {
            envelope_epoch: 7,
            current_epoch: 8
        })
    ));
    let encoded = serde_json::to_string(&envelope).unwrap();
    assert_eq!(
        serde_json::from_str::<MlsLocalCheckpointEnvelope>(&encoded).unwrap(),
        envelope
    );
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn scope_group_mapping_preserves_the_existing_v1_keyspace() {
    let realm = install().scope;
    assert_eq!(scope_checkpoint_key(&realm).unwrap(), checkpoint().realm_id);
    let id = EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [1; 32]);
    let sidecar = ScopeRef::Sidecar {
        realm_id: checkpoint().realm_id.parse().unwrap(),
        sidecar_id: arkret_wire::SidecarId::from_event_id(&id),
    };
    assert_eq!(
        scope_checkpoint_key_for_group(&sidecar, "group-one").unwrap(),
        format!("{}\u{1f}group-one", scope_checkpoint_key(&sidecar).unwrap())
    );
    assert_ne!(
        scope_checkpoint_key_for_group(&sidecar, "group-one").unwrap(),
        scope_checkpoint_key_for_group(&sidecar, "group-two").unwrap()
    );
    assert!(scope_checkpoint_key_for_group(&sidecar, " ").is_err());
    assert!(scope_checkpoint_key(&ScopeRef::RealmGenesis).is_err());
}

#[derive(Default)]
struct Host {
    calls: Vec<&'static str>,
    durable: bool,
    fail: bool,
    generation: u64,
}

struct Port(Arc<Mutex<Host>>);
struct Stage {
    host: Arc<Mutex<Host>>,
    generation: u64,
    published: bool,
}

impl MlsCheckpointPort for Port {
    type Staged = Stage;
    fn stage(self, _install: MlsCheckpointInstall) -> garth::Result<Stage> {
        let generation = {
            let mut host = self.0.lock().unwrap();
            host.calls.push("stage");
            host.generation
        };
        Ok(Stage {
            host: self.0,
            generation,
            published: false,
        })
    }
}

impl MlsCheckpointStage for Stage {
    async fn make_durable(&mut self) -> garth::Result<()> {
        std::future::poll_fn(|_| {
            // The lock is acquired on every poll: no host borrow crosses await.
            let mut host = self.host.lock().unwrap();
            if host.fail {
                return Poll::Ready(Err(garth::Error::Protocol("disk failed".into())));
            }
            if !host.durable {
                return Poll::Pending;
            }
            host.calls.push("durable");
            Poll::Ready(Ok(()))
        })
        .await
    }
    fn publish(mut self) -> garth::Result<()> {
        let mut host = self.host.lock().unwrap();
        if host.generation != self.generation {
            return Err(garth::Error::Protocol("session replaced".into()));
        }
        host.calls.push("publish");
        self.published = true;
        Ok(())
    }
}

impl Drop for Stage {
    fn drop(&mut self) {
        if !self.published {
            self.host.lock().unwrap().calls.push("abort");
        }
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn checkpoint_publish_waits_for_durability() {
    let host = Arc::new(Mutex::new(Host::default()));
    let mut future = Box::pin(install_checkpoint(Port(host.clone()), install()));
    assert!(poll(future.as_mut()).is_pending());
    assert_eq!(host.lock().unwrap().calls, ["stage"]);
    host.lock().unwrap().durable = true;
    assert!(matches!(poll(future.as_mut()), Poll::Ready(Ok(()))));
    assert_eq!(host.lock().unwrap().calls, ["stage", "durable", "publish"]);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn cancelled_or_failed_checkpoint_never_publishes() {
    for fail in [false, true] {
        let host = Arc::new(Mutex::new(Host {
            fail,
            ..Host::default()
        }));
        let mut future = Box::pin(install_checkpoint(Port(host.clone()), install()));
        let result = poll(future.as_mut());
        if fail {
            assert!(matches!(result, Poll::Ready(Err(_))));
        } else {
            assert!(result.is_pending());
        }
        drop(future);
        assert_eq!(host.lock().unwrap().calls, ["stage", "abort"]);
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn late_durable_completion_does_not_publish_into_a_new_session() {
    let host = Arc::new(Mutex::new(Host::default()));
    let mut future = Box::pin(install_checkpoint(Port(host.clone()), install()));
    assert!(poll(future.as_mut()).is_pending());
    {
        let mut state = host.lock().unwrap();
        state.generation = 1;
        state.durable = true;
    }
    assert!(matches!(poll(future.as_mut()), Poll::Ready(Err(_))));
    assert_eq!(host.lock().unwrap().calls, ["stage", "durable", "abort"]);
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn mismatched_checkpoint_scope_never_reaches_the_host() {
    let host = Arc::new(Mutex::new(Host::default()));
    let mut request = install();
    request.checkpoint.realm_id = "another-realm".into();
    let mut future = Box::pin(install_checkpoint(Port(host.clone()), request));
    assert!(matches!(poll(future.as_mut()), Poll::Ready(Err(_))));
    assert!(host.lock().unwrap().calls.is_empty());
}
