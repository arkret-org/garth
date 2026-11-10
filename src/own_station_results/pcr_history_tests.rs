//! Client-source tests with real root/Device proofs, not live Station admission.
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use arkret_models_identity::{CurrentPrincipalRequestBody, ResolvedSignerKey};
use arkret_signatures::{Ed25519PayloadSigner, SignEventOptions};
use arkret_test_kit::pcr_genesis::{HumanPcrFixtureInput, HumanPcrOriginalsFixture};
use arkret_wire::{
    ActorId, CurrentRevision, DetachedSignatureContext, EventKind, RealmCommitAuthorityRef,
};
use serde_json::{Value, json};

use super::*;
use crate::own_station_results::tests::{
    observed_client_for_account, seal_native_fixture_commit_at,
};

fn fixture() -> HumanPcrOriginalsFixture {
    HumanPcrOriginalsFixture::webvh(HumanPcrFixtureInput {
        station_id: &"ak:did_core:web:station.example".parse().unwrap(),
        endpoint: &url::Url::parse("https://principal.example/").unwrap(),
        root_seed: [7; 32],
        next_root_seed: [8; 32],
        device_seed: [41; 32],
        device_hpke_private_key: [51; 32],
        device_id: crate::test_fixtures::device_id(),
        genesis_salt: arkret_wire::GenesisSalt::new(arkret_canonical::base64url_encode([61; 32]))
            .unwrap(),
        created_at: crate::test_fixtures::at(0),
    })
    .unwrap()
}

fn principal_request(f: &HumanPcrOriginalsFixture) -> CurrentPrincipalRequestBody {
    CurrentPrincipalRequestBody {
        request_id: "ak:request:0196419b-0000-7000-8000-000000000001"
            .parse()
            .unwrap(),
        account_id: f.account.clone(),
    }
}

pub(super) fn original(
    f: &HumanPcrOriginalsFixture,
    event: arkret_wire::Event,
    position: u64,
    previous: Option<arkret_wire::RealmCommitId>,
) -> CommittedEventFullView {
    let mut commit = crate::test_fixtures::commit(
        81,
        &event,
        CommitStreamRef::Realm {
            realm_id: event.realm_id.clone(),
        },
        position,
    );
    commit.previous_commit_ref = previous;
    commit.authority_ref =
        RealmCommitAuthorityRef::GenesisOrChangeEvent(f.unit.create().event_id.clone());
    assert_eq!(
        commit.signature.context,
        DetachedSignatureContext::RealmCommit
    );
    CommittedEventFullView {
        event,
        commit: seal_native_fixture_commit_at(
            commit,
            crate::test_fixtures::at(if position < 2 { 1 } else { 3 }),
        ),
    }
}

pub(super) fn founding(f: &HumanPcrOriginalsFixture) -> [CommittedEventFullView; 2] {
    let create = original(f, f.unit.create().clone(), 0, None);
    let authorize = original(
        f,
        f.unit.founding_authorize().clone(),
        1,
        Some(create.commit.commit_id.clone()),
    );
    [create, authorize]
}

fn scan(rows: &[CommittedEventFullView], f: &[CommittedEventFullView; 2]) -> Value {
    json!(StreamScanResponseBody {
        committed_events: rows.iter().cloned().map(CommittedEventView::Full).collect(),
        readable_floor: Some(arkret_wire::ReadableFloor {
            oldest_position: 0,
            floor_commit_id: f[0].commit.commit_id.clone(),
            floor_reason: arkret_wire::ReadableFloorReason::StreamStart,
        }),
        truncated: true,
    })
}

pub(super) fn setup(
    f: &HumanPcrOriginalsFixture,
    pair: &[CommittedEventFullView; 2],
) -> Vec<Value> {
    vec![
        json!(f.current_principal(principal_request(f).request_id)),
        json!(CommittedEventView::Full(pair[0].clone())),
        scan(pair, pair),
        json!(f.document),
        json!(f.log),
    ]
}

fn successor(f: &HumanPcrOriginalsFixture, foreign: &str) -> arkret_wire::Event {
    let mut actor = f.account.clone();
    if foreign == "station" {
        actor.station_id = "ak:did_core:web:other-station.example".parse().unwrap();
    }
    let realm = if foreign == "realm" {
        RealmId::from_event_id(&EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [99; 32],
        ))
    } else {
        f.unit.create().realm_id.clone()
    };
    let mut event = crate::test_fixtures::event(
        82,
        EventKind::DeviceRevoke,
        json!({
            "device_id":"ak:device:0196419b-0000-7000-8000-000000000002",
            "revoked_by":f.device_id,"revoked_at":"2026-09-16T00:00:02.000Z","reason":"security_rotation"
        }),
    );
    event.actor_id = ActorId::account(actor);
    event.realm_id = realm.clone();
    event.scope_ref = ScopeRef::Realm { realm_id: realm };
    event.producer_proof = None;
    let mut authored = arkret_wire::AuthoredEvent::finalize_with_digest_suite(
        event,
        arkret_canonical::DigestSuite::Sha256,
    )
    .unwrap();
    let signer = Ed25519PayloadSigner::new(
        f.device_signing_key.clone(),
        f.resolution.did.clone(),
        f.device_verification_method.clone(),
    );
    arkret_signatures::sign_event(
        &mut authored,
        &signer,
        SignEventOptions::new().with_created_at(crate::test_fixtures::at(2)),
    )
    .unwrap();
    authored.into_event()
}

#[tokio::test]
async fn registered_human_pcr_history_verifies_originals_without_old_private_state() {
    for refusal in [
        "none",
        "empty_scan",
        "withheld_scan",
        "changed_get",
        "realm",
        "station",
        "wrong_key",
        "wrong_target",
        "wrong_authorization",
        "wrong_generation",
        "unavailable",
        "late_session",
    ] {
        let f = fixture();
        let pair = founding(&f);
        let mut bodies = setup(&f, &pair);
        let event = successor(&f, refusal);
        let id = event.event_id.clone();
        let mut full = original(
            &f,
            event,
            3,
            Some(arkret_wire::RealmCommitId::from_digest([80; 32])),
        );
        // Authorization acceptance predates the target. Its time must not be
        // replaced by the later business Commit's time.
        assert_ne!(pair[1].commit.committed_at, full.commit.committed_at);
        if refusal == "changed_get" {
            full.commit.committed_at = crate::test_fixtures::at(5);
        }
        bodies.push(json!(CommittedEventView::Full(full.clone())));
        let needs_scan = !matches!(refusal, "realm" | "station");
        let needs_key =
            needs_scan && !matches!(refusal, "empty_scan" | "withheld_scan" | "changed_get");
        if needs_scan {
            let mut page = scan(std::slice::from_ref(&full), &pair);
            if refusal == "empty_scan" {
                page["committed_events"] = json!([]);
                page["truncated"] = json!(false);
            }
            if refusal == "withheld_scan" {
                page["committed_events"] =
                    json!([{"commit":full.commit,"event_disclosure":{"status":"withheld"}}]);
            }
            bodies.push(page);
        }
        if needs_key {
            let mut authorization = CommittedEventRef {
                event_id: pair[1].event.event_id.clone(),
                commit_id: pair[1].commit.commit_id.clone(),
                stream_ref: pair[1].commit.stream_ref.clone(),
                stream_position: 1,
            };
            if refusal == "wrong_authorization" {
                authorization.stream_ref = CommitStreamRef::Realm {
                    realm_id: RealmId::from_event_id(&EventId::from_digest(
                        arkret_canonical::DigestSuite::Sha256,
                        [98; 32],
                    )),
                };
            }
            let key = ResolvedSignerKey {
                public_key_base64url: arkret_wire::Base64UrlString::new(
                    arkret_canonical::base64url_encode(
                        if refusal == "wrong_key" {
                            ed25519_dalek::SigningKey::from_bytes(&[42; 32]).verifying_key()
                        } else {
                            f.device_signing_key.verifying_key()
                        }
                        .as_bytes(),
                    ),
                )
                .unwrap(),
                authorization_ref: authorization,
                revision: CurrentRevision {
                    commit_id: pair[1].commit.commit_id.clone(),
                    stream_position: 1,
                },
                governance_generation: if refusal == "wrong_generation" { 1 } else { 0 },
            };
            bodies.push(json!({"__signer_key":key,"__expected_native_target":CommittedEventRef {
                event_id:id.clone(),commit_id:full.commit.commit_id.clone(),stream_ref:full.commit.stream_ref.clone(),stream_position:3
            },"__wrong_historical_target":refusal=="wrong_target",
                "__unavailable":refusal=="unavailable","__withdraw_source":refusal=="late_session"}));
        }
        let active = Arc::new(AtomicBool::new(true));
        let (source, server, requests) =
            observed_client_for_account(bodies, f.account.clone(), active.clone());
        let current = source
            .current_principal(&principal_request(&f))
            .await
            .unwrap();
        let pcr = read_own_station_human_pcr_genesis(&source, current)
            .await
            .unwrap();
        // The founding Device and root remain verified by their original native
        // registration and signatures; reading them makes no further HTTP call.
        assert_eq!(
            pcr.read_original(&pair[1].event.event_id)
                .await
                .unwrap()
                .full()
                .unwrap(),
            &pair[1]
        );
        let result = pcr.read_original(&id).await;
        assert_eq!(
            result.is_ok(),
            refusal == "none",
            "{refusal}: {}",
            result
                .as_ref()
                .err()
                .map(ToString::to_string)
                .unwrap_or_default()
        );
        if let Ok(event) = result {
            assert_eq!(event.full().unwrap(), &full);
            assert_eq!(event.reference().unwrap().event_id, id);
            active.store(false, Ordering::SeqCst);
            assert!(event.full().is_err());
            assert!(event.reference().is_err());
        }
        server.join().unwrap();
        assert_eq!(
            requests.lock().unwrap().len(),
            5 + 1 + usize::from(needs_scan) + usize::from(needs_key),
            "{refusal}"
        );
    }
}

#[tokio::test]
async fn pcr_history_context_requires_its_real_registration_and_current_account() {
    for refusal in [
        "native_log",
        "truncated_log",
        "current_account",
        "founding_floor",
    ] {
        let f = fixture();
        let pair = founding(&f);
        let mut bodies = setup(&f, &pair);
        match refusal {
            "native_log" => {
                bodies[4]["entries"][0]["state"]["id"] = json!("did:webvh:zOther:other.example")
            }
            "truncated_log" => bodies[4]["entries"] = json!([]),
            "current_account" => {
                bodies[0]["account_id"]["station_id"] =
                    json!("ak:did_core:web:other-station.example");
                bodies.truncate(1);
            }
            "founding_floor" => {
                bodies[2]["readable_floor"]["oldest_position"] = json!(1);
                bodies.truncate(3);
            }
            _ => unreachable!(),
        }
        let count = bodies.len();
        let (source, server, requests) =
            observed_client_for_account(bodies, f.account.clone(), Arc::new(AtomicBool::new(true)));
        let result = source.current_principal(&principal_request(&f)).await;
        if refusal == "current_account" {
            assert!(result.is_err());
        } else {
            assert!(
                read_own_station_human_pcr_genesis(&source, result.unwrap())
                    .await
                    .is_err(),
                "{refusal}"
            );
        }
        server.join().unwrap();
        assert_eq!(requests.lock().unwrap().len(), count, "{refusal}");
    }
}
