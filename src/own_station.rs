//! Ordinary clients consume original governance results from their own
//! durably enrolled Station. Native authority verification remains separate.

use arkret_http_client::Client;
use arkret_models_discovery::StationConnectionBinding;
use arkret_wire::{AccountId, RealmId, RealmSnapshotId, RealmStateSnapshot, StreamScanRequest};

use crate::{Error, RealmReplica, Result, VerifiedFloorSnapshot, VerifiedScanPage};

/// An authenticated, immutable transport bound to a host-enrolled connection,
/// full Account and request epoch. This is a local capability, never a wire
/// credential, portable proof or boolean verification result.
#[derive(Clone)]
pub struct OwnStationConsumer {
    http: Client,
    account: AccountId,
    request_epoch: u64,
    context: [u8; 32],
}

/// Original snapshot read on one enrolled authenticated Station transport.
#[derive(Clone, Debug)]
pub struct OwnStationSnapshot {
    snapshot: RealmStateSnapshot,
    context: [u8; 32],
}

impl OwnStationSnapshot {
    pub fn snapshot(&self) -> &RealmStateSnapshot {
        &self.snapshot
    }
}

impl OwnStationConsumer {
    /// The host must supply its durable enrollment and fence this epoch again
    /// before committing returned rows to its account store.
    pub async fn authenticate(
        http: Client,
        enrolled: &StationConnectionBinding,
        account: AccountId,
        request_epoch: u64,
    ) -> Result<Self> {
        account.validate()?;
        if http.base_url().as_str() != enrolled.base_url
            || account.station_id != enrolled.service_id
        {
            return Err(Error::Protocol(
                "own Station transport/account mismatch".to_owned(),
            ));
        }
        let described = arkret_http_client::station_connection::fetch_station_description(
            http.base_url(),
            true,
        )
        .await?;
        let actual = StationConnectionBinding::from_description(http.base_url(), &described, true)?;
        enrolled.require_same(&actual)?;
        let now = u64::try_from(chrono::Utc::now().timestamp_millis())
            .map_err(|error| Error::Protocol(error.to_string()))?;
        let request = arkret_models_identity::CurrentPrincipalRequestBody {
            request_id: arkret_wire::RequestId::new_v7_at(now),
            account_id: account.clone(),
        };
        // Account/profile materialization is not the authentication anchor.
        // Registration already accepts this self result with an exact full
        // Account echo and its lifetime PCR before recovery is initialized.
        http.current_principal(&request)
            .await?
            .validate_for_request(&request)?;
        let bytes = arkret_canonical::canonical_json_bytes(&(enrolled, &account, request_epoch))
            .map_err(|error| Error::Protocol(error.to_string()))?;
        Ok(Self {
            http,
            account,
            request_epoch,
            context: arkret_canonical::sha256_bytes(&bytes),
        })
    }

    pub fn require_context(&self, account: &AccountId, request_epoch: u64) -> Result<()> {
        if account != &self.account || request_epoch != self.request_epoch {
            return Err(Error::Protocol(
                "own Station request epoch or Account changed".to_owned(),
            ));
        }
        Ok(())
    }

    pub async fn snapshot_head(&self, realm_id: &RealmId) -> Result<OwnStationSnapshot> {
        let snapshot = self.http.realm_state_snapshot_head(realm_id).await?;
        crate::replica::validate_original_snapshot(&snapshot, realm_id, &snapshot.snapshot_id)?;
        Ok(OwnStationSnapshot {
            snapshot,
            context: self.context,
        })
    }

    pub async fn exact_snapshot(
        &self,
        realm_id: &RealmId,
        snapshot_id: &RealmSnapshotId,
    ) -> Result<OwnStationSnapshot> {
        let snapshot = self
            .http
            .realm_state_snapshot_by_ref(realm_id, snapshot_id)
            .await?;
        crate::replica::validate_original_snapshot(&snapshot, realm_id, snapshot_id)?;
        Ok(OwnStationSnapshot {
            snapshot,
            context: self.context,
        })
    }

    /// Each page is read on this exact authenticated transport, then checked
    /// atomically against its independent stream predecessor and original cut.
    pub async fn scan(
        &self,
        replica: &mut RealmReplica,
        request: &StreamScanRequest,
        cut: &OwnStationSnapshot,
    ) -> Result<VerifiedScanPage> {
        self.require_snapshot(cut)?;
        let outcome = self.http.scan_commit_stream(request).await?;
        replica.consume_station_scan(self.context, request, outcome, &cut.snapshot)
    }

    pub fn install_snapshot_heads(
        &self,
        replica: &mut RealmReplica,
        snapshot: &OwnStationSnapshot,
    ) -> Result<()> {
        self.require_snapshot(snapshot)?;
        replica.consume_station_snapshot(self.context, &snapshot.snapshot)
    }

    /// Restore the host's Account-scoped durable accepted anchor; its resumed
    /// tail must still reach this independently fetched original head.
    pub fn restore_anchor(
        &self,
        replica: &mut RealmReplica,
        anchor: &arkret_wire::RealmCommit,
        cut: &OwnStationSnapshot,
    ) -> Result<()> {
        self.require_snapshot(cut)?;
        replica.consume_station_anchor(self.context, anchor, &cut.snapshot)
    }

    /// Live bootstrap from one original current head. Other stream heads do
    /// not become this stream's predecessors or reconstructed past history.
    pub fn bootstrap_stream(
        &self,
        replica: &mut RealmReplica,
        stream: &arkret_wire::CommitStreamRef,
        cut: &OwnStationSnapshot,
    ) -> Result<()> {
        self.require_snapshot(cut)?;
        replica.consume_station_stream_head(self.context, stream, &cut.snapshot)
    }

    /// Visibility information alone cannot establish a replay predecessor.
    pub async fn readable_floor(
        &self,
        realm: &RealmId,
        stream: &arkret_wire::CommitStreamRef,
    ) -> Result<arkret_wire::ReadableFloor> {
        let request = StreamScanRequest {
            realm_id: realm.clone(),
            stream_ref: stream.clone(),
            direction: arkret_wire::StreamScanDirection::After(None),
            limit: 1,
        };
        let outcome = self.http.scan_commit_stream(&request).await?;
        outcome.validate_for_request(&request)?;
        outcome
            .readable_floor
            .ok_or_else(|| Error::Protocol("Station omitted readable floor".to_owned()))
    }

    fn require_snapshot(&self, snapshot: &OwnStationSnapshot) -> Result<()> {
        if snapshot.context != self.context {
            return Err(Error::Protocol(
                "snapshot belongs to another Account/request epoch".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn install_window_floor(
        &self,
        replica: &mut RealmReplica,
        stream: &arkret_wire::CommitStreamRef,
        basis: &arkret_models_collaboration::sync_frames::account_sync::StreamWindowStartBasis,
        floor: &arkret_wire::ReadableFloor,
        cut: &OwnStationSnapshot,
        dependencies: &std::collections::BTreeMap<
            arkret_wire::CommitStreamRef,
            Vec<VerifiedScanPage>,
        >,
    ) -> Result<VerifiedFloorSnapshot> {
        self.require_snapshot(cut)?;
        replica.consume_station_floor(
            self.context,
            stream,
            basis,
            floor,
            &cut.snapshot,
            dependencies,
        )
    }
}

impl crate::AuthorityTransport for OwnStationConsumer {
    async fn submit(
        &self,
        request: &arkret_wire::AuthoritySubmitRequest,
        options: &arkret_http_client::ClientRequestOptions,
    ) -> Result<arkret_wire::AuthoritySubmitOutcome> {
        use arkret_models_collaboration::authority_commit::{
            SelfAuthoritySubmitOutcome, SelfAuthoritySubmitRequest,
        };
        let request = match request {
            arkret_wire::AuthoritySubmitRequest::Event(value) => {
                SelfAuthoritySubmitRequest::Event(value.clone())
            }
            arkret_wire::AuthoritySubmitRequest::MlsCommit(value) => {
                SelfAuthoritySubmitRequest::MlsCommit(value.clone())
            }
        };
        match self.submit_self(&request, options).await? {
            SelfAuthoritySubmitOutcome::Ordinary(outcome) => Ok(outcome),
            _ => Err(Error::Protocol(
                "ordinary submission returned an aggregate".into(),
            )),
        }
    }

    async fn submit_self(
        &self,
        request: &arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest,
        options: &arkret_http_client::ClientRequestOptions,
    ) -> Result<arkret_models_collaboration::authority_commit::SelfAuthoritySubmitOutcome> {
        let outcome = self
            .http
            .submit_to_realm_authority(request, options)
            .await?;
        for item in crate::authority::accepted_items(request, &outcome)? {
            item.validate_shape()?;
            item.commit.validate_content_address()?;
            let suite = item.event.event_id.digest_suite_code().digest_suite();
            item.event
                .verify_event_id_matches_content_with_digest_suite(suite)?;
            item.event
                .validate_proof_bindings_with_digest_suite(suite)?;
        }
        Ok(outcome)
    }

    async fn scan(&self, request: &StreamScanRequest) -> Result<arkret_wire::StreamScanOutcome> {
        let outcome = self.http.scan_commit_stream(request).await?;
        outcome.validate_for_request(request)?;
        Ok(outcome)
    }

    async fn exact_snapshot(
        &self,
        realm: &RealmId,
        id: &RealmSnapshotId,
    ) -> Result<RealmStateSnapshot> {
        Ok(OwnStationConsumer::exact_snapshot(self, realm, id)
            .await?
            .snapshot)
    }

    async fn authority_bundle(
        &self,
        _: &arkret_wire::AuthorityBundleRequest,
    ) -> Result<arkret_wire::RealmAuthorityBundle> {
        Err(Error::Protocol(
            "ordinary consumers do not resolve native authority histories".into(),
        ))
    }

    async fn install_handoff(
        &self,
        _: &arkret_wire::AuthorityHandoffRequest,
        _: &arkret_http_client::ClientRequestOptions,
    ) -> Result<arkret_wire::RealmAuthorityHandoff> {
        Err(Error::Protocol(
            "ordinary consumers do not install native authority handoffs".into(),
        ))
    }
}

#[cfg(all(test, feature = "native"))]
mod tests {
    use std::io::{Read, Write};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Duration;

    use arkret_models_discovery::{AccountAuthority, ServiceDescribe, TransportBinding};
    use arkret_models_identity::{
        CurrentPrincipalOutcome, CurrentPrincipalRequestBody, PrincipalResolutionProjection,
    };
    use arkret_wire::{Did, DidCoreId, ServiceKind, TrustDomainId, WebOrigin};

    use super::*;

    #[tokio::test]
    async fn authenticates_before_profile_materialization_and_rejects_substitution() {
        // The fixture deliberately has no account/viewer projection. Only the
        // existing authenticated current-principal result is available.
        for mode in 0..4 {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let base =
                url::Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
            let mut description = ServiceDescribe::development(
                Did::new("did:web:station.example").unwrap(),
                TrustDomainId::new("ak:trust_domain:example.net").unwrap(),
                ServiceKind::Station,
                vec![
                    "ak.operation_bundle.station.describe.v1".into(),
                    "ak.operation_bundle.station.http_core_current.v1".into(),
                ],
                vec![TransportBinding::HttpJson {
                    base_url: base.to_string(),
                    extension_profile_required: (),
                }],
            );
            description.auth_metadata.account_authority = Some(AccountAuthority {
                origin: WebOrigin::new(base.origin().ascii_serialization()).unwrap(),
                gate_account_base_url: base.to_string(),
                extra: Default::default(),
            });
            let mut enrolled =
                StationConnectionBinding::from_description(&base, &description, true).unwrap();
            if mode == 3 {
                enrolled.trust_domain = TrustDomainId::new("ak:trust_domain:changed.net").unwrap();
            }
            let account = AccountId {
                station_id: description.service_id.clone(),
                principal_id: DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            };
            let running = Arc::new(AtomicBool::new(true));
            let serving = running.clone();
            let viewers = Arc::new(AtomicUsize::new(0));
            let observed_viewers = viewers.clone();
            let principals = Arc::new(AtomicUsize::new(0));
            let observed_principals = principals.clone();
            let server = std::thread::spawn(move || {
                while serving.load(Ordering::SeqCst) {
                    let Ok((mut socket, _)) = listener.accept() else {
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    };
                    socket
                        .set_read_timeout(Some(Duration::from_secs(5)))
                        .unwrap();
                    let mut bytes = Vec::new();
                    let header_end = loop {
                        let mut buffer = [0; 4096];
                        let size = socket.read(&mut buffer).unwrap();
                        assert!(size > 0);
                        bytes.extend_from_slice(&buffer[..size]);
                        if let Some(end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
                            break end + 4;
                        }
                    };
                    let headers = String::from_utf8_lossy(&bytes[..header_end]).into_owned();
                    let length = headers
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().unwrap())
                        })
                        .unwrap_or(0);
                    while bytes.len() < header_end + length {
                        let mut buffer = [0; 4096];
                        let size = socket.read(&mut buffer).unwrap();
                        assert!(size > 0);
                        bytes.extend_from_slice(&buffer[..size]);
                    }
                    let (status, body) = if headers
                        .starts_with("GET /_arkret/describe?service_kind=station ")
                    {
                        (200, serde_json::to_string(&description).unwrap())
                    } else if headers.starts_with("POST /_arkret/self/account/current-principal ") {
                        observed_principals.fetch_add(1, Ordering::SeqCst);
                        let request: CurrentPrincipalRequestBody =
                            serde_json::from_slice(&bytes[header_end..header_end + length])
                                .unwrap();
                        let mut outcome = CurrentPrincipalOutcome {
                            request_id: request.request_id,
                            account_id: request.account_id,
                            principal_control_realm_id: crate::test_fixtures::realm_id(),
                            resolution_projection: PrincipalResolutionProjection {
                                did: Did::new("did:web:alice.example").unwrap(),
                                method_history_head: "fixture-head".into(),
                                version_id: "fixture-version".into(),
                                resolution_event_ref: crate::test_fixtures::realm_id()
                                    .event_id()
                                    .to_string(),
                                updated_at: chrono::Utc::now(),
                            },
                        };
                        if mode == 1 {
                            outcome.account_id.station_id =
                                DidCoreId::new("ak:did_core:web:other.example").unwrap();
                        } else if mode == 2 {
                            outcome.request_id = arkret_wire::RequestId::new_v7_at(1);
                        }
                        (200, serde_json::to_string(&outcome).unwrap())
                    } else {
                        if headers.starts_with("GET /_arkret/self/account/viewer ") {
                            observed_viewers.fetch_add(1, Ordering::SeqCst);
                        }
                        (404, String::new())
                    };
                    let response = format!(
                        "HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    socket.write_all(response.as_bytes()).unwrap();
                }
            });
            let http = Client::builder(base)
                .allow_insecure_localhost()
                .build()
                .unwrap();
            let result =
                OwnStationConsumer::authenticate(http, &enrolled, account.clone(), 7).await;
            running.store(false, Ordering::SeqCst);
            server.join().unwrap();
            assert_eq!(
                viewers.load(Ordering::SeqCst),
                0,
                "profile readiness is not an authentication prerequisite"
            );
            assert_eq!(principals.load(Ordering::SeqCst), usize::from(mode != 3));
            if mode == 0 {
                let consumer = result.unwrap();
                consumer.require_context(&account, 7).unwrap();
                assert!(consumer.require_context(&account, 8).is_err());
                let other_account = AccountId {
                    station_id: DidCoreId::new("ak:did_core:web:other.example").unwrap(),
                    ..account
                };
                assert!(consumer.require_context(&other_account, 7).is_err());
            } else {
                assert!(
                    result.is_err(),
                    "substituted Account/request/Station binding must fail closed: {mode}"
                );
            }
        }
    }
}
