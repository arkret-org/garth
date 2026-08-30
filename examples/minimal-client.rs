use arkret_models_collaboration::http_bodies::{EventsQueryOutcome, EventsSubscribeFrame};
use arkret_models_collaboration::session_grant_bodies::{
    SessionGrantOutcome, SessionGrantRefreshOutcome, SessionGrantRefreshRequestBody,
    SessionGrantRequestBody,
};
use arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeBatch;
use arkret_models_collaboration::sync_frames::client_sync::SyncRequestBody;
use arkret_wire::{AccountId, DeviceId, DidCoreId, RealmId, SessionGrantId};
use chrono::{Duration, Utc};
use garth::Result;
use garth::subscribe::scan::BoxScanFuture;
use garth::{
    ArkretClient, AuthenticatedTransportFactory, BoxRealmStreamFuture, ClientEvent,
    ClientProjector, EventsScanRequest, EventsScanTransport, MemorySecureKeyStore, MemoryStore,
    NativeExecutor, RealmEventsFrameSource, RealmEventsTransport, RunOptions,
    SecureSessionGrantStore, SessionGrantState, SessionGrantStore, SessionGrantTransport,
    SessionRefreshOptions, SessionTransportProvider, SyncLoopControl, TransportProvider,
};
use garth::{AsyncSyncTransport, BoxSyncFuture};

struct Projector;

impl ClientProjector for Projector {
    async fn project(&self, batch: Vec<ClientEvent>) -> Result<()> {
        println!("projected {} client events", batch.len());
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct ReferenceTransport;

#[derive(Clone)]
struct ReferenceConfig {
    service_url: String,
}

#[derive(Clone)]
struct ReferenceSigner {
    key_handle: String,
}

struct EmptyRealmSource;

impl RealmEventsFrameSource for EmptyRealmSource {
    fn next_frame<'a>(&'a mut self) -> BoxRealmStreamFuture<'a, Option<EventsSubscribeFrame>> {
        Box::pin(async { Ok(None) })
    }
}

impl RealmEventsTransport for ReferenceTransport {
    type Source = EmptyRealmSource;

    fn open_realm_events<'a>(
        &'a self,
        _realm_id: &'a RealmId,
        _after: Option<&'a str>,
    ) -> BoxRealmStreamFuture<'a, Self::Source> {
        Box::pin(async { Ok(EmptyRealmSource) })
    }
}

impl EventsScanTransport for ReferenceTransport {
    fn scan_events<'a>(
        &'a self,
        _request: EventsScanRequest,
    ) -> BoxScanFuture<'a, EventsQueryOutcome> {
        Box::pin(async {
            Ok(EventsQueryOutcome {
                events: Vec::new(),
                snapshot_bootstrap: None,
                prev_cursor: None,
                next_cursor: None,
                has_more: false,
                range_completeness: None,
            })
        })
    }
}

impl AsyncSyncTransport for ReferenceTransport {
    fn sync_async<'a>(
        &'a self,
        _request: SyncRequestBody,
        _options: arkret_http_client::ClientRequestOptions,
    ) -> BoxSyncFuture<'a, AccountSubscribeBatch> {
        Box::pin(async {
            Err(garth::Error::Protocol(
                "reference transport performs no network IO".to_owned(),
            ))
        })
    }
}

#[derive(Clone, Copy)]
struct ReferenceSessionTransport;

impl SessionGrantTransport for ReferenceSessionTransport {
    fn issue_session_grant<'a>(
        &'a self,
        _request: SessionGrantRequestBody,
    ) -> garth::session::BoxSessionFuture<'a, SessionGrantOutcome> {
        Box::pin(async {
            Err(garth::Error::Protocol(
                "reference transport performs no login IO".to_owned(),
            ))
        })
    }

    fn refresh_session_grant<'a>(
        &'a self,
        _request: SessionGrantRefreshRequestBody,
    ) -> garth::session::BoxSessionFuture<'a, SessionGrantRefreshOutcome> {
        Box::pin(async {
            Err(garth::Error::Protocol(
                "reference transport performs no refresh IO".to_owned(),
            ))
        })
    }
}

#[derive(Clone)]
struct ReferenceFactory {
    config: ReferenceConfig,
    signer: ReferenceSigner,
}

impl AuthenticatedTransportFactory for ReferenceFactory {
    type Transport = ReferenceTransport;

    fn build(&self, _state: &SessionGrantState) -> Result<Self::Transport> {
        assert!(self.config.service_url.starts_with("https://"));
        assert!(!self.signer.key_handle.is_empty());
        Ok(ReferenceTransport)
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let actor_id = DidCoreId::new("ak:did_core:webvh:z6mkfixture:alice.example")?;
    let principal_id = DidCoreId::new("ak:did_core:webvh:z6mkfixture:alice.example")?;
    let station_id = DidCoreId::new("ak:did_core:webvh:z6mkfixture:service.example")?;
    let device_id = DeviceId::new("ak:device:01904100-0000-7000-8000-000000000001")?;
    let realm_id = RealmId::new("ak:realm:AfF-hFqRoMbajXkPapH-xaq0xwK-UKt2ph2zTs9JZRAO")?;

    // Production hosts replace this memory vault with Keychain/Keystore/etc.
    let grant_store =
        SecureSessionGrantStore::new(MemorySecureKeyStore::default(), "reference/session-grant");
    grant_store
        .save(&SessionGrantState {
            account_id: AccountId::new(principal_id, station_id.clone()),
            device_id: Some(device_id.clone()),
            grant_id: SessionGrantId::from_issuance_digest([1_u8; 32]),
            grant_jwt: "reference-grant".to_owned(),
            expires_at: Utc::now() + Duration::hours(1),
            audience_id: station_id,
            granted_scope: vec![
                arkret_wire::CapabilityActionId::SELF_EVENTS_STREAM_SUBSCRIBE_V1.to_owned(),
            ],
            session_public_key: Some("reference-public-key".to_owned()),
            dpop_jkt: Some("reference-jkt".to_owned()),
        })
        .await?;
    let restored = grant_store.load()?.expect("stored grant must restore");
    println!("restored session {}", restored.grant_id);

    let store = MemoryStore::new();
    let client = ArkretClient::new(NativeExecutor, store.clone(), store);
    let provider = SessionTransportProvider::restore(
        ReferenceSessionTransport,
        ReferenceFactory {
            config: ReferenceConfig {
                service_url: "https://service.example".to_owned(),
            },
            signer: ReferenceSigner {
                key_handle: "platform-key-handle".to_owned(),
            },
        },
        SessionRefreshOptions::default(),
        grant_store,
    )?;
    // Resolve the authenticated transport once so the example also proves the
    // platform config/signer factory boundary, not only the runner signatures.
    let _authenticated_transport = provider.provide().await?;
    let projector = Projector;

    // A real host keeps this control alive. Pre-cancelling makes the compiled
    // example deterministic and network-free while exercising both facades.
    let account_control = SyncLoopControl::new();
    account_control.cancel();
    let _ = client
        .run_account(
            actor_id,
            device_id,
            &provider,
            &projector,
            &account_control,
            RunOptions::default(),
        )
        .await?;

    let realm_control = SyncLoopControl::new();
    realm_control.cancel();
    let _ = client
        .run_realm(
            &provider,
            realm_id,
            arkret_canonical::DigestSuite::Sha256,
            &projector,
            &realm_control,
            RunOptions::default(),
        )
        .await?;

    Ok(())
}
