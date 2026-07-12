use arkret::{AsyncSyncTransport, BoxSyncFuture, SyncOutcome, SyncRequestBody};
use arkret_core::{
    DeviceId, Did, EventsSubscribeFrame, GrantId, RealmId, Result, SessionGrantOutcome,
    SessionGrantRefreshOutcome, SessionGrantRefreshRequestBody, SessionGrantRequestBody,
    SyncBackfillOutcome,
};
use chrono::{Duration, Utc};
use garth::subscribe::scan::BoxScanFuture;
use garth::{
    ArkretClient, AuthenticatedTransportFactory, BoxRealmStreamFuture, ClientEvent,
    ClientProjector, EventsScanRequest, EventsScanTransport, MemorySecureKeyStore, MemoryStore,
    NativeExecutor, RealmEventsFrameSource, RealmEventsTransport, RunOptions,
    SecureSessionGrantStore, SessionGrantState, SessionGrantStore, SessionGrantTransport,
    SessionRefreshOptions, SessionTransportProvider, SyncLoopControl, TransportProvider,
};

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
    ) -> BoxScanFuture<'a, SyncBackfillOutcome> {
        Box::pin(async {
            Ok(SyncBackfillOutcome {
                events: Vec::new(),
                snapshot_bootstrap: None,
                prev_cursor: None,
                next_cursor: None,
                limited: false,
            })
        })
    }
}

impl AsyncSyncTransport for ReferenceTransport {
    fn sync_async<'a>(&'a self, _request: SyncRequestBody) -> BoxSyncFuture<'a, SyncOutcome> {
        Box::pin(async {
            Err(arkret_core::Error::Protocol(
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
            Err(arkret_core::Error::Protocol(
                "reference transport performs no login IO".to_owned(),
            ))
        })
    }

    fn refresh_session_grant<'a>(
        &'a self,
        _request: SessionGrantRefreshRequestBody,
    ) -> garth::session::BoxSessionFuture<'a, SessionGrantRefreshOutcome> {
        Box::pin(async {
            Err(arkret_core::Error::Protocol(
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
    let actor_id = Did::new("did:webvh:z6mkfixture:alice.example")?;
    let device_id = DeviceId::new("ak:device:01904100-0000-7000-8000-000000000001")?;
    let realm_id = RealmId::new("ak:realm:01904100-0000-7000-8000-000000000001")?;

    // Production hosts replace this memory vault with Keychain/Keystore/etc.
    let grant_store =
        SecureSessionGrantStore::new(MemorySecureKeyStore::default(), "reference/session-grant");
    grant_store
        .save(&SessionGrantState {
            principal_id: actor_id.clone(),
            device_id: Some(device_id.clone()),
            grant_id: GrantId::new("ak:grant:01904100-0000-7000-8000-000000000001")?,
            grant_jwt: "reference-grant".to_owned(),
            expires_at: Utc::now() + Duration::hours(1),
            audience: "did:webvh:z6mkfixture:service.example".to_owned(),
            granted_scope: vec!["ak.self.events.stream.subscribe".to_owned()],
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
            &projector,
            &realm_control,
            RunOptions::default(),
        )
        .await?;

    Ok(())
}
