//! Native Device consumption shares the ordinary continuity/current engine.

use std::sync::Arc;

use arkret_http_client::own_station_device_results::{
    BoundOwnStationDeviceResponse as NativeResponse, OwnStationDeviceClient as NativeClient,
    OwnStationDeviceSnapshot as NativeContext,
};
use arkret_wire::ScopeRef;

use super::*;

#[derive(Clone)]
enum DeviceLease {
    Snapshot(Arc<NativeResponse<RealmId, RealmStateSnapshot>>),
    Scan(Arc<NativeResponse<StreamScanRequestBody, StreamScanResponseBody>>),
}
impl DeviceLease {
    fn check(&self) -> Result<()> {
        match self {
            Self::Snapshot(value) => {
                value.value()?;
            }
            Self::Scan(value) => {
                value.value()?;
            }
        }
        Ok(())
    }
}

/// One exact-scope current/history view. It never becomes a Human Session or
/// a portable governance proof. Cold state must be re-admitted by fresh reads.
#[derive(Clone)]
pub struct OwnStationDeviceReplica {
    inner: OwnStationReplica,
    scope: ScopeRef,
    lease: Option<DeviceLease>,
}

pub struct OwnStationDeviceScanPage {
    response: Arc<NativeResponse<StreamScanRequestBody, StreamScanResponseBody>>,
}
impl OwnStationDeviceScanPage {
    pub fn rows(&self) -> Result<&[CommittedEventView]> {
        Ok(&self.response.value()?.committed_events)
    }
    pub fn into_rows(self) -> Result<Vec<CommittedEventView>> {
        Ok(self.response.value()?.committed_events.clone())
    }
    pub fn request(&self) -> &StreamScanRequestBody {
        self.response.request()
    }
    pub fn context(&self) -> &NativeContext {
        self.response.context()
    }
}

fn require_scope(snapshot: &RealmStateSnapshot, scope: &ScopeRef) -> Result<()> {
    arkret_http_client::own_station_device_results::validate_device_snapshot_scope(snapshot, scope)
        .map_err(|error| protocol(&error.to_string()))
}

/// Head and historical originals share shape/content checks, but their bound
/// request types remain distinct; a by-ref object cannot install current.
pub fn consume_own_station_device_snapshot<Q>(
    response: &NativeResponse<Q, RealmStateSnapshot>,
) -> Result<&RealmStateSnapshot> {
    let value = response.value()?;
    let scope = response.context().effective_scope();
    require_scope(value, scope)?;
    validate_snapshot(value, scope.realm_id())?;
    response.value()?;
    Ok(value)
}

impl OwnStationDeviceReplica {
    pub fn new(scope: ScopeRef) -> Result<Self> {
        if !matches!(scope, ScopeRef::Realm { .. } | ScopeRef::Circle { .. }) {
            return Err(protocol("native replica requires a Realm or Circle"));
        }
        Ok(Self {
            inner: OwnStationReplica::new(scope.realm_id().clone()),
            scope,
            lease: None,
        })
    }
    pub fn scope(&self) -> &ScopeRef {
        &self.scope
    }
    pub fn snapshot(&self) -> Result<Option<&RealmStateSnapshot>> {
        if let Some(lease) = &self.lease {
            lease.check()?;
        }
        Ok(self.inner.snapshot.as_ref())
    }
    pub fn head(&self) -> Result<Option<&CommitStreamHead>> {
        if let Some(lease) = &self.lease {
            lease.check()?;
        }
        let stream = CommitStreamRef::from_scope(&self.scope, None)
            .map_err(|error| protocol(&error.to_string()))?;
        Ok(self.inner.heads.get(&stream))
    }
    fn check_context(&self, context: &NativeContext) -> Result<()> {
        if context.effective_scope() != &self.scope {
            return Err(protocol("native replica belongs to another exact scope"));
        }
        self.inner
            .check_source_context(&ReplicaContext::Device(context.clone()))?;
        if let Some(lease) = &self.lease {
            lease.check()?;
        }
        Ok(())
    }
    fn check_client(&self, client: &NativeClient) -> Result<()> {
        self.check_context(client.context()?)
    }
    pub async fn refresh_current(&mut self, client: &NativeClient) -> Result<()> {
        self.check_client(client)?;
        let response = client.snapshot_head(self.scope.realm_id()).await?;
        self.install_current(response)
    }
    pub fn install_current(
        &mut self,
        response: NativeResponse<RealmId, RealmStateSnapshot>,
    ) -> Result<()> {
        self.check_context(response.context())?;
        if response.request() != self.scope.realm_id() {
            return Err(protocol("native current request belongs to another Realm"));
        }
        let value = consume_own_station_device_snapshot(&response)?;
        let mut candidate = self.inner.clone();
        candidate.install_snapshot_value(value)?;
        response.value()?;
        candidate.context = Some(ReplicaContext::Device(response.context().clone()));
        self.inner = candidate;
        self.lease = Some(DeviceLease::Snapshot(Arc::new(response)));
        Ok(())
    }
    pub async fn bootstrap_current_head(&mut self, client: &NativeClient) -> Result<()> {
        self.check_client(client)?;
        let stream = CommitStreamRef::from_scope(&self.scope, None)
            .map_err(|error| protocol(&error.to_string()))?;
        if self.inner.heads.contains_key(&stream) {
            return Err(protocol("native bootstrap would replace accepted history"));
        }
        let expected = self
            .inner
            .current_heads
            .get(&stream)
            .cloned()
            .ok_or_else(|| protocol("native bootstrap has no exact current coverage"))?;
        self.restore_checkpoint_head(client, &expected).await
    }
    pub async fn restore_checkpoint_head(
        &mut self,
        client: &NativeClient,
        expected: &CommitStreamHead,
    ) -> Result<()> {
        self.check_client(client)?;
        let stream = CommitStreamRef::from_scope(&self.scope, None)
            .map_err(|error| protocol(&error.to_string()))?;
        if expected.stream_ref != stream {
            return Err(protocol("native checkpoint belongs to another stream"));
        }
        let request = StreamScanRequestBody {
            realm_id: self.scope.realm_id().clone(),
            stream_ref: stream,
            direction: StreamScanDirection::Before(Some(
                expected
                    .stream_position
                    .checked_add(1)
                    .ok_or_else(|| protocol("native checkpoint position overflow"))?,
            )),
            limit: 1,
        };
        let response = client.scan_commit_stream(&request).await?;
        self.check_context(response.context())?;
        let mut candidate = self.inner.clone();
        candidate
            .restore_scan_head(client, expected, response.request(), response.value()?)
            .await?;
        response.value()?;
        client.check_context()?;
        candidate.context = Some(ReplicaContext::Device(response.context().clone()));
        self.inner = candidate;
        self.lease = Some(DeviceLease::Scan(Arc::new(response)));
        Ok(())
    }
    pub async fn apply_bound_scan(
        &mut self,
        client: &NativeClient,
        response: NativeResponse<StreamScanRequestBody, StreamScanResponseBody>,
    ) -> Result<OwnStationDeviceScanPage> {
        self.check_client(client)?;
        self.check_context(response.context())?;
        if response.context() != client.context()?
            || response.request().stream_ref
                != CommitStreamRef::from_scope(&self.scope, None)
                    .map_err(|error| protocol(&error.to_string()))?
        {
            return Err(protocol(
                "native scan differs from its local Device or scope",
            ));
        }
        let mut candidate = self.inner.clone();
        candidate
            .apply_verified_scan(client, response.request(), response.value()?)
            .await?;
        response.value()?;
        client.check_context()?;
        candidate.context = Some(ReplicaContext::Device(response.context().clone()));
        self.inner = candidate;
        let response = Arc::new(response);
        self.lease = Some(DeviceLease::Scan(response.clone()));
        Ok(OwnStationDeviceScanPage { response })
    }
}
