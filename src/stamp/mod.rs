//! Durable, monotonic allocation of the HLC carried by signed Arkret values.
//!
//! A host MUST NOT mint these from a wall-clock string or an in-memory-only
//! counter: both regress across a process restart, and a wall clock that steps
//! backward could reissue an `hlc` tuple. `encoding.md` §7 forbids reusing an
//! emitted HLC tuple, so this module keeps a durable HLC floor.
//!
//! Actor sequence allocation deliberately does not live here. A host derives
//! `actor_seq` and `prev_refs` from the typed `(realm_id, actor_id)` frontier (or
//! the previous event in the same authoring transaction). Burning a local actor
//! sequence before acceptance would create an unfillable chain gap.
//! - `hlc` is a per-`(realm, device)` generator. The physical component is unix
//!   milliseconds; the durable floor makes it monotonic across restarts and
//!   immune to a backward wall clock. The `node_id` segment is the SDK's
//!   Realm-scoped pseudonymous derivation (`encoding.md` §7).
//!
//! The HLC advance is driven by a [`HostClock`] rather than the SDK
//! `HlcGenerator`'s advancing entry points, which read `SystemTime::now()` and
//! panic on `wasm32-unknown-unknown`. The SDK is still the single source of the
//! `node_id` derivation and the `Hlc` wire type.

use std::future::Future;

use crate::protocol::{DeviceId, DidCoreId, Error, Hlc, RealmId, Result};
use serde::{Deserialize, Serialize};

use crate::{HostClock, MaybeSendSync};

/// 16-bit logical counter ceiling (`encoding.md` §7: 4 lowercase hex digits).
const MAX_LOGICAL: u32 = crate::protocol::hlc::HLC_MAX_LOGICAL;
/// 48-bit physical millisecond ceiling (`encoding.md` §7: 12 lowercase hex).
const MAX_PHYSICAL: u64 = crate::protocol::hlc::HLC_MAX_PHYSICAL_MS;

/// Identity of one Realm/device HLC chain under an optional service and actor
/// scope. The actor is part of the storage partition for host isolation only;
/// no actor sequence state is stored or allocated here.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct StampScope {
    pub service_id: Option<DidCoreId>,
    pub actor_id: DidCoreId,
    pub device_id: DeviceId,
    pub realm_id: RealmId,
}

/// The durable HLC high-water mark for one [`StampScope`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StampFloor {
    /// Physical milliseconds of the highest HLC already issued.
    pub hlc_physical_ms: u64,
    /// Logical counter of the highest HLC already issued.
    pub hlc_logical: u32,
}

/// One atomic transition applied to a durable [`StampFloor`].
#[derive(Clone, Debug)]
pub enum StampFloorUpdate {
    IssueHlc { now_ms: u64 },
    Observe(RemoteStamp),
}

impl StampFloor {
    /// Apply one monotonic transition without mutating `self`.
    ///
    /// Stores call this while holding their transaction or cross-process lock,
    /// then durably commit the result before releasing that boundary.
    pub fn apply(self, update: StampFloorUpdate) -> Result<Self> {
        if self.hlc_physical_ms > MAX_PHYSICAL || self.hlc_logical > MAX_LOGICAL {
            return Err(Error::Protocol(
                "persisted stamp floor exceeds the HLC wire bounds".to_owned(),
            ));
        }
        match update {
            StampFloorUpdate::IssueHlc { now_ms } => {
                let (hlc_physical_ms, hlc_logical) =
                    advance_hlc(self.hlc_physical_ms, self.hlc_logical, now_ms)?;
                Ok(Self {
                    hlc_physical_ms,
                    hlc_logical,
                })
            }
            StampFloorUpdate::Observe(remote) => {
                let mut next = self;
                if let Some(hlc) = remote.hlc {
                    let (physical, logical) = hlc_parts(&hlc)?;
                    if (physical, logical) > (next.hlc_physical_ms, next.hlc_logical) {
                        next.hlc_physical_ms = physical;
                        next.hlc_logical = logical;
                    }
                }
                Ok(next)
            }
        }
    }
}

/// Durable persistence seam for the [`StampFloor`], keyed by [`StampScope`].
///
/// Implemented by the batteries-included [`crate::MemoryStore`] and
/// [`crate::FileStore`]; a web client provides an IndexedDB-backed
/// implementation. `advance_floor` MUST atomically load, apply, and durably
/// commit the transition before it resolves. A crash may skip an allocated
/// stamp, but concurrent callers and restarts must never receive the same one.
pub trait MonotonicStampStore: Clone + MaybeSendSync + 'static {
    fn load_floor(
        &self,
        scope: StampScope,
    ) -> impl Future<Output = Result<Option<StampFloor>>> + '_;

    fn advance_floor(
        &self,
        scope: StampScope,
        update: StampFloorUpdate,
    ) -> impl Future<Output = Result<StampFloor>> + '_;
}

/// A monotonic HLC ready to stamp onto a value before the SDK signs it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SigningStamp {
    pub hlc: Hlc,
}

/// Allocates durable, monotonic [`SigningStamp`]s for one [`StampScope`].
#[derive(Clone, Debug)]
pub struct SigningStampAllocator<S, E = crate::SystemClock> {
    store: S,
    clock: E,
    scope: StampScope,
    node_id: String,
}

impl<S> SigningStampAllocator<S, crate::SystemClock>
where
    S: MonotonicStampStore,
{
    /// Build an allocator using the host system clock. `local_node_secret` is
    /// the Realm-scoped local secret feeding the HLC `node_id` derivation; it
    /// MUST NOT be a principal DID, public handle, or any cross-Realm-stable
    /// identifier (`encoding.md` §7).
    pub fn new(store: S, scope: StampScope, local_node_secret: &[u8]) -> Self {
        Self::with_clock(store, scope, local_node_secret, crate::SystemClock)
    }
}

impl<S, E> SigningStampAllocator<S, E>
where
    S: MonotonicStampStore,
    E: HostClock,
{
    /// Build an allocator with a caller-supplied [`HostClock`] (tests and hosts
    /// whose wall clock is not `SystemTime`, e.g. wasm).
    pub fn with_clock(store: S, scope: StampScope, local_node_secret: &[u8], clock: E) -> Self {
        let node_id = derive_node_id(
            scope.realm_id.as_str(),
            scope.device_id.as_str(),
            local_node_secret,
        );
        Self {
            store,
            clock,
            scope,
            node_id,
        }
    }

    pub fn scope(&self) -> &StampScope {
        &self.scope
    }

    /// Issue and durably burn the next monotonic HLC for this scope.
    pub async fn issue(&self) -> Result<SigningStamp> {
        let now_ms = host_now_ms(&self.clock);
        let floor = self
            .store
            .advance_floor(self.scope.clone(), StampFloorUpdate::IssueHlc { now_ms })
            .await?;

        let hlc = Hlc::new(format!(
            "{:012x}-{:04x}-{}",
            floor.hlc_physical_ms, floor.hlc_logical, self.node_id
        ))
        .map_err(|err| Error::Protocol(format!("allocated hlc is invalid: {err}")))?;
        Ok(SigningStamp { hlc })
    }

    /// Advance the durable floor to at least a value observed from remote
    /// history, without issuing a stamp. Use this on the receive path so a
    /// remote HLC lifts the local floor before the next local value.
    pub async fn observe(&self, remote: RemoteStamp) -> Result<()> {
        self.store
            .advance_floor(self.scope.clone(), StampFloorUpdate::Observe(remote))
            .await?;
        Ok(())
    }
}

/// A remote observation used to lift the local floor via
/// [`SigningStampAllocator::observe`].
#[derive(Clone, Debug, Default)]
pub struct RemoteStamp {
    pub hlc: Option<Hlc>,
}

/// Monotonic HLC advance driven by a host-provided `now_ms`.
///
/// - `now_ms > floor`: jump to the newer physical time, reset logical.
/// - `now_ms <= floor` (clock stalled or rolled back): hold the physical floor
///   and bump logical, so the tuple stays strictly greater and is never reused.
/// - logical saturated: fail with `hlc_logical_overflow`. `encoding.md` §7
///   permits exactly two responses: wait for a larger `unix_ms`, or abort the
///   write with a local transient error for the caller to retry; it
///   explicitly forbids faking a larger wall clock to escape the overflow. A
///   wasm host cannot block, so this takes the error path (the same one the
///   SDK's non-blocking `HlcGenerator::try_generate` takes).
fn advance_hlc(floor_physical: u64, floor_logical: u32, now_ms: u64) -> Result<(u64, u32)> {
    if now_ms > MAX_PHYSICAL {
        return Err(Error::Protocol(
            "host clock exceeds the HLC 48-bit physical field".to_owned(),
        ));
    }
    if now_ms > floor_physical {
        return Ok((now_ms, 0));
    }
    if floor_logical < MAX_LOGICAL {
        return Ok((floor_physical, floor_logical + 1));
    }
    Err(Error::Protocol(
        "hlc_logical_overflow: local HLC saturated the 4-hex logical counter".to_owned(),
    ))
}

fn host_now_ms<E: HostClock>(clock: &E) -> u64 {
    // A pre-epoch wall clock maps to 0, matching the SDK generator; the durable
    // floor then keeps the HLC monotonic regardless.
    let millis = clock.now().timestamp_millis();
    u64::try_from(millis).unwrap_or(0).min(MAX_PHYSICAL)
}

fn hlc_parts(hlc: &Hlc) -> Result<(u64, u32)> {
    let parts = crate::protocol::hlc::parse_hlc(hlc.as_str())?;
    Ok((parts.physical_ms, parts.logical))
}

/// Derive the 8-hex `node_id` through the SDK so the derivation stays
/// single-sourced (`encoding.md` §7). The advancing generator entry points read
/// the system clock and panic on wasm, but `with_initial_time(..).current()`
/// only formats the seeded state, so it is clock-free and wasm-safe.
fn derive_node_id(realm_id: &str, device_id: &str, local_node_secret: &[u8]) -> String {
    let probe = crate::protocol::hlc::HlcGenerator::with_initial_time(
        realm_id,
        device_id,
        local_node_secret,
        0,
    )
    .current();
    // `probe` is `000000000000-0000-<node_id>`; the node segment is the last 8.
    probe.as_str()[18..26].to_owned()
}

/// Materialize the canonical HLC represented by a persisted floor.
///
/// Hosts with an unavoidable synchronous protocol builder can atomically
/// persist [`StampFloorUpdate::IssueHlc`] in their store, then call this helper
/// to obtain the same Realm-scoped SDK HLC representation used by
/// [`SigningStampAllocator`].
pub fn hlc_from_floor(
    scope: &StampScope,
    local_node_secret: &[u8],
    floor: StampFloor,
) -> Result<Hlc> {
    let node_id = derive_node_id(
        scope.realm_id.as_str(),
        scope.device_id.as_str(),
        local_node_secret,
    );
    Hlc::new(format!(
        "{:012x}-{:04x}-{node_id}",
        floor.hlc_physical_ms, floor.hlc_logical
    ))
    .map_err(|error| Error::Protocol(format!("allocated hlc is invalid: {error}")))
}

#[cfg(test)]
mod hlc_only_tests {
    use std::sync::{Arc, Mutex};

    use chrono::{DateTime, Utc};

    use super::*;
    use crate::MemoryStore;

    #[derive(Clone)]
    struct FixedClock(Arc<Mutex<i64>>);

    impl HostClock for FixedClock {
        fn now(&self) -> DateTime<Utc> {
            DateTime::from_timestamp_millis(*self.0.lock().unwrap()).unwrap()
        }
    }

    fn scope() -> StampScope {
        StampScope {
            service_id: None,
            actor_id: DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            device_id: DeviceId::new("ak:device:01904100-0000-7000-8000-000000000001").unwrap(),
            realm_id: RealmId::new("ak:realm:AfF-hFqRoMbajXkPapH-xaq0xwK-UKt2ph2zTs9JZRAO")
                .unwrap(),
        }
    }

    #[tokio::test]
    async fn allocator_burns_only_hlc_and_survives_clock_rollback() {
        let clock = FixedClock(Arc::new(Mutex::new(1_000)));
        let allocator = SigningStampAllocator::with_clock(
            MemoryStore::new(),
            scope(),
            b"local-node-secret",
            clock.clone(),
        );
        let first = allocator.issue().await.unwrap();
        *clock.0.lock().unwrap() = 900;
        let second = allocator.issue().await.unwrap();
        assert!(second.hlc.as_str() > first.hlc.as_str());
    }

    #[test]
    fn persisted_floor_has_no_actor_sequence_field() {
        let encoded = serde_json::to_value(StampFloor::default()).unwrap();
        assert!(encoded.get("actor_seq").is_none());
    }
}
