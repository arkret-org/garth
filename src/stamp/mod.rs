//! Durable, monotonic allocation of the `(actor_seq, hlc)` stamp every signed
//! Arkret v1 event carries.
//!
//! A host MUST NOT mint these from a wall-clock string or an in-memory-only
//! counter: both regress across a process restart, and a wall clock that steps
//! backward (VM snapshot restore, NTP correction, deliberate tampering) would
//! reissue an `hlc` tuple or an `actor_seq` height that was already signed and
//! sent. `encoding.md` §7 forbids reusing an emitted HLC tuple, and
//! `event-and-patch.md` §2.6 makes `actor_seq` a strictly increasing per-`(actor,
//! realm)` chain. This module keeps a durable floor so neither can happen.
//!
//! - `actor_seq` is chained per `(actor, realm)`: the issued height is
//!   `max(local_floor, server_frontier) + 1`. The server frontier drives
//!   cross-device coordination (siblings/CAS live server-side); the durable
//!   local floor only guarantees this device never reissues a height it already
//!   emitted before a crash.
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

use arkret_core::{DeviceId, Did, Error, Hlc, RealmId, Result};
use serde::{Deserialize, Serialize};

use crate::{HostClock, MaybeSendSync};

/// 16-bit logical counter ceiling (`encoding.md` §7: 4 lowercase hex digits).
const MAX_LOGICAL: u32 = arkret::hlc::HLC_MAX_LOGICAL;
/// 48-bit physical millisecond ceiling (`encoding.md` §7: 12 lowercase hex).
const MAX_PHYSICAL: u64 = arkret::hlc::HLC_MAX_PHYSICAL_MS;

/// Identity of one signing chain: a single `(actor, device, realm)` combination
/// under an optional service scope. `actor_seq` is a per-`(actor, realm)`
/// concept; the `device_id` narrows the durable floor to the local device that
/// owns this store (and feeds the HLC `node_id` derivation), so a device never
/// reissues its own stamps across a restart.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct StampScope {
    pub service_id: Option<Did>,
    pub actor_id: Did,
    pub device_id: DeviceId,
    pub realm_id: RealmId,
}

/// The durable high-water mark for one [`StampScope`]. Every field records the
/// highest value already *issued* (not merely observed): a fresh scope defaults
/// to all-zero, so the first issued `actor_seq` is `1` and the first HLC is at
/// or after the current wall clock.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StampFloor {
    /// Highest `actor_seq` already issued (`0` = none issued yet).
    pub actor_seq: u64,
    /// Physical milliseconds of the highest HLC already issued.
    pub hlc_physical_ms: u64,
    /// Logical counter of the highest HLC already issued.
    pub hlc_logical: u32,
}

/// One atomic transition applied to a durable [`StampFloor`].
#[derive(Clone, Debug)]
pub enum StampFloorUpdate {
    Issue {
        observed_frontier: Option<u64>,
        now_ms: u64,
    },
    /// Advance only the Realm/device HLC floor for a protocol value that is
    /// not itself an Event envelope. This must not consume an actor-chain
    /// sequence number.
    IssueHlc {
        now_ms: u64,
    },
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
            StampFloorUpdate::Issue {
                observed_frontier,
                now_ms,
            } => {
                let actor_seq = self
                    .actor_seq
                    .max(observed_frontier.unwrap_or(0))
                    .checked_add(1)
                    .ok_or_else(|| Error::Protocol("actor_seq counter overflow".to_owned()))?;
                let (hlc_physical_ms, hlc_logical) =
                    advance_hlc(self.hlc_physical_ms, self.hlc_logical, now_ms)?;
                Ok(Self {
                    actor_seq,
                    hlc_physical_ms,
                    hlc_logical,
                })
            }
            StampFloorUpdate::IssueHlc { now_ms } => {
                let (hlc_physical_ms, hlc_logical) =
                    advance_hlc(self.hlc_physical_ms, self.hlc_logical, now_ms)?;
                Ok(Self {
                    hlc_physical_ms,
                    hlc_logical,
                    ..self
                })
            }
            StampFloorUpdate::Observe(remote) => {
                let mut next = self;
                if let Some(actor_seq) = remote.actor_seq {
                    next.actor_seq = next.actor_seq.max(actor_seq);
                }
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

/// A monotonic `(actor_seq, hlc)` pair ready to stamp onto an event before the
/// SDK signs it. Signature monotonicity follows from the tuple's monotonicity:
/// the signer binds over these values (via the canonical `event_digest`), so a
/// never-reissued `(actor_seq, hlc)` means a never-reissued signed envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SigningStamp {
    pub actor_seq: u64,
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

    /// Issue the next monotonic `(actor_seq, hlc)` for this chain.
    ///
    /// `observed_frontier` is the highest `actor_seq` the server has already
    /// accepted for this `(actor, realm)` (the actor frontier the next event
    /// chains onto, `event-and-patch.md` §2.6). The issued height is
    /// `max(local_floor, observed_frontier) + 1`, so the server frontier can
    /// pull the chain forward after a fresh install while the durable local
    /// floor prevents restart reuse. Pass `None` to advance from the local
    /// floor alone.
    ///
    /// The advanced floor is persisted before the stamp is returned, so a
    /// crash between allocation and signing loses the stamp (the height is
    /// skipped) rather than reissuing it.
    pub async fn issue(&self, observed_frontier: Option<u64>) -> Result<SigningStamp> {
        let now_ms = host_now_ms(&self.clock);
        let floor = self
            .store
            .advance_floor(
                self.scope.clone(),
                StampFloorUpdate::Issue {
                    observed_frontier,
                    now_ms,
                },
            )
            .await?;

        let hlc = Hlc::new(format!(
            "{:012x}-{:04x}-{}",
            floor.hlc_physical_ms, floor.hlc_logical, self.node_id
        ))
        .map_err(|err| Error::Protocol(format!("allocated hlc is invalid: {err}")))?;
        Ok(SigningStamp {
            actor_seq: floor.actor_seq,
            hlc,
        })
    }

    /// Advance the durable floor to at least a value observed from remote
    /// history, without issuing a stamp. Use this on the receive path so a
    /// remote HLC or a server actor frontier lifts the local floor before the
    /// next local event, keeping the chain globally monotonic
    /// (`encoding.md` §7 receive rule).
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
    pub actor_seq: Option<u64>,
    pub hlc: Option<Hlc>,
}

/// Monotonic HLC advance driven by a host-provided `now_ms`.
///
/// - `now_ms > floor`: jump to the newer physical time, reset logical.
/// - `now_ms <= floor` (clock stalled or rolled back): hold the physical floor
///   and bump logical, so the tuple stays strictly greater and is never reused.
/// - logical saturated: fail with `hlc_logical_overflow`. `encoding.md` §7
///   permits exactly two responses — wait for a larger `unix_ms`, or abort the
///   write with a local transient error for the caller to retry — and
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
    let parts = arkret::hlc::parse_hlc(hlc.as_str())?;
    Ok((parts.physical_ms, parts.logical))
}

/// Derive the 8-hex `node_id` through the SDK so the derivation stays
/// single-sourced (`encoding.md` §7). The advancing generator entry points read
/// the system clock and panic on wasm, but `with_initial_time(..).current()`
/// only formats the seeded state, so it is clock-free and wasm-safe.
fn derive_node_id(realm_id: &str, device_id: &str, local_node_secret: &[u8]) -> String {
    let probe =
        arkret::hlc::HlcGenerator::with_initial_time(realm_id, device_id, local_node_secret, 0)
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
mod tests {
    use std::collections::BTreeSet;
    #[cfg(all(feature = "native", not(target_arch = "wasm32")))]
    use std::path::Path;
    use std::sync::{Arc, Mutex};

    use chrono::{DateTime, Utc};

    use super::*;
    use crate::MemoryStore;

    #[derive(Clone)]
    struct FixedClock {
        millis: Arc<Mutex<i64>>,
    }

    impl FixedClock {
        fn at(millis: i64) -> Self {
            Self {
                millis: Arc::new(Mutex::new(millis)),
            }
        }

        fn set(&self, millis: i64) {
            *self.millis.lock().unwrap() = millis;
        }
    }

    impl HostClock for FixedClock {
        fn now(&self) -> DateTime<Utc> {
            DateTime::from_timestamp_millis(*self.millis.lock().unwrap())
                .expect("test timestamp in range")
        }
    }

    fn scope() -> StampScope {
        StampScope {
            service_id: None,
            actor_id: Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
            device_id: DeviceId::new("ak:device:01904100-0000-7000-8000-000000000001").unwrap(),
            realm_id: RealmId::new("ak:realm:01904100-0000-7000-8000-000000000009").unwrap(),
        }
    }

    fn allocator(
        store: MemoryStore,
        clock: FixedClock,
    ) -> SigningStampAllocator<MemoryStore, FixedClock> {
        SigningStampAllocator::with_clock(store, scope(), b"local-node-secret", clock)
    }

    #[tokio::test]
    async fn first_issue_starts_actor_seq_at_one_and_hlc_at_wall_clock() {
        let clock = FixedClock::at(0x01970e589d21);
        let alloc = allocator(MemoryStore::new(), clock);

        let stamp = alloc.issue(None).await.unwrap();
        assert_eq!(stamp.actor_seq, 1);
        assert!(stamp.hlc.as_str().starts_with("01970e589d21-0000-"));
    }

    #[tokio::test]
    async fn successive_issues_are_strictly_monotonic() {
        let clock = FixedClock::at(0x01970e589d21);
        let alloc = allocator(MemoryStore::new(), clock);

        let first = alloc.issue(None).await.unwrap();
        // Same wall-clock millisecond: logical must advance so the tuple grows.
        let second = alloc.issue(None).await.unwrap();
        assert_eq!(first.actor_seq, 1);
        assert_eq!(second.actor_seq, 2);
        assert!(second.hlc.as_str() > first.hlc.as_str());
        assert!(second.hlc.as_str().starts_with("01970e589d21-0001-"));
    }

    #[tokio::test]
    async fn concurrent_allocator_clones_and_instances_never_reuse_stamps() {
        let store = MemoryStore::new();
        let clock = FixedClock::at(0x01970e589d21);
        let cloned = allocator(store.clone(), clock.clone());
        let barrier = Arc::new(tokio::sync::Barrier::new(65));
        let mut tasks = Vec::new();

        for index in 0..64 {
            let alloc = if index % 2 == 0 {
                cloned.clone()
            } else {
                allocator(store.clone(), clock.clone())
            };
            let barrier = barrier.clone();
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                alloc.issue(None).await.unwrap()
            }));
        }
        barrier.wait().await;

        let mut actor_seqs = BTreeSet::new();
        let mut hlcs = BTreeSet::new();
        for task in tasks {
            let stamp = task.await.unwrap();
            assert!(actor_seqs.insert(stamp.actor_seq));
            assert!(hlcs.insert(stamp.hlc));
        }
        assert_eq!(actor_seqs.len(), 64);
        assert_eq!(actor_seqs.first(), Some(&1));
        assert_eq!(actor_seqs.last(), Some(&64));
        assert_eq!(
            store.load_floor(scope()).await.unwrap().unwrap().actor_seq,
            64
        );
    }

    #[tokio::test]
    async fn concurrent_observe_and_issue_never_regress_the_floor() {
        let store = MemoryStore::new();
        let clock = FixedClock::at(0x01970e589d21);
        let alloc = allocator(store.clone(), clock);
        let remote_hlc = Hlc::new("01970e589d90-0007-a13f9c2e").unwrap();
        let barrier = Arc::new(tokio::sync::Barrier::new(34));
        let mut tasks = Vec::new();

        for _ in 0..32 {
            let alloc = alloc.clone();
            let barrier = barrier.clone();
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                alloc.issue(None).await.map(|_| ())
            }));
        }
        let observer = {
            let alloc = alloc.clone();
            let barrier = barrier.clone();
            let remote_hlc = remote_hlc.clone();
            tokio::spawn(async move {
                barrier.wait().await;
                alloc
                    .observe(RemoteStamp {
                        actor_seq: Some(10_000),
                        hlc: Some(remote_hlc),
                    })
                    .await
            })
        };
        barrier.wait().await;
        for task in tasks {
            task.await.unwrap().unwrap();
        }
        observer.await.unwrap().unwrap();

        let next = alloc.issue(None).await.unwrap();
        assert!(next.actor_seq > 10_000);
        assert!(next.hlc > remote_hlc);
    }

    #[tokio::test]
    async fn frontier_observation_pulls_actor_seq_forward() {
        let clock = FixedClock::at(0x01970e589d21);
        let alloc = allocator(MemoryStore::new(), clock);

        let stamp = alloc.issue(Some(100)).await.unwrap();
        assert_eq!(stamp.actor_seq, 101);
        // The local floor now dominates a stale frontier.
        let next = alloc.issue(Some(50)).await.unwrap();
        assert_eq!(next.actor_seq, 102);
    }

    #[tokio::test]
    async fn restart_does_not_reuse_actor_seq_or_hlc() {
        // A shared MemoryStore models the durable floor surviving the restart;
        // a fresh allocator over the same store is the reopened process.
        let store = MemoryStore::new();
        let clock = FixedClock::at(0x01970e589d21);
        let last = {
            let alloc = allocator(store.clone(), clock.clone());
            let mut last = alloc.issue(None).await.unwrap();
            for _ in 0..3 {
                last = alloc.issue(None).await.unwrap();
            }
            last
        };

        let reopened = allocator(store, clock);
        let after_restart = reopened.issue(None).await.unwrap();
        assert!(after_restart.actor_seq > last.actor_seq);
        assert!(after_restart.hlc.as_str() > last.hlc.as_str());
    }

    #[tokio::test]
    async fn clock_rollback_does_not_regress_hlc() {
        let store = MemoryStore::new();
        let clock = FixedClock::at(0x01970e589d21);
        let alloc = allocator(store, clock.clone());

        let before = alloc.issue(None).await.unwrap();
        // Wall clock steps 10s backward (NTP correction / snapshot restore).
        clock.set(0x01970e589d21 - 10_000);
        let after = alloc.issue(None).await.unwrap();

        let (before_phys, _) = hlc_parts(&before.hlc).unwrap();
        let (after_phys, after_logical) = hlc_parts(&after.hlc).unwrap();
        assert_eq!(after_phys, before_phys, "physical floor must not regress");
        assert_eq!(after_logical, 1, "logical advances while physical holds");
        assert!(after.hlc.as_str() > before.hlc.as_str());
    }

    #[tokio::test]
    async fn observe_lifts_floor_from_remote_history() {
        let clock = FixedClock::at(0x01970e589d21);
        let alloc = allocator(MemoryStore::new(), clock);

        alloc
            .observe(RemoteStamp {
                actor_seq: Some(500),
                hlc: Some(Hlc::new("01970e589d90-0007-a13f9c2e").unwrap()),
            })
            .await
            .unwrap();

        let stamp = alloc.issue(None).await.unwrap();
        assert_eq!(stamp.actor_seq, 501);
        // The remote HLC (physical 0x01970e589d90) is ahead of the local clock
        // (0x01970e589d21), so the next issue advances past it.
        assert!(stamp.hlc.as_str() > "01970e589d90-0007-a13f9c2e");
    }

    #[test]
    fn advance_hlc_saturated_logical_fails_instead_of_faking_the_wall_clock() {
        // Clock has not advanced and logical is saturated. `encoding.md` §7
        // allows only "wait for a larger unix_ms" or "abort with
        // hlc_logical_overflow", and forbids inventing wall-clock skew to
        // escape the overflow. Non-blocking issuance must therefore fail.
        let err = advance_hlc(1_000, MAX_LOGICAL, 500).unwrap_err();
        assert!(
            err.to_string().contains("hlc_logical_overflow"),
            "expected hlc_logical_overflow, got {err}"
        );
    }

    #[test]
    fn advance_hlc_saturated_logical_recovers_once_the_clock_moves_on() {
        // The caller's retry succeeds as soon as a larger unix_ms is available,
        // which is what makes the error path a transient one.
        let (physical, logical) = advance_hlc(1_000, MAX_LOGICAL, 1_001).unwrap();
        assert_eq!(physical, 1_001);
        assert_eq!(logical, 0);
    }

    #[test]
    fn node_id_is_realm_scoped_and_stable() {
        let a = derive_node_id("ak:realm:one", "device-1", b"secret");
        let a_again = derive_node_id("ak:realm:one", "device-1", b"secret");
        let other_realm = derive_node_id("ak:realm:two", "device-1", b"secret");
        assert_eq!(a, a_again);
        assert_eq!(a.len(), 8);
        assert_ne!(a, other_realm);
    }

    #[cfg(all(feature = "native", not(target_arch = "wasm32")))]
    #[tokio::test]
    async fn durable_file_store_restart_never_reuses_a_stamp() {
        use crate::FileStore;

        let path =
            std::env::temp_dir().join(format!("garth-stamp-restart-{}.json", std::process::id()));
        cleanup_file_store(&path);
        let clock = FixedClock::at(0x01970e589d21);

        let last = {
            let store = FileStore::open(&path).unwrap();
            let alloc = SigningStampAllocator::with_clock(
                store,
                scope(),
                b"local-node-secret",
                clock.clone(),
            );
            let mut last = alloc.issue(None).await.unwrap();
            for _ in 0..3 {
                last = alloc.issue(None).await.unwrap();
            }
            last
        };

        // Reopen the same file with the wall clock rolled backward: neither the
        // actor_seq height nor the HLC tuple may be reissued or regress.
        clock.set(0x01970e589d21 - 5_000);
        let reopened = FileStore::open(&path).unwrap();
        let alloc =
            SigningStampAllocator::with_clock(reopened, scope(), b"local-node-secret", clock);
        let after = alloc.issue(None).await.unwrap();
        assert!(after.actor_seq > last.actor_seq);
        assert!(after.hlc.as_str() > last.hlc.as_str());
        cleanup_file_store(&path);
    }

    #[cfg(all(feature = "native", not(target_arch = "wasm32")))]
    #[tokio::test]
    async fn separate_file_store_handles_allocate_unique_stamps() {
        use crate::FileStore;

        let path =
            std::env::temp_dir().join(format!("garth-stamp-handles-{}.json", std::process::id()));
        cleanup_file_store(&path);
        let clock = FixedClock::at(0x01970e589d21);
        let barrier = Arc::new(tokio::sync::Barrier::new(33));
        let mut tasks = Vec::new();
        for _ in 0..32 {
            let store = FileStore::open(&path).unwrap();
            let alloc = SigningStampAllocator::with_clock(
                store,
                scope(),
                b"local-node-secret",
                clock.clone(),
            );
            let barrier = barrier.clone();
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                alloc.issue(None).await.unwrap()
            }));
        }
        barrier.wait().await;

        let mut actor_seqs = BTreeSet::new();
        let mut hlcs = BTreeSet::new();
        for task in tasks {
            let stamp = task.await.unwrap();
            assert!(actor_seqs.insert(stamp.actor_seq));
            assert!(hlcs.insert(stamp.hlc));
        }
        assert_eq!(actor_seqs.len(), 32);
        assert_eq!(actor_seqs.first(), Some(&1));
        assert_eq!(actor_seqs.last(), Some(&32));
        let reopened = FileStore::open(&path).unwrap();
        assert_eq!(
            reopened
                .load_floor(scope())
                .await
                .unwrap()
                .unwrap()
                .actor_seq,
            32
        );
        cleanup_file_store(&path);
    }

    #[cfg(all(feature = "native", not(target_arch = "wasm32")))]
    #[tokio::test]
    async fn separate_file_store_handles_do_not_lose_observations() {
        use crate::FileStore;

        let path = std::env::temp_dir().join(format!(
            "garth-stamp-handle-observe-{}.json",
            std::process::id()
        ));
        cleanup_file_store(&path);
        let clock = FixedClock::at(0x01970e589d21);
        let remote_hlc = Hlc::new("01970e589d90-0007-a13f9c2e").unwrap();
        let barrier = Arc::new(tokio::sync::Barrier::new(34));
        let mut issuers = Vec::new();
        for _ in 0..32 {
            let alloc = SigningStampAllocator::with_clock(
                FileStore::open(&path).unwrap(),
                scope(),
                b"local-node-secret",
                clock.clone(),
            );
            let barrier = barrier.clone();
            issuers.push(tokio::spawn(async move {
                barrier.wait().await;
                alloc.issue(None).await.map(|_| ())
            }));
        }
        let observer = {
            let alloc = SigningStampAllocator::with_clock(
                FileStore::open(&path).unwrap(),
                scope(),
                b"local-node-secret",
                clock.clone(),
            );
            let barrier = barrier.clone();
            let remote_hlc = remote_hlc.clone();
            tokio::spawn(async move {
                barrier.wait().await;
                alloc
                    .observe(RemoteStamp {
                        actor_seq: Some(10_000),
                        hlc: Some(remote_hlc),
                    })
                    .await
            })
        };
        barrier.wait().await;
        for issuer in issuers {
            issuer.await.unwrap().unwrap();
        }
        observer.await.unwrap().unwrap();

        let reopened = SigningStampAllocator::with_clock(
            FileStore::open(&path).unwrap(),
            scope(),
            b"local-node-secret",
            clock,
        );
        let next = reopened.issue(None).await.unwrap();
        assert!(next.actor_seq > 10_000);
        assert!(next.hlc > remote_hlc);
        cleanup_file_store(&path);
    }

    #[cfg(all(feature = "native", not(target_arch = "wasm32")))]
    #[test]
    fn file_store_process_worker() {
        use crate::FileStore;

        let Ok(path) = std::env::var("GARTH_STAMP_WORKER_PATH") else {
            return;
        };
        let count = std::env::var("GARTH_STAMP_WORKER_COUNT")
            .unwrap()
            .parse::<usize>()
            .unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let store = FileStore::open(path).unwrap();
            let alloc = SigningStampAllocator::with_clock(
                store,
                scope(),
                b"local-node-secret",
                FixedClock::at(0x01970e589d21),
            );
            for _ in 0..count {
                let stamp = alloc.issue(None).await.unwrap();
                println!("GARTH_STAMP_SEQ={}", stamp.actor_seq);
            }
        });
    }

    #[cfg(all(feature = "native", not(target_arch = "wasm32")))]
    #[test]
    fn separate_processes_allocate_unique_stamps() {
        use std::process::{Command, Stdio};

        use crate::FileStore;

        const WORKERS: usize = 4;
        const PER_WORKER: usize = 16;
        let path =
            std::env::temp_dir().join(format!("garth-stamp-processes-{}.json", std::process::id()));
        cleanup_file_store(&path);
        let executable = std::env::current_exe().unwrap();
        let mut children = Vec::new();
        for _ in 0..WORKERS {
            children.push(
                Command::new(&executable)
                    .arg("stamp::tests::file_store_process_worker")
                    .arg("--exact")
                    .arg("--nocapture")
                    .env("GARTH_STAMP_WORKER_PATH", &path)
                    .env("GARTH_STAMP_WORKER_COUNT", PER_WORKER.to_string())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .unwrap(),
            );
        }

        let mut actor_seqs = BTreeSet::new();
        for child in children {
            let output = child.wait_with_output().unwrap();
            assert!(
                output.status.success(),
                "worker failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            for line in String::from_utf8_lossy(&output.stdout).lines() {
                if let Some(value) = line.strip_prefix("GARTH_STAMP_SEQ=") {
                    assert!(actor_seqs.insert(value.parse::<u64>().unwrap()));
                }
            }
        }
        assert_eq!(actor_seqs.len(), WORKERS * PER_WORKER);
        assert_eq!(actor_seqs.first(), Some(&1));
        assert_eq!(actor_seqs.last(), Some(&64));

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let store = FileStore::open(&path).unwrap();
            assert_eq!(
                store.load_floor(scope()).await.unwrap().unwrap().actor_seq,
                64
            );
        });
        cleanup_file_store(&path);
    }

    #[cfg(all(feature = "native", not(target_arch = "wasm32")))]
    fn cleanup_file_store(path: &Path) {
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(path.with_extension("tmp"));
        let mut lock = path.as_os_str().to_owned();
        lock.push(".lock");
        let _ = std::fs::remove_file(std::path::PathBuf::from(lock));
    }
}
