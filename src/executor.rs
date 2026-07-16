use std::future::Future;
use std::time::Duration;

use chrono::{DateTime, Utc};

/// Runtime-neutral task and timer abstraction used by client engines.
pub trait Executor: Clone + 'static {
    fn sleep(&self, dur: Duration) -> impl Future<Output = ()> + '_;
}

pub(crate) async fn wait_cancellable<E: Executor>(
    executor: &E,
    duration: Duration,
    mut is_cancelled: impl FnMut() -> bool,
) -> bool {
    const QUANTUM: Duration = Duration::from_millis(50);
    let mut remaining = duration;
    while !remaining.is_zero() {
        if is_cancelled() {
            return true;
        }
        let step = remaining.min(QUANTUM);
        executor.sleep(step).await;
        remaining = remaining.saturating_sub(step);
    }
    is_cancelled()
}

/// Host wall clock used for protocol expiry decisions.
pub trait HostClock: Clone + 'static {
    fn now(&self) -> DateTime<Utc>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl HostClock for SystemClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

#[cfg(feature = "native")]
#[derive(Clone, Copy, Debug, Default)]
pub struct NativeExecutor;

#[cfg(feature = "native")]
impl Executor for NativeExecutor {
    fn sleep(&self, dur: Duration) -> impl Future<Output = ()> + '_ {
        tokio::time::sleep(dur)
    }
}

#[cfg(all(feature = "wasm", target_arch = "wasm32"))]
#[derive(Clone, Copy, Debug, Default)]
pub struct WasmExecutor;

#[cfg(all(feature = "wasm", target_arch = "wasm32"))]
impl Executor for WasmExecutor {
    fn sleep(&self, dur: Duration) -> impl Future<Output = ()> + '_ {
        gloo_timers::future::sleep(dur)
    }
}
