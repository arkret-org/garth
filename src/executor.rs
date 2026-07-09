use std::future::Future;
use std::time::Duration;

/// Runtime-neutral task and timer abstraction used by client engines.
pub trait Executor: Clone + 'static {
    fn sleep(&self, dur: Duration) -> impl Future<Output = ()> + '_;
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
