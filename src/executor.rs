use std::future::Future;
use std::time::Duration;

/// Runtime-neutral task and timer abstraction used by client engines.
///
/// Native builds require spawned futures to be `Send` so the default
/// implementation can use `tokio::spawn`. Wasm builds use `spawn_local`,
/// because browser futures are frequently single-threaded.
pub trait Executor: Clone + 'static {
    type JoinHandle;

    #[cfg(not(target_arch = "wasm32"))]
    fn spawn<F>(&self, fut: F) -> Self::JoinHandle
    where
        F: Future<Output = ()> + Send + 'static;

    #[cfg(target_arch = "wasm32")]
    fn spawn<F>(&self, fut: F) -> Self::JoinHandle
    where
        F: Future<Output = ()> + 'static;

    fn sleep(&self, dur: Duration) -> impl Future<Output = ()> + '_;
}

#[cfg(feature = "native")]
#[derive(Clone, Copy, Debug, Default)]
pub struct NativeExecutor;

#[cfg(feature = "native")]
impl Executor for NativeExecutor {
    type JoinHandle = tokio::task::JoinHandle<()>;

    #[cfg(not(target_arch = "wasm32"))]
    fn spawn<F>(&self, fut: F) -> Self::JoinHandle
    where
        F: Future<Output = ()> + Send + 'static,
    {
        tokio::spawn(fut)
    }

    #[cfg(target_arch = "wasm32")]
    fn spawn<F>(&self, fut: F) -> Self::JoinHandle
    where
        F: Future<Output = ()> + 'static,
    {
        tokio::task::spawn_local(fut)
    }

    fn sleep(&self, dur: Duration) -> impl Future<Output = ()> + '_ {
        tokio::time::sleep(dur)
    }
}

#[cfg(all(feature = "wasm", target_arch = "wasm32"))]
#[derive(Clone, Copy, Debug, Default)]
pub struct WasmExecutor;

#[cfg(all(feature = "wasm", target_arch = "wasm32"))]
impl Executor for WasmExecutor {
    type JoinHandle = ();

    fn spawn<F>(&self, fut: F) -> Self::JoinHandle
    where
        F: Future<Output = ()> + 'static,
    {
        wasm_bindgen_futures::spawn_local(fut);
    }

    fn sleep(&self, dur: Duration) -> impl Future<Output = ()> + '_ {
        gloo_timers::future::sleep(dur)
    }
}
