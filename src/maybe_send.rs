//! `#[cfg]`-gated `Send`/`Sync` markers for the wasm dual-target.
//!
//! garth's boxed futures already drop `Send` on `wasm32` (see
//! [`BoxSessionFuture`](crate::session::SessionGrantTransport),
//! [`BoxRealmStreamFuture`](crate::subscribe::BoxRealmStreamFuture) and
//! [`BoxScanFuture`](crate::subscribe::EventsScanTransport)). Host-facing traits
//! need the same treatment so a browser client can implement them with `!Send`
//! values (Dioxus `!Send` signals, JS-interop futures) instead of the trait
//! forcing a `Send + Sync` bound that is only meaningful on native.
//!
//! On native, [`MaybeSend`] / [`MaybeSendSync`] are blanket-implemented for
//! every `Send` / `Send + Sync` type, so generic code that moves a value across
//! threads (e.g. spawning a future onto a multi-threaded runtime) still gets the
//! real bounds transitively through the supertrait. On `wasm32`, both markers
//! are satisfied by every type, which drops the constraint entirely.
//!
//! Using these markers as supertrait bounds keeps the `#[cfg]` toggle in a
//! single place instead of duplicating `#[cfg(target_arch = "wasm32")]` blocks
//! across every host-facing trait. Boxed `dyn Future` type aliases still need a
//! literal `#[cfg]` pair because a non-auto trait cannot be added to a trait
//! object.

/// `Send` on native, no constraint on `wasm32`.
#[cfg(not(target_arch = "wasm32"))]
pub trait MaybeSend: Send {}
#[cfg(not(target_arch = "wasm32"))]
impl<T: Send + ?Sized> MaybeSend for T {}

/// `Send` on native, no constraint on `wasm32`.
#[cfg(target_arch = "wasm32")]
pub trait MaybeSend {}
#[cfg(target_arch = "wasm32")]
impl<T: ?Sized> MaybeSend for T {}

/// `Send + Sync` on native, no constraint on `wasm32`.
#[cfg(not(target_arch = "wasm32"))]
pub trait MaybeSendSync: Send + Sync {}
#[cfg(not(target_arch = "wasm32"))]
impl<T: Send + Sync + ?Sized> MaybeSendSync for T {}

/// `Send + Sync` on native, no constraint on `wasm32`.
#[cfg(target_arch = "wasm32")]
pub trait MaybeSendSync {}
#[cfg(target_arch = "wasm32")]
impl<T: ?Sized> MaybeSendSync for T {}
