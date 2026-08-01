//! The one shared cell the pump loop and the channel adapters both hold.
//!
//! Native stream seams are `Send` (`RealmEventsFrameSource`,
//! `SignalStreamFrameSource`), so the shared handle has to be `Send` there;
//! a browser build is single-threaded and its seams drop the bound. This is
//! the same `#[cfg]` split [`crate::maybe_send`] applies to trait bounds,
//! applied to the container instead.
//!
//! The lock is only ever taken around a synchronous queue read or a frame
//! push — never across an await — so a blocking mutex is the right primitive
//! and cannot deadlock the pump.

#[cfg(not(target_arch = "wasm32"))]
mod imp {
    use std::sync::{Arc, Mutex};

    /// `Arc<Mutex<T>>` on native.
    #[derive(Debug)]
    pub struct SharedCell<T>(Arc<Mutex<T>>);

    impl<T> SharedCell<T> {
        pub fn new(value: T) -> Self {
            Self(Arc::new(Mutex::new(value)))
        }

        /// Run `f` under the lock. A poisoned lock is recovered rather than
        /// propagated: the connection is being torn down either way, and a
        /// panic here would take the pump loop with it.
        pub fn with_mut<R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
            let mut guard = self.0.lock().unwrap_or_else(|error| error.into_inner());
            f(&mut guard)
        }
    }

    impl<T> Clone for SharedCell<T> {
        fn clone(&self) -> Self {
            Self(self.0.clone())
        }
    }
}

#[cfg(target_arch = "wasm32")]
mod imp {
    use std::cell::RefCell;
    use std::rc::Rc;

    /// `Rc<RefCell<T>>` on `wasm32`.
    #[derive(Debug)]
    pub struct SharedCell<T>(Rc<RefCell<T>>);

    impl<T> SharedCell<T> {
        pub fn new(value: T) -> Self {
            Self(Rc::new(RefCell::new(value)))
        }

        pub fn with_mut<R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
            f(&mut self.0.borrow_mut())
        }
    }

    impl<T> Clone for SharedCell<T> {
        fn clone(&self) -> Self {
            Self(self.0.clone())
        }
    }
}

pub use imp::SharedCell;
