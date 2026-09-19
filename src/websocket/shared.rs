//! Small native/wasm shared cell used by the single-owner WebSocket pump.

#[cfg(not(target_arch = "wasm32"))]
mod imp {
    use std::sync::{Arc, Mutex};

    #[derive(Debug)]
    pub struct SharedCell<T>(Arc<Mutex<T>>);

    impl<T> SharedCell<T> {
        pub fn new(value: T) -> Self {
            Self(Arc::new(Mutex::new(value)))
        }

        pub fn with_mut<R>(&self, operation: impl FnOnce(&mut T) -> R) -> R {
            let mut guard = self.0.lock().unwrap_or_else(|error| error.into_inner());
            operation(&mut guard)
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

    #[derive(Debug)]
    pub struct SharedCell<T>(Rc<RefCell<T>>);

    impl<T> SharedCell<T> {
        pub fn new(value: T) -> Self {
            Self(Rc::new(RefCell::new(value)))
        }

        pub fn with_mut<R>(&self, operation: impl FnOnce(&mut T) -> R) -> R {
            operation(&mut self.0.borrow_mut())
        }
    }

    impl<T> Clone for SharedCell<T> {
        fn clone(&self) -> Self {
            Self(self.0.clone())
        }
    }
}

pub use imp::SharedCell;
