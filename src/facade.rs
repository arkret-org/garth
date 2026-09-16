use crate::AuthorityClient;

#[derive(Clone, Debug)]
pub struct ArkretClient<T, S> {
    authority: AuthorityClient<T>,
    store: S,
}

impl<T, S> ArkretClient<T, S> {
    pub fn new(transport: T, store: S) -> Self {
        Self {
            authority: AuthorityClient::new(transport),
            store,
        }
    }

    pub fn authority(&self) -> &AuthorityClient<T> {
        &self.authority
    }

    pub fn store(&self) -> &S {
        &self.store
    }
}
