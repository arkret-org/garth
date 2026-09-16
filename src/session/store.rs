use zeroize::Zeroizing;

use super::SessionGrantState;
use crate::{
    Error, MaybeSend, MaybeSendSync, PutSecretOptions, Result, SecretClass, SecretDurability,
    SecureKeyStore, SecureKeyStoreError,
};

pub trait SessionGrantStore: Clone + MaybeSendSync + 'static {
    fn load(&self) -> Result<Option<SessionGrantState>>;
    fn save<'a>(
        &'a self,
        state: &'a SessionGrantState,
    ) -> impl std::future::Future<Output = Result<()>> + MaybeSend + 'a;
    fn clear(&self) -> Result<()>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct NoopSessionGrantStore;

impl SessionGrantStore for NoopSessionGrantStore {
    fn load(&self) -> Result<Option<SessionGrantState>> {
        Ok(None)
    }

    async fn save(&self, _state: &SessionGrantState) -> Result<()> {
        Ok(())
    }

    fn clear(&self) -> Result<()> {
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct SecureSessionGrantStore<S> {
    secure_store: S,
    storage_key: String,
}

impl<S: SecureKeyStore> SecureSessionGrantStore<S> {
    pub fn new(secure_store: S, storage_key: impl Into<String>) -> Self {
        Self {
            secure_store,
            storage_key: storage_key.into(),
        }
    }
}

impl<S> SessionGrantStore for SecureSessionGrantStore<S>
where
    S: SecureKeyStore + Clone,
{
    fn load(&self) -> Result<Option<SessionGrantState>> {
        self.secure_store
            .get_secret_bytes(&self.storage_key)
            .map_err(Error::from)?
            .map(|encoded| serde_json::from_slice(&encoded).map_err(Error::from))
            .transpose()
    }

    async fn save(&self, state: &SessionGrantState) -> Result<()> {
        let encoded = Zeroizing::new(serde_json::to_vec(state)?);
        self.secure_store
            .put_secret(
                &self.storage_key,
                &encoded,
                PutSecretOptions {
                    durability: SecretDurability::DurableBeforeReturn,
                    class: SecretClass::SessionCredential,
                },
            )
            .await
            .map_err(Error::from)
    }

    fn clear(&self) -> Result<()> {
        match self.secure_store.delete_secret(&self.storage_key) {
            Ok(()) | Err(SecureKeyStoreError::NotFound) => Ok(()),
            Err(error) => Err(Error::from(error)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noop_store_never_invents_a_session() {
        let store = NoopSessionGrantStore;
        assert!(store.load().unwrap().is_none());
        store.clear().unwrap();
        assert!(store.load().unwrap().is_none());
    }

    #[test]
    fn secure_store_clear_is_idempotent_when_absent() {
        let store =
            SecureSessionGrantStore::new(crate::MemorySecureKeyStore::new(), "test/session-grant");
        store.clear().unwrap();
        store.clear().unwrap();
        assert!(store.load().unwrap().is_none());
    }
}
