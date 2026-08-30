use crate::protocol::{Error, Result};
use zeroize::Zeroizing;

use super::SessionGrantState;
use crate::{PutSecretOptions, SecretClass, SecretDurability};
use crate::{SecureKeyStore, SecureKeyStoreError};

pub trait SessionGrantStore: Clone + crate::MaybeSendSync + 'static {
    fn load(&self) -> Result<Option<SessionGrantState>>;

    fn save<'a>(
        &'a self,
        state: &'a SessionGrantState,
    ) -> impl std::future::Future<Output = Result<()>> + crate::MaybeSend + 'a;

    fn clear(&self) -> Result<()>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct NoopSessionGrantStore;

impl SessionGrantStore for NoopSessionGrantStore {
    fn load(&self) -> Result<Option<SessionGrantState>> {
        Ok(None)
    }

    fn save<'a>(
        &'a self,
        _state: &'a SessionGrantState,
    ) -> impl std::future::Future<Output = Result<()>> + crate::MaybeSend + 'a {
        async { Ok(()) }
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

impl<S> SecureSessionGrantStore<S>
where
    S: SecureKeyStore,
{
    pub fn new(secure_store: S, storage_key: impl Into<String>) -> Self {
        Self {
            secure_store,
            storage_key: storage_key.into(),
        }
    }

    pub fn storage_key(&self) -> &str {
        &self.storage_key
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
            .map(|encoded| {
                serde_json::from_slice(&encoded).map_err(|error| {
                    Error::Protocol(format!("decode secure session grant: {error}"))
                })
            })
            .transpose()
    }

    fn save<'a>(
        &'a self,
        state: &'a SessionGrantState,
    ) -> impl std::future::Future<Output = Result<()>> + crate::MaybeSend + 'a {
        let encoded = serde_json::to_vec(state)
            .map(Zeroizing::new)
            .map_err(|error| Error::Protocol(format!("encode secure session grant: {error}")));
        async move {
            let encoded = encoded?;
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
    use chrono::{Duration, Utc};

    use super::*;
    use crate::protocol::{AccountId, DeviceId, DidCoreId, SessionGrantId};
    use crate::{MemorySecureKeyStore, SecureKeyStore};

    fn state() -> SessionGrantState {
        SessionGrantState {
            account_id: AccountId::new(
                DidCoreId::new("ak:did_core:webvh:z6mkfixture:alice.example").unwrap(),
                DidCoreId::new("ak:did_core:webvh:z6mkfixture:service.example").unwrap(),
            ),
            device_id: Some(
                DeviceId::new("ak:device:01904100-0000-7000-8000-000000000001").unwrap(),
            ),
            grant_id: SessionGrantId::from_issuance_digest([1_u8; 32]),
            grant_jwt: "secret-grant".to_owned(),
            expires_at: Utc::now() + Duration::hours(1),
            audience_id: DidCoreId::new("ak:did_core:webvh:z6mkfixture:service.example").unwrap(),
            granted_scope: vec!["ak.self.events.stream.subscribe.v1".to_owned()],
            session_public_key: Some("session-public-key".to_owned()),
            dpop_jkt: Some("jkt-1".to_owned()),
        }
    }

    #[tokio::test]
    async fn secure_store_round_trips_and_clears_grant_without_plain_state() {
        let secure = MemorySecureKeyStore::new();
        let store = SecureSessionGrantStore::new(secure.clone(), "session/account-1");
        let expected = state();

        store.save(&expected).await.unwrap();
        assert_eq!(store.load().unwrap(), Some(expected));
        assert!(secure.get_secret("session/account-1").unwrap().is_some());

        store.clear().unwrap();
        assert_eq!(store.load().unwrap(), None);
    }
}
