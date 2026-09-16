use std::future::Future;

use chrono::{DateTime, Utc};

use super::{
    SessionEngine, SessionGrantState, SessionGrantStore, SessionGrantTransport,
    SessionRefreshOptions,
};
use crate::{Error, MaybeSend, MaybeSendSync, Result};

pub trait AuthenticatedTransportFactory: MaybeSendSync {
    type Transport;

    fn build<'a>(
        &'a self,
        grant: &'a SessionGrantState,
    ) -> impl Future<Output = Result<Self::Transport>> + MaybeSend + 'a;
}

#[derive(Clone, Debug)]
pub struct SessionTransportProvider<T, S, F> {
    engine: SessionEngine<T, S>,
    factory: F,
}

impl<T, S, F> SessionTransportProvider<T, S, F>
where
    T: SessionGrantTransport,
    S: SessionGrantStore,
    F: AuthenticatedTransportFactory,
{
    pub fn new(engine: SessionEngine<T, S>, factory: F) -> Self {
        Self { engine, factory }
    }

    pub fn engine(&self) -> &SessionEngine<T, S> {
        &self.engine
    }

    pub async fn provide(
        &self,
        refresh: SessionRefreshOptions,
        now: DateTime<Utc>,
    ) -> Result<F::Transport> {
        self.engine.refresh_if_due(refresh, now).await?;
        let grant = self.engine.current().ok_or_else(|| {
            Error::Protocol("authenticated transport requires an active session grant".to_owned())
        })?;
        self.factory.build(&grant).await
    }
}
