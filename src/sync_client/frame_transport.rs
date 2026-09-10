use super::*;

/// One validated frame at a time. A source must not read ahead while its host
/// is committing the preceding frame.
pub trait AccountFrameSource {
    fn next_frame(&mut self) -> BoxSyncFuture<'_, Option<AccountSubscribeFrame>>;

    /// Called only after the host atomically commits this exact frame cursor.
    fn committed(&mut self, _cursor: &str) -> Result<()> {
        Ok(())
    }
}

pub trait AccountFrameTransport: crate::maybe_send::MaybeSendSync {
    type Source: AccountFrameSource;

    fn open_account_frames(
        &self,
        request: SyncRequestBody,
        options: arkret_http_client::ClientRequestOptions,
    ) -> BoxSyncFuture<'_, Self::Source>;
}

impl AccountFrameSource for arkret_http_client::AccountSubscribeFrameStream {
    fn next_frame(&mut self) -> BoxSyncFuture<'_, Option<AccountSubscribeFrame>> {
        Box::pin(async move {
            arkret_http_client::AccountSubscribeFrameStream::next_frame(self)
                .await
                .map_err(Error::from)
        })
    }
}

impl AccountFrameTransport for arkret_http_client::Client {
    type Source = arkret_http_client::AccountSubscribeFrameStream;

    fn open_account_frames(
        &self,
        request: SyncRequestBody,
        options: arkret_http_client::ClientRequestOptions,
    ) -> BoxSyncFuture<'_, Self::Source> {
        Box::pin(async move {
            self.account_subscribe_frames_with_options(&request, &options)
                .await
                .map_err(Error::from)
        })
    }
}
