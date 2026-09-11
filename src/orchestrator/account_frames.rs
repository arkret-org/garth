use super::*;
use crate::protocol::AccountSubscribeFrameKind;
use crate::{AccountFrameSource, AccountFrameTransport, SyncResponseProcessor};

impl<E, C, D> ArkretClient<E, C, D>
where
    E: Executor + Clone,
    C: CursorStore,
    D: EventCacheStore,
{
    pub(super) async fn run_account_frame_steps<TP, CMT, H>(
        &self,
        actor_id: DidCoreId,
        device_id: DeviceId,
        provider: &TP,
        handlers: AccountStepHandlers<'_, CMT, H>,
        control: &SyncLoopControl,
        options: RunOptions,
    ) -> RunResult<RunStopReason>
    where
        TP: TransportProvider,
        TP::Transport: AccountFrameTransport,
        CMT: AccountStepCommitter + ?Sized,
        H: AccountPostCommitHook<TP::Transport> + ?Sized,
    {
        let engine = self.subscription_engine().with_control(control.clone());
        let scope = engine.account_scope(actor_id, device_id);
        let mut backoff = RetrySchedule::new(options.min_backoff, options.max_backoff).with_jitter(
            options.jitter_ratio,
            account_backoff_seed(self.backoff_seed, &scope),
        );
        let mut sequence = 0_u64;
        let mut cursor_reset_attempted = false;
        'reconnect: loop {
            let session_generation = provider.account_session_generation();
            if !provider.is_active() {
                return Ok(Self::stop(provider, RunStopReason::LifecycleEnded));
            }
            if control.is_cancelled() {
                return Ok(Self::stop(provider, RunStopReason::Cancelled));
            }
            let durable = engine
                .restore_account_loop(scope.clone())
                .await
                .map_err(|error| Self::fail(provider, RunErrorClass::StoreFailure, error))?;
            let request = provider
                .account_request(durable.token().map(str::to_owned))
                .map_err(|error| Self::fail(provider, RunErrorClass::ProtocolViolation, error))?;
            sequence = sequence.checked_add(1).ok_or_else(|| {
                Self::fail(
                    provider,
                    RunErrorClass::ProtocolViolation,
                    crate::Error::Protocol("account request sequence exhausted".into()),
                )
            })?;
            provider.observe(RunEvent::Connecting);
            let mut opening = std::pin::pin!(async {
                let transport = provider.provide().await?;
                let source = transport
                    .open_account_frames(request.clone(), durable.next_request_options())
                    .await?;
                Ok::<_, crate::Error>((transport, source))
            });
            // A browser fetch may not resolve until the long-poll server emits
            // its first body bytes. Demand can change while that happens (for
            // example when navigation selects a Realm), so the same freshness
            // guard used while reading frames must also cover transport/open.
            // Dropping the stale opening future aborts that request and lets the
            // reconnect build a replacement request with the new filter.
            let opened = loop {
                if !provider.account_request_is_current(&request)
                    || provider.account_session_generation() != session_generation
                {
                    continue 'reconnect;
                }
                if control.is_cancelled() {
                    return Ok(Self::stop(provider, RunStopReason::Cancelled));
                }
                let mut tick = std::pin::pin!(self.executor.sleep(Duration::from_millis(250)));
                let ready = std::future::poll_fn(|cx| {
                    use std::future::Future;
                    if let std::task::Poll::Ready(result) = opening.as_mut().poll(cx) {
                        return std::task::Poll::Ready(Some(result));
                    }
                    tick.as_mut().poll(cx).map(|_| None)
                })
                .await;
                if let Some(result) = ready {
                    break result;
                }
            };
            let (transport, mut source) = match opened {
                Ok(value) => value,
                Err(error)
                    if error.is_invalid_cursor()
                        && request.after.is_some()
                        && !cursor_reset_attempted =>
                {
                    cursor_reset_attempted = true;
                    handlers
                        .committer
                        .reset_account_context(session_generation)
                        .await
                        .map_err(|error| {
                            Self::fail(provider, RunErrorClass::StoreFailure, error)
                        })?;
                    continue;
                }
                Err(error) if classify_error(&error) == RunErrorClass::Unauthorized => {
                    match self
                        .recover_unauthorized(provider, control, &mut backoff)
                        .await?
                    {
                        UnauthorizedRecovery::Recovered | UnauthorizedRecovery::Retry => continue,
                        UnauthorizedRecovery::GuardedStop(reason) => return Ok(reason),
                        UnauthorizedRecovery::Unavailable => {
                            return Ok(Self::stop(
                                provider,
                                RunStopReason::Unauthorized { reason: None },
                            ));
                        }
                    }
                }
                Err(error) if retryable(classify_error(&error)) => {
                    let delay = backoff.next_delay();
                    if let Some(reason) = self.wait_guarded(delay, control, provider).await {
                        return Ok(Self::stop(provider, reason));
                    }
                    continue;
                }
                Err(error) => return Err(Self::fail(provider, classify_error(&error), error)),
            };
            provider.observe(RunEvent::Online);
            loop {
                // Keep one read future alive while observing only small host
                // lifecycle/demand coordinates. Never cancel and restart a
                // partially consumed NDJSON read merely for a timer tick.
                let mut next = source.next_frame();
                let result = loop {
                    if !provider.account_request_is_current(&request)
                        || provider.account_session_generation() != session_generation
                    {
                        continue 'reconnect;
                    }
                    if control.is_cancelled() {
                        return Ok(Self::stop(provider, RunStopReason::Cancelled));
                    }
                    let mut tick = std::pin::pin!(self.executor.sleep(Duration::from_millis(250)));
                    let ready = std::future::poll_fn(|cx| {
                        use std::future::Future;
                        if let std::task::Poll::Ready(result) = next.as_mut().poll(cx) {
                            return std::task::Poll::Ready(Some(result));
                        }
                        tick.as_mut().poll(cx).map(|_| None)
                    })
                    .await;
                    if let Some(result) = ready {
                        break result;
                    }
                };
                drop(next);
                let frame = match result {
                    Ok(Some(frame)) => frame,
                    Ok(None) => break,
                    Err(error)
                        if error.is_invalid_cursor()
                            && request.after.is_some()
                            && !cursor_reset_attempted =>
                    {
                        cursor_reset_attempted = true;
                        handlers
                            .committer
                            .reset_account_context(session_generation)
                            .await
                            .map_err(|error| {
                                Self::fail(provider, RunErrorClass::StoreFailure, error)
                            })?;
                        continue 'reconnect;
                    }
                    Err(error) if retryable(classify_error(&error)) => {
                        let delay = backoff.next_delay();
                        if let Some(reason) = self.wait_guarded(delay, control, provider).await {
                            return Ok(Self::stop(provider, reason));
                        }
                        continue 'reconnect;
                    }
                    Err(error) => return Err(Self::fail(provider, classify_error(&error), error)),
                };
                if !provider.account_request_is_current(&request)
                    || provider.account_session_generation() != session_generation
                {
                    continue 'reconnect;
                }
                match frame.kind {
                    AccountSubscribeFrameKind::Heartbeat => continue,
                    AccountSubscribeFrameKind::Unauthorized => {
                        match self
                            .recover_unauthorized(provider, control, &mut backoff)
                            .await?
                        {
                            UnauthorizedRecovery::Recovered | UnauthorizedRecovery::Retry => {
                                continue 'reconnect;
                            }
                            UnauthorizedRecovery::GuardedStop(reason) => return Ok(reason),
                            UnauthorizedRecovery::Unavailable => {
                                return Ok(Self::stop(
                                    provider,
                                    RunStopReason::Unauthorized { reason: None },
                                ));
                            }
                        }
                    }
                    AccountSubscribeFrameKind::Delta
                    | AccountSubscribeFrameKind::Frontier
                    | AccountSubscribeFrameKind::CatchupComplete
                    | AccountSubscribeFrameKind::Dropped
                    | AccountSubscribeFrameKind::ResyncRequired => {}
                    _ => {
                        return Err(Self::fail(
                            provider,
                            RunErrorClass::ProtocolViolation,
                            crate::Error::Protocol("unsupported account frame kind".into()),
                        ));
                    }
                }
                let updates =
                    SyncResponseProcessor::process_frame(frame.clone()).map_err(|error| {
                        Self::fail(provider, RunErrorClass::ProtocolViolation, error)
                    })?;
                let mut step = AccountStreamStep {
                    session_generation,
                    request_sequence: sequence,
                    request: request.clone(),
                    cursor: frame.cursor.clone(),
                    updates,
                    frame,
                };
                let outcome =
                    handlers.committer.commit(&step).await.map_err(|error| {
                        Self::fail(provider, RunErrorClass::StoreFailure, error)
                    })?;
                match outcome {
                    AccountCommitOutcome::Replay => continue 'reconnect,
                    AccountCommitOutcome::Committed { updates } => step.updates = updates,
                }
                if let Some(cursor) = &step.cursor {
                    source.committed(cursor).map_err(|error| {
                        Self::fail(provider, RunErrorClass::ProtocolViolation, error)
                    })?;
                }
                backoff.reset();
                cursor_reset_attempted = false;
                if step.frame.requires_resubscribe() {
                    let delay = Duration::from_millis(step.frame.reconnect_after_ms.unwrap_or(0));
                    if let Some(reason) = self.wait_guarded(delay, control, provider).await {
                        return Ok(Self::stop(provider, reason));
                    }
                    continue 'reconnect;
                }
                match handlers
                    .post_commit
                    .post_commit(&transport, &step)
                    .await
                    .map_err(|error| Self::fail(provider, RunErrorClass::ProjectorFailure, error))?
                {
                    AccountPostCommitOutcome::Continue => {}
                    AccountPostCommitOutcome::Retry => break,
                    AccountPostCommitOutcome::Unauthorized { reason } => {
                        return Ok(Self::stop(provider, RunStopReason::Unauthorized { reason }));
                    }
                }
            }
            if let Some(reason) = self.wait_guarded(options.beat, control, provider).await {
                return Ok(Self::stop(provider, reason));
            }
        }
    }
}
