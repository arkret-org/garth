//! Account-aggregate delivery over independently committed authority streams.

pub use arkret_models_collaboration::sync_frames::account_subscribe::{
    AccountDataContainer, AccountStreamInterrupt, AccountSubscribeBatch,
    AccountSubscribeDeviceListChanges, AccountSubscribeFrame, AccountSubscribeFrameKind,
    AccountSubscribeRealms, AgentDraftPendingIntent, AgentDraftPendingIntentChange,
    AgentDraftPendingIntentContainer, AgentDraftPendingIntentKey, AgentDraftPendingIntentRemoval,
    AgentDraftPendingIntentTerminalRedacted, DeviceMessageContainer, EventContainer,
    NotificationContainer, NotificationDelta, NotificationDeltaAction, RealmListRequest,
    RealmSyncEntry, RealmTimeline, StationCasAccountDataContainer, StationCasAccountDataRemoval,
    StreamTraceError, StreamTraceValidator, SyncFilter, SyncRequestBody,
};
pub use arkret_models_collaboration::sync_frames::demand_sync::{
    AccountBaselineSegment, RealmInvalidation, RealmListChanges, RealmListPage,
};

/// Validate one aggregate frame without treating its cursor as stream finality.
/// Durable finality remains on every timeline item's RealmCommit coordinate.
pub fn validate_account_frame(frame: &AccountSubscribeFrame) -> crate::Result<()> {
    frame.validate()?;
    Ok(())
}
