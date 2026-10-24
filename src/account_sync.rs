//! Account-aggregate delivery over independently committed authority streams.

pub use arkret_models_collaboration::sync_frames::account_subscribe::{
    AccountDataContainer, AccountFilter, AccountStreamInterrupt, AccountSubscribeBatch,
    AccountSubscribeDeviceListChanges, AccountSubscribeFrame, AccountSubscribeFrameKind,
    AccountSubscribeParameters, AccountSubscribeRealms, AgentDraftPendingIntent,
    AgentDraftPendingIntentChange, AgentDraftPendingIntentContainer, AgentDraftPendingIntentKey,
    AgentDraftPendingIntentRemoval, AgentDraftPendingIntentTerminalRedacted, EventContainer,
    NotificationContainer, NotificationDelta, NotificationDeltaAction, RealmListParameters,
    RealmSyncEntry, RecipientDeliveryContainer, StationCasAccountDataContainer,
    StationCasAccountDataRemoval, StreamTraceError, StreamTraceValidator,
};
pub use arkret_models_collaboration::sync_frames::account_sync::RealmStreamWindow;
pub use arkret_models_collaboration::sync_frames::demand_sync::{
    AccountBaselineSegment, RealmInvalidation, RealmListChanges, RealmListPage,
};

/// Validate one aggregate frame without treating its cursor as stream finality.
/// Durable finality remains on every committed Event view's RealmCommit coordinate.
pub fn validate_account_frame(frame: &AccountSubscribeFrame) -> crate::Result<()> {
    frame.validate()?;
    Ok(())
}
