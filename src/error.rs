use arkret_keystore::KeyStoreError;
use arkret_models_collaboration::sync_frames::account_subscribe::AccountStreamInterrupt;
use arkret_wire::Problem;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

/// Client-runtime error boundary.
///
/// Semantic crates keep their own focused errors. Garth converts those errors
/// once, at the runtime boundary, instead of depending on the retired core
/// facade's catch-all error type.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    #[error("invalid Arkret identifier: {0}")]
    InvalidId(String),
    #[error("conflicting bytes for idempotent object {0}")]
    IdempotencyConflict(String),
    #[error("canonical JSON does not allow floating point or ambiguous numbers")]
    NonCanonicalNumber,
    #[error("canonical JSON integer is outside the JSON safe-integer range")]
    NumberOutOfSafeRange,
    #[error("canonical JSON object contains duplicate key {0:?}")]
    DuplicateObjectKey(String),
    #[error("canonical JSON contains a forbidden string value: {0}")]
    NonCanonicalString(String),
    #[error("canonical JSON serialization failed: {0}")]
    CanonicalJson(#[from] serde_json::Error),
    #[error("cryptographic operation failed: {0}")]
    Crypto(String),
    #[error("invalid service URL: {0}")]
    Url(#[from] url::ParseError),
    #[error("insecure service URL is not allowed by default: {0}")]
    InsecureUrl(String),
    #[error("HTTP request failed: {0}")]
    Http(String),
    #[error("Arkret API returned {status}: {error}")]
    Api { status: u16, error: Box<Problem> },
    #[error("account stream interrupted: {0:?}")]
    AccountStreamInterrupt(AccountStreamInterrupt),
    #[error("key-store error: {0}")]
    KeyStore(#[from] KeyStoreError),
    #[error("protocol error: {0}")]
    Protocol(String),
}

impl Error {
    /// Preserve the server's registry-backed `reason_code` as a typed value.
    ///
    /// Session issuance and refresh use this to distinguish provision
    /// migration, key re-authorization, and session refresh without parsing a
    /// human-readable message or collapsing the RFC 9457 error into an HTTP
    /// status.
    pub fn reason_code(&self) -> Option<arkret_wire::ReasonCode> {
        let Self::Api { error, .. } = self else {
            return None;
        };
        error
            .extensions
            .get("reason_code")
            .and_then(serde_json::Value::as_str)
            .map(arkret_wire::ReasonCode::from_wire)
    }

    pub fn agent_runtime_scope_reason(&self) -> Option<arkret_wire::ReasonCode> {
        match self.reason_code()? {
            reason @ (arkret_wire::ReasonCode::AgentProvisionScopeMigrationRequired
            | arkret_wire::ReasonCode::AgentKeyScopeReauthorizationRequired
            | arkret_wire::ReasonCode::AgentSessionScopeRefreshRequired) => Some(reason),
            _ => None,
        }
    }

    pub fn is_invalid_cursor(&self) -> bool {
        let Self::Api { error, .. } = self else {
            return false;
        };
        const CODES: &[&str] = &[
            "cursor_expired",
            "cursor_integrity_invalid",
            "cursor_unrecognized",
            "cursor_invalid",
            "invalid_cursor",
            "stream_resync_required",
        ];
        let code = error.code();
        if CODES.contains(&code) {
            return true;
        }
        if code != "param_invalid" {
            return false;
        }
        error
            .extensions
            .get("reason_code")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|reason| CODES.contains(&reason))
            || (error.detail.to_ascii_lowercase().contains("cursor")
                && [
                    "invalid",
                    "malformed",
                    "expired",
                    "integrity",
                    "unrecognized",
                ]
                .iter()
                .any(|marker| error.detail.to_ascii_lowercase().contains(marker)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_session_scope_reason_survives_the_http_error_boundary() {
        for expected in [
            arkret_wire::ReasonCode::AgentProvisionScopeMigrationRequired,
            arkret_wire::ReasonCode::AgentKeyScopeReauthorizationRequired,
            arkret_wire::ReasonCode::AgentSessionScopeRefreshRequired,
        ] {
            let mut envelope = Problem::from_code("failed_precondition", "scope is incomplete");
            envelope.extensions.insert(
                "reason_code".to_owned(),
                serde_json::Value::String(expected.as_str().to_owned()),
            );
            let error = Error::from(arkret_http_client::Error::Api {
                status: 412,
                error: Box::new(envelope),
            });
            assert_eq!(error.reason_code(), Some(expected.clone()));
            assert_eq!(error.agent_runtime_scope_reason(), Some(expected));
        }
    }

    #[test]
    fn unrelated_api_reason_is_not_an_agent_scope_diagnosis() {
        let mut envelope = Problem::from_code("failed_precondition", "unrelated");
        envelope.extensions.insert(
            "reason_code".to_owned(),
            serde_json::json!(arkret_wire::ReasonCode::AGENT_PAUSED),
        );
        let error = Error::Api {
            status: 403,
            error: Box::new(envelope),
        };
        assert_eq!(
            error.reason_code(),
            Some(arkret_wire::ReasonCode::AgentPaused)
        );
        assert_eq!(error.agent_runtime_scope_reason(), None);
    }
}

impl From<arkret_identifiers::IdentifierError> for Error {
    fn from(error: arkret_identifiers::IdentifierError) -> Self {
        match error {
            arkret_identifiers::IdentifierError::InvalidId(value) => Self::InvalidId(value),
            arkret_identifiers::IdentifierError::Random(message) => Self::Crypto(message),
            arkret_identifiers::IdentifierError::Protocol(message) => Self::Protocol(message),
        }
    }
}

impl From<arkret_canonical::CanonicalError> for Error {
    fn from(error: arkret_canonical::CanonicalError) -> Self {
        match error {
            arkret_canonical::CanonicalError::NonCanonicalNumber => Self::NonCanonicalNumber,
            arkret_canonical::CanonicalError::NumberOutOfSafeRange => Self::NumberOutOfSafeRange,
            arkret_canonical::CanonicalError::DuplicateObjectKey(key) => {
                Self::DuplicateObjectKey(key)
            }
            arkret_canonical::CanonicalError::NonCanonicalString(message) => {
                Self::NonCanonicalString(message)
            }
            arkret_canonical::CanonicalError::CanonicalJson(error) => Self::CanonicalJson(error),
            arkret_canonical::CanonicalError::Protocol(message) => Self::Protocol(message),
            _ => Self::Protocol(error.to_string()),
        }
    }
}

macro_rules! protocol_error_from {
    ($type:path) => {
        impl From<$type> for Error {
            fn from(error: $type) -> Self {
                Self::Protocol(error.to_string())
            }
        }
    };
}

protocol_error_from!(arkret_wire::WireError);
protocol_error_from!(arkret_hlc::HlcError);
protocol_error_from!(arkret_event_draft::EventDraftError);
protocol_error_from!(arkret_signatures::Error);
protocol_error_from!(arkret_crypto::Error);
protocol_error_from!(arkret_crypto::CryptoError);
protocol_error_from!(arkret_crypto::KeyBackupError);
protocol_error_from!(arkret_identity::IdentityError);
protocol_error_from!(arkret_auth::AuthError);
protocol_error_from!(arkret_schema::SchemaError);
impl From<arkret_models_collaboration::sync_frames::stream_trace::StreamTraceError> for Error {
    fn from(
        error: arkret_models_collaboration::sync_frames::stream_trace::StreamTraceError,
    ) -> Self {
        Self::Protocol(format!("{}: {error}", error.violation()))
    }
}

impl From<arkret_http_client::Error> for Error {
    fn from(error: arkret_http_client::Error) -> Self {
        match error {
            arkret_http_client::Error::Api { status, error } => Self::Api { status, error },
            arkret_http_client::Error::Http(message) => Self::Http(message),
            arkret_http_client::Error::InsecureUrl(message) => Self::InsecureUrl(message),
            arkret_http_client::Error::AccountStreamInterrupt(interrupt) => {
                Self::AccountStreamInterrupt(interrupt)
            }
            arkret_http_client::Error::Protocol(message) => Self::Protocol(message),
            arkret_http_client::Error::Url(source) => Self::Url(source),
            _ => Self::Protocol(error.to_string()),
        }
    }
}
