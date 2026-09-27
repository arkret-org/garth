use arkret_models_collaboration::sync_frames::account_subscribe::AccountStreamInterrupt;
use arkret_wire::Problem;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

/// Client-runtime error boundary.
///
/// Semantic crates keep their own focused errors. Garth converts transport and
/// wire errors once at the runtime boundary.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    #[error("canonical JSON serialization failed: {0}")]
    CanonicalJson(#[from] serde_json::Error),
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
    /// An exact Realm Snapshot by-ref read was refused on a registered
    /// surface. The window naming that reference fails closed.
    #[error("exact Realm snapshot read refused: {0:?}")]
    ExactSnapshotRefused(crate::exact_snapshot::ExactSnapshotRefusal),
    /// A later scan observed a Realm head beyond the previously fetched
    /// authority cut. Nothing was installed; restart with fresh authority.
    #[error("Realm scan requires a newer verified authority cut")]
    AuthorityCutBehind,
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("storage error: {0}")]
    Storage(String),
}

impl Error {
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
protocol_error_from!(arkret_canonical::CanonicalError);
protocol_error_from!(arkret_auth::AuthError);
protocol_error_from!(arkret_identifiers::IdentifierError);
impl From<arkret_models_collaboration::sync_frames::account_subscribe::StreamTraceError> for Error {
    fn from(
        error: arkret_models_collaboration::sync_frames::account_subscribe::StreamTraceError,
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
