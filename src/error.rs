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
    /// Keep the durable Account cut and refetch the affected stream's
    /// authenticated snapshot and tail; never reset the Account baseline.
    #[error("stream {stream_ref:?} skipped readable position {expected}; received {actual}")]
    StreamPositionGap {
        stream_ref: arkret_wire::CommitStreamRef,
        expected: u64,
        actual: u64,
    },
    /// The declared window extends beyond the verified readable tail.
    #[error("stream {stream_ref:?} has an incomplete readable tail")]
    StreamTailIncomplete {
        stream_ref: arkret_wire::CommitStreamRef,
    },
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("storage error: {0}")]
    Storage(String),
}

impl Error {
    pub fn is_stream_interruption(&self) -> bool {
        matches!(
            self,
            Self::StreamPositionGap { .. } | Self::StreamTailIncomplete { .. }
        )
    }

    pub fn is_invalid_cursor(&self) -> bool {
        let Self::Api { error, .. } = self else {
            return false;
        };
        const CODES: &[&str] = &[
            "cursor_expired",
            "cursor_integrity_invalid",
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
            // The closed WebSocket error carrier preserves code/message,
            // but has no HTTP reason_code extension. A param_invalid message
            // identifying the cursor is still a cursor parameter refusal.
            || error.detail.to_ascii_lowercase().contains("cursor")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_cursor_constraint_messages_keep_their_reset_semantics() {
        for (message, expected) in [
            ("cursor must use the canonical SDK wire profile", true),
            ("invalid committed stream cursor", true),
            ("realm_ids must not be empty", false),
        ] {
            let failure = Error::Api {
                status: 400,
                error: Box::new(Problem::new("param_invalid", 400, message)),
            };
            assert_eq!(failure.is_invalid_cursor(), expected);
        }
        let revoked = Error::Api {
            status: 403,
            error: Box::new(Problem::new(
                "cursor_revoked",
                403,
                "cursor authority has been revoked",
            )),
        };
        assert!(!revoked.is_invalid_cursor());
        let unverifiable_issuer = Error::Api {
            status: 400,
            error: Box::new(Problem::new("cursor_unrecognized", 400, "unknown code")),
        };
        assert!(!unverifiable_issuer.is_invalid_cursor());
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
            arkret_http_client::Error::Wire(arkret_wire::WireError::StreamPositionGap {
                stream_ref,
                expected,
                actual,
            }) => Self::StreamPositionGap {
                stream_ref,
                expected,
                actual,
            },
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
