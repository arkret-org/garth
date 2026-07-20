use arkret_keystore::KeyStoreError;
use arkret_models_collaboration::sync_frames::account_subscribe::AccountStreamInterrupt;
use arkret_wire::ErrorEnvelope;
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
    #[cfg(feature = "mls")]
    #[error("MLS operation failed: {0}")]
    Mls(String),
    #[error("Arkret API returned {status}: {error}")]
    Api {
        status: u16,
        error: Box<ErrorEnvelope>,
    },
    #[error("account stream interrupted: {0:?}")]
    AccountStreamInterrupt(AccountStreamInterrupt),
    #[error("key-store error: {0}")]
    KeyStore(#[from] KeyStoreError),
    #[error("protocol error: {0}")]
    Protocol(String),
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
        ];
        let code = error.error.code.as_str();
        if CODES.contains(&code) {
            return true;
        }
        if code != "invalid_param" {
            return false;
        }
        error
            .error
            .details
            .get("reason_code")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|reason| CODES.contains(&reason))
            || (error.error.message.to_ascii_lowercase().contains("cursor")
                && [
                    "invalid",
                    "malformed",
                    "expired",
                    "integrity",
                    "unrecognized",
                ]
                .iter()
                .any(|marker| error.error.message.to_ascii_lowercase().contains(marker)))
    }

    pub fn as_key_store_error(&self) -> Option<&KeyStoreError> {
        match self {
            Self::KeyStore(error) => Some(error),
            _ => None,
        }
    }

    pub fn is_key_store_not_found(&self) -> bool {
        matches!(
            self.as_key_store_error(),
            Some(KeyStoreError::NotFound { .. })
        )
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

#[cfg(feature = "mls")]
protocol_error_from!(arkret_mls::MlsError);

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
