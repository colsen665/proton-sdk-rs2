use std::time::Duration;
use thiserror::Error;

/// HTTP failure returned by a blob transfer endpoint.
///
/// Keeping the status code typed lets callers distinguish a transient service
/// failure from a permanent client error without parsing an error string.
#[derive(Debug, Error)]
#[error("blob transfer failed with HTTP status {status}: {message}")]
pub struct HttpTransferError {
    pub status: u16,
    pub message: String,
    pub retry_after: Option<Duration>,
}

impl HttpTransferError {
    pub fn new(
        status: reqwest::StatusCode,
        message: impl Into<String>,
        retry_after: Option<Duration>,
    ) -> Self {
        Self {
            status: status.as_u16(),
            message: message.into(),
            retry_after,
        }
    }

    pub fn status_code(&self) -> Option<reqwest::StatusCode> {
        reqwest::StatusCode::from_u16(self.status).ok()
    }

    /// Returns whether retrying this transfer is useful.
    pub fn is_retryable(&self) -> bool {
        matches!(self.status, 408 | 425 | 429) || self.status >= 500
    }

    pub fn is_expired_target(&self) -> bool {
        self.status == reqwest::StatusCode::NOT_FOUND.as_u16()
    }
}

#[derive(Debug, Error, Clone, serde::Serialize, serde::Deserialize)]
pub enum ProtonDriveError {
    #[error("API error: {0}")]
    ApiError(String),
    #[error("Internal error: {0}")]
    InternalError(String),
    #[error("Cryptography error: {0}")]
    CryptoError(String),
    #[error("Not found")]
    NotFound,
    #[error("Unauthorized")]
    Unauthorized,
    #[error("{0}")]
    Validation(String),
    #[error("{0}")]
    Abort(String),
    #[error("{0}")]
    Connection(String),
    #[error("{0}")]
    RateLimited(String),
    #[error("{0}")]
    Server(String),
    #[error("{0}")]
    Unimplemented(String),
}

impl ProtonDriveError {
    pub fn abort() -> Self {
        Self::Abort("Operation aborted".into())
    }

    pub fn is_abort(&self) -> bool {
        matches!(self, Self::Abort(_))
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Abort(_) => "AbortError",
            Self::Validation(_) => "ValidationError",
            Self::RateLimited(_) => "RateLimitedError",
            Self::Connection(_) => "ConnectionError",
            Self::Server(_) => "ServerError",
            Self::NotFound => "NotFound",
            Self::Unauthorized => "Unauthorized",
            Self::ApiError(_) => "ApiError",
            Self::InternalError(_) => "InternalError",
            Self::CryptoError(_) => "CryptoError",
            Self::Unimplemented(_) => "UnimplementedError",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationStatus {
    NotSigned,
    SignedAndInvalid,
    SignedAndValid,
}

pub fn get_verification_message(
    verified: VerificationStatus,
    verification_errors: Option<&[String]>,
    signature_type: Option<&str>,
    not_available_verification_keys: bool,
) -> String {
    if verified == VerificationStatus::NotSigned {
        return match signature_type {
            Some(kind) => format!("Missing signature for {kind}"),
            None => "Missing signature".into(),
        };
    }
    if not_available_verification_keys {
        return match signature_type {
            Some(kind) => format!("Verification keys for {kind} are not available"),
            None => "Verification keys are not available".into(),
        };
    }
    if let Some(errors) = verification_errors {
        let joined = errors.join(", ");
        return match signature_type {
            Some(kind) => format!("Signature verification for {kind} failed: {joined}"),
            None => format!("Signature verification failed: {joined}"),
        };
    }
    match signature_type {
        Some(kind) => format!("Signature verification for {kind} failed"),
        None => "Signature verification failed".into(),
    }
}

pub fn is_not_application_error(error: Option<&ProtonDriveError>) -> bool {
    matches!(
        error,
        Some(
            ProtonDriveError::Abort(_)
                | ProtonDriveError::Validation(_)
                | ProtonDriveError::RateLimited(_)
                | ProtonDriveError::Connection(_)
        )
    )
}

pub fn is_not_application_error_name(name: &str) -> bool {
    matches!(name, "AbortError" | "OfflineError" | "TimeoutError")
}

#[derive(Debug, Error)]
#[error("{message}")]
pub struct IntegrityException {
    pub message: String,
}

impl IntegrityException {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

#[derive(Debug, Error)]
#[error("content size mismatch: uploaded {uploaded} bytes, expected {expected} bytes")]
pub struct ContentSizeMismatchIntegrityException {
    pub uploaded: i64,
    pub expected: i64,
}

#[derive(Debug, Error)]
#[error("checksum mismatch")]
pub struct ChecksumMismatchIntegrityException {
    pub actual: Vec<u8>,
    pub expected: Vec<u8>,
}

#[derive(Debug, Error)]
#[error("too many requests")]
pub struct TooManyRequestsException {
    pub retry_after: Option<Duration>,
}

impl TooManyRequestsException {
    pub fn from_headers(headers: &reqwest::header::HeaderMap) -> Self {
        Self {
            retry_after: parse_retry_after(headers),
        }
    }
}

pub fn parse_retry_after(headers: &reqwest::header::HeaderMap) -> Option<Duration> {
    let value = headers.get(reqwest::header::RETRY_AFTER)?.to_str().ok()?;
    value.parse::<u64>().ok().map(Duration::from_secs)
}

/// Failure reported by a Drive API endpoint.
///
/// The HTTP status and the Proton response code are kept typed so callers can
/// classify a failure (not found, already exists, quota, retryable…) without
/// parsing the message text. The `Display` output keeps the historical
/// `"API error {code}: {message}"` / `"HTTP {status}: {body}"` wording.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ApiError {
    /// HTTP status of the response, when the failure came from a non-2xx
    /// response. `None` when the response was 2xx with an error `Code`.
    pub http_status: Option<u16>,
    /// Proton response code (`Code` in the JSON body), when present.
    pub code: Option<u32>,
    /// Proton error message (`Error` in the JSON body), or a body excerpt.
    pub message: String,
    /// Delay requested by a `Retry-After` header.
    pub retry_after: Option<Duration>,
    /// Endpoint-specific `Details` object of the error body, when present
    /// (e.g. the conflicting link and revision of a draft conflict).
    pub details: Option<serde_json::Value>,
}

impl ApiError {
    pub const CODE_NOT_ENOUGH_PERMISSIONS: u32 = 2011;
    pub const CODE_ALREADY_EXISTS: u32 = 2500;
    pub const CODE_NOT_EXISTS: u32 = 2501;
    pub const CODE_INSUFFICIENT_QUOTA: u32 = 200001;
    pub const CODE_INSUFFICIENT_SPACE: u32 = 200002;
    pub const CODE_MAX_FILE_SIZE_FOR_FREE_USER: u32 = 200003;
    pub const CODE_INSUFFICIENT_VOLUME_QUOTA: u32 = 200100;
    pub const CODE_INSUFFICIENT_DEVICE_QUOTA: u32 = 200101;
    pub const CODE_TOO_MANY_CHILDREN: u32 = 200300;
    pub const CODE_NESTING_TOO_DEEP: u32 = 200301;

    /// Longest body excerpt kept in `message` when the body is not a Proton
    /// error object.
    const MAX_BODY_EXCERPT: usize = 512;

    /// Error for a response that carried a non-success `Code` in its body.
    pub fn from_code(code: u32, message: impl Into<String>) -> Self {
        Self {
            http_status: None,
            code: Some(code),
            message: message.into(),
            retry_after: None,
            details: None,
        }
    }

    /// Error for a non-2xx response. Extracts `Code`/`Error`/`Details` when
    /// the body is a Proton error object, otherwise keeps a body excerpt.
    pub fn from_http(
        status: reqwest::StatusCode,
        headers: &reqwest::header::HeaderMap,
        body: &str,
    ) -> Self {
        let mut error = Self::from_body(body).unwrap_or_else(|| Self {
            http_status: None,
            code: None,
            message: Self::body_excerpt(body).to_owned(),
            retry_after: None,
            details: None,
        });
        error.http_status = Some(status.as_u16());
        error.retry_after = parse_retry_after(headers);
        error
    }

    /// Parses a Proton error object (`Code`, `Error`, optional `Details`).
    /// Returns `None` when the body is not one.
    pub fn from_body(body: &str) -> Option<Self> {
        let value: serde_json::Value = serde_json::from_str(body).ok()?;
        let code = u32::try_from(value.get("Code")?.as_u64()?).ok()?;
        let message = value
            .get("Error")
            .and_then(|message| message.as_str())
            .map(str::to_owned)
            .unwrap_or_else(|| Self::body_excerpt(body).to_owned());
        let details = value.get("Details").filter(|d| !d.is_null()).cloned();
        Some(Self {
            details,
            ..Self::from_code(code, message)
        })
    }

    /// Deserializes [`ApiError::details`] into an endpoint-specific type.
    pub fn details_as<T: serde::de::DeserializeOwned>(&self) -> Option<T> {
        serde_json::from_value(self.details.clone()?).ok()
    }

    /// Finds an `ApiError` anywhere in an error's context chain.
    pub fn find(error: &anyhow::Error) -> Option<&ApiError> {
        error.chain().find_map(|cause| {
            cause.downcast_ref::<ApiError>().or_else(|| {
                // Errors raised by middleware are wrapped transparently.
                match cause.downcast_ref::<reqwest_middleware::Error>() {
                    Some(reqwest_middleware::Error::Middleware(inner)) => Self::find(inner),
                    _ => None,
                }
            })
        })
    }

    fn body_excerpt(body: &str) -> &str {
        let mut end = body.len().min(Self::MAX_BODY_EXCERPT);
        while !body.is_char_boundary(end) {
            end -= 1;
        }
        &body[..end]
    }

    fn has_code(&self, codes: &[u32]) -> bool {
        self.code.is_some_and(|code| codes.contains(&code))
    }

    fn has_status(&self, statuses: &[u16]) -> bool {
        self.http_status
            .is_some_and(|status| statuses.contains(&status))
    }

    pub fn is_not_found(&self) -> bool {
        self.has_code(&[Self::CODE_NOT_EXISTS]) || self.has_status(&[404])
    }

    pub fn is_already_exists(&self) -> bool {
        self.has_code(&[Self::CODE_ALREADY_EXISTS])
    }

    pub fn is_permission_denied(&self) -> bool {
        self.has_code(&[Self::CODE_NOT_ENOUGH_PERMISSIONS]) || self.has_status(&[403])
    }

    pub fn is_unauthorized(&self) -> bool {
        self.has_status(&[401])
    }

    pub fn is_quota_exceeded(&self) -> bool {
        self.has_code(&[
            Self::CODE_INSUFFICIENT_QUOTA,
            Self::CODE_INSUFFICIENT_SPACE,
            Self::CODE_INSUFFICIENT_VOLUME_QUOTA,
            Self::CODE_INSUFFICIENT_DEVICE_QUOTA,
        ])
    }

    pub fn is_file_too_large(&self) -> bool {
        self.has_code(&[Self::CODE_MAX_FILE_SIZE_FOR_FREE_USER])
    }

    pub fn is_too_many_children(&self) -> bool {
        self.has_code(&[Self::CODE_TOO_MANY_CHILDREN])
    }

    pub fn is_nesting_too_deep(&self) -> bool {
        self.has_code(&[Self::CODE_NESTING_TOO_DEEP])
    }

    pub fn is_rate_limited(&self) -> bool {
        self.has_status(&[429])
    }

    /// Returns whether repeating the same request may succeed: request
    /// timeouts, rate limiting and server-side failures.
    pub fn is_retryable(&self) -> bool {
        self.http_status
            .is_some_and(|status| matches!(status, 408 | 425 | 429) || status >= 500)
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (self.code, self.http_status) {
            (Some(code), _) => write!(f, "API error {}: {}", code, self.message),
            (None, Some(status)) => {
                let status = reqwest::StatusCode::from_u16(status)
                    .map(|s| s.to_string())
                    .unwrap_or_else(|_| status.to_string());
                write!(f, "HTTP {}: {}", status, self.message)
            }
            (None, None) => write!(f, "API error: {}", self.message),
        }
    }
}

impl std::error::Error for ApiError {}

/// C# RetryPolicy: `2^(attempt-2)` seconds plus up to 250ms jitter.
pub fn retry_backoff_delay(attempt: u32) -> Duration {
    let exp = 2u64.saturating_pow(attempt.saturating_sub(1).min(6));
    let base_ms = 500 * exp;
    let jitter_ms = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_millis())
        .unwrap_or(0)
        % 250) as u64;
    Duration::from_millis(base_ms + jitter_ms)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_retry_after_seconds() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(reqwest::header::RETRY_AFTER, "12".parse().unwrap());
        assert_eq!(parse_retry_after(&headers), Some(Duration::from_secs(12)));
    }

    #[test]
    fn checksum_mismatch_is_integrity_error() {
        let err = ChecksumMismatchIntegrityException {
            actual: vec![1],
            expected: vec![2],
        };
        assert_eq!(err.to_string(), "checksum mismatch");
    }

    #[test]
    fn retry_backoff_grows() {
        let first = retry_backoff_delay(1);
        let second = retry_backoff_delay(2);
        assert!(first >= Duration::from_millis(500));
        assert!(second >= Duration::from_millis(1000));
    }

    #[test]
    fn missing_or_invalid_retry_after_is_ignored() {
        let mut headers = reqwest::header::HeaderMap::new();
        assert_eq!(parse_retry_after(&headers), None);
        headers.insert(reqwest::header::RETRY_AFTER, "later".parse().unwrap());
        assert_eq!(parse_retry_after(&headers), None);
    }

    #[test]
    fn content_size_mismatch_includes_both_sizes() {
        assert_eq!(
            ContentSizeMismatchIntegrityException {
                uploaded: 41,
                expected: 42,
            }
            .to_string(),
            "content size mismatch: uploaded 41 bytes, expected 42 bytes"
        );
    }

    #[test]
    fn validation_error_preserves_the_message() {
        assert_eq!(
            ProtonDriveError::Validation("Invalid URL".into()).to_string(),
            "Invalid URL"
        );
    }

    #[test]
    fn retry_backoff_is_bounded_at_the_thirty_two_second_step() {
        let delay = retry_backoff_delay(u32::MAX);
        assert!(delay >= Duration::from_secs(32));
        assert!(delay < Duration::from_millis(32_250));
    }

    #[test]
    fn get_verification_message_matches_typescript_cases() {
        use VerificationStatus::*;
        let errors = ["error1".to_string(), "error2".to_string()];
        let cases: [(
            VerificationStatus,
            Option<&[String]>,
            Option<&str>,
            bool,
            &str,
        ); 8] = [
            (
                NotSigned,
                None,
                Some("type"),
                false,
                "Missing signature for type",
            ),
            (NotSigned, None, None, false, "Missing signature"),
            (
                NotSigned,
                None,
                Some("type"),
                true,
                "Missing signature for type",
            ),
            (
                SignedAndInvalid,
                None,
                Some("type"),
                false,
                "Signature verification for type failed",
            ),
            (
                SignedAndInvalid,
                None,
                None,
                false,
                "Signature verification failed",
            ),
            (
                SignedAndInvalid,
                None,
                Some("type"),
                true,
                "Verification keys for type are not available",
            ),
            (
                SignedAndInvalid,
                None,
                None,
                true,
                "Verification keys are not available",
            ),
            (
                SignedAndInvalid,
                Some(errors.as_slice()),
                None,
                false,
                "Signature verification failed: error1, error2",
            ),
        ];
        for (status, errors, kind, missing_keys, expected) in cases {
            assert_eq!(
                get_verification_message(status, errors, kind, missing_keys),
                expected
            );
        }
    }

    #[test]
    fn is_not_application_error_matches_typescript() {
        assert!(is_not_application_error(Some(&ProtonDriveError::abort())));
        assert!(is_not_application_error(Some(
            &ProtonDriveError::Validation("x".into())
        )));
        assert!(is_not_application_error(Some(
            &ProtonDriveError::RateLimited("x".into())
        )));
        assert!(is_not_application_error(Some(
            &ProtonDriveError::Connection("x".into())
        )));
        assert!(!is_not_application_error(Some(
            &ProtonDriveError::InternalError("x".into())
        )));
        assert!(!is_not_application_error(None));
        assert!(is_not_application_error_name("AbortError"));
        assert!(is_not_application_error_name("OfflineError"));
        assert!(is_not_application_error_name("TimeoutError"));
        assert!(!is_not_application_error_name("Error"));
    }

    #[test]
    fn api_error_from_http_extracts_proton_code_and_message() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(reqwest::header::RETRY_AFTER, "7".parse().unwrap());
        let error = ApiError::from_http(
            reqwest::StatusCode::UNPROCESSABLE_ENTITY,
            &headers,
            r#"{"Code":2500,"Error":"A file or folder with that name already exists"}"#,
        );
        assert_eq!(error.http_status, Some(422));
        assert_eq!(error.code, Some(2500));
        assert!(error.is_already_exists());
        assert_eq!(error.retry_after, Some(Duration::from_secs(7)));
        assert_eq!(
            error.to_string(),
            "API error 2500: A file or folder with that name already exists"
        );
    }

    #[test]
    fn api_error_keeps_the_details_object() {
        #[derive(serde::Deserialize)]
        struct Conflict {
            #[serde(rename = "ConflictLinkID")]
            link_id: String,
        }
        let error = ApiError::from_http(
            reqwest::StatusCode::CONFLICT,
            &reqwest::header::HeaderMap::new(),
            r#"{"Code":2500,"Error":"Conflict","Details":{"ConflictLinkID":"link-1"}}"#,
        );
        assert_eq!(error.http_status, Some(409));
        let conflict: Conflict = error.details_as().expect("details");
        assert_eq!(conflict.link_id, "link-1");
        assert!(
            ApiError::from_body(r#"{"Code":2500,"Error":"x","Details":null}"#)
                .unwrap()
                .details
                .is_none()
        );
        assert!(ApiError::from_body("not json").is_none());
    }

    #[test]
    fn api_error_from_http_keeps_a_bounded_excerpt_of_non_json_bodies() {
        let body = "é".repeat(600);
        let error = ApiError::from_http(
            reqwest::StatusCode::BAD_GATEWAY,
            &reqwest::header::HeaderMap::new(),
            &body,
        );
        assert_eq!(error.code, None);
        assert!(error.message.len() <= 512);
        assert!(error.is_retryable());
        assert!(error.to_string().starts_with("HTTP 502 Bad Gateway: "));
    }

    #[test]
    fn api_error_classifies_proton_codes_and_statuses() {
        assert!(ApiError::from_code(2501, "gone").is_not_found());
        assert!(ApiError::from_code(2011, "no").is_permission_denied());
        for code in [200001, 200002, 200100, 200101] {
            assert!(ApiError::from_code(code, "full").is_quota_exceeded());
        }
        assert!(ApiError::from_code(200003, "big").is_file_too_large());
        assert!(ApiError::from_code(200300, "many").is_too_many_children());
        assert!(ApiError::from_code(200301, "deep").is_nesting_too_deep());

        let status = |code: u16| ApiError {
            http_status: Some(code),
            code: None,
            message: String::new(),
            retry_after: None,
            details: None,
        };
        assert!(status(404).is_not_found());
        assert!(status(401).is_unauthorized());
        assert!(status(429).is_rate_limited());
        assert!(status(429).is_retryable());
        assert!(status(503).is_retryable());
        assert!(!status(400).is_retryable());
        assert!(!ApiError::from_code(2500, "exists").is_retryable());
    }

    #[test]
    fn api_error_is_found_through_context_layers() {
        let error = anyhow::Error::new(ApiError::from_code(2501, "gone"))
            .context("Failed to get node")
            .context("Failed to list folder");
        assert_eq!(ApiError::find(&error).and_then(|e| e.code), Some(2501));
        assert!(ApiError::find(&anyhow::anyhow!("plain")).is_none());
    }

    #[test]
    fn transfer_http_errors_classify_permanent_and_transient_statuses() {
        let permanent = HttpTransferError::new(reqwest::StatusCode::BAD_REQUEST, "bad", None);
        let transient =
            HttpTransferError::new(reqwest::StatusCode::SERVICE_UNAVAILABLE, "busy", None);
        let expired = HttpTransferError::new(reqwest::StatusCode::NOT_FOUND, "expired", None);

        assert!(!permanent.is_retryable());
        assert!(transient.is_retryable());
        assert!(expired.is_expired_target());
    }
}
