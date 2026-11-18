use std::{
    collections::HashMap,
    sync::{Arc, Mutex, MutexGuard, OnceLock, Weak},
};

use http::Uri;
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};
use serde::Serialize;
use tokio::sync::{OnceCell, broadcast};

use crate::{
    SessionId,
    api::{
        ApiResponse,
        response::{
            AuthenticationResponse, ModulusResponse, RefreshSessionResponse, ScopesResponse,
            SesisonInitiationResponse, SessionForkInitResponse, SessionForkStatusResponse,
        },
    },
};

/// Proton API code for a refresh token the server no longer accepts.
const INVALID_REFRESH_TOKEN_CODE: i64 = 10013;
const SUCCESS_CODE: i64 = 1000;

/// A non-success response from the session refresh endpoint.
///
/// Returned (inside `anyhow::Error`) by [`DefaultAuthenticationApiClient`]'s
/// `refresh_session`. Custom [`AuthenticationApiClient`] implementations can return it too, so
/// that [`TokenCredential`] can tell a rejected refresh token from a transient failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshSessionError {
    /// HTTP status code of the response.
    pub status: u16,
    /// Proton API `Code` from the response body, if the body carried one.
    pub code: Option<i64>,
    /// Proton API `Error` message from the response body, if any.
    pub message: Option<String>,
}

impl std::fmt::Display for RefreshSessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "session refresh failed with HTTP status {}", self.status)?;
        if let Some(code) = self.code {
            write!(f, ", code {code}")?;
        }
        if let Some(message) = &self.message {
            write!(f, ": {message}")?;
        }
        Ok(())
    }
}

impl std::error::Error for RefreshSessionError {}

/// Why a token refresh failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenRefreshFailureKind {
    /// The server rejected the refresh token (Proton code 10013). The session cannot be
    /// refreshed again; the user must re-authenticate.
    RefreshTokenExpired,
    /// A network failure, timeout, HTTP 408, 429 or 5xx. A later attempt may succeed.
    Transient,
    /// Any other failure, such as an unexpected 4xx response or an undecodable body.
    Other,
}

/// Error returned by [`TokenCredential::get_refreshed_access_token`] when the refresh fails.
///
/// All callers that waited on the same refresh receive a clone of the same error.
#[derive(Debug, Clone)]
pub struct TokenRefreshError {
    kind: TokenRefreshFailureKind,
    source: Arc<anyhow::Error>,
}

impl TokenRefreshError {
    fn new(source: anyhow::Error) -> Self {
        Self {
            kind: classify_refresh_failure(&source),
            source: Arc::new(source),
        }
    }

    /// Returns the classification of the failure.
    pub fn kind(&self) -> TokenRefreshFailureKind {
        self.kind
    }

    /// Returns `true` when the server rejected the refresh token, so re-authentication is needed.
    pub fn is_refresh_token_expired(&self) -> bool {
        self.kind == TokenRefreshFailureKind::RefreshTokenExpired
    }
}

impl std::fmt::Display for TokenRefreshError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.kind {
            TokenRefreshFailureKind::RefreshTokenExpired => write!(
                f,
                "refresh token was rejected, re-authentication is required: {}",
                self.source
            ),
            TokenRefreshFailureKind::Transient | TokenRefreshFailureKind::Other => {
                write!(f, "token refresh failed: {}", self.source)
            }
        }
    }
}

impl std::error::Error for TokenRefreshError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref().as_ref())
    }
}

/// Classifies a refresh endpoint response by HTTP status and Proton API code.
///
/// Only Proton code 10013 (invalid refresh token) counts as an expired refresh token, whatever
/// the HTTP status (Proton sends it with 400 or 422). Other 400/422 responses are not treated as
/// definite rejections of the refresh token.
pub(crate) fn classify_refresh_response(status: u16, code: Option<i64>) -> TokenRefreshFailureKind {
    if code == Some(INVALID_REFRESH_TOKEN_CODE) {
        return TokenRefreshFailureKind::RefreshTokenExpired;
    }
    match status {
        408 | 429 | 500..=599 => TokenRefreshFailureKind::Transient,
        _ => TokenRefreshFailureKind::Other,
    }
}

/// Classifies an error returned by [`AuthenticationApiClient::refresh_session`].
pub(crate) fn classify_refresh_failure(error: &anyhow::Error) -> TokenRefreshFailureKind {
    for cause in error.chain() {
        if let Some(error) = cause.downcast_ref::<RefreshSessionError>() {
            return classify_refresh_response(error.status, error.code);
        }
        if let Some(error) = cause.downcast_ref::<reqwest::Error>() {
            if let Some(status) = error.status() {
                return classify_refresh_response(status.as_u16(), None);
            }
            if error.is_timeout() || error.is_connect() || error.is_request() || error.is_body() {
                return TokenRefreshFailureKind::Transient;
            }
        }
        if cause.downcast_ref::<std::io::Error>().is_some() {
            return TokenRefreshFailureKind::Transient;
        }
    }
    TokenRefreshFailureKind::Other
}

/// Returns the refresh error carried by a refresh endpoint response, or `None` on success.
///
/// A response fails when its HTTP status is not 2xx, or when its body carries a Proton `Code`
/// other than 1000.
pub(crate) fn refresh_error_from_response(status: u16, body: &[u8]) -> Option<RefreshSessionError> {
    let json = serde_json::from_slice::<serde_json::Value>(body).ok();
    let code = json
        .as_ref()
        .and_then(|json| json.get("Code").or_else(|| json.get("code")))
        .and_then(serde_json::Value::as_i64);
    let message = json
        .as_ref()
        .and_then(|json| json.get("Error").or_else(|| json.get("error")))
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);

    let is_success_status = (200..300).contains(&status);
    let is_success_code = code.is_none_or(|code| code == SUCCESS_CODE);
    if is_success_status && is_success_code {
        return None;
    }
    Some(RefreshSessionError {
        status,
        code,
        message,
    })
}

type RefreshOutcome = Result<(String, String), TokenRefreshError>;

#[derive(Clone)]
pub struct TokenCredential {
    session_id: SessionId,
    #[allow(dead_code)]
    access_token: String,
    #[allow(dead_code)]
    refresh_token: String,
    state: Arc<TokenCredentialState>,
}

struct TokenCredentialState {
    client: Arc<dyn AuthenticationApiClient>,
    tokens: Mutex<TokenSlot>,
    tokens_refreshed_tx: broadcast::Sender<(String, String)>,
    refresh_token_expired_tx: broadcast::Sender<()>,
}

impl TokenCredentialState {
    fn lock_tokens(&self) -> MutexGuard<'_, TokenSlot> {
        self.tokens
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// The current token pair and, while a refresh runs, the attempt that will replace it.
struct TokenSlot {
    access_token: String,
    refresh_token: String,
    in_flight: Option<Arc<RefreshAttempt>>,
}

/// One single-flight refresh of a specific token pair. Every caller that rejected the same
/// access token awaits the same `outcome`.
struct RefreshAttempt {
    access_token: String,
    refresh_token: String,
    outcome: OnceCell<RefreshOutcome>,
}

static TOKEN_STATES: OnceLock<Mutex<HashMap<String, Weak<TokenCredentialState>>>> = OnceLock::new();

impl TokenCredential {
    /// Creates a new `TokenCredential` seeded with the given access and refresh tokens.
    /// The underlying token pair is refreshed automatically when callers invoke `get_tokens`.
    pub fn new(
        client: Arc<dyn AuthenticationApiClient>,
        session_id: SessionId,
        access_token: String,
        refresh_token: String,
    ) -> Self {
        let registry = TOKEN_STATES.get_or_init(|| Mutex::new(HashMap::new()));
        let state = {
            let mut registry = registry.lock().unwrap();
            if let Some(state) = registry
                .get(session_id.raw())
                .and_then(|state| state.upgrade())
            {
                state
            } else {
                let (tokens_refreshed_tx, _) = broadcast::channel(16);
                let (refresh_token_expired_tx, _) = broadcast::channel(16);
                let state = Arc::new(TokenCredentialState {
                    client,
                    tokens: Mutex::new(TokenSlot {
                        access_token: access_token.clone(),
                        refresh_token: refresh_token.clone(),
                        in_flight: None,
                    }),
                    tokens_refreshed_tx,
                    refresh_token_expired_tx,
                });
                registry.insert(session_id.raw().clone(), Arc::downgrade(&state));
                state
            }
        };

        Self {
            session_id,
            state,
            access_token,
            refresh_token,
        }
    }

    /// Returns the current (access, refresh) token pair.
    ///
    /// While a refresh is in flight this returns the pair being refreshed; after a failed
    /// refresh it keeps returning that pair.
    pub async fn get_tokens(&self) -> anyhow::Result<(String, String)> {
        let tokens = self.state.lock_tokens();
        Ok((tokens.access_token.clone(), tokens.refresh_token.clone()))
    }

    /// Alias for `get_tokens`; returns the (access, refresh) token pair.
    pub async fn get_access_token(&self) -> anyhow::Result<(String, String)> {
        self.get_tokens().await
    }

    /// Subscribes to a broadcast channel that fires whenever tokens are successfully refreshed.
    /// The sent value is the new (access, refresh) token pair.
    pub fn subscribe_tokens_refreshed(&self) -> broadcast::Receiver<(String, String)> {
        self.state.tokens_refreshed_tx.subscribe()
    }

    /// Subscribes to a broadcast channel that fires when the server rejects the refresh token
    /// (Proton code 10013). It fires once per failed refresh attempt, not for transient failures.
    /// Callers should prompt for re-authentication on receipt.
    pub fn subscribe_refresh_token_expired(&self) -> broadcast::Receiver<()> {
        self.state.refresh_token_expired_tx.subscribe()
    }

    /// Returns the session identifier associated with this credential.
    pub fn session_id(&self) -> SessionId {
        self.session_id.clone()
    }

    /// Returns the access token that was last explicitly stored in this credential.
    /// For the latest valid token use the async `get_tokens` instead.
    pub fn current_access_token(&self) -> &str {
        &self.access_token
    }

    /// Returns the refresh token that was active when this credential was constructed or last
    /// explicitly stored.
    ///
    /// Note: if the access token has been silently refreshed during the session the internally
    /// stored refresh token field is not updated; callers that need the latest token pair should
    /// use the async [`Self::get_tokens`] instead.
    pub fn current_refresh_token(&self) -> &str {
        &self.refresh_token
    }

    fn trigger_tokens_refreshed(&self, access_token: String, refresh_token: String) {
        let _ = self
            .state
            .tokens_refreshed_tx
            .send((access_token, refresh_token));
    }

    fn trigger_refresh_token_expired(&self) {
        let _ = self.state.refresh_token_expired_tx.send(());
    }

    /// Obtains a fresh access token, triggering a server-side refresh if the given
    /// `rejected_access_token` matches the current stored token.
    ///
    /// Concurrent callers that rejected the same token share one refresh request. If the
    /// refresh fails, every one of them receives the error, as an `anyhow::Error` that
    /// downcasts to [`TokenRefreshError`]; the stored tokens stay unchanged, so a later call
    /// retries. When the server rejects the refresh token,
    /// [`Self::subscribe_refresh_token_expired`] subscribers are notified.
    pub async fn get_refreshed_access_token(
        &self,
        rejected_access_token: String,
    ) -> anyhow::Result<String> {
        let attempt = {
            let mut tokens = self.state.lock_tokens();
            let is_likely_already_refreshed = tokens.access_token != rejected_access_token;
            if is_likely_already_refreshed {
                return Ok(tokens.access_token.clone());
            }
            match &tokens.in_flight {
                Some(attempt) => attempt.clone(),
                None => {
                    let attempt = Arc::new(RefreshAttempt {
                        access_token: tokens.access_token.clone(),
                        refresh_token: tokens.refresh_token.clone(),
                        outcome: OnceCell::new(),
                    });
                    tokens.in_flight = Some(attempt.clone());
                    attempt
                }
            }
        };

        let outcome = attempt
            .outcome
            .get_or_init(|| self.run_refresh(&attempt))
            .await
            .clone();
        let (access_token, _) = outcome?;
        Ok(access_token)
    }

    /// Performs the refresh for `attempt`, publishes its result and notifies subscribers.
    /// Runs at most once per attempt to completion, inside the attempt's `OnceCell`.
    async fn run_refresh(&self, attempt: &Arc<RefreshAttempt>) -> RefreshOutcome {
        let outcome = self
            .state
            .client
            .refresh_session(
                self.session_id.clone(),
                attempt.access_token.clone(),
                attempt.refresh_token.clone(),
            )
            .await
            .map(|response| (response.access_token, response.refresh_token))
            .map_err(TokenRefreshError::new);

        {
            let mut tokens = self.state.lock_tokens();
            let is_current_attempt = tokens
                .in_flight
                .as_ref()
                .is_some_and(|in_flight| Arc::ptr_eq(in_flight, attempt));
            if is_current_attempt {
                tokens.in_flight = None;
                if let Ok((access_token, refresh_token)) = &outcome {
                    tokens.access_token = access_token.clone();
                    tokens.refresh_token = refresh_token.clone();
                }
            }
        }

        match &outcome {
            Ok((access_token, refresh_token)) => {
                self.trigger_tokens_refreshed(access_token.clone(), refresh_token.clone());
            }
            Err(error) if error.is_refresh_token_expired() => {
                log::warn!("refresh token rejected by the server: {error}");
                self.trigger_refresh_token_expired();
            }
            Err(error) => {
                log::warn!("token refresh failed: {error}");
            }
        }

        outcome
    }
}

#[async_trait::async_trait]
pub trait AuthenticationApiClient: Send + Sync {
    async fn initiate_session(&self, username: String)
    -> anyhow::Result<SesisonInitiationResponse>;

    async fn authenticate(
        &self,
        initiation_response: SesisonInitiationResponse,
        srp_client_handshake: proton_crypto::srp::ClientProof,
        username: String,
    ) -> anyhow::Result<AuthenticationResponse>;

    async fn validate_second_factor(
        &self,
        second_factor_code: String,
    ) -> anyhow::Result<ScopesResponse>;

    async fn end_session(&self) -> anyhow::Result<ApiResponse>;

    async fn end_session_with_token(
        &self,
        session_id: SessionId,
        access_token: String,
    ) -> anyhow::Result<ApiResponse>;

    async fn refresh_session(
        &self,
        session_id: SessionId,
        access_token: String,
        refresh_token: String,
    ) -> anyhow::Result<RefreshSessionResponse>;

    async fn get_scopes(&self) -> anyhow::Result<ScopesResponse>;

    async fn get_random_srp_modulus(&self) -> anyhow::Result<ModulusResponse>;

    async fn init_session_fork(&self) -> anyhow::Result<SessionForkInitResponse>;

    /// `Ok(None)` when the browser login has not completed yet (HTTP 422).
    async fn poll_session_fork(
        &self,
        selector: &str,
    ) -> anyhow::Result<Option<SessionForkStatusResponse>>;
}

pub struct DefaultAuthenticationApiClient {
    http_client: reqwest::Client,
    refresh_redirect_uri: Uri,
}

impl DefaultAuthenticationApiClient {
    const DEFAULT_API_BASE: &'static str = "https://drive-api.proton.me/";

    pub fn new(http_client: reqwest::Client, refresh_redirect_uri: Uri) -> Self {
        Self {
            http_client,
            refresh_redirect_uri,
        }
    }

    fn endpoint(&self, path: &str) -> anyhow::Result<String> {
        if path.starts_with("http://") || path.starts_with("https://") {
            return Ok(path.to_string());
        }

        let base = reqwest::Url::parse(Self::DEFAULT_API_BASE)?;
        Ok(base.join(path)?.to_string())
    }

    fn auth_headers(session_id: &SessionId, access_token: &str) -> anyhow::Result<HeaderMap> {
        let mut headers = HeaderMap::new();
        let bearer = format!("Bearer {}", access_token);
        headers.insert(AUTHORIZATION, HeaderValue::from_str(&bearer)?);
        headers.insert("x-pm-uid", HeaderValue::from_str(session_id.raw())?);
        Ok(headers)
    }

    async fn error_for_status_with_body(
        response: reqwest::Response,
    ) -> anyhow::Result<reqwest::Response> {
        let status = response.status();
        if status.is_success() {
            return Ok(response);
        }

        let url = response.url().clone();
        let body = response
            .text()
            .await
            .unwrap_or_else(|error| format!("<failed to read response body: {error}>"));
        let body = truncate_error_body(&body);

        if status.is_client_error() {
            anyhow::bail!("HTTP status client error ({status}) for url ({url}): {body}");
        } else if status.is_server_error() {
            anyhow::bail!("HTTP status server error ({status}) for url ({url}): {body}");
        } else {
            anyhow::bail!("HTTP status error ({status}) for url ({url}): {body}");
        }
    }
}

fn truncate_error_body(body: &str) -> String {
    const MAX_ERROR_BODY_LEN: usize = 2048;
    if body.len() <= MAX_ERROR_BODY_LEN {
        return body.to_string();
    }

    let truncate_at = body
        .char_indices()
        .map(|(index, _)| index)
        .take_while(|index| *index <= MAX_ERROR_BODY_LEN)
        .last()
        .unwrap_or(0);
    let mut truncated = body[..truncate_at].to_string();
    truncated.push_str("…<truncated>");
    truncated
}

#[derive(Serialize)]
struct SessionInitiationRequest {
    #[serde(rename = "Username")]
    username: String,
}

#[derive(Serialize)]
struct AuthenticationRequest {
    #[serde(rename = "ClientEphemeral")]
    client_ephemeral: String,
    #[serde(rename = "ClientProof")]
    client_proof: String,
    #[serde(rename = "SRPSession")]
    srp_session_id: String,
    #[serde(rename = "Username")]
    username: String,
}

#[derive(Serialize)]
struct SecondFactorValidationRequest {
    #[serde(rename = "TwoFactorCode")]
    second_factor_code: String,
}

#[derive(Serialize)]
struct SessionRefreshRequest {
    #[serde(rename = "RefreshToken")]
    refresh_token: String,
    #[serde(rename = "ResponseType")]
    response_type: String,
    #[serde(rename = "GrantType")]
    grant_type: String,
    #[serde(rename = "RedirectURI")]
    redirect_uri: String,
}

#[async_trait::async_trait]
impl AuthenticationApiClient for DefaultAuthenticationApiClient {
    async fn initiate_session(
        &self,
        username: String,
    ) -> anyhow::Result<SesisonInitiationResponse> {
        let request = SessionInitiationRequest { username };
        let request_body = serde_json::to_vec(&request)?;

        let response = self
            .http_client
            .post(self.endpoint("auth/v4/info")?)
            .header("content-type", "application/json")
            .body(request_body)
            .send()
            .await?;
        let response = Self::error_for_status_with_body(response).await?;

        crate::utils::decode_json::<SesisonInitiationResponse>(response).await
    }

    async fn authenticate(
        &self,
        initiation_response: SesisonInitiationResponse,
        srp_client_handshake: proton_crypto::srp::ClientProof,
        username: String,
    ) -> anyhow::Result<AuthenticationResponse> {
        let request = AuthenticationRequest {
            client_ephemeral: srp_client_handshake.ephemeral.clone(),
            client_proof: srp_client_handshake.proof.clone(),
            srp_session_id: initiation_response.srp_session_id,
            username,
        };

        log::debug!(
            "submitting SRP authentication proof (client_ephemeral_len={}, client_proof_len={}, srp_session_len={})",
            request.client_ephemeral.len(),
            request.client_proof.len(),
            request.srp_session_id.len(),
        );

        let request_body = serde_json::to_vec(&request)?;

        let response = self
            .http_client
            .post(self.endpoint("auth/v4")?)
            .header("content-type", "application/json")
            .body(request_body)
            .send()
            .await?;
        let response = Self::error_for_status_with_body(response).await?;

        crate::utils::decode_json::<AuthenticationResponse>(response).await
    }

    async fn validate_second_factor(
        &self,
        second_factor_code: String,
    ) -> anyhow::Result<ScopesResponse> {
        let request = SecondFactorValidationRequest { second_factor_code };
        let request_body = serde_json::to_vec(&request)?;

        let response = self
            .http_client
            .post(self.endpoint("auth/v4/2fa")?)
            .header("content-type", "application/json")
            .body(request_body)
            .send()
            .await?
            .error_for_status()?;

        crate::utils::decode_json::<ScopesResponse>(response).await
    }

    async fn end_session(&self) -> anyhow::Result<ApiResponse> {
        let response = self
            .http_client
            .delete(self.endpoint("auth/v4")?)
            .send()
            .await?
            .error_for_status()?;

        crate::utils::decode_json::<ApiResponse>(response).await
    }

    async fn end_session_with_token(
        &self,
        session_id: SessionId,
        access_token: String,
    ) -> anyhow::Result<ApiResponse> {
        let headers = Self::auth_headers(&session_id, &access_token)?;
        let response = self
            .http_client
            .delete(self.endpoint("auth/v4")?)
            .headers(headers)
            .send()
            .await?
            .error_for_status()?;

        crate::utils::decode_json::<ApiResponse>(response).await
    }

    async fn refresh_session(
        &self,
        session_id: SessionId,
        access_token: String,
        refresh_token: String,
    ) -> anyhow::Result<RefreshSessionResponse> {
        let request = SessionRefreshRequest {
            refresh_token,
            response_type: "token".to_string(),
            grant_type: "refresh_token".to_string(),
            redirect_uri: self.refresh_redirect_uri.to_string(),
        };

        let headers = Self::auth_headers(&session_id, &access_token)?;

        let response = self
            .http_client
            .post(self.endpoint("auth/v4/refresh")?)
            .headers(headers)
            .header("content-type", "application/json")
            .body(serde_json::to_vec(&request)?)
            .send()
            .await?;

        let status = response.status().as_u16();
        let body = response.bytes().await?;
        if let Some(error) = refresh_error_from_response(status, &body) {
            return Err(error.into());
        }
        Ok(serde_json::from_slice::<RefreshSessionResponse>(&body)?)
    }

    async fn get_scopes(&self) -> anyhow::Result<ScopesResponse> {
        let response = self
            .http_client
            .get(self.endpoint("auth/v4/scopes")?)
            .send()
            .await?
            .error_for_status()?;

        crate::utils::decode_json::<ScopesResponse>(response).await
    }

    async fn get_random_srp_modulus(&self) -> anyhow::Result<ModulusResponse> {
        let response = self
            .http_client
            .get(self.endpoint("auth/v4/modulus")?)
            .send()
            .await?
            .error_for_status()?;

        crate::utils::decode_json::<ModulusResponse>(response).await
    }

    async fn init_session_fork(&self) -> anyhow::Result<SessionForkInitResponse> {
        let response = self
            .http_client
            .get(self.endpoint("auth/v4/sessions/forks")?)
            .send()
            .await?;
        let response = Self::error_for_status_with_body(response).await?;
        crate::utils::decode_json::<SessionForkInitResponse>(response).await
    }

    async fn poll_session_fork(
        &self,
        selector: &str,
    ) -> anyhow::Result<Option<SessionForkStatusResponse>> {
        let path = format!("auth/v4/sessions/forks/{selector}");
        let response = self.http_client.get(self.endpoint(&path)?).send().await?;
        if response.status() == reqwest::StatusCode::UNPROCESSABLE_ENTITY {
            return Ok(None);
        }
        let response = Self::error_for_status_with_body(response).await?;
        Ok(Some(
            crate::utils::decode_json::<SessionForkStatusResponse>(response).await?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn refresh_failures_classify_expired_and_transient_responses() {
        use TokenRefreshFailureKind::*;
        assert_eq!(
            classify_refresh_response(422, Some(10013)),
            RefreshTokenExpired
        );
        assert_eq!(
            classify_refresh_response(400, Some(10013)),
            RefreshTokenExpired
        );
        assert_eq!(classify_refresh_response(422, Some(2001)), Other);
        assert_eq!(classify_refresh_response(422, None), Other);
        assert_eq!(classify_refresh_response(400, None), Other);
        assert_eq!(classify_refresh_response(401, None), Other);
        assert_eq!(classify_refresh_response(408, None), Transient);
        assert_eq!(classify_refresh_response(429, Some(2028)), Transient);
        assert_eq!(classify_refresh_response(500, None), Transient);
        assert_eq!(classify_refresh_response(503, None), Transient);
    }

    #[test]
    fn refresh_errors_classify_through_context_and_io_failures() {
        let rejected = anyhow::Error::new(RefreshSessionError {
            status: 422,
            code: Some(10013),
            message: Some("Invalid refresh token".into()),
        })
        .context("refreshing session");
        assert_eq!(
            classify_refresh_failure(&rejected),
            TokenRefreshFailureKind::RefreshTokenExpired
        );

        let io = anyhow::Error::new(std::io::Error::from(std::io::ErrorKind::ConnectionReset));
        assert_eq!(
            classify_refresh_failure(&io),
            TokenRefreshFailureKind::Transient
        );

        let undecodable = anyhow::Error::new(serde_json::from_str::<u8>("x").unwrap_err());
        assert_eq!(
            classify_refresh_failure(&undecodable),
            TokenRefreshFailureKind::Other
        );
    }

    #[test]
    fn refresh_response_errors_carry_status_and_proton_code() {
        assert_eq!(
            refresh_error_from_response(
                200,
                br#"{"Code":1000,"AccessToken":"a","RefreshToken":"r"}"#
            ),
            None
        );
        assert_eq!(
            refresh_error_from_response(422, br#"{"Code":10013,"Error":"Invalid refresh token"}"#),
            Some(RefreshSessionError {
                status: 422,
                code: Some(10013),
                message: Some("Invalid refresh token".into()),
            })
        );
        assert_eq!(
            refresh_error_from_response(200, br#"{"Code":10013}"#).map(|error| error.code),
            Some(Some(10013))
        );
        assert_eq!(
            refresh_error_from_response(502, b"<html>bad gateway</html>"),
            Some(RefreshSessionError {
                status: 502,
                code: None,
                message: None,
            })
        );
    }

    /// Answers `refresh_session` from a queue of outcomes, each released by one gate permit.
    struct FakeRefreshClient {
        calls: AtomicUsize,
        gate: tokio::sync::Semaphore,
        outcomes: Mutex<VecDeque<anyhow::Result<RefreshSessionResponse>>>,
    }

    impl FakeRefreshClient {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                calls: AtomicUsize::new(0),
                gate: tokio::sync::Semaphore::new(0),
                outcomes: Mutex::new(VecDeque::new()),
            })
        }

        fn release(&self, outcome: anyhow::Result<RefreshSessionResponse>) {
            self.outcomes.lock().unwrap().push_back(outcome);
            self.gate.add_permits(1);
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    #[async_trait::async_trait]
    impl AuthenticationApiClient for FakeRefreshClient {
        async fn initiate_session(&self, _: String) -> anyhow::Result<SesisonInitiationResponse> {
            unimplemented!()
        }

        async fn authenticate(
            &self,
            _: SesisonInitiationResponse,
            _: proton_crypto::srp::ClientProof,
            _: String,
        ) -> anyhow::Result<AuthenticationResponse> {
            unimplemented!()
        }

        async fn validate_second_factor(&self, _: String) -> anyhow::Result<ScopesResponse> {
            unimplemented!()
        }

        async fn end_session(&self) -> anyhow::Result<ApiResponse> {
            unimplemented!()
        }

        async fn end_session_with_token(
            &self,
            _: SessionId,
            _: String,
        ) -> anyhow::Result<ApiResponse> {
            unimplemented!()
        }

        async fn refresh_session(
            &self,
            _: SessionId,
            access_token: String,
            refresh_token: String,
        ) -> anyhow::Result<RefreshSessionResponse> {
            assert_eq!(access_token, "old-access");
            assert_eq!(refresh_token, "old-refresh");
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.gate.acquire().await.unwrap().forget();
            self.outcomes.lock().unwrap().pop_front().unwrap()
        }

        async fn get_scopes(&self) -> anyhow::Result<ScopesResponse> {
            unimplemented!()
        }

        async fn get_random_srp_modulus(&self) -> anyhow::Result<ModulusResponse> {
            unimplemented!()
        }

        async fn init_session_fork(&self) -> anyhow::Result<SessionForkInitResponse> {
            unimplemented!()
        }

        async fn poll_session_fork(
            &self,
            _: &str,
        ) -> anyhow::Result<Option<SessionForkStatusResponse>> {
            unimplemented!()
        }
    }

    fn credential(client: Arc<FakeRefreshClient>, session_id: &str) -> TokenCredential {
        TokenCredential::new(
            client,
            SessionId::new(session_id.into()),
            "old-access".into(),
            "old-refresh".into(),
        )
    }

    fn rejected_refresh_token() -> anyhow::Error {
        RefreshSessionError {
            status: 422,
            code: Some(10013),
            message: Some("Invalid refresh token".into()),
        }
        .into()
    }

    async fn let_spawned_tasks_reach_the_refresh() {
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test]
    async fn concurrent_refresh_waiters_all_receive_the_rejection() {
        let client = FakeRefreshClient::new();
        let credential = credential(client.clone(), "test-session-rejected");
        let mut expired = credential.subscribe_refresh_token_expired();
        let mut refreshed = credential.subscribe_tokens_refreshed();

        let waiters: Vec<_> = (0..3)
            .map(|_| {
                let credential = credential.clone();
                tokio::spawn(async move {
                    credential
                        .get_refreshed_access_token("old-access".into())
                        .await
                })
            })
            .collect();
        let_spawned_tasks_reach_the_refresh().await;
        client.release(Err(rejected_refresh_token()));

        for waiter in waiters {
            let error = waiter.await.unwrap().unwrap_err();
            let error = error.downcast_ref::<TokenRefreshError>().unwrap();
            assert!(error.is_refresh_token_expired());
        }
        assert_eq!(client.calls(), 1);
        assert!(expired.try_recv().is_ok());
        assert!(expired.try_recv().is_err());
        assert!(refreshed.try_recv().is_err());
        assert_eq!(
            credential.get_tokens().await.unwrap(),
            ("old-access".into(), "old-refresh".into())
        );
    }

    #[tokio::test]
    async fn transient_refresh_failure_is_an_error_and_a_later_call_retries() {
        let client = FakeRefreshClient::new();
        let credential = credential(client.clone(), "test-session-transient");
        let mut expired = credential.subscribe_refresh_token_expired();
        let mut refreshed = credential.subscribe_tokens_refreshed();

        client.release(Err(RefreshSessionError {
            status: 503,
            code: None,
            message: None,
        }
        .into()));
        let error = credential
            .get_refreshed_access_token("old-access".into())
            .await
            .unwrap_err();
        assert_eq!(
            error.downcast_ref::<TokenRefreshError>().unwrap().kind(),
            TokenRefreshFailureKind::Transient
        );
        assert!(expired.try_recv().is_err());
        assert!(refreshed.try_recv().is_err());

        client.release(Ok(RefreshSessionResponse {
            access_token: "new-access".into(),
            refresh_token: "new-refresh".into(),
        }));
        let access_token = credential
            .get_refreshed_access_token("old-access".into())
            .await
            .unwrap();
        assert_eq!(access_token, "new-access");
        assert_eq!(client.calls(), 2);
        assert_eq!(
            refreshed.try_recv().unwrap(),
            ("new-access".into(), "new-refresh".into())
        );
        assert_eq!(
            credential.get_tokens().await.unwrap(),
            ("new-access".into(), "new-refresh".into())
        );

        let access_token = credential
            .get_refreshed_access_token("old-access".into())
            .await
            .unwrap();
        assert_eq!(access_token, "new-access");
        assert_eq!(client.calls(), 2);
    }

    #[tokio::test]
    async fn concurrent_refresh_waiters_share_one_successful_refresh() {
        let client = FakeRefreshClient::new();
        let credential = credential(client.clone(), "test-session-success");
        let mut refreshed = credential.subscribe_tokens_refreshed();

        let waiters: Vec<_> = (0..3)
            .map(|_| {
                let credential = credential.clone();
                tokio::spawn(async move {
                    credential
                        .get_refreshed_access_token("old-access".into())
                        .await
                })
            })
            .collect();
        let_spawned_tasks_reach_the_refresh().await;
        assert_eq!(
            credential.get_tokens().await.unwrap(),
            ("old-access".into(), "old-refresh".into())
        );
        client.release(Ok(RefreshSessionResponse {
            access_token: "new-access".into(),
            refresh_token: "new-refresh".into(),
        }));

        for waiter in waiters {
            assert_eq!(waiter.await.unwrap().unwrap(), "new-access");
        }
        assert_eq!(client.calls(), 1);
        assert!(refreshed.try_recv().is_ok());
        assert!(refreshed.try_recv().is_err());
    }
}
