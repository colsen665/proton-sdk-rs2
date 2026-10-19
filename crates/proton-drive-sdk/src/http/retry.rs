//! Retry policy for Drive API (metadata) requests.
//!
//! Mirrors the request loop of the official JS SDK
//! (`internal/apiService/apiService.ts`):
//!
//! * HTTP 429: wait for `Retry-After` (or a default) and retry. After too
//!   many consecutive 429 responses, stop sending requests for a cool-down.
//! * HTTP 5xx: retry once. After too many consecutive 5xx responses, stop
//!   sending requests for a cool-down.
//! * Timeouts and connection failures: retry a bounded number of times.
//!
//! Unlike the JS SDK, 5xx responses and timeouts are retried only for
//! idempotent methods, because a non-idempotent request may already have
//! been applied. A 429 response or a connection failure means the request
//! was not processed, so those are retried for every method.
//!
//! Blob transfers have their own retry loops and do not use this middleware.

use crate::error::ApiError;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Tunables of [`DriveApiRetryMiddleware`]. Defaults follow the JS SDK.
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    /// Delay after a 429 response without a usable `Retry-After`.
    pub default_rate_limit_delay: Duration,
    /// Delay before retrying a 5xx response.
    pub server_error_delay: Duration,
    /// Delay before retrying a timed-out request.
    pub timeout_delay: Duration,
    /// Delay before retrying after a connection failure.
    pub connection_error_delay: Duration,
    /// Total attempts allowed for a request that keeps timing out.
    pub max_timeout_attempts: u32,
    /// Total attempts allowed for a request that keeps failing to connect.
    pub max_connection_attempts: u32,
    /// Consecutive 429 responses after which requests fail fast.
    pub rate_limit_breaker_threshold: u32,
    /// How long requests fail fast after the 429 threshold is reached.
    pub rate_limit_cool_down: Duration,
    /// Consecutive 5xx responses after which requests fail fast.
    pub server_error_breaker_threshold: u32,
    /// How long requests fail fast after the 5xx threshold is reached.
    pub server_error_cool_down: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            default_rate_limit_delay: Duration::from_secs(10),
            server_error_delay: Duration::from_secs(1),
            timeout_delay: Duration::from_secs(1),
            connection_error_delay: Duration::from_secs(5),
            max_timeout_attempts: 3,
            max_connection_attempts: 3,
            rate_limit_breaker_threshold: 50,
            rate_limit_cool_down: Duration::from_secs(60),
            server_error_breaker_threshold: 10,
            server_error_cool_down: Duration::from_secs(60),
        }
    }
}

/// Result of one attempt, reduced to what the policy needs.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Outcome {
    Status {
        status: u16,
        retry_after: Option<Duration>,
    },
    Timeout,
    Connection,
    Other,
}

impl Outcome {
    fn of(result: &reqwest_middleware::Result<reqwest::Response>) -> Self {
        match result {
            Ok(response) => Self::Status {
                status: response.status().as_u16(),
                retry_after: crate::error::parse_retry_after(response.headers()),
            },
            Err(reqwest_middleware::Error::Reqwest(error)) if error.is_timeout() => Self::Timeout,
            Err(reqwest_middleware::Error::Reqwest(error)) if error.is_connect() => {
                Self::Connection
            }
            Err(_) => Self::Other,
        }
    }
}

fn is_idempotent(method: &reqwest::Method) -> bool {
    use reqwest::Method;
    [
        Method::GET,
        Method::HEAD,
        Method::OPTIONS,
        Method::PUT,
        Method::DELETE,
    ]
    .contains(method)
}

impl RetryPolicy {
    /// Delay before the next attempt, or `None` to return the result.
    /// `attempt` is the number of attempts already made (1 after the first).
    fn retry_delay(
        &self,
        method: &reqwest::Method,
        outcome: &Outcome,
        attempt: u32,
    ) -> Option<Duration> {
        match outcome {
            Outcome::Status {
                status: 429,
                retry_after,
            } => Some(
                retry_after
                    .filter(|delay| !delay.is_zero())
                    .unwrap_or(self.default_rate_limit_delay),
            ),
            Outcome::Status { status, .. } if *status >= 500 => {
                (is_idempotent(method) && attempt == 1).then_some(self.server_error_delay)
            }
            Outcome::Status { .. } | Outcome::Other => None,
            Outcome::Timeout => (is_idempotent(method) && attempt < self.max_timeout_attempts)
                .then_some(self.timeout_delay),
            Outcome::Connection => {
                (attempt < self.max_connection_attempts).then_some(self.connection_error_delay)
            }
        }
    }
}

/// Consecutive-failure counters shared by all requests of one client.
#[derive(Debug, Default)]
struct BreakerState {
    consecutive_rate_limits: u32,
    last_rate_limit: Option<Instant>,
    consecutive_server_errors: u32,
    last_server_error: Option<Instant>,
}

impl BreakerState {
    fn record(&mut self, outcome: &Outcome, now: Instant) {
        let Outcome::Status { status, .. } = outcome else {
            return;
        };
        if *status == 429 {
            self.consecutive_rate_limits += 1;
            self.last_rate_limit = Some(now);
        } else {
            self.consecutive_rate_limits = 0;
            if *status >= 500 {
                self.consecutive_server_errors += 1;
                self.last_server_error = Some(now);
            } else {
                self.consecutive_server_errors = 0;
            }
        }
    }

    /// The error to fail with while a breaker is open.
    fn open_breaker(&self, policy: &RetryPolicy, now: Instant) -> Option<ApiError> {
        let open = |count: u32, threshold: u32, last: Option<Instant>, cool_down: Duration| {
            count >= threshold && last.is_some_and(|at| now.duration_since(at) < cool_down)
        };
        if open(
            self.consecutive_rate_limits,
            policy.rate_limit_breaker_threshold,
            self.last_rate_limit,
            policy.rate_limit_cool_down,
        ) {
            let mut error = ApiError::from_http(
                reqwest::StatusCode::TOO_MANY_REQUESTS,
                &reqwest::header::HeaderMap::new(),
                "Too many server requests, please try again later",
            );
            error.retry_after = self.last_rate_limit.map(|at| {
                policy
                    .rate_limit_cool_down
                    .saturating_sub(now.duration_since(at))
            });
            return Some(error);
        }
        if open(
            self.consecutive_server_errors,
            policy.server_error_breaker_threshold,
            self.last_server_error,
            policy.server_error_cool_down,
        ) {
            return Some(ApiError::from_http(
                reqwest::StatusCode::SERVICE_UNAVAILABLE,
                &reqwest::header::HeaderMap::new(),
                "Too many server errors, please try again later",
            ));
        }
        None
    }
}

/// `reqwest_middleware` layer applying [`RetryPolicy`] to Drive API calls.
///
/// Requests whose body cannot be cloned (streams) are sent once. While a
/// breaker is open, requests fail with an [`ApiError`] (status 429 or 503)
/// without contacting the server.
#[derive(Debug, Clone, Default)]
pub struct DriveApiRetryMiddleware {
    policy: RetryPolicy,
    state: Arc<parking_lot::Mutex<BreakerState>>,
}

impl DriveApiRetryMiddleware {
    pub fn new(policy: RetryPolicy) -> Self {
        Self {
            policy,
            state: Arc::default(),
        }
    }
}

#[async_trait::async_trait]
impl reqwest_middleware::Middleware for DriveApiRetryMiddleware {
    async fn handle(
        &self,
        request: reqwest::Request,
        extensions: &mut http::Extensions,
        next: reqwest_middleware::Next<'_>,
    ) -> reqwest_middleware::Result<reqwest::Response> {
        let method = request.method().clone();
        let mut pending = Some(request);
        let mut attempt = 0u32;
        loop {
            let request = pending.take().expect("request for the next attempt");
            if let Some(error) = self.state.lock().open_breaker(&self.policy, Instant::now()) {
                return Err(reqwest_middleware::Error::middleware(error));
            }
            let retry_copy = request.try_clone();
            let url = request.url().clone();
            let result = next.clone().run(request, extensions).await;
            attempt += 1;

            let outcome = Outcome::of(&result);
            self.state.lock().record(&outcome, Instant::now());

            let (Some(delay), Some(copy)) = (
                self.policy.retry_delay(&method, &outcome, attempt),
                retry_copy,
            ) else {
                return result;
            };
            tracing::info!(
                %method,
                %url,
                attempt,
                ?outcome,
                ?delay,
                "Retrying Drive API request"
            );
            tokio::time::sleep(delay).await;
            pending = Some(copy);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::Method;

    fn status(status: u16) -> Outcome {
        Outcome::Status {
            status,
            retry_after: None,
        }
    }

    #[test]
    fn rate_limits_are_retried_for_every_method_honouring_retry_after() {
        let policy = RetryPolicy::default();
        let throttled = Outcome::Status {
            status: 429,
            retry_after: Some(Duration::from_secs(3)),
        };
        assert_eq!(
            policy.retry_delay(&Method::POST, &throttled, 7),
            Some(Duration::from_secs(3))
        );
        assert_eq!(
            policy.retry_delay(&Method::GET, &status(429), 1),
            Some(policy.default_rate_limit_delay)
        );
    }

    #[test]
    fn server_errors_are_retried_once_and_only_when_idempotent() {
        let policy = RetryPolicy::default();
        assert_eq!(
            policy.retry_delay(&Method::GET, &status(503), 1),
            Some(policy.server_error_delay)
        );
        assert_eq!(policy.retry_delay(&Method::GET, &status(503), 2), None);
        assert_eq!(policy.retry_delay(&Method::POST, &status(500), 1), None);
        assert_eq!(policy.retry_delay(&Method::GET, &status(404), 1), None);
        assert_eq!(policy.retry_delay(&Method::GET, &status(200), 1), None);
    }

    #[test]
    fn timeouts_and_connection_failures_are_bounded() {
        let policy = RetryPolicy::default();
        assert!(
            policy
                .retry_delay(&Method::GET, &Outcome::Timeout, 2)
                .is_some()
        );
        assert!(
            policy
                .retry_delay(&Method::GET, &Outcome::Timeout, 3)
                .is_none()
        );
        assert!(
            policy
                .retry_delay(&Method::POST, &Outcome::Timeout, 1)
                .is_none()
        );
        assert!(
            policy
                .retry_delay(&Method::POST, &Outcome::Connection, 1)
                .is_some()
        );
        assert!(
            policy
                .retry_delay(&Method::POST, &Outcome::Connection, 3)
                .is_none()
        );
        assert!(
            policy
                .retry_delay(&Method::GET, &Outcome::Other, 1)
                .is_none()
        );
    }

    #[test]
    fn rate_limit_breaker_opens_after_threshold_and_closes_after_cool_down() {
        let policy = RetryPolicy {
            rate_limit_breaker_threshold: 3,
            ..RetryPolicy::default()
        };
        let mut state = BreakerState::default();
        let start = Instant::now();
        for _ in 0..2 {
            state.record(&status(429), start);
        }
        assert!(state.open_breaker(&policy, start).is_none());
        state.record(&status(429), start);
        let error = state.open_breaker(&policy, start).expect("open");
        assert!(error.is_rate_limited());
        assert_eq!(error.retry_after, Some(policy.rate_limit_cool_down));
        assert!(
            state
                .open_breaker(&policy, start + policy.rate_limit_cool_down)
                .is_none()
        );
    }

    #[test]
    fn breakers_reset_on_success() {
        let policy = RetryPolicy {
            server_error_breaker_threshold: 2,
            ..RetryPolicy::default()
        };
        let mut state = BreakerState::default();
        let now = Instant::now();
        state.record(&status(502), now);
        state.record(&status(200), now);
        state.record(&status(502), now);
        assert!(state.open_breaker(&policy, now).is_none());
        state.record(&status(503), now);
        assert!(
            state
                .open_breaker(&policy, now)
                .is_some_and(|e| e.is_retryable())
        );
        state.record(&Outcome::Timeout, now);
        assert!(state.open_breaker(&policy, now).is_some());
    }

    /// Serves the given raw HTTP responses in order, one per connection.
    async fn serve(responses: Vec<&'static str>) -> (String, Arc<std::sync::atomic::AtomicUsize>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = format!("http://{}/", listener.local_addr().unwrap());
        let served = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = served.clone();
        tokio::spawn(async move {
            for response in responses {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut buffer = [0u8; 4096];
                let _ = socket.read(&mut buffer).await;
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                socket.write_all(response.as_bytes()).await.unwrap();
                socket.shutdown().await.unwrap();
            }
        });
        (address, served)
    }

    fn fast_client() -> reqwest_middleware::ClientWithMiddleware {
        let policy = RetryPolicy {
            default_rate_limit_delay: Duration::ZERO,
            server_error_delay: Duration::ZERO,
            ..RetryPolicy::default()
        };
        reqwest_middleware::ClientBuilder::new(reqwest::Client::new())
            .with(DriveApiRetryMiddleware::new(policy))
            .build()
    }

    const UNAVAILABLE: &str =
        "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    const THROTTLED: &str = "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 0\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    const OK: &str = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";

    #[tokio::test]
    async fn middleware_retries_a_server_error_then_returns_success() {
        let (address, served) = serve(vec![UNAVAILABLE, OK]).await;
        let response = fast_client().get(&address).send().await.unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(served.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn middleware_retries_a_throttled_post_with_its_body() {
        let (address, served) = serve(vec![THROTTLED, OK]).await;
        let response = fast_client()
            .post(&address)
            .body("payload")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(served.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn open_breaker_fails_fast_with_a_findable_api_error() {
        let policy = RetryPolicy {
            rate_limit_breaker_threshold: 1,
            default_rate_limit_delay: Duration::ZERO,
            ..RetryPolicy::default()
        };
        let (address, served) = serve(vec![THROTTLED, OK]).await;
        let client = reqwest_middleware::ClientBuilder::new(reqwest::Client::new())
            .with(DriveApiRetryMiddleware::new(policy))
            .build();
        let error: anyhow::Error = client.get(&address).send().await.unwrap_err().into();
        assert_eq!(served.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(ApiError::find(&error).is_some_and(ApiError::is_rate_limited));
    }

    #[tokio::test]
    async fn middleware_does_not_retry_a_failed_post() {
        let (address, served) = serve(vec![UNAVAILABLE, OK]).await;
        let response = fast_client().post(&address).send().await.unwrap();
        assert_eq!(response.status(), 503);
        assert_eq!(served.load(std::sync::atomic::Ordering::SeqCst), 1);
    }
}
