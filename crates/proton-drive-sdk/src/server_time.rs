//! Keeps the crypto time in sync with the API.
//!
//! Without it, keys and signatures are dated by the device clock. A device
//! clock ahead of the server produces keys from the future that the API
//! rejects as invalid. Like upstream's `updateServerTime`, the offset is shared
//! by every client in the process.

use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use proton_rpgp::{CheckUnixTime, UnixTime};

/// Server time minus device time, in seconds.
static OFFSET_SECONDS: AtomicI64 = AtomicI64::new(0);

/// The smallest change of the offset that a response may make.
const MIN_OFFSET_CHANGE_SECONDS: u64 = 2;

fn device_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default()
}

/// Records the server time reported by an API response.
pub fn update(server_unix_seconds: i64) {
    let observed = server_unix_seconds.saturating_sub(device_now());
    // Decided against the stored offset, even under concurrent updates; `Err` means kept.
    let _ = OFFSET_SECONDS.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        adopted_offset(current, observed)
    });
}

/// The offset to store after observing `observed`, or `None` to keep `current`.
///
/// Whole-second clocks read ±1 s off across a second boundary; adopting that
/// could date a signature before its new key, which rPGP rejects.
fn adopted_offset(current: i64, observed: i64) -> Option<i64> {
    (observed.abs_diff(current) >= MIN_OFFSET_CHANGE_SECONDS).then_some(observed)
}

/// Server time from `x-pm-date`, falling back to `Date`, in Unix seconds.
fn server_time_from_headers(headers: &http::HeaderMap) -> Option<i64> {
    let parse = |name: &str| {
        let value = headers.get(name)?.to_str().ok()?;
        chrono::DateTime::parse_from_rfc2822(value)
            .or_else(|_| chrono::DateTime::parse_from_rfc3339(value))
            .ok()
    };
    parse("x-pm-date")
        .or_else(|| parse("date"))
        .map(|date| date.timestamp())
}

/// Updates the server time from `x-pm-date`, falling back to `Date`.
pub fn update_from_headers(headers: &http::HeaderMap) {
    if let Some(server_time) = server_time_from_headers(headers) {
        update(server_time);
    }
}

/// The current server time in Unix seconds.
pub fn now_unix_seconds() -> i64 {
    device_now() + OFFSET_SECONDS.load(Ordering::Relaxed)
}

/// The current server time, for dating new keys.
pub fn now() -> UnixTime {
    UnixTime::new(now_unix_seconds().max(0) as u64)
}

/// The current server time, for signing and encrypting.
pub fn check_now() -> CheckUnixTime {
    now().into()
}

/// Updates the server time from every API response.
pub struct ServerTimeMiddleware;

#[async_trait::async_trait]
impl reqwest_middleware::Middleware for ServerTimeMiddleware {
    async fn handle(
        &self,
        request: reqwest::Request,
        extensions: &mut http::Extensions,
        next: reqwest_middleware::Next<'_>,
    ) -> reqwest_middleware::Result<reqwest::Response> {
        let response = next.run(request, extensions).await?;
        update_from_headers(response.headers());
        Ok(response)
    }
}

/// Wraps an HTTP client so its responses keep the crypto time in sync.
pub fn client_with_server_time(
    client: reqwest::Client,
) -> reqwest_middleware::ClientWithMiddleware {
    reqwest_middleware::ClientBuilder::new(client)
        .with(ServerTimeMiddleware)
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The offset stored after each observation in turn, from the initial 0.
    fn offset_after(observations: &[i64]) -> i64 {
        observations.iter().fold(0, |current, &observed| {
            adopted_offset(current, observed).unwrap_or(current)
        })
    }

    #[test]
    fn one_second_jitter_is_ignored() {
        assert_eq!(adopted_offset(0, -1), None);
        assert_eq!(adopted_offset(0, 1), None);
        assert_eq!(adopted_offset(0, 0), None);
        assert_eq!(adopted_offset(-30, -29), None);
        assert_eq!(adopted_offset(-30, -31), None);
    }

    #[test]
    fn a_change_of_two_seconds_or_more_is_adopted() {
        assert_eq!(adopted_offset(0, 2), Some(2));
        assert_eq!(adopted_offset(0, -2), Some(-2));
        assert_eq!(adopted_offset(5, 3), Some(3));
        assert_eq!(adopted_offset(0, 3_600), Some(3_600));
        assert_eq!(adopted_offset(i64::MIN, i64::MAX), Some(i64::MAX));
    }

    #[test]
    fn alternating_jitter_around_zero_keeps_the_offset() {
        assert_eq!(offset_after(&[0, -1, 0, -1, 0, -1]), 0);
        assert_eq!(offset_after(&[-1, 0, -1, 1, 0]), 0);
    }

    #[test]
    fn a_large_offset_is_adopted_first_then_jitter_around_it_is_ignored() {
        assert_eq!(offset_after(&[-120]), -120);
        assert_eq!(offset_after(&[-120, -121, -120, -119, -121]), -120);
        assert_eq!(offset_after(&[-120, -121, -118]), -118);
        assert_eq!(offset_after(&[-120, 0]), 0);
    }

    #[test]
    fn server_time_prefers_pm_date_then_date_and_ignores_invalid_values() {
        let mut headers = http::HeaderMap::new();
        headers.insert("date", "Wed, 21 Oct 2015 07:28:00 GMT".parse().unwrap());
        assert_eq!(server_time_from_headers(&headers), Some(1_445_412_480));

        headers.insert(
            "x-pm-date",
            "Thu, 22 Oct 2015 07:28:00 GMT".parse().unwrap(),
        );
        assert_eq!(server_time_from_headers(&headers), Some(1_445_498_880));

        let mut invalid = http::HeaderMap::new();
        invalid.insert("date", "not a date".parse().unwrap());
        assert_eq!(server_time_from_headers(&invalid), None);
    }
}
