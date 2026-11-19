//! Keeps the crypto time in sync with the API.
//!
//! Without it, keys and signatures are dated by the device clock. A device
//! clock ahead of the server produces keys from the future that the API
//! rejects as invalid. Like upstream's `updateServerTime`, the offset is shared
//! by every client in the process.
//!
//! The crypto time does not go backwards (as C#'s `CryptographyTimeProvider`,
//! which keeps the latest `Date` seen): a change of the offset or of the device
//! clock could otherwise date a signature before the key that makes it, which
//! rPGP rejects. Unlike C#, the floor is bounded: it holds the time at most
//! [`MAX_FLOOR_LEAD_SECONDS`] ahead of device time plus offset, so one answer
//! with a far-future `Date` cannot pin the crypto time ahead for the rest of
//! the process; the next answer with the right time brings it back.

use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use proton_rpgp::{CheckUnixTime, UnixTime};

/// The process-wide crypto clock.
static CLOCK: CryptoClock = CryptoClock::new();

/// The smallest change of the offset that a response may make.
const MIN_OFFSET_CHANGE_SECONDS: u64 = 2;

/// The furthest the floor may hold the crypto time ahead of device time plus
/// offset. A larger step back moves the crypto time back with it.
const MAX_FLOOR_LEAD_SECONDS: i64 = 60;

fn device_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default()
}

/// Server time as the offset from the device clock, never returned earlier
/// than the last time returned within the floor's bound.
struct CryptoClock {
    /// Server time minus device time, in seconds.
    offset: AtomicI64,
    /// The latest time returned, in Unix seconds.
    floor: AtomicI64,
}

impl CryptoClock {
    const fn new() -> Self {
        Self {
            offset: AtomicI64::new(0),
            floor: AtomicI64::new(i64::MIN),
        }
    }

    /// Records `server` seen at device time `device`.
    fn update_at(&self, server: i64, device: i64) {
        let observed = server.saturating_sub(device);
        // Decided against the stored offset, even under concurrent updates; `Err` means kept.
        let _ = self
            .offset
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                adopted_offset(current, observed)
            });
    }

    /// The crypto time at device time `device`, raising the floor to it.
    fn now_at(&self, device: i64) -> i64 {
        let base = device.saturating_add(self.offset.load(Ordering::Relaxed));
        let mut time = base;
        let previous = self
            .floor
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |floor| {
                time = floored(floor, base);
                (time != floor).then_some(time)
            });
        if let Ok(floor) = previous
            && time < floor
        {
            tracing::warn!(
                seconds = floor.saturating_sub(time),
                "Crypto time moved back past the floor's bound"
            );
        }
        time
    }
}

/// Records the server time reported by an API response.
pub fn update(server_unix_seconds: i64) {
    CLOCK.update_at(server_unix_seconds, device_now());
}

/// The time to return at `base` (device time plus offset) after `floor`, the
/// latest time returned: `floor` while `base` is behind it by up to
/// [`MAX_FLOOR_LEAD_SECONDS`], else `base`.
fn floored(floor: i64, base: i64) -> i64 {
    if base >= floor || floor.saturating_sub(base) > MAX_FLOOR_LEAD_SECONDS {
        base
    } else {
        floor
    }
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

/// The current server time in Unix seconds, never earlier than a time
/// returned before unless the clock moved back more than
/// [`MAX_FLOOR_LEAD_SECONDS`].
pub fn now_unix_seconds() -> i64 {
    CLOCK.now_at(device_now())
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

    const DEVICE: i64 = 1_800_000_000;

    #[test]
    fn a_smaller_offset_does_not_move_the_time_back() {
        let clock = CryptoClock::new();
        assert_eq!(clock.now_at(DEVICE), DEVICE);
        // A key dated now, then an answer 5 s behind: its signature must not
        // be dated before the key.
        clock.update_at(DEVICE - 5, DEVICE);
        assert_eq!(clock.now_at(DEVICE), DEVICE);
        assert_eq!(clock.now_at(DEVICE + 3), DEVICE);
        // Moves on once device time plus offset passes the floor.
        assert_eq!(clock.now_at(DEVICE + 6), DEVICE + 1);
        assert_eq!(clock.now_at(DEVICE + 7), DEVICE + 2);
    }

    #[test]
    fn a_device_clock_stepped_back_does_not_move_the_time_back() {
        let clock = CryptoClock::new();
        assert_eq!(clock.now_at(DEVICE), DEVICE);
        assert_eq!(clock.now_at(DEVICE - 30), DEVICE);
        assert_eq!(clock.now_at(DEVICE - 29), DEVICE);
        assert_eq!(clock.now_at(DEVICE + 1), DEVICE + 1);
    }

    #[test]
    fn the_floor_holds_at_most_its_bound() {
        let clock = CryptoClock::new();
        clock.update_at(DEVICE + MAX_FLOOR_LEAD_SECONDS, DEVICE);
        assert_eq!(clock.now_at(DEVICE), DEVICE + MAX_FLOOR_LEAD_SECONDS);
        clock.update_at(DEVICE, DEVICE);
        assert_eq!(clock.now_at(DEVICE), DEVICE + MAX_FLOOR_LEAD_SECONDS);

        let clock = CryptoClock::new();
        clock.update_at(DEVICE + MAX_FLOOR_LEAD_SECONDS + 1, DEVICE);
        assert_eq!(clock.now_at(DEVICE), DEVICE + MAX_FLOOR_LEAD_SECONDS + 1);
        clock.update_at(DEVICE, DEVICE);
        assert_eq!(clock.now_at(DEVICE), DEVICE);
    }

    #[test]
    fn a_far_future_answer_does_not_pin_the_time() {
        let clock = CryptoClock::new();
        assert_eq!(clock.now_at(DEVICE), DEVICE);
        // One answer a year ahead dates what is made meanwhile a year ahead
        // (as before), and the next right answer brings the time back.
        clock.update_at(DEVICE + 365 * 86_400, DEVICE);
        assert_eq!(clock.now_at(DEVICE), DEVICE + 365 * 86_400);
        clock.update_at(DEVICE + 1, DEVICE + 1);
        assert_eq!(clock.now_at(DEVICE + 1), DEVICE + 1);
        assert_eq!(clock.now_at(DEVICE + 2), DEVICE + 2);

        let clock = CryptoClock::new();
        clock.update_at(i64::MAX, DEVICE);
        assert_eq!(clock.now_at(DEVICE), i64::MAX);
        clock.update_at(DEVICE, DEVICE);
        assert_eq!(clock.now_at(DEVICE), DEVICE);
    }

    #[test]
    fn the_floor_rule() {
        assert_eq!(floored(i64::MIN, DEVICE), DEVICE);
        assert_eq!(floored(DEVICE, DEVICE + 1), DEVICE + 1);
        assert_eq!(floored(DEVICE, DEVICE - 1), DEVICE);
        assert_eq!(floored(DEVICE, DEVICE - MAX_FLOOR_LEAD_SECONDS), DEVICE);
        assert_eq!(
            floored(DEVICE, DEVICE - MAX_FLOOR_LEAD_SECONDS - 1),
            DEVICE - MAX_FLOOR_LEAD_SECONDS - 1
        );
        assert_eq!(floored(i64::MAX, i64::MIN), i64::MIN);
    }
}
