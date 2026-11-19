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
//!
//! The offset is taken only from the answers of the Drive API host
//! ([`ServerTimeMiddleware::for_api`]), not from block storage or other hosts,
//! and it is bounded, since signatures are also verified at this time: a wrong
//! offset makes fresh signatures fail or future-dated ones pass.
//! - The first offset adopted after a start must be within
//!   [`MAX_FIRST_OFFSET_SECONDS`] (a day) of the device clock. A day covers a
//!   hardware clock kept in local time and a machine without time sync; a
//!   larger offset is refused with a WARN and the device clock is used.
//! - Later, a change of more than [`MAX_UNCONFIRMED_CHANGE_SECONDS`] is adopted
//!   only when a second answer confirms it (its offset within
//!   [`MIN_OFFSET_CHANGE_SECONDS`] of the first); until then the old offset
//!   stays, with a WARN. A real correction, such as NTP stepping the device
//!   clock, is confirmed by the next answer.

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

/// The largest first offset adopted after a start, either way.
pub const MAX_FIRST_OFFSET_SECONDS: u64 = 86_400;

/// The largest change of an adopted offset that one answer may make; a larger
/// one waits for a second answer that agrees.
pub const MAX_UNCONFIRMED_CHANGE_SECONDS: u64 = 60;

/// "No value" in the clock's atomics: no offset adopted, nothing pending or
/// refused. Observed offsets are clamped above it.
const NONE: i64 = i64::MIN;

fn some(value: i64) -> Option<i64> {
    (value != NONE).then_some(value)
}

fn device_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default()
}

/// Server time as the offset from the device clock, never returned earlier
/// than the last time returned within the floor's bound.
struct CryptoClock {
    /// Server time minus device time, in seconds; [`NONE`] before the first
    /// adopted answer (device time is used).
    offset: AtomicI64,
    /// A change of more than [`MAX_UNCONFIRMED_CHANGE_SECONDS`] waiting for a
    /// second answer, or [`NONE`].
    pending: AtomicI64,
    /// The last first offset refused (and warned about), or [`NONE`].
    refused: AtomicI64,
    /// The latest time returned, in Unix seconds.
    floor: AtomicI64,
}

/// What an answer does to the offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Decision {
    /// The offset stays (within a second of it); nothing is pending after.
    Keep,
    /// The offset becomes this; nothing is pending after.
    Adopt(i64),
    /// The offset stays and this change waits for a second answer.
    Hold(i64),
    /// The first offset is beyond a day; the device clock stays.
    Refuse(i64),
}

impl CryptoClock {
    const fn new() -> Self {
        Self {
            offset: AtomicI64::new(NONE),
            pending: AtomicI64::new(NONE),
            refused: AtomicI64::new(NONE),
            floor: AtomicI64::new(i64::MIN),
        }
    }

    /// The adopted offset, `None` before the first adopted answer.
    fn offset(&self) -> Option<i64> {
        some(self.offset.load(Ordering::Relaxed))
    }

    /// Records `server` seen at device time `device`.
    fn update_at(&self, server: i64, device: i64) {
        let observed = server.saturating_sub(device).max(NONE + 1);
        let pending = some(self.pending.load(Ordering::Relaxed));
        let mut decision = Decision::Keep;
        // Decided against the stored offset, even under concurrent updates; `Err` means kept.
        let _ = self
            .offset
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                decision = decide(some(current), pending, observed);
                match decision {
                    Decision::Adopt(offset) => Some(offset),
                    _ => None,
                }
            });
        match decision {
            Decision::Keep | Decision::Adopt(_) => {
                if pending.is_some() {
                    self.pending.store(NONE, Ordering::Relaxed);
                }
            }
            Decision::Hold(offset) => {
                self.pending.store(offset, Ordering::Relaxed);
                tracing::warn!(
                    offset,
                    current = self.offset(),
                    "Server time offset changed by more than {MAX_UNCONFIRMED_CHANGE_SECONDS} s; \
                     kept the old one until another answer confirms it"
                );
            }
            Decision::Refuse(offset) => {
                let previous = some(self.refused.swap(offset, Ordering::Relaxed));
                if previous.is_none_or(|previous| !agrees(previous, offset)) {
                    tracing::warn!(
                        offset,
                        "Server time is more than a day from the device clock; \
                         refused, the device clock is used"
                    );
                }
            }
        }
    }

    /// The crypto time at device time `device`, raising the floor to it.
    fn now_at(&self, device: i64) -> i64 {
        let base = device.saturating_add(self.offset().unwrap_or(0));
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

/// The adopted server time offset (server time minus device time, in
/// seconds), or `None` while no Drive API answer has been adopted and the
/// device clock is used.
pub fn offset_seconds() -> Option<i64> {
    CLOCK.offset()
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

/// Whether two offsets are the same up to the one-second jitter.
fn agrees(a: i64, b: i64) -> bool {
    a.abs_diff(b) < MIN_OFFSET_CHANGE_SECONDS
}

/// The offset to store after observing `observed`, or `None` to keep `current`.
///
/// Whole-second clocks read ±1 s off across a second boundary; adopting that
/// could date a signature before its new key, which rPGP rejects.
fn adopted_offset(current: i64, observed: i64) -> Option<i64> {
    (!agrees(observed, current)).then_some(observed)
}

/// What observing `observed` does, given the adopted offset (`None` before
/// the first) and a change pending confirmation.
fn decide(current: Option<i64>, pending: Option<i64>, observed: i64) -> Decision {
    let Some(current) = current else {
        return if observed.unsigned_abs() <= MAX_FIRST_OFFSET_SECONDS {
            Decision::Adopt(observed)
        } else {
            Decision::Refuse(observed)
        };
    };
    match adopted_offset(current, observed) {
        None => Decision::Keep,
        Some(offset)
            if offset.abs_diff(current) <= MAX_UNCONFIRMED_CHANGE_SECONDS
                || pending.is_some_and(|pending| agrees(pending, offset)) =>
        {
            Decision::Adopt(offset)
        }
        Some(offset) => Decision::Hold(offset),
    }
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

/// Updates the server time from `x-pm-date`, falling back to `Date`. For
/// answers of the Drive API host only.
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

/// A URL's scheme, host and port: whose answers they are.
type Origin = (String, Option<String>, Option<u16>);

fn origin(url: &reqwest::Url) -> Origin {
    (
        url.scheme().to_owned(),
        url.host_str().map(str::to_owned),
        url.port_or_known_default(),
    )
}

/// Updates the server time from the answers of the Drive API host.
pub struct ServerTimeMiddleware {
    api: Origin,
    clock: &'static CryptoClock,
}

impl ServerTimeMiddleware {
    /// Takes the server time from answers to requests to the scheme, host and
    /// port of `api_base_url`, the Drive API's base URL, and from no others.
    pub fn for_api(api_base_url: &reqwest::Url) -> Self {
        Self {
            api: origin(api_base_url),
            clock: &CLOCK,
        }
    }
}

#[async_trait::async_trait]
impl reqwest_middleware::Middleware for ServerTimeMiddleware {
    async fn handle(
        &self,
        request: reqwest::Request,
        extensions: &mut http::Extensions,
        next: reqwest_middleware::Next<'_>,
    ) -> reqwest_middleware::Result<reqwest::Response> {
        let from_api = origin(request.url()) == self.api;
        let response = next.run(request, extensions).await?;
        if from_api && let Some(server_time) = server_time_from_headers(response.headers()) {
            self.clock.update_at(server_time, device_now());
        }
        Ok(response)
    }
}

/// Wraps the Drive API's HTTP client, whose base URL is `api_base_url`, so its
/// answers keep the crypto time in sync. Block storage and other hosts' clients
/// are not wrapped.
pub fn client_with_server_time(
    client: reqwest::Client,
    api_base_url: &reqwest::Url,
) -> reqwest_middleware::ClientWithMiddleware {
    reqwest_middleware::ClientBuilder::new(client)
        .with(ServerTimeMiddleware::for_api(api_base_url))
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
        // A change of more than a minute, confirmed by a second answer.
        clock.update_at(DEVICE, DEVICE);
        clock.update_at(DEVICE, DEVICE);
        assert_eq!(clock.now_at(DEVICE), DEVICE);
    }

    #[test]
    fn a_far_future_offset_does_not_pin_the_time() {
        let clock = CryptoClock::new();
        clock.update_at(DEVICE, DEVICE);
        assert_eq!(clock.now_at(DEVICE), DEVICE);
        // Two answers a year ahead date what is made meanwhile a year ahead,
        // and two right answers bring the time back.
        clock.update_at(DEVICE + 365 * 86_400, DEVICE);
        clock.update_at(DEVICE + 365 * 86_400, DEVICE);
        assert_eq!(clock.now_at(DEVICE), DEVICE + 365 * 86_400);
        clock.update_at(DEVICE + 1, DEVICE + 1);
        clock.update_at(DEVICE + 1, DEVICE + 1);
        assert_eq!(clock.now_at(DEVICE + 1), DEVICE + 1);
        assert_eq!(clock.now_at(DEVICE + 2), DEVICE + 2);

        let clock = CryptoClock::new();
        clock.update_at(DEVICE, DEVICE);
        clock.update_at(i64::MAX, DEVICE);
        clock.update_at(i64::MAX, DEVICE);
        assert_eq!(clock.now_at(DEVICE), i64::MAX);
        clock.update_at(DEVICE, DEVICE);
        clock.update_at(DEVICE, DEVICE);
        assert_eq!(clock.now_at(DEVICE), DEVICE);
    }

    #[test]
    fn no_offset_before_the_first_adopted_answer() {
        let clock = CryptoClock::new();
        assert_eq!(clock.offset(), None);
        assert_eq!(clock.now_at(DEVICE), DEVICE);
        clock.update_at(DEVICE + DAY + 1, DEVICE);
        assert_eq!(clock.offset(), None);
        clock.update_at(DEVICE - 30, DEVICE);
        assert_eq!(clock.offset(), Some(-30));
    }

    /// Answers from another host than the Drive API's, such as block storage,
    /// do not move the offset.
    #[tokio::test]
    async fn answers_from_other_hosts_are_ignored() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let clock: &'static CryptoClock = Box::leak(Box::new(CryptoClock::new()));
        let api = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let storage = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = |listener: &tokio::net::TcpListener| {
            reqwest::Url::parse(&format!("http://{}/drive/", listener.local_addr().unwrap()))
                .unwrap()
        };
        let (api_url, storage_url) = (url(&api), url(&storage));
        let date = chrono::DateTime::from_timestamp(device_now() + 7_200, 0)
            .unwrap()
            .to_rfc2822();
        let serve = |listener: tokio::net::TcpListener| {
            let answer = format!(
                "HTTP/1.1 200 OK\r\nDate: {date}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = [0u8; 4096];
                let _ = stream.read(&mut request).await.unwrap();
                stream.write_all(answer.as_bytes()).await.unwrap();
            })
        };
        let client = reqwest_middleware::ClientBuilder::new(reqwest::Client::new())
            .with(ServerTimeMiddleware {
                api: origin(&api_url),
                clock,
            })
            .build();

        let server = serve(storage);
        let url = storage_url.join("block").unwrap();
        client.get(url).send().await.unwrap();
        server.await.unwrap();
        assert_eq!(clock.offset(), None, "a storage answer is ignored");

        let server = serve(api);
        client
            .get(api_url.join("shares").unwrap())
            .send()
            .await
            .unwrap();
        server.await.unwrap();
        let offset = clock.offset().expect("the Drive API's answer is adopted");
        assert!((7_198..=7_202).contains(&offset), "offset {offset}");
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

    const DAY: i64 = 86_400;

    #[test]
    fn a_first_offset_beyond_a_day_is_refused() {
        for server in [
            DEVICE + DAY + 1,
            DEVICE - DAY - 1,
            DEVICE + 365 * DAY,
            i64::MAX,
            i64::MIN,
        ] {
            let clock = CryptoClock::new();
            clock.update_at(server, DEVICE);
            assert_eq!(clock.now_at(DEVICE), DEVICE, "first answer {server}");
            // Still the first adopted offset: the next one must be within a day too.
            clock.update_at(server, DEVICE);
            assert_eq!(clock.now_at(DEVICE), DEVICE, "second answer {server}");
            assert_eq!(clock.offset(), None);
        }
    }

    #[test]
    fn a_first_offset_within_a_day_is_adopted() {
        for offset in [2 * 3_600, -2 * 3_600, DAY, -DAY] {
            let clock = CryptoClock::new();
            clock.update_at(DEVICE + offset, DEVICE);
            assert_eq!(clock.now_at(DEVICE), DEVICE + offset, "offset {offset}");
            assert_eq!(clock.offset(), Some(offset));
        }
    }

    #[test]
    fn a_jump_of_ten_minutes_is_held_until_a_second_answer_agrees() {
        let clock = CryptoClock::new();
        clock.update_at(DEVICE, DEVICE);
        clock.update_at(DEVICE + 600, DEVICE);
        assert_eq!(clock.now_at(DEVICE), DEVICE);
        // Agrees within P19's 2 s.
        clock.update_at(DEVICE + 601, DEVICE);
        assert_eq!(clock.now_at(DEVICE), DEVICE + 601);

        let clock = CryptoClock::new();
        clock.update_at(DEVICE, DEVICE);
        clock.update_at(DEVICE - 600, DEVICE);
        assert_eq!(clock.now_at(DEVICE), DEVICE);
        clock.update_at(DEVICE - 600, DEVICE);
        assert_eq!(clock.now_at(DEVICE), DEVICE - 600);
    }

    #[test]
    fn one_odd_answer_between_two_right_ones_changes_nothing() {
        let clock = CryptoClock::new();
        clock.update_at(DEVICE, DEVICE);
        clock.update_at(DEVICE + 600, DEVICE);
        clock.update_at(DEVICE, DEVICE);
        assert_eq!(clock.now_at(DEVICE), DEVICE);
        // The odd answer is no longer pending: the same one again is held.
        clock.update_at(DEVICE + 600, DEVICE);
        assert_eq!(clock.now_at(DEVICE), DEVICE);
        // A non-confirming answer replaces the pending one.
        clock.update_at(DEVICE - 900, DEVICE);
        assert_eq!(clock.now_at(DEVICE), DEVICE);
        clock.update_at(DEVICE - 900, DEVICE);
        assert_eq!(clock.now_at(DEVICE), DEVICE - 900);
    }

    #[test]
    fn changes_up_to_a_minute_follow_the_two_second_rule() {
        let clock = CryptoClock::new();
        clock.update_at(DEVICE, DEVICE);
        clock.update_at(DEVICE + 60, DEVICE);
        assert_eq!(clock.now_at(DEVICE), DEVICE + 60);
        clock.update_at(DEVICE + 61, DEVICE);
        assert_eq!(clock.now_at(DEVICE), DEVICE + 60);
        // 61 s from the adopted offset: held.
        clock.update_at(DEVICE + 121, DEVICE);
        assert_eq!(clock.now_at(DEVICE), DEVICE + 60);
    }
}
