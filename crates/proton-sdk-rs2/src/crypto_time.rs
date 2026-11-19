//! The time signatures are verified at.
//!
//! Signatures are dated by the clock of the client that makes them, which for
//! Proton's clients is server time. Verified at a device clock that is slow, a
//! signature made in the last seconds is dated in the future, and rPGP rejects
//! it. A crate that keeps server time (`proton-drive-sdk`) installs its clock
//! with [`set_source`]; until then the device clock is used.

use std::sync::OnceLock;

use proton_rpgp::CheckUnixTime;

static SOURCE: OnceLock<fn() -> CheckUnixTime> = OnceLock::new();

/// Installs the clock that [`check_now`] reads. The first source installed
/// stays for the life of the process; later calls change nothing.
pub fn set_source(source: fn() -> CheckUnixTime) {
    let _ = SOURCE.set(source);
}

/// The time to verify signatures at: the installed source's, else the device
/// clock.
pub fn check_now() -> CheckUnixTime {
    SOURCE
        .get()
        .map_or_else(CheckUnixTime::enable_now, |source| source())
}
