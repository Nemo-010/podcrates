//! What each road that is a dialer shares: the time left before the
//! deadline of a dial, as a road bounds each of its steps by a duration.

#![cfg_attr(
    not(any(
        feature = "via",
        feature = "forwarder",
        feature = "wisp",
        feature = "wstunnel",
        feature = "vless",
        feature = "shadowsocks"
    )),
    allow(dead_code)
)]

use std::time::Duration;

use pod_core::{Class, Failure, Stage, Target};
use tokio::time::Instant;

/// The time left before `deadline`, or a timeout of the dial of `target`
/// when none is left.
pub(crate) fn left(deadline: Instant, target: &Target) -> Result<Duration, Failure> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Err(Failure::new(Stage::Connect, Class::Timeout, format!("no time is left to dial {target}")));
    }
    Ok(left)
}

/// A dial that did not end before `deadline`.
pub(crate) fn late(target: &Target, road: &str) -> Failure {
    Failure::new(Stage::Connect, Class::Timeout, format!("the dial of {target} through {road} did not end in time"))
}
