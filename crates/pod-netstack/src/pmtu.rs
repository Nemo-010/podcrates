//! The search of the path MTU on a ladder (T-819, TR-3 of the ingest
//! study), in the manner of RFC 8899 (DPLPMTUD): the first rung is taken to
//! work, and each higher rung counts only when a probe of that size comes
//! back. A rung whose probes go unanswered [`MOST_PROBES`] times ends the
//! search at the rung below it; after [`RAISE_AFTER`] the search tries the
//! next rung again, as a path can grow. A loss of data packets at the size
//! in use (a black hole that the carrier finds) goes back to the first rung.
//!
//! The ladder is sans-IO: the carrier sends each [`Probe`] as a padded
//! packet of its own, sealed as each other packet, so a box on the path
//! cannot tell it from data, and calls [`Ladder::acked`] when its peer
//! confirms it. This module holds no socket and no clock.

use std::time::{Duration, Instant};

/// The sizes of the ladder, in bytes of the packet of the carrier.
pub const RUNGS: [u16; 4] = [1120, 1320, 1400, 1500];
/// The probes of one rung with no answer before the search ends below it.
pub const MOST_PROBES: u8 = 3;
/// How long a probe waits for its answer.
pub const PROBE_WAIT: Duration = Duration::from_secs(5);
/// How long a settled search waits before it tries the next rung again.
pub const RAISE_AFTER: Duration = Duration::from_secs(600);

/// A probe to send: `size` bytes, named by `id` in the peer's answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Probe {
    pub id: u32,
    pub size: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// A search of the rung `RUNGS[rung]`, with `sent` probes of it; the
    /// last one is out since `at` when `out` is set.
    Search { rung: usize, sent: u8, out: Option<(u32, Instant)> },
    /// No search until `until`.
    Settled { until: Instant },
}

/// The search of one path.
#[derive(Debug, Clone)]
pub struct Ladder {
    /// The index in [`RUNGS`] of the largest size that is confirmed.
    confirmed: usize,
    state: State,
    next_id: u32,
}

impl Ladder {
    /// A search from the first rung, which is taken to work.
    pub fn new() -> Ladder {
        Ladder { confirmed: 0, state: State::Search { rung: 1, sent: 0, out: None }, next_id: 1 }
    }

    /// The largest size that the path carries, as far as it is known.
    pub fn mtu(&self) -> u16 {
        RUNGS[self.confirmed]
    }

    /// Whether the search is at rest.
    pub fn settled(&self) -> bool {
        matches!(self.state, State::Settled { .. })
    }

    /// The probe to send at `now`, if any: the first of a rung, another
    /// after an unanswered one, or the next rung after [`RAISE_AFTER`].
    pub fn poll(&mut self, now: Instant) -> Option<Probe> {
        if let State::Settled { until } = self.state {
            if now < until || self.confirmed + 1 >= RUNGS.len() {
                return None;
            }
            self.state = State::Search { rung: self.confirmed + 1, sent: 0, out: None };
        }
        let State::Search { rung, sent, out } = self.state else { return None };
        if let Some((_, at)) = out
            && now.saturating_duration_since(at) < PROBE_WAIT
        {
            return None;
        }
        if sent >= MOST_PROBES {
            // Each probe of this rung went unanswered: the path stops below.
            self.state = State::Settled { until: now + RAISE_AFTER };
            return None;
        }
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1).max(1);
        self.state = State::Search { rung, sent: sent + 1, out: Some((id, now)) };
        Some(Probe { id, size: RUNGS[rung] })
    }

    /// The peer confirmed the probe `id`: its rung is confirmed, and the
    /// search goes on to the next one, or rests at the top. An answer to an
    /// old probe, or to none, changes nothing.
    pub fn acked(&mut self, id: u32, now: Instant) {
        let State::Search { rung, out: Some((out_id, _)), .. } = self.state else { return };
        if id != out_id {
            return;
        }
        self.confirmed = rung;
        self.state = if rung + 1 < RUNGS.len() {
            State::Search { rung: rung + 1, sent: 0, out: None }
        } else {
            State::Settled { until: now + RAISE_AFTER }
        };
    }

    /// The carrier lost data packets at [`Ladder::mtu`] that smaller ones
    /// pass: the path became smaller. Back to the first rung, and a new
    /// search from it.
    pub fn black_hole(&mut self) {
        *self = Ladder { next_id: self.next_id, ..Ladder::new() };
    }
}

impl Default for Ladder {
    fn default() -> Self {
        Ladder::new()
    }
}

#[cfg(test)]
#[path = "pmtu_tests.rs"]
mod tests;
