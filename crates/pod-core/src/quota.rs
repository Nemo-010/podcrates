//! A byte budget that reserves before a write (T-823, RT-5 of the ingest
//! study). [`crate::metered::Metered`] counts after the bytes went, so a
//! budget shared by many writers goes past its limit by the writes in
//! flight. A [`Quota`] takes the bytes first: a writer reserves, writes at
//! most what it got, then commits what it wrote; the rest goes back. A
//! reservation that is dropped with no commit gives all its bytes back, so
//! a failed or cancelled write costs nothing.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// A budget of bytes that each clone shares.
#[derive(Debug, Clone)]
pub struct Quota {
    left: Arc<AtomicU64>,
}

impl Quota {
    /// A budget of `bytes`.
    pub fn new(bytes: u64) -> Quota {
        Quota { left: Arc::new(AtomicU64::new(bytes)) }
    }

    /// The bytes that no reservation and no commit took.
    pub fn left(&self) -> u64 {
        self.left.load(Ordering::Acquire)
    }

    /// All of `bytes`, or `None` when fewer are left: nothing is taken then.
    pub fn reserve(&self, bytes: u64) -> Option<Reservation> {
        self.take(|left| (left >= bytes).then_some(bytes))
    }

    /// As many of `bytes` as are left, or `None` when none are: for a write
    /// that can be cut short.
    pub fn reserve_up_to(&self, bytes: u64) -> Option<Reservation> {
        self.take(|left| (left > 0 && bytes > 0).then(|| bytes.min(left)))
    }

    fn take(&self, want: impl Fn(u64) -> Option<u64>) -> Option<Reservation> {
        let mut got = 0;
        // One exchange takes the bytes: two writers never take the same ones.
        self.left
            .try_update(Ordering::AcqRel, Ordering::Acquire, |left| {
                got = want(left)?;
                Some(left - got)
            })
            .ok()?;
        Some(Reservation { left: self.left.clone(), held: got })
    }
}

/// Bytes taken from a [`Quota`]: [`Reservation::commit`] keeps the bytes
/// written, and a drop gives back what is held.
#[derive(Debug)]
#[must_use = "a reservation that is dropped gives its bytes back"]
pub struct Reservation {
    left: Arc<AtomicU64>,
    held: u64,
}

impl Reservation {
    /// The bytes that this reservation holds.
    pub fn bytes(&self) -> u64 {
        self.held
    }

    /// Keep `used` bytes (at most those held) and give the rest back.
    pub fn commit(mut self, used: u64) {
        self.held -= used.min(self.held);
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if self.held > 0 {
            self.left.fetch_add(self.held, Ordering::AcqRel);
        }
    }
}

#[cfg(test)]
#[path = "quota_tests.rs"]
mod tests;
