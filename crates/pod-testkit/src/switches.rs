//! A gate of no blocking call in a hot path (T-838, VF-3 of the ingest
//! study). A call that blocks (a read of a file, a wait on a lock, a sleep,
//! a write to a full pipe) gives up the processor: the kernel counts a
//! voluntary switch of context for the thread. [`count`] gives the
//! voluntary switches of this thread while a closure runs, so that a test
//! holds a seal, an open or one turn of a state machine to none. A switch
//! that the scheduler forces (the time slice ended) is involuntary and does
//! not count.
//!
//! Linux only (`getrusage(RUSAGE_THREAD)`); elsewhere the count is `None`.

/// The value of `f`, and the voluntary switches of context of this thread
/// while it ran; `None` where the system does not count them.
pub fn count<R>(f: impl FnOnce() -> R) -> (R, Option<u64>) {
    let before = voluntary();
    let value = f();
    let after = voluntary();
    (value, before.zip(after).map(|(b, a)| a.saturating_sub(b)))
}

#[cfg(target_os = "linux")]
fn voluntary() -> Option<u64> {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::zeroed();
    // SAFETY: `usage` is a valid place for one `rusage`, which the call
    // fills; RUSAGE_THREAD reads the counts of the calling thread.
    let rc = unsafe { libc::getrusage(libc::RUSAGE_THREAD, usage.as_mut_ptr()) };
    if rc != 0 {
        return None;
    }
    // SAFETY: the call returned 0, so it filled `usage`.
    let usage = unsafe { usage.assume_init() };
    u64::try_from(usage.ru_nvcsw).ok()
}

#[cfg(not(target_os = "linux"))]
fn voluntary() -> Option<u64> {
    None
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn a_sleep_counts_and_a_computation_does_not() {
        let ((), slept) = count(|| std::thread::sleep(std::time::Duration::from_millis(2)));
        assert!(slept.unwrap() >= 1, "a sleep gives up the processor");
        let (sum, computed) = count(|| (0..200_000u64).map(std::hint::black_box).sum::<u64>());
        assert_eq!(sum, 199_999 * 200_000 / 2);
        assert_eq!(computed, Some(0), "a computation blocks on nothing");
    }
}
