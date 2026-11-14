//! The signal mask of the calling thread, for any set of signals.
//! `rt_sigprocmask` changes the mask of one thread, and a new thread takes
//! the mask of the thread that made it.

use super::{SIG_BLOCK, SYS_RT_SIGPROCMASK, Sysres, sys};

/// The terminal's hangup and quit signals, beside `SIGINT` and `SIGTERM`.
/// The four numbers are the same on each Linux architecture.
pub const SIGHUP: u64 = 1;
pub const SIGQUIT: u64 = 3;

/// The bit of signal number `sig` in a mask word: bit `sig - 1`.
pub const fn sigbit(sig: u64) -> u64 {
    1 << (sig - 1)
}

/// Block each signal of `set` in the calling thread, and report the earlier
/// mask in `old` for [`super::sigrestore`].
pub fn sigblock(set: u64, old: &mut u64) -> Sysres {
    unsafe { sys(SYS_RT_SIGPROCMASK, [SIG_BLOCK, &set as *const u64 as u64, old as *mut u64 as u64, 8, 0, 0]) }
}
