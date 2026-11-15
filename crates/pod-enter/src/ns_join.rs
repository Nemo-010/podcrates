//! The join of the mounts of a running payload ([`crate::spawn_joined`]).
//!
//! A payload of the namespace rung in a user namespace of its own (a
//! caller with no capabilities, `ns_user`) has a mount namespace that this
//! user namespace owns. The kernel gives `setns(CLONE_NEWNS)` only to a
//! holder of `CAP_SYS_ADMIN` over that owner and in the user namespace of
//! the caller, so the caller with no capabilities gets `EPERM`. The owner
//! of a user namespace holds each capability in it: the child joins the
//! user namespace and the mount namespace in one call,
//! `setns(pidfd, CLONE_NEWUSER | CLONE_NEWNS)`. Where the payload is in
//! the user namespace of the caller (a run as root), the join is
//! `CLONE_NEWNS` alone: the kernel refuses a join of the own user
//! namespace with `EINVAL`.

use std::os::unix::fs::MetadataExt;

use pod_hostprobe::sys::{self, Errno};

use crate::entry::NS_JOIN_STEP;

/// The step byte of `setns(pidfd, CLONE_NEWUSER | CLONE_NEWNS)`.
pub const NS_JOIN_USER_STEP: u8 = 27;

/// The join, decided before the fork.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Join {
    pub(crate) pidfd: i64,
    /// The root of the run is an overlay: the landing check asks for one.
    pub(crate) overlay: bool,
    /// The payload is in a user namespace that is not the one of the
    /// caller: the child joins it too.
    pub(crate) user: bool,
}

impl Join {
    /// The join of the payload of `pidfd`. It reads the user namespaces
    /// here, before the fork.
    pub(crate) fn of(pidfd: i64, overlay: bool) -> Join {
        Join { pidfd, overlay, user: other_user_namespace(pidfd) }
    }

    /// The namespaces of the call.
    pub(crate) fn flags(&self) -> u64 {
        if self.user { sys::CLONE_NEWUSER | sys::CLONE_NEWNS } else { sys::CLONE_NEWNS }
    }

    /// The step byte of the call.
    pub(crate) fn step(&self) -> u8 {
        if self.user { NS_JOIN_USER_STEP } else { NS_JOIN_STEP }
    }

    /// In the child, first after the death signal. One call: a pidfd with
    /// several flags joins all of them, or none. Async-signal-safe.
    pub(crate) fn enter(&self) -> std::result::Result<(), (u8, Errno)> {
        sys::setns(self.pidfd, self.flags()).map(drop).map_err(|e| (self.step(), e))
    }
}

/// The pid in a `/proc/self/fdinfo` text of a pidfd, where it is a pid of
/// the PID namespace of the reader: the kernel writes 0 for a process
/// outside it and -1 for a process that ended.
pub fn fdinfo_pid(text: &str) -> Option<i64> {
    let line = text.lines().find_map(|l| l.strip_prefix("Pid:"))?;
    line.trim().parse::<i64>().ok().filter(|&p| p > 0)
}

/// The device and inode of a namespace link.
fn ns_id(path: &str) -> Option<(u64, u64)> {
    std::fs::metadata(path).ok().map(|m| (m.dev(), m.ino()))
}

/// Is the process of `pidfd` in a user namespace that is not the one of
/// this process? False where `/proc` does not tell: the join is then the
/// mount namespace alone, as before, and a refusal falls back.
pub fn other_user_namespace(pidfd: i64) -> bool {
    let fdinfo = format!("/proc/self/fdinfo/{pidfd}");
    let pid = || std::fs::read_to_string(&fdinfo).ok().as_deref().and_then(fdinfo_pid);
    let Some(p) = pid() else { return false };
    let (own, theirs) = (ns_id("/proc/self/ns/user"), ns_id(&format!("/proc/{p}/ns/user")));
    // The pid again: a process that ended between the two reads gave its
    // number free, and the link above can be the one of another process.
    let same = pid() == Some(p);
    matches!((own, theirs), (Some(a), Some(b)) if same && a != b)
}

#[cfg(test)]
mod tests;
