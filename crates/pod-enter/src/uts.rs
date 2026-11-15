//! The host name of the payload on the namespace rung: a UTS namespace of
//! its own and `sethostname(2)` before the exec (PodUtils/podvm#403). The
//! release, the version and the machine of `uname` stay the host's.

use pod_core::Class;
use pod_hostprobe::sys::{self, CBuf};

use crate::{Error, Plan, Result};

/// The step byte of a refused `unshare(CLONE_NEWUTS)`.
pub const NS_UTS_STEP: u8 = 21;
/// The step byte of a refused `sethostname(2)`.
pub const NS_HOSTNAME_STEP: u8 = 22;
/// `HOST_NAME_MAX` of Linux: the nodename field holds 64 bytes and a NUL.
pub const MOST: usize = 64;

/// The host name of `plan` as the child gives it to the kernel, checked
/// before the fork: not empty, at most [`MOST`] bytes, no NUL.
pub(crate) fn checked(plan: &Plan) -> Result<Option<CBuf>> {
    let Some(name) = &plan.hostname else { return Ok(None) };
    let refuse = |why: &str| Error::runtime(Class::Usage, format!("the host name {name:?} {why}"));
    if name.is_empty() {
        return Err(refuse("is empty"));
    }
    if name.len() > MOST {
        return Err(refuse(&format!("has {} bytes; the kernel takes at most {MOST}", name.len())));
    }
    CBuf::new(name).map(Some).ok_or_else(|| refuse("contains a NUL byte"))
}

/// A plan with a host name enters only a mount namespace of its own: a
/// chroot, a join or the entry with no chroot has no UTS namespace, and the
/// payload would see the host's name.
pub(crate) fn refuse_without_namespace(plan: &Plan, entry: &str) -> Result<()> {
    match &plan.hostname {
        Some(name) => Err(Error::runtime(
            Class::Unsupported,
            format!("the host name {name:?} needs the namespace rung; {entry} has no UTS namespace of its own"),
        )),
        None => Ok(()),
    }
}

/// In the child, after the mount namespace: a UTS namespace, then the
/// name. Async-signal-safe: `name` was built before the fork.
pub(crate) fn enter(name: &CBuf, bytes: usize) -> std::result::Result<(), (u8, sys::Errno)> {
    sys::unshare(sys::CLONE_NEWUTS).map_err(|e| (NS_UTS_STEP, e))?;
    // SAFETY: `name` is a buffer of `bytes` bytes that lives past the call.
    unsafe { sys::sys(sys::SYS_SETHOSTNAME, [name.ptr(), bytes as u64, 0, 0, 0, 0]) }
        .map(drop)
        .map_err(|e| (NS_HOSTNAME_STEP, e))
}

#[cfg(test)]
mod tests;
