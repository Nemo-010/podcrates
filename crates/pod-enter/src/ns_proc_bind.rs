//! A `/proc` for the namespace rung in a user namespace (`ns_user`): a
//! recursive bind of the host's `/proc` on the `/proc` of the image.
//!
//! The kernel gives a fresh proc only to a holder of `CAP_SYS_ADMIN` over
//! the user namespace that owns the PID namespace. The rung makes no PID
//! namespace, so in its own user namespace the mount gets `EPERM`. A bind
//! needs only `CAP_SYS_ADMIN` over the mount namespace of the rung.
//!
//! What the bind shows: the processes of the PID namespace of the entry,
//! as a fresh proc of the rung as root shows them. The entry binds only a
//! proc whose `/proc/self` is its own pid ([`proc_of_this_pid_namespace`]):
//! a proc of a parent PID namespace would show more processes, and the
//! entry then keeps no `/proc`. The bind keeps the options of the host's
//! proc (`hidepid`, `subset`) and its mounts under it; the kernel locks
//! those mounts in the user namespace, so the payload cannot remove a mask
//! of a container. Each file of the proc checks the credentials of the
//! payload, which hold no capability outside its user namespace. The bind
//! is in the mount namespace of the rung, after `/` became recursively
//! private: it cannot reach the host. A remount adds `nosuid`, `nodev` and
//! `noexec`, as on the fresh proc.

use pod_hostprobe::sys::{self, CBuf};

use crate::entry::ns_setup_step;
use crate::names::Names;
use crate::ns_optional::{NS_PROC_STEP, refused_line};

/// The step byte of the bind of the host's `/proc`. It names its step but
/// never goes to the readiness pipe, as [`NS_PROC_STEP`].
pub const NS_PROC_BIND_STEP: u8 = 28;

/// The step byte of the remount of that bind, as [`NS_PROC_BIND_STEP`].
pub const NS_PROC_REMOUNT_STEP: u8 = 29;

/// What the child does where the kernel refuses the fresh proc in a user
/// namespace. Built before the fork.
pub(crate) enum Fallback {
    /// Nothing: a mount with no fallback (the bind of `/dev/pts`).
    None,
    /// The bind of the host's `/proc`, and the lines of its refusals.
    Bind { source: CBuf, empty: CBuf, remount: u64, bind_refused: Vec<u8>, remount_refused: Vec<u8> },
    /// No bind: the host's `/proc` cannot serve. The full line.
    Refused(Vec<u8>),
}

/// Is a proc whose `/proc/self` link reads `self_link` the proc of the PID
/// namespace of the process `pid`? A proc of a parent PID namespace gives
/// another number, and one of a child PID namespace gives none.
pub fn proc_of_this_pid_namespace(self_link: &str, pid: i64) -> bool {
    self_link.parse::<i64>().is_ok_and(|p| p == pid)
}

/// The flags of the remount of the bind: no set-user-ID, no device and no
/// program, and read-only where the host's proc is read-only (the kernel
/// refuses to clear a flag of a locked mount).
pub fn remount_flags(read_only: bool) -> u64 {
    let ro = if read_only { sys::MS_RDONLY } else { 0 };
    sys::MS_REMOUNT | sys::MS_BIND | sys::MS_NOSUID | sys::MS_NODEV | sys::MS_NOEXEC | ro
}

/// The host's `/proc`: read-only or not, or why the entry does not bind it.
fn host_proc() -> std::result::Result<bool, &'static str> {
    let path = CBuf::new("/proc").expect("a literal");
    let fs = sys::statfs(&path).map_err(|_| "cannot be read")?;
    if fs.f_type != sys::PROC_SUPER_MAGIC {
        return Err("is not a proc");
    }
    let link = sys::readlink(&CBuf::new("/proc/self").expect("a literal")).map_err(|_| "has no /proc/self")?;
    if !proc_of_this_pid_namespace(&link, sys::getpid()) {
        return Err("is not the proc of the PID namespace of the entry");
    }
    Ok(fs.flag(sys::ST_RDONLY) == Some(true))
}

/// The start of the line of a refused fresh proc and of the step after it.
fn then_line(names: &Names, step: u8) -> String {
    format!(
        "{}: the namespace rung runs with no /proc: {} failed with errno {}, then {} failed with errno ",
        names.product,
        ns_setup_step(NS_PROC_STEP).unwrap_or("the proc mount"),
        sys::EPERM.0,
        ns_setup_step(step).unwrap_or("the bind of /proc"),
    )
}

/// The line where the host's `/proc` cannot serve: `why` is the cause.
pub fn not_bound_line(names: &Names, why: &str) -> String {
    format!(
        "{}: the namespace rung runs with no /proc: {} failed with errno {}, and the host's /proc {why}, so the \
         entry does not bind it\n",
        names.product,
        ns_setup_step(NS_PROC_STEP).unwrap_or("the proc mount"),
        sys::EPERM.0,
    )
}

/// The fallback of the proc mount, read and built before the fork.
pub(crate) fn fallback(names: &Names) -> Fallback {
    match host_proc() {
        Ok(read_only) => Fallback::Bind {
            source: CBuf::new("/proc").expect("a literal"),
            empty: sys::cempty(),
            remount: remount_flags(read_only),
            bind_refused: then_line(names, NS_PROC_BIND_STEP).into_bytes(),
            remount_refused: then_line(names, NS_PROC_REMOUNT_STEP).into_bytes(),
        },
        Err(why) => Fallback::Refused(not_bound_line(names, why).into_bytes()),
    }
}

/// In the child, at `EPERM` of the fresh proc in a user namespace: the
/// bind, then its remount. A refused remount removes the bind, so the
/// payload never holds a proc without the flags. No allocation.
pub(crate) fn bind(f: &Fallback, target: &CBuf) {
    match f {
        Fallback::None => {}
        Fallback::Refused(line) => {
            let _ = sys::write(2, line);
        }
        Fallback::Bind { source, empty, remount, bind_refused, remount_refused } => {
            if let Err(e) = sys::mount(source, target, empty, sys::MS_BIND | sys::MS_REC) {
                return refused_line(bind_refused, e);
            }
            if let Err(e) = sys::mount(empty, target, empty, *remount) {
                let _ = sys::umount_detach(target);
                refused_line(remount_refused, e);
            }
        }
    }
}

#[cfg(test)]
mod tests;
