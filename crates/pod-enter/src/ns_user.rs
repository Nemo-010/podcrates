//! The namespace rung of a caller with no capabilities
//! (PodUtils/podvm#406): a user namespace first, as `unshare -Ur` makes it,
//! then the steps of the rung as for root.
//!
//! The kernel gives `unshare(CLONE_NEWNS)` only to a holder of
//! `CAP_SYS_ADMIN` in its own user namespace. A caller with no capabilities
//! gets `EPERM` there, and holds each capability in a user namespace that it
//! makes. So the entry tries the rung as now, and at that `EPERM` tries it
//! again in a user namespace ([`spawn_own`]); only then does it fall back.
//!
//! In the child, first in the rung: `unshare(CLONE_NEWUSER)`, `deny` into
//! `/proc/self/setgroups`, one line in `uid_map` and in `gid_map` (the
//! effective ids of the caller to the ids of [`Plan::userns_ids`], 0 by
//! default), all of [`pod_hostprobe::userns`], the sequence of the probe
//! leg too. The maps come before each mount: a directory that the overlay
//! root makes needs a mapped owner. The files of the caller show as owned
//! by the ids inside in the payload, each other owner as the overflow id
//! (65534).
//!
//! The child holds each capability in the namespace that it makes, also
//! with ids inside that are not 0, so each mount of the rung is the same.
//! Only the caller's ids are mapped, so each file that the child makes
//! (a mount point, the root of the overlay) gets the caller's ids. The
//! `execve` of a uid that is not 0 clears the permitted and the effective
//! capabilities: the payload of a user of its image holds none.

use std::io::Write;

use pod_core::Class;
use pod_hostprobe::select::Rung;
use pod_hostprobe::sys::{self, Errno};
use pod_hostprobe::userns::{Maps, Step};

use crate::entry::{NsEntry, NsMount, ns_setup_step};
use crate::launch::spawn_with;
use crate::{Child, Error, Plan, Result, RootDir};

/// The step bytes of the user namespace, one for each call.
pub const NS_USER_STEP: u8 = 23;
pub const NS_SETGROUPS_STEP: u8 = 24;
pub const NS_UID_MAP_STEP: u8 = 25;
pub const NS_GID_MAP_STEP: u8 = 26;

/// The byte of a step of [`pod_hostprobe::userns::enter`].
pub(crate) fn step_byte(step: Step) -> u8 {
    match step {
        Step::Unshare => NS_USER_STEP,
        Step::Setgroups => NS_SETGROUPS_STEP,
        Step::UidMap => NS_UID_MAP_STEP,
        Step::GidMap => NS_GID_MAP_STEP,
    }
}

/// The name of a step byte of the user namespace, for
/// [`crate::ns_setup_step`].
pub(crate) fn step_name(byte: u8) -> Option<&'static str> {
    let step = match byte {
        NS_USER_STEP => Step::Unshare,
        NS_SETGROUPS_STEP => Step::Setgroups,
        NS_UID_MAP_STEP => Step::UidMap,
        NS_GID_MAP_STEP => Step::GidMap,
        _ => return None,
    };
    Some(step.name())
}

/// In the child, before each other step of the rung. Async-signal-safe:
/// `maps` was built before the fork.
pub(crate) fn enter(maps: &Maps) -> std::result::Result<(), (u8, Errno)> {
    pod_hostprobe::userns::enter(maps).map_err(|(step, e)| (step_byte(step), e))
}

/// Does this refusal of the rung call for the form with a user namespace?
/// Only `EPERM` of `unshare(CLONE_NEWNS)`: the answer of the kernel to a
/// caller with no `CAP_SYS_ADMIN` in its own user namespace. Each other
/// refusal has another cause, which a user namespace does not remove.
pub fn calls_for_user_namespace(step: &str, errno: Errno) -> bool {
    Some(step) == ns_setup_step(7) && errno == sys::EPERM
}

/// The refusal of the rung in its two forms, for a fallback line: the
/// first refusal, then the one in a user namespace.
pub fn both_refused(first: &str, errno: Errno, step: &str, again: Errno) -> String {
    format!(
        "{first} ({} ({})), and in a user namespace at {step} ({} ({}))",
        errno.name(),
        errno.0,
        again.name(),
        again.0
    )
}

/// The outcome of [`spawn_own`]: the child, or the refusal of the last
/// form that the entry tried, and the first refusal where the entry tried
/// the form with a user namespace after it.
pub(crate) struct Own {
    pub(crate) result: Result<Child>,
    pub(crate) first: Option<(&'static str, Errno)>,
}

/// The ids inside the user namespace of `plan`: 0 where it names none.
/// `u32::MAX` is `(uid_t)-1`, and the kernel refuses a map of it: the
/// refusal comes before the fork, not as a fallback to chroot.
pub(crate) fn userns_ids(plan: &Plan) -> Result<(u32, u32)> {
    let ids = plan.userns_ids.unwrap_or((0, 0));
    if ids.0 == u32::MAX || ids.1 == u32::MAX {
        return Err(Error::runtime(
            Class::Usage,
            format!("the ids {}:{} inside the user namespace: the kernel maps no id {}", ids.0, ids.1, u32::MAX),
        ));
    }
    Ok(ids)
}

/// Enter the namespace rung with the mounts of `mount`, and, at `EPERM` of
/// `unshare(CLONE_NEWNS)`, again in a user namespace of its own. `banner`
/// is the banner of the first try; the second try writes none.
pub(crate) fn spawn_own(root: &RootDir, plan: &Plan, mount: &mut NsMount, banner: bool, err: &mut dyn Write) -> Own {
    let ids = match userns_ids(plan) {
        Ok(ids) => ids,
        Err(e) => return Own { result: Err(e), first: None },
    };
    let word = Rung::Namespace.word();
    match spawn_with(root, plan, word, None, None, None, Some(NsEntry::Own(mount)), banner, err) {
        Err(Error::NsSetup { step, errno }) if calls_for_user_namespace(step, errno) => {
            mount.user = Some(Maps::of_caller_inside(ids));
            mount.devices = Some(crate::ns_dev_bind::devices(root, &plan.names));
            let result = spawn_with(root, plan, word, None, None, None, Some(NsEntry::Own(mount)), false, err);
            Own { result, first: Some((step, errno)) }
        }
        result => Own { result, first: None },
    }
}

#[cfg(test)]
mod tests;
