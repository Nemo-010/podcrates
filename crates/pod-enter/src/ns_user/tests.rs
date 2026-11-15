use super::*;
use crate::{NS_JOIN_STEP, NS_PROC_STEP, NS_PTS_STEP};

/// Each call of the user namespace has its own byte, a name for the
/// fallback line, and no byte of another step.
#[test]
fn each_step_has_a_byte_and_a_name_of_its_own() {
    let bytes = [NS_USER_STEP, NS_SETGROUPS_STEP, NS_UID_MAP_STEP, NS_GID_MAP_STEP];
    for (b, s) in bytes.iter().zip([Step::Unshare, Step::Setgroups, Step::UidMap, Step::GidMap]) {
        assert_eq!(step_byte(s), *b);
        assert_eq!(ns_setup_step(*b), Some(s.name()));
    }
    assert_eq!(ns_setup_step(NS_USER_STEP), Some("unshare(CLONE_NEWUSER)"));
    assert_eq!(ns_setup_step(NS_UID_MAP_STEP), Some("writing /proc/self/uid_map"));
    // The other steps of the child: the launch (1 to 16), the overlay
    // (18 to 20), the host name (21, 22).
    let others = [
        NS_JOIN_STEP,
        NS_PROC_STEP,
        NS_PTS_STEP,
        crate::ns_overlay::NS_OVERLAY_TMPFS_STEP,
        crate::ns_overlay::NS_OVERLAY_DIRS_STEP,
        crate::ns_overlay::NS_OVERLAY_STEP,
        crate::uts::NS_UTS_STEP,
        crate::uts::NS_HOSTNAME_STEP,
        crate::confine::STEP,
    ];
    for b in bytes {
        assert!(b > 16 && !others.contains(&b), "the byte {b} is the byte of another step");
    }
    assert_eq!(step_name(27), None);
}

/// Only `EPERM` of `unshare(CLONE_NEWNS)` calls for the user namespace:
/// another errno, or a refusal at another step, has a cause that a user
/// namespace does not remove.
#[test]
fn only_eperm_of_the_mount_namespace_calls_for_a_user_namespace() {
    let newns = ns_setup_step(7).unwrap();
    assert!(calls_for_user_namespace(newns, sys::EPERM));
    assert!(!calls_for_user_namespace(newns, sys::EINVAL));
    assert!(!calls_for_user_namespace(ns_setup_step(9).unwrap(), sys::EPERM));
    assert!(!calls_for_user_namespace(ns_setup_step(NS_USER_STEP).unwrap(), sys::EPERM));
}

/// The fallback line names the two refusals, each with its errno.
#[test]
fn the_cause_names_both_refusals() {
    let c = both_refused(ns_setup_step(7).unwrap(), sys::EPERM, ns_setup_step(NS_USER_STEP).unwrap(), sys::EINVAL);
    assert_eq!(c, "unshare(CLONE_NEWNS) (EPERM (1)), and in a user namespace at unshare(CLONE_NEWUSER) (EINVAL (22))");
}
