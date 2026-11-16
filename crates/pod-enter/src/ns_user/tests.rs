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

fn plan(ids: Option<(u32, u32)>) -> Plan {
    Plan {
        argv: vec!["/bin/true".to_string()],
        env: Vec::new(),
        working_dir: "/".to_string(),
        fds: crate::Fds::default(),
        banner: String::new(),
        path_dirs: vec!["/bin".to_string()],
        names: crate::Names::DEFAULT,
        limits: Vec::new(),
        no_new_privs: false,
        die_with_parent: false,
        confine: None,
        hostname: None,
        volumes: Vec::new(),
        userns_ids: ids,
    }
}

/// A plan with no ids maps to 0, as the probe legs; a plan with ids maps
/// the caller to them, one line each; `u32::MAX` is refused before the
/// fork with its value.
#[test]
fn the_ids_of_the_plan_are_the_ids_inside() {
    let line = |ids| {
        let m = Maps::of_caller_inside(userns_ids(&plan(ids)).unwrap());
        (String::from_utf8(m.uid_line().to_vec()).unwrap(), String::from_utf8(m.gid_line().to_vec()).unwrap())
    };
    let leg = Maps::of_caller();
    let zero = line(None);
    assert_eq!((zero.0.as_bytes(), zero.1.as_bytes()), (leg.uid_line(), leg.gid_line()));
    assert!(zero.0.starts_with("0 ") && zero.0.ends_with(" 1\n"), "{}", zero.0);
    let user = line(Some((1001, 1002)));
    let caller = |l: &str| l.split(' ').nth(1).unwrap().to_string();
    assert_eq!(user.0, format!("1001 {} 1\n", caller(&zero.0)));
    assert_eq!(user.1, format!("1002 {} 1\n", caller(&zero.1)));
    for bad in [(u32::MAX, 1001), (1001, u32::MAX)] {
        let e = userns_ids(&plan(Some(bad))).unwrap_err().to_string();
        assert!(e.contains("the kernel maps no id 4294967295"), "{e}");
    }
}
