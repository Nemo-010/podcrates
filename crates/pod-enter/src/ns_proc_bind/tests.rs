use super::*;
use crate::{NS_JOIN_STEP, NS_JOIN_USER_STEP, NS_PTS_STEP};

/// Only a proc whose `/proc/self` is the pid of the entry is bound: a proc
/// of a parent PID namespace shows another number, and one of a child PID
/// namespace shows none.
#[test]
fn only_the_proc_of_the_own_pid_namespace_is_bound() {
    assert!(proc_of_this_pid_namespace("4242", 4242));
    assert!(!proc_of_this_pid_namespace("4243", 4242));
    assert!(!proc_of_this_pid_namespace("1", 4242));
    assert!(!proc_of_this_pid_namespace("", 4242));
    assert!(!proc_of_this_pid_namespace("self", 4242));
}

/// The remount gives the flags of the fresh proc, and keeps a read-only
/// proc of the host read-only.
#[test]
fn the_remount_gives_the_flags_of_the_fresh_proc() {
    let f = remount_flags(false);
    for flag in [sys::MS_REMOUNT, sys::MS_BIND, sys::MS_NOSUID, sys::MS_NODEV, sys::MS_NOEXEC] {
        assert_eq!(f & flag, flag, "{flag:#x}");
    }
    assert_eq!(f & sys::MS_RDONLY, 0);
    assert_eq!(remount_flags(true) & sys::MS_RDONLY, sys::MS_RDONLY);
    assert_eq!(f & sys::MS_REC, 0, "a remount changes the top mount only");
}

/// The proc of the test process is its own: the fallback is the bind,
/// and each refusal names the fresh proc and the step after it.
#[test]
fn the_fallback_of_this_host_is_the_bind() {
    let Fallback::Bind { bind_refused, remount_refused, .. } = fallback(&Names::DEFAULT) else {
        panic!("the /proc of the test is not bound");
    };
    let b = String::from_utf8(bind_refused).unwrap();
    assert!(
        b.ends_with(
            "the namespace rung runs with no /proc: mounting proc on /proc failed with errno 1, then binding the \
             host's /proc on /proc failed with errno "
        ),
        "{b}"
    );
    let r = String::from_utf8(remount_refused).unwrap();
    assert!(r.contains("then remounting the bind of /proc nosuid, nodev and noexec failed with errno "), "{r}");
    let n = not_bound_line(&Names::DEFAULT, "is not the proc of the PID namespace of the entry");
    assert!(
        n.ends_with(
            "and the host's /proc is not the proc of the PID namespace of the entry, so the entry does not bind it\n"
        ),
        "{n}"
    );
}

/// The new steps have bytes of their own.
#[test]
fn the_steps_of_the_bind_have_bytes_of_their_own() {
    let taken = [NS_PROC_STEP, NS_PTS_STEP, NS_JOIN_STEP, NS_JOIN_USER_STEP, crate::NS_GID_MAP_STEP];
    for b in [NS_PROC_BIND_STEP, NS_PROC_REMOUNT_STEP] {
        assert!(b > crate::NS_GID_MAP_STEP && !taken.contains(&b), "{b}");
        assert!(ns_setup_step(b).is_some());
    }
    assert_ne!(NS_PROC_BIND_STEP, NS_PROC_REMOUNT_STEP);
}
