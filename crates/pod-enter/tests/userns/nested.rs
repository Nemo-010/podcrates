//! The ids of the plan for a caller that is uid 0 of a user namespace that
//! is not the initial one (T-787, PodUtils/podvm#452): podvm's foreground
//! run maps its caller to 0 in a user namespace of its own and then enters
//! the rung. The test starts again as uid 0 of such a namespace (over uid
//! 65534 where the test runs as root), which owns its PID namespace and its
//! proc. With `Plan::userns_ids` 1001:1001 the payload is 1001 in a nested
//! user namespace (`1001 0 1`) with no capability, on the namespace rung
//! and on the chroot rung; an exec that joins the run is 1001 too. With no
//! ids the payload stays 0. A refused nested namespace names its call, and
//! the entry does not fall back to chroot. A host root (the initial
//! namespace) keeps the payload at 0.

use super::*;

/// The ids inside of the test.
const IDS: (u32, u32) = (1001, 1001);

fn with_ids(script: &str, ids: Option<(u32, u32)>) -> Plan {
    let mut p = plan(script, Some(NAME));
    p.userns_ids = ids;
    p
}

fn initial() -> bool {
    pod_hostprobe::userns::is_initial_map(&fs::read_to_string("/proc/self/uid_map").unwrap())
}

/// As root, before the test starts again: the host root keeps the payload
/// at 0, whatever the ids of the plan. Where this root is uid 0 of another
/// user namespace (a container), the payload gets the ids.
pub fn host_root(root: &Path) {
    let dir = RootDir::open(root.to_str().unwrap()).unwrap();
    let want = if initial() { 0 } else { IDS.0 };
    let script = format!("test \"$(id -u)\" = {want} || exit 11");
    let mut err = Vec::new();
    let code = run_namespace(&dir, &with_ids(&script, Some(IDS)), &mut err);
    let err = String::from_utf8_lossy(&err);
    assert_eq!(code.map_err(|e| e.to_string()), Ok(0), "the payload of root with the ids: {err}");
}

/// The test as uid 0 of a user namespace that is not the initial one.
pub fn root_of_a_user_namespace(root: &Path) {
    assert!(nobody::is_root() && !initial(), "the test must run as uid 0 of a user namespace");
    let dir = RootDir::open(root.to_str().unwrap()).unwrap();
    let (u, g) = IDS;
    let script = format!(
        "test \"$(id -u)\" = {u} || exit 21; test \"$(id -g)\" = {g} || exit 22; \
         test \"$(stat -c %u:%g /{})\" = {u}:{g} || exit 23; \
         grep -Eq '^CapEff:[[:space:]]+0+$' /proc/self/status || exit 24; \
         grep -Eq '^CapPrm:[[:space:]]+0+$' /proc/self/status || exit 25; \
         read a b c < /proc/self/uid_map; test \"$a $b $c\" = \"{u} 0 1\" || exit 26; \
         read a b c < /proc/self/gid_map; test \"$a $b $c\" = \"{g} 0 1\" || exit 27; \
         touch /tmp/new && test \"$(stat -c %u /tmp/new)\" = {u} || exit 28; \
         test \"$(uname -n)\" = {NAME} || exit 29; test -e /tmp/of-the-image && exit 30; exit 0",
        ids::OF_THE_CALLER
    );
    let mut err = Vec::new();
    let code = run_namespace(&dir, &with_ids(&script, Some(IDS)), &mut err);
    let err = String::from_utf8_lossy(&err);
    assert_eq!(code.map_err(|e| e.to_string()), Ok(0), "the payload with the ids {u}:{g}: {err}");
    assert!(!err.contains("entered chroot instead"), "{err}");
    assert!(!err.contains("runs with no /proc"), "{err}");

    // No ids: the payload is 0 of the namespace of the caller, with its
    // capabilities, as before.
    let script = "test \"$(id -u)\" = 0 || exit 31; read a b c < /proc/self/uid_map; test \"$a\" = 0 || exit 32; \
         grep -Eq '^CapEff:[[:space:]]+0+$' /proc/self/status && exit 33; exit 0";
    let mut err = Vec::new();
    let code = run_namespace(&dir, &with_ids(script, None), &mut err);
    assert_eq!(code.map_err(|e| e.to_string()), Ok(0), "the payload with no ids: {}", String::from_utf8_lossy(&err));

    // The chroot rung: the same ids. The image has no proc there.
    let script = format!(
        "test \"$(id -u)\" = {u} || exit 41; test \"$(stat -c %u:%g /{})\" = {u}:{g} || exit 42",
        ids::OF_THE_CALLER
    );
    let mut err = Vec::new();
    let mut p = with_ids(&script, Some(IDS));
    p.hostname = None;
    let code = pod_enter::spawn(&dir, &p, &mut err).and_then(|c| c.wait());
    assert_eq!(code.map_err(|e| e.to_string()), Ok(0), "the chroot rung: {}", String::from_utf8_lossy(&err));

    joined(&dir);
    refused(&dir);
}

/// A join of a run with the ids: the exec is 1001 with no capability, also
/// with a plan that names no ids.
fn joined(dir: &RootDir) {
    let mut err = Vec::new();
    let run = spawn_namespace(dir, &with_ids("exec sleep 60", Some(IDS)), &mut err).unwrap();
    let comm = format!("/proc/{}/comm", run.pid);
    for _ in 0..200 {
        if fs::read_to_string(&comm).is_ok_and(|c| c.trim_end() == "sleep") {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let pidfd = sys::pidfd_open(run.pid).unwrap();
    let script = format!(
        "test \"$(id -u)\" = {} || exit 51; grep -Eq '^CapEff:[[:space:]]+0+$' /proc/self/status || exit 52",
        IDS.0
    );
    let mut joined = Vec::new();
    let code = spawn_joined(dir, &plan(&script, None), pidfd, &mut joined).and_then(|c| c.wait());
    let _ = sys::close(pidfd);
    let _ = sys::kill(run.pid, 9);
    let _ = run.wait();
    let (err, joined) = (String::from_utf8_lossy(&err), String::from_utf8_lossy(&joined));
    assert!(!err.contains("entered chroot instead"), "the run fell back: {err}");
    assert_eq!(code.map_err(|e| e.to_string()), Ok(0), "the joined exec: {joined}");
    assert!(!joined.contains("does not share the mounts"), "{joined}");
}

/// No user namespace for the namespace of the caller (the limit of the
/// namespace set to 0): the nested one is refused at its step, the payload
/// does not run, and the entry does not fall back to chroot as 0. The
/// limit stays: this is the last check of the process.
fn refused(dir: &RootDir) {
    fs::write("/proc/sys/user/max_user_namespaces", "0").unwrap();
    let mut err = Vec::new();
    let code = run_namespace(dir, &with_ids("exit 0", Some(IDS)), &mut err);
    let err = String::from_utf8_lossy(&err);
    let e = code.expect_err("the payload ran with no nested user namespace").to_string();
    assert!(e.contains("the ids 1001:1001 of the plan need a nested user namespace"), "{e}");
    assert!(e.contains("unshare(CLONE_NEWUSER) failed with ENOSPC (28)"), "{e}");
    assert!(!err.contains("entered chroot instead"), "{err}");
}
