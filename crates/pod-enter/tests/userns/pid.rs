//! The PID namespace of the namespace rung (T-806, PodUtils/podvm#457), as
//! root (a PID namespace in the user namespace of the caller) and as a
//! caller with no capabilities (a PID namespace that the user namespace of
//! the rung owns). The payload is pid 2 under the init of the entry, its
//! `/proc` is a fresh proc of the namespace, it lists the processes of the
//! run alone, and a pid of the host is not there. A SIGTERM to the init
//! ends the payload; the end of the init ends each process of the
//! namespace; an exec that joins the run lands in its namespace.

use pod_enter::{Bounded, Child};

use super::*;

fn with_pid(script: &str) -> Plan {
    let mut p = plan(script, None);
    p.pid_namespace = true;
    p
}

/// As root: the test `test` as root first, then as uid 65534. As another
/// user: as this user.
pub fn as_root_then_nobody(test: &str, tag: &str, body: fn(&Path)) {
    if std::env::var_os(IMAGE).is_none() && nobody::is_root() {
        let _one = ONE.lock().unwrap_or_else(|e| e.into_inner());
        let bb = match busybox() {
            Ok(bb) => bb,
            Err(why) => return skip_line(&format!("no static busybox: {why}")),
        };
        let root = image(&bb, &format!("{tag}-root"));
        body(&root);
        let _ = fs::remove_dir_all(&root);
    }
    as_nobody(test, tag, body);
}

/// The caller as root, or with no capabilities and a user namespace.
fn caller() -> bool {
    nobody::is_root() || no_capabilities()
}

/// Each host pid of the processes under `pid`, from the `children` files
/// of `/proc`; `None` where the kernel has no such file.
fn descendants(pid: i64) -> Option<Vec<i64>> {
    let mut out = Vec::new();
    let mut next = vec![pid];
    while let Some(p) = next.pop() {
        let text = fs::read_to_string(format!("/proc/{p}/task/{p}/children")).ok()?;
        for c in text.split_whitespace().filter_map(|c| c.parse::<i64>().ok()) {
            out.push(c);
            next.push(c);
        }
    }
    Some(out)
}

/// Wait until the payload of `run` has the name `comm`.
fn wait_for(run: &Child, comm: &str) {
    for _ in 0..200 {
        let kids = descendants(run.pid).unwrap_or_default();
        if kids.iter().any(|k| fs::read_to_string(format!("/proc/{k}/comm")).is_ok_and(|c| c.trim_end() == comm)) {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

/// The payload in its PID namespace: pid 2, a fresh proc, no host pid.
pub fn hides_the_host(root: &Path) {
    if !caller() {
        return;
    }
    let dir = RootDir::open(root.to_str().unwrap()).unwrap();
    let host = std::process::id();
    let script = format!(
        "test $$ = 2 || exit 31; read p rest < /proc/self/stat; test \"$p\" = 2 || exit 32; \
         test \"$(cat /proc/1/cmdline | wc -c)\" -gt 0 || exit 33; \
         kill -0 {host} 2>/tmp/kill.err && exit 34; test -d /proc/{host} && exit 35; \
         n=$(ls /proc | grep -c '^[0-9][0-9]*$'); test \"$n\" -le 6 || exit 36; \
         grep -q ' /proc [a-z]*,nosuid,nodev,noexec' /proc/self/mountinfo || exit 37"
    );
    let mut err = Vec::new();
    let code = run_namespace(&dir, &with_pid(&script), &mut err);
    let err = String::from_utf8_lossy(&err);
    assert_eq!(code.map_err(|e| e.to_string()), Ok(0), "the payload in its PID namespace: {err}");
    assert!(!err.contains("entered chroot instead"), "{err}");
}

/// A SIGTERM to the init ends the payload, which has no handler: the init
/// gives it the signal, and exits 143. Then the end of the init ends a
/// process that the payload left in the background.
pub fn ends_with_its_init(root: &Path) {
    if !caller() {
        return;
    }
    let dir = RootDir::open(root.to_str().unwrap()).unwrap();
    let mut err = Vec::new();
    let run = spawn_namespace(&dir, &with_pid("exec sleep 60"), &mut err).unwrap();
    wait_for(&run, "sleep");
    sys::kill(run.pid, sys::SIGTERM as i64).unwrap();
    let ended = run.wait_bounded(10_000).map_err(|e| e.to_string());
    assert_eq!(ended, Ok(Bounded::Exited(143)), "{}", String::from_utf8_lossy(&err));

    let run = spawn_namespace(&dir, &with_pid("sleep 61 & exec sleep 62"), &mut err).unwrap();
    wait_for(&run, "sleep");
    std::thread::sleep(std::time::Duration::from_millis(200));
    let Some(kids) = descendants(run.pid) else {
        let _ = sys::kill(run.pid, 9);
        let _ = run.wait();
        return skip_line("the kernel has no /proc/PID/task/TID/children");
    };
    assert!(kids.len() >= 2, "the payload and its background process: {kids:?}");
    sys::kill(run.pid, 9).unwrap();
    assert_eq!(run.wait_bounded(10_000).map_err(|e| e.to_string()), Ok(Bounded::Exited(137)));
    for k in kids {
        assert!(!Path::new(&format!("/proc/{k}")).exists(), "process {k} outlived the init of its namespace");
    }
}

/// An exec that joins a run in a PID namespace lands in it: its `/proc`
/// is the proc of the run, it sees the payload of the run as pid 2, and
/// its own pid is a pid of that namespace.
pub fn a_join_lands_in_it(root: &Path) {
    if !caller() {
        return;
    }
    let dir = RootDir::open(root.to_str().unwrap()).unwrap();
    let mut err = Vec::new();
    let run = spawn_namespace(&dir, &with_pid("touch /tmp/shared && exec sleep 60"), &mut err).unwrap();
    wait_for(&run, "sleep");
    let pidfd = sys::pidfd_open(run.pid).unwrap();
    let script = "test -e /tmp/shared || exit 41; read p rest < /proc/self/stat || exit 42; \
         test \"$p\" = $$ || exit 43; test \"$p\" -gt 2 || exit 44; \
         test \"$(cat /proc/2/comm)\" = sleep || exit 45";
    let mut joined = Vec::new();
    let code = spawn_joined(&dir, &plan(script, None), pidfd, &mut joined).and_then(|c| c.wait());
    let _ = sys::close(pidfd);
    let _ = sys::kill(run.pid, 9);
    let _ = run.wait();
    let (err, joined) = (String::from_utf8_lossy(&err), String::from_utf8_lossy(&joined));
    assert!(!err.contains("entered chroot instead"), "the run fell back: {err}");
    assert_eq!(code.map_err(|e| e.to_string()), Ok(0), "the joined exec: {joined}");
    assert!(!joined.contains("does not share the mounts"), "{joined}");
}
