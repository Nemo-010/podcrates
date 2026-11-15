//! The namespace rung for a caller with no capabilities
//! (PodUtils/podvm#406): the entry makes a user namespace that maps the
//! caller to 0, then its mount and UTS namespaces, and does not fall back
//! to chroot. The payload sees uid 0, the name of the plan, a `/tmp` that
//! is not the `/tmp` of the image, and a `/proc` (a bind of the host's,
//! T-672). An exec that joins the run sees the `/tmp` of the run (T-671).
//! The device nodes of the host replace the regular files of the image
//! (T-688).
//!
//! As root, the test makes the image and starts its own binary again as
//! uid and gid 65534 with no groups (`pod_testkit::nobody`). The image is
//! a static `busybox` of the host (`PODVM_T486_BUSYBOX`, or `/bin/busybox`
//! where it is static). Where the host has none, where the kernel gives
//! such a caller no user namespace that takes a mount, or where uid 65534
//! cannot reach the binary, the test says `skipping` and passes:
//! `scripts/ci/userns-tests.sh` fails on that line.
#![cfg(target_os = "linux")]

use std::fs;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use pod_enter::{Fds, Names, Plan, RootDir, run_namespace, spawn_joined, spawn_namespace};
use pod_hostprobe::sys;
use pod_testkit::host::skip_line;
use pod_testkit::nobody;

const NAME: &str = "unit2";
/// The image that the root parent made for the child of uid 65534.
const IMAGE: &str = "POD_ENTER_USERNS_IMAGE";

fn busybox() -> Result<PathBuf, String> {
    let p = std::env::var_os("PODVM_T486_BUSYBOX").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("/bin/busybox"));
    let mut head = [0u8; 4096];
    let n = fs::File::open(&p).and_then(|mut f| f.read(&mut head)).map_err(|e| format!("{}: {e}", p.display()))?;
    if [&b"ld-linux"[..], b"ld-musl"].iter().any(|ld| head[..n].windows(ld.len()).any(|w| w == *ld)) {
        return Err(format!("{} is not static", p.display()));
    }
    Ok(p)
}

/// An image with `/bin/busybox` and its applets, `/tmp` with one file of
/// the image, and an empty `/proc`.
fn image(bb: &Path, tag: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("pod-enter-userns-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    for d in ["bin", "tmp", "proc"] {
        fs::create_dir_all(root.join(d)).unwrap();
        fs::set_permissions(root.join(d), fs::Permissions::from_mode(0o755)).unwrap();
    }
    fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
    fs::write(root.join("tmp/of-the-image"), "x").unwrap();
    fs::copy(bb, root.join("bin/busybox")).unwrap();
    fs::set_permissions(root.join("bin/busybox"), fs::Permissions::from_mode(0o755)).unwrap();
    for applet in ["sh", "id", "uname", "test", "touch", "grep", "sleep", "head", "wc"] {
        std::os::unix::fs::symlink("busybox", root.join("bin").join(applet)).unwrap();
    }
    root
}

fn plan(script: &str, hostname: Option<&str>) -> Plan {
    let env = vec![format!("PATH={}", Plan::DEFAULT_PATH)];
    Plan {
        argv: vec!["/bin/sh".to_string(), "-c".to_string(), script.to_string()],
        path_dirs: Plan::path_from(&env),
        env,
        working_dir: "/".to_string(),
        fds: Fds::default(),
        banner: "the banner\n".to_string(),
        names: Names::DEFAULT,
        limits: Vec::new(),
        no_new_privs: false,
        die_with_parent: false,
        confine: None,
        hostname: hostname.map(str::to_string),
    }
}

/// As root: the image, then the test `test` again as uid 65534. As
/// another user: the test as this user.
fn as_nobody(test: &str, tag: &str, body: fn(&Path)) {
    if let Some(root) = std::env::var_os(IMAGE) {
        return body(Path::new(&root));
    }
    let bb = match busybox() {
        Ok(bb) => bb,
        Err(why) => return skip_line(&format!("no static busybox: {why}")),
    };
    let root = image(&bb, tag);
    if tag == "dev" {
        dev_of_the_image(&root);
    }
    if !nobody::is_root() {
        body(&root);
        let _ = fs::remove_dir_all(&root);
        return;
    }
    let env = [(IMAGE, root.to_str().unwrap())];
    let code = nobody::again(&[test, "--exact", "--nocapture", "--test-threads=1"], &env);
    let _ = fs::remove_dir_all(&root);
    match code {
        Ok(code) => assert_eq!(code, 0, "the test as uid {} failed", nobody::NOBODY),
        Err(why) => skip_line(&why),
    }
}

/// The caller holds no capability and gets a user namespace for the rung;
/// else a skip line.
fn no_capabilities() -> bool {
    assert_eq!(nobody::effective_caps(), Some(0), "the caller must hold no capability");
    if let Err(why) = pod_testkit::host::userns() {
        skip_line(&format!("the kernel gives this caller no user namespace for the rung: {why}"));
        return false;
    }
    true
}

#[test]
fn a_caller_with_no_capabilities_enters_the_namespace_rung() {
    as_nobody("a_caller_with_no_capabilities_enters_the_namespace_rung", "run", as_the_caller);
}

#[test]
fn a_caller_with_no_capabilities_gets_the_devices_of_the_host() {
    as_nobody("a_caller_with_no_capabilities_gets_the_devices_of_the_host", "dev", devices_of_the_host);
}

#[test]
fn a_caller_with_no_capabilities_joins_its_run() {
    as_nobody("a_caller_with_no_capabilities_joins_its_run", "join", joins_its_run);
}

/// The test as the caller with no capabilities.
fn as_the_caller(root: &Path) {
    if !no_capabilities() {
        return;
    }
    let dir = RootDir::open(root.to_str().unwrap()).unwrap();
    let active = format!("${}", Names::DEFAULT.mode_active);
    let script = format!(
        "test \"$(id -u)\" = 0 || exit 3; test \"$(uname -n)\" = {NAME} || exit 4; \
         test -e /tmp/of-the-image && exit 5; touch /tmp/new || exit 6; \
         test \"{active}\" = namespace || exit 7; test -r /proc/self/status || exit 8; \
         grep -q ' /proc [a-z]*,nosuid,nodev,noexec' /proc/self/mountinfo || exit 9"
    );
    let mut err = Vec::new();
    let code = run_namespace(&dir, &plan(&script, Some(NAME)), &mut err);
    let err = String::from_utf8_lossy(&err);
    assert_eq!(code.map_err(|e| e.to_string()), Ok(0), "the payload as uid {}: {err}", nobody::NOBODY);
    assert_eq!(err.matches("the banner").count(), 1, "the banner goes out one time: {err}");
    assert!(!err.contains("entered chroot instead"), "{err}");
    assert!(!err.contains("runs with no /proc"), "{err}");
    assert!(!root.join("tmp/new").exists(), "the write of the payload landed in the /tmp of the image");
}

/// The `/dev` of [`devices_of_the_host`], of the caller of the test: the
/// child makes the missing mount points in it.
fn dev_of_the_image(root: &Path) {
    let dev = root.join("dev");
    fs::create_dir_all(&dev).unwrap();
    fs::write(dev.join("null"), "").unwrap();
    fs::write(dev.join("random"), vec![0u8; 1 << 20]).unwrap();
    fs::write(dev.join("urandom"), vec![0u8; 1 << 20]).unwrap();
    fs::write(root.join("zero-of-the-image"), "z").unwrap();
    std::os::unix::fs::symlink("../zero-of-the-image", dev.join("zero")).unwrap();
    if nobody::is_root() {
        std::os::unix::fs::chown(&dev, Some(nobody::NOBODY), Some(nobody::NOBODY)).unwrap();
    }
}

/// The `/dev` that `pod-rootfs` leaves in a user namespace: regular files
/// (a `/dev/urandom` of 1 MiB), a missing `/dev/full` and `/dev/tty`, and
/// a link at `/dev/zero`. The payload reads more than 1 MiB of
/// `/dev/urandom`, `/dev/null` is a character device, a write to
/// `/dev/full` fails with `ENOSPC`, each bind is `nosuid` and `noexec` but
/// not `nodev`, and the link stays a link.
fn devices_of_the_host(root: &Path) {
    if !no_capabilities() {
        return;
    }
    let dev = root.join("dev");
    let dir = RootDir::open(root.to_str().unwrap()).unwrap();
    let script = "test \"$(head -c 2000000 /dev/urandom | wc -c)\" = 2000000 || exit 3; \
         test \"$(head -c 2000000 /dev/random | wc -c)\" = 2000000 || exit 4; test -c /dev/null || exit 5; \
         out=$(echo x 2>&1 >/dev/full); case \"$out\" in *'No space left'*) ;; *) exit 6;; esac; \
         test -L /dev/zero || exit 7; \
         grep -Eq ' /dev/urandom [^ ]*nosuid[^ ]*noexec' /proc/self/mountinfo || exit 8; \
         grep -Eq ' /dev/(null|urandom) [^ ]*nodev' /proc/self/mountinfo && exit 9; test -c /dev/tty || exit 10";
    // The child writes the line of a skipped path to the standard error
    // of the payload: a file here.
    let lines = std::env::temp_dir().join(format!("pod-enter-userns-dev-err-{}", std::process::id()));
    let file = fs::File::create(&lines).unwrap();
    let mut plan = plan(script, None);
    plan.fds.pass.push((2, i64::from(std::os::fd::AsRawFd::as_raw_fd(&file))));
    let mut err = Vec::new();
    let code = run_namespace(&dir, &plan, &mut err);
    let (err, payload) = (String::from_utf8_lossy(&err), fs::read_to_string(&lines).unwrap_or_default());
    let _ = fs::remove_file(&lines);
    assert_eq!(code.map_err(|e| e.to_string()), Ok(0), "the payload as uid {}: {err}{payload}", nobody::NOBODY);
    assert!(!err.contains("entered chroot instead"), "{err}");
    assert!(payload.contains("keeps the image's /dev/zero: the image holds a symbolic link"), "{payload}");
    assert_eq!(payload.matches("keeps the image's").count(), 1, "one line, for the link: {payload}");
    assert_eq!(fs::read(dev.join("urandom")).unwrap().len(), 1 << 20, "the bind wrote into the image");
}

/// A run that writes `/tmp/shared` and sleeps, then an exec that joins it
/// as the same caller: the exec sees the file of the run and uid 0, and
/// does not fall back to a mount namespace of its own.
fn joins_its_run(root: &Path) {
    if !no_capabilities() {
        return;
    }
    let dir = RootDir::open(root.to_str().unwrap()).unwrap();
    let mut err = Vec::new();
    let run = spawn_namespace(&dir, &plan("touch /tmp/shared && exec sleep 60", None), &mut err).unwrap();
    // The exec of `sleep` comes after the write of the file.
    let comm = format!("/proc/{}/comm", run.pid);
    for _ in 0..200 {
        if fs::read_to_string(&comm).is_ok_and(|c| c.trim_end() == "sleep") {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let pidfd = sys::pidfd_open(run.pid).unwrap();
    let active = format!("${}", Names::DEFAULT.mode_active);
    let script = format!(
        "test -e /tmp/shared || exit 3; test \"$(id -u)\" = 0 || exit 4; test \"{active}\" = namespace || exit 5"
    );
    let mut joined = Vec::new();
    let code = spawn_joined(&dir, &plan(&script, None), pidfd, &mut joined).and_then(|c| c.wait());
    let _ = sys::close(pidfd);
    let _ = sys::kill(run.pid, 9);
    let _ = run.wait();
    let (err, joined) = (String::from_utf8_lossy(&err), String::from_utf8_lossy(&joined));
    assert!(!err.contains("entered chroot instead"), "the run fell back: {err}");
    assert_eq!(code.map_err(|e| e.to_string()), Ok(0), "the joined exec as uid {}: {joined}", nobody::NOBODY);
    assert!(!joined.contains("does not share the mounts"), "{joined}");
}
