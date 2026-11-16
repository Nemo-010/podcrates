//! The overlay root with an upper directory of the caller (T-750), as root
//! and as a caller with no capabilities, over the flagged tmpfs of
//! `volumes.rs`: the checks before the fork (the working directory and the
//! paths of the rules of the confinement) read the upper layer over the
//! image, as the payload sees them after the mount of the overlay.

use super::*;
use pod_confine::{Access, Spec};
use pod_enter::{Root, Upper, VolumeBind, run_namespace_root, spawn_joined_root, spawn_namespace_root};

/// The layers of the test: the image gets `/gone` and `/gonedir`; the
/// upper directory (on the tmpfs) holds `/only/in` and a whiteout at
/// `/gone` and at `/gonedir`. A whiteout of an unprivileged process needs
/// Linux 5.8.
fn layers(root: &Path, vols: &Path) -> (String, String) {
    fs::write(root.join("gone"), "gone").unwrap();
    fs::create_dir_all(root.join("gonedir")).unwrap();
    let (upper, work) = (vols.join("upper"), vols.join("work"));
    for d in [upper.join("only"), work.clone()] {
        fs::create_dir_all(d).unwrap();
    }
    fs::write(upper.join("only/in"), "up").unwrap();
    for w in ["gone", "gonedir"] {
        let c = sys::CBuf::new(upper.join(w).to_str().unwrap()).unwrap();
        sys::mknodat(sys::AT_FDCWD as i64, &c, sys::S_IFCHR | 0o600, 0).expect("a whiteout in the upper directory");
    }
    (upper.to_str().unwrap().to_string(), work.to_str().unwrap().to_string())
}

fn spec() -> Spec {
    Spec::new().allow("/bin", Access::READ | Access::EXECUTE).allow("/only", Access::READ | Access::WRITE)
}

/// The run of `p` on the overlay root: the exit code or the refusal, and
/// the error writer.
fn run(root: Root<'_>, p: &Plan) -> (Result<i32, String>, String) {
    let mut err = Vec::new();
    let code = run_namespace_root(root, p, &mut err).map_err(|e| e.to_string());
    (code, String::from_utf8_lossy(&err).into_owned())
}

/// The test in the process over the tmpfs.
pub fn layered(root: &Path, vols: &Path) {
    let who = if nobody::is_root() { "root" } else { "a caller with no capabilities" };
    if !nobody::is_root() && !no_capabilities() {
        return;
    }
    let (upper, work) = layers(root, vols);
    let lower = RootDir::open(root.to_str().unwrap()).unwrap();
    let overlay = Root::Overlay { lower: &lower, upper: Upper::Dir { upper: &upper, work: &work } };

    // A working directory that only the upper layer holds.
    let mut p = plan("test \"$(pwd)\" = /only || exit 21; test \"$(cat in)\" = up || exit 22; exit 0", None);
    p.working_dir = "/only".to_string();
    let (code, err) = run(overlay, &p);
    assert_eq!(code, Ok(0), "-w on a directory of the upper layer alone as {who}: {err}");

    // A rule on a directory that only the upper layer holds: accepted, and
    // it holds (a write outside the rules fails).
    let landlock = pod_confine::check();
    if let Err(e) = &landlock {
        skip_line(&format!("no Landlock for the confinement: {e}"));
    } else {
        let script = "echo w > /only/out || exit 23; echo n > /tmp/no && exit 24; exit 0";
        let mut p = plan(script, None);
        p.confine = Some(spec());
        let (code, err) = run(overlay, &p);
        assert_eq!(code, Ok(0), "a rule on a directory of the upper layer alone as {who}: {err}");
        assert_eq!(fs::read_to_string(vols.join("upper/only/out")).unwrap(), "w\n", "the write under the rule");
    }

    // A path that a whiteout of the upper layer removes: refused by name
    // before the banner, so before the fork.
    let mut p = plan("exit 0", None);
    p.working_dir = "/gonedir".to_string();
    let (code, err) = run(overlay, &p);
    assert!(code.as_ref().is_err_and(|e| e.contains("\"/gonedir\"") && e.contains("upper layer")), "{code:?}");
    assert!(!err.contains("the banner"), "the refusal of the working directory came after the banner: {err}");
    if landlock.is_ok() {
        let mut p = plan("exit 0", None);
        p.confine = Some(spec().allow("/gone", Access::READ));
        let (code, err) = run(overlay, &p);
        assert!(
            code.as_ref().is_err_and(|e| e.contains("\"/gone\"") && e.contains("does not exist")),
            "a rule on a path that a whiteout removes: {code:?}"
        );
        assert!(!err.contains("the banner"), "the refusal of the rule came after the banner: {err}");
    }

    // A volume over a directory of the upper layer wins: `/only/sub` is in
    // its host side alone, and the payload sees no `in`.
    let host = vols.join("over");
    fs::create_dir_all(host.join("sub")).unwrap();
    let mut p = plan("test -e /only/in && exit 25; test \"$(pwd)\" = /only/sub || exit 26; exit 0", None);
    p.working_dir = "/only/sub".to_string();
    p.volumes = vec![VolumeBind { host: host.to_str().unwrap().to_string(), guest: "/only".into(), read_only: false }];
    if landlock.is_ok() {
        p.confine = Some(spec().allow("/only/sub", Access::READ));
    }
    let (code, err) = run(overlay, &p);
    assert_eq!(code, Ok(0), "a volume over a directory of the upper layer as {who}: {err}");

    // An exec that joins the run checks its working directory in the same
    // view.
    let held = spawn_namespace_root(overlay, &plan("exec sleep 60", None), &mut std::io::sink()).unwrap();
    let comm = format!("/proc/{}/comm", held.pid);
    for _ in 0..200 {
        if fs::read_to_string(&comm).is_ok_and(|c| c.trim_end() == "sleep") {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let pidfd = sys::pidfd_open(held.pid).unwrap();
    let mut p = plan("test \"$(cat in)\" = up || exit 27; exit 0", None);
    p.working_dir = "/only".to_string();
    let mut joined = Vec::new();
    let code = spawn_joined_root(overlay, &p, pidfd, &mut joined).and_then(|c| c.wait()).map_err(|e| e.to_string());
    let _ = sys::close(pidfd);
    let _ = sys::kill(held.pid, 9);
    let _ = held.wait();
    let joined = String::from_utf8_lossy(&joined);
    assert_eq!(code, Ok(0), "-w of the upper layer alone in a joined exec as {who}: {joined}");
    assert!(!joined.contains("does not share the mounts"), "{joined}");
}
