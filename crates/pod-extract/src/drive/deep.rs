//! A tree deeper than the limit of descriptors, and a tree past the depth
//! limit of the walk (T-615).
//!
//! `RLIMIT_NOFILE` belongs to the whole process, and libtest runs the tests
//! on threads of one process: the test binary starts itself again, and the
//! child lowers the limit.

use std::os::unix::fs::PermissionsExt;

use super::*;
use crate::tree::{TooDeep, Walk, too_deep};

/// The variable that makes the worker below run.
const WORKER: &str = "POD_EXTRACT_TEST_DEEP_WORKER";

/// The soft limit of descriptors in the worker, and the depth of its tree.
const NOFILE: u64 = 64;
const DEPTH: usize = 200;
/// Each directory at a multiple of this depth gets mode 0555.
const CLOSED_EACH: usize = 20;

/// A chain `d/d/...` of `depth` directories under `top`, with a file at
/// each level. Give the deepest directory.
fn chain(top: &std::path::Path, depth: usize) -> std::path::PathBuf {
    let mut p = top.to_path_buf();
    for _ in 0..depth {
        p.push("d");
    }
    std::fs::create_dir_all(&p).unwrap();
    let mut q = top.to_path_buf();
    for _ in 0..depth {
        q.push("d");
        std::fs::write(q.join("f"), b"f").unwrap();
    }
    p
}

/// The walk of `open_tree` and of the removal holds one directory open at a
/// time: a tree of 200 levels passes under a limit of 64 descriptors.
#[test]
fn a_tree_deeper_than_the_descriptor_limit_is_walked_and_removed() {
    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "drive::deep::worker_walks_under_a_low_descriptor_limit", "--nocapture"])
        .env(WORKER, "1")
        .output();
    let out = match out {
        Ok(o) => o,
        // A test binary under an emulator with no binfmt registration.
        Err(e) if e.raw_os_error() == Some(8) => {
            pod_testkit::host::skip_line(&format!("this host cannot exec the test binary as a child ({e})"));
            return;
        }
        Err(e) => panic!("the start of the worker failed: {e}"),
    };
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success() && stdout.contains("1 passed"),
        "the worker under a low descriptor limit failed:\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"
    );
}

/// The half that runs in the child. It does nothing with no [`WORKER`].
#[test]
fn worker_walks_under_a_low_descriptor_limit() {
    use pod_hostprobe::sys;
    if std::env::var_os(WORKER).is_none() {
        return;
    }
    let s = Scratch::new("deep");
    let top = s.path().join("tree");
    let deepest = chain(&top, DEPTH);
    // Closed from the deepest up: a closed parent stops no change below it
    // for root, and the owner keeps the search bit.
    let mut closed = 0u64;
    for level in (1..=DEPTH).rev() {
        if level % CLOSED_EACH == 0 {
            let mut p = top.clone();
            (0..level).for_each(|_| p.push("d"));
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o555)).unwrap();
            closed += 1;
        }
    }
    let (_, hard) = sys::prlimit(sys::rlimit::NOFILE).unwrap();
    sys::set_rlimit(sys::rlimit::NOFILE, NOFILE, hard).unwrap();

    let root = Dir::open(&top.to_string_lossy()).unwrap();
    let opened = crate::modes::open_tree(&root).expect("open_tree of a deep tree");
    drop(root);
    assert_eq!(opened, closed, "open_tree stopped before the end of the tree");
    let m = std::fs::metadata(&deepest).unwrap().permissions().mode() & 0o700;
    assert_eq!(m, 0o700, "the deepest directory did not get the owner bits");

    assert!(crate::remove_tree(&top).expect("the removal of a deep tree"));
    assert!(std::fs::symlink_metadata(&top).is_err(), "the deep tree is still there");
}

/// A tree past the depth limit of the walk is refused with the typed cause,
/// by `open_tree` and by the removal.
#[test]
fn a_tree_past_the_depth_limit_is_refused() {
    let s = Scratch::new("toodeep");
    let top = s.path().join("tree");
    chain(&top, 8);
    let root = Dir::open(&top.to_string_lossy()).unwrap();
    let e = crate::modes::open_tree_to(&root, 5).expect_err("a tree of 8 levels under a limit of 5");
    assert_eq!(too_deep(&e), Some(&TooDeep { path: "d/d/d/d/d/d".into(), limit: 5 }), "{e}");
    assert_eq!(e.class, pod_core::Class::Unsupported);
    drop(root);
    let parent = Dir::open(&s.path().to_string_lossy()).unwrap();
    let e = crate::remove::remove_at_to(parent.fd(), b"tree", 5).expect_err("a removal of 8 levels under 5");
    assert_eq!(too_deep(&e).map(|t| t.limit), Some(5), "{e}");
    assert!(top.exists(), "the refused removal removed the tree");
    assert!(crate::modes::open_tree_to(&Dir::open(&top.to_string_lossy()).unwrap(), 8).is_ok());
    assert!(crate::remove::remove_at_to(parent.fd(), b"tree", 8).unwrap());
    assert!(!top.exists());
}

/// A name that is not UTF-8 (a payload can make one) is removed by its
/// bytes: a lossy text of it names no file, and the removal of its parent
/// then fails.
#[test]
fn a_name_that_is_not_utf8_is_removed() {
    use std::os::unix::ffi::OsStrExt;
    let s = Scratch::new("notutf8");
    let top = s.path().join("tree");
    let odd = top.join(std::ffi::OsStr::from_bytes(b"x\xff"));
    std::fs::create_dir_all(odd.join(std::ffi::OsStr::from_bytes(b"\xfe"))).unwrap();
    std::fs::write(odd.join(std::ffi::OsStr::from_bytes(b"f\xfd")), b"f").unwrap();
    assert!(crate::remove_tree(&top).expect("the removal of a tree with names that are not UTF-8"));
    assert!(!top.exists());
}

/// A directory that moves during the walk stops the walk at the way up: the
/// walk does not go up through a directory that is not the level above.
#[test]
fn a_directory_that_moved_stops_the_walk() {
    let s = Scratch::new("moved");
    std::fs::create_dir_all(s.path().join("a/b")).unwrap();
    let root = Dir::open(&s.path().to_string_lossy()).unwrap();
    let mut w = Walk::of(root.fd(), 8).unwrap();
    while let Some(e) = w.next() {
        if e.name == b"a" {
            break;
        }
    }
    assert!(w.descend(b"a", crate::remove::open_closed).unwrap());
    assert!(w.descend(b"b", crate::remove::open_closed).unwrap());
    std::fs::rename(s.path().join("a/b"), s.path().join("b2")).unwrap();
    let e = w.ascend().expect_err("the way up from a directory that moved");
    assert_eq!(e.class, pod_core::Class::TempFail, "{e}");
    assert!(e.to_string().contains("moved during the walk"), "{e}");
}
