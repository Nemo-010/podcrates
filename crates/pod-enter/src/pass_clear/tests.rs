use pod_hostprobe::sys::{self, CBuf};

use super::*;
use crate::{Fds, Names};

fn plan(pass: Vec<(i64, i64)>) -> Plan {
    Plan {
        argv: vec!["/bin/true".to_string()],
        env: Vec::new(),
        working_dir: "/".to_string(),
        fds: Fds { pass },
        banner: String::new(),
        path_dirs: vec!["/bin".to_string()],
        names: Names::DEFAULT,
        limits: Vec::new(),
        no_new_privs: false,
        die_with_parent: false,
        confine: None,
        hostname: None,
        volumes: Vec::new(),
    }
}

fn open_dir() -> i64 {
    let tmp = CBuf::new(std::env::temp_dir().to_str().unwrap()).unwrap();
    sys::open(&tmp, sys::O_RDONLY | sys::O_DIRECTORY | sys::O_CLOEXEC, 0).unwrap()
}

fn is_open(fd: i64) -> bool {
    sys::fstatat(fd, &sys::cempty(), sys::AT_EMPTY_PATH).is_ok()
}

/// A root descriptor on a passed number moves above each passed number;
/// the caller keeps its own; the copy closes with `Moved`.
#[test]
fn a_root_on_a_passed_number_moves_above_each_passed_number() {
    let root = open_dir();
    let p = plan(vec![(root, 0), (root + 3, 0)]);
    let mut moved = Moved::default();
    let copy = keep(&p, root, "the root file system", &mut moved).unwrap();
    assert!(copy > root + 3, "{copy} is not above {}", root + 3);
    assert!(is_open(root) && is_open(copy));
    drop(moved);
    assert!(!is_open(copy), "the copy stayed open");
    assert!(is_open(root), "the caller's descriptor closed");
    let _ = sys::close(root);
}

/// A descriptor on no passed number stays, and no copy is made.
#[test]
fn a_descriptor_on_no_passed_number_stays() {
    let root = open_dir();
    let p = plan(vec![(root + 1, 0)]);
    let mut moved = Moved::default();
    assert_eq!(keep(&p, root, "the root file system", &mut moved).unwrap(), root);
    assert!(moved.0.is_empty());
    let _ = sys::close(root);
}

/// The kind of the file names what holds the number in a refusal.
#[test]
fn the_kind_names_a_directory_and_a_pipe() {
    let root = open_dir();
    assert_eq!(kind(root), "a directory");
    let mut pipe = [0i32; 2];
    sys::pipe2(&mut pipe, sys::O_CLOEXEC).unwrap();
    assert_eq!(kind(i64::from(pipe[0])), "a pipe");
    for fd in [root, i64::from(pipe[0]), i64::from(pipe[1])] {
        let _ = sys::close(fd);
    }
    assert_eq!(kind(root), "a descriptor that fstat cannot read");
}
