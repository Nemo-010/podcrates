use std::path::{Path, PathBuf};

use super::*;

/// A made-up hierarchy: the cgroup of a systemd user session, with the
/// delegated `user@1000.service` and an `app.slice` under it.
fn tree(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("pod-hostprobe-cgroup-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let user = root.join("user.slice/user-1000.slice/user@1000.service");
    let scope = user.join("app.slice/run.scope");
    std::fs::create_dir_all(&scope).unwrap();
    std::fs::write(root.join("cgroup.controllers"), "cpuset cpu io memory hugetlb pids rdma misc\n").unwrap();
    std::fs::write(user.join("cgroup.controllers"), "cpu memory pids\n").unwrap();
    std::fs::write(user.join("cgroup.subtree_control"), "cpu memory pids\n").unwrap();
    std::fs::write(scope.join("cgroup.controllers"), "memory pids\n").unwrap();
    root
}

const MEMBERSHIP: &str = "0::/user.slice/user-1000.slice/user@1000.service/app.slice/run.scope\n";

/// The write test of a made-up tree: only the directories under `at`.
fn writable_under(at: PathBuf) -> impl Fn(&Path) -> Result<(), Errno> {
    move |d: &Path| if d.starts_with(&at) { Ok(()) } else { Err(sys::EACCES) }
}

#[test]
fn the_nearest_writable_directory_with_each_controller_is_delegated() {
    let root = tree("ok");
    let user = root.join("user.slice/user-1000.slice/user@1000.service");
    let leg = assess(Ok(CGROUP2_SUPER_MAGIC), MEMBERSHIP, &root, &writable_under(user.clone()));
    assert_eq!(leg.own.as_deref(), Some("/user.slice/user-1000.slice/user@1000.service/app.slice/run.scope"));
    // The scope and app.slice pass the write test, but the scope lacks
    // `cpu`: the nearest writable directory is the one judged.
    assert_eq!(
        leg.verdict,
        Delegation::None(Reason::MissingControllers {
            path: user.join("app.slice/run.scope"),
            offered: vec!["memory".into(), "pids".into()],
            missing: vec!["cpu".into()],
        })
    );
    // Only the service itself writable: a delegation there.
    let only = user.clone();
    let leg = assess(Ok(CGROUP2_SUPER_MAGIC), MEMBERSHIP, &root, &move |d: &Path| {
        if d == only { Ok(()) } else { Err(sys::EACCES) }
    });
    match &leg.verdict {
        Delegation::Delegated { path, controllers, enabled } => {
            assert_eq!(path, &user);
            assert_eq!(controllers, &["cpu", "memory", "pids"]);
            assert_eq!(enabled, &["cpu", "memory", "pids"]);
        }
        other => panic!("{other:?}"),
    }
    assert!(leg.verdict.is_delegated());
    assert!(leg.verdict.words().starts_with("delegated: "), "{}", leg.verdict.words());
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn no_writable_directory_names_the_errno_of_the_own_cgroup() {
    let root = tree("ro");
    let leg = assess(Ok(CGROUP2_SUPER_MAGIC), MEMBERSHIP, &root, &|_: &Path| Err(sys::EACCES));
    let Delegation::None(Reason::NotWritable { cgroup, errno }) = &leg.verdict else { panic!("{:?}", leg.verdict) };
    assert_eq!(cgroup, &root.join(MEMBERSHIP.trim().trim_start_matches("0::/")));
    assert_eq!(*errno, sys::EACCES);
    assert!(leg.verdict.words().contains("EACCES"), "{}", leg.verdict.words());
    let _ = std::fs::remove_dir_all(&root);
}

/// The walk stops at the root: a directory above the hierarchy is never
/// tested.
#[test]
fn the_walk_never_leaves_the_root() {
    let root = tree("walk");
    let above = root.parent().unwrap().to_path_buf();
    let seen = std::cell::RefCell::new(Vec::new());
    let leg = assess(Ok(CGROUP2_SUPER_MAGIC), MEMBERSHIP, &root, &|d: &Path| {
        seen.borrow_mut().push(d.to_path_buf());
        Err(sys::EACCES)
    });
    assert!(!leg.verdict.is_delegated());
    let seen = seen.into_inner();
    assert_eq!(seen.last(), Some(&root));
    assert!(seen.iter().all(|d| d.starts_with(&root) && d != &above), "{seen:?}");
    assert_eq!(seen.len(), 6, "{seen:?}");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn cgroup_v1_and_a_missing_mount_are_named() {
    let root = Path::new("/nonexistent");
    let tmpfs = 0x0102_1994;
    let leg = assess(Ok(tmpfs), MEMBERSHIP, root, &|_: &Path| Ok(()));
    assert_eq!(leg.verdict, Delegation::None(Reason::NotCgroup2 { f_type: tmpfs }));
    assert!(leg.verdict.words().contains("not cgroup2"), "{}", leg.verdict.words());
    let leg = assess(Err(sys::ENOENT), MEMBERSHIP, root, &|_: &Path| Ok(()));
    assert_eq!(leg.verdict, Delegation::None(Reason::NoMount(sys::ENOENT)));
}

/// A line `0::` is needed, and a path with `..` is refused: it would
/// lead the walk out of the root.
#[test]
fn the_membership_is_the_clean_line_zero() {
    let root = Path::new("/nonexistent");
    for text in ["", "1:name=systemd:/user.slice\n", "0::user.slice\n", "0::/a/../../etc\n"] {
        let leg = assess(Ok(CGROUP2_SUPER_MAGIC), text, root, &|_: &Path| Ok(()));
        assert_eq!(leg.verdict, Delegation::None(Reason::NoMembership), "{text:?}");
        assert_eq!(leg.own, None, "{text:?}");
    }
    let leg = assess(Ok(CGROUP2_SUPER_MAGIC), "12:pids:/x\n0::/\n", root, &|_: &Path| Err(sys::EPERM));
    assert_eq!(leg.own.as_deref(), Some("/"));
}

/// The leg on this host: each verdict is one of the forms above, and its
/// words are one line. Where the host delegates, the directory exists.
#[test]
fn the_leg_runs_on_this_host() {
    let leg = probe();
    let words = leg.verdict.words();
    assert!(!words.contains('\n'), "{words}");
    if let Delegation::Delegated { path, .. } = &leg.verdict {
        assert!(path.is_dir(), "{words}");
    }
    eprintln!("cgroup: {words}");
}
