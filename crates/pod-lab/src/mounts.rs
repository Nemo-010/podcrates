//! The mount holds of a lab, in one mount namespace of the lab process: a
//! tmpfs on `/tmp`, a `/dev` with no pseudo terminal, the files of the ids,
//! a bind with `noexec` or read-only, an empty `/proc`, and a network
//! namespace.
//!
//! As root, the lab enters a mount namespace alone. As another user, it
//! enters a user namespace that maps it to 0, makes each mount, then enters
//! a second user namespace that maps it back to its own ids: the command
//! runs as its own user with no capability, as on the host. The maps of
//! the second namespace go through a descriptor of `/proc` that the lab
//! opens first, as a mount can cover `/proc`.

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;

use pod_hostprobe::sys::{self as k, CBuf};
use pod_hostprobe::userns;

use crate::hold::{c, egid, euid, words, write_once};
use crate::profile::Hold;

const CLONE_NEWNET: u64 = linux_raw_sys::general::CLONE_NEWNET as u64;

/// True where the hold is a mount of [`holds`].
pub fn is_mount(h: Hold) -> bool {
    matches!(
        h,
        Hold::Tmpfs { .. }
            | Hold::DevNoPty
            | Hold::NoPasswdEntry
            | Hold::NoexecHome
            | Hold::NoProc
            | Hold::ReadOnly { .. }
            | Hold::NetNs
    )
}

/// The order of the mounts: the binds of the files of the host first, as a
/// tmpfs can cover their source; `/proc` last, as the others use it.
fn rank(h: Hold) -> u8 {
    match h {
        Hold::NetNs => 0,
        Hold::NoPasswdEntry => 1,
        Hold::ReadOnly { .. } | Hold::NoexecHome => 2,
        Hold::DevNoPty => 3,
        Hold::Tmpfs { .. } => 4,
        _ => 5,
    }
}

/// Make each mount of `holds` in one new mount namespace. `Err` where the
/// namespace itself fails: then no hold is set. Else one result for each
/// hold, in the order of `holds`.
pub fn holds(holds: &[Hold]) -> Result<Vec<Result<(), String>>, String> {
    let (uid, gid) = (euid(), egid());
    let proc = k::open(&c("/proc")?, k::O_PATH | k::O_DIRECTORY | k::O_CLOEXEC, 0).map_err(|e| words("/proc", e))?;
    let out = (|| {
        if uid != 0 {
            userns::enter(&userns::Maps::new(uid, gid))
                .map_err(|(step, e)| format!("the user namespace of the mounts: {}", words(step.name(), e)))?;
        }
        let net = if holds.contains(&Hold::NetNs) { CLONE_NEWNET } else { 0 };
        k::unshare(k::CLONE_NEWNS | net).map_err(|e| words("unshare(CLONE_NEWNS)", e))?;
        let none = k::cempty();
        k::mount(&none, &c("/")?, &none, k::MS_REC | k::MS_PRIVATE).map_err(|e| words("mount(/, MS_PRIVATE)", e))?;
        let mut order: Vec<usize> = (0..holds.len()).collect();
        order.sort_by_key(|&i| rank(holds[i]));
        let mut each: Vec<Result<(), String>> = vec![Ok(()); holds.len()];
        // Two parts of one hold (the `/dev` of `no-ptmx`) share one mount.
        let mut done: Vec<(Hold, Result<(), String>)> = Vec::new();
        for i in order {
            each[i] = match done.iter().find(|(h, _)| *h == holds[i]) {
                Some((_, r)) => r.clone(),
                None => {
                    let r = one(holds[i], uid, gid);
                    done.push((holds[i], r.clone()));
                    r
                }
            };
        }
        if uid != 0 {
            back(proc, uid, gid)?;
        }
        Ok(each)
    })();
    let _ = k::close(proc);
    out
}

/// The second user namespace, which maps the caller back to its own ids.
fn back(proc: i64, uid: u32, gid: u32) -> Result<(), String> {
    k::unshare(k::CLONE_NEWUSER).map_err(|e| words("unshare(CLONE_NEWUSER) back to the caller", e))?;
    match write_once(proc, "self/setgroups", b"deny") {
        Ok(()) => {}
        Err(why) if why.contains("ENOENT") => {}
        Err(why) => return Err(why),
    }
    write_once(proc, "self/uid_map", format!("{uid} 0 1\n").as_bytes())?;
    write_once(proc, "self/gid_map", format!("{gid} 0 1\n").as_bytes())
}

fn one(h: Hold, uid: u32, gid: u32) -> Result<(), String> {
    match h {
        Hold::Tmpfs { size, noexec } => tmpfs(size, noexec),
        Hold::DevNoPty => dev_no_pty(),
        Hold::NoPasswdEntry => ids(uid, gid),
        Hold::NoexecHome => {
            let home = std::env::var("HOME").map_err(|_| "HOME is not set".to_string())?;
            bind_with(&home, k::MS_NOEXEC)
        }
        Hold::ReadOnly { path } => bind_with(path, k::MS_RDONLY),
        Hold::NoProc => {
            let flags = k::MS_RDONLY | k::MS_NOSUID | k::MS_NODEV | k::MS_NOEXEC;
            mount_tmpfs("/proc", flags, "size=4k,mode=555")
        }
        // The flag of `unshare` made it.
        Hold::NetNs => Ok(()),
        _ => Ok(()),
    }
}

fn mount_tmpfs(at: &str, flags: u64, data: &str) -> Result<(), String> {
    k::mount_data(&c("tmpfs")?, &c(at)?, &c("tmpfs")?, flags, &c(data)?)
        .map(|_| ())
        .map_err(|e| words(&format!("mount(tmpfs, {at})"), e))
}

/// A tmpfs on `/tmp`.
fn tmpfs(size: Option<u64>, noexec: bool) -> Result<(), String> {
    let mut data = "mode=1777".to_string();
    if let Some(n) = size {
        data.push_str(&format!(",size={n}"));
    }
    let mut flags = k::MS_NOSUID | k::MS_NODEV;
    if noexec {
        flags |= k::MS_NOEXEC;
    }
    mount_tmpfs("/tmp", flags, &data)
}

/// The flags of the mount of `path` that a remount of a bind in a user
/// namespace must keep (the kernel locks them), as flags of `mount(2)`.
fn kept_flags(path: &CBuf) -> u64 {
    const PAIRS: [(u64, u64); 7] = [
        (k::ST_RDONLY, k::MS_RDONLY),
        (k::ST_NOSUID, k::MS_NOSUID),
        (k::ST_NODEV, k::MS_NODEV),
        (k::ST_NOEXEC, k::MS_NOEXEC),
        (1024, 1024),    // ST_NOATIME, MS_NOATIME
        (2048, 2048),    // ST_NODIRATIME, MS_NODIRATIME
        (4096, 1 << 21), // ST_RELATIME, MS_RELATIME
    ];
    match k::statfs(path) {
        Ok(s) => PAIRS.iter().filter(|(st, _)| s.flag(*st) == Some(true)).fold(0, |f, (_, ms)| f | ms),
        Err(_) => 0,
    }
}

/// A bind of `path` over itself, then a remount of the bind with `add` and
/// the flags that it has.
fn bind_with(path: &str, add: u64) -> Result<(), String> {
    let p = c(path)?;
    let flags = kept_flags(&p);
    let none = k::cempty();
    k::mount(&p, &p, &none, k::MS_BIND | k::MS_REC).map_err(|e| words(&format!("mount(bind, {path})"), e))?;
    k::mount(&none, &p, &none, k::MS_BIND | k::MS_REMOUNT | flags | add)
        .map(|_| ())
        .map_err(|e| words(&format!("mount(remount, {path})"), e))
}

/// The nodes of the host that `/dev` of the lab keeps.
const NODES: [&str; 5] = ["null", "zero", "full", "random", "urandom"];

/// A tmpfs on `/dev` with the nodes of [`NODES`] bound from the host, the
/// links of the standard streams, `shm`, and a FIFO at `tty`: a read of
/// `/dev/tty` waits, and no `ptmx` or `pts` is there.
fn dev_no_pty() -> Result<(), String> {
    let mut held: Vec<(&str, i64)> = Vec::new();
    for name in NODES {
        let path = format!("/dev/{name}");
        if let Ok(fd) = k::open(&c(&path)?, k::O_PATH | k::O_CLOEXEC, 0) {
            held.push((name, fd));
        }
    }
    let out = (|| {
        mount_tmpfs("/dev", k::MS_NOSUID | k::MS_NOEXEC, "mode=755,size=64k")?;
        for &(name, fd) in &held {
            let at = format!("/dev/{name}");
            let f = k::open(&c(&at)?, k::O_WRONLY | k::O_CREAT | k::O_CLOEXEC, 0o666).map_err(|e| words(&at, e))?;
            let _ = k::close(f);
            let from = format!("/proc/self/fd/{fd}");
            k::mount(&c(&from)?, &c(&at)?, &k::cempty(), k::MS_BIND)
                .map_err(|e| words(&format!("mount(bind, {at})"), e))?;
        }
        let tty = c("/dev/tty")?;
        k::mknodat(k::AT_FDCWD as i64, &tty, k::S_IFIFO | 0o666, 0).map_err(|e| words("mknod(/dev/tty)", e))?;
        for (link, to) in [
            ("fd", "/proc/self/fd"),
            ("stdin", "/proc/self/fd/0"),
            ("stdout", "/proc/self/fd/1"),
            ("stderr", "/proc/self/fd/2"),
        ] {
            std::os::unix::fs::symlink(to, format!("/dev/{link}")).map_err(|e| format!("/dev/{link}: {e}"))?;
        }
        k::mkdir(&c("/dev/shm")?, 0o1777).map_err(|e| words("mkdir(/dev/shm)", e))?;
        // The umask of the caller takes bits from each new mode.
        use std::os::unix::fs::PermissionsExt;
        let mode = |path: &str, m: u32| {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(m)).map_err(|e| format!("{path}: {e}"))
        };
        mode("/dev/shm", 0o1777)?;
        mode("/dev/tty", 0o666)
    })();
    for (_, fd) in held {
        let _ = k::close(fd);
    }
    out
}

/// `/etc/passwd` with no line of `uid` and `/etc/group` with no line of
/// `gid`, each written into a new file of the temporary directory, bound
/// over the file of the host, then unlinked: the bind keeps the file.
fn ids(uid: u32, gid: u32) -> Result<(), String> {
    for (file, id) in [("/etc/passwd", uid), ("/etc/group", gid)] {
        let text = match std::fs::read_to_string(file) {
            Ok(t) => t,
            // No file: no line of the id.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(format!("{file}: {e}")),
        };
        let id = id.to_string();
        let kept: String =
            text.lines().filter(|l| l.split(':').nth(2) != Some(id.as_str())).map(|l| format!("{l}\n")).collect();
        let name = file.trim_start_matches("/etc/");
        let tmp = std::env::temp_dir().join(format!("podlab-{name}-{}", k::getpid()));
        let made = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(&tmp)
            .and_then(|mut f| f.write_all(kept.as_bytes()));
        if let Err(e) = made {
            let _ = std::fs::remove_file(&tmp);
            return Err(format!("{}: {e}", tmp.display()));
        }
        let from = c(&tmp.to_string_lossy())?;
        let bound = k::mount(&from, &c(file)?, &k::cempty(), k::MS_BIND);
        let _ = std::fs::remove_file(&tmp);
        bound.map_err(|e| words(&format!("mount(bind, {file})"), e))?;
    }
    Ok(())
}
