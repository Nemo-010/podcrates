//! The mechanisms that hold the parts of a lab, in the lab process before
//! the command: the mount namespace with its tmpfs, the descriptors, the
//! Landlock rulesets, `no_new_privs` and the seccomp filter.
//!
//! The lab process has one thread (a fresh exec of the binary), so it can
//! enter a user namespace. Each function gives the reason of a refusal in
//! words; the part then does not hold.

use pod_confine::deny::{Deny, program};
use pod_confine::spec::FILE_RIGHTS;
use pod_hostprobe::sys::{self as k, CBuf, Errno};
use pod_hostprobe::userns;

use crate::profile::{Call, Hold};

fn c(s: &str) -> Result<CBuf, String> {
    CBuf::new(s).ok_or_else(|| format!("the path {s:?} holds a NUL"))
}

fn words(call: &str, e: Errno) -> String {
    format!("{call}: {} ({})", e.name(), e.0)
}

fn euid() -> u32 {
    // SAFETY: no pointer; geteuid always succeeds.
    unsafe { k::sys(k::SYS_GETEUID, [0; 6]) }.map_or(0, |n| n as u32)
}

fn egid() -> u32 {
    // SAFETY: as above.
    unsafe { k::sys(k::SYS_GETEGID, [0; 6]) }.map_or(0, |n| n as u32)
}

/// Write `bytes` into `path` in one `write(2)`, as the kernel takes a map.
fn write_once(path: &str, bytes: &[u8]) -> Result<(), String> {
    let fd = k::open(&c(path)?, k::O_WRONLY | k::O_CLOEXEC, 0).map_err(|e| words(path, e))?;
    let n = k::write(fd, bytes);
    let _ = k::close(fd);
    match n {
        Ok(n) if n as usize == bytes.len() => Ok(()),
        Ok(_) => Err(format!("{path}: a short write")),
        Err(e) => Err(words(path, e)),
    }
}

/// A tmpfs on `/tmp` in a new mount namespace. As root, a mount namespace
/// alone. As another user, a user namespace that maps the caller to 0, the
/// mount namespace and the mount, then a second user namespace that maps
/// the caller back to its own ids: the command runs as its own user with
/// no capability, as on the host.
pub fn tmpfs(size: Option<u64>, noexec: bool) -> Result<(), String> {
    let (uid, gid) = (euid(), egid());
    if uid != 0 {
        userns::enter(&userns::Maps::new(uid, gid))
            .map_err(|(step, e)| format!("the user namespace of the mount: {}", words(step.name(), e)))?;
    }
    k::unshare(k::CLONE_NEWNS).map_err(|e| words("unshare(CLONE_NEWNS)", e))?;
    let none = k::cempty();
    k::mount(&none, &c("/")?, &none, k::MS_REC | k::MS_PRIVATE).map_err(|e| words("mount(/, MS_PRIVATE)", e))?;
    let mut data = "mode=1777".to_string();
    if let Some(n) = size {
        data.push_str(&format!(",size={n}"));
    }
    let mut flags = k::MS_NOSUID | k::MS_NODEV;
    if noexec {
        flags |= k::MS_NOEXEC;
    }
    k::mount_data(&c("tmpfs")?, &c("/tmp")?, &c("tmpfs")?, flags, &c(&data)?)
        .map_err(|e| words("mount(tmpfs, /tmp)", e))?;
    if uid != 0 {
        k::unshare(k::CLONE_NEWUSER).map_err(|e| words("unshare(CLONE_NEWUSER) back to the caller", e))?;
        match write_once("/proc/self/setgroups", b"deny") {
            Ok(()) => {}
            Err(why) if why.contains("ENOENT") => {}
            Err(why) => return Err(why),
        }
        write_once("/proc/self/uid_map", format!("{uid} 0 1\n").as_bytes())?;
        write_once("/proc/self/gid_map", format!("{gid} 0 1\n").as_bytes())?;
    }
    Ok(())
}

/// Close each descriptor from 3 up except `keep`: the lab starts from a
/// known set, whatever its parent left open.
pub fn close_from_3(keep: i64) {
    let open: Vec<i64> = match std::fs::read_dir("/proc/self/fd") {
        Ok(dir) => dir.filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok()).collect(),
        Err(_) => (3..1024).collect(),
    };
    for fd in open.into_iter().filter(|&fd| fd >= 3 && fd != keep) {
        let _ = k::close(fd);
    }
}

/// Open `/dev/null` at each descriptor from 3 to `last`, not close-on-exec.
pub fn fds(last: i32) -> Result<(), String> {
    let null = c("/dev/null")?;
    for n in 3..=i64::from(last) {
        let fd = k::open(&null, k::O_RDWR, 0).map_err(|e| words("open(/dev/null)", e))?;
        if fd != n {
            k::dup2(fd, n).map_err(|e| words("dup2", e))?;
            let _ = k::close(fd);
        }
    }
    Ok(())
}

/// A ruleset of `rights` (file) and `net`, restricted on this process.
fn ruleset(fs: u64, net: u64, rules: &[(i64, u64)]) -> Result<(), String> {
    let attr = k::LandlockRulesetAttr { handled_access_fs: fs, handled_access_net: net, scoped: 0 };
    let set = k::landlock_create_ruleset(&attr).map_err(|e| words("landlock_create_ruleset", e))?;
    let out = (|| {
        for &(fd, allowed) in rules {
            let rule = k::LandlockPathBeneathAttr { allowed_access: allowed, parent_fd: fd as i32 };
            match k::landlock_add_path_rule(set, &rule) {
                // A file of a pseudo file system (`/dev/stdin` is a pipe):
                // no rule can name it, so it stays refused.
                Err(e) if e.0 == linux_raw_sys::errno::EBADFD as i32 => {}
                r => {
                    r.map_err(|e| words("landlock_add_rule", e))?;
                }
            }
        }
        k::set_no_new_privs().map_err(|e| words("prctl(PR_SET_NO_NEW_PRIVS)", e))?;
        k::landlock_restrict_self(set).map_err(|e| words("landlock_restrict_self", e))
    })();
    let _ = k::close(set);
    out.map(|_| ())
}

/// Each TCP bind and each TCP connect fails with `EACCES` (Landlock ABI 4,
/// a ruleset that handles both rights and has no port rule).
pub fn landlock_tcp() -> Result<(), String> {
    let abi = k::landlock_abi().map_err(|e| words("Landlock", e))?;
    if abi < 4 {
        return Err(format!("the Landlock ABI is {abi}; a TCP rule needs ABI 4"));
    }
    let net = (k::LANDLOCK_ACCESS_NET_BIND_TCP | k::LANDLOCK_ACCESS_NET_CONNECT_TCP) as u64;
    ruleset(0, net, &[])
}

/// `rights` on each path except `path` and the directories above it: for
/// each directory from `/` down to `path`, a rule on each entry that is not
/// the next step. The listing is the one of the start of the lab.
pub fn hide(path: &str, rights: u64) -> Result<(), String> {
    k::landlock_abi().map_err(|e| words("Landlock", e))?;
    let steps: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let mut rules: Vec<(i64, u64)> = Vec::new();
    let mut dir = String::from("/");
    let out = (|| {
        for i in 0..=steps.len() {
            if i == steps.len() && !steps.is_empty() {
                break;
            }
            let next = steps.get(i).copied();
            let list = std::fs::read_dir(&dir).map_err(|e| format!("a listing of {dir}: {e}"))?;
            for entry in list.flatten() {
                let name = entry.file_name();
                let Some(name) = name.to_str() else { continue };
                if Some(name) == next {
                    continue;
                }
                let full = format!("{}/{name}", dir.trim_end_matches('/'));
                // A path that does not open (a dead link, a race) gets no
                // rule: it stays refused, which hides no more than it must.
                let Ok(fd) = k::open(&c(&full)?, k::O_PATH | k::O_CLOEXEC, 0) else { continue };
                let is_dir = std::fs::metadata(&full).is_ok_and(|m| m.is_dir());
                let allowed = if is_dir { rights } else { rights & FILE_RIGHTS };
                if allowed == 0 {
                    let _ = k::close(fd);
                } else {
                    rules.push((fd, allowed));
                }
            }
            if let Some(next) = next {
                dir = format!("{}/{next}", dir.trim_end_matches('/'));
            }
        }
        ruleset(rights, 0, &rules)
    })();
    for (fd, _) in rules {
        let _ = k::close(fd);
    }
    out
}

/// The seccomp filter of `calls`, through the BPF program of `pod-confine`,
/// after `no_new_privs`.
pub fn seccomp(calls: &[Deny]) -> Result<(), String> {
    let filter = program(calls).map_err(|f| format!("the filter: {f}"))?;
    k::set_no_new_privs().map_err(|e| words("prctl(PR_SET_NO_NEW_PRIVS)", e))?;
    k::seccomp_set_filter(&filter, 0).map_err(|e| words("seccomp(SET_MODE_FILTER)", e)).map(|_| ())
}

/// The deny rules of a hold, for the one filter of a lab.
pub fn deny_rules(hold: Hold) -> Vec<Deny> {
    match hold {
        Hold::Seccomp(calls) => calls.iter().map(deny).collect(),
        Hold::ConfineDefaults => Deny::defaults(),
        _ => Vec::new(),
    }
}

fn deny(call: &Call) -> Deny {
    let d = Deny::call(call.name, call.nr, call.errno as u16);
    match call.flags {
        Some((index, mask)) => d.when_flags(index, mask),
        None => d,
    }
}

/// A target where `socket(2)` and its siblings can go through
/// `socketcall(2)`: a filter of `getsockname` does not see that path.
pub const SOCKETCALL: bool = cfg!(any(target_arch = "x86", target_arch = "s390x", target_arch = "powerpc64"));

/// The reason that a hold cannot run on this target or for this caller,
/// before any change; `None` where it can try.
pub fn cannot(hold: Hold) -> Option<String> {
    match hold {
        Hold::Elsewhere(who) => Some(format!("no lab of pod-lab holds it: {who}")),
        Hold::NonRoot if euid() == 0 => {
            Some("the caller is root; a lab cannot drop root, so run the lab as a user that is not root".to_string())
        }
        Hold::Seccomp(calls) if SOCKETCALL && calls.iter().any(|c| c.nr == k::SYS_GETSOCKNAME) => {
            Some("on this target getsockname can go through socketcall(2), which the filter does not see".to_string())
        }
        _ => None,
    }
}
