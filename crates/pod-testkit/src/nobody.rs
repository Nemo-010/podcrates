//! A test as a caller with no capabilities. As root, the test starts its
//! own binary again as uid and gid [`NOBODY`] with no supplementary groups:
//! the kernel clears each capability at the change of the uid. As another
//! user, the test runs in its own process. [`again_over_a_bare_proc`] also
//! gives the test a proc with no flags of the host.

use std::os::unix::process::CommandExt;

/// The uid and the gid of the caller with no capabilities.
pub const NOBODY: u32 = 65534;

/// Is the effective uid of this process 0?
pub fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

/// The effective capabilities of this process (`CapEff` of
/// `/proc/self/status`), or `None` where the file has no such line.
pub fn effective_caps() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let hex = status.lines().find_map(|l| l.strip_prefix("CapEff:"))?;
    u64::from_str_radix(hex.trim(), 16).ok()
}

/// Start this test binary again with `args` and `env` as [`NOBODY`], with
/// no supplementary groups (std calls `setgroups(0)` before `setuid` as
/// root), and give its exit code. `Err` where it cannot start: [`NOBODY`]
/// must be able to execute the binary through each directory of its path.
pub fn again(args: &[&str], env: &[(&str, &str)]) -> Result<i32, String> {
    let exe = std::env::current_exe().map_err(|e| format!("the path of this test binary: {e}"))?;
    let status = std::process::Command::new(&exe)
        .args(args)
        .envs(env.iter().copied())
        .uid(NOBODY)
        .gid(NOBODY)
        .status()
        .map_err(|e| format!("{} could not start as uid {NOBODY}: {e}", exe.display()))?;
    Ok(status.code().unwrap_or(128))
}

/// Start this test binary again as [`again`] does, as pid 1 of its own user,
/// mount and PID namespaces, over a fresh proc on `/proc` with no
/// `nosuid`, `nodev` or `noexec`. The user namespace maps the uid and the
/// gid of the caller ([`NOBODY`] where it is root) to themselves, so the
/// exec clears each capability. A check of the flags that the code under
/// test sets on a bind of `/proc` then sees them on each host: a bind keeps
/// the flags of the host's proc, and the proc of most hosts has them
/// already. `Err` where the kernel refuses a namespace or the proc.
pub fn again_over_a_bare_proc(args: &[&str], env: &[(&str, &str)]) -> Result<i32, String> {
    let exe = std::env::current_exe().map_err(|e| format!("the path of this test binary: {e}"))?;
    let (uid, gid) = if is_root() { (NOBODY, NOBODY) } else { unsafe { (libc::geteuid(), libc::getegid()) } };
    let uid_map = format!("{uid} {uid} 1");
    let gid_map = format!("{gid} {gid} 1");
    let mut command = std::process::Command::new(&exe);
    command.args(args).envs(env.iter().copied());
    if is_root() {
        command.uid(NOBODY).gid(NOBODY);
    }
    // SAFETY: the closure runs in the child between the fork and the exec,
    // and makes only calls of the C library with no allocation.
    unsafe { command.pre_exec(move || bare_proc(uid_map.as_bytes(), gid_map.as_bytes())) };
    let status = command.status().map_err(|e| format!("{} over a fresh proc as uid {uid}: {e}", exe.display()))?;
    Ok(status.code().unwrap_or(128))
}

fn os<T: PartialEq + From<i8>>(r: T) -> std::io::Result<T> {
    if r == T::from(-1) { Err(std::io::Error::last_os_error()) } else { Ok(r) }
}

/// Write `data` to the file `path` (a C string).
fn put(path: &[u8], data: &[u8]) -> std::io::Result<()> {
    let fd = os(unsafe { libc::open(path.as_ptr().cast(), libc::O_WRONLY | libc::O_CLOEXEC) })?;
    let wrote = os(unsafe { libc::write(fd, data.as_ptr().cast(), data.len()) });
    unsafe { libc::close(fd) };
    wrote.map(drop)
}

/// The child of [`again_over_a_bare_proc`]: the namespaces, then a fork.
/// The grandchild is pid 1 of the new PID namespace: it mounts the proc
/// and goes on to the exec; this process waits for it and exits with its
/// code.
fn bare_proc(uid_map: &[u8], gid_map: &[u8]) -> std::io::Result<()> {
    // The change of the uid made the process not dumpable: its files of
    // /proc then belong to root, and it cannot write its own maps.
    os(unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 1, 0, 0, 0) })?;
    os(unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS | libc::CLONE_NEWPID) })?;
    put(b"/proc/self/setgroups\0", b"deny")?;
    put(b"/proc/self/uid_map\0", uid_map)?;
    put(b"/proc/self/gid_map\0", gid_map)?;
    let pid = os(unsafe { libc::fork() })?;
    if pid == 0 {
        let none = std::ptr::null();
        os(unsafe { libc::mount(none, c"/".as_ptr(), none, libc::MS_REC | libc::MS_PRIVATE, none.cast()) })?;
        let proc = c"proc".as_ptr();
        os(unsafe { libc::mount(proc, c"/proc".as_ptr(), proc, 0, none.cast()) })?;
        return Ok(());
    }
    let mut status = 0;
    while unsafe { libc::waitpid(pid, &mut status, 0) } == -1 {
        if std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
            unsafe { libc::_exit(127) }
        }
    }
    let code = if libc::WIFEXITED(status) { libc::WEXITSTATUS(status) } else { 128 + libc::WTERMSIG(status) };
    unsafe { libc::_exit(code) }
}
