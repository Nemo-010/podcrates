//! A test as a caller with no capabilities. As root, the test starts its
//! own binary again as uid and gid [`NOBODY`] with no supplementary groups:
//! the kernel clears each capability at the change of the uid. As another
//! user, the test runs in its own process.

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
