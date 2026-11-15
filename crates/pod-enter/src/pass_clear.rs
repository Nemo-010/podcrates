//! The descriptors of the entry clear of the passed numbers. The child puts
//! each passed descriptor onto its number first: a descriptor of the entry
//! (the root file system, the memfd of the exec, the readiness pipe) on such
//! a number would be lost. `RootDir::open` takes the lowest free number,
//! which a caller can pass (PodUtils/podvm#422).

use pod_hostprobe::sys;

use crate::{Plan, Result, errno_failure};

/// The lowest number above each passed number.
fn above(plan: &Plan) -> i64 {
    plan.fds.pass.iter().map(|&(child_fd, _)| child_fd).max().unwrap_or(0) + 1
}

fn passed(plan: &Plan, fd: i64) -> bool {
    plan.fds.pass.iter().any(|&(child_fd, _)| child_fd == fd)
}

/// Copies of the descriptors of the caller that the entry moved, closed
/// when the parent ends its part of the spawn.
#[derive(Default)]
pub(crate) struct Moved(Vec<i64>);

impl Drop for Moved {
    fn drop(&mut self) {
        for &fd in &self.0 {
            let _ = sys::close(fd);
        }
    }
}

/// `fd` of the caller, or, where it holds a passed number, a close-on-exec
/// copy above each passed number. The caller keeps its own descriptor; the
/// copy closes with `moved`.
pub(crate) fn keep(plan: &Plan, fd: i64, what: &str, moved: &mut Moved) -> Result<i64> {
    if !passed(plan, fd) {
        return Ok(fd);
    }
    match sys::fcntl(fd, sys::F_DUPFD_CLOEXEC, above(plan) as u64) {
        Ok(copy) => {
            moved.0.push(copy);
            Ok(copy)
        }
        Err(e) => Err(errno_failure(
            &format!("a passed descriptor goes onto {fd}, the number of {what} ({}), and the move failed", kind(fd)),
            e,
        )),
    }
}

/// `fd` of the entry itself, or a close-on-exec copy above each passed
/// number; the original closes.
pub(crate) fn clear_of_passes(plan: &Plan, fd: i64) -> Result<i64> {
    if !passed(plan, fd) {
        return Ok(fd);
    }
    let moved = sys::fcntl(fd, sys::F_DUPFD_CLOEXEC, above(plan) as u64);
    let _ = sys::close(fd);
    moved.map_err(|e| errno_failure("moving the readiness pipe clear of the passed descriptors failed", e))
}

/// The kind of the file of `fd`, for a refusal.
fn kind(fd: i64) -> &'static str {
    let empty = sys::cempty();
    match sys::fstatat(fd, &empty, sys::AT_EMPTY_PATH) {
        Ok(st) => match st.st_mode & sys::S_IFMT {
            0o040000 => "a directory",
            0o140000 => "a socket",
            0o010000 => "a pipe",
            0o100000 => "a regular file or a memfd",
            0o020000 => "a character device",
            _ => "another kind of file",
        },
        Err(_) => "a descriptor that fstat cannot read",
    }
}

#[cfg(test)]
mod tests;
