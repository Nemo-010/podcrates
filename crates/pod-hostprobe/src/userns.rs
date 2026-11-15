//! The user namespace of a caller with no capabilities, as `unshare -Ur`
//! makes it: `unshare(CLONE_NEWUSER)`, then `deny` into
//! `/proc/self/setgroups`, then a map of one line in `uid_map` and in
//! `gid_map` (the id of the caller to 0). In that namespace the process
//! holds each capability, so a mount namespace that it makes after this
//! takes mounts.
//!
//! The namespace rung of `pod-enter` and the probe leg
//! [`crate::probes::USERNS_LEG`] call [`enter`], so the two cannot drift
//! into different sequences. [`Maps`] is built before a fork, and [`enter`]
//! does only system calls on it: it is async-signal-safe.

use crate::sys::{self, CBuf, Errno};

/// The call of the sequence that the kernel refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Step {
    Unshare,
    Setgroups,
    UidMap,
    GidMap,
}

impl Step {
    /// The name of the call, for a fallback line and for a probe row.
    pub fn name(self) -> &'static str {
        match self {
            Step::Unshare => "unshare(CLONE_NEWUSER)",
            Step::Setgroups => "writing deny to /proc/self/setgroups",
            Step::UidMap => "writing /proc/self/uid_map",
            Step::GidMap => "writing /proc/self/gid_map",
        }
    }
}

/// The paths and the lines of the maps, built before the fork.
pub struct Maps {
    setgroups: CBuf,
    uid_map: CBuf,
    gid_map: CBuf,
    uid_line: Vec<u8>,
    gid_line: Vec<u8>,
}

/// One line of a map: `0 <id> 1`. The kernel takes one line with no
/// capability in the parent namespace only where `id` is the effective id
/// of the writer.
pub fn map_line(id: u32) -> String {
    format!("0 {id} 1\n")
}

impl Maps {
    /// The maps of `uid` and `gid` to 0.
    pub fn new(uid: u32, gid: u32) -> Maps {
        let c = |s: &str| CBuf::new(s).expect("a literal path has no NUL");
        Maps {
            setgroups: c("/proc/self/setgroups"),
            uid_map: c("/proc/self/uid_map"),
            gid_map: c("/proc/self/gid_map"),
            uid_line: map_line(uid).into_bytes(),
            gid_line: map_line(gid).into_bytes(),
        }
    }

    /// The maps of the effective ids of this process.
    pub fn of_caller() -> Maps {
        let id = |nr| unsafe { sys::sys(nr, [0; 6]) }.map_or(0, |n| n as u32);
        Maps::new(id(sys::SYS_GETEUID), id(sys::SYS_GETEGID))
    }

    /// The line of `uid_map`.
    pub fn uid_line(&self) -> &[u8] {
        &self.uid_line
    }

    /// The line of `gid_map`.
    pub fn gid_line(&self) -> &[u8] {
        &self.gid_line
    }
}

/// Write `bytes` into the file at `path` in one `write(2)`: the kernel
/// takes a map in one write only. No allocation.
fn write_file(path: &CBuf, bytes: &[u8]) -> Result<(), Errno> {
    let fd = sys::open(path, sys::O_WRONLY | sys::O_CLOEXEC, 0)?;
    let n = sys::write(fd, bytes);
    let _ = sys::close(fd);
    match n {
        Ok(n) if n as usize == bytes.len() => Ok(()),
        Ok(_) => Err(sys::EIO),
        Err(e) => Err(e),
    }
}

/// Enter a new user namespace and map the caller to 0 in it. The process
/// must have one thread: the kernel refuses `CLONE_NEWUSER` to a process
/// with more (`EINVAL`). Async-signal-safe.
pub fn enter(m: &Maps) -> Result<(), (Step, Errno)> {
    sys::unshare(sys::CLONE_NEWUSER).map_err(|e| (Step::Unshare, e))?;
    // A kernel before 3.19 has no `setgroups` file, and takes the map of
    // the group with no `deny`.
    match write_file(&m.setgroups, b"deny") {
        Ok(()) | Err(sys::ENOENT) => {}
        Err(e) => return Err((Step::Setgroups, e)),
    }
    write_file(&m.uid_map, &m.uid_line).map_err(|e| (Step::UidMap, e))?;
    write_file(&m.gid_map, &m.gid_line).map_err(|e| (Step::GidMap, e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_map_is_one_line_of_the_id_to_0() {
        assert_eq!(map_line(1000), "0 1000 1\n");
        let m = Maps::new(1000, 100);
        assert_eq!(m.uid_line(), b"0 1000 1\n");
        assert_eq!(m.gid_line(), b"0 100 1\n");
    }

    #[test]
    fn the_maps_of_the_caller_are_its_effective_ids() {
        let euid = unsafe { sys::sys(sys::SYS_GETEUID, [0; 6]) }.expect("geteuid") as u32;
        let egid = unsafe { sys::sys(sys::SYS_GETEGID, [0; 6]) }.expect("getegid") as u32;
        let m = Maps::of_caller();
        assert_eq!(m.uid_line(), map_line(euid).as_bytes());
        assert_eq!(m.gid_line(), map_line(egid).as_bytes());
    }

    #[test]
    fn each_step_has_a_name() {
        let names: Vec<_> = [Step::Unshare, Step::Setgroups, Step::UidMap, Step::GidMap].map(Step::name).into();
        assert_eq!(names[0], "unshare(CLONE_NEWUSER)");
        assert!(names.iter().all(|n| !n.is_empty()));
        let mut d = names.clone();
        d.dedup();
        assert_eq!(d.len(), 4);
    }
}
