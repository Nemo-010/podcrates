//! A walk of a tree with one directory open at a time.
//!
//! A recursion holds one descriptor for each level of depth, and a tree
//! deeper than `RLIMIT_NOFILE` stops it early. This walk keeps the listing
//! and the identity (device and inode) of each level in memory, holds only
//! the directory that it is in, and opens `..` to go up. The identity of
//! `..` must be the identity of the level above: a directory that moved
//! during the walk stops it with an error, and the walk never goes up out of
//! the tree.
//!
//! A tree deeper than the limit is refused with the typed cause
//! [`TooDeep`]. The listing of each level stays in memory, so the limit
//! bounds that memory.

use pod_core::{Class, Failure, Stage};
use pod_hostprobe::sys::{self, CBuf, Dirent};

use crate::error::{self, Result};

/// The deepest directory below the start of a walk ([`crate::modes::open_tree`]
/// and [`crate::remove::remove_at`]), and the most components of a path of an
/// entry ([`crate::safety::components`]).
///
/// One path that the kernel takes has at most 4096 bytes (`PATH_MAX`), so
/// 2048 levels at most. A tree twice as deep is not a root file system.
pub const MAX_DEPTH: usize = 4096;

/// A tree deeper than the limit of the walk. The class is `Unsupported`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TooDeep {
    /// The first directory past the limit, below the start of the walk.
    pub path: String,
    pub limit: usize,
}

impl std::fmt::Display for TooDeep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the directory {:?} is deeper than {} levels below the start of the walk; the crate does not walk \
             a tree that deep",
            self.path, self.limit
        )
    }
}

impl std::error::Error for TooDeep {}

/// The [`TooDeep`] cause of a failure, when it has one.
pub fn too_deep(f: &Failure) -> Option<&TooDeep> {
    error::cause(f)
}

struct Frame {
    /// The name in the level above. Empty for the start.
    name: Vec<u8>,
    id: (u64, u64),
    left: Vec<Dirent>,
}

/// The walk. The descriptor of the start belongs to the caller and stays
/// open; each other descriptor belongs to the walk.
pub(crate) struct Walk {
    base: i64,
    cur: i64,
    stack: Vec<Frame>,
    /// The levels at the start that do not count against the limit.
    free: usize,
    limit: usize,
}

impl Walk {
    /// A walk of the entries of `base`.
    pub(crate) fn of(base: i64, limit: usize) -> Result<Walk> {
        let left = sys::getdents64(base).unwrap_or_default();
        Ok(Walk { base, cur: base, stack: vec![Frame { name: Vec::new(), id: id(base)?, left }], free: 0, limit })
    }

    /// A walk that starts in `base` with no entries of it: the caller goes
    /// into one name with [`Walk::descend`], and that level does not count.
    pub(crate) fn at(base: i64, limit: usize) -> Result<Walk> {
        let stack = vec![Frame { name: Vec::new(), id: id(base)?, left: Vec::new() }];
        Ok(Walk { base, cur: base, stack, free: 1, limit })
    }

    /// The directory that the walk is in.
    pub(crate) fn fd(&self) -> i64 {
        self.cur
    }

    /// True at the start.
    pub(crate) fn at_start(&self) -> bool {
        self.stack.len() == 1
    }

    /// The next entry of the directory that the walk is in.
    pub(crate) fn next(&mut self) -> Option<Dirent> {
        self.stack.last_mut().and_then(|f| f.left.pop())
    }

    /// Go into the directory `n` of the current one, opened with `open`
    /// (which gives `None` for a name that is not a directory or does not
    /// open). False: the walk did not move.
    pub(crate) fn descend(&mut self, n: &[u8], open: impl FnOnce(i64, &CBuf) -> Option<i64>) -> Result<bool> {
        let Some(c) = CBuf::from_bytes(n) else { return Ok(false) };
        // The depth of `n`: the start is level 0.
        let depth = self.stack.len() - self.free;
        if depth > self.limit {
            let mut parts: Vec<String> =
                self.stack.iter().skip(1).map(|f| String::from_utf8_lossy(&f.name).into_owned()).collect();
            parts.push(String::from_utf8_lossy(n).into_owned());
            let cause = TooDeep { path: parts.join("/"), limit: self.limit };
            return Err(Failure::caused(Stage::Host, Class::Unsupported, cause.to_string(), cause));
        }
        let Some(fd) = open(self.cur, &c) else { return Ok(false) };
        let id = match id(fd) {
            Ok(id) => id,
            Err(e) => {
                let _ = sys::close(fd);
                return Err(e);
            }
        };
        let left = sys::getdents64(fd).unwrap_or_default();
        self.stack.push(Frame { name: n.to_vec(), id, left });
        self.leave_cur();
        self.cur = fd;
        Ok(true)
    }

    /// Go up one level, and give the name of the directory left. The walk is
    /// then in its parent. Call it only when [`Walk::at_start`] is false.
    pub(crate) fn ascend(&mut self) -> Result<Vec<u8>> {
        let done = self.stack.pop().expect("ascend at the start of the walk");
        let parent = if self.stack.len() == 1 {
            self.base
        } else {
            let dots = CBuf::from_bytes(b"..").expect("no NUL");
            let flags = sys::O_RDONLY | sys::O_DIRECTORY | sys::O_NOFOLLOW | sys::O_CLOEXEC;
            let fd = sys::openat(self.cur, &dots, flags, 0).map_err(|e| error::sys("cannot open \"..\"", e))?;
            let want = self.stack.last().map(|f| f.id);
            if id(fd).ok() != want {
                let _ = sys::close(fd);
                let text = format!(
                    "the directory above {:?} moved during the walk, so the walk stops and does not go up out of \
                     the tree",
                    String::from_utf8_lossy(&done.name)
                );
                return Err(Failure::new(Stage::Host, Class::TempFail, text));
            }
            fd
        };
        self.leave_cur();
        self.cur = parent;
        Ok(done.name)
    }

    fn leave_cur(&mut self) {
        if self.cur != self.base {
            let _ = sys::close(self.cur);
        }
    }
}

impl Drop for Walk {
    fn drop(&mut self) {
        self.leave_cur();
    }
}

fn id(fd: i64) -> Result<(u64, u64)> {
    let st =
        sys::fstatat(fd, &sys::cempty(), sys::AT_EMPTY_PATH).map_err(|e| error::sys("cannot stat a directory", e))?;
    Ok((st.st_dev, st.st_ino))
}
