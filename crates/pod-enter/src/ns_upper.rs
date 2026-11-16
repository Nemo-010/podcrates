//! The view of the guest root for the checks before the fork: the volumes
//! of the plan over the image, and, on an overlay root with an upper
//! directory of the caller (`Upper::Dir`), the upper layer over the lower
//! one, as overlayfs shows them to the payload.
//!
//! The rules of overlayfs, as `pod-rootfs` reads a root of two layers: an
//! entry of the upper layer hides the same name of the lower layer; a
//! whiteout (a character device 0:0) hides the name; a directory of the
//! upper layer with `trusted.overlay.opaque` or `user.overlay.opaque` set to
//! `y` hides each entry of the lower layer under it. A volume hides both
//! layers at its guest path, as the child binds it over the merged root.
//! `Upper::Tmpfs` has no upper directory here: its upper layer starts
//! empty, so the lower layer is the view.

use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};

use pod_hostprobe::sys::{self, CBuf};

use crate::abi::GuestRoot;
use crate::userland::Maps;
use crate::{Plan, RootDir};

/// The attributes that mark an opaque directory of overlayfs: `trusted.`
/// for a mount of root, `user.` for a mount with `userxattr`.
const OPAQUE: [&str; 2] = ["trusted.overlay.opaque", "user.overlay.opaque"];

/// The guest root of the checks before the fork.
pub(crate) struct View {
    /// The image (the lower layer) and the volumes.
    maps: Maps,
    /// The upper directory of an overlay root.
    upper: Option<PathBuf>,
}

impl View {
    /// The view of `root` with the volumes of `plan` and the upper
    /// directory `upper`, where the root is an overlay with one.
    pub(crate) fn new(root: &RootDir, plan: &Plan, upper: Option<&str>) -> View {
        View { maps: Maps::of_binds(&root.path, &plan.volumes), upper: upper.map(PathBuf::from) }
    }

    /// The host path that the two layers show at `parts`, or `None` where
    /// they show nothing: no entry, a whiteout, or an entry of the lower
    /// layer under an opaque directory.
    fn merged(&self, upper: &Path, parts: &[String]) -> Option<PathBuf> {
        let lower = self.maps.root().to_path_buf();
        let Some((last, dirs)) = parts.split_last() else { return Some(lower) };
        let mut layers = (Some(upper.to_path_buf()), (!opaque(upper)).then_some(lower));
        for name in dirs {
            let (path, m, in_upper) = entry(&layers, name)?;
            if !m.is_dir() {
                return None;
            }
            layers = if in_upper {
                let dir = |l: &PathBuf| std::fs::symlink_metadata(l).is_ok_and(|m| m.is_dir());
                let below = layers.1.map(|l| l.join(name)).filter(|l| !opaque(&path) && dir(l));
                (Some(path), below)
            } else {
                (None, Some(path))
            };
        }
        entry(&layers, last).map(|(path, _, _)| path)
    }

    /// Where the upper directory takes part in the view of `parts`: a path
    /// that no volume serves.
    fn layered(&self, parts: &[String]) -> Option<&Path> {
        self.upper.as_deref().filter(|_| !self.maps.in_volume(parts))
    }
}

/// A whiteout of overlayfs: a character device 0:0.
fn whiteout(m: &std::fs::Metadata) -> bool {
    m.file_type().is_char_device() && m.rdev() == 0
}

/// Is the directory `dir` opaque? A directory that does not open (no read
/// permission) is not.
fn opaque(dir: &Path) -> bool {
    let Some(c) = CBuf::from_bytes(dir.as_os_str().as_bytes()) else { return false };
    let Ok(fd) = sys::open(&c, sys::O_RDONLY | sys::O_DIRECTORY | sys::O_NOFOLLOW | sys::O_CLOEXEC, 0) else {
        return false;
    };
    let set = OPAQUE.iter().any(|n| {
        let mut b = [0u8; 2];
        CBuf::new(n).is_some_and(|c| sys::fgetxattr(fd, &c, &mut b) == Ok(1) && b[0] == b'y')
    });
    let _ = sys::close(fd);
    set
}

/// The entry `name` of the merged directory of `layers` (its upper and its
/// lower directory, each where it takes part): its path, its metadata, and
/// whether the upper layer holds it.
fn entry(layers: &(Option<PathBuf>, Option<PathBuf>), name: &str) -> Option<(PathBuf, std::fs::Metadata, bool)> {
    let read = |dir: &Option<PathBuf>| {
        let p = dir.as_ref()?.join(name);
        std::fs::symlink_metadata(&p).ok().map(|m| (p, m))
    };
    if let Some((p, m)) = read(&layers.0) {
        return (!whiteout(&m)).then_some((p, m, true));
    }
    read(&layers.1).filter(|(_, m)| !whiteout(m)).map(|(p, m)| (p, m, false))
}

impl GuestRoot for View {
    fn root(&self) -> &Path {
        self.maps.root()
    }

    fn host_of(&self, parts: &[String]) -> (PathBuf, bool) {
        match self.layered(parts) {
            // A path that the layers do not show is no host path: `hidden`
            // says so to the walk.
            Some(upper) => (self.merged(upper, parts).unwrap_or_else(|| upper.join(parts.join("/"))), false),
            None => self.maps.host_of(parts),
        }
    }

    fn hidden(&self, parts: &[String]) -> bool {
        self.layered(parts).is_some_and(|upper| self.merged(upper, parts).is_none())
    }

    fn above_mount(&self, parts: &[String]) -> bool {
        self.maps.above_mount(parts)
    }

    fn volume_label(&self, guest: &str) -> Option<String> {
        self.maps.volume_label(guest)
    }
}

#[cfg(test)]
mod tests;
