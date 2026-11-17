//! A rotation of an identity key with two slots (T-826; report 08 of the dig
//! study): the current key in its file, and the key before it in the file
//! of the same name with [`PREVIOUS`] after it. A rotation keeps the old key
//! in the previous slot, then replaces the current one; both are an
//! identity of the node until [`retire`] removes the previous slot. So a
//! peer that pins the old key can still reach the node while it learns the
//! new one.
//!
//! The rules. At most one previous key: a rotation while one is there is
//! refused, and the current key is not changed. The previous slot is a new
//! file, written and synced before the current key is replaced (a durable
//! replace, `pod_core::files::replace_private`), so the old secret is on
//! disk at each step; of two rotations at once, one makes the slot and the
//! other is refused. Only [`retire`] removes the old key. A reader that
//! knows no rotation reads the current file as before.

use std::path::{Path, PathBuf};

use pod_core::entropy::Entropy;
use pod_core::files::{self as cache, Places};

use super::Identity;
use super::file::{Key, Place, body, kept_path_in, make, read};

/// The suffix of the file of the previous key.
pub const PREVIOUS: &str = ".previous";

/// The two keys of a rotation.
#[derive(Debug)]
pub struct Rotated {
    /// The key before the rotation, kept in the previous slot.
    pub previous: Identity,
    /// The new key, in the current slot.
    pub current: Key,
    /// Why the new key may not survive a power cut (the sync of its
    /// directory failed); `None` when it is on disk.
    pub unconfirmed: Option<String>,
}

/// Whether a key has a previous key beside it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Slots {
    Single,
    Overlapping,
}

/// The file of the previous key of the key file `path`.
pub fn previous_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(PREVIOUS);
    PathBuf::from(name)
}

/// Rotate the key kept at `place` (a key that exists: a rotation makes no
/// first key) in the `places` of the caller's app.
pub fn rotate(places: &Places, place: &Place, entropy: &mut dyn Entropy) -> Result<Rotated, String> {
    rotate_at(&kept(&places.read(), place)?, entropy)
}

/// The previous key of the key kept at `place`, when a rotation is open.
pub fn previous(places: &Places, place: &Place) -> Result<Option<Identity>, String> {
    previous_at(&kept(&places.read(), place)?)
}

/// Remove the previous key of the key kept at `place`: `false` when there
/// was none. A peer that pins only the old key cannot reach the node after.
pub fn retire(places: &Places, place: &Place) -> Result<bool, String> {
    retire_at(&kept(&places.read(), place)?)
}

/// The path of the key kept at `place`, which must exist.
fn kept(dirs: &[PathBuf], place: &Place) -> Result<PathBuf, String> {
    kept_path_in(dirs, place)?
        .ok_or_else(|| "there is no key to rotate: a node makes its key at its first start".into())
}

/// [`rotate`] of the key file `path`.
pub fn rotate_at(path: &Path, entropy: &mut dyn Entropy) -> Result<Rotated, String> {
    let old = read(path)?.ok_or_else(|| format!("{}: there is no key to rotate", path.display()))?;
    let slot = previous_path(path);
    let open = || format!("{}: a rotation is open; retire the previous key first", slot.display());
    if read(&slot)?.is_some() {
        return Err(open());
    }
    // A new file only: of two rotations at once, the second finds it.
    let made = cache::create_private(&slot, &body(&old))
        .map_err(|e| format!("{}: could not keep the previous key: {e}", slot.display()))?;
    if !made {
        return Err(open());
    }
    let new = make(entropy)?;
    let commit = cache::replace_private(path, &body(&new), 0o600, false)
        .map_err(|e| format!("{}: could not write the new key: {e}", path.display()))?;
    let unconfirmed = commit.unconfirmed().map(|e| e.to_string());
    Ok(Rotated {
        previous: old,
        current: Key { identity: new, path: Some(path.to_path_buf()), made: true },
        unconfirmed,
    })
}

/// [`previous`] of the key file `path`.
pub fn previous_at(path: &Path) -> Result<Option<Identity>, String> {
    read(&previous_path(path))
}

/// The slots of the key file `path`.
pub fn slots_at(path: &Path) -> Result<Slots, String> {
    Ok(if previous_at(path)?.is_some() { Slots::Overlapping } else { Slots::Single })
}

/// [`retire`] of the key file `path`.
pub fn retire_at(path: &Path) -> Result<bool, String> {
    let slot = previous_path(path);
    match std::fs::remove_file(&slot) {
        Ok(()) => {
            #[cfg(unix)]
            if let Some(dir) = slot.parent() {
                let _ = std::fs::File::open(dir).and_then(|d| d.sync_all());
            }
            Ok(true)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(format!("{}: could not remove the previous key: {e}", slot.display())),
    }
}

#[cfg(test)]
#[path = "rotate_tests.rs"]
mod tests;
