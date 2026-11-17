use std::path::PathBuf;

use pod_core::entropy::OsEntropy;

use super::*;
use crate::file;

fn dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pod-identity-rotate-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    dir
}

/// A node's key in `dir`, made by its first load.
fn first_key(dir: &std::path::Path) -> (Place, Key) {
    let place = file::node_place("lab");
    let key = file::load_in(&[dir.to_path_buf()], &place, &mut OsEntropy).unwrap();
    (place, key)
}

#[test]
fn a_rotation_keeps_both_keys_and_a_new_run_reads_both() {
    let dir = dir("both");
    let (place, key) = first_key(&dir);
    let path = key.path.clone().unwrap();
    let rotated = rotate_at(&path, &mut OsEntropy).unwrap();
    assert_eq!(rotated.previous.public(), key.identity.public());
    assert_ne!(rotated.current.identity.public(), key.identity.public(), "a new identity");
    // A new run: the current key is the new one, and the previous is kept.
    let again = file::load_in(std::slice::from_ref(&dir), &place, &mut OsEntropy).unwrap();
    assert_eq!(again.identity.public(), rotated.current.identity.public());
    assert!(!again.made);
    assert_eq!(previous_at(&path).unwrap().map(|i| i.public()), Some(key.identity.public()));
    assert_eq!(slots_at(&path).unwrap(), Slots::Overlapping);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_second_rotation_is_refused_and_the_current_key_stays_byte_for_byte() {
    let dir = dir("twice");
    let (_, key) = first_key(&dir);
    let path = key.path.unwrap();
    rotate_at(&path, &mut OsEntropy).unwrap();
    let before = std::fs::read(&path).unwrap();
    let words = rotate_at(&path, &mut OsEntropy).expect_err("a rotation is open");
    assert!(words.contains("retire the previous key first"), "{words}");
    assert_eq!(std::fs::read(&path).unwrap(), before);
    // Retired, a rotation is possible again.
    assert!(retire_at(&path).unwrap());
    assert!(rotate_at(&path, &mut OsEntropy).is_ok());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn retire_removes_the_previous_key_once_and_again_is_no_change() {
    let dir = dir("retire");
    let (_, key) = first_key(&dir);
    let path = key.path.unwrap();
    rotate_at(&path, &mut OsEntropy).unwrap();
    assert!(retire_at(&path).unwrap());
    assert!(!retire_at(&path).unwrap(), "idempotent");
    assert!(previous_at(&path).unwrap().is_none());
    assert_eq!(slots_at(&path).unwrap(), Slots::Single);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn no_key_and_an_ephemeral_key_are_not_rotated() {
    let dir = dir("none");
    let place = file::node_place("lab");
    let words = kept(std::slice::from_ref(&dir), &place).expect_err("no key");
    assert!(words.contains("no key to rotate"), "{words}");
    assert!(kept(std::slice::from_ref(&dir), &Place::Ephemeral).is_err());
    assert!(rotate_at(&dir.join("absent.key"), &mut OsEntropy).is_err());
    assert!(dir.read_dir().unwrap().next().is_none(), "nothing is made");
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn both_slots_are_private() {
    use std::os::unix::fs::PermissionsExt;
    let dir = dir("modes");
    let (_, key) = first_key(&dir);
    let path = key.path.unwrap();
    rotate_at(&path, &mut OsEntropy).unwrap();
    for each in [path.clone(), previous_path(&path)] {
        assert_eq!(std::fs::metadata(&each).unwrap().permissions().mode() & 0o777, 0o600, "{}", each.display());
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_key_of_the_old_name_is_rotated_in_its_own_file() {
    let dir = dir("old");
    let place = file::node_place("lab");
    let old = dir.join(file::old_node_file("lab"));
    let key = file::load_in(std::slice::from_ref(&dir), &Place::File(old.clone()), &mut OsEntropy).unwrap();
    assert_eq!(kept(std::slice::from_ref(&dir), &place).unwrap(), old);
    let rotated = rotate_at(&old, &mut OsEntropy).unwrap();
    assert_eq!(rotated.previous.public(), key.identity.public());
    assert!(previous_path(&old).exists());
    let _ = std::fs::remove_dir_all(&dir);
}
