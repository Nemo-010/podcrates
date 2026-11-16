//! The unix carrier on hostile hosts. Under a Landlock domain with no
//! `REFER`, as in the labs of `pod-lab` with Landlock (`no-tun`,
//! `root-unreadable`) and on the `bind-denied` host of podrunner, the domain
//! refuses each move to another directory with `EXDEV`, so the listener
//! cannot move its staged socket. Where a filter refuses `listen`
//! (`listen-denied`), the failure names `listen`. Landlock and a seccomp
//! filter with no `TSYNC` restrict one thread and its children: each is on
//! a new thread of the test, and the other tests do not get it.

#![cfg(any(target_os = "linux", target_os = "android"))]

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use pod_link::Carrier as _;
use pod_link::unix::Unix;

/// `LANDLOCK_ACCESS_FS_EXECUTE`: the one right that the ruleset handles.
/// Each ruleset refuses a move to another directory unless it handles
/// `LANDLOCK_ACCESS_FS_REFER` and a rule grants it; this one does not.
const ACCESS_FS_EXECUTE: u64 = 1;
const CREATE_RULESET_VERSION: libc::c_uint = 1;

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pl-hosts-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Restrict this thread with a Landlock domain that handles no `REFER`.
/// `Err` gives the reason when the host has no Landlock.
fn restrict_this_thread() -> Result<(), String> {
    // SAFETY: the version query of landlock_create_ruleset takes no pointer.
    let abi = unsafe {
        libc::syscall(libc::SYS_landlock_create_ruleset, std::ptr::null::<u64>(), 0usize, CREATE_RULESET_VERSION)
    };
    if abi < 1 {
        return Err(format!("no Landlock: {}", std::io::Error::last_os_error()));
    }
    let handled: u64 = ACCESS_FS_EXECUTE;
    // SAFETY: the attribute of ABI 1 is one u64, and it lives for the call.
    let ruleset =
        unsafe { libc::syscall(libc::SYS_landlock_create_ruleset, &raw const handled, size_of::<u64>(), 0u32) };
    assert!(ruleset >= 0, "landlock_create_ruleset: {}", std::io::Error::last_os_error());
    // SAFETY: prctl of this thread; landlock_restrict_self of a ruleset of
    // this function, closed after it.
    unsafe {
        assert_eq!(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), 0, "no_new_privs");
        let restricted = libc::syscall(libc::SYS_landlock_restrict_self, ruleset as libc::c_int, 0u32);
        let e = std::io::Error::last_os_error();
        libc::close(ruleset as libc::c_int);
        assert_eq!(restricted, 0, "landlock_restrict_self: {e}");
    }
    Ok(())
}

/// The domain holds: a move of a file to another directory is `EXDEV`.
fn a_move_is_refused(dir: &Path) {
    let (a, b) = (dir.join("a"), dir.join("b"));
    std::fs::create_dir_all(&a).unwrap();
    std::fs::create_dir_all(&b).unwrap();
    std::fs::write(a.join("f"), b"x").unwrap();
    let e = std::fs::rename(a.join("f"), b.join("f")).unwrap_err();
    assert_eq!(e.raw_os_error(), Some(libc::EXDEV), "the domain refuses a move: {e}");
    std::fs::remove_file(a.join("f")).unwrap();
    std::fs::remove_dir(&a).unwrap();
    std::fs::remove_dir(&b).unwrap();
}

/// The listener binds, has the mode 0600, leaves no staging directory, and
/// answers a dial.
#[test]
fn a_unix_listener_binds_under_landlock_with_no_refer() {
    let dir = scratch("listen");
    let path = dir.join("s.sock");
    let at = path.to_str().unwrap().to_string();
    let inside = dir.clone();
    let ran = std::thread::spawn(move || {
        if let Err(reason) = restrict_this_thread() {
            return Some(reason);
        }
        a_move_is_refused(&inside);
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async {
            let carrier = Unix::default();
            let door = carrier.listen(&at).await;
            let mut door = door.unwrap_or_else(|e| panic!("the listener under Landlock with no REFER: {e}"));
            let mode = std::fs::symlink_metadata(&at).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
            let left: Vec<_> = std::fs::read_dir(&inside).unwrap().map(|e| e.unwrap().file_name()).collect();
            assert_eq!(left, ["s.sock"], "no staging directory stays");
            let (near, far) = tokio::join!(carrier.dial(&at), door.accept());
            near.unwrap();
            far.unwrap();
            drop(door);
            assert!(!Path::new(&at).exists(), "the listener removes its socket");
        });
        None
    })
    .join()
    .expect("the thread of the domain");
    let _ = std::fs::remove_dir_all(&dir);
    if let Some(reason) = ran {
        println!("SKIP: a_unix_listener_binds_under_landlock_with_no_refer: {reason}");
    }
}

/// Refuse `listen(2)` with `EACCES` on this thread, as the lab
/// `listen-denied` does. False when the host refuses the filter.
fn refuse_listen_on_this_thread() -> bool {
    #[cfg(target_arch = "x86_64")]
    const ARCH: u32 = 0xC000_003E;
    #[cfg(target_arch = "aarch64")]
    const ARCH: u32 = 0xC000_00B7;
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    return false;
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    {
        const LD_ABS: u16 = 0x20; // BPF_LD | BPF_W | BPF_ABS
        const JEQ: u16 = 0x15; // BPF_JMP | BPF_JEQ | BPF_K
        const RET: u16 = 0x06; // BPF_RET | BPF_K
        const ERRNO: u32 = 0x0005_0000;
        const ALLOW: u32 = 0x7FFF_0000;
        let op = |code: u16, jt: u8, jf: u8, k: u32| libc::sock_filter { code, jt, jf, k };
        // The arch at offset 4 of `struct seccomp_data`, the number at 0. A
        // jump counts from the next instruction.
        let program = [
            op(LD_ABS, 0, 0, 4),
            op(JEQ, 0, 3, ARCH),
            op(LD_ABS, 0, 0, 0),
            op(JEQ, 0, 1, libc::SYS_listen as u32),
            op(RET, 0, 0, ERRNO | libc::EACCES as u32),
            op(RET, 0, 0, ALLOW),
        ];
        let prog = libc::sock_fprog { len: program.len() as u16, filter: program.as_ptr() as *mut _ };
        // SAFETY: prctl of this thread; the program lives for the call.
        unsafe {
            libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0
                && libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &raw const prog) == 0
        }
    }
}

/// A refused `listen` is a refusal that names `listen`, and leaves no file
/// at the path and no staging directory.
#[test]
fn a_refused_listen_names_listen() {
    let dir = scratch("refused");
    let path = dir.join("s.sock");
    let at = path.to_str().unwrap().to_string();
    let inside = dir.clone();
    let ran = std::thread::spawn(move || {
        if !refuse_listen_on_this_thread() {
            return false;
        }
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let e = runtime.block_on(Unix::default().listen(&at)).err().expect("listen is refused");
        assert_eq!(e.kind, pod_link::CarrierErrorKind::Refused, "{e}");
        assert!(e.to_string().contains("listen: "), "the failure names listen: {e}");
        let left: Vec<_> = std::fs::read_dir(&inside).unwrap().collect();
        assert!(left.is_empty(), "no file stays: {left:?}");
        true
    })
    .join()
    .expect("the thread of the filter");
    let _ = std::fs::remove_dir_all(&dir);
    if !ran {
        println!("SKIP: a_refused_listen_names_listen: the host refuses a seccomp filter");
    }
}
