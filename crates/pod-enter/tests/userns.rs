//! The namespace rung for a caller with no capabilities
//! (PodUtils/podvm#406): the entry makes a user namespace that maps the
//! caller to 0, then its mount and UTS namespaces, and does not fall back
//! to chroot. The payload sees uid 0, the name of the plan, and a `/tmp`
//! that is not the `/tmp` of the image.
//!
//! As root, the test makes the image and starts its own binary again as
//! uid and gid 65534 with no groups (`pod_testkit::nobody`). The image is
//! a static `busybox` of the host (`PODVM_T486_BUSYBOX`, or `/bin/busybox`
//! where it is static). Where the host has none, where the kernel gives
//! such a caller no user namespace that takes a mount, or where uid 65534
//! cannot reach the binary, the test says `skipping` and passes:
//! `scripts/ci/userns-tests.sh` fails on that line.
#![cfg(target_os = "linux")]

use std::fs;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use pod_enter::{Fds, Names, Plan, RootDir, run_namespace};
use pod_testkit::host::skip_line;
use pod_testkit::nobody;

const NAME: &str = "unit2";
/// The image that the root parent made for the child of uid 65534.
const IMAGE: &str = "POD_ENTER_USERNS_IMAGE";
const TEST: &str = "a_caller_with_no_capabilities_enters_the_namespace_rung";

fn busybox() -> Result<PathBuf, String> {
    let p = std::env::var_os("PODVM_T486_BUSYBOX").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("/bin/busybox"));
    let mut head = [0u8; 4096];
    let n = fs::File::open(&p).and_then(|mut f| f.read(&mut head)).map_err(|e| format!("{}: {e}", p.display()))?;
    if [&b"ld-linux"[..], b"ld-musl"].iter().any(|ld| head[..n].windows(ld.len()).any(|w| w == *ld)) {
        return Err(format!("{} is not static", p.display()));
    }
    Ok(p)
}

/// An image with `/bin/busybox` and its applets, `/tmp` with one file of
/// the image, and no `/proc`.
fn image(bb: &Path) -> PathBuf {
    let root = std::env::temp_dir().join(format!("pod-enter-userns-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    for d in ["bin", "tmp"] {
        fs::create_dir_all(root.join(d)).unwrap();
        fs::set_permissions(root.join(d), fs::Permissions::from_mode(0o755)).unwrap();
    }
    fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
    fs::write(root.join("tmp/of-the-image"), "x").unwrap();
    fs::copy(bb, root.join("bin/busybox")).unwrap();
    fs::set_permissions(root.join("bin/busybox"), fs::Permissions::from_mode(0o755)).unwrap();
    for applet in ["sh", "id", "uname", "test", "touch"] {
        std::os::unix::fs::symlink("busybox", root.join("bin").join(applet)).unwrap();
    }
    root
}

fn plan(script: &str) -> Plan {
    let env = vec![format!("PATH={}", Plan::DEFAULT_PATH)];
    Plan {
        argv: vec!["/bin/sh".to_string(), "-c".to_string(), script.to_string()],
        path_dirs: Plan::path_from(&env),
        env,
        working_dir: "/".to_string(),
        fds: Fds::default(),
        banner: "the banner\n".to_string(),
        names: Names::DEFAULT,
        limits: Vec::new(),
        no_new_privs: false,
        die_with_parent: false,
        confine: None,
        hostname: Some(NAME.to_string()),
    }
}

#[test]
fn a_caller_with_no_capabilities_enters_the_namespace_rung() {
    if let Some(root) = std::env::var_os(IMAGE) {
        return as_the_caller(Path::new(&root));
    }
    let bb = match busybox() {
        Ok(bb) => bb,
        Err(why) => return skip_line(&format!("no static busybox: {why}")),
    };
    let root = image(&bb);
    if !nobody::is_root() {
        as_the_caller(&root);
        let _ = fs::remove_dir_all(&root);
        return;
    }
    let env = [(IMAGE, root.to_str().unwrap())];
    let code = nobody::again(&[TEST, "--exact", "--nocapture", "--test-threads=1"], &env);
    let _ = fs::remove_dir_all(&root);
    match code {
        Ok(code) => assert_eq!(code, 0, "the test as uid {} failed", nobody::NOBODY),
        Err(why) => skip_line(&why),
    }
}

/// The test as the caller with no capabilities.
fn as_the_caller(root: &Path) {
    assert_eq!(nobody::effective_caps(), Some(0), "the caller must hold no capability");
    if let Err(why) = pod_testkit::host::userns() {
        return skip_line(&format!("the kernel gives this caller no user namespace for the rung: {why}"));
    }
    let dir = RootDir::open(root.to_str().unwrap()).unwrap();
    let active = format!("${}", Names::DEFAULT.mode_active);
    let script = format!(
        "test \"$(id -u)\" = 0 || exit 3; test \"$(uname -n)\" = {NAME} || exit 4; \
         test -e /tmp/of-the-image && exit 5; touch /tmp/new || exit 6; \
         test \"{active}\" = namespace || exit 7"
    );
    let mut err = Vec::new();
    let code = run_namespace(&dir, &plan(&script), &mut err);
    let err = String::from_utf8_lossy(&err);
    assert_eq!(code.map_err(|e| e.to_string()), Ok(0), "the payload as uid {}: {err}", nobody::NOBODY);
    assert_eq!(err.matches("the banner").count(), 1, "the banner goes out one time: {err}");
    assert!(!err.contains("entered chroot instead"), "{err}");
    assert!(!root.join("tmp/new").exists(), "the write of the payload landed in the /tmp of the image");
}
