use super::*;

/// overlayfs splits the options at `,` and the layers at `:`: a path with
/// either, or with the escape itself, stays one value.
#[test]
fn a_path_with_a_separator_stays_one_value() {
    assert_eq!(overlay_escape("/var/lib/img"), "/var/lib/img");
    assert_eq!(overlay_escape("/a,b:c\\d"), "/a\\,b\\:c\\\\d");
    assert_eq!(overlay_options("/r,1/upper", "/r:1/work"), "lowerdir=.,upperdir=/r\\,1/upper,workdir=/r\\:1/work");
}

/// The lower layer of the options is the working directory of the child,
/// never a path that can change after the check.
#[test]
fn the_lower_layer_is_the_held_descriptor() {
    assert!(overlay_options("/u", "/w").starts_with("lowerdir=.,"));
}

/// Each step of the overlay root has a name, and the landing check names
/// the overlay.
#[test]
fn each_step_of_the_overlay_root_has_a_name() {
    assert_eq!(ns_setup_step(NS_OVERLAY_TMPFS_STEP), Some("mounting the tmpfs of the overlay layers"));
    assert_eq!(ns_setup_step(NS_OVERLAY_DIRS_STEP), Some("making the upper and work directories"));
    assert_eq!(ns_setup_step(NS_OVERLAY_STEP), Some("mounting overlay on the root"));
    let landing = ns_setup_step(10).unwrap();
    assert_eq!(overlay_step(landing), "verifying the chroot landed on the overlay");
    assert_eq!(overlay_step("mounting overlay on the root"), "mounting overlay on the root");
}

/// The refusal names `overlay`, has no code of a payload, and is
/// `Unsupported` for a caller that reads a `Failure`.
#[test]
fn the_refusal_names_the_overlay() {
    let e = Error::Overlay { step: "mounting overlay on the root", errno: sys::EINVAL };
    let text = e.to_string();
    assert_eq!(
        text,
        "the overlay root was refused at mounting overlay on the root: EINVAL (22); the payload did not run"
    );
    assert_eq!(e.payload_code(), None);
    assert_eq!(e.code_or(125), 125);
    let f: pod_core::Failure = e.into();
    assert_eq!(f.class, Class::Unsupported);
}

/// An upper directory of the caller is absolute: a relative one would
/// resolve against the lower layer, the working directory of the child.
#[test]
fn a_relative_upper_directory_is_refused() {
    let d = std::env::temp_dir().join(format!("pod-enter-overlay-unit-{}", std::process::id()));
    std::fs::create_dir_all(d.join("tmp")).unwrap();
    let lower = RootDir::open(d.to_str().unwrap()).unwrap();
    let e = OverlayMount::new(&lower, Upper::Dir { upper: "upper", work: "/w" }).err().unwrap().to_string();
    assert!(e.contains("the overlay root") && e.contains("absolute"), "{e}");
    let long = format!("/{}", "a".repeat(OVERLAY_OPTIONS_MOST));
    let e = OverlayMount::new(&lower, Upper::Dir { upper: &long, work: "/w" }).err().unwrap().to_string();
    assert!(e.contains("mount(2) takes at most 4095"), "{e}");
    assert!(OverlayMount::new(&lower, Upper::Tmpfs { size: 1 << 20 }).is_ok());
    let _ = std::fs::remove_dir_all(d);
}

/// In a user namespace the mount tries `userxattr` first, then the plain
/// options (a kernel before 5.11); a mount of a host root tries the plain
/// options alone. A kernel can read an opaque directory with no such
/// option (Ubuntu's), so the live test alone does not hold this (T-755).
#[test]
fn the_mount_in_a_user_namespace_tries_userxattr_first() {
    let d = std::env::temp_dir().join(format!("pod-enter-overlay-attempts-{}", std::process::id()));
    std::fs::create_dir_all(d.join("tmp")).unwrap();
    let lower = RootDir::open(d.to_str().unwrap()).unwrap();
    let mut m = OverlayMount::new(&lower, Upper::Dir { upper: "/u", work: "/w" }).unwrap();
    let (first, plain) = m.attempts(true);
    assert!(std::ptr::eq(first, &m.options_userxattr), "the first try in a user namespace has userxattr");
    assert!(plain.is_some_and(|p| std::ptr::eq(p, &m.options)), "then the plain options");
    m.caller_userns = false;
    let (first, plain) = m.attempts(false);
    assert!(std::ptr::eq(first, &m.options) && plain.is_none(), "a host root: the plain options alone");
    m.caller_userns = true;
    assert!(std::ptr::eq(m.attempts(false).0, &m.options_userxattr), "a caller in a user namespace of its own");
    let _ = std::fs::remove_dir_all(d);
}
