//! The leg of the namespace rung through a user namespace
//! ([`pod_hostprobe::probes::USERNS_LEG`]) as a caller with no
//! capabilities. As root, the test starts itself again as uid and gid
//! 65534 with no groups: the kernel clears each capability at that change.
//!
//! Where the kernel refuses a user namespace with capabilities to such a
//! caller (`user.max_user_namespaces` 0, the sysctl of AppArmor), the test
//! says `skipping` and passes. `scripts/ci/userns-tests.sh` fails on that
//! line. As root, the binary must be in a directory that uid 65534 can
//! reach, or the test says `skipping` too. With no libtest
//! (`harness = false`): the binary reads the flag of a probe child first,
//! and has one thread.

#[cfg(target_os = "linux")]
fn main() {
    use pod_hostprobe::probes::USERNS_LEG;
    use pod_hostprobe::verdict::Verdict;
    use pod_hostprobe::{Settings, child::Spawner, run_child};
    use pod_testkit::host::skip_line;
    use pod_testkit::nobody;

    let settings = Settings::default();
    let args: Vec<String> = std::env::args().collect();
    if args.get(1) == Some(&settings.child_flag) {
        let name = args.get(2).map_or("", String::as_str);
        std::process::exit(run_child(name, &mut std::io::stdout()));
    }
    if nobody::is_root() {
        match nobody::again(&[], &[]) {
            Ok(code) => std::process::exit(code),
            Err(why) => {
                skip_line(&why);
                return;
            }
        }
    }
    let caps = nobody::effective_caps();
    assert_eq!(caps, Some(0), "the caller must hold no capability");
    let spawner = Spawner::new(&settings);
    let leg = spawner.run_probe(USERNS_LEG, 0);
    println!("userns_leg: {}", leg.row(USERNS_LEG));
    if leg.verdict == Verdict::Ok {
        return;
    }
    // The probe of the test kit (no code of this crate) says whether the
    // kernel gives such a caller a user namespace that takes a mount.
    if let Err(why) = pod_testkit::host::userns() {
        skip_line(&format!("{why}: {}", leg.row(USERNS_LEG)));
        return;
    }
    panic!("the leg failed for a caller with no capabilities: {}", leg.row(USERNS_LEG));
}

#[cfg(not(target_os = "linux"))]
fn main() {}
