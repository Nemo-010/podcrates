//! The runs of a lab: `bind-denied`, `inherited-fds` and `small-tmp` with a
//! payload (this binary, or `/bin/sh` of the host), a profile that the lab
//! cannot hold, and a profile whose check inside the lab fails.
//!
//! As root, each case runs as root, then the test starts itself again as
//! uid 65534 (the kernel clears each capability), as CI runs it as a user.
//! Where uid 65534 cannot reach this binary, the test says so. The classes
//! of podssh and podnet are in `lab/hosts.rs`. A case that the host
//! cannot give says `skipping` with the reason; `scripts/ci/userns-tests.sh`
//! fails on that line. No libtest (`harness = false`): the binary reads the
//! flag of a lab process, of a probe child and of a payload first, and has
//! one thread.

#[cfg(target_os = "linux")]
#[path = "lab/payload.rs"]
mod payload;

#[cfg(target_os = "linux")]
#[path = "lab/hosts_payload.rs"]
mod hosts_payload;

#[cfg(target_os = "linux")]
#[path = "lab/hosts.rs"]
mod hosts;

#[cfg(target_os = "linux")]
mod cases {
    use std::ffi::OsString;
    use std::io::Read;

    use pod_lab::{Expect, Hold, IdFact, LabFact, Observe, Options, Part, Profile, RunError, Settings, State};
    use pod_testkit::host::skip_line;

    /// The profiles of the tests. `never-holds`: `chroot(/tmp)` gives
    /// `EPERM` to a user and succeeds for root, never `EINVAL`.
    /// `caps-dropped`: a mount, which gives a caller that is not root each
    /// capability in its user namespace until the exec, and the drop of
    /// the capabilities, which the identity of the lab shows.
    static TESTS: &[Profile] = &[
        Profile {
            name: "never-holds",
            about: "a part that no host holds",
            source: "tests/lab.rs",
            parts: &[Part {
                name: "chroot-einval",
                about: "chroot(/tmp) gives EINVAL",
                observe: &[Observe::Row { row: "chroot(/tmp)", expect: Expect::Refused(&[22]) }],
                hold: Hold::Host,
            }],
        },
        Profile {
            name: "caps-dropped",
            about: "a tmpfs, and no capability in the lab",
            source: "tests/lab.rs",
            parts: &[
                Part {
                    name: "tmp",
                    about: "a tmpfs on /tmp",
                    observe: &[Observe::Lab(LabFact::TmpdirAtMost(u64::MAX))],
                    hold: Hold::Tmpfs { size: None, noexec: false },
                },
                Part {
                    name: "no-caps",
                    about: "CapEff is 0 in the lab",
                    observe: &[Observe::Identity(IdFact::NoCaps)],
                    hold: Hold::DropCaps,
                },
            ],
        },
    ];

    pub fn settings() -> Settings {
        Settings::default()
    }

    pub fn test_settings() -> Settings {
        Settings { lab_flag: "--podlab-test-lab".to_string(), profiles: TESTS, ..Settings::default() }
    }

    /// This binary, as the lab process sees it: a tmpfs on `/tmp` hides a
    /// binary under `/tmp`, and `/proc/self/exe` of the lab process is this
    /// binary at the exec.
    fn exe() -> OsString {
        "/proc/self/exe".into()
    }

    pub fn payload(kind: &str) -> Vec<OsString> {
        vec![exe(), "--payload".into(), kind.into()]
    }

    fn sh(script: &str) -> Vec<OsString> {
        vec!["/bin/sh".into(), "-c".into(), script.into()]
    }

    /// Run `cmd` in the lab `name`, with its standard output on a pipe.
    pub fn run(
        settings: &Settings,
        name: &str,
        cmd: &[OsString],
        partial: bool,
    ) -> (Result<pod_lab::Ran, RunError>, String) {
        let profile = pod_lab::find(settings.profiles, name).expect("a profile");
        let (mut r, w) = std::io::pipe().expect("a pipe");
        let out = pod_lab::run(settings, profile, cmd, Options { partial, stdout: Some(w.into()) });
        let mut text = String::new();
        r.read_to_string(&mut text).expect("the output of the payload");
        (out, text)
    }

    pub fn ran(name: &str, out: Result<pod_lab::Ran, RunError>, text: &str) -> i32 {
        match out {
            Ok(ran) => {
                assert!(ran.verdict.holds(), "{name}: the lab ran with a part that does not hold: {:?}", ran.verdict);
                pod_lab::exit_code(ran.status)
            }
            Err(e) => panic!("{name}: {e}: {e:?}; output {text:?}"),
        }
    }

    fn mark(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("pod-lab-{name}-{}", std::process::id()))
    }

    pub fn inherited_fds() {
        let (out, text) = run(&settings(), "inherited-fds", &payload("fds"), false);
        assert_eq!(ran("inherited-fds", out, &text), 0, "{text}");
        assert_eq!(text.trim(), "fds 3-9 open", "{text}");
        // The exit code and the output of a shell pass through.
        let (out, text) = run(&settings(), "inherited-fds", &sh("echo from-sh; exit 7"), false);
        assert_eq!(ran("inherited-fds", out, &text), 7, "{text}");
        assert_eq!(text.trim(), "from-sh");
        println!("inherited_fds: ok");
    }

    pub fn bind_denied() {
        match pod_hostprobe::sys::landlock_abi() {
            Ok(abi) if abi >= 4 => {}
            other => {
                skip_line(&format!("bind_denied: the lab needs Landlock ABI 4; this host gives {other:?}"));
                return;
            }
        }
        let (out, text) = run(&settings(), "bind-denied", &payload("net"), false);
        assert_eq!(ran("bind-denied", out, &text), 0, "{text}");
        assert!(text.contains("inet refused") && text.contains("unix ok"), "{text}");
        println!("bind_denied: ok");
    }

    pub fn small_tmp() {
        if !pod_testkit::nobody::is_root()
            && let Err(why) = pod_testkit::host::userns()
        {
            skip_line(&format!("small_tmp: the tmpfs of the lab needs a user namespace with a mount: {why}"));
            return;
        }
        let (out, text) = run(&settings(), "small-tmp", &payload("tmp"), false);
        assert_eq!(ran("small-tmp", out, &text), 0, "{text}");
        assert!(text.starts_with("tmp ok"), "{text}");
        println!("small_tmp: ok");
    }

    /// A part that no lab here holds stops the run: the command does not
    /// run. With `partial`, it runs, and the verdict says that the part
    /// does not hold.
    pub fn a_part_held_elsewhere_refuses_the_run() {
        let m = mark("elsewhere");
        let cmd = sh(&format!("touch {}", m.display()));
        let (out, _) = run(&settings(), "proxy-only", &cmd, false);
        match out {
            Err(RunError::Refused(v)) => assert!(v.parts.iter().all(|p| p.state != State::Holds), "{v:?}"),
            other => panic!("proxy-only ran with no proxy part: {other:?}"),
        }
        assert!(!m.exists(), "the command ran in a lab that does not hold");
        let (out, _) = run(&settings(), "proxy-only", &cmd, true);
        let ran = out.expect("a partial lab runs");
        assert!(ran.status.success() && m.exists());
        assert!(ran.verdict.parts.iter().all(|p| p.state == State::Fails), "{:?}", ran.verdict);
        let _ = std::fs::remove_file(&m);
        println!("a_part_held_elsewhere_refuses_the_run: ok");
    }

    /// The check inside the lab, before the command: a part whose row
    /// contradicts it stops the run.
    pub fn a_part_that_does_not_hold_inside_stops_the_command() {
        let m = mark("inside");
        let (out, _) = run(&test_settings(), "never-holds", &sh(&format!("touch {}", m.display())), false);
        match out {
            Err(RunError::Refused(v)) => {
                assert_eq!(v.parts[0].state, State::Fails, "{v:?}");
                assert_eq!(v.parts[0].seen[0].what, "chroot(/tmp)");
            }
            other => panic!("the lab ran a command with a part that does not hold: {other:?}"),
        }
        assert!(!m.exists(), "the command ran in a lab that does not hold");
        println!("a_part_that_does_not_hold_inside_stops_the_command: ok");
    }

    /// The lab drops each capability: of root, and of a caller in the user
    /// namespace of a mount.
    pub fn caps_dropped() {
        if !pod_testkit::nobody::is_root()
            && let Err(why) = pod_testkit::host::userns()
        {
            skip_line(&format!("caps_dropped: the tmpfs of the lab needs a user namespace with a mount: {why}"));
            return;
        }
        let (out, text) = run(&test_settings(), "caps-dropped", &payload("caps"), false);
        assert_eq!(ran("caps-dropped", out, &text), 0, "{text}");
        assert_eq!(text.trim(), "CapEff 0");
        println!("caps_dropped: ok");
    }
}

#[cfg(target_os = "linux")]
fn main() {
    let (settings, test) = (cases::settings(), cases::test_settings());
    pod_lab::dispatch(&settings);
    pod_lab::dispatch(&test);
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("--payload") {
        std::process::exit(payload::main(args.get(2).map_or("", String::as_str)));
    }
    if args.get(1).map(String::as_str) == Some(hosts::CTTY_CHILD) {
        hosts::ctty_child();
    }
    let as_root = pod_testkit::nobody::is_root();
    if as_root {
        println!("lab: as root");
    }
    cases::inherited_fds();
    cases::bind_denied();
    cases::small_tmp();
    cases::a_part_held_elsewhere_refuses_the_run();
    cases::a_part_that_does_not_hold_inside_stops_the_command();
    cases::caps_dropped();
    hosts::all();
    // As root, each case runs again as uid 65534, as CI runs it as a user.
    if as_root {
        println!("lab: again as uid 65534");
        match pod_testkit::nobody::again(&[], &[]) {
            Ok(code) => std::process::exit(code),
            Err(why) => println!("lab: not as uid 65534: {why}"),
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {}
