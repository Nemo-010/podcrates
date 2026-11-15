//! The fallback of [`start`]: a missing, stale or failed state boots
//! cold; a state that loads starts warm, with the command on a new medium.

use super::*;

/// A saved directory for `plan`: an idle mailbox, a stream, an overlay,
/// a variable store and the text of `f`.
fn saved(d: &Path, f: &Fingerprint) -> PathBuf {
    let state = d.join("state");
    std::fs::create_dir(&state).unwrap();
    std::fs::write(state.join(STATE), b"QEVM stream").unwrap();
    std::fs::write(state.join(ROOT), qcow2_naming("/images/base.vhdx")).unwrap();
    std::fs::write(state.join(MAILBOX), idle_mailbox().image()).unwrap();
    std::fs::write(state.join(VARS), b"saved vars").unwrap();
    std::fs::write(state.join(FINGERPRINT), f.text()).unwrap();
    state
}

fn warm(dir: PathBuf, f: &Fingerprint) -> Warm {
    Warm { dir, fingerprint: f.clone(), wait: Duration::from_secs(30) }
}

/// The mailbox of the cold boot: the command and the token of the request,
/// as `stage` writes them, and no marker of a restored agent; the swap
/// starts at the file of the plan.
fn assert_cold_mailbox(plan: &Plan, swap: &crate::swap::Swap, token: &str) {
    let m = Fat16::from_image(std::fs::read(&plan.mailbox).unwrap()).unwrap();
    assert_eq!(m.get(agent::GO).as_deref(), Some(token.as_bytes()));
    assert!(!agent::ready(&m), "the mailbox of the cold boot is new");
    assert_eq!((swap.current(), swap.token()), (plan.mailbox.as_path(), token));
}

/// `true` stands for `qemu-img`; `/bin/sh` is an emulator that refuses the
/// machine line and exits.
fn start_in(d: &Path, plan: &Plan, w: &Warm) -> (Child, Start, crate::swap::Swap) {
    let s = Settings::new(std::env::temp_dir());
    let out = start(&s, Path::new("true"), &d.join("base.vhdx"), plan, agent::AGENT_CMD, &request("tok-2"), w);
    let st = out.expect("a cold boot starts the emulator");
    (st.child, st.how, st.swap)
}

#[test]
fn no_state_and_a_stale_state_boot_cold_and_leave_the_store_of_the_caller() {
    pod_testkit::need_tool!("/bin/sh");
    pod_testkit::need_tool!("true");
    let d = dir("warm-cold");
    let plan = plan_in(&d);
    std::fs::write(&plan.firmware_vars, b"fresh vars").unwrap();
    let now = print("QEMU emulator version 11.0.0");

    let (mut child, how, swap) = start_in(&d, &plan, &warm(d.join("none"), &now));
    let _ = child.wait();
    assert_eq!(how, Start::Cold(Cold::Missing));
    assert_cold_mailbox(&plan, &swap, "tok-2");

    let state = saved(&d, &print("QEMU emulator version 10.2.1"));
    let (mut child, how, swap) = start_in(&d, &plan, &warm(state.clone(), &now));
    let _ = child.wait();
    let stale = Cold::Stale {
        saved: "qemu \"QEMU emulator version 10.2.1\"".into(),
        now: "qemu \"QEMU emulator version 11.0.0\"".into(),
    };
    assert_eq!(how, Start::Cold(stale));
    assert_cold_mailbox(&plan, &swap, "tok-2");
    assert_eq!(std::fs::read(&plan.firmware_vars).unwrap(), b"fresh vars");

    // A state with a file missing is no state.
    std::fs::remove_file(state.join(VARS)).unwrap();
    let (mut child, how, _) = start_in(&d, &plan, &warm(state, &print("QEMU emulator version 10.2.1")));
    let _ = child.wait();
    assert_eq!(how, Start::Cold(Cold::Missing));
    let _ = std::fs::remove_dir_all(&d);
}

/// A state with the same fingerprint whose emulator exits during the load
/// boots cold, with the variable store of the caller back in place.
#[test]
fn a_state_that_does_not_load_boots_cold() {
    pod_testkit::need_tool!("/bin/sh");
    pod_testkit::need_tool!("true");
    let d = dir("warm-failed");
    let plan = plan_in(&d);
    std::fs::write(&plan.firmware_vars, b"fresh vars").unwrap();
    let f = print("QEMU emulator version 11.0.0");
    let state = saved(&d, &f);
    let (mut child, how, swap) = start_in(&d, &plan, &warm(state.clone(), &f));
    let _ = child.wait();
    let Start::Cold(Cold::Failed { why }) = how else { panic!("{how:?}") };
    assert!(why.contains("exited"), "{why}");
    assert_cold_mailbox(&plan, &swap, "tok-2");
    assert_eq!(std::fs::read(&plan.firmware_vars).unwrap(), b"fresh vars");
    assert_eq!(std::fs::read(state.join(VARS)).unwrap(), b"saved vars", "the state stays");
    let _ = std::fs::remove_dir_all(&d);
}

/// A bad option of the plan is a failure of the start, not a cold boot.
#[test]
fn a_bad_plan_is_a_failure_and_not_a_cold_boot() {
    let d = dir("warm-bad-plan");
    let mut plan = plan_in(&d);
    plan.options.vnc = Some(PathBuf::new());
    let s = Settings::new(std::env::temp_dir());
    let f = print("QEMU 11.0.0");
    let e = start(&s, Path::new("true"), &d.join("base"), &plan, agent::AGENT_CMD, &request("t"), &warm(d.clone(), &f))
        .unwrap_err();
    assert_eq!(e.class, Class::Usage, "{e}");
    assert!(cold(&e).is_none());
    let _ = std::fs::remove_dir_all(&d);
}

/// A plan with an NVMe mailbox has no warm start: the restored guest reads
/// the saved mailbox from its cache. The save, the restore and the start
/// refuse it with no request to the emulator and no cold boot.
#[test]
fn a_warm_start_needs_a_usb_mailbox() {
    pod_testkit::need_loopback!();
    let d = dir("warm-nvme");
    let mut plan = plan_in(&d);
    plan.options.mailbox = crate::plan::MailboxBus::Nvme;
    run_files(&plan);
    let seen = stand(&plan.monitor, |_, _| OK.into());
    let f = print("QEMU 11.0.0");
    let state = saved(&d, &f);
    let s = Settings::new(std::env::temp_dir());
    let fails = [
        save(&plan, &f, &d.join("new"), Duration::from_secs(30)).map(drop).unwrap_err(),
        restore(&s, Path::new("true"), &plan, agent::AGENT_CMD, &request("t"), &warm(state.clone(), &f))
            .map(drop)
            .unwrap_err(),
        start(&s, Path::new("true"), &d.join("base"), &plan, agent::AGENT_CMD, &request("t"), &warm(state, &f))
            .map(drop)
            .unwrap_err(),
    ];
    for e in fails {
        assert_eq!(e.class, Class::Usage, "{e}");
        assert!(e.to_string().contains("USB mailbox"), "{e}");
        assert!(cold(&e).is_none(), "{e}");
    }
    assert!(names(&seen).is_empty(), "no request: {:?}", names(&seen));
    assert!(!d.join("new").exists() && !d.join("new.part").exists());
    let _ = std::fs::remove_dir_all(&d);
}

/// A state that loads starts warm: the emulator gets the machine line and
/// `-incoming` with the saved mailbox as it is, the saved variable store is
/// in place, the guest goes on, and then the command comes on a new medium
/// with the next volume id, swapped in by `id`.
#[test]
fn a_state_that_loads_starts_warm_with_the_next_command() {
    use std::os::unix::fs::PermissionsExt;
    pod_testkit::need_loopback!();
    pod_testkit::need_tool!("/bin/sh");
    pod_testkit::need_tool!("sleep");
    pod_testkit::need_tool!("true");
    let d = dir("warm-loads");
    let mut plan = plan_in(&d);
    std::fs::write(&plan.firmware_vars, b"fresh vars").unwrap();
    // The stand-in of the emulator keeps its arguments, says that it
    // started, and lives; the test serves its QMP socket.
    let fake = d.join("fake-emulator");
    let (args, started) = (d.join("args"), d.join("started"));
    let script = format!(
        "#!/bin/sh\n[ \"$1\" = probe ] && exit 0\nprintf '%s\\n' \"$@\" > {}\n: > {}\nexec sleep 600\n",
        args.display(),
        started.display()
    );
    std::fs::write(&fake, script).unwrap();
    std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o700)).unwrap();
    // A file that a test thread just wrote can be busy (ETXTBSY) while
    // another thread forks: wait until it runs.
    until("the stand-in runs", || Command::new(&fake).arg("probe").status().is_ok_and(|s| s.success()));
    plan.emulator = fake;
    let f = print("QEMU emulator version 11.0.0");
    let state = saved(&d, &f);
    let monitor = plan.monitor.clone();
    let served = std::thread::spawn(move || {
        until("the stand-in of the emulator starts", || started.exists());
        stand(&monitor, |name, n| match (name, n) {
            ("query-status", 1) => "{\"return\": {\"status\": \"inmigrate\"}}".into(),
            ("query-status", _) => "{\"return\": {\"status\": \"paused\"}}".into(),
            _ => OK.into(),
        })
    });
    let (child, how, swap) = start_in(&d, &plan, &warm(state.clone(), &f));
    let child = Alive(child);
    assert_eq!(how, Start::Warm);
    let seen = served.join().expect("the stand-in");
    let names = names(&seen);
    let cont = names.iter().position(|n| n == "cont").expect("cont");
    assert_eq!(names[cont + 1..], ["qmp_capabilities", "blockdev-change-medium"], "the swap comes after the load");
    let line = std::fs::read_to_string(&args).unwrap();
    let line: Vec<&str> = line.lines().collect();
    assert_eq!(line[line.len() - 2..], ["-incoming", &format!("file:{}", state.join(STATE).display())]);
    let saved_box = std::fs::read(state.join(MAILBOX)).unwrap();
    assert!(std::fs::read(&plan.mailbox).unwrap() == saved_box, "the emulator loads the saved mailbox as it is");
    let other = crate::swap::other_file(&plan);
    assert_eq!((swap.current(), swap.token()), (other.as_path(), "tok-2"));
    let m = Fat16::from_image(std::fs::read(&other).unwrap()).unwrap();
    assert_eq!(m.get(agent::GO).as_deref(), Some(&b"tok-2"[..]));
    assert!(m.get(agent::KEEP).is_some(), "a keep-alive request keeps the guest");
    let saved_id = Fat16::from_image(saved_box).unwrap().volume_id();
    assert_eq!(m.volume_id(), saved_id.wrapping_add(1), "Windows reads a medium again only for another volume id");
    assert_eq!(std::fs::read(&plan.firmware_vars).unwrap(), b"saved vars");
    drop(child);
    let _ = std::fs::remove_dir_all(&d);
}
