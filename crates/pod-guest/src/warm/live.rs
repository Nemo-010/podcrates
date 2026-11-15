//! The save and the restore with the QEMU of the host. Each test skips
//! where no `qemu-system-x86_64` or `qemu-img` is on `PATH`.
//!
//! The firmware is 2 MiB of `hlt`: the guest stops at its first
//! instruction and stays, so a test needs no image of an OS.

use super::state::load;
use super::tests::{Alive, dir, idle_mailbox, plan_in, request};
use super::*;

/// A plan for the QEMU of the host, with its files: the firmware, the
/// variable store, a raw base of 4 MiB by an absolute path, and the
/// overlay over it.
fn live_plan(d: &Path) -> (Plan, PathBuf) {
    let mut plan = plan_in(d);
    plan.emulator = "qemu-system-x86_64".into();
    plan.memory_mib = 64;
    std::fs::write(&plan.firmware_code, vec![0xf4u8; 2 << 20]).unwrap();
    std::fs::write(&plan.firmware_vars, vec![0u8; 128 << 10]).unwrap();
    let base = d.join("base.img");
    std::fs::write(&base, vec![0u8; 4 << 20]).unwrap();
    (plan, base)
}

fn status(plan: &Plan) -> String {
    let mut m = qmp::Monitor::connect(&plan.monitor, Duration::from_secs(30)).expect("the QMP socket");
    let line = m.ask("{\"execute\":\"query-status\"}").expect("query-status");
    qmp::json_member(&line, "status").unwrap_or_default()
}

/// The major version of the emulator, from `QEMU emulator version X.Y.Z`.
fn major(qemu: &str) -> u32 {
    let version = qemu.split("version ").nth(1).unwrap_or_default();
    version.split('.').next().and_then(|v| v.parse().ok()).unwrap_or(0)
}

/// The plan line with the root disk on AHCI in place of NVMe, which each
/// QEMU with `file:` migrates (QEMU 8.2 refuses only the NVMe disk): the
/// save writes a stream with the USB mailbox, a second emulator loads it
/// with the saved mailbox as it is, the guest runs after both, and the
/// command comes on a new medium after the load, by `id`, with no
/// deprecated argument. A stream cut short is a failed load.
#[test]
fn a_real_emulator_saves_and_loads_a_stream() {
    pod_testkit::need_tool!("qemu-system-x86_64");
    pod_testkit::need_tool!("qemu-img");
    let d = dir("warm-live-stream");
    let (mut plan, base) = live_plan(&d);
    plan.emu_args = ["-compat", "deprecated-input=reject"].map(String::from).to_vec();
    let s = Settings::new(std::env::temp_dir());
    let qemu_img = Path::new("qemu-img");
    stage_idle(&s, qemu_img, &base, &plan, agent::AGENT_CMD).unwrap();
    // The agent of a real guest writes the marker; this guest has none.
    std::fs::write(&plan.mailbox, idle_mailbox().image()).unwrap();
    let nvme = "nvme,drive=root,serial=wqroot";
    let line: Vec<String> = crate::argv(&plan)
        .into_iter()
        .map(|a| if a == nvme { "ide-hd,drive=root,bus=ide.0".into() } else { a })
        .collect();
    assert!(!line.iter().any(|a| a.starts_with("nvme")), "{line:?}");
    let child = emulator::spawn_emulator(&plan, &line, Stdio::null()).expect("the emulator starts");
    let mut child = Alive(child);
    let state = d.join("state");
    let f = print_of(&plan);
    let saved = save(&plan, &f, &state, Duration::from_secs(60));
    let after = status(&plan);
    emulator::stop_emulator(&plan, &mut child.0);
    saved.expect("the save");
    assert_eq!(after, "running", "the guest goes on after the save");
    for file in [STATE, ROOT, MAILBOX, VARS, FINGERPRINT] {
        assert!(state.join(file).is_file(), "{file}");
    }

    // The steps of `restore` on this line.
    let _ = std::fs::remove_file(&plan.root);
    emulator::run_steps(&overlay_argv(qemu_img, &state.join(ROOT), &plan.root)).unwrap();
    std::fs::copy(state.join(MAILBOX), &plan.mailbox).unwrap();
    let _ = std::fs::remove_file(&plan.monitor);
    let mut args = line.clone();
    args.extend(["-incoming".to_string(), format!("file:{}", state.join(STATE).display())]);
    let child = emulator::spawn_emulator(&plan, &args, Stdio::null()).expect("the emulator starts");
    let mut child = Alive(child);
    let loaded = load(&plan, &mut child.0, Duration::from_secs(60)).and_then(|()| {
        let mut swap = crate::swap::Swap::restored(&plan)?;
        let mut m = qmp::Monitor::connect(&plan.monitor, Duration::from_secs(30))?;
        swap.next(&mut m, &s, agent::AGENT_CMD, &request("tok-live"))?;
        let block = m.ask("{\"execute\":\"query-block\"}")?;
        Ok((swap, crate::swap::mailbox_file(&block)))
    });
    let after = if loaded.is_ok() { status(&plan) } else { String::new() };
    emulator::stop_emulator(&plan, &mut child.0);
    let (swap, inside) = loaded.expect("the load and the swap");
    assert_eq!(after, "running", "the guest runs after the load");
    assert_eq!(inside.as_deref().map(Path::new), Some(swap.current()), "the new medium is in the guest");
    assert_eq!(swap.current(), crate::swap::other_file(&plan));
    assert!(std::fs::read(&plan.mailbox).unwrap() == std::fs::read(state.join(MAILBOX)).unwrap(), "the saved mailbox");

    let cut = std::fs::read(state.join(STATE)).unwrap();
    std::fs::write(state.join(STATE), &cut[..cut.len().min(1000)]).unwrap();
    let _ = std::fs::remove_file(&plan.monitor);
    let child = emulator::spawn_emulator(&plan, &args, Stdio::null()).expect("the emulator starts");
    let mut child = Alive(child);
    let e = load(&plan, &mut child.0, Duration::from_secs(60)).unwrap_err();
    assert_eq!(e.class, Class::Unavailable, "a stream cut short ends the emulator: {e}");
    drop(child);
    let _ = std::fs::remove_dir_all(&d);
}

/// A fingerprint of `plan` over the test base.
fn print_of(plan: &Plan) -> Fingerprint {
    fingerprint(plan, "sha256:the-test-base", agent::AGENT_CMD).expect("the fingerprint")
}

/// The machine line of the plan with a USB mailbox and its NVMe root disk:
/// QEMU 11 saves it and [`start`] restores it with the command on a new
/// medium; an older QEMU refuses the save with its reasons and the guest
/// goes on, and [`start`] boots cold.
#[test]
fn a_real_emulator_saves_the_plan_from_qemu_11_and_boots_cold_before() {
    pod_testkit::need_tool!("qemu-system-x86_64");
    pod_testkit::need_tool!("qemu-img");
    let s = Settings::new(std::env::temp_dir());
    let d = dir("warm-live-plan");
    let (plan, base) = live_plan(&d);
    let qemu_img = Path::new("qemu-img");
    stage_idle(&s, qemu_img, &base, &plan, agent::AGENT_CMD).unwrap();
    std::fs::write(&plan.mailbox, idle_mailbox().image()).unwrap();
    let f = print_of(&plan);
    let child = emulator::spawn_uefi(&plan, Stdio::null()).expect("the emulator starts");
    let mut child = Alive(child);
    let state = d.join("state");
    let saved = save(&plan, &f, &state, Duration::from_secs(60));
    let after = status(&plan);
    emulator::stop_emulator(&plan, &mut child.0);
    drop(child);
    assert_eq!(after, "running", "the guest goes on after the save");
    let new_enough = major(&f.qemu) >= 11;
    match &saved {
        Ok(()) => eprintln!("{}: the plan saves", f.qemu),
        Err(e) => eprintln!("{}: the plan does not save: {e}", f.qemu),
    }
    match &saved {
        Ok(()) => {}
        Err(e) if !new_enough => {
            assert_eq!(e.class, Class::Unavailable, "{e}");
            assert!(e.to_string().contains("nvme"), "{e}");
        }
        Err(e) => panic!("{}: the save of the plan: {e}", f.qemu),
    }
    let w = Warm { dir: state.clone(), fingerprint: f.clone(), wait: Duration::from_secs(60) };
    let st = start(&s, qemu_img, &base, &plan, agent::AGENT_CMD, &request("tok-live"), &w).unwrap();
    let (how, swap) = (st.how, st.swap);
    let mut child = Alive(st.child);
    let after = status(&plan);
    emulator::stop_emulator(&plan, &mut child.0);
    drop(child);
    assert_eq!(after, "running");
    if saved.is_ok() {
        assert_eq!(how, Start::Warm, "{}", f.qemu);
        assert_eq!(swap.current(), crate::swap::other_file(&plan), "the command is on a new medium");
    } else {
        assert_eq!(how, Start::Cold(Cold::Missing));
    }
    let _ = std::fs::remove_dir_all(&d);
}
