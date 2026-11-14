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

/// A line with no NVMe disk, which each QEMU with `file:` migrates: the
/// save writes a stream that a second emulator loads, the guest runs after
/// both, and a stream cut short is a failed load.
#[test]
fn a_real_emulator_saves_and_loads_a_stream() {
    pod_testkit::need_tool!("qemu-system-x86_64");
    pod_testkit::need_tool!("qemu-img");
    let d = dir("warm-live-stream");
    let (plan, base) = live_plan(&d);
    let s = Settings::new(std::env::temp_dir());
    stage_idle(&s, Path::new("qemu-img"), &base, &plan, agent::AGENT_CMD).unwrap();
    // The agent of a real guest writes the marker; this guest has none.
    std::fs::write(&plan.mailbox, idle_mailbox().image()).unwrap();
    let line = |root: &Path| -> Vec<String> {
        let mut a: Vec<String> =
            ["-M", "q35", "-accel", "tcg", "-cpu", "max", "-m", "64", "-nodefaults"].map(String::from).to_vec();
        a.extend(["-display", "none", "-no-reboot", "-drive"].map(String::from));
        a.push(format!("if=pflash,format=raw,readonly=on,file={}", plan.firmware_code.display()));
        a.push("-drive".into());
        a.push(format!("if=pflash,format=raw,file={}", plan.firmware_vars.display()));
        a.push("-drive".into());
        a.push(format!("if=none,id=root,file={},format=qcow2", root.display()));
        a.extend(["-device", "virtio-blk-pci,drive=root", "-qmp"].map(String::from));
        a.push(format!("unix:{},server=on,wait=off", plan.monitor.display()));
        a
    };
    let child = emulator::spawn_emulator(&plan, &line(&plan.root), Stdio::null()).expect("the emulator starts");
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

    let restored = d.join("restored.qcow2");
    emulator::run_steps(&overlay_argv(Path::new("qemu-img"), &state.join(ROOT), &restored)).unwrap();
    let _ = std::fs::remove_file(&plan.monitor);
    let mut args = line(&restored);
    args.extend(["-incoming".to_string(), format!("file:{}", state.join(STATE).display())]);
    let child = emulator::spawn_emulator(&plan, &args, Stdio::null()).expect("the emulator starts");
    let mut child = Alive(child);
    let loaded = load(&plan, &mut child.0, Duration::from_secs(60));
    let after = if loaded.is_ok() { status(&plan) } else { String::new() };
    emulator::stop_emulator(&plan, &mut child.0);
    loaded.expect("the load");
    assert_eq!(after, "running", "the guest runs after the load");

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

/// The machine line of the plan, with its NVMe disks: QEMU 11 saves it and
/// [`start`] restores it; an older QEMU refuses the save with its reasons
/// and the guest goes on, and [`start`] boots cold.
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
    let (child, how) = start(&s, qemu_img, &base, &plan, agent::AGENT_CMD, &request("tok-live"), &w).unwrap();
    let mut child = Alive(child);
    let after = status(&plan);
    emulator::stop_emulator(&plan, &mut child.0);
    drop(child);
    assert_eq!(after, "running");
    if saved.is_ok() {
        assert_eq!(how, Start::Warm, "{}", f.qemu);
    } else {
        assert_eq!(how, Start::Cold(Cold::Missing));
    }
    let _ = std::fs::remove_dir_all(&d);
}
