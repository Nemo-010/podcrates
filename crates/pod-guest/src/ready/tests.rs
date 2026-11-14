use super::*;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::process::Command;
use std::sync::{Arc, Mutex};

use crate::{Accel, Settings, scratch_dir};

/// A plan whose files are in the per-run directory `dir`.
fn plan_in(dir: &Path) -> Plan {
    Plan {
        emulator: "/bin/sh".into(),
        accel: Accel::Tcg,
        share: "/usr/share/qemu".into(),
        firmware_code: "/code.fd".into(),
        firmware_vars: dir.join("vars.fd"),
        root: dir.join("run.qcow2"),
        mailbox: dir.join("mailbox.img"),
        serial: dir.join("serial.log"),
        monitor: dir.join("qmp.sock"),
        memory_mib: 512,
        cpus: 1,
        options: Default::default(),
        emu_args: Vec::new(),
    }
}

fn dir(tag: &str) -> PathBuf {
    scratch_dir(&Settings::new(std::env::temp_dir()), tag).expect("a scratch directory")
}

/// A child that lives until the test kills it: the emulator of a wait.
struct Alive(Child);

impl Alive {
    fn start() -> Alive {
        Alive(Command::new("sleep").arg("600").spawn().expect("sleep starts"))
    }
}

impl Drop for Alive {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn quick(signs: Vec<Sign>, deadline: Duration) -> Ready {
    Ready { signs, deadline, every: Duration::from_millis(10) }
}

/// A QMP stand-in on the socket of `plan`: each `screendump` writes the
/// next frame of `frames` (the last one again after the end). It returns
/// the count of dumps.
fn screen_stand(plan: &Plan, frames: Vec<&'static [u8]>) -> Arc<Mutex<usize>> {
    // A run that failed can leave its socket, and a later process can get
    // its pid and so its directory.
    let _ = std::fs::remove_file(&plan.monitor);
    let listener = UnixListener::bind(&plan.monitor).expect("the QMP socket");
    let dumps = Arc::new(Mutex::new(0usize));
    let seen = dumps.clone();
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(conn) = conn else { return };
            let mut out = conn.try_clone().expect("a second handle");
            let _ = out.write_all(b"{\"QMP\": {\"version\": {}}}\n");
            for line in BufReader::new(conn).lines() {
                let Ok(line) = line else { break };
                if let Some(rest) = line.split("\"filename\":\"").nth(1) {
                    let file = rest.split('"').next().unwrap_or_default();
                    let mut n = seen.lock().unwrap_or_else(|e| e.into_inner());
                    let frame = frames[(*n).min(frames.len() - 1)];
                    *n += 1;
                    let _ = std::fs::write(file, frame);
                }
                if out.write_all(b"{\"return\": {}}\n").is_err() {
                    break;
                }
            }
        }
    });
    dumps
}

#[test]
fn the_marker_of_the_agent_on_the_mailbox_is_a_ready_guest() {
    pod_testkit::need_tool!("sleep");
    let d = dir("ready-marker");
    let plan = plan_in(&d);
    let mut m = Fat16::new();
    m.put(agent::READY, b"WQREADY\r\n").unwrap();
    std::fs::write(&plan.mailbox, m.image()).unwrap();
    let mut child = Alive::start();
    let ready = quick(vec![Sign::Serial("never".into()), Sign::Marker], Duration::from_secs(60));
    assert_eq!(wait(&plan, &mut child.0, &ready).unwrap(), 1, "the second sign held");
    let _ = std::fs::remove_dir_all(&d);
}

/// A text that two polls cut in two is found; a log that became shorter is
/// read again from its start.
#[test]
fn a_serial_text_is_found_across_two_polls() {
    let mut scan = Scan::new(b"WQ READY");
    assert!(!scan.feed(b"BdsDxe: loading ... WQ RE"));
    assert!(scan.feed(b"ADY\r\n"));
    let d = dir("ready-serial");
    let log = d.join("serial.log");
    let mut scan = Scan::new(b"login:");
    assert!(!scan.poll(&log), "no log yet");
    std::fs::write(&log, b"boot... log").unwrap();
    assert!(!scan.poll(&log));
    std::fs::OpenOptions::new().append(true).open(&log).unwrap().write_all(b"in: ").unwrap();
    assert!(scan.poll(&log));
    let mut scan = Scan::new(b"again");
    std::fs::write(&log, vec![b'x'; 4096]).unwrap();
    assert!(!scan.poll(&log));
    std::fs::write(&log, b"again").unwrap();
    assert!(scan.poll(&log), "a log that a new boot wrote again");
    let _ = std::fs::remove_dir_all(&d);
}

/// The screen of the boot changes, then stays: ready. A screen that never
/// changes after the first dump is not ready, and the deadline names the
/// sign.
#[test]
fn a_screen_that_changed_and_settled_is_ready_and_a_still_one_is_not() {
    pod_testkit::need_loopback!();
    pod_testkit::need_tool!("sleep");
    let d = dir("ready-screen");
    let plan = plan_in(&d);
    let dumps = screen_stand(&plan, vec![b"P6 firmware", b"P6 firmware", b"P6 shell", b"P6 shell"]);
    let mut child = Alive::start();
    let settle = quick(vec![Sign::Screen { settle: Duration::ZERO }], Duration::from_secs(60));
    assert_eq!(wait(&plan, &mut child.0, &settle).unwrap(), 0);
    assert_eq!(*dumps.lock().unwrap(), 4, "a change at the third dump, the same at the fourth");
    assert!(!dump_path(&plan.monitor).exists(), "each dump is removed");

    let d2 = dir("ready-still");
    let plan = plan_in(&d2);
    let dumps = screen_stand(&plan, vec![b"P6 one screen"]);
    let still = quick(vec![Sign::Screen { settle: Duration::ZERO }], Duration::from_millis(300));
    let e = wait(&plan, &mut child.0, &still).unwrap_err();
    assert!(matches!(unready(&e), Some(Unready::Deadline { .. })), "{e}");
    assert_eq!(e.class, Class::Timeout);
    assert!(e.to_string().contains("a screen that changed"), "{e}");
    assert!(*dumps.lock().unwrap() >= 2, "the screen was read on each poll");
    let _ = std::fs::remove_dir_all(&d);
    let _ = std::fs::remove_dir_all(&d2);
}

#[test]
fn no_sign_within_the_deadline_is_a_timeout_that_names_each_sign() {
    pod_testkit::need_tool!("sleep");
    let d = dir("ready-deadline");
    let plan = plan_in(&d);
    let mut child = Alive::start();
    let ready = quick(vec![Sign::Marker, Sign::Serial("login:".into())], Duration::from_millis(200));
    let e = wait(&plan, &mut child.0, &ready).unwrap_err();
    assert_eq!(e.class, Class::Timeout);
    let Some(Unready::Deadline { signs, .. }) = unready(&e) else { panic!("{e}") };
    assert_eq!(signs.len(), 2);
    assert!(e.to_string().contains("WQREADY.TXT") && e.to_string().contains("\"login:\""), "{e}");
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn an_emulator_that_exits_first_ends_the_wait() {
    pod_testkit::need_tool!("/bin/sh");
    let d = dir("ready-exit");
    let plan = plan_in(&d);
    let mut child = Command::new("/bin/sh").args(["-c", "exit 3"]).spawn().unwrap();
    let e = wait(&plan, &mut child, &quick(vec![Sign::Marker], Duration::from_secs(60))).unwrap_err();
    assert!(matches!(unready(&e), Some(Unready::Exited { .. })), "{e}");
    assert_eq!(e.class, Class::Unavailable);
    assert!(e.to_string().contains("exit status: 3"), "{e}");
    let _ = std::fs::remove_dir_all(&d);
}

/// The provision types its line only into a ready guest: an emulator that
/// exits at once ends the provision at once, not after a fixed sleep.
#[test]
fn the_provision_waits_for_a_ready_guest_and_not_for_a_fixed_time() {
    pod_testkit::need_tool!("/bin/sh");
    pod_testkit::need_tool!("true");
    let d = dir("ready-provision");
    // `/bin/sh -M q35 ...` refuses its first option and exits.
    let plan = plan_in(&d);
    let start = Instant::now();
    let e = crate::provision(
        &Settings::new(std::env::temp_dir()),
        Path::new("true"),
        Path::new("base.vhdx"),
        &plan,
        &d.join("out.qcow2"),
        &Ready::screen(Duration::from_secs(3600)),
        Duration::from_secs(3600),
    )
    .unwrap_err();
    assert!(matches!(unready(&e), Some(Unready::Exited { .. })), "{e}");
    assert!(start.elapsed() < Duration::from_secs(600), "no fixed sleep");
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn a_path_goes_into_json_as_a_string() {
    assert_eq!(qmp::json_text("/run/a b/screen.ppm"), "\"/run/a b/screen.ppm\"");
    assert_eq!(qmp::json_text("q\"\\\n"), "\"q\\\"\\\\\\u000a\"");
}
