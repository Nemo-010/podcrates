use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use pod_core::Class;

use super::*;
use crate::{Accel, Request, mailbox, run, scratch_dir, timeout_of};

/// A plan whose files are in `dir`, with the emulator `emulator`.
fn plan_in(dir: &Path, emulator: PathBuf) -> Plan {
    Plan {
        emulator,
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

fn request(token: &str) -> Request {
    Request { command: "exit 42".into(), token: token.into(), timeout: Duration::from_secs(1), mode: agent::Mode::Once }
}

/// Wait for `what` within a bound.
fn until(what: &str, mut done: impl FnMut() -> bool) {
    let start = Instant::now();
    while !done() {
        assert!(start.elapsed() < pod_testkit::host::scaled(Duration::from_secs(20)), "{what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// A stand-in of the emulator that writes a boot line to the serial log
/// and to its error stream, and lives until it is killed.
fn stand_in(dir: &Path, plan: &Plan) -> PathBuf {
    let fake = dir.join("fake-emulator");
    let script = format!(
        "#!/bin/sh\n[ \"$1\" = probe ] && exit 0\nprintf 'BdsDxe: starting Boot0001\\n' > {}\n\
         echo 'qemu: a warning' >&2\nexec sleep 600\n",
        plan.serial.display()
    );
    std::fs::write(&fake, script).unwrap();
    std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o700)).unwrap();
    // A file that a test thread just wrote can be busy (ETXTBSY) while
    // another thread forks: wait until it runs.
    until("the stand-in runs", || Command::new(&fake).arg("probe").status().is_ok_and(|s| s.success()));
    fake
}

/// A QMP stand-in on `monitor`: each `screendump` writes a small PPM and
/// counts; `quit` ends it and removes the socket, as an emulator that
/// exits. Returns the count of dumps.
fn qmp_stand(monitor: PathBuf) -> Arc<Mutex<usize>> {
    let _ = std::fs::remove_file(&monitor);
    let listener = UnixListener::bind(&monitor).expect("the QMP socket");
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
                    let _ = std::fs::write(file, b"P6\n2 1\n255\n\xff\xff\xff\x00\x00\x00");
                    *seen.lock().unwrap_or_else(|e| e.into_inner()) += 1;
                }
                let _ = out.write_all(b"{\"return\": {}}\n");
                if line.contains("\"quit\"") {
                    let _ = std::fs::remove_file(&monitor);
                    return;
                }
            }
        }
    });
    dumps
}

/// The mailbox of a run whose agent found it, ran the command, and had
/// each shutdown refused.
fn refused_shutdown(s: &Settings, token: &str) -> Fat16 {
    let mut m = mailbox(s, agent::AGENT_CMD, &request(token)).unwrap();
    m.put(agent::READY, b"WQREADY\r\n").unwrap();
    m.put(agent::CODE, format!("42 {token}\r\n").as_bytes()).unwrap();
    m.remove(agent::GO).unwrap();
    let log = "12:00:01.00 found D: after 0 tries\r\n12:00:02.00 code 42\r\n12:00:02.10 shutdown 21\r\n";
    m.put(agent::LOG, log.as_bytes()).unwrap();
    m
}

/// PodUtils/podvm#380: a run that timed out kept no trace. It keeps a
/// screen taken while the emulator runs, the serial log, the error stream
/// of the emulator and the mailbox, names their directory, and says what
/// the mailbox tells of the agent.
#[test]
fn a_run_that_times_out_keeps_a_screen_from_before_the_stop_and_its_logs() {
    pod_testkit::need_tool!("/bin/sh");
    pod_testkit::need_tool!("sleep");
    let mut s = Settings::new(std::env::temp_dir());
    let d = scratch_dir(&s, "evidence-kept").expect("a scratch directory");
    s.evidence = Some(d.join("evidence"));
    let plan = plan_in(&d, PathBuf::new());
    let plan = Plan { emulator: stand_in(&d, &plan), ..plan };
    let token = "tok/../one";
    std::fs::write(&plan.mailbox, refused_shutdown(&s, token).image()).unwrap();
    let dumps = qmp_stand(plan.monitor.clone());
    let e = run(&s, &plan, &request(token)).unwrap_err();
    let kept = dir(s.evidence.as_deref().unwrap(), token);
    let screen = std::fs::read(kept.join(SCREEN)).unwrap_or_default();
    let serial = std::fs::read_to_string(kept.join(SERIAL)).unwrap_or_default();
    let emulator = std::fs::read_to_string(kept.join(EMULATOR)).unwrap_or_default();
    let copy = std::fs::read(kept.join(MAILBOX)).ok().and_then(Fat16::from_image);
    let _ = std::fs::remove_dir_all(&d);
    let text = e.to_string();
    assert_eq!(e.class, Class::Timeout, "{text}");
    assert!(timeout_of(&e).is_some_and(|t| t.stop.confirmed()), "{text}");
    assert!(screen.starts_with(b"P6"), "no screen from before the stop: {text}");
    assert_eq!(*dumps.lock().unwrap(), 1);
    assert!(text.contains(&kept.display().to_string()), "the text names the directory: {text}");
    assert!(kept.ends_with("timeout-tok____one"), "{}", kept.display());
    assert!(text.contains("screen.ppm, serial.log, emulator.log, mailbox.img"), "{text}");
    assert!(serial.contains("BdsDxe"), "{serial:?}");
    assert!(emulator.contains("a warning"), "{emulator:?}");
    assert!(copy.is_some_and(|m| m.get(agent::LOG).is_some()), "the copy of the mailbox");
    assert!(text.contains("wrote the result (code 42) and the guest did not power off"), "{text}");
    assert!(text.contains("shutdown 21"), "the log of the agent is in the text: {text}");
}

/// With no evidence directory, a run that times out takes no screen and
/// writes no file; the text still says what the mailbox tells.
#[test]
fn a_run_with_no_evidence_directory_takes_no_screen() {
    pod_testkit::need_tool!("/bin/sh");
    pod_testkit::need_tool!("sleep");
    let s = Settings::new(std::env::temp_dir());
    let d = scratch_dir(&s, "evidence-none").expect("a scratch directory");
    let plan = plan_in(&d, PathBuf::new());
    let plan = Plan { emulator: stand_in(&d, &plan), ..plan };
    std::fs::write(&plan.mailbox, mailbox(&s, agent::AGENT_CMD, &request("tok-2")).unwrap().image()).unwrap();
    let dumps = qmp_stand(plan.monitor.clone());
    let e = run(&s, &plan, &request("tok-2")).unwrap_err();
    let left: Vec<_> = std::fs::read_dir(&d).unwrap().flatten().map(|e| e.file_name()).collect();
    let _ = std::fs::remove_dir_all(&d);
    let text = e.to_string();
    assert_eq!(e.class, Class::Timeout, "{text}");
    assert_eq!(*dumps.lock().unwrap(), 0, "a screen with no directory: {text}");
    assert!(!left.iter().any(|n| n.to_string_lossy().starts_with("timeout-")), "{left:?}");
    assert!(!text.contains("evidence"), "{text}");
    assert!(text.contains("the agent did not write WQREADY.TXT"), "{text}");
}

#[test]
fn the_mailbox_tells_what_the_agent_did() {
    let s = Settings::new(std::env::temp_dir());
    let mut m = mailbox(&s, agent::AGENT_CMD, &request("tok-3")).unwrap();
    assert!(seen(&m, "tok-3").contains("did not write WQREADY.TXT"), "{}", seen(&m, "tok-3"));
    m.put(agent::READY, b"WQREADY\r\n").unwrap();
    m.put(agent::LOG, b" 9:00:00.00 found E: after 7 tries\r\n").unwrap();
    let text = seen(&m, "tok-3");
    assert!(text.contains("found the mailbox and wrote no result"), "{text}");
    assert!(text.ends_with("the log of the agent:  9:00:00.00 found E: after 7 tries"), "{text}");
    m.put(agent::CODE, b"0 tok-other\r\n").unwrap();
    assert!(seen(&m, "tok-3").contains("another token"), "{}", seen(&m, "tok-3"));
    let m = refused_shutdown(&s, "tok-3");
    assert!(seen(&m, "tok-3").contains("code 42"), "{}", seen(&m, "tok-3"));
    // Only the last lines of a long log.
    let mut m = m;
    let long: String = (0..40).map(|i| format!("line {i}\r\n")).collect();
    m.put(agent::LOG, long.as_bytes()).unwrap();
    let text = seen(&m, "tok-3");
    assert!(text.contains("line 39") && text.contains("line 32") && !text.contains("line 31"), "{text}");
}

#[test]
fn the_directory_of_a_token_is_one_safe_name() {
    let root = Path::new("/ev");
    assert_eq!(dir(root, "0123abcd"), Path::new("/ev/timeout-0123abcd"));
    assert_eq!(dir(root, "../x y"), Path::new("/ev/timeout-___x_y"));
    assert_eq!(dir(root, ""), Path::new("/ev/timeout-run"));
    assert_eq!(dir(root, &"a".repeat(100)).file_name().unwrap().len(), "timeout-".len() + 64);
}
