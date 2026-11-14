use super::*;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::plan::Options;
use crate::{Accel, Mode, emulator, scratch_dir};

fn plan_in(dir: &Path, mailbox: MailboxBus) -> Plan {
    Plan {
        emulator: "qemu-system-x86_64".into(),
        accel: Accel::Tcg,
        share: "/usr/share/qemu".into(),
        firmware_code: dir.join("code.fd"),
        firmware_vars: dir.join("vars.fd"),
        root: dir.join("run.qcow2"),
        mailbox: dir.join("mailbox.img"),
        serial: dir.join("serial.log"),
        monitor: dir.join("qmp.sock"),
        memory_mib: 64,
        cpus: 1,
        options: Options { mailbox, ..Options::default() },
        emu_args: Vec::new(),
    }
}

fn dir(tag: &str) -> PathBuf {
    scratch_dir(&Settings::new(std::env::temp_dir()), tag).expect("a scratch directory")
}

fn request(command: &str, token: &str, mode: Mode) -> Request {
    Request { command: command.into(), token: token.into(), timeout: Duration::from_secs(10), mode }
}

fn read_file(path: &Path) -> Fat16 {
    Fat16::from_image(std::fs::read(path).unwrap()).unwrap()
}

/// Play the agent on the medium in `file`: the result of `token`, and the
/// token deleted when `deleted`.
fn agent_done(file: &Path, token: &str, deleted: bool) {
    let mut m = read_file(file);
    m.put(agent::OUT, b"out\r\n").unwrap();
    m.put(agent::ERR, b"").unwrap();
    m.put(agent::CODE, format!("0 {token}\r\n").as_bytes()).unwrap();
    if deleted {
        m.remove(agent::GO).unwrap();
    }
    std::fs::write(file, m.image()).unwrap();
}

/// A QMP stand-in on `socket` that keeps each request line and answers
/// `answer` to each one after the handshake.
fn stand(socket: &Path, answer: &'static str) -> Arc<Mutex<Vec<String>>> {
    let _ = std::fs::remove_file(socket);
    let listener = UnixListener::bind(socket).expect("the QMP socket");
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    std::thread::spawn(move || {
        let Ok((conn, _)) = listener.accept() else { return };
        let mut out = conn.try_clone().expect("a second handle");
        let _ = out.write_all(b"{\"QMP\": {\"version\": {}}}\n");
        for line in BufReader::new(conn).lines() {
            let Ok(line) = line else { break };
            let ok = line.contains("qmp_capabilities");
            log.lock().unwrap_or_else(|e| e.into_inner()).push(line);
            let reply = if ok { "{\"return\": {}}" } else { answer };
            if out.write_all(format!("{reply}\n").as_bytes()).is_err() {
                break;
            }
        }
    });
    seen
}

fn lines(seen: &Arc<Mutex<Vec<String>>>) -> Vec<String> {
    seen.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

/// A guest with the first command on a USB mailbox: the plan, its
/// settings and the swap.
fn staged(tag: &str) -> (PathBuf, Plan, Settings, Swap) {
    let d = dir(tag);
    let plan = plan_in(&d, MailboxBus::Usb);
    let s = Settings::new(std::env::temp_dir());
    let m = crate::mailbox(&s, agent::AGENT_CMD, &request("ver", "tok-1", Mode::KeepAlive)).unwrap();
    std::fs::write(&plan.mailbox, m.image()).unwrap();
    let swap = Swap::new(&plan, "tok-1").unwrap();
    (d, plan, s, swap)
}

/// A result is settled only when the agent deleted its token: a swap
/// before the delete lets the agent delete the token of the new medium.
#[test]
fn a_result_is_settled_only_after_the_agent_deleted_its_token() {
    let mut m = Fat16::new();
    m.put(agent::GO, b"tok-1").unwrap();
    m.put(agent::CODE, b"3 tok-1\r\n").unwrap();
    assert!(crate::poll_outcome(&m, "tok-1").is_some(), "the code is there");
    assert_eq!(settled(&m, "tok-1"), None, "the token is still on the medium");
    m.remove(agent::GO).unwrap();
    assert_eq!(settled(&m, "tok-1").map(|o| o.code), Some(3));
    assert_eq!(settled(&m, "tok-0"), None, "another token");
}

#[test]
fn a_fixed_mailbox_cannot_take_a_next_command() {
    let d = dir("swap-nvme");
    let plan = plan_in(&d, MailboxBus::Nvme);
    std::fs::write(&plan.mailbox, Fat16::new().image()).unwrap();
    let e = Swap::new(&plan, "tok-1").unwrap_err();
    assert_eq!(e.class, Class::Usage, "{e}");
    let _ = std::fs::remove_dir_all(&d);
}

/// Each next command goes to the other file, on a new mailbox with
/// another volume id, and the emulator gets `blockdev-change-medium` of
/// that file for the drive `mbox`.
#[test]
fn each_next_command_is_a_new_medium_in_the_other_file() {
    let (d, plan, s, mut swap) = staged("swap-next");
    let seen = stand(&plan.monitor, "{\"return\": {}}");
    let mut monitor = qmp::Monitor::connect(&plan.monitor, Duration::from_secs(5)).unwrap();
    let first = read_file(&plan.mailbox).volume_id();
    agent_done(&plan.mailbox, "tok-1", true);
    assert_eq!(swap.poll().unwrap().map(|o| o.stdout), Some(b"out\r\n".to_vec()));

    swap.next(&mut monitor, &s, agent::AGENT_CMD, &request("dir C:\\", "tok-2", Mode::KeepAlive)).unwrap();
    let other = other_file(&plan);
    assert_eq!(swap.current(), other.as_path());
    assert_eq!(swap.token(), "tok-2");
    let m = read_file(&other);
    assert_ne!(m.volume_id(), first, "Windows reads a medium again only for another volume id");
    assert_eq!(m.get(agent::GO).as_deref(), Some(&b"tok-2"[..]));
    assert!(m.get(agent::KEEP).is_some());
    assert!(m.get(agent::CODE).is_none() && !agent::ready(&m), "a new mailbox");
    assert_eq!(swap.poll().unwrap(), None, "no result of tok-2 yet");
    let sent = lines(&seen);
    let change = sent.last().unwrap();
    assert_eq!(qmp::json_member(change, "execute").as_deref(), Some("blockdev-change-medium"));
    assert_eq!(qmp::json_member(change, "device").as_deref(), Some("mbox"));
    assert_eq!(qmp::json_member(change, "filename").as_deref(), other.to_str());

    // The last command: no keep-alive file, so the agent shuts down after it.
    agent_done(&other, "tok-2", true);
    swap.next(&mut monitor, &s, agent::AGENT_CMD, &request("ver", "tok-3", Mode::Once)).unwrap();
    assert_eq!(swap.current(), plan.mailbox.as_path(), "back to the first file");
    let m = read_file(&plan.mailbox);
    assert!(m.get(agent::KEEP).is_none());
    assert_ne!(m.volume_id(), read_file(&other).volume_id());
    assert_eq!(lines(&seen).iter().filter(|l| l.contains("blockdev-change-medium")).count(), 2);
    let _ = std::fs::remove_dir_all(&d);
}

/// No swap while the guest still uses the medium, and a refusal of the
/// emulator keeps the medium and the token.
#[test]
fn no_swap_before_the_result_is_settled_and_a_refusal_keeps_the_medium() {
    let (d, plan, s, mut swap) = staged("swap-refused");
    let seen = stand(&plan.monitor, "{\"error\": {\"class\": \"GenericError\", \"desc\": \"Device is locked\"}}");
    let mut monitor = qmp::Monitor::connect(&plan.monitor, Duration::from_secs(5)).unwrap();
    let next = request("ver", "tok-2", Mode::KeepAlive);
    let e = swap.next(&mut monitor, &s, agent::AGENT_CMD, &next).unwrap_err();
    assert_eq!(e.class, Class::Usage, "no result: {e}");
    agent_done(&plan.mailbox, "tok-1", false);
    let e = swap.next(&mut monitor, &s, agent::AGENT_CMD, &next).unwrap_err();
    assert_eq!(e.class, Class::Usage, "the token is still there: {e}");
    assert_eq!(lines(&seen).len(), 1, "only the handshake: {:?}", lines(&seen));

    agent_done(&plan.mailbox, "tok-1", true);
    let e = swap.next(&mut monitor, &s, agent::AGENT_CMD, &next).unwrap_err();
    assert_eq!(e.class, Class::Protocol, "{e}");
    assert!(e.to_string().contains("Device is locked"), "{e}");
    assert_eq!(swap.current(), plan.mailbox.as_path());
    assert_eq!(swap.token(), "tok-1");
    assert!(swap.poll().unwrap().is_some(), "the result of tok-1 stays readable");
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn the_change_request_names_the_drive_and_the_file_as_json() {
    let r = change_request(Path::new("/run/a \"b\".img")).unwrap();
    assert_eq!(
        r,
        "{\"execute\":\"blockdev-change-medium\",\"arguments\":{\"device\":\"mbox\",\"filename\":\"/run/a \\\"b\\\".img\",\"format\":\"raw\"}}"
    );
    let bad = <std::ffi::OsStr as std::os::unix::ffi::OsStrExt>::from_bytes(b"/run/\xff.img");
    assert_eq!(change_request(Path::new(bad)).unwrap_err().class, Class::Usage);
}

/// The QEMU of the host takes the line of a USB mailbox and changes its
/// medium two times. The firmware is 2 MiB of `hlt`: no OS runs.
#[test]
fn a_real_emulator_changes_the_medium_of_a_usb_mailbox() {
    pod_testkit::need_tool!("qemu-system-x86_64");
    pod_testkit::need_tool!("qemu-img");
    let d = dir("swap-live");
    let plan = plan_in(&d, MailboxBus::Usb);
    std::fs::write(&plan.firmware_code, vec![0xf4u8; 2 << 20]).unwrap();
    std::fs::write(&plan.firmware_vars, vec![0u8; 128 << 10]).unwrap();
    let base = d.join("base.img");
    std::fs::write(&base, vec![0u8; 4 << 20]).unwrap();
    let s = Settings::new(std::env::temp_dir());
    let first = request("ver", "tok-1", Mode::KeepAlive);
    crate::stage(&s, Path::new("qemu-img"), &base, &plan, agent::AGENT_CMD, &first).unwrap();
    let child = emulator::spawn_uefi(&plan, Stdio::null()).expect("the emulator starts");
    let mut running = emulator::Running::new(&plan, child);
    let mut monitor = qmp::Monitor::connect(&plan.monitor, Duration::from_secs(30)).expect("the QMP socket");
    let mut swap = Swap::new(&plan, "tok-1").unwrap();
    let mut files = Vec::new();
    for (n, token) in ["tok-2", "tok-3"].into_iter().enumerate() {
        let before = swap.current().to_path_buf();
        agent_done(&before, swap.token(), true);
        let next = request("ver", token, Mode::KeepAlive);
        let swapped = swap.next(&mut monitor, &s, agent::AGENT_CMD, &next).map_err(|e| format!("swap {n}: {e}"));
        let block = monitor.ask("{\"execute\":\"query-block\"}").unwrap_or_default();
        let has = |p: &Path| block.contains(&qmp::json_text(p.to_str().unwrap()));
        files.push(swapped.map(|()| (has(swap.current()), has(&before))));
    }
    drop(monitor);
    let _ = running.child().kill();
    drop(running);
    let want: Vec<std::result::Result<(bool, bool), String>> = vec![Ok((true, false)), Ok((true, false))];
    assert_eq!(files, want, "query-block names the new file and not the old one after each swap");
    let _ = std::fs::remove_dir_all(&d);
}
