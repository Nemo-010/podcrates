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
    stand_with(socket, move |_| answer.to_string())
}

/// A QMP stand-in on `socket` that keeps each request line and answers
/// `reply` of it after the handshake.
fn stand_with(socket: &Path, mut reply: impl FnMut(&str) -> String + Send + 'static) -> Arc<Mutex<Vec<String>>> {
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
            let reply = if line.contains("qmp_capabilities") { "{\"return\": {}}".to_string() } else { reply(&line) };
            log.lock().unwrap_or_else(|e| e.into_inner()).push(line);
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
/// that file for the device `wqmbox`, by `id` and not by the deprecated
/// `device`.
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
    assert_eq!(qmp::json_member(change, "id").as_deref(), Some("wqmbox"));
    assert!(!change.contains("\"device\""), "{change}");
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

const LOCKED: &str = "{\"error\": {\"class\": \"GenericError\", \"desc\": \"Device 'mbox' is locked and force was not \
                      specified, wait for tray to open and try again\"}}";

const DEPRECATED: &str =
    "{\"error\": {\"class\": \"GenericError\", \"desc\": \"Deprecated parameter device disabled by policy\"}}";

/// A QMP stand-in of a drive whose medium the guest locks, as QEMU 8.2
/// answers (`do_open_tray` of `block/qapi-sysemu.c`): a change with no
/// `force` and no open tray is refused, and a `blockdev-open-tray` with no
/// `force` leaves the tray closed. The guest locks each new medium again.
/// As QEMU with `-compat deprecated-input=reject`, it refuses the
/// argument `device`, and it knows only the device `wqmbox`.
fn locked_drive() -> impl FnMut(&str) -> String + Send + 'static {
    let mut open = false;
    move |line| {
        let force = line.contains("\"force\":true");
        let ok = "{\"return\": {}}".to_string();
        if line.contains("\"device\"") {
            return DEPRECATED.to_string();
        }
        if line.contains("\"arguments\"") && qmp::json_member(line, "id").as_deref() != Some("wqmbox") {
            return "{\"error\": {\"class\": \"DeviceNotFound\", \"desc\": \"Device not found\"}}".to_string();
        }
        match qmp::json_member(line, "execute").as_deref() {
            Some("blockdev-open-tray") => {
                open |= force;
                ok
            }
            Some("blockdev-change-medium") if open || force => {
                open = false;
                ok
            }
            Some("blockdev-change-medium") => LOCKED.to_string(),
            _ => ok,
        }
    }
}

/// Windows locks the medium that it has mounted. Each swap changes the
/// locked medium, and a change with no `force` gets the refusal of QEMU.
/// A change that names the drive by `device` is refused.
#[test]
fn a_swap_changes_a_medium_that_the_guest_locked() {
    let (d, plan, s, mut swap) = staged("swap-locked");
    let seen = stand_with(&plan.monitor, locked_drive());
    let mut monitor = qmp::Monitor::connect(&plan.monitor, Duration::from_secs(5)).unwrap();
    let plain = "{\"execute\":\"blockdev-change-medium\",\"arguments\":{\"id\":\"wqmbox\",\"filename\":\"x\"}}";
    let e = monitor.ask(plain).unwrap_err();
    assert!(e.to_string().contains("is locked and force was not specified"), "the stand-in holds the lock: {e}");
    let e = monitor.ask(&plain.replace("\"id\":\"wqmbox\"", "\"device\":\"mbox\"")).unwrap_err();
    assert!(e.to_string().contains("Deprecated parameter device"), "the stand-in refuses `device`: {e}");
    for token in ["tok-2", "tok-3"] {
        agent_done(swap.current(), swap.token(), true);
        swap.next(&mut monitor, &s, agent::AGENT_CMD, &request("ver", token, Mode::KeepAlive))
            .unwrap_or_else(|e| panic!("{token}: {e}"));
        assert_eq!(swap.token(), token);
    }
    assert_eq!(swap.current(), plan.mailbox.as_path(), "two swaps: back to the first file");
    let changes = lines(&seen).iter().filter(|l| l.contains("blockdev-change-medium")).count();
    assert_eq!(changes, 4, "two refused, two swaps");
    let _ = std::fs::remove_dir_all(&d);
}

/// The lock comes from the entry of the device `wqmbox`: QEMU writes the
/// members of an entry in no fixed order.
#[test]
fn the_lock_of_the_mailbox_is_read_from_its_entry_of_query_block() {
    let block = "{\"return\": [{\"device\": \"root\", \"locked\": false, \"removable\": false, \"qdev\": \"/machine/peripheral-anon/device[1]\"}, \
                 {\"io-status\": \"ok\", \"device\": \"mbox\", \"locked\": true, \"removable\": true, \"inserted\": {\"ro\": true, \
                 \"file\": \"a.img\"}, \"qdev\": \"wqmbox\", \"tray_open\": false}]}";
    assert_eq!(mailbox_locked(block), Some(true));
    assert_eq!(mailbox_locked(&block.replace("\"locked\": true", "\"locked\": false")), Some(false));
    assert_eq!(mailbox_locked(&block.replace("wqmbox", "usb0")), None, "no mailbox device");
    assert_eq!(mailbox_locked("{\"return\": []}"), None);
}

#[test]
fn the_change_request_names_the_device_and_the_file_as_json() {
    let r = change_request(Path::new("/run/a \"b\".img")).unwrap();
    assert_eq!(
        r,
        "{\"execute\":\"blockdev-change-medium\",\"arguments\":{\"id\":\"wqmbox\",\"filename\":\"/run/a \\\"b\\\".img\",\"format\":\"raw\",\"force\":true}}"
    );
    let bad = <std::ffi::OsStr as std::os::unix::ffi::OsStrExt>::from_bytes(b"/run/\xff.img");
    assert_eq!(change_request(Path::new(bad)).unwrap_err().class, Class::Usage);
}

/// The arguments of a QEMU that refuses each deprecated argument of QMP.
const NO_DEPRECATED: [&str; 2] = ["-compat", "deprecated-input=reject"];

/// The QEMU of the host takes the line of a USB mailbox and changes its
/// medium two times, with no deprecated argument. The firmware is 2 MiB
/// of `hlt`: no OS runs.
#[test]
fn a_real_emulator_changes_the_medium_of_a_usb_mailbox() {
    pod_testkit::need_tool!("qemu-system-x86_64");
    pod_testkit::need_tool!("qemu-img");
    let d = dir("swap-live");
    let mut plan = plan_in(&d, MailboxBus::Usb);
    plan.emu_args = NO_DEPRECATED.map(String::from).to_vec();
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

/// A guest of real mode, at the reset vector of the pc machine. It loops:
/// REQUEST SENSE (it takes the reports of a new medium and clears the unit
/// attention), then PREVENT ALLOW MEDIUM REMOVAL with the lock bit, to the
/// ATAPI drive at the primary IDE ports. So it locks each medium that the
/// drive gets, as Windows locks its mounted stick. No QMP command locks a
/// tray: only a guest can.
const LOCK_GUEST: [u8; 93] = [
    0xba, 0xf6, 0x01, 0xb0, 0xa0, 0xee, // select the master drive
    0xba, 0xf1, 0x01, 0x30, 0xc0, 0xee, // features 0: no DMA
    0xba, 0xf4, 0x01, 0xee, 0xba, 0xf5, 0x01, 0xb0, 0x08, 0xee, // byte count 2048
    0xba, 0xf7, 0x01, 0xb0, 0xa0, 0xee, // PACKET
    0xba, 0xf0, 0x01, 0xb8, 0x03, 0x00, 0xef, 0x31, 0xc0, 0xef, // REQUEST SENSE,
    0xb8, 0x12, 0x00, 0xef, 0x31, 0xc0, 0xef, 0xef, 0xef, // 18 bytes
    0xba, 0xf7, 0x01, 0xec, 0xa8, 0x08, 0x74, 0x06, // while DRQ:
    0xba, 0xf0, 0x01, 0xed, 0xeb, 0xf2, // read one word
    0xba, 0xf7, 0x01, 0xb0, 0xa0, 0xee, // PACKET
    0xba, 0xf0, 0x01, 0xb8, 0x1e, 0x00, 0xef, 0x31, 0xc0, 0xef, // PREVENT ALLOW MEDIUM REMOVAL,
    0xb8, 0x01, 0x00, 0xef, 0x31, 0xc0, 0xef, 0xef, 0xef, // prevent
    0xb9, 0xff, 0xff, 0xe2, 0xfe, // a short delay
    0xeb, 0xa3, // to the start
];

/// The firmware of 64 KiB with [`LOCK_GUEST`] at its start and a far jump
/// to it at the reset vector, 16 bytes before the end.
fn lock_firmware() -> Vec<u8> {
    let mut rom = vec![0xf4u8; 64 << 10];
    rom[..LOCK_GUEST.len()].copy_from_slice(&LOCK_GUEST);
    rom[0xfff0..0xfff5].copy_from_slice(&[0xea, 0x00, 0x00, 0x00, 0xf0]);
    rom
}

/// Wait up to 30 s until the guest locks the medium of the mailbox.
fn wait_locked(monitor: &mut qmp::Monitor) -> std::result::Result<(), String> {
    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_secs(30) {
        let block = monitor.ask("{\"execute\":\"query-block\"}").map_err(|e| e.to_string())?;
        if mailbox_locked(&block) == Some(true) {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Err("the guest did not lock the medium within 30 s".into())
}

/// The QEMU of the host with a guest that locks the medium of the device
/// `wqmbox` (an ATAPI drive of the same tray code as the USB disk): a
/// change with no `force` gets the refusal of the run on Windows, and two
/// swaps change the locked medium. The emulator refuses each deprecated
/// argument.
#[test]
fn a_real_emulator_changes_a_medium_that_the_guest_locked() {
    pod_testkit::need_tool!("qemu-system-x86_64");
    let (d, plan, s, mut swap) = staged("swap-live-locked");
    let rom = d.join("lock.rom");
    std::fs::write(&rom, lock_firmware()).unwrap();
    let mut args: Vec<String> =
        ["-machine", "pc", "-accel", "tcg", "-display", "none", "-nodefaults"].map(String::from).to_vec();
    args.extend(NO_DEPRECATED.map(String::from));
    args.push("-bios".into());
    args.push(crate::plan::options::escape(&rom));
    args.push("-drive".into());
    args.push(format!("if=none,id=mbox,file={},format=raw,media=cdrom", crate::plan::options::escape(&plan.mailbox)));
    args.push("-device".into());
    args.push("ide-cd,drive=mbox,bus=ide.0,unit=0,id=wqmbox".into());
    args.push("-qmp".into());
    args.push(format!("unix:{},server=on,wait=off", plan.monitor.display()));
    let child = emulator::spawn_emulator(&plan, &args, Stdio::null()).expect("the emulator starts");
    let mut running = emulator::Running::new(&plan, child);
    let mut monitor = qmp::Monitor::connect(&plan.monitor, Duration::from_secs(30)).expect("the QMP socket");
    let mut run = || -> std::result::Result<(), String> {
        wait_locked(&mut monitor)?;
        // QEMU opens the file before it looks at the tray.
        std::fs::copy(&plan.mailbox, other_file(&plan)).map_err(|e| e.to_string())?;
        let plain = change_request(&other_file(&plan)).unwrap().replace(",\"force\":true", "");
        match monitor.ask(&plain) {
            Err(e) if e.to_string().contains("is locked and force was not specified") => {}
            other => return Err(format!("a change with no force: {other:?}")),
        }
        for token in ["tok-2", "tok-3"] {
            let before = swap.current().to_path_buf();
            agent_done(&before, swap.token(), true);
            let next = request("ver", token, Mode::KeepAlive);
            swap.next(&mut monitor, &s, agent::AGENT_CMD, &next).map_err(|e| format!("{token}: {e}"))?;
            let block = monitor.ask("{\"execute\":\"query-block\"}").map_err(|e| e.to_string())?;
            let has = |p: &Path| block.contains(&qmp::json_text(p.to_str().unwrap()));
            if !has(swap.current()) || has(&before) {
                return Err(format!("{token}: query-block does not name only the new file: {block}"));
            }
            wait_locked(&mut monitor).map_err(|e| format!("{token}: {e}"))?;
        }
        Ok(())
    };
    let outcome = run();
    drop(monitor);
    let _ = running.child().kill();
    drop(running);
    assert_eq!(outcome, Ok(()));
    let _ = std::fs::remove_dir_all(&d);
}
