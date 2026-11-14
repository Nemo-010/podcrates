use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::Command;

use super::*;
use crate::ready::Sign;
use crate::{Accel, scratch_dir};

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

/// Wait for `what` within a bound.
fn until(what: &str, mut done: impl FnMut() -> bool) {
    let start = Instant::now();
    while !done() {
        assert!(start.elapsed() < pod_testkit::host::scaled(Duration::from_secs(20)), "{what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// True while the process `pid` runs. A zombie has ended.
fn alive(pid: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .is_ok_and(|stat| !stat.rsplit(')').next().unwrap_or_default().trim_start().starts_with('Z'))
}

/// A QMP stand-in on `monitor` that refuses each `send-key` and accepts
/// each other request, for each connection.
fn refusing_keys(monitor: PathBuf) {
    let listener = UnixListener::bind(&monitor).expect("the QMP socket");
    for conn in listener.incoming() {
        let Ok(conn) = conn else { return };
        let mut out = conn.try_clone().expect("a second handle");
        let _ = out.write_all(b"{\"QMP\": {\"version\": {}}}\n");
        for line in BufReader::new(conn).lines() {
            let Ok(line) = line else { break };
            let answer: &[u8] = if line.contains("send-key") {
                b"{\"error\": {\"class\": \"GenericError\", \"desc\": \"no keyboard\"}}\n"
            } else {
                b"{\"return\": {}}\n"
            };
            if out.write_all(answer).is_err() {
                break;
            }
        }
    }
}

/// PodUtils/podvm#370: QMP refuses the keys of the provision. The failure
/// comes back, and no emulator stays after it.
#[test]
fn a_provision_whose_keys_fail_leaves_no_emulator() {
    pod_testkit::need_tool!("/bin/sh");
    pod_testkit::need_tool!("sleep");
    pod_testkit::need_tool!("true");
    let s = Settings::new(std::env::temp_dir());
    let d = scratch_dir(&s, "provision-keys").expect("a scratch directory");
    let (pidfile, fake) = (d.join("emulator.pid"), d.join("fake-emulator"));
    let plan = plan_in(&d, fake.clone());
    // The stand-in of the emulator says that the guest is ready on the
    // serial line, writes its pid, and lives.
    let script = format!(
        "#!/bin/sh\n[ \"$1\" = probe ] && exit 0\nprintf READY > {}\necho $$ > {}\nexec sleep 600\n",
        plan.serial.display(),
        pidfile.display()
    );
    std::fs::write(&fake, script).unwrap();
    std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o700)).unwrap();
    // A file that a test thread just wrote can be busy (ETXTBSY) while
    // another thread forks: wait until it runs.
    until("the stand-in runs", || Command::new(&fake).arg("probe").status().is_ok_and(|s| s.success()));
    // The provision removes the socket before the spawn: the stand-in of
    // QMP binds it after the emulator starts.
    let (monitor, started) = (plan.monitor.clone(), pidfile.clone());
    std::thread::spawn(move || {
        until("the stand-in of the emulator starts", || started.exists());
        refusing_keys(monitor);
    });
    let ready =
        Ready { signs: vec![Sign::Serial("READY".into())], deadline: Duration::from_secs(60), every: ready::EVERY };
    let out = d.join("out.qcow2");
    let e = provision(&s, Path::new("true"), &d.join("base"), &plan, &out, &ready, Duration::from_secs(5)).unwrap_err();
    let pid: u32 = std::fs::read_to_string(&pidfile).unwrap().trim().parse().unwrap();
    let left = alive(pid);
    if left {
        let _ = pod_hostprobe::sys::kill(i64::from(pid), 9);
    }
    let _ = std::fs::remove_dir_all(&d);
    assert!(e.to_string().contains("qmp refused"), "{e}");
    assert!(!left, "an emulator stays after a provision whose keys failed");
}
