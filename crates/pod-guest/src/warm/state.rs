//! The save and the restore of a saved state, through QMP.

use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::Child;
use std::time::{Duration, Instant};

use pod_core::Class;

use super::{Cold, FINGERPRINT, Fingerprint, MAILBOX, ROOT, STATE, VARS, Warm, log_stream};
use crate::plan::MailboxBus;
use crate::swap::{self, Swap};
use crate::{Fat16, Plan, Request, Result, Settings, agent, context, emulator, failure, io_at, overlay_argv, qmp};

/// The time between two polls of the emulator.
const EVERY: Duration = Duration::from_millis(50);
/// The wait for the QMP socket of a guest that runs.
const MONITOR_WAIT: Duration = Duration::from_secs(5);
/// The rate of the save, in bytes each second. The guest is stopped, so
/// the default limit of the emulator only makes the save slower.
const BANDWIDTH: u64 = 1 << 40;

/// The `-incoming` arguments of a restore from `dir`, after the machine
/// line of `plan` ([`crate::argv`]), with no program.
pub fn incoming_argv(plan: &Plan, dir: &Path) -> Result<Vec<String>> {
    let mut a = crate::argv(plan);
    a.push("-incoming".to_string());
    a.push(format!("file:{}", uri_path(&dir.join(STATE))?));
    Ok(a)
}

/// `path` as the path of a `file:` URI: UTF-8 with no comma, as the
/// emulator reads `,offset=` after the path.
fn uri_path(path: &Path) -> Result<&str> {
    match path.to_str() {
        Some(p) if !p.contains(',') => Ok(p),
        _ => Err(failure(Class::Usage, format!("{}: a saved state needs a UTF-8 path with no comma", path.display()))),
    }
}

/// Check that the mailbox `m` is the one of an idle agent in keep-alive
/// mode: [`agent::READY`] and [`agent::KEEP`] on it, and no
/// [`agent::GO`]. A token on the mailbox is a command that waits or runs,
/// and a state with it runs that command again at each restore.
pub fn idle(m: &Fat16) -> Result<()> {
    let why = if !agent::ready(m) {
        "the agent did not write WQREADY.TXT"
    } else if m.get(agent::KEEP).is_none() {
        "no WQKEEP.TXT: the guest is not in keep-alive mode"
    } else if m.get(agent::GO).is_some() {
        "WQGO.TXT is on the mailbox: a command waits or runs"
    } else {
        return Ok(());
    };
    Err(failure(Class::Usage, format!("the guest is not an idle agent: {why}")))
}

/// Refuse a plan whose mailbox is not [`MailboxBus::Usb`]: the restored
/// guest holds the saved mailbox in its cache, and only a new medium
/// gives it the next command.
fn usb_mailbox(plan: &Plan) -> Result<()> {
    if plan.options.mailbox == MailboxBus::Usb {
        return Ok(());
    }
    Err(failure(
        Class::Usage,
        "a warm start needs a USB mailbox (MailboxBus::Usb): the restored guest reads the saved mailbox from its \
         cache, and only a new medium gives it the next command",
    ))
}

/// Freeze the guest of `plan`, which runs, into `dir`, and let it go on.
///
/// The guest must be an idle agent in keep-alive mode ([`idle`]) on a USB
/// mailbox ([`MailboxBus::Usb`], else [`Class::Usage`]): the caller boots
/// it with [`super::stage_idle`] and waits for
/// [`crate::ready::Sign::Marker`]. The save stops the guest, writes the
/// migration stream, copies the overlay, the medium in the mailbox device
/// (after a swap it is the other file, [`swap::mailbox_file`]) and the
/// variable store, writes `fingerprint` last, and then sends `cont`. The
/// files go to `DIR.part` first and get the name `dir` at the end, so a
/// save that fails leaves no state and the state before it.
///
/// An emulator that cannot migrate a device of the plan is
/// [`Class::Unavailable`] with its reasons. A save that does not end
/// within `wait` is cancelled ([`Class::Timeout`]). The overlay must name
/// its base by an absolute path: the copy is in another directory.
pub fn save(plan: &Plan, fingerprint: &Fingerprint, dir: &Path, wait: Duration) -> Result<()> {
    let mut part = dir.as_os_str().to_owned();
    part.push(".part");
    let part = PathBuf::from(part);
    uri_path(&part.join(STATE))?;
    usb_mailbox(plan)?;
    let mut m = qmp::Monitor::connect(&plan.monitor, MONITOR_WAIT)?;
    let line = m.ask("{\"execute\":\"query-migrate\"}")?;
    if let Some(reasons) = blocked(&line) {
        return Err(failure(Class::Unavailable, format!("the emulator cannot save this guest: {reasons}")));
    }
    m.call("stop")?;
    let made = freeze(&mut m, plan, fingerprint, &part, wait);
    // The guest goes on in each case: a failed save leaves it as it was.
    let resumed = m.call("cont");
    if let Err(e) = made {
        let _ = std::fs::remove_dir_all(&part);
        return Err(e);
    }
    let _ = std::fs::remove_dir_all(dir);
    std::fs::rename(&part, dir).map_err(|e| io_at(dir, e))?;
    resumed.map_err(|e| context("the state is saved, and the guest did not go on", e))
}

/// The text of `"blocked-reasons"` of a `query-migrate` response.
fn blocked(line: &str) -> Option<String> {
    let at = line.find("\"blocked-reasons\"")?;
    let rest = &line[at..];
    let list = &rest[rest.find('[')? + 1..rest.find(']')?];
    let list = list.trim();
    (!list.is_empty()).then(|| list.to_string())
}

/// The steps of [`save`] between `stop` and `cont`, into `part`.
fn freeze(m: &mut qmp::Monitor, plan: &Plan, fingerprint: &Fingerprint, part: &Path, wait: Duration) -> Result<()> {
    // The guest is stopped, so the medium on disk is the one that it sees.
    let block = m.ask("{\"execute\":\"query-block\"}")?;
    let medium = swap::mailbox_file(&block).map(PathBuf::from).ok_or_else(|| {
        failure(Class::Protocol, format!("the emulator names no medium of the mailbox device: {}", block.trim()))
    })?;
    let bytes = std::fs::read(&medium).map_err(|e| io_at(&medium, e))?;
    let mailbox = Fat16::from_image(bytes)
        .ok_or_else(|| failure(Class::Protocol, format!("{}: not a mailbox", medium.display())))?;
    idle(&mailbox)?;
    let _ = std::fs::remove_dir_all(part);
    // The stream holds the memory of the guest.
    std::fs::DirBuilder::new().mode(0o700).create(part).map_err(|e| io_at(part, e))?;
    m.ask(&format!("{{\"execute\":\"migrate-set-parameters\",\"arguments\":{{\"max-bandwidth\":{BANDWIDTH}}}}}"))?;
    let uri = format!("file:{}", uri_path(&part.join(STATE))?);
    m.ask(&format!("{{\"execute\":\"migrate\",\"arguments\":{{\"uri\":{}}}}}", qmp::json_text(&uri)))?;
    let start = Instant::now();
    loop {
        let line = m.ask("{\"execute\":\"query-migrate\"}")?;
        match qmp::json_member(&line, "status").as_deref() {
            Some("completed") => break,
            Some(end @ ("failed" | "cancelled")) => {
                let why = qmp::json_member(&line, "error-desc").unwrap_or_default();
                return Err(failure(Class::Protocol, format!("the save {end}: {why}")));
            }
            _ => {}
        }
        if start.elapsed() >= wait {
            let _ = m.call("migrate_cancel");
            return Err(failure(Class::Timeout, format!("the save did not end within {}s", wait.as_secs())));
        }
        std::thread::sleep(EVERY);
    }
    // The emulator flushed its disks at the end of the migration, and the
    // guest is stopped: the files are the ones of the stream.
    let root = part.join(ROOT);
    copy(&plan.root, &root)?;
    absolute_backing(&root)?;
    copy(&medium, &part.join(MAILBOX))?;
    copy(&plan.firmware_vars, &part.join(VARS))?;
    let file = part.join(FINGERPRINT);
    std::fs::write(&file, fingerprint.text()).map_err(|e| io_at(&file, e))
}

fn copy(from: &Path, to: &Path) -> Result<()> {
    std::fs::copy(from, to).map(drop).map_err(|e| io_at(from, e))
}

/// Refuse a qcow2 overlay whose backing file has a relative name: the
/// emulator reads it from the directory of the overlay, and the copy is
/// in another one.
pub(super) fn absolute_backing(qcow2: &Path) -> Result<()> {
    let mut f = std::fs::File::open(qcow2).map_err(|e| io_at(qcow2, e))?;
    let mut head = [0u8; 20];
    f.read_exact(&mut head).map_err(|e| io_at(qcow2, e))?;
    if head[..4] != *b"QFI\xfb" {
        return Err(failure(Class::Protocol, format!("{}: not a qcow2 image", qcow2.display())));
    }
    let offset = u64::from_be_bytes(head[8..16].try_into().unwrap_or_default());
    let size = u32::from_be_bytes(head[16..20].try_into().unwrap_or_default());
    // The format limits the name to 1023 bytes.
    if offset == 0 || size == 0 || size > 1023 {
        return Ok(());
    }
    let mut name = vec![0u8; size as usize];
    f.seek(SeekFrom::Start(offset)).and_then(|_| f.read_exact(&mut name)).map_err(|e| io_at(qcow2, e))?;
    if name.first() == Some(&b'/') || name.windows(3).any(|w| w == b"://") || name.starts_with(b"json:") {
        return Ok(());
    }
    Err(failure(
        Class::Usage,
        format!(
            "the overlay names its base {:?} by a relative path; give the base by an absolute path",
            String::from_utf8_lossy(&name)
        ),
    ))
}

/// Start the guest of `plan` from the state of `warm`, give it the command
/// of `request`, and return the emulator that runs and the media of the
/// mailbox, with the command on the medium in the guest.
///
/// The emulator loads the state with the saved mailbox as it is. The
/// restored guest holds that mailbox in its cache, so the command comes
/// after the load on a new medium ([`Swap::restored`], [`Swap::next`] with
/// `agent_cmd`), as each next command of a guest that runs.
///
/// A failure with the cause [`Cold`] says why the state was not used: no
/// state, another fingerprint, or a load or a swap that failed (the
/// emulator is then stopped, and the variable store of the caller is put
/// back). Each other failure (a bad option of the plan, a mailbox that is
/// not [`MailboxBus::Usb`], an I/O error before the state is read) has no
/// such cause.
pub fn restore(
    s: &Settings,
    qemu_img: &Path,
    plan: &Plan,
    agent_cmd: &str,
    request: &Request,
    warm: &Warm,
) -> Result<(Child, Swap)> {
    plan.options.check()?;
    usb_mailbox(plan)?;
    let dir = &warm.dir;
    let saved = match std::fs::read_to_string(dir.join(FINGERPRINT)) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(Cold::Missing.failure()),
        Err(e) => return Err(io_at(&dir.join(FINGERPRINT), e)),
    };
    if [STATE, ROOT, MAILBOX, VARS].iter().any(|f| !dir.join(f).is_file()) {
        return Err(Cold::Missing.failure());
    }
    let now = warm.fingerprint.text();
    if saved != now {
        let (saved, now) = first_difference(&saved, &now);
        return Err(Cold::Stale { saved, now }.failure());
    }
    let fresh_vars = std::fs::read(&plan.firmware_vars).map_err(|e| io_at(&plan.firmware_vars, e))?;
    let loaded = load_from(s, qemu_img, plan, agent_cmd, request, warm);
    if loaded.is_err() {
        // A cold boot after this one takes the store of the caller.
        let _ = std::fs::write(&plan.firmware_vars, &fresh_vars);
    }
    loaded.map_err(|e| Cold::Failed { why: e.to_string() }.failure())
}

/// The first line of each text that differs from the other.
fn first_difference(saved: &str, now: &str) -> (String, String) {
    let mut a = saved.lines();
    let mut b = now.lines();
    loop {
        match (a.next(), b.next()) {
            (Some(x), Some(y)) if x == y => {}
            (None, None) => return (String::new(), String::new()),
            (x, y) => return (x.unwrap_or_default().to_string(), y.unwrap_or_default().to_string()),
        }
    }
}

/// The files of the run from the state, the emulator, the load, and the
/// command on a new medium.
fn load_from(
    s: &Settings,
    qemu_img: &Path,
    plan: &Plan,
    agent_cmd: &str,
    request: &Request,
    warm: &Warm,
) -> Result<(Child, Swap)> {
    let dir = &warm.dir;
    let args = incoming_argv(plan, dir)?;
    let file = dir.join(MAILBOX);
    let bytes = std::fs::read(&file).map_err(|e| io_at(&file, e))?;
    // The saved mailbox stays as the restored RAM knows it: a command on it
    // is hidden by the cache of the guest.
    let m = Fat16::from_image(bytes)
        .ok_or_else(|| failure(Class::Protocol, format!("{}: not a mailbox", file.display())))?;
    idle(&m)?;
    let _ = std::fs::remove_file(&plan.root);
    let _ = std::fs::remove_file(&plan.monitor);
    // A thin overlay: the saved one stays as it is, and the next restore
    // reads it again.
    emulator::run_steps(&overlay_argv(qemu_img, &dir.join(ROOT), &plan.root))?;
    std::fs::write(&plan.mailbox, m.image()).map_err(|e| io_at(&plan.mailbox, e))?;
    copy(&dir.join(VARS), &plan.firmware_vars)?;
    let log = emulator::emulator_log(s, plan);
    let mut running = emulator::Running::new(plan, emulator::spawn_emulator(plan, &args, log_stream(s, plan)?)?);
    let given = load(plan, running.child(), warm.wait).and_then(|()| {
        let mut swap = Swap::restored(plan)?;
        let mut monitor = qmp::Monitor::connect(&plan.monitor, MONITOR_WAIT)?;
        swap.next(&mut monitor, s, agent_cmd, request).map(|()| swap)
    });
    match given {
        Ok(swap) => Ok((running.into_child(), swap)),
        Err(e) => {
            // The stop comes before the log is read. An emulator that
            // exited is reaped and gets no signal.
            drop(running);
            let tail = log.as_deref().map(emulator::log_tail).unwrap_or_default();
            Err(failure(e.class, format!("{e}{tail}")))
        }
    }
}

/// Wait for the end of the load of the emulator `child` within `wait`,
/// then let the guest go on: `query-status` is `inmigrate` during the
/// load, then `paused` (the guest was stopped at the save) or `running`.
/// An emulator that exits, or another status, is a failed load.
pub(super) fn load(plan: &Plan, child: &mut Child, wait: Duration) -> Result<()> {
    let start = Instant::now();
    let mut monitor: Option<qmp::Monitor> = None;
    loop {
        if let Some(status) = child.try_wait().map_err(|e| io_at(&plan.emulator, e))? {
            return Err(failure(Class::Unavailable, format!("the emulator exited ({status}) during the load")));
        }
        if monitor.is_none() {
            // The emulator can answer only after the load: a connection
            // that fails is made again at the next poll.
            monitor = qmp::Monitor::connect(&plan.monitor, Duration::ZERO).ok();
        }
        if let Some(m) = monitor.as_mut() {
            match m.ask("{\"execute\":\"query-status\"}") {
                Ok(line) => match qmp::json_member(&line, "status").as_deref() {
                    Some("inmigrate") => {}
                    Some("running") => return Ok(()),
                    Some("paused") => return m.call("cont"),
                    other => {
                        return Err(failure(Class::Protocol, format!("the emulator is {other:?} after the load")));
                    }
                },
                Err(_) => monitor = None,
            }
        }
        if start.elapsed() >= wait {
            return Err(failure(Class::Timeout, format!("the load did not end within {}s", wait.as_secs())));
        }
        std::thread::sleep(EVERY);
    }
}
