//! The provision of a base image of the UEFI flavour: one boot that types
//! the installer of the agent into the console.

use std::path::Path;
use std::process::Stdio;
use std::time::{Duration, Instant};

use pod_core::Class;

use crate::ready::{self, Ready};
use crate::{Fat16, Plan, Result, Settings, agent, convert_argv, emulator, failure, io_at, overlay_argv, qmp};

/// Provision a new image: boot it one time and type the installer into its
/// console, as the agent must exist before a task can start it. Returns the
/// report of the installer ([`agent::SETUP`]).
///
/// The keys go to the console when `ready` holds ([`crate::ready::wait`]:
/// for an image with no agent yet, a screen that settles,
/// [`crate::ready::Ready::screen`], or a fixed time after the spawn,
/// [`crate::ready::Sign::After`]). An emulator that exits first, or no
/// ready guest within the deadline, is a failure with the cause
/// [`crate::ready::Unready`]. Each failure after the spawn stops the
/// emulator, also a failure of the keys. `wait` bounds the power-off after
/// the keys.
///
/// This is the only step that uses the console, one time for each base
/// image. Each later run uses the mailbox. The typed line scans the drive
/// letters: Windows gives the letter, and it can change between boots.
///
/// The base is not written. The installer writes to [`Plan::root`], an
/// overlay over `base` ([`overlay_argv`]), and the overlay is never `base`.
/// After the guest powers off, [`convert_argv`] writes the overlay into
/// `out`, a new standalone image with no backing file, so that the caller
/// can move or remove `base`.
pub fn provision(
    s: &Settings,
    qemu_img: &Path,
    base: &Path,
    plan: &Plan,
    out: &Path,
    ready: &Ready,
    wait: Duration,
) -> Result<Vec<u8>> {
    let mut m = Fat16::with_oem(&s.oem)?;
    m.put(agent::MARKER, &s.marker)?;
    m.put(agent::AGENT_NAME, agent::AGENT_CMD.as_bytes())?;
    m.put(agent::SETUP_NAME, agent::SETUP_CMD.as_bytes())?;
    std::fs::write(&plan.mailbox, m.image()).map_err(|e| io_at(&plan.mailbox, e))?;
    let _ = std::fs::remove_file(&plan.root);
    let _ = std::fs::remove_file(&plan.monitor);
    // `qemu-img` refuses a file that exists. `out` is the product of the
    // caller, so it is removed only when this boot writes it again.
    if out != plan.root {
        let _ = std::fs::remove_file(out);
    }
    emulator::run_steps(&overlay_argv(qemu_img, base, &plan.root))?;
    // From here each failure stops the emulator: the guard does it when it
    // is dropped (PodUtils/podvm#370).
    let mut running = emulator::Running::new(plan, emulator::spawn_uefi(plan, Stdio::null())?);
    // The shell must finish its boot first: keys typed into a boot screen
    // go nowhere.
    ready::wait(plan, running.child(), ready)?;
    type_into_console(
        plan,
        "for %d in (D E F G H I J K L M N O P Q R S T U V W X Y Z) do @if exist %d:\\WQMARK.TXT %d:\\WA.CMD",
    )?;
    // The installer ends with `shutdown`, so the guest flushes its FAT
    // writes before it powers off. The read below is safe only after the
    // emulator exits.
    let start = Instant::now();
    while start.elapsed() < wait {
        if running.child().try_wait().map_err(|e| io_at(&plan.emulator, e))?.is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    // The signal is only for an emulator that lived past its wait. The
    // `try_wait` above reaped a child that exited, and the kernel can give
    // its pid to another process.
    let _stop = running.stop();
    // The convert comes after the emulator is gone and before the report. A
    // convert that fails is a failure that names the program and its
    // stderr, so that no half-written `out` reads as a provisioned image.
    emulator::run_steps(&convert_argv(qemu_img, &plan.root, out))?;
    // The installer writes SETUP.TXT to the mailbox: the evidence that the
    // provision ran.
    let bytes = std::fs::read(&plan.mailbox).map_err(|e| io_at(&plan.mailbox, e))?;
    let back = Fat16::from_image(bytes)
        .ok_or_else(|| failure(Class::Protocol, format!("{}: not a mailbox", plan.mailbox.display())))?;
    back.get(agent::SETUP).ok_or_else(|| failure(Class::Protocol, "the installer wrote no SETUP.TXT"))
}

/// Type `text` into the console of the guest through QMP, then return. A
/// shifted character is the modifier and the key in one `send-key`.
fn type_into_console(plan: &Plan, text: &str) -> Result<()> {
    let mut m = qmp::Monitor::connect(&plan.monitor, Duration::from_secs(120))?;
    for ch in text.chars() {
        let (name, shifted) = qmp::key(ch).ok_or_else(|| failure(Class::Usage, format!("no key for {ch:?}")))?;
        if shifted {
            m.keys(&["shift", name])?;
        } else {
            m.keys(&[name])?;
        }
        std::thread::sleep(Duration::from_millis(8));
    }
    m.keys(&["ret"])?;
    std::thread::sleep(Duration::from_millis(500));
    Ok(())
}

#[cfg(test)]
mod tests;
