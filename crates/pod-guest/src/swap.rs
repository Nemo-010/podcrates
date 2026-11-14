//! The next command of a guest in [`agent::Mode::KeepAlive`]: a new mailbox
//! medium for each command, swapped in through QMP.
//!
//! The host does not write the mailbox that the guest has mounted. Windows
//! keeps the directory and the FAT of a mounted FAT volume in its cache,
//! and on a fixed disk nothing tells it that the disk changed under it: a
//! token that the host writes into the image file is not seen, and a later
//! write of the guest puts its cached sectors over the files of the host.
//!
//! So the mailbox is a USB stick with a removable medium
//! ([`MailboxBus::Usb`]), and each command comes on a new medium:
//!
//! 1. The host waits until the result of the command before is settled on
//!    the medium ([`settled`]): its code with the token, and no
//!    [`agent::GO`]. The agent deletes the token after it writes the code;
//!    a swap before the delete would let the agent delete the new token.
//! 2. The host writes a new mailbox with the next command and a new volume
//!    id into the other of two files, and sends `blockdev-change-medium`
//!    with `force` for the drive [`MAILBOX_DRIVE`] ([`change_request`]).
//! 3. The emulator reports a unit attention at the next access of the
//!    guest. The disk class driver of Windows marks the device for a
//!    verify; FastFAT reads the boot sector, finds another volume id, drops
//!    its cache with no flush, and mounts the new volume at the same drive
//!    letter. The agent writes [`agent::READY`] in each poll, so that
//!    access comes also when Windows polls no removable drive.
//!
//! The agent writes each file with a flush at its close on a hot-pluggable
//! device, so a settled result is on the medium, and the swap drops no
//! write of the guest.
//!
//! Windows locks the medium of the mounted stick (PREVENT ALLOW MEDIUM
//! REMOVAL). With no `force` the emulator refuses the change and only asks
//! the guest to eject. With `force` it opens the tray, drops the lock of
//! the guest, changes the medium and closes the tray; the guest gets the
//! same unit attention as for an unlocked medium.

use std::path::{Path, PathBuf};

use pod_core::Class;

use crate::plan::{MAILBOX_DRIVE, MailboxBus};
use crate::{Fat16, Outcome, Plan, Request, Result, Settings, agent, failure, io_at, qmp};

/// The outcome of `token` on the mailbox `m`, when the guest is done with
/// the medium: the code of `token` ([`crate::poll_outcome`]) and no
/// [`agent::GO`]. `None` while the command runs or the agent has not yet
/// deleted its token.
pub fn settled(m: &Fat16, token: &str) -> Option<Outcome> {
    if m.get(agent::GO).is_some() {
        return None;
    }
    crate::poll_outcome(m, token)
}

/// The QMP request that puts `file` as the medium of the mailbox drive.
/// A path that is not UTF-8 is [`Class::Usage`]: JSON holds text.
///
/// `force`: the guest locks the medium that it has mounted, and the
/// emulator changes a locked medium only with `force`.
pub fn change_request(file: &Path) -> Result<String> {
    let path = file.to_str().ok_or_else(|| failure(Class::Usage, format!("{}: not a UTF-8 path", file.display())))?;
    Ok(format!(
        "{{\"execute\":\"blockdev-change-medium\",\"arguments\":{{\"device\":{},\"filename\":{},\"format\":\"raw\",\"force\":true}}}}",
        qmp::json_text(MAILBOX_DRIVE),
        qmp::json_text(path)
    ))
}

/// The lock of the mailbox drive in a `query-block` response: true while
/// the guest prevents the removal of the medium. `None` when no entry of
/// the response is the drive [`MAILBOX_DRIVE`] or the entry has no lock.
pub fn mailbox_locked(block: &str) -> Option<bool> {
    qmp::list_entries(block)
        .into_iter()
        .find(|e| qmp::json_member(e, "device").as_deref() == Some(MAILBOX_DRIVE))
        .and_then(|e| qmp::json_bool(e, "locked"))
}

/// The second file of the mailbox of `plan`: `MAILBOX.swap`, beside it.
pub fn other_file(plan: &Plan) -> PathBuf {
    let mut name = plan.mailbox.clone().into_os_string();
    name.push(".swap");
    PathBuf::from(name)
}

/// The two media of the mailbox of a guest that runs, and the token of the
/// command on the one in the guest.
#[derive(Debug, Clone)]
pub struct Swap {
    files: [PathBuf; 2],
    current: usize,
    token: String,
    volume_id: u32,
}

impl Swap {
    /// The mailbox of `plan`, which holds the command with `token` (as
    /// [`crate::stage`] writes it). A plan whose mailbox is not
    /// [`MailboxBus::Usb`] is [`Class::Usage`]: a fixed disk cannot change
    /// its medium.
    pub fn new(plan: &Plan, token: &str) -> Result<Swap> {
        if plan.options.mailbox != MailboxBus::Usb {
            return Err(failure(
                Class::Usage,
                "the next command of a running guest needs a USB mailbox (MailboxBus::Usb): Windows does not read a \
                 fixed disk again",
            ));
        }
        let volume_id = read(&plan.mailbox)?.volume_id();
        Ok(Swap { files: [plan.mailbox.clone(), other_file(plan)], current: 0, token: token.to_string(), volume_id })
    }

    /// The file of the medium in the guest.
    pub fn current(&self) -> &Path {
        &self.files[self.current]
    }

    /// The token of the command on the medium in the guest.
    pub fn token(&self) -> &str {
        &self.token
    }

    /// Read the medium in the guest: the outcome of the current command
    /// once it is settled ([`settled`]).
    pub fn poll(&self) -> Result<Option<Outcome>> {
        Ok(settled(&read(self.current())?, &self.token))
    }

    /// Put the command of `request` on a new medium and swap it into the
    /// guest through `monitor`. The new medium is a new mailbox
    /// ([`crate::mailbox`] of `s` and `agent_cmd`) with the next volume id.
    ///
    /// A command before with no settled result is [`Class::Usage`], and no
    /// medium changes. A refusal of the emulator is [`Class::Protocol`];
    /// the medium in the guest and the token stay as they were.
    pub fn next(&mut self, monitor: &mut qmp::Monitor, s: &Settings, agent_cmd: &str, request: &Request) -> Result<()> {
        if self.poll()?.is_none() {
            return Err(failure(
                Class::Usage,
                format!(
                    "the command with token {:?} has no settled result: the guest still uses the medium",
                    self.token
                ),
            ));
        }
        let id = self.volume_id.wrapping_add(1);
        let mut m = crate::mailbox(s, agent_cmd, request)?;
        m.set_volume_id(id);
        let other = 1 - self.current;
        let file = &self.files[other];
        std::fs::write(file, m.image()).map_err(|e| io_at(file, e))?;
        monitor.ask(&change_request(file)?)?;
        self.current = other;
        self.token = request.token.clone();
        self.volume_id = id;
        Ok(())
    }
}

/// The mailbox in the file `path`.
fn read(path: &Path) -> Result<Fat16> {
    let bytes = std::fs::read(path).map_err(|e| io_at(path, e))?;
    Fat16::from_image(bytes).ok_or_else(|| failure(Class::Protocol, format!("{}: not a mailbox", path.display())))
}

#[cfg(test)]
mod tests;
