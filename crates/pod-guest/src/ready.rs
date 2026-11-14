//! The wait for a guest that is ready, in place of a fixed sleep.
//!
//! Three signs, each one read from the host with no help from the guest
//! but the one it gives:
//!
//! * [`Sign::Marker`]: the agent wrote [`crate::agent::READY`] to the
//!   mailbox (a provisioned image).
//! * [`Sign::Serial`]: the serial log of the plan holds a text.
//! * [`Sign::Screen`]: the screen changed after the first dump of QMP
//!   `screendump`, then stayed the same for `settle` (an image with no
//!   agent yet: the shell of a provision boot is at its prompt).
//!
//! [`wait`] polls each sign until one holds, the emulator exits, or the
//! deadline comes; each end but the first is a failure with the cause
//! [`Unready`].

use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::Child;
use std::time::{Duration, Instant};

use pod_core::{Class, Failure, Stage};
use sha2::{Digest, Sha256};

use crate::{Fat16, Plan, Result, agent, io_at, qmp};

/// The time that a screen must stay the same after it changed.
pub const SETTLE: Duration = Duration::from_secs(5);
/// The time between two polls.
pub const EVERY: Duration = Duration::from_millis(500);
/// The most bytes of the serial log that one poll reads.
const SERIAL_STEP: u64 = 1 << 20;

/// One sign of a ready guest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sign {
    /// The agent wrote `WQREADY.TXT` to the mailbox of the plan.
    Marker,
    /// The serial log of the plan ([`Plan::serial`]) holds this text.
    Serial(String),
    /// The screen changed after the first dump, then stayed the same for
    /// `settle`.
    Screen { settle: Duration },
}

impl std::fmt::Display for Sign {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Sign::Marker => write!(f, "the marker {} of the agent", agent::READY),
            Sign::Serial(text) => write!(f, "the text {text:?} on the serial line"),
            Sign::Screen { settle } => write!(f, "a screen that changed and then stayed the same for {settle:?}"),
        }
    }
}

/// What [`wait`] waits for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ready {
    /// The signs; the first one that holds ends the wait.
    pub signs: Vec<Sign>,
    /// The limit of the whole wait.
    pub deadline: Duration,
    /// The time between two polls.
    pub every: Duration,
}

impl Ready {
    /// A wait for a screen that settles ([`SETTLE`]), polled each
    /// [`EVERY`]: the readiness of a provision boot.
    pub fn screen(deadline: Duration) -> Ready {
        Ready { signs: vec![Sign::Screen { settle: SETTLE }], deadline, every: EVERY }
    }
}

/// Why [`wait`] ended with no ready guest: the cause of its failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unready {
    /// No sign held within the deadline.
    Deadline { after: Duration, signs: Vec<Sign> },
    /// The emulator exited first.
    Exited { status: String },
}

impl std::fmt::Display for Unready {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Unready::Deadline { after, signs } => {
                let signs: Vec<String> = signs.iter().map(Sign::to_string).collect();
                write!(f, "the guest was not ready within {}s: no {}", after.as_secs(), signs.join(", no "))
            }
            Unready::Exited { status } => write!(f, "the emulator exited ({status}) before the guest was ready"),
        }
    }
}

impl std::error::Error for Unready {}

impl Unready {
    /// [`Class::Timeout`] for the deadline, [`Class::Unavailable`] for an
    /// emulator that exited.
    pub fn failure(self) -> Failure {
        let class = match self {
            Unready::Deadline { .. } => Class::Timeout,
            Unready::Exited { .. } => Class::Unavailable,
        };
        Failure::caused(Stage::Host, class, self.to_string(), self)
    }
}

/// The [`Unready`] in the chain of `f`.
pub fn unready(f: &Failure) -> Option<&Unready> {
    crate::cause_of::<Unready>(f)
}

/// Poll the signs of `ready` for the guest of `plan`, whose emulator is
/// `child`, and return the index of the first sign that held.
///
/// The emulator that exits first, and the deadline, are failures with the
/// cause [`Unready`]. The wait does not stop the emulator: the caller does.
/// A sign that cannot be read yet (no QMP socket, no serial log) does not
/// hold; it is no failure.
pub fn wait(plan: &Plan, child: &mut Child, ready: &Ready) -> Result<usize> {
    let start = Instant::now();
    let mut watches: Vec<Watch> = ready.signs.iter().map(Watch::new).collect();
    loop {
        for (i, w) in watches.iter_mut().enumerate() {
            if w.holds(plan) {
                return Ok(i);
            }
        }
        if let Some(status) = child.try_wait().map_err(|e| io_at(&plan.emulator, e))? {
            return Err(Unready::Exited { status: status.to_string() }.failure());
        }
        let spent = start.elapsed();
        if spent >= ready.deadline {
            return Err(Unready::Deadline { after: ready.deadline, signs: ready.signs.clone() }.failure());
        }
        std::thread::sleep(ready.every.min(ready.deadline - spent));
    }
}

/// The state of the poll of one sign.
enum Watch {
    Marker,
    Serial(Scan),
    Screen(Screen),
}

impl Watch {
    fn new(sign: &Sign) -> Watch {
        match sign {
            Sign::Marker => Watch::Marker,
            Sign::Serial(text) => Watch::Serial(Scan::new(text.as_bytes())),
            Sign::Screen { settle } => Watch::Screen(Screen::new(*settle)),
        }
    }

    fn holds(&mut self, plan: &Plan) -> bool {
        match self {
            Watch::Marker => {
                std::fs::read(&plan.mailbox).ok().and_then(Fat16::from_image).is_some_and(|m| agent::ready(&m))
            }
            Watch::Serial(scan) => scan.poll(&plan.serial),
            Watch::Screen(screen) => screen.poll(&plan.monitor),
        }
    }
}

/// A search for a text in a file that grows: each poll reads the new
/// bytes, and keeps the end of the last ones, so that a text that two
/// polls cut is found.
pub struct Scan {
    text: Vec<u8>,
    offset: u64,
    carry: Vec<u8>,
}

impl Scan {
    pub fn new(text: &[u8]) -> Scan {
        Scan { text: text.to_vec(), offset: 0, carry: Vec::new() }
    }

    /// Read the new bytes of `path`, at most 1 MiB, and say if the text is
    /// in the bytes so far. A file that became shorter is read again from
    /// its start.
    pub fn poll(&mut self, path: &Path) -> bool {
        let Ok(mut file) = std::fs::File::open(path) else { return false };
        let len = file.metadata().map(|m| m.len()).unwrap_or(0);
        if len < self.offset {
            self.offset = 0;
            self.carry.clear();
        }
        let mut fresh = Vec::new();
        if file.seek(SeekFrom::Start(self.offset)).is_err() || file.take(SERIAL_STEP).read_to_end(&mut fresh).is_err() {
            return false;
        }
        self.offset += fresh.len() as u64;
        self.feed(&fresh)
    }

    /// Take `fresh` bytes after the ones before.
    pub fn feed(&mut self, fresh: &[u8]) -> bool {
        self.carry.extend_from_slice(fresh);
        if self.text.is_empty() || self.carry.windows(self.text.len()).any(|w| w == self.text) {
            return true;
        }
        let keep = self.text.len() - 1;
        if self.carry.len() > keep {
            self.carry.drain(..self.carry.len() - keep);
        }
        false
    }
}

/// The poll of the screen through QMP `screendump`.
struct Screen {
    settle: Duration,
    monitor: Option<qmp::Monitor>,
    last: Option<[u8; 32]>,
    /// When the screen last changed, after the first dump.
    changed: Option<Instant>,
}

impl Screen {
    fn new(settle: Duration) -> Screen {
        Screen { settle, monitor: None, last: None, changed: None }
    }

    fn poll(&mut self, socket: &Path) -> bool {
        let Some(frame) = self.dump(socket) else { return false };
        let now = Instant::now();
        if self.last.is_none() {
            // The first dump: the screen of the boot, the base of a change.
        } else if self.last != Some(frame) {
            self.changed = Some(now);
        } else if self.changed.is_some_and(|at| now.duration_since(at) >= self.settle) {
            return true;
        }
        self.last = Some(frame);
        false
    }

    /// The digest of one dump of the screen; `None` when the monitor is not
    /// there yet or refused. A broken connection is made again at the next
    /// poll.
    fn dump(&mut self, socket: &Path) -> Option<[u8; 32]> {
        if self.monitor.is_none() {
            self.monitor = qmp::Monitor::connect(socket, Duration::ZERO).ok();
        }
        let file = dump_path(socket);
        let done = self.monitor.as_mut()?.screendump(&file);
        if done.is_err() {
            self.monitor = None;
            return None;
        }
        let bytes = std::fs::read(&file).ok()?;
        let _ = std::fs::remove_file(&file);
        Sha256::digest(&bytes).as_slice().try_into().ok()
    }
}

/// The file of a dump: beside the QMP socket, in the per-run directory.
fn dump_path(socket: &Path) -> PathBuf {
    socket.with_file_name("screen.ppm")
}

#[cfg(test)]
mod tests;
