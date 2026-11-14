//! The screen sign: a QMP `screendump` read as an image, with a tolerance
//! for a cursor.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::qmp;

/// The largest box of changed pixels (width, height) that is no change of
/// the screen. It holds the text cursor of the Windows console (8x16 to
/// 16x32 pixels at the resolutions of `-vga std`) and the pointer (32x32).
pub const CURSOR: (usize, usize) = (32, 32);

/// One dump of the screen: a P6 PPM, the format of QEMU's `screendump`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Frame {
    width: usize,
    height: usize,
    rgb: Vec<u8>,
}

impl Frame {
    /// The frame of a P6 PPM with a maximum value below 256; `None` for
    /// each other file.
    pub(crate) fn from_ppm(bytes: &[u8]) -> Option<Frame> {
        let mut at = 2;
        if bytes.get(..2)? != b"P6" {
            return None;
        }
        let mut fields = [0usize; 3];
        for field in &mut fields {
            *field = header_number(bytes, &mut at)?;
        }
        let [width, height, max] = fields;
        // One whitespace byte ends the header; the samples follow.
        if !(1..256).contains(&max) || !bytes.get(at)?.is_ascii_whitespace() {
            return None;
        }
        let len = width.checked_mul(height)?.checked_mul(3)?;
        let rgb = bytes.get(at + 1..)?.get(..len)?.to_vec();
        (width > 0 && height > 0).then_some(Frame { width, height, rgb })
    }

    fn pixel(&self, i: usize) -> &[u8] {
        &self.rgb[i * 3..i * 3 + 3]
    }

    /// The same screen: the pixels that differ fit in a box of [`CURSOR`]. A
    /// frame of another size is another screen.
    pub(crate) fn same(&self, other: &Frame) -> bool {
        (self.width, self.height) == (other.width, other.height) && self.within(|i| self.pixel(i) != other.pixel(i))
    }

    /// A screen of one colour but for a box of [`CURSOR`] (a pointer, a
    /// cursor): a boot phase, not a console. The colour is the one of a
    /// corner, as a pointer can cover the other one.
    pub(crate) fn blank(&self) -> bool {
        let last = self.width * self.height - 1;
        [0, last].iter().any(|&c| self.within(|i| self.pixel(i) != self.pixel(c)))
    }

    /// The pixels `i` where `differs(i)` fit in a box of [`CURSOR`]. The
    /// scan stops at the first pixel outside such a box.
    fn within(&self, differs: impl Fn(usize) -> bool) -> bool {
        let mut seen: Option<(usize, usize, usize, usize)> = None;
        for y in 0..self.height {
            for x in 0..self.width {
                if !differs(y * self.width + x) {
                    continue;
                }
                let (x0, x1, y0, y1) = seen.map_or((x, x, y, y), |(a, b, c, _)| (a.min(x), b.max(x), c, y));
                if x1 - x0 >= CURSOR.0 || y1 - y0 >= CURSOR.1 {
                    return false;
                }
                seen = Some((x0, x1, y0, y1));
            }
        }
        true
    }
}

/// A decimal number of a PPM header after its whitespace and comments.
fn header_number(bytes: &[u8], at: &mut usize) -> Option<usize> {
    loop {
        match bytes.get(*at)? {
            b'#' => *at += bytes.get(*at..)?.iter().position(|&b| b == b'\n')?,
            b if b.is_ascii_whitespace() => *at += 1,
            _ => break,
        }
    }
    let digits = bytes.get(*at..)?.iter().take_while(|b| b.is_ascii_digit()).count();
    let text = std::str::from_utf8(bytes.get(*at..*at + digits)?).ok()?;
    *at += digits;
    text.parse().ok()
}

/// The poll of the screen through QMP `screendump`.
pub(super) struct Screen {
    settle: Duration,
    monitor: Option<qmp::Monitor>,
    /// The first dump: the screen of the boot.
    first: Option<Frame>,
    /// The dump at the last change: a later dump is compared to it, so that
    /// a cursor that blinks or a slow drift does not hide a change.
    base: Option<Frame>,
    /// When the screen last changed, after the first dump.
    changed: Option<Instant>,
}

impl Screen {
    pub(super) fn new(settle: Duration) -> Screen {
        Screen { settle, monitor: None, first: None, base: None, changed: None }
    }

    pub(super) fn poll(&mut self, socket: &Path) -> bool {
        let Some(frame) = self.dump(socket) else { return false };
        let now = Instant::now();
        let (Some(first), Some(base)) = (&self.first, &self.base) else {
            self.first = Some(frame.clone());
            self.base = Some(frame);
            return false;
        };
        if !base.same(&frame) {
            self.base = Some(frame);
            self.changed = Some(now);
            return false;
        }
        // A screen that is back to the boot screen, or that shows nothing,
        // is a boot phase: keys typed into it go nowhere.
        self.changed.is_some_and(|at| now.duration_since(at) >= self.settle) && !base.same(first) && !base.blank()
    }

    /// One dump of the screen; `None` when the monitor is not there yet or
    /// refused, or the file is no P6 PPM. A broken connection is made again
    /// at the next poll.
    fn dump(&mut self, socket: &Path) -> Option<Frame> {
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
        Frame::from_ppm(&bytes)
    }
}

/// The file of a dump: beside the QMP socket, in the per-run directory.
pub(super) fn dump_path(socket: &Path) -> PathBuf {
    socket.with_file_name("screen.ppm")
}
