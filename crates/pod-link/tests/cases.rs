//! The scripted cases of `tests/cases/` (T-776): one end of a link against
//! a peer whose bytes the case gives, on a paused clock. A failure names
//! the file and the step. The form of a case is in `tests/cases/README.md`.
//!
//! The runner polls each operation once and never waits: the clock is
//! paused and moves only at `advance`, and before each check the runner
//! lets the end run until it does nothing more.

mod common;

use std::collections::HashMap;
use std::future::{Future, poll_fn};
use std::path::{Path, PathBuf};
use std::pin::{Pin, pin};
use std::task::Poll;
use std::time::Duration;

use common::wire::{frame, show};
use pod_link::frame::PREFACE;
use pod_link::{Decoder, Frame, Link, ResetCode, Role, Settings, Stream};
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};

/// The output of `fut` when it is ready at its first poll.
async fn now<F: Future>(fut: F) -> Option<F::Output> {
    let mut fut = pin!(fut);
    poll_fn(|cx| {
        Poll::Ready(match fut.as_mut().poll(cx) {
            Poll::Ready(v) => Some(v),
            Poll::Pending => None,
        })
    })
    .await
}

/// One read of `io` that does not wait: `None` when no byte is there.
async fn try_read<R: AsyncRead + Unpin>(io: &mut R, buf: &mut [u8]) -> Option<std::io::Result<usize>> {
    poll_fn(|cx| {
        let mut rb = ReadBuf::new(buf);
        Poll::Ready(match Pin::new(&mut *io).poll_read(cx, &mut rb) {
            Poll::Ready(Ok(())) => Some(Ok(rb.filled().len())),
            Poll::Ready(Err(e)) => Some(Err(e)),
            Poll::Pending => None,
        })
    })
    .await
}

/// One write to `io` that does not wait: the bytes it took.
async fn try_write<W: AsyncWrite + Unpin>(io: &mut W, bytes: &[u8]) -> std::io::Result<usize> {
    poll_fn(|cx| {
        Poll::Ready(match Pin::new(&mut *io).poll_write(cx, bytes) {
            Poll::Ready(r) => r,
            Poll::Pending => Ok(0),
        })
    })
    .await
}

/// One case in its run.
struct Run {
    link: Link,
    io: DuplexStream,
    decoder: Decoder,
    eof: bool,
    /// The bytes of the peer that the carrier did not take yet.
    out: Vec<u8>,
    streams: HashMap<u32, Stream>,
    /// The bytes of each stream that the end did not write yet.
    writes: HashMap<u32, usize>,
    end_seen: bool,
}

impl Run {
    async fn start(role: Role, settings: Settings, ring: usize) -> Run {
        let (near, far) = pod_link::memory::pair(ring);
        let link = Link::new(near, role, settings).expect("the settings of the case");
        let mut run = Run {
            link,
            io: far,
            decoder: Decoder::with_preface(),
            eof: false,
            out: PREFACE.to_vec(),
            streams: HashMap::new(),
            writes: HashMap::new(),
            end_seen: false,
        };
        run.settle().await;
        run
    }

    /// Give the bytes of the peer and of the writes that wait, and let the
    /// end run, until nothing moves for a while. The clock does not move.
    async fn settle(&mut self) {
        let mut still = 0;
        while still < 64 {
            let mut moved = false;
            if !self.out.is_empty() {
                let n = try_write(&mut self.io, &self.out).await.unwrap_or(0);
                self.out.drain(..n);
                moved |= n > 0;
            }
            for (id, left) in self.writes.iter_mut().filter(|(_, l)| **l > 0) {
                let stream = self.streams.get_mut(id).expect("a stream with a write");
                let n = try_write(stream, &vec![b'a'; *left]).await.unwrap_or(0);
                *left -= n;
                moved |= n > 0;
            }
            tokio::task::yield_now().await;
            still = if moved { 0 } else { still + 1 };
        }
        self.writes.retain(|_, left| *left > 0);
        self.end_seen |= self.link.ended().is_some();
    }

    /// The next frame of the end, when one is there.
    async fn next(&mut self) -> Option<Frame> {
        let mut buf = vec![0; 64 << 10];
        loop {
            if let Some(f) = self.decoder.next().expect("the end sends valid frames") {
                return Some(f);
            }
            match try_read(&mut self.io, &mut buf).await {
                Some(Ok(0)) | Some(Err(_)) => {
                    self.eof = true;
                    return None;
                }
                Some(Ok(n)) => self.decoder.push(&buf[..n]),
                None => return None,
            }
        }
    }

    fn stream(&mut self, id: &str) -> Result<(u32, &mut Stream), String> {
        let id: u32 = id.parse().map_err(|_| format!("the stream {id:?}"))?;
        self.streams.get_mut(&id).map(|s| (id, s)).ok_or(format!("no stream {id} in the case"))
    }

    async fn step(&mut self, verb: &str, args: &[&str], rest: &str) -> Result<(), String> {
        let arg = |i: usize| args.get(i).copied().ok_or(format!("{verb}: an argument is missing"));
        let num = |i: usize| -> Result<usize, String> { arg(i)?.parse().map_err(|_| format!("{verb}: a number")) };
        match verb {
            "send" | "send-many" => {
                let (count, text) = if verb == "send" {
                    (1, rest)
                } else {
                    (num(0)?, rest.split_once(' ').ok_or("send-many: N FRAME")?.1)
                };
                let f = frame(text)?;
                for _ in 0..count {
                    f.encode(&mut self.out).map_err(|e| format!("the frame of the peer: {e}"))?;
                }
                self.settle().await;
            }
            "expect" => {
                self.settle().await;
                let want = frame(rest)?;
                match self.next().await {
                    Some(got) if got == want => {}
                    Some(got) => return Err(format!("the end sent {:.120}", show(&got))),
                    None => return Err("the end sent no frame".into()),
                }
            }
            "expect-quiet" => {
                self.settle().await;
                if let Some(got) = self.next().await {
                    return Err(format!("the end sent {:.120}", show(&got)));
                }
                if self.eof || self.decoder.buffered() > 0 {
                    return Err("the end sent bytes or ended its carrier".into());
                }
            }
            "expect-eof" => {
                self.settle().await;
                if let Some(got) = self.next().await {
                    return Err(format!("the end sent {:.120}", show(&got)));
                }
                if !self.eof {
                    return Err("the carrier of the end did not end".into());
                }
            }
            "expect-end" => {
                self.settle().await;
                let got = self.link.ended().map(|e| format!("{e:?}"));
                if !got.as_deref().is_some_and(|g| g.starts_with(rest)) {
                    return Err(format!("the link ended with {got:?}"));
                }
            }
            "open" => {
                let stream = self.link.open().map_err(|e| format!("open: {e}"))?;
                let want: u32 = arg(0)?.parse().map_err(|_| "open: an id")?;
                if stream.id() != want {
                    return Err(format!("open gave the stream {}", stream.id()));
                }
                self.streams.insert(want, stream);
                self.settle().await;
            }
            "accept" => {
                self.settle().await;
                let stream = now(self.link.accept()).await.ok_or("no stream to accept")?.map_err(|e| e.to_string())?;
                if stream.id().to_string() != arg(0)? {
                    return Err(format!("accept gave the stream {}", stream.id()));
                }
                self.streams.insert(stream.id(), stream);
            }
            "write" => {
                let (id, _) = self.stream(arg(0)?)?;
                *self.writes.entry(id).or_default() += num(1)?;
                self.settle().await;
            }
            "read" => {
                self.settle().await;
                let want = num(1)?;
                let (_, stream) = self.stream(arg(0)?)?;
                let mut got = 0;
                let mut buf = vec![0; want];
                while got < want {
                    match try_read(stream, &mut buf[got..]).await {
                        Some(Ok(n @ 1..)) => got += n,
                        other => return Err(format!("read {got} of {want} bytes, then {other:?}")),
                    }
                }
                self.settle().await;
            }
            "read-end" | "read-fails" => {
                self.settle().await;
                let (_, stream) = self.stream(arg(0)?)?;
                let got = try_read(stream, &mut [0; 1]).await;
                let fine = match (verb, &got) {
                    ("read-end", Some(Ok(0))) => true,
                    ("read-fails", Some(Err(e))) => format!("{:?}", e.kind()) == arg(1)?,
                    _ => false,
                };
                if !fine {
                    return Err(format!("the read gave {got:?}"));
                }
            }
            "close" => {
                let (id, stream) = self.stream(arg(0)?)?;
                let done = now(tokio::io::AsyncWriteExt::shutdown(stream)).await;
                if !matches!(done, Some(Ok(()))) || self.writes.contains_key(&id) {
                    return Err(format!("the close gave {done:?}"));
                }
                self.settle().await;
            }
            "reset" => {
                let code = num(1)? as u32;
                self.stream(arg(0)?)?.1.reset(ResetCode(code));
                self.settle().await;
            }
            "drop" => {
                let (id, _) = self.stream(arg(0)?)?;
                self.streams.remove(&id);
                self.writes.remove(&id);
                self.settle().await;
            }
            "advance" => {
                tokio::time::advance(duration(arg(0)?)?).await;
                self.settle().await;
            }
            other => return Err(format!("the step {other:?} does not exist")),
        }
        Ok(())
    }
}

/// `2s`, `1999ms`.
fn duration(text: &str) -> Result<Duration, String> {
    let bad = || format!("the duration {text:?}");
    if let Some(ms) = text.strip_suffix("ms") {
        return ms.parse().map(Duration::from_millis).map_err(|_| bad());
    }
    text.strip_suffix('s').ok_or_else(bad)?.parse().map(Duration::from_secs).map_err(|_| bad())
}

fn settings(text: &str) -> Result<Settings, String> {
    let mut s = Settings::default();
    for pair in text.split_whitespace() {
        let (key, value) = pair.split_once('=').ok_or(format!("the setting {pair:?}"))?;
        let n = || value.parse::<usize>().map_err(|_| format!("the setting {pair:?}"));
        match key {
            "stream_window" => s.stream_window = n()? as u32,
            "link_window" => s.link_window = n()? as u32,
            "max_streams" => s.max_streams = n()?,
            "frame_size" => s.frame_size = n()?,
            "keepalive" => s.keepalive = duration(value)?,
            "dead_after" => s.dead_after = duration(value)?,
            _ => return Err(format!("the setting {key:?} does not exist")),
        }
    }
    Ok(s)
}

/// The header of a case: `key: value` lines before the first step.
struct Header {
    role: Role,
    settings: Settings,
    ring: usize,
    rules: Vec<String>,
    class: String,
}

fn header(lines: &[(usize, &str)]) -> Result<(Header, usize), String> {
    let mut h = Header {
        role: Role::Listener,
        settings: Settings::default(),
        ring: 1 << 20,
        rules: vec![],
        class: String::new(),
    };
    let mut at = 0;
    for (i, (_, line)) in lines.iter().enumerate() {
        let Some((key, value)) = line.split_once(": ") else { break };
        match key {
            "role" if value == "dialer" => h.role = Role::Dialer,
            "role" if value == "listener" => h.role = Role::Listener,
            "settings" => h.settings = settings(value)?,
            "ring" => h.ring = value.parse().map_err(|_| "the ring")?,
            "rules" => h.rules = value.split_whitespace().map(String::from).collect(),
            "class" => h.class = value.to_string(),
            _ => return Err(format!("the header line {line:?}")),
        }
        at = i + 1;
    }
    if h.rules.is_empty() || h.class.is_empty() {
        return Err("the header has no rules or no class".into());
    }
    Ok((h, at))
}

/// Run one case file: `Err` names the step.
async fn run_case(path: &Path) -> Result<Header, String> {
    let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let lines: Vec<(usize, &str)> = text
        .lines()
        .enumerate()
        .map(|(i, l)| (i + 1, l.trim()))
        .filter(|(_, l)| !l.is_empty() && !l.starts_with('#'))
        .collect();
    let (h, at) = header(&lines)?;
    let mut run = Run::start(h.role, h.settings, h.ring).await;
    let mut covered = false;
    for (number, line) in &lines[at..] {
        let (verb, rest) = line.split_once(' ').unwrap_or((line, ""));
        let args: Vec<&str> = rest.split_whitespace().collect();
        if run.end_seen && !covered && !verb.starts_with("expect") {
            return Err(format!("line {number}: the link ended ({:?}) and no expect-end came first", run.link.ended()));
        }
        run.step(verb, &args, rest).await.map_err(|e| format!("line {number} ({line:.60}): {e}"))?;
        covered |= verb == "expect-end";
    }
    if run.end_seen && !covered {
        return Err(format!("the link ended ({:?}) and no expect-end covers it", run.link.ended()));
    }
    Ok(h)
}

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests").join("cases")
}

/// The cases of the directory, each on a fresh runtime with a paused clock.
#[test]
fn each_case() {
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir())
        .expect("tests/cases")
        .map(|e| e.expect("a file").path())
        .filter(|p| p.extension().is_some_and(|x| x == "case"))
        .collect();
    files.sort();
    let count: usize = std::fs::read_to_string(dir().join("count"))
        .expect("tests/cases/count")
        .trim()
        .strip_prefix("count ")
        .and_then(|n| n.parse().ok())
        .expect("count N");
    let mut faults = Vec::new();
    let mut classes = std::collections::BTreeSet::new();
    for path in &files {
        let rt = tokio::runtime::Builder::new_current_thread().enable_time().start_paused(true).build().unwrap();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        match rt.block_on(run_case(path)) {
            Ok(h) => {
                classes.insert(h.class);
            }
            Err(e) => faults.push(format!("{name}: {e}")),
        }
    }
    if files.len() != count {
        faults.push(format!("tests/cases/count says {count}, the directory has {} cases", files.len()));
    }
    assert!(faults.is_empty(), "tests/cases:\n{}", faults.join("\n"));
    assert_eq!(classes.into_iter().collect::<Vec<_>>(), ["close", "credit", "memory", "streams", "time"]);
}

/// Each row of the table of the classes in `WIRE.md` names cases that
/// exist, or an invariant.
#[test]
fn each_class_row_names_a_case_or_an_invariant() {
    let wire = include_str!("../WIRE.md");
    let at = wire.find("## The classes of defects").expect("the table of the classes");
    let rows: Vec<&str> =
        wire[at..].lines().skip_while(|l| !l.starts_with('|')).take_while(|l| l.starts_with('|')).skip(2).collect();
    assert!(rows.len() >= 10, "{} rows", rows.len());
    let mut faults = Vec::new();
    for row in rows {
        let cells: Vec<&str> = row.trim_matches('|').split('|').map(str::trim).collect();
        let [class, _, cases] = cells[..] else { panic!("the row {row:?} does not have 3 cells") };
        if !["credit", "streams", "close", "time", "memory"].contains(&class) {
            faults.push(format!("{row}: the class {class:?}"));
        }
        if cases.starts_with("invariant: ") {
            continue;
        }
        for name in cases.split(", ") {
            let name = name.trim_matches('`');
            if !dir().join(format!("{name}.case")).is_file() {
                faults.push(format!("{row}: no case {name}"));
            }
        }
    }
    assert!(faults.is_empty(), "WIRE.md, the classes of defects:\n{}", faults.join("\n"));
}
