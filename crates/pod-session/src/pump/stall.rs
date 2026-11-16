//! The far end's line of a wait that holds (PodUtils/podssh#283): the half
//! that reads the target says where it waits, and the pump looks at it
//! while the link lives. A wait for room, for the writer of the link, or
//! for room to send again that holds for [`STALL_AFTER`] gives one line,
//! with the offsets and the room. A read of the target that gives no byte
//! for as long, while the target took bytes of the client, gives one line
//! too. The line goes to the sink of [`Watch::stall`], with the kind
//! [`STALL`].

use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use pod_core::Event;
use tokio::time::Instant;

use super::super::budget::Tell;
use super::super::link::Link;
use super::lock;

/// The kind of the event of a wait that holds.
pub const STALL: &str = "session.stall";
/// How long a wait holds before its line.
pub const STALL_AFTER: Duration = Duration::from_secs(20);
/// How often the pump looks at the waits.
const LOOK: Duration = Duration::from_secs(5);

/// Where the lines of a far end's waits go, with the session's name.
#[derive(Debug, Clone)]
pub struct Stall {
    pub tell: Tell,
    /// The short id of the session.
    pub session: String,
}

/// What the half that reads the target waits for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum UpWait {
    /// Room for the records of a resume, within the window.
    Again,
    /// Room in the replay buffer, within the window.
    Room,
    /// Bytes of the target.
    Target,
    /// The writer of the link, which takes one batch at a time.
    Writer,
    /// Nothing: the target ended its bytes.
    Done,
}

/// The wait of the half that reads the target, since when, and the bytes
/// that the target took.
pub(super) struct Waits {
    up: Mutex<(UpWait, Instant)>,
    /// The bytes written to the target on this link.
    took: AtomicU64,
    /// [`Waits::took`] when the read of the target started.
    took_at_read: AtomicU64,
}

impl Waits {
    pub(super) fn new() -> Waits {
        Waits {
            up: Mutex::new((UpWait::Target, Instant::now())),
            took: AtomicU64::new(0),
            took_at_read: AtomicU64::new(0),
        }
    }

    /// The half that reads the target waits for `wait` from now.
    pub(super) fn up(&self, wait: UpWait) {
        if wait == UpWait::Target {
            self.took_at_read.store(self.took.load(Ordering::Relaxed), Ordering::Relaxed);
        }
        *lock(&self.up) = (wait, Instant::now());
    }

    /// `n` more bytes went to the target.
    pub(super) fn took(&self, n: usize) {
        self.took.fetch_add(n as u64, Ordering::Relaxed);
    }
}

/// The line of `wait`, held for `held`, where it gives one: each wait but a
/// read of a target that took nothing in the meantime, and the end.
pub(super) fn line(wait: UpWait, held: Duration, took: u64, link: &Link, window: Option<usize>) -> Option<String> {
    let s = held.as_secs();
    let window = window.map_or("no window".to_string(), |w| format!("a window of {w} bytes"));
    let offsets = format!(
        "this side sent {} bytes, the client acknowledged {}; the replay buffer keeps {} bytes, room {}; {window}",
        link.sent(),
        link.acknowledged(),
        link.kept(),
        link.room()
    );
    let what = match wait {
        UpWait::Again => format!("the records sent again wait for room for {s} s"),
        UpWait::Room => format!("the reader of the target waits for room for {s} s"),
        UpWait::Writer => format!("the reader of the target waits {s} s for the writer of the link"),
        UpWait::Target if took > 0 => {
            format!("the target sent no byte for {s} s, while it took {took} bytes of the client")
        }
        UpWait::Target | UpWait::Done => return None,
    };
    Some(format!("{what}; {offsets}"))
}

/// Look at `waits` while the link lives, and say each wait that holds,
/// once. It never ends: the pump's other parts end the link.
pub(super) async fn look(
    waits: &Waits,
    state: &Mutex<Link>,
    window: Option<usize>,
    stall: Option<&Stall>,
) -> std::convert::Infallible {
    let Some(stall) = stall else { return std::future::pending().await };
    let mut told: Option<Instant> = None;
    loop {
        tokio::time::sleep(LOOK).await;
        let (wait, since) = *lock(&waits.up);
        let held = since.elapsed();
        if held < STALL_AFTER || told == Some(since) {
            continue;
        }
        let took = waits.took.load(Ordering::Relaxed).saturating_sub(waits.took_at_read.load(Ordering::Relaxed));
        let words = line(wait, held, took, &lock(state), window);
        if let Some(words) = words {
            told = Some(since);
            stall.tell.events.event(Event::info(STALL, format!("session {}: {words}", stall.session)));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_wait_for_room_gives_the_offsets_and_a_quiet_target_that_took_nothing_gives_none() {
        let link = Link::new(0, 0).with_replay(1 << 20);
        let room = line(UpWait::Room, Duration::from_secs(25), 0, &link, Some(786_432)).unwrap();
        assert!(room.starts_with("the reader of the target waits for room for 25 s; this side sent 0 bytes"), "{room}");
        assert!(room.ends_with("a window of 786432 bytes"), "{room}");
        assert_eq!(line(UpWait::Target, Duration::from_secs(25), 0, &link, None), None);
        let quiet = line(UpWait::Target, Duration::from_secs(25), 4096, &link, None).unwrap();
        assert!(quiet.starts_with("the target sent no byte for 25 s, while it took 4096 bytes"), "{quiet}");
        assert!(line(UpWait::Writer, Duration::from_secs(21), 0, &link, None).unwrap().contains("for the writer"));
        assert_eq!(line(UpWait::Done, Duration::from_secs(99), 7, &link, None), None);
    }

    #[derive(Default)]
    struct Lines(Mutex<Vec<String>>);

    impl pod_core::Events for Lines {
        fn event(&self, event: Event) {
            assert_eq!(event.kind, STALL);
            lock(&self.0).push(event.text);
        }
    }

    /// A wait for room that holds gives one line after 20 s, not two; a new
    /// wait gives its own; a read of a target that took nothing gives none.
    #[tokio::test(start_paused = true)]
    async fn a_wait_that_holds_gives_one_line_each() {
        let lines = std::sync::Arc::new(Lines::default());
        let stall = Stall { tell: Tell::new(lines.clone(), ""), session: "0187db18".into() };
        let (waits, state) = (Waits::new(), Mutex::new(Link::new(0, 0).with_replay(1 << 20)));
        waits.up(UpWait::Room);
        let looking = look(&waits, &state, Some(786_432), Some(&stall));
        tokio::pin!(looking);
        macro_rules! run {
            ($secs:expr) => {
                tokio::time::timeout(Duration::from_secs($secs), looking.as_mut())
            };
        }
        assert!(run!(16).await.is_err());
        assert!(lock(&lines.0).is_empty());
        assert!(run!(30).await.is_err());
        let got = lock(&lines.0).clone();
        assert_eq!(got.len(), 1, "{got:?}");
        assert!(got[0].starts_with("session 0187db18: the reader of the target waits for room for 20 s"), "{got:?}");
        waits.up(UpWait::Target);
        assert!(run!(30).await.is_err());
        waits.up(UpWait::Writer);
        assert!(run!(30).await.is_err());
        let got = lock(&lines.0).clone();
        assert_eq!(got.len(), 2, "{got:?}");
        assert!(got[1].contains(" s for the writer of the link"), "{got:?}");
    }
}
