//! The accept side of the split: a task for each listener of a half takes
//! its peers, reads the hello of each within `join_timeout`, and joins the
//! up half and the down half of one session. The two halves must prove the
//! same key, when their carriers prove one. A half that waits longer than
//! `join_timeout` for the other goes.

use std::collections::HashMap;
use std::io;

use pod_identity::PublicKey;
use tokio::sync::mpsc;
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{Instant, timeout};

use super::run::{self, End, Timing};
use super::wire::{self, kind};
use super::{Half, NAME, Split};
use crate::carrier::{Accepted, BoxIo, CarrierError, CarrierErrorKind, Listener, Pending};

/// The halves that wait for their other half, at most.
const PENDING: usize = 256;

/// The sessions that wait for an accept.
const QUEUE: usize = 64;

type Joined = Result<Accepted, CarrierError>;

/// A listener of the split: the listeners of its two halves. Its drop ends
/// its tasks and each half that waits; the sessions that it gave live on.
pub struct SplitListener {
    address: String,
    results: mpsc::Receiver<Joined>,
    task: JoinHandle<()>,
}

impl std::fmt::Debug for SplitListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SplitListener").field("address", &self.address).finish_non_exhaustive()
    }
}

fn err(kind: CarrierErrorKind, text: impl Into<String>) -> CarrierError {
    CarrierError::new(NAME, kind, text)
}

/// A half after its hello.
struct Hello {
    up: bool,
    session: [u8; 16],
    io: BoxIo,
    peer: Option<PublicKey>,
}

pub(super) fn start(split: &Split, up: Box<dyn Listener>, down: Box<dyn Listener>) -> SplitListener {
    let address = format!("{}|{}", up.address(), down.address());
    let (out, results) = mpsc::channel(QUEUE);
    let task = tokio::spawn(serve(up, down, split.timing(), split.join_timeout, out));
    SplitListener { address, results, task }
}

/// Take the peers of each listener, read their hellos, and join each
/// session whose two halves came.
async fn serve(
    up: Box<dyn Listener>,
    down: Box<dyn Listener>,
    timing: Timing,
    within: std::time::Duration,
    out: mpsc::Sender<Joined>,
) {
    // A task for each listener: no accept of a listener is cancelled.
    let (peers, mut accepts) = mpsc::channel(QUEUE);
    let mut doors = JoinSet::new();
    for mut door in [up, down] {
        let peers = peers.clone();
        doors.spawn(async move { while peers.send(door.accept_peer().await).await.is_ok() {} });
    }
    let mut hellos = JoinSet::new();
    let mut waiting: HashMap<[u8; 16], (Instant, Hello)> = HashMap::new();
    let mut tick = tokio::time::interval(within);
    loop {
        let accepted = tokio::select! {
            Some(accepted) = accepts.recv() => accepted,
            Some(done) = hellos.join_next(), if !hellos.is_empty() => {
                match done {
                    Ok(Ok(hello)) => join(hello, &mut waiting, timing, &out),
                    Ok(Err(e)) => {
                        let _ = out.try_send(Err(e));
                    }
                    Err(_) => {}
                }
                continue;
            }
            _ = tick.tick() => {
                waiting.retain(|_, (at, _)| at.elapsed() < within);
                continue;
            }
        };
        match accepted {
            Ok(peer) if hellos.len() + waiting.len() < PENDING => {
                hellos.spawn(async move {
                    let mut io = peer.io;
                    match timeout(within, wire::read_hello(&mut io)).await {
                        Ok(Ok((up, session))) => Ok(Hello { up, session, io, peer: peer.peer }),
                        Ok(Err(e)) => Err(CarrierError::io(NAME, "the hello of a half", e)),
                        Err(_) => Err(err(CarrierErrorKind::Io(io::ErrorKind::TimedOut), "no hello of a half in time")),
                    }
                });
            }
            Ok(_) => tracing::debug!("the split listener holds its most halves: a half goes"),
            Err(e) => {
                let _ = out.try_send(Err(e));
            }
        }
    }
}

/// Keep `hello` until the other half of its session comes; then write the
/// join down and give the session.
fn join(hello: Hello, waiting: &mut HashMap<[u8; 16], (Instant, Hello)>, timing: Timing, out: &mpsc::Sender<Joined>) {
    let other = match waiting.remove(&hello.session) {
        Some((_, other)) if other.up != hello.up => other,
        Some(_) => {
            let _ = out.try_send(Err(err(CarrierErrorKind::Refused, "two halves of one session name the same half")));
            return;
        }
        None => {
            waiting.insert(hello.session, (Instant::now(), hello));
            return;
        }
    };
    let (up, down) = if hello.up { (hello, other) } else { (other, hello) };
    if let (Some(a), Some(b)) = (up.peer, down.peer)
        && a != b
    {
        let _ = out.try_send(Err(err(CarrierErrorKind::Refused, format!("the up half proved {a}, the down half {b}"))));
        return;
    }
    let (peer, out) = (up.peer.or(down.peer), out.clone());
    tokio::spawn(async move {
        let mut down_io = down.io;
        if let Err(e) = wire::write(&mut down_io, kind::JOINED, &[]).await {
            let _ = out.send(Err(CarrierError::io(NAME, "the join of the down half", e))).await;
            return;
        }
        let end = End { out: down_io, out_half: Half::Down, into: up.io, in_half: Half::Up };
        let io: BoxIo = Box::new(run::run(end, timing));
        if out.try_send(Ok(Accepted { io, peer })).is_err() {
            tracing::debug!("a session of the split listener found the queue full");
        }
    });
}

impl SplitListener {
    /// The next session and the key that its halves proved. A half that
    /// failed is an error of one accept: the listener stays open.
    pub async fn accept_peer(&mut self) -> Result<Accepted, CarrierError> {
        self.results.recv().await.unwrap_or_else(|| {
            Err(err(CarrierErrorKind::Io(io::ErrorKind::BrokenPipe), "the task of the listener ended"))
        })
    }
}

impl Listener for SplitListener {
    fn address(&self) -> String {
        self.address.clone()
    }

    fn accept(&mut self) -> Pending<'_, BoxIo> {
        Box::pin(async move { SplitListener::accept_peer(self).await.map(|a| a.io) })
    }

    fn accept_peer(&mut self) -> Pending<'_, Accepted> {
        Box::pin(SplitListener::accept_peer(self))
    }
}

impl Drop for SplitListener {
    fn drop(&mut self) {
        self.task.abort();
    }
}
