//! The sixth case of PodUtils/podssh#283: a link is lost while bytes go
//! both ways; the first new link ends before the far end greets; the
//! client tries again after its backoff (about 1.1 s), at the same resume
//! deadline, and the second new link resumes the session. Then the bytes
//! must move both ways, whole. In one case the stand-in relay ends both sides
//! of the old link; in the other it ends only the client's side, so that the
//! far end's old link still lives when the resume comes, and the resume
//! stops it. The far end says each resume to the sink of its keeper.

use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pod_core::Event;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio::sync::mpsc;

use pod_session::budget::Tell;
use pod_session::client::{self, Outcome};
use pod_session::keep::{Keeper, RESUME};
use pod_session::resume::{self, Next, Note};
use pod_session::{Ask, End, OsEntropy, Role, Settings, far};

const PIPE: usize = 256 * 1024;
const MIB: usize = 1 << 20;
const LIMIT: Duration = Duration::from_secs(60);

/// How the stand-in relay ends a link.
#[derive(Debug, Clone, Copy)]
enum Cut {
    /// Both sides end, with no word.
    Both,
    /// The client's side ends; the far end's side stays open and silent,
    /// and what the far end writes goes nowhere, as when the relay has not
    /// told the node yet.
    ClientSide,
}

fn pseudo_random(len: usize, seed: u32) -> Vec<u8> {
    let mut x = seed;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x as u8
        })
        .collect()
}

/// Copy `from` into `to` until `left` (bytes of both ways together) runs
/// out: the part before the cut goes through, and the rest never does.
async fn copy_until<R, W>(from: &mut R, to: &mut W, left: &AtomicI64)
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let n = match from.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        let before = left.fetch_sub(n as i64, Ordering::SeqCst);
        if before <= n as i64 {
            let _ = to.write_all(&buf[..before.max(0) as usize]).await;
            return;
        }
        if to.write_all(&buf[..n]).await.is_err() {
            return;
        }
    }
}

/// A link through a stand-in relay host: both ways until `after` bytes
/// passed, then `cut`. `None` never cuts.
fn relayed(after: Option<usize>, cut: Cut) -> (DuplexStream, DuplexStream) {
    let (client, relay_client) = tokio::io::duplex(PIPE);
    let (relay_far, far) = tokio::io::duplex(PIPE);
    tokio::spawn(async move {
        let left = AtomicI64::new(after.map_or(i64::MAX, |c| c as i64));
        let (mut cr, mut cw) = tokio::io::split(relay_client);
        let (mut fr, mut fw) = tokio::io::split(relay_far);
        tokio::select! {
            _ = copy_until(&mut cr, &mut fw, &left) => {}
            _ = copy_until(&mut fr, &mut cw, &left) => {}
        }
        drop((cr, cw));
        if let Cut::ClientSide = cut {
            let mut buf = vec![0u8; 64 * 1024];
            while matches!(fr.read(&mut buf).await, Ok(n) if n > 0) {}
        }
        drop((fr, fw));
    });
    (client, far)
}

/// A far end that takes each link from `links`: a new session gets a target
/// whose other end goes to `targets`; a resume goes on through the keeper.
fn far_end(
    keeper: Arc<Keeper<DuplexStream>>,
    settings: Settings,
    mut links: mpsc::UnboundedReceiver<DuplexStream>,
    targets: mpsc::UnboundedSender<DuplexStream>,
) {
    tokio::spawn(async move {
        while let Some(link) = links.recv().await {
            let (keeper, targets) = (keeper.clone(), targets.clone());
            tokio::spawn(async move {
                let Ok(accepted) = far::accept(link, Role::NODE, settings, &keeper.sessions, &mut OsEntropy).await
                else {
                    return;
                };
                if accepted.established().resumed {
                    let _ = keeper.run_resumed(accepted).await;
                } else {
                    let (target, app) = tokio::io::duplex(PIPE);
                    let _ = targets.send(app);
                    keeper.run_new(accepted, target).await;
                }
            });
        }
    });
}

/// Write `out` and read as many bytes at once, then end this side.
async fn exchange(stream: DuplexStream, out: Vec<u8>) -> Vec<u8> {
    let (mut r, mut w) = tokio::io::split(stream);
    let len = out.len();
    let writer = tokio::spawn(async move {
        w.write_all(&out).await.unwrap();
        w
    });
    let mut got = vec![0u8; len];
    r.read_exact(&mut got).await.unwrap();
    let mut w = writer.await.unwrap();
    w.shutdown().await.unwrap();
    got
}

/// The sixth case, with the old link ended by `old`: the session's bytes
/// both ways, whole, and the far end's lines of its resumes.
async fn sixth_case(old: Cut) -> Vec<String> {
    let settings = Settings { resume_deadline: Duration::from_secs(30), ..Settings::default() }.on_the_pair();
    let lines: Arc<Mutex<Vec<Event>>> = Arc::default();
    let sink = lines.clone();
    let tell = Tell::new(Arc::new(move |e: Event| sink.lock().unwrap().push(e)), "the node's settings");
    let keeper = Arc::new(Keeper::new(Duration::from_secs(30)).with_tell(tell));
    let (links_tx, links_rx) = mpsc::unbounded_channel();
    let (targets_tx, mut targets_rx) = mpsc::unbounded_channel();
    far_end(keeper.clone(), settings, links_rx, targets_tx);

    // The old link ends once 3 MiB passed, in the middle of the bytes.
    let (client_link, far_link) = relayed(Some(3 * MIB), old);
    links_tx.send(far_link).unwrap();
    let client = client::start(client_link, Ask::New, settings, &mut OsEntropy).await.unwrap();

    let attempts = Arc::new(AtomicUsize::new(0));
    let connect = {
        let (attempts, links_tx) = (attempts.clone(), links_tx.clone());
        move |_: &pod_session::Ended| {
            // The first new link: the relay takes it and ends the client's
            // side before the far end's GREETING passes. The second holds.
            let first = attempts.fetch_add(1, Ordering::SeqCst) == 0;
            let (client_link, far_link) = if first { relayed(Some(0), old) } else { relayed(None, Cut::Both) };
            links_tx.send(far_link).unwrap();
            async move { Next::Link(client_link) }
        }
    };
    let notes: Arc<Mutex<Vec<Note>>> = Arc::default();
    let note = {
        let notes = notes.clone();
        move |n: Note| notes.lock().unwrap().push(n)
    };
    let (app, app_end) = tokio::io::duplex(PIPE);
    let session = tokio::spawn(async move { resume::run(client, app_end, connect, note, &mut OsEntropy).await });

    let target = tokio::time::timeout(LIMIT, targets_rx.recv()).await.unwrap().unwrap();
    let (up, down) = (pseudo_random(8 * MIB, 3), pseudo_random(8 * MIB, 4));
    let moved =
        tokio::time::timeout(LIMIT, async { tokio::join!(exchange(target, down.clone()), exchange(app, up.clone())) })
            .await;
    let notes_now = notes.lock().unwrap().clone();
    let lines_now: Vec<String> = lines.lock().unwrap().iter().map(|e| e.text.clone()).collect();
    let (at_server, at_client) =
        moved.unwrap_or_else(|_| panic!("the bytes stopped: notes {notes_now:?}; far end {lines_now:?}"));
    assert_eq!(Sha256::digest(&at_server), Sha256::digest(&up), "the client's bytes reached the target whole");
    assert_eq!(Sha256::digest(&at_client), Sha256::digest(&down), "the target's bytes reached the client whole");

    let outcome = tokio::time::timeout(LIMIT, session).await.unwrap().unwrap();
    assert!(
        matches!(&outcome, Outcome::Layer(ended) if matches!(ended.end, End::LocalEnd | End::Closed(_))),
        "{outcome:?}"
    );
    let notes = notes.lock().unwrap().clone();
    let failed_first = notes.iter().position(
        |n| matches!(n, Note::Retry { why, .. } if why.contains("the new link ended before the far end greeted")),
    );
    let resumed = notes.iter().position(|n| matches!(n, Note::Resumed { .. }));
    assert!(matches!((failed_first, resumed), (Some(a), Some(b)) if a < b), "{notes:?}");
    assert_eq!(attempts.load(Ordering::SeqCst), 2, "{notes:?}");
    let lines = lines.lock().unwrap();
    assert!(lines.iter().all(|e| e.kind == RESUME), "{lines:?}");
    lines.iter().map(|e| e.text.clone()).collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_resume_after_a_new_link_that_ended_before_the_greeting_moves_bytes_both_ways() {
    let lines = sixth_case(Cut::Both).await;
    assert_eq!(lines.len(), 1, "one resume: {lines:?}");
    assert!(lines[0].contains(": resume 1: the client has "), "{lines:?}");
    assert!(lines[0].contains("; no link carried the session; room "), "{lines:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_resume_while_the_old_link_lives_at_the_far_end_stops_it_and_moves_bytes_both_ways() {
    let lines = sixth_case(Cut::ClientSide).await;
    assert_eq!(lines.len(), 1, "one resume: {lines:?}");
    assert!(lines[0].contains(": resume 1: the client has "), "{lines:?}");
    assert!(lines[0].contains("; it stopped the first link; room "), "{lines:?}");
}
