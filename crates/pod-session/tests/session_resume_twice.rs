//! The case of PodUtils/podssh#283 as the consumer amended it: two resumes in
//! quick succession after the relay's open links are cut. The stand-in relay
//! host stops while bytes go both ways: its link goes silent, open at both
//! ends. A spare link beside it resumes the session (the first resume); then
//! the relay cuts each link that is open, the spare's and the silent one's,
//! as a proxy that resets its open tunnels; the client resumes again at once
//! on a new link (the second resume). Then the bytes must move both ways,
//! whole, and the far end says both resumes, with the relay link of each.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pod_core::Event;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio::sync::{Notify, mpsc, watch};

use pod_session::budget::Tell;
use pod_session::client::{self, Outcome};
use pod_session::keep::{Keeper, RESUME};
use pod_session::resume::{self, Next, Note};
use pod_session::{Ask, End, OsEntropy, Role, Settings, far};

const PIPE: usize = 256 * 1024;
const MIB: usize = 1 << 20;
const LIMIT: Duration = Duration::from_secs(60);

/// What the stand-in relay does with one link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Hop {
    /// It carries the bytes both ways.
    Open,
    /// It carries nothing more and keeps both sides open: a relay host that
    /// stopped.
    Silent,
    /// Both sides end with no word: a reset of the tunnel.
    Cut,
}

/// The stand-in relay: each link that it carries, by its number.
#[derive(Default)]
struct Relay {
    hops: Mutex<Vec<watch::Sender<Hop>>>,
    /// The bytes that the first link carried, both ways.
    first: Arc<AtomicU64>,
    /// Told each time the first link carried more.
    moved: Arc<Notify>,
}

impl Relay {
    /// A new link through the relay: the client's side and the far end's.
    fn link(&self) -> (DuplexStream, DuplexStream) {
        let (client, relay_client) = tokio::io::duplex(PIPE);
        let (relay_far, far) = tokio::io::duplex(PIPE);
        let (tx, rx) = watch::channel(Hop::Open);
        let mut hops = self.hops.lock().unwrap();
        let counted = hops.is_empty().then(|| (self.first.clone(), self.moved.clone()));
        hops.push(tx);
        tokio::spawn(carry(relay_client, relay_far, rx, counted));
        (client, far)
    }

    fn set(&self, hop: usize, to: Hop) {
        let _ = self.hops.lock().unwrap()[hop].send(to);
    }

    /// Cut each link that is open or silent.
    fn cut_all(&self) {
        for hop in self.hops.lock().unwrap().iter() {
            let _ = hop.send(Hop::Cut);
        }
    }

    /// Until the first link carried `bytes`.
    async fn first_carried(&self, bytes: u64) {
        loop {
            let moved = self.moved.notified();
            if self.first.load(Ordering::SeqCst) >= bytes {
                return;
            }
            moved.await;
        }
    }
}

async fn copy<R, W>(from: &mut R, to: &mut W, counted: &Option<(Arc<AtomicU64>, Arc<Notify>)>)
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let n = match from.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        if to.write_all(&buf[..n]).await.is_err() {
            break;
        }
        if let Some((bytes, moved)) = counted {
            bytes.fetch_add(n as u64, Ordering::SeqCst);
            moved.notify_waiters();
        }
    }
    let _ = to.shutdown().await;
}

/// Carry one link as `hop` says: both ways while it is open; nothing, with
/// both sides held, while it is silent; then both sides end at its cut.
async fn carry(
    client: DuplexStream,
    far: DuplexStream,
    mut hop: watch::Receiver<Hop>,
    counted: Option<(Arc<AtomicU64>, Arc<Notify>)>,
) {
    let (mut cr, mut cw) = tokio::io::split(client);
    let (mut fr, mut fw) = tokio::io::split(far);
    tokio::select! {
        _ = async { tokio::join!(copy(&mut cr, &mut fw, &counted), copy(&mut fr, &mut cw, &counted)) } => {}
        _ = hop.wait_for(|h| *h != Hop::Open) => {}
    }
    let _ = hop.wait_for(|h| *h == Hop::Cut).await;
}

/// A far end that takes each link from `links`, as the reverse road's node
/// does: each link named by its number at the relay.
fn far_end(
    keeper: Arc<Keeper<DuplexStream>>,
    settings: Settings,
    mut links: mpsc::UnboundedReceiver<(usize, DuplexStream)>,
    targets: mpsc::UnboundedSender<DuplexStream>,
) {
    tokio::spawn(async move {
        while let Some((n, link)) = links.recv().await {
            let (keeper, targets) = (keeper.clone(), targets.clone());
            tokio::spawn(async move {
                let Ok(accepted) = far::accept(link, Role::NODE, settings, &keeper.sessions, &mut OsEntropy).await
                else {
                    return;
                };
                let accepted = accepted.by(format!("relay link {n}"));
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_resumes_in_quick_succession_after_the_open_links_are_cut_move_bytes_both_ways() {
    let settings =
        Settings { resume_deadline: Duration::from_secs(30), spare_links: true, ..Settings::default() }.on_the_pair();
    let lines: Arc<Mutex<Vec<Event>>> = Arc::default();
    let sink = lines.clone();
    let tell = Tell::new(Arc::new(move |e: Event| sink.lock().unwrap().push(e)), "the node's settings");
    let keeper = Arc::new(Keeper::new(Duration::from_secs(30)).with_tell(tell));
    let (links_tx, links_rx) = mpsc::unbounded_channel();
    let (targets_tx, mut targets_rx) = mpsc::unbounded_channel();
    far_end(keeper.clone(), settings, links_rx, targets_tx);
    let relay = Arc::new(Relay::default());

    let (client_link, far_link) = relay.link();
    links_tx.send((0, far_link)).unwrap();
    let client = client::start(client_link, Ask::New, settings, &mut OsEntropy).await.unwrap();

    let connect = {
        let (relay, links_tx) = (relay.clone(), links_tx.clone());
        move |_: &pod_session::Ended| {
            let (client_link, far_link) = relay.link();
            let n = relay.hops.lock().unwrap().len() - 1;
            links_tx.send((n, far_link)).unwrap();
            async move { Next::Link(client_link) }
        }
    };
    let notes: Arc<Mutex<Vec<Note>>> = Arc::default();
    let note = {
        let (notes, relay) = (notes.clone(), relay.clone());
        move |n: Note| {
            let first = matches!(n, Note::Resumed { .. })
                && !notes.lock().unwrap().iter().any(|n| matches!(n, Note::Resumed { .. }));
            notes.lock().unwrap().push(n);
            // The first resume is done: the relay resets each open link at
            // once, the new one too.
            if first {
                relay.cut_all();
            }
        }
    };
    let (app, app_end) = tokio::io::duplex(PIPE);
    let session = tokio::spawn(async move { resume::run(client, app_end, connect, note, &mut OsEntropy).await });

    let target = tokio::time::timeout(LIMIT, targets_rx.recv()).await.unwrap().unwrap();
    let (up, down) = (pseudo_random(16 * MIB, 5), pseudo_random(16 * MIB, 6));
    let moving = tokio::spawn(async move { tokio::join!(exchange(target, down.clone()), exchange(app, up.clone())) });
    // The relay host stops in the middle of the bytes.
    tokio::time::timeout(LIMIT, relay.first_carried(4 * MIB as u64)).await.expect("the first link carries bytes");
    relay.set(0, Hop::Silent);

    let moved = tokio::time::timeout(LIMIT, moving).await;
    let notes_now = notes.lock().unwrap().clone();
    let lines_now: Vec<String> = lines.lock().unwrap().iter().map(|e| e.text.clone()).collect();
    let (at_server, at_client) =
        moved.unwrap_or_else(|_| panic!("the bytes stopped: notes {notes_now:?}; far end {lines_now:?}")).unwrap();
    assert_eq!(Sha256::digest(&at_server), Sha256::digest(pseudo_random(16 * MIB, 5)), "client to target");
    assert_eq!(Sha256::digest(&at_client), Sha256::digest(pseudo_random(16 * MIB, 6)), "target to client");

    let outcome = tokio::time::timeout(LIMIT, session).await.unwrap().unwrap();
    assert!(
        matches!(&outcome, Outcome::Layer(ended) if matches!(ended.end, End::LocalEnd | End::Closed(_))),
        "{outcome:?}"
    );
    let notes = notes.lock().unwrap().clone();
    let resumes = notes.iter().filter(|n| matches!(n, Note::Resumed { .. })).count();
    assert!(resumes >= 2, "{notes:?}");
    let lines: Vec<String> =
        lines.lock().unwrap().iter().inspect(|e| assert_eq!(e.kind, RESUME)).map(|e| e.text.clone()).collect();
    // The far end says each resume that the client called done, once, on
    // the relay link that carried it: it took the session, or it gave way to
    // the next one when the cut came while it waited for the old link to
    // stop. The newest took the session.
    assert_eq!(lines.len(), resumes, "{lines:?} {notes:?}");
    for n in 1..=resumes {
        let line = lines.iter().find(|l| l.contains(&format!(": resume {n} on relay link ")));
        let line = line.unwrap_or_else(|| panic!("resume {n}: {lines:?}"));
        let took = line.contains(" bytes again; ");
        assert!(took || line.ends_with("; this resume gave way"), "{lines:?}");
        assert!(took || n < resumes, "the newest resume took the session: {lines:?}");
    }
    let first = lines.iter().find(|l| l.contains(": resume 1 on relay link 1")).unwrap();
    assert!(first.ends_with("; it stopped the first link") || first.ends_with("gave way"), "{lines:?}");
}
