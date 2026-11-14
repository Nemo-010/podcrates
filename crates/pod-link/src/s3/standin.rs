//! A stand-in of the S3 API on the loopback, for the tests of this crate
//! and of a consumer (feature `s3-standin`): plain HTTP/1.1 with
//! keep-alive, buckets in memory, the PUT of `If-None-Match: *`, the GET of
//! `If-Match`, the DELETE and the `ListObjectsV2` of path style. It checks
//! the SigV4 of each request with the signer of the crate over what it
//! received and with the made-up [`key`], and the payload hash with its own
//! SHA-256; a request with no signature gets 403. It counts its work
//! ([`Counts`]), and can drop the answer of a PUT that it took
//! ([`StandIn::lose_puts`]). No binary needs it.

mod serve;

use std::collections::BTreeMap;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinSet;

use super::{Credentials, Endpoint};

/// The made-up key that the stand-in takes. No service knows it.
pub fn key() -> Credentials {
    Credentials::new("PODLINKTESTKEY", "pod-link-test-secret-not-real")
}

/// An object of a bucket: its body and its ETag (with its quotes).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Object {
    pub body: Vec<u8>,
    pub etag: String,
}

/// The objects of one bucket, by key.
pub type Bucket = BTreeMap<String, Object>;

/// The work of a stand-in so far.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    pub puts: usize,
    pub gets: usize,
    pub lists: usize,
    pub deletes: usize,
    /// PUTs of a key that was there (412).
    pub exists: usize,
    /// Requests with no signature or a wrong one (403).
    pub refused: usize,
    /// The answers of PUTs that the stand-in dropped.
    pub lost: usize,
}

#[derive(Default)]
struct Tally {
    puts: AtomicUsize,
    gets: AtomicUsize,
    lists: AtomicUsize,
    deletes: AtomicUsize,
    exists: AtomicUsize,
    refused: AtomicUsize,
    lose_puts: AtomicUsize,
    lost: AtomicUsize,
}

impl Tally {
    fn add(counter: &AtomicUsize) {
        counter.fetch_add(1, Ordering::SeqCst);
    }
}

struct State {
    buckets: Mutex<BTreeMap<String, Bucket>>,
    tally: Tally,
}

impl State {
    fn buckets(&self) -> MutexGuard<'_, BTreeMap<String, Bucket>> {
        self.buckets.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// A stand-in on its loopback port. A drop closes the port and each
/// connection.
pub struct StandIn {
    addr: SocketAddr,
    state: Arc<State>,
    // A drop of the sender ends the accept loop and its connections.
    _stop: oneshot::Sender<()>,
}

impl StandIn {
    /// Bind `127.0.0.1:0` and serve the empty `buckets` on the runtime of
    /// the caller.
    pub async fn start(buckets: &[&str]) -> io::Result<StandIn> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let (standin, stop) = StandIn::new(listener.local_addr()?, buckets);
        tokio::spawn(run(listener, standin.state.clone(), stop));
        Ok(standin)
    }

    /// Bind `127.0.0.1:0` and serve the empty `buckets` on a thread with
    /// its own runtime: for a test with no runtime, or one that blocks its
    /// own (a child process).
    pub fn start_thread(buckets: &[&str]) -> io::Result<StandIn> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
        let (standin, stop) = StandIn::new(listener.local_addr()?, buckets);
        let state = standin.state.clone();
        std::thread::Builder::new().name("s3-standin".into()).spawn(move || {
            runtime.block_on(async move {
                if let Ok(listener) = TcpListener::from_std(listener) {
                    run(listener, state, stop).await;
                }
            });
        })?;
        Ok(standin)
    }

    fn new(addr: SocketAddr, buckets: &[&str]) -> (StandIn, oneshot::Receiver<()>) {
        let buckets = buckets.iter().map(|b| (b.to_string(), Bucket::new())).collect();
        let state = Arc::new(State { buckets: Mutex::new(buckets), tally: Tally::default() });
        let (stop, stopped) = oneshot::channel();
        (StandIn { addr, state, _stop: stop }, stopped)
    }

    /// The address of the port.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// The endpoint text: `http://127.0.0.1:PORT`.
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// The endpoint of the carrier.
    pub fn endpoint(&self) -> Endpoint {
        Endpoint::parse(&self.url()).expect("the endpoint of a loopback address")
    }

    /// The buckets with their objects, locked: a test reads them or puts
    /// an object in place.
    pub fn buckets(&self) -> MutexGuard<'_, BTreeMap<String, Bucket>> {
        self.state.buckets()
    }

    /// The keys of `bucket` under `prefix`, in order; none for a missing
    /// bucket.
    pub fn keys(&self, bucket: &str, prefix: &str) -> Vec<String> {
        let buckets = self.state.buckets();
        let keys = buckets.get(bucket).into_iter().flat_map(|b| b.keys());
        keys.filter(|k| k.starts_with(prefix)).cloned().collect()
    }

    /// The work so far.
    pub fn counts(&self) -> Counts {
        let t = &self.state.tally;
        let n = |c: &AtomicUsize| c.load(Ordering::SeqCst);
        Counts {
            puts: n(&t.puts),
            gets: n(&t.gets),
            lists: n(&t.lists),
            deletes: n(&t.deletes),
            exists: n(&t.exists),
            refused: n(&t.refused),
            lost: n(&t.lost),
        }
    }

    /// Drop the answers of the next `n` PUTs that take their object, and
    /// close their connections, as a network that loses an answer does.
    pub fn lose_puts(&self, n: usize) {
        self.state.tally.lose_puts.store(n, Ordering::SeqCst);
    }
}

/// The accept loop, until the stand-in is dropped. The port closes before
/// the connections, so a peer that sees its connection end finds the port
/// closed.
async fn run(listener: TcpListener, state: Arc<State>, mut stop: oneshot::Receiver<()>) {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            _ = &mut stop => break,
            accepted = listener.accept() => {
                let Ok((tcp, _)) = accepted else { break };
                while connections.try_join_next().is_some() {}
                connections.spawn(serve::serve(tcp, state.clone()));
            }
        }
    }
    drop(listener);
    drop(connections);
}
