//! The accept side of the s3 carrier: a task lists the open objects of the
//! prefix, and runs the handshake of each new session in a task of its own,
//! at most `max_handshakes` at once. The open objects at the bind are old,
//! so the listener takes none of them. A drop of the listener ends its
//! task and its handshakes under way; the sessions it gave live on.

use std::collections::HashSet;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use pod_identity::PublicKey;
use tokio::sync::{Semaphore, mpsc};
use tokio::task::{JoinHandle, JoinSet};
use tokio_rustls::TlsAcceptor;

use super::client::{Client, Fault};
use super::stream::{self, Dirs, Keys, TuningRef, base};
use super::{NAME, S3};
use crate::carrier::{Accepted, BoxIo, CarrierError, CarrierErrorKind, Listener, Pending};
use crate::dgram_tls;

/// A session, or a failed handshake.
type Shaken = Result<(BoxIo, PublicKey), CarrierError>;

/// The results that wait for an accept; a handshake that finds the queue
/// full is dropped.
const QUEUE: usize = 64;

/// A listener of the s3 carrier. Its drop ends the task of its accepts.
pub struct S3Listener {
    address: String,
    results: mpsc::Receiver<Shaken>,
    task: JoinHandle<()>,
}

impl std::fmt::Debug for S3Listener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3Listener").field("address", &self.address).finish_non_exhaustive()
    }
}

/// The sessions of the open objects under `dir`, each page.
async fn sessions(client: &Client, dir: &str, page: usize) -> Result<Vec<String>, Fault> {
    let (mut out, mut token) = (Vec::new(), None);
    loop {
        let listing = client.list(dir, None, token.as_deref(), page).await?;
        out.extend(listing.objects.into_iter().filter_map(|o| o.key.strip_prefix(dir).map(str::to_string)));
        match listing.next {
            Some(next) => token = Some(next),
            None => return Ok(out),
        }
    }
}

/// The id of a session: 32 hex digits.
fn session_id(text: &str) -> bool {
    text.len() == 32 && text.bytes().all(|b| b.is_ascii_hexdigit())
}

/// What the task of a listener holds.
struct Door {
    client: Arc<Client>,
    prefix: String,
    acceptor: TlsAcceptor,
    alpn: &'static [u8],
    tuning: TuningRef,
    within: Duration,
    limit: Arc<Semaphore>,
    out: mpsc::Sender<Shaken>,
}

pub(super) async fn bind(
    s: &S3,
    client: Arc<Client>,
    prefix: &str,
    acceptor: TlsAcceptor,
) -> Result<S3Listener, CarrierError> {
    let dir = format!("{}open/", base(prefix));
    // One try: a refused key or a missing bucket is an error of the bind.
    let seen: HashSet<String> = sessions(&client, &dir, s.page).await.map_err(Fault::into_error)?.into_iter().collect();
    let address = if prefix.is_empty() { client.bucket.clone() } else { format!("{}/{prefix}", client.bucket) };
    let (out, results) = mpsc::channel(QUEUE);
    let door = Door {
        client,
        prefix: prefix.to_string(),
        acceptor,
        alpn: s.alpn,
        tuning: s.tuning(),
        within: s.handshake_timeout,
        limit: Arc::new(Semaphore::new(s.max_handshakes)),
        out,
    };
    let task = tokio::spawn(serve(door, dir, seen));
    Ok(S3Listener { address, results, task })
}

/// List the open objects, and start the handshake of each new session;
/// list again after a wait that doubles while no session comes.
async fn serve(door: Door, dir: String, mut seen: HashSet<String>) {
    let t = door.tuning.clone();
    let mut tasks = JoinSet::new();
    let mut wait = t.poll_min;
    loop {
        while tasks.try_join_next().is_some() {}
        let mut fresh = 0;
        match stream::again(&t, || sessions(&door.client, &dir, t.page)).await {
            Ok(found) => {
                for id in found {
                    if seen.contains(&id) || !session_id(&id) {
                        continue;
                    }
                    // A session past the most handshakes waits for the next
                    // listing.
                    let Ok(permit) = door.limit.clone().try_acquire_owned() else { continue };
                    seen.insert(id.clone());
                    fresh += 1;
                    tasks.spawn(handshake(take(&door), id, permit));
                }
            }
            Err(e) => {
                let _ = door.out.try_send(Err(e));
            }
        }
        wait = if fresh > 0 { t.poll_min } else { (wait * 2).min(t.poll_max) };
        tokio::time::sleep(wait).await;
    }
}

/// The parts of a door that one handshake needs.
struct Take {
    client: Arc<Client>,
    prefix: String,
    acceptor: TlsAcceptor,
    alpn: &'static [u8],
    tuning: TuningRef,
    within: Duration,
    out: mpsc::Sender<Shaken>,
}

fn take(door: &Door) -> Take {
    Take {
        client: door.client.clone(),
        prefix: door.prefix.clone(),
        acceptor: door.acceptor.clone(),
        alpn: door.alpn,
        tuning: door.tuning.clone(),
        within: door.within,
        out: door.out.clone(),
    }
}

async fn handshake(t: Take, id: String, permit: tokio::sync::OwnedSemaphorePermit) {
    let keys = Keys::of(&t.prefix, &id);
    if t.tuning.prune
        && let Err(e) = t.client.delete(&keys.open).await
    {
        tracing::debug!(error = ?e, "the s3 listener kept an open object");
    }
    let from = format!("the session {id} of {}", t.client.bucket);
    let io = stream::start(t.client.clone(), Dirs { out: keys.down, into: keys.up }, t.tuning.clone());
    let shaken = dgram_tls::accept_stream(NAME, io, t.acceptor, t.alpn, &from, t.within).await;
    drop(permit);
    if t.out.try_send(shaken).is_err() {
        tracing::debug!(session = %id, "a session of the s3 listener found the queue full");
    }
}

impl S3Listener {
    /// The next session of a client whose key is pinned, and that key. A
    /// client that failed its handshake is an error of one accept: the
    /// listener stays open.
    pub async fn accept_key(&mut self) -> Result<(BoxIo, PublicKey), CarrierError> {
        match self.results.recv().await {
            Some(result) => result,
            None => Err(CarrierError::new(
                NAME,
                CarrierErrorKind::Io(io::ErrorKind::BrokenPipe),
                "the task of the listener ended",
            )),
        }
    }
}

impl Listener for S3Listener {
    fn address(&self) -> String {
        self.address.clone()
    }

    fn accept(&mut self) -> Pending<'_, BoxIo> {
        Box::pin(async move { self.accept_key().await.map(|(io, _)| io) })
    }

    fn accept_peer(&mut self) -> Pending<'_, Accepted> {
        Box::pin(async move { self.accept_key().await.map(|(io, key)| Accepted { io, peer: Some(key) }) })
    }
}

impl Drop for S3Listener {
    fn drop(&mut self) {
        self.task.abort();
    }
}
