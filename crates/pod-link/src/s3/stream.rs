//! The byte stream of one session of the s3 carrier: each direction is a
//! run of objects `DIR/SESSION/SEQ`, SEQ in 16 hex digits from 0, so a
//! listing gives them in order. The writer puts each batch of the link's
//! bytes as the next object, at most `in_flight` at once, and an empty
//! object at the end. The reader lists the keys after the last one it
//! read, reads the run that follows it with no gap, `in_flight` at once,
//! and gives the bytes in order; it polls after a wait of `poll_min`
//! doubled up to `poll_max` while no object comes.

use std::io;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, DuplexStream};
use tokio::sync::Notify;
use tokio::task::JoinSet;
use tokio::time::Instant;

use super::Tuning;
use super::client::{Client, Fault};
use super::xml::Object;
use crate::carrier::{CarrierError, CarrierErrorKind};
use crate::pipes::{Ends, Pipes, State, pipes, until};

/// The wait after which a writer puts the bytes it holds, short of a whole
/// object.
const LINGER: Duration = Duration::from_millis(5);

/// The key of the object `seq` under `dir` (with its `/` at the end).
pub(super) fn key(dir: &str, seq: u64) -> String {
    format!("{dir}{seq:016x}")
}

/// The keys of one end: the objects that it writes and the ones it reads.
pub(super) struct Dirs {
    pub out: String,
    pub into: String,
}

/// The tuning that the tasks of a session share.
pub(crate) type TuningRef = Arc<Tuning>;

/// The keys of a session under a prefix: the open object and the two
/// directions, each with its `/` at the end.
pub(super) struct Keys {
    pub open: String,
    pub up: String,
    pub down: String,
}

/// The base of the keys of a prefix: none, or the prefix and a `/`.
pub(super) fn base(prefix: &str) -> String {
    if prefix.is_empty() { String::new() } else { format!("{prefix}/") }
}

impl Keys {
    pub fn of(prefix: &str, session: &str) -> Keys {
        let base = base(prefix);
        Keys {
            open: format!("{base}open/{session}"),
            up: format!("{base}up/{session}/"),
            down: format!("{base}down/{session}/"),
        }
    }
}

/// The byte stream of a session over `client`.
pub(super) fn start(client: Arc<Client>, dirs: Dirs, tuning: TuningRef) -> Pipes {
    let ends = Ends::new();
    let (io, far) = pipes(tuning.object, ends.clone());
    let kick = Arc::new(Notify::new());
    tokio::spawn(writer(client.clone(), dirs.out, far.to_peer, ends.clone(), tuning.clone(), kick.clone()));
    tokio::spawn(reader(client, dirs.into, far.from_peer, ends, tuning, kick));
    io
}

fn fail(ends: &Ends, e: &CarrierError) {
    let kind = match e.kind {
        CarrierErrorKind::Refused | CarrierErrorKind::KeyRefused => io::ErrorKind::PermissionDenied,
        CarrierErrorKind::NotFound => io::ErrorKind::NotFound,
        CarrierErrorKind::Io(kind) => kind,
        _ => io::ErrorKind::Other,
    };
    ends.fail(kind, e.to_string());
}

/// Run `call` again after each failure that asks for it, with the backoff
/// of the tuning, until it fails for `idle`.
pub(super) async fn again<T, F, Fut>(tuning: &Tuning, mut call: F) -> Result<T, CarrierError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, Fault>>,
{
    let (since, mut wait) = (Instant::now(), tuning.poll_min);
    loop {
        match call().await {
            Ok(v) => return Ok(v),
            Err(Fault::Fatal(e)) => return Err(e),
            Err(Fault::Again(e)) if since.elapsed() >= tuning.idle => {
                let kind = CarrierErrorKind::Io(io::ErrorKind::TimedOut);
                return Err(CarrierError::new(
                    e.carrier,
                    kind,
                    format!("the bucket failed for {:?}: {e}", tuning.idle),
                ));
            }
            Err(Fault::Again(e)) => {
                tracing::debug!(error = %e, "a call of the s3 carrier goes again");
                tokio::time::sleep(wait).await;
                wait = (wait * 2).min(tuning.poll_max);
            }
        }
    }
}

/// The bytes of this end's objects in the bucket, within the budget:
/// `held` counts each byte put, and a listing of the direction counts
/// again what the peer did not remove yet, with the PUTs in flight
/// (`flying`), which no listing shows yet.
struct Budget {
    held: u64,
    flying: u64,
    warned: bool,
}

impl Budget {
    async fn room(&mut self, client: &Client, dir: &str, n: u64, t: &Tuning) -> Result<(), CarrierError> {
        let since = Instant::now();
        while self.held + n > t.budget {
            self.held = again(t, || count(client, dir, t.page)).await? + self.flying;
            if self.held + n <= t.budget {
                break;
            }
            if since.elapsed() >= t.idle {
                let text = format!("the budget of {} bytes of {dir} is spent: the peer removes no object", t.budget);
                return Err(CarrierError::new(client.name, CarrierErrorKind::Io(io::ErrorKind::StorageFull), text));
            }
            tokio::time::sleep(t.poll_max).await;
        }
        self.held += n;
        self.flying += n;
        let high = self.held >= t.budget / 5 * 4;
        if high && !self.warned {
            tracing::warn!(dir, held = self.held, budget = t.budget, "the objects of a link hold 80 % of their budget");
        }
        self.warned = high;
        Ok(())
    }
}

/// The bytes of the objects under `dir`.
async fn count(client: &Client, dir: &str, page: usize) -> Result<u64, Fault> {
    let (mut total, mut token) = (0, None);
    loop {
        let listing = client.list(dir, None, token.as_deref(), page).await?;
        total += listing.objects.iter().map(|o| o.size).sum::<u64>();
        match listing.next {
            Some(next) => token = Some(next),
            None => return Ok(total),
        }
    }
}

/// Put the link's bytes as objects under `dir`; the end of the bytes is an
/// empty object.
async fn writer(
    client: Arc<Client>,
    dir: String,
    mut from: DuplexStream,
    ends: Arc<Ends>,
    t: Arc<Tuning>,
    kick: Arc<Notify>,
) {
    let mut state = ends.watch();
    let (mut seq, mut held, mut eof) = (0u64, Vec::new(), false);
    let mut budget = Budget { held: 0, flying: 0, warned: false };
    let mut puts = JoinSet::new();
    let mut buf = vec![0u8; t.object];
    let mut due = None;
    loop {
        let full = held.len() >= t.object || (eof && !held.is_empty()) || due.is_some_and(|at| Instant::now() >= at);
        if full && puts.len() < t.in_flight {
            let body = std::mem::take(&mut held);
            if let Err(e) = budget.room(&client, &dir, body.len() as u64, &t).await {
                return fail(&ends, &e);
            }
            let (c, k, tuning) = (client.clone(), key(&dir, seq), t.clone());
            let n = body.len() as u64;
            puts.spawn(async move { again(&tuning, || c.put(&k, &body)).await.map(|()| n) });
            (seq, due) = (seq + 1, None);
            continue;
        }
        if eof && held.is_empty() && seq != u64::MAX {
            let (c, k, tuning) = (client.clone(), key(&dir, seq), t.clone());
            puts.spawn(async move { again(&tuning, || c.put(&k, &[])).await.map(|()| 0) });
            seq = u64::MAX;
        }
        if seq == u64::MAX && puts.is_empty() {
            return;
        }
        let room = t.object.saturating_sub(held.len());
        tokio::select! {
            done = puts.join_next(), if !puts.is_empty() => match done {
                Some(Ok(Ok(n))) => {
                    budget.flying -= n;
                    kick.notify_one();
                }
                Some(Ok(Err(e))) => return fail(&ends, &e),
                Some(Err(e)) => return ends.fail(io::ErrorKind::Other, format!("a PUT of the s3 carrier failed: {e}")),
                None => {}
            },
            read = from.read(&mut buf[..room]), if !eof && room > 0 && puts.len() < t.in_flight => match read {
                Ok(0) | Err(_) => eof = true,
                Ok(n) => {
                    held.extend_from_slice(&buf[..n]);
                    due = due.or(Some(Instant::now() + LINGER));
                }
            },
            () = tokio::time::sleep_until(due.unwrap_or_else(Instant::now)), if due.is_some() && puts.len() < t.in_flight => {}
            () = until(&mut state, &[State::Failed]) => return,
        }
    }
}

/// The run of objects from `next` with no gap, out of a listing.
fn run(dir: &str, next: u64, objects: Vec<Object>) -> Vec<Object> {
    (next..)
        .zip(objects)
        .take_while(|(want, o)| o.key.strip_prefix(dir).and_then(|s| u64::from_str_radix(s, 16).ok()) == Some(*want))
        .map(|(_, o)| o)
        .collect()
}

/// Read the objects under `dir` in order into the link; the empty object
/// is the end of its bytes. A drop of the link ends the reader.
async fn reader(
    client: Arc<Client>,
    dir: String,
    mut to: DuplexStream,
    ends: Arc<Ends>,
    t: Arc<Tuning>,
    kick: Arc<Notify>,
) {
    let mut state = ends.watch();
    let (mut next, mut wait) = (0u64, t.poll_min);
    loop {
        let after = next.checked_sub(1).map(|seq| key(&dir, seq));
        let listed = tokio::select! {
            listed = again(&t, || client.list(&dir, after.as_deref(), None, t.page)) => listed,
            () = until(&mut state, &[State::Failed, State::Gone]) => return,
        };
        let objects = match listed {
            Ok(listing) => run(&dir, next, listing.objects),
            Err(e) => return fail(&ends, &e),
        };
        if objects.is_empty() {
            tokio::select! {
                () = tokio::time::sleep(wait) => wait = (wait * 2).min(t.poll_max),
                () = kick.notified() => wait = t.poll_min,
                () = until(&mut state, &[State::Failed, State::Gone]) => return,
            }
            continue;
        }
        wait = t.poll_min;
        for batch in objects.chunks(t.in_flight) {
            let mut gets = JoinSet::new();
            for (i, object) in batch.iter().cloned().enumerate() {
                let (c, tuning) = (client.clone(), t.clone());
                gets.spawn(
                    async move { (i, again(&tuning, || c.get(&object.key, &object.etag, tuning.object)).await) },
                );
            }
            let mut bodies = vec![None; batch.len()];
            while let Some(done) = gets.join_next().await {
                match done {
                    Ok((i, Ok(Some(body)))) => bodies[i] = Some(body),
                    Ok((_, Ok(None))) => {
                        let text = format!("an object of {dir} was gone before its read");
                        return ends.fail(io::ErrorKind::UnexpectedEof, text);
                    }
                    Ok((_, Err(e))) => return fail(&ends, &e),
                    Err(e) => return ends.fail(io::ErrorKind::Other, format!("a GET of the s3 carrier failed: {e}")),
                }
            }
            for (object, body) in batch.iter().zip(bodies.into_iter().flatten()) {
                if t.prune {
                    let (c, k) = (client.clone(), object.key.clone());
                    tokio::spawn(async move {
                        if let Err(e) = c.delete(&k).await {
                            tracing::debug!(error = ?e, "the s3 carrier kept an object it read");
                        }
                    });
                }
                next += 1;
                if body.is_empty() {
                    let _ = to.shutdown().await;
                    return;
                }
                if to.write_all(&body).await.is_err() {
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_run_stops_at_its_first_gap() {
        let o = |seq: u64| Object { key: key("p/up/s/", seq), etag: String::new(), size: 1 };
        let keys = |v: Vec<Object>| v.into_iter().map(|o| o.key).collect::<Vec<_>>();
        let got = keys(run("p/up/s/", 3, vec![o(3), o(4), o(6)]));
        assert_eq!(got, vec![key("p/up/s/", 3), key("p/up/s/", 4)], "the run stops before the gap at 5");
        assert!(run("p/up/s/", 3, vec![o(4), o(5)]).is_empty(), "the object 3 is not there yet");
        assert_eq!(key("d/", 255), "d/00000000000000ff");
    }
}
