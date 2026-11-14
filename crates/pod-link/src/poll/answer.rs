//! The answers of a listener of the poll carriers to each request of a
//! lane: the open, the bytes up, and the bytes down in each form.

use std::io;

use pod_identity::PublicKey;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt as _};
use tokio::time::{Instant, timeout};

use super::listen::{Counters, Serving};
use super::session::{Opened, Visit, Waited};
use super::wire::{self, Body, Conn, EVENT, FIN_EVENT, Head, LAST_CHUNK, PING};
use super::{BATCH, HOLD, MAX_HOLD, MIN_HOLD, PING_EVERY};

/// The wait that an open answered 429 asks for, in seconds.
const RETRY_AFTER: u64 = 1;

/// The most bytes of a body that a listener reads at once.
const PART: usize = 64 << 10;

/// Answer `status` with `body`. False when the connection failed.
async fn reply<S: AsyncRead + AsyncWrite + Unpin>(
    conn: &mut Conn<S>,
    status: u16,
    fields: &[(&str, String)],
    body: &[u8],
) -> bool {
    let mut out = wire::answer(status, fields, Body::Length(body.len())).into_bytes();
    out.extend_from_slice(body);
    conn.send(&out).await.is_ok()
}

/// A refusal that closes the connection.
async fn close<S: AsyncRead + AsyncWrite + Unpin>(conn: &mut Conn<S>, status: u16) -> bool {
    reply(conn, status, &[("Connection", "close".into())], &[]).await;
    false
}

fn number(query: &str, name: &str) -> Option<u64> {
    wire::param(query, name)?.parse().ok()
}

/// Answer one request. False when the connection must close.
pub(super) async fn handle<S: AsyncRead + AsyncWrite + Unpin>(
    conn: &mut Conn<S>,
    head: &Head,
    key: &PublicKey,
    s: &Serving,
) -> bool {
    let Some((method, target)) = head.request() else { return close(conn, 400).await };
    if head.chunked() {
        return close(conn, 411).await;
    }
    let len = match head.length() {
        Ok(len) => len.unwrap_or(0),
        Err(_) => return close(conn, 400).await,
    };
    if len > BATCH {
        return close(conn, 413).await;
    }
    let (method, (path, query)) = (method.to_string(), wire::split(target));
    let (path, query) = (path.to_string(), query.to_string());
    let lane = path.rsplit('/').next().unwrap_or_default();
    // The body up goes into the link as it comes; each other body is read
    // and dropped, so no request keeps a whole body.
    let streamed = (method.as_str(), lane) == ("POST", "up");
    if !streamed && !skip(conn, len, s).await {
        return false;
    }
    let id = wire::param(&query, "s").filter(|v| v.len() == 32).and_then(|v| u128::from_str_radix(v, 16).ok());
    let Some(id) = id else {
        return (!streamed || skip(conn, len, s).await) && reply(conn, 404, &[], &[]).await;
    };
    if (method.as_str(), lane) == ("POST", "open") {
        return open(conn, id, key, s).await;
    }
    let Some(visit) = s.table.visit(id, key) else {
        return (!streamed || skip(conn, len, s).await) && reply(conn, 404, &[], &[]).await;
    };
    match (method.as_str(), lane) {
        ("POST", "up") => up(conn, &visit, id, &query, len, s).await,
        ("POST", "down") => {
            Counters::add(&s.stats.polls, 1);
            let hold = number(&query, "hold").map_or(HOLD, std::time::Duration::from_secs);
            poll(conn, &visit, id, &query, Some(hold.clamp(MIN_HOLD, MAX_HOLD)), s).await
        }
        ("GET", "out") => {
            Counters::add(&s.stats.shorts, 1);
            poll(conn, &visit, id, &query, None, s).await
        }
        ("GET", "push") => push(conn, &visit, id, &query, head, s).await,
        _ => reply(conn, 404, &[], &[]).await,
    }
}

async fn open<S: AsyncRead + AsyncWrite + Unpin>(conn: &mut Conn<S>, id: u128, key: &PublicKey, s: &Serving) -> bool {
    let busy = |s: &Serving| {
        Counters::add(&s.stats.busy, 1);
        [("Retry-After", RETRY_AFTER.to_string())]
    };
    match s.table.open(id, *key) {
        Opened::Again => reply(conn, 201, &[], &[]).await,
        Opened::Stranger => reply(conn, 404, &[], &[]).await,
        Opened::Busy => reply(conn, 429, &busy(s), &[]).await,
        Opened::New(io) => match s.out.try_send(Ok((Box::new(io), *key))) {
            Ok(()) => {
                Counters::add(&s.stats.sessions, 1);
                reply(conn, 201, &[], &[]).await
            }
            Err(_) => {
                s.table.end(id, io::ErrorKind::ConnectionRefused, "no accept took the session");
                reply(conn, 429, &busy(s), &[]).await
            }
        },
    }
}

/// Read and drop a body of `len` bytes within the answer time. False when
/// the connection failed.
async fn skip<S: AsyncRead + AsyncWrite + Unpin>(conn: &mut Conn<S>, len: usize, s: &Serving) -> bool {
    let read = async {
        let mut left = len;
        while left > 0 {
            left -= conn.part(left.min(PART)).await?.len();
        }
        Ok::<_, io::Error>(())
    };
    matches!(timeout(s.answer_timeout, read).await, Ok(Ok(())))
}

/// The bytes up: each part of the body past the next offset goes into the
/// link as it comes, the part before it came already. A cut in the body
/// keeps the part that went in: the POST again skips it.
async fn up<S: AsyncRead + AsyncWrite + Unpin>(
    conn: &mut Conn<S>,
    visit: &Visit,
    id: u128,
    query: &str,
    len: usize,
    s: &Serving,
) -> bool {
    let session = visit.session();
    let (Some(seq), Some(ack)) = (number(query, "seq"), number(query, "ack")) else {
        return close(conn, 400).await;
    };
    let fin = wire::param(query, "fin") == Some("1");
    let end = seq + len as u64;
    let up = session.up.lock().await;
    if seq > up.next || (up.pipe.is_none() && end > up.next) || session.down.ack(ack).is_err() {
        drop(up);
        s.table.end(id, io::ErrorKind::InvalidData, "the dialer sent an offset out of order");
        return close(conn, 409).await;
    }
    drop(up);
    let read = async {
        // The next offset only grows, so each part starts at or below it.
        let mut at = seq;
        while at < end {
            let part = conn.part(((end - at) as usize).min(PART)).await?;
            let to = at + part.len() as u64;
            let mut up = session.up.lock().await;
            let skip = up.next.saturating_sub(at).min(part.len() as u64);
            Counters::add(&s.stats.duplicate, skip);
            if to > up.next {
                if let Some(pipe) = up.pipe.as_mut()
                    && pipe.write_all(&part[skip as usize..]).await.is_err()
                {
                    // The link of this side is gone: its end goes down.
                    up.pipe = None;
                }
                up.next = to;
            }
            at = to;
        }
        Ok::<_, io::Error>(())
    };
    if !matches!(timeout(s.answer_timeout, read).await, Ok(Ok(()))) {
        return false;
    }
    let mut up = session.up.lock().await;
    if fin
        && end == up.next
        && let Some(mut pipe) = up.pipe.take()
    {
        let _ = pipe.shutdown().await;
    }
    let next = up.next;
    drop(up);
    reply(conn, 202, &[("Pod-Ack", next.to_string())], &[]).await
}

/// A long poll (held up to `hold`) or a simplex poll (at once).
async fn poll<S: AsyncRead + AsyncWrite + Unpin>(
    conn: &mut Conn<S>,
    visit: &Visit,
    id: u128,
    query: &str,
    hold: Option<std::time::Duration>,
    s: &Serving,
) -> bool {
    let session = visit.session();
    let Some(since) = number(query, "since") else { return close(conn, 400).await };
    match session.down.ack(since) {
        Ok(true) => {}
        // A request that a cut held back: the dialer asked again.
        Ok(false) => return reply(conn, if hold.is_some() { 200 } else { 204 }, &[], &[]).await,
        Err(()) => {
            s.table.end(id, io::ErrorKind::InvalidData, "the dialer asked for an offset past the bytes sent");
            return reply(conn, 409, &[], &[]).await;
        }
    }
    let turn = session.down.turn();
    if let Some(hold) = hold {
        let mut state = session.ends.watch();
        session.down.wait(since, turn, Some(Instant::now() + hold), &mut state).await;
    }
    let max = if hold.is_some() { BATCH } else { super::SIMPLEX_BATCH };
    let slice = session.down.slice(since, max);
    Counters::add(&s.stats.resent, slice.resent);
    let fin = if slice.fin { vec![("Pod-Fin", "1".to_string())] } else { Vec::new() };
    let status = if hold.is_none() && slice.bytes.is_empty() && !slice.fin { 204 } else { 200 };
    reply(conn, status, &fin, &slice.bytes).await
}

/// A push of the bytes down as they come: events of SSE, or raw chunks.
async fn push<S: AsyncRead + AsyncWrite + Unpin>(
    conn: &mut Conn<S>,
    visit: &Visit,
    id: u128,
    query: &str,
    head: &Head,
    s: &Serving,
) -> bool {
    if !s.push {
        Counters::add(&s.stats.no_push, 1);
        return reply(conn, 406, &[], &[]).await;
    }
    Counters::add(&s.stats.pushes, 1);
    let session = visit.session();
    let Some(since) = number(query, "since") else { return close(conn, 400).await };
    match session.down.ack(since) {
        Ok(true) => {}
        // A request that a cut held back: no one reads its answer.
        Ok(false) => return false,
        Err(()) => {
            s.table.end(id, io::ErrorKind::InvalidData, "the dialer asked for an offset past the bytes sent");
            return reply(conn, 409, &[], &[]).await;
        }
    }
    let turn = session.down.turn();
    let sse = head.field("accept").is_some_and(|v| v.contains("text/event-stream"));
    let kind = if sse { "text/event-stream" } else { "application/octet-stream" };
    let mut out = wire::answer(200, &[], Body::Chunked(kind)).into_bytes();
    if sse {
        out.extend_from_slice(&wire::chunk(PING));
    }
    if conn.send(&out).await.is_err() {
        return false;
    }
    let (mut pos, mut state) = (since, session.ends.watch());
    loop {
        let deadline = sse.then(|| Instant::now() + PING_EVERY);
        match session.down.wait(pos, turn, deadline, &mut state).await {
            // A cut with no last chunk: the dialer asks again.
            Waited::Superseded | Waited::Ended => return false,
            Waited::Timeout => {
                if conn.send(&wire::chunk(PING)).await.is_err() {
                    return false;
                }
                continue;
            }
            Waited::Ready => {}
        }
        let slice = session.down.slice(pos, BATCH);
        Counters::add(&s.stats.resent, slice.resent);
        let mut out = Vec::new();
        if !slice.bytes.is_empty() {
            let data = if sse {
                let mut events = Vec::new();
                let mut at = pos;
                for piece in slice.bytes.chunks(EVENT) {
                    at += piece.len() as u64;
                    events.extend_from_slice(&wire::event(at, piece));
                }
                events
            } else {
                slice.bytes.clone()
            };
            out.extend_from_slice(&wire::chunk(&data));
            pos += slice.bytes.len() as u64;
        }
        if slice.fin {
            if sse {
                out.extend_from_slice(&wire::chunk(FIN_EVENT));
            }
            out.extend_from_slice(LAST_CHUNK);
        }
        if conn.send(&out).await.is_err() || slice.fin {
            return false;
        }
    }
}
