//! A stand-in of the relay role's HTTP road for links of the resumable
//! layer, in memory: each dial of the road is a pipe whose other end this
//! role serves. An open of a layer's link (`OPEN_LAYER`, `ONE_LAYER`) with
//! the token makes a session of the road whose bytes are one link of a far
//! end of the layer, which keeps its sessions as podssh's role does; the
//! target of a new session echoes each byte. The batches up go through
//! `http_road::window::Up`, the role's window. `cut` forgets each session
//! of the road, as a role that lost them: each request of one then gets
//! `404`, and the client loses the link.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pod_relay::http_road::answer::{Body, Framing};
use pod_relay::http_road::client::Road;
use pod_relay::http_road::conn::{BoxIo, Dial, Dialing};
use pod_relay::http_road::window::{Refusal, Stored, Up};
use pod_relay::http_road::{
    ACK, CLOSE, Kind, MARK, OFFSET, REFUSE, Route, SEQ, TOTAL, close_value, layer_route, query, route,
};
use pod_session::keep::Keeper;
use pod_session::{OsEntropy, Role as LayerRole, Settings};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::{Notify, mpsc, watch};

pub const TOKEN: &str = "token-of-the-test";
const PIPE: usize = 256 * 1024;
const DOWN_MAX: usize = 1 << 20;

/// The far side of one session of the road: its window up, its bytes down
/// that no request acknowledged, and its end.
struct Session {
    key: String,
    up: Mutex<Up>,
    to_link: mpsc::UnboundedSender<Option<Vec<u8>>>,
    /// The bytes down from `base`, and the end of the link's bytes.
    down: Mutex<(u64, Vec<u8>, bool)>,
    more: Notify,
}

/// The stand-in role.
pub struct LayerRoad {
    keeper: Arc<Keeper<DuplexStream>>,
    sessions: Mutex<HashMap<String, Arc<Session>>>,
    next: AtomicU64,
    /// The opens of a layer's link, by its form: the one-POST form and the
    /// others.
    pub opens: AtomicU64,
    pub ones: AtomicU64,
    /// Each cut, for the requests of the one-POST form.
    cuts: watch::Sender<u64>,
}

impl LayerRoad {
    pub fn new() -> Arc<LayerRoad> {
        Arc::new(LayerRoad {
            keeper: Arc::new(Keeper::new(Duration::from_secs(600))),
            sessions: Mutex::default(),
            next: AtomicU64::new(1),
            opens: AtomicU64::new(0),
            ones: AtomicU64::new(0),
            cuts: watch::channel(0).0,
        })
    }

    /// The road to this role.
    pub fn road(self: &Arc<Self>) -> Road {
        let me = self.clone();
        let dial: Dial = Arc::new(move || -> Dialing {
            let me = me.clone();
            Box::pin(async move {
                let (ours, theirs) = tokio::io::duplex(PIPE);
                tokio::spawn(me.serve(theirs));
                Ok(Box::new(ours) as BoxIo)
            })
        });
        Road {
            dial,
            dial_alpn: None,
            authority: "relay.test".into(),
            user_agent: "pod-relay/test".into(),
            forms: None,
            learned: Arc::default(),
            extra: Ok(pod_ws::Extra::default()),
        }
    }

    /// Forget each session of the road, and end each request of the
    /// one-POST form with no last chunk; the sessions of the layer stay
    /// kept.
    pub fn cut(&self) {
        self.sessions.lock().unwrap().clear();
        self.cuts.send_modify(|n| *n += 1);
    }

    /// A far end of the layer on a new link: the role's end of the link.
    fn far_link(&self) -> DuplexStream {
        let (ours, link) = tokio::io::duplex(PIPE);
        let keeper = self.keeper.clone();
        tokio::spawn(async move {
            let accepted =
                pod_session::far::accept(link, LayerRole::SERVE, Settings::default(), &keeper.sessions, &mut OsEntropy)
                    .await;
            let Ok(accepted) = accepted else { return };
            if accepted.established().resumed {
                let _ = keeper.run_resumed(accepted).await;
                return;
            }
            let (target, echo) = tokio::io::duplex(PIPE);
            tokio::spawn(async move {
                let (mut r, mut w) = tokio::io::split(echo);
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
            keeper.run_new(accepted, target).await;
        });
        ours
    }

    /// A new session of the road on a new link: its id and its answer.
    fn open(&self) -> Vec<u8> {
        let n = self.next.fetch_add(1, Ordering::SeqCst);
        let (id, key) = (format!("{n:032x}"), format!("{n:043}"));
        let (to_link, mut rx) = mpsc::unbounded_channel::<Option<Vec<u8>>>();
        let session = Arc::new(Session {
            key: key.clone(),
            up: Mutex::new(Up::new(8)),
            to_link,
            down: Mutex::new((0, Vec::new(), false)),
            more: Notify::new(),
        });
        let (mut r, mut w) = tokio::io::split(self.far_link());
        // The batches up into the link, in order; `None` is its end.
        tokio::spawn(async move {
            while let Some(Some(batch)) = rx.recv().await {
                if w.write_all(&batch).await.is_err() {
                    return;
                }
            }
            let _ = w.shutdown().await;
        });
        // The link's bytes into the window down.
        let s = session.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                let n = r.read(&mut buf).await.unwrap_or(0);
                {
                    let mut down = s.down.lock().unwrap();
                    if n == 0 {
                        down.2 = true;
                    } else {
                        down.1.extend_from_slice(&buf[..n]);
                    }
                }
                s.more.notify_waiters();
                if n == 0 {
                    return;
                }
            }
        });
        self.sessions.lock().unwrap().insert(id.clone(), session);
        let doc = format!(r#"{{"session":"{id}","key":"{key}","down_max":{DOWN_MAX}}}"#);
        answer(200, &[], doc.as_bytes())
    }

    async fn serve(self: Arc<Self>, mut io: DuplexStream) {
        let mut buf = Vec::new();
        while let Some((target, headers, body)) = read_request(&mut io, &mut buf).await {
            let path = target.split('?').next().unwrap_or_default().to_string();
            let token = header(&headers, "x-relay-token");
            if layer_route(&path) == Some(Route::One) {
                return self.one(io, buf, token).await;
            }
            let reply = match (layer_route(&path), route(&path)) {
                (Some(Route::Open), _) if token.as_deref() == Some(TOKEN) => {
                    self.opens.fetch_add(1, Ordering::SeqCst);
                    self.open()
                }
                (Some(Route::Open), _) => answer(403, &[], b"layer: missing or wrong token"),
                (_, Some(Route::Session(id, kind))) => {
                    let found = self.sessions.lock().unwrap().get(&id).cloned();
                    match found.filter(|s| header(&headers, "x-session-key").as_deref() == Some(s.key.as_str())) {
                        Some(s) => s.answer(kind, &target, body).await,
                        None => refusal(Refusal::UnknownSession, "http: no such session"),
                    }
                }
                _ => answer(404, &[], b"not found"),
            };
            if io.write_all(&reply).await.is_err() {
                return;
            }
        }
    }

    /// The one-POST form of a layer's link: the mark, then each chunk up
    /// into the link and the link's bytes down in chunks; the last chunk at
    /// the end of the link.
    async fn one(self: Arc<Self>, io: DuplexStream, mut buf: Vec<u8>, token: Option<String>) {
        let (mut from, mut to) = tokio::io::split(io);
        if token.as_deref() != Some(TOKEN) {
            let _ = to.write_all(&answer(403, &[], b"layer: missing or wrong token")).await;
            return;
        }
        self.ones.fetch_add(1, Ordering::SeqCst);
        let mut cut = self.cuts.subscribe();
        cut.mark_unchanged();
        let (mut r, mut w) = tokio::io::split(self.far_link());
        let head = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n";
        let mut first = head.as_bytes().to_vec();
        first.extend_from_slice(&chunk(MARK));
        if to.write_all(&first).await.is_err() {
            return;
        }
        let reader = tokio::spawn(async move {
            let mut body = Body::new(&mut from, &mut buf, Framing::Chunked);
            while let Ok(Some(bytes)) = body.next().await {
                if w.write_all(&bytes).await.is_err() {
                    return;
                }
            }
            let _ = w.shutdown().await;
        });
        let mut piece = vec![0u8; 64 * 1024];
        loop {
            let read = tokio::select! {
                read = r.read(&mut piece) => read,
                _ = cut.changed() => {
                    // A cut: no last chunk, and the connection ends.
                    reader.abort();
                    return;
                }
            };
            match read {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if to.write_all(&chunk(&piece[..n])).await.is_err() || to.flush().await.is_err() {
                        return;
                    }
                }
            }
        }
        let _ = to.write_all(b"0\r\n\r\n").await;
    }
}

impl Session {
    async fn answer(&self, kind: Kind, target: &str, body: Vec<u8>) -> Vec<u8> {
        let q = query(target);
        match kind {
            Kind::Up => match q.seq {
                Some(seq) => self.up(seq, body, q.total.filter(|_| q.fin)),
                None => answer(400, &[], b"http: up takes seq"),
            },
            Kind::Down => self.down(q.at.unwrap_or(0), q.wait_ms.unwrap_or(0)).await,
            Kind::Exchange => {
                let at = q.at.unwrap_or(0);
                if let Some(seq) = q.seq {
                    let stored = self.up(seq, body, q.total.filter(|_| q.fin));
                    if !stored.starts_with(b"HTTP/1.1 204") {
                        return stored;
                    }
                    let mut reply = self.down(at, 0).await;
                    let line = format!("{SEQ}: {seq}\r\n");
                    let end = reply.windows(2).position(|w| w == b"\r\n").unwrap_or(0) + 2;
                    reply.splice(end..end, line.into_bytes());
                    return reply;
                }
                self.down(at, q.wait_ms.unwrap_or(0)).await
            }
            Kind::Close => {
                let _ = self.to_link.send(None);
                answer(204, &[], b"")
            }
        }
    }

    fn up(&self, seq: u64, body: Vec<u8>, total: Option<u64>) -> Vec<u8> {
        let mut up = self.up.lock().unwrap();
        let acked = match up.store(seq, body, total) {
            Stored::Taken(n) | Stored::Again(n) => n,
            Stored::Full => return refusal(Refusal::Full, "http: full"),
            Stored::Conflict(next) => return answer(409, &[], format!("http: next is {next}").as_bytes()),
            Stored::Mismatch { .. } => return answer(410, &[(CLOSE, close_value(1002, "count mismatch"))], b""),
        };
        while let Some(batch) = up.take() {
            let _ = self.to_link.send(Some(batch));
        }
        if up.done() {
            let _ = self.to_link.send(None);
        }
        answer(204, &[(SEQ, acked.to_string()), (ACK, up.next().to_string())], b"")
    }

    async fn down(&self, at: u64, wait_ms: u64) -> Vec<u8> {
        let deadline = tokio::time::Instant::now() + Duration::from_millis(wait_ms.min(2000));
        loop {
            let woken = self.more.notified();
            {
                let mut guard = self.down.lock().unwrap();
                let (base, bytes, ended) = &mut *guard;
                let ended = *ended;
                let end = *base + bytes.len() as u64;
                if at < *base || at > end {
                    return answer(409, &[], b"http: an offset outside the window");
                }
                // Each byte before `at` came: the role forgets them.
                bytes.drain(..(at - *base) as usize);
                *base = at;
                if !bytes.is_empty() {
                    let n = bytes.len().min(DOWN_MAX);
                    return answer(200, &[(OFFSET, at.to_string())], &bytes[..n]);
                }
                if ended {
                    let headers = [(CLOSE, close_value(1000, "link closed")), (TOTAL, at.to_string())];
                    return answer(410, &headers, b"http: the session ended");
                }
            }
            if tokio::time::timeout_at(deadline, woken).await.is_err() {
                return answer(204, &[(OFFSET, at.to_string())], b"");
            }
        }
    }
}

fn header(headers: &[(String, String)], name: &str) -> Option<String> {
    headers.iter().find(|(n, _)| n == name).map(|(_, v)| v.clone())
}

fn chunk(bytes: &[u8]) -> Vec<u8> {
    let mut out = format!("{:x}\r\n", bytes.len()).into_bytes();
    out.extend_from_slice(bytes);
    out.extend_from_slice(b"\r\n");
    out
}

fn answer(status: u16, headers: &[(&str, String)], body: &[u8]) -> Vec<u8> {
    let mut out = format!("HTTP/1.1 {status} X\r\n");
    for (name, value) in headers {
        out.push_str(&format!("{name}: {value}\r\n"));
    }
    if status != 204 {
        out.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    out.push_str("\r\n");
    let mut out = out.into_bytes();
    out.extend_from_slice(body);
    out
}

fn refusal(reason: Refusal, words: &str) -> Vec<u8> {
    let mut headers = vec![(REFUSE, reason.word().to_string())];
    if reason == Refusal::Full {
        headers.push(("Retry-After", "1".to_string()));
    }
    answer(reason.status(), &headers, format!("{words}\n").as_bytes())
}

async fn read_request(io: &mut DuplexStream, buf: &mut Vec<u8>) -> Option<(String, Vec<(String, String)>, Vec<u8>)> {
    let mut piece = vec![0u8; 64 * 1024];
    let end = loop {
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break end + 4;
        }
        let n = io.read(&mut piece).await.ok().filter(|n| *n > 0)?;
        buf.extend_from_slice(&piece[..n]);
    };
    let text = String::from_utf8(buf.drain(..end).collect()).ok()?;
    let mut lines = text.split("\r\n");
    let target = lines.next()?.split(' ').nth(1)?.to_string();
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(n, v)| (n.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    let chunked = header(&headers, "transfer-encoding").is_some_and(|v| v.eq_ignore_ascii_case("chunked"));
    if chunked {
        return Some((target, headers, Vec::new()));
    }
    let length: usize = header(&headers, "content-length").map_or(Some(0), |v| v.parse().ok())?;
    while buf.len() < length {
        let n = io.read(&mut piece).await.ok().filter(|n| *n > 0)?;
        buf.extend_from_slice(&piece[..n]);
    }
    let body = buf.drain(..length).collect();
    Some((target, headers, body))
}
