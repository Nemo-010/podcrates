//! A stand-in ntfy server of the tests, in Rust, on the loopback: HTTP/1.1
//! with no TLS here, HTTP/2 and HTTP/1.1 behind TLS in `ntfy_tls.rs`. It
//! keeps each message, as ntfy does with its cache: a POST to `/TOPIC`
//! stores the body with an id of 12 letters and digits and the time; a
//! `GET /TOPIC/json?poll=1&since=X` gives the messages of the topic since
//! X (a time: those of that second and later; an id: those after it), one
//! JSON object a line; a `GET /TOPIC/json?since=X` with no `poll` is a
//! stream (HTTP/2 alone): its `open` line, the kept messages, then each new
//! one. A body of 4,096 bytes or more gets `413`, as a server with no
//! attachments refuses it. A test reads each request, plants a message as
//! of another end, and gives a [`Script`] of refusals.

use std::sync::{Arc, Mutex};

use pod_proxy::http::request::{self, read_request};
use pod_wormhole::ntfy::Point;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};
use tokio::task::JoinHandle;

/// How a stand-in answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Script {
    /// As a public server that takes the messages of the pairing.
    Takes,
    /// Each request gets this status, with these words in ntfy's JSON.
    Refuses(u16, String),
    /// The first `n` POSTs get `429`, as a visitor past its burst.
    LimitsPosts(usize),
}

/// One request, as the stand-in read it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Asked {
    /// The number of its connection, from 1.
    pub conn: u64,
    pub h2: bool,
    pub method: String,
    pub target: String,
    pub body: String,
}

/// One message that the stand-in keeps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Kept {
    pub id: String,
    pub time: u64,
    pub topic: String,
    pub text: String,
}

#[derive(Default)]
pub struct State {
    pub kept: Vec<Kept>,
    subs: Vec<(String, UnboundedSender<String>)>,
    pub asked: Vec<Asked>,
    pub connections: u64,
    script: Option<Script>,
    limited: usize,
}

/// A running stand-in.
pub struct Ntfy {
    /// Its root, `http://127.0.0.1:PORT/`.
    pub url: Point,
    pub state: Arc<Mutex<State>>,
    task: JoinHandle<()>,
}

impl Ntfy {
    /// The stand-in at `url` of `state`, served by `task`.
    pub fn of(url: Point, state: Arc<Mutex<State>>, task: JoinHandle<()>) -> Ntfy {
        Ntfy { url, state, task }
    }

    /// Each request, in order.
    pub fn asked(&self) -> Vec<Asked> {
        self.state.lock().unwrap().asked.clone()
    }

    /// Each message kept, in order.
    pub fn kept(&self) -> Vec<Kept> {
        self.state.lock().unwrap().kept.clone()
    }

    /// The connections that the stand-in took.
    pub fn connections(&self) -> u64 {
        self.state.lock().unwrap().connections
    }

    /// Keep `text` at `topic` as of `time`, as another end posted it.
    pub fn plant(&self, topic: &str, text: &str, time: u64) {
        put(&self.state, topic, text, time);
    }
}

impl Drop for Ntfy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// A stand-in that takes the messages of the pairing.
pub async fn start() -> Ntfy {
    start_with(Script::Takes).await
}

/// A stand-in that answers as `script` says, HTTP/1.1 with no TLS.
pub async fn start_with(script: Script) -> Ntfy {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("a port of the loopback");
    let port = listener.local_addr().expect("its address").port();
    let state = state_with(script);
    let kept = state.clone();
    let task = tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let conn = {
                let mut s = kept.lock().unwrap();
                s.connections += 1;
                s.connections
            };
            tokio::spawn(serve_http1(tcp, kept.clone(), conn));
        }
    });
    Ntfy { url: Point::parse(&format!("http://127.0.0.1:{port}/")).unwrap(), state, task }
}

/// The state of a stand-in that answers as `script` says.
pub fn state_with(script: Script) -> Arc<Mutex<State>> {
    Arc::new(Mutex::new(State { script: Some(script), ..State::default() }))
}

/// What the stand-in answers to one request.
pub enum Reply {
    /// A whole answer: its status and its body.
    Whole(u16, String),
    /// A stream of the lines of a topic: those of the moment, then each
    /// new one.
    Stream(Vec<String>, UnboundedReceiver<String>),
}

/// The seconds since the Unix epoch.
pub fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn line(m: &Kept) -> String {
    json!({ "id": m.id, "time": m.time, "expires": m.time + 43_200, "event": "message", "topic": m.topic, "message": m.text })
        .to_string()
}

fn put(state: &Arc<Mutex<State>>, topic: &str, text: &str, time: u64) -> Kept {
    let mut s = state.lock().unwrap();
    // 12 letters and digits, as ntfy draws them; a count keeps them apart.
    let id = format!("pw{:010}", s.kept.len() + 1);
    let kept = Kept { id, time, topic: topic.to_string(), text: text.to_string() };
    s.kept.push(kept.clone());
    let said = line(&kept);
    s.subs.retain(|(t, tx)| t != topic || tx.send(said.clone()).is_ok());
    kept
}

fn refusal(status: u16, words: &str) -> Reply {
    Reply::Whole(status, json!({ "code": u32::from(status) * 100 + 1, "http": status, "error": words }).to_string())
}

/// The answer to one request of `method` for `target` with `body`.
pub fn route(state: &Arc<Mutex<State>>, conn: u64, h2: bool, method: &str, target: &str, body: &[u8]) -> Reply {
    let text = String::from_utf8_lossy(body).into_owned();
    let script = {
        let mut s = state.lock().unwrap();
        s.asked.push(Asked { conn, h2, method: method.into(), target: target.into(), body: text.clone() });
        s.script.clone().unwrap_or(Script::Takes)
    };
    if let Script::Refuses(status, words) = &script {
        return refusal(*status, words);
    }
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    let topic_ok =
        |t: &str| (1..=64).contains(&t.len()) && t.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    match (method, parts.as_slice()) {
        ("POST", [topic]) if topic_ok(topic) => {
            if let Script::LimitsPosts(n) = script {
                let mut s = state.lock().unwrap();
                if s.limited < n {
                    s.limited += 1;
                    return refusal(429, "limit reached: too many requests");
                }
            }
            // ntfy keeps a body of its whole limit as an attachment.
            if body.len() >= 4096 {
                return refusal(413, "attachments not allowed");
            }
            let kept = put(state, topic, text.trim(), now());
            Reply::Whole(200, line(&kept))
        }
        ("GET", [topic, "json"]) if topic_ok(topic) => {
            let word = |key: &str| query.split('&').find_map(|kv| kv.strip_prefix(key)?.strip_prefix('='));
            let since = word("since").unwrap_or("none");
            let mut s = state.lock().unwrap();
            let after = s.kept.iter().position(|m| m.id == since);
            let lines: Vec<String> = s
                .kept
                .iter()
                .enumerate()
                .filter(|(i, m)| {
                    m.topic == *topic
                        && match (after, since.parse::<u64>()) {
                            (Some(at), _) => *i > at,
                            (None, Ok(time)) => m.time >= time,
                            (None, Err(_)) => since == "all",
                        }
                })
                .map(|(_, m)| line(m))
                .collect();
            if word("poll") == Some("1") {
                return Reply::Whole(200, lines.iter().map(|l| format!("{l}\n")).collect());
            }
            if !h2 {
                return refusal(400, "the stand-in streams on HTTP/2 alone");
            }
            let (tx, rx) = unbounded_channel();
            s.subs.push((topic.to_string(), tx));
            let open = json!({ "id": "pwopen000000", "time": now(), "event": "open", "topic": topic }).to_string();
            Reply::Stream(std::iter::once(open).chain(lines).collect(), rx)
        }
        _ => refusal(404, "page not found"),
    }
}

/// The requests of one connection of HTTP/1.1, in turns.
pub async fn serve_http1<S>(mut stream: S, state: Arc<Mutex<State>>, conn: u64)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut rest = Vec::new();
    loop {
        let Ok((head, after)) = read_request(&mut stream, std::mem::take(&mut rest)).await else { return };
        let length: usize = head.header("content-length").and_then(|v| v.parse().ok()).unwrap_or(0);
        let mut body = after;
        while body.len() < length {
            let mut chunk = [0u8; 4096];
            match stream.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(n) => body.extend_from_slice(&chunk[..n]),
            }
        }
        rest = body.split_off(length);
        let Reply::Whole(status, answer) = route(&state, conn, false, &head.method, &head.target, &body) else {
            return;
        };
        let kind = if status == 200 && head.method == "GET" { "application/x-ndjson" } else { "application/json" };
        let phrase = if status == 200 { "OK" } else { request::reason(status) };
        let out = format!(
            "HTTP/1.1 {status} {phrase}\r\nContent-Type: {kind}; charset=utf-8\r\nContent-Length: {}\r\n\r\n{answer}",
            answer.len()
        );
        if stream.write_all(out.as_bytes()).await.is_err() {
            return;
        }
    }
}
