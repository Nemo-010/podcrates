//! The WebTorrent trackers of the tests, on the loopback: a stand-in in
//! Rust ([`start`]), and webtorrent/bittorrent-tracker ([`Bittorrent`]),
//! software that this crate did not write.
//!
//! The stand-in speaks the JSON of bittorrent-tracker 11.2.3 in text
//! messages of a pod-ws WebSocket. An announce adds its peer to the swarm
//! of its `info_hash` and gets the answer with the `interval`, unless it
//! holds an `answer`; each offer goes at once to one other peer of the
//! swarm, in the order of their arrival, and to nobody when the swarm has
//! no other peer; an answer goes to the peer of its `to_peer_id`. It keeps
//! no offer. An `info_hash` or a `peer_id` that is not 20 characters, and an
//! offer with no `sdp` text (as tracker.openwebtorrent.com and
//! tracker.webtorrent.dev refuse one), get a `failure reason`. A test can
//! make the next offers reach nobody, and reads each announce; a tracker of
//! a [`Script`] refuses or says nothing.
//!
//! bittorrent-tracker is the one that `POD_WORMHOLE_TEST_TRACKER` names
//! (`ws://127.0.0.1:PORT/`, as `scripts/ci/tracker-tests.sh` runs it). A
//! host with none skips it with the reason, unless
//! `POD_WORMHOLE_TEST_WEBTORRENT=required`.

use std::sync::{Arc, Mutex};

use pod_proxy::http::request;
use pod_ws::url::WsUrl;
use pod_ws::{frame, server};
use serde_json::{Value, json};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::{UnboundedSender, unbounded_channel};
use tokio::task::JoinHandle;

/// How a stand-in answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Script {
    /// As a public tracker, with this `interval` in seconds.
    Takes(u64),
    /// Each announce gets this `failure reason`.
    Refuses(String),
    /// No announce gets an answer.
    Silent,
}

/// One announce that the stand-in read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Announce {
    pub info_hash: String,
    pub peer_id: String,
    pub event: Option<String>,
    /// The `sdp` of each offer.
    pub offers: Vec<String>,
    /// The `sdp` of its answer, and the peer that the answer goes to.
    pub answer: Option<String>,
    pub to: Option<String>,
}

#[derive(Default)]
struct State {
    /// Each peer: its `info_hash`, its `peer_id`, its connection, its writer.
    peers: Vec<(String, String, u64, UnboundedSender<String>)>,
    /// The next offers that reach nobody.
    lost: usize,
    announces: Vec<Announce>,
    connections: u64,
}

/// A running stand-in.
pub struct Tracker {
    /// Its WebSocket, `ws://127.0.0.1:PORT/`.
    pub url: WsUrl,
    state: Arc<Mutex<State>>,
    task: JoinHandle<()>,
}

impl Tracker {
    /// Each announce, in order.
    pub fn announces(&self) -> Vec<Announce> {
        self.state.lock().unwrap().announces.clone()
    }

    /// The next `n` offers reach nobody, as an offer that comes before the
    /// giver announced, or that goes to a stranger.
    pub fn lose(&self, n: usize) {
        self.state.lock().unwrap().lost = n;
    }
}

impl Drop for Tracker {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// A stand-in that takes the announces, with an `interval` of 120 s.
pub async fn start() -> Tracker {
    start_with(Script::Takes(120)).await
}

/// A stand-in that answers by `script`, on a free port of the loopback.
pub async fn start_with(script: Script) -> Tracker {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("a port of the loopback");
    let port = listener.local_addr().expect("its address").port();
    let state = Arc::new(Mutex::new(State::default()));
    let shared = state.clone();
    let task = tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            tokio::spawn(serve(tcp, shared.clone(), script.clone()));
        }
    });
    Tracker { url: WsUrl::parse(&format!("ws://127.0.0.1:{port}/")).unwrap(), state, task }
}

async fn serve(mut tcp: TcpStream, state: Arc<Mutex<State>>, script: Script) {
    let Ok((head, pending)) = request::read_request(&mut tcp, Vec::new()).await else { return };
    let Ok(key) = server::check_upgrade(&head) else { return };
    if tcp.write_all(&server::switching(&key)).await.is_err() {
        return;
    }
    let session = Arc::new(server::session(tcp, pending, None));
    let (tx, mut rx) = unbounded_channel::<String>();
    let writer = {
        let session = session.clone();
        tokio::spawn(async move {
            while let Some(text) = rx.recv().await {
                if session.send_text(&text).await.is_err() {
                    break;
                }
            }
        })
    };
    let id = {
        let mut state = state.lock().unwrap();
        state.connections += 1;
        state.connections
    };
    while let Ok(f) = session.read_frame().await {
        if f.opcode != frame::OPCODE_TEXT {
            break;
        }
        let Ok(message) = serde_json::from_slice::<Value>(&f.payload) else {
            let _ = tx.send(json!({ "failure reason": "invalid JSON" }).to_string());
            continue;
        };
        handle(&state, id, &tx, &script, &message);
    }
    // A closed socket leaves each swarm, as bittorrent-tracker does.
    state.lock().unwrap().peers.retain(|(_, _, conn, _)| *conn != id);
    drop(tx);
    let _ = writer.await;
    let _ = session.send_close(1000, "").await;
}

/// One announce of a client.
fn handle(state: &Mutex<State>, conn: u64, tx: &UnboundedSender<String>, script: &Script, message: &Value) {
    let send = |value: Value| {
        let _ = tx.send(value.to_string());
    };
    let fail = |words: &str| send(json!({ "action": "announce", "failure reason": words }));
    let text = |key: &str| message[key].as_str().map(str::to_string);
    if message["action"] != "announce" {
        return fail("invalid action in WS request");
    }
    let Some(info_hash) = text("info_hash").filter(|h| h.chars().count() == 20) else {
        return fail("invalid info_hash");
    };
    let Some(peer_id) = text("peer_id").filter(|p| p.chars().count() == 20) else {
        return fail("invalid peer_id");
    };
    let offers: Vec<&Value> = message["offers"].as_array().map(|o| o.iter().collect()).unwrap_or_default();
    let sdps: Option<Vec<String>> = offers.iter().map(|o| o["offer"]["sdp"].as_str().map(str::to_string)).collect();
    let Some(sdps) = sdps else { return fail("announce: wrong offer item field format") };
    let answer = message["answer"]["sdp"].as_str().map(str::to_string);
    let mut state = state.lock().unwrap();
    state.announces.push(Announce {
        info_hash: info_hash.clone(),
        peer_id: peer_id.clone(),
        event: text("event"),
        offers: sdps.clone(),
        answer: answer.clone(),
        to: text("to_peer_id"),
    });
    match script {
        Script::Refuses(words) => return fail(words),
        Script::Silent => return,
        Script::Takes(_) => {}
    }
    if text("event").as_deref() == Some("stopped") {
        state.peers.retain(|(h, p, ..)| !(*h == info_hash && *p == peer_id));
        return;
    }
    if !state.peers.iter().any(|(h, p, ..)| *h == info_hash && *p == peer_id) {
        state.peers.push((info_hash.clone(), peer_id.clone(), conn, tx.clone()));
    }
    if let Some(answer) = answer {
        let to = text("to_peer_id").unwrap_or_default();
        if let Some((.., writer)) = state.peers.iter().find(|(h, p, ..)| *h == info_hash && *p == to) {
            let forwarded = json!({
                "action": "announce", "answer": { "type": "answer", "sdp": answer },
                "offer_id": message["offer_id"], "peer_id": peer_id, "info_hash": info_hash,
            });
            let _ = writer.send(forwarded.to_string());
        }
        return;
    }
    let Script::Takes(interval) = script else { return };
    let swarm = state.peers.iter().filter(|(h, ..)| *h == info_hash).count();
    send(json!({
        "complete": 0, "incomplete": swarm, "action": "announce", "info_hash": info_hash, "interval": interval,
    }));
    let others: Vec<UnboundedSender<String>> =
        state.peers.iter().filter(|(h, p, ..)| *h == info_hash && *p != peer_id).map(|(.., w)| w.clone()).collect();
    for (n, (offer, sdp)) in offers.iter().zip(sdps).enumerate() {
        if state.lost > 0 {
            state.lost -= 1;
            continue;
        }
        let Some(to) = others.get(n) else { break };
        let forwarded = json!({
            "action": "announce", "offer": { "type": "offer", "sdp": sdp },
            "offer_id": offer["offer_id"], "peer_id": peer_id, "info_hash": info_hash,
        });
        let _ = to.send(forwarded.to_string());
    }
}

/// webtorrent/bittorrent-tracker, at the URL of `POD_WORMHOLE_TEST_TRACKER`.
pub struct Bittorrent {
    /// Its WebSocket, `ws://127.0.0.1:PORT/`.
    pub url: WsUrl,
}

impl Bittorrent {
    /// The tracker; `None`, with the reason on stderr, when no variable
    /// names one and the run does not require it.
    pub fn named() -> Option<Bittorrent> {
        if let Ok(named) = std::env::var("POD_WORMHOLE_TEST_TRACKER")
            && !named.trim().is_empty()
        {
            let url = WsUrl::parse(named.trim()).expect("POD_WORMHOLE_TEST_TRACKER is ws://HOST:PORT/");
            return Some(Bittorrent { url });
        }
        let why = "no bittorrent-tracker here (run scripts/ci/tracker-tests.sh, or set POD_WORMHOLE_TEST_TRACKER)";
        let required = std::env::var("POD_WORMHOLE_TEST_WEBTORRENT").is_ok_and(|v| v == "required");
        assert!(!required, "POD_WORMHOLE_TEST_WEBTORRENT=required: {why}");
        eprintln!("did not run: {why}");
        None
    }
}
