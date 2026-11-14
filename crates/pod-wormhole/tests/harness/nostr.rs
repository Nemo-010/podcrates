//! A stand-in Nostr relay of the tests, in Rust, on the loopback: NIP-01
//! in text messages of a pod-ws WebSocket. It keeps no event, as a relay
//! does with the ephemeral range: a `REQ` gets its `EOSE` at once, and an
//! `EVENT` goes to each subscription of that moment whose filter holds it
//! (`kinds`, each `#X` tag, `since`), with `OK` true. An event whose id or
//! signature does not check gets `OK` false `invalid:`; an event that it
//! had gets `OK` true `duplicate:` and goes to nobody, as strfry does; an
//! event that no subscription holds gets `OK` false `mute:`. A test can
//! make the next events that hold a message reach nobody, and reads each
//! event; a relay of a [`Script`] refuses as some public relays do.
//! No relay of another party publishes a static release (call C549):
//! strfry and nostr-rs-relay have tags alone.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use pod_proxy::http::request;
use pod_wormhole::nostr::event::{self, Checked};
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
    /// As a public relay that takes the events of the pairing.
    Takes,
    /// Each `REQ` gets `CLOSED` with these words.
    ClosesEachReq(String),
    /// Each `EVENT` gets `OK` false with these words.
    RefusesEachEvent(String),
    /// Each `REQ` gets a `NOTICE` with these words, and no `EOSE`.
    NoticeOnly(String),
}

#[derive(Default)]
struct State {
    /// Each subscription: the connection, its id, its filter, its writer.
    subs: Vec<(u64, String, Value, UnboundedSender<String>)>,
    /// The next events that hold a message and reach no subscriber.
    lost: usize,
    /// Each event that checked, in order.
    events: Vec<Checked>,
    ids: HashSet<String>,
    connections: u64,
}

/// A running stand-in.
pub struct Relay {
    /// Its WebSocket, `ws://127.0.0.1:PORT/`.
    pub url: WsUrl,
    state: Arc<Mutex<State>>,
    task: JoinHandle<()>,
}

impl Relay {
    /// Each event that checked, the lost ones too.
    pub fn events(&self) -> Vec<Checked> {
        self.state.lock().unwrap().events.clone()
    }

    /// The next `n` events that hold a message reach no subscriber, as an
    /// event that comes before the other end subscribed.
    pub fn lose(&self, n: usize) {
        self.state.lock().unwrap().lost = n;
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// A stand-in that takes the events of the pairing.
pub async fn start() -> Relay {
    start_with(Script::Takes).await
}

/// A stand-in that answers by `script`, on a free port of the loopback.
pub async fn start_with(script: Script) -> Relay {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("a port of the loopback");
    let port = listener.local_addr().expect("its address").port();
    let state = Arc::new(Mutex::new(State::default()));
    let shared = state.clone();
    let task = tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            tokio::spawn(serve(tcp, shared.clone(), script.clone()));
        }
    });
    Relay { url: WsUrl::parse(&format!("ws://127.0.0.1:{port}/")).unwrap(), state, task }
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
        let Ok(Value::Array(message)) = serde_json::from_slice::<Value>(&f.payload) else {
            let _ = tx.send(json!(["NOTICE", "ERROR: bad msg: not a JSON array"]).to_string());
            continue;
        };
        handle(&state, id, &tx, &script, &message);
    }
    state.lock().unwrap().subs.retain(|(conn, ..)| *conn != id);
    // Let the writer send what is queued, then end.
    drop(tx);
    let _ = writer.await;
    let _ = session.send_close(1000, "").await;
}

/// One message of a client.
fn handle(state: &Mutex<State>, conn: u64, tx: &UnboundedSender<String>, script: &Script, message: &[Value]) {
    let send = |value: Value| {
        let _ = tx.send(value.to_string());
    };
    let text = |n: usize| message.get(n).and_then(Value::as_str).unwrap_or_default().to_string();
    let mut state = state.lock().unwrap();
    match text(0).as_str() {
        "REQ" => match script {
            Script::ClosesEachReq(words) => send(json!(["CLOSED", text(1), words])),
            Script::NoticeOnly(words) => send(json!(["NOTICE", words])),
            _ => {
                let filter = message.get(2).cloned().unwrap_or(Value::Null);
                state.subs.push((conn, text(1), filter, tx.clone()));
                // It keeps no event: the end of the stored ones comes at once.
                send(json!(["EOSE", text(1)]));
            }
        },
        "CLOSE" => state.subs.retain(|(c, sub, ..)| !(*c == conn && *sub == text(1))),
        "EVENT" => {
            let raw = message.get(1).cloned().unwrap_or(Value::Null);
            let id = raw["id"].as_str().unwrap_or_default().to_string();
            let Some(checked) = event::checked(&raw) else {
                return send(json!(["OK", id, false, "invalid: the id or the signature does not check"]));
            };
            if let Script::RefusesEachEvent(words) = script {
                return send(json!(["OK", id, false, words]));
            }
            if !state.ids.insert(id.clone()) {
                return send(json!(["OK", id, true, "duplicate: already have this event"]));
            }
            state.events.push(checked.clone());
            if !checked.content.is_empty() && state.lost > 0 {
                state.lost -= 1;
                return send(json!(["OK", id, false, "mute: no one was listening to your ephemeral event"]));
            }
            let mut heard = false;
            for (_, sub, filter, to) in &state.subs {
                if holds(filter, &checked) {
                    let _ = to.send(json!(["EVENT", sub, raw]).to_string());
                    heard = true;
                }
            }
            match heard {
                true => send(json!(["OK", id, true, ""])),
                false => send(json!(["OK", id, false, "mute: no one was listening to your ephemeral event"])),
            }
        }
        other => send(json!(["NOTICE", format!("ERROR: unknown message type {other}")])),
    }
}

/// Whether `filter` holds `event`: each of its conditions, as NIP-01 says.
fn holds(filter: &Value, event: &Checked) -> bool {
    let Some(conditions) = filter.as_object() else { return false };
    conditions.iter().all(|(key, value)| match key.as_str() {
        "kinds" => value.as_array().is_some_and(|k| k.iter().any(|k| k.as_u64() == Some(u64::from(event.kind)))),
        "since" => value.as_u64().is_some_and(|since| event.created_at >= since),
        "until" => value.as_u64().is_some_and(|until| event.created_at <= until),
        "limit" => true,
        tag if tag.starts_with('#') && tag.len() == 2 => value.as_array().is_some_and(|values| {
            event.tags.iter().any(|(n, v)| *n == tag[1..] && values.iter().any(|w| w.as_str() == Some(v.as_str())))
        }),
        // A condition that this stand-in does not know holds no event.
        _ => false,
    })
}
