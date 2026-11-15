//! DERP's handshake on a connection, and the tasks that read and write its
//! frames.

use std::future::Future;
use std::sync::{Arc, Weak};
use std::time::Duration;

use pod_core::Class;
use pod_core::entropy::{Entropy, OsEntropy};
use pod_ws::RelaySession;
use pod_ws::close::close_code_and_reason;
use pod_ws::frame::{OPCODE_BINARY, OPCODE_CLOSE};
use tokio::sync::{mpsc, watch};
use tokio::time::{Instant, MissedTickBehavior};

use super::{HANDSHAKE_LIMIT, Inner, PING_EVERY};
use crate::dial::BoxIo;
use crate::frame::{self, Decoder, Frame};
use crate::key::{self, Key, Secret, ServerInfo};
use crate::servers::Server;

/// A failure of the handshake: its class and its words.
pub(super) type Missed = (Class, String);

/// DERP's handshake on `session`: the server's key and info. `app` names
/// the program in the client's info.
pub(super) async fn handshake(
    session: &RelaySession<BoxIo>,
    decoder: &mut Decoder,
    secret: &Secret,
    server: &Server,
    app: &str,
) -> Result<(Key, ServerInfo), Missed> {
    let protocol = |text: String| (Class::Protocol, text);
    let server_key = match within(next_frame(session, decoder), server, "its key").await? {
        Frame::ServerKey { key } => Key(key),
        other => {
            return Err(protocol(format!("{server} sent {} first, where a DERP server sends its key", other.name())));
        }
    };
    let mut nonce = [0u8; frame::NONCE];
    OsEntropy.fill(&mut nonce).map_err(|e| (Class::Unavailable, e.to_string()))?;
    let sealed = secret.seal(&server_key, &key::client_info_json(app), nonce);
    let hello = frame::client_info(&secret.public().0, &sealed);
    session.send_binary(&hello).await.map_err(|e| (e.class(), format!("{server}: {e}")))?;
    let sealed = match within(next_frame(session, decoder), server, "its info").await? {
        Frame::ServerInfo { sealed } => sealed,
        other => {
            let sent = other.name();
            let text = format!("{server} sent {sent} after this end's key, where a DERP server sends its info");
            return Err(protocol(text));
        }
    };
    let json = secret.open(&server_key, &sealed).map_err(|why| protocol(format!("{server}'s info: {why}")))?;
    let info = key::server_info(&json).map_err(|why| protocol(format!("{server}: {why}")))?;
    Ok((server_key, info))
}

async fn within<T>(step: impl Future<Output = Result<T, Missed>>, server: &Server, what: &str) -> Result<T, Missed> {
    match tokio::time::timeout(HANDSHAKE_LIMIT, step).await {
        Err(_) => Err((Class::Timeout, format!("{server} did not send {what} within {} s", HANDSHAKE_LIMIT.as_secs()))),
        Ok(answer) => answer,
    }
}

async fn next_frame(session: &RelaySession<BoxIo>, decoder: &mut Decoder) -> Result<Frame, Missed> {
    loop {
        if let Some(frame) = decoder.decode().map_err(|e| (Class::Protocol, e.to_string()))? {
            return Ok(frame);
        }
        let message = session.read_frame().await.map_err(|e| (e.class(), e.to_string()))?;
        match message.opcode {
            OPCODE_BINARY => decoder.push(&message.payload),
            // A server that closes in its handshake refuses this end: derper
            // with `--verify-clients` closes on a key that it does not know.
            OPCODE_CLOSE => return Err((Class::Refused, closed(&message.payload))),
            _ => return Err((Class::Protocol, "a text message, where DERP sends binary ones".to_string())),
        }
    }
}

fn closed(payload: &[u8]) -> String {
    match close_code_and_reason(payload) {
        (Some(code), reason) if reason.is_empty() => format!("the server closed its WebSocket ({code})"),
        (Some(code), reason) => format!("the server closed its WebSocket ({code} {reason})"),
        (None, _) => "the server closed its WebSocket".to_string(),
    }
}

pub(super) async fn read_loop(
    inner: Weak<Inner>,
    session: Arc<RelaySession<BoxIo>>,
    mut decoder: Decoder,
    mut ended: watch::Receiver<Option<String>>,
) {
    let why = loop {
        match decoder.decode() {
            Ok(Some(frame)) => {
                let Some(inner) = inner.upgrade() else { return };
                inner.handle(frame);
                continue;
            }
            Ok(None) => {}
            Err(e) => break e.to_string(),
        }
        let message = tokio::select! {
            message = session.read_frame() => message,
            _ = ended.wait_for(Option::is_some) => return,
        };
        match message {
            Ok(message) if message.opcode == OPCODE_BINARY => decoder.push(&message.payload),
            Ok(message) if message.opcode == OPCODE_CLOSE => break closed(&message.payload),
            Ok(_) => break "a text message, where DERP sends binary ones".to_string(),
            Err(e) => break e.to_string(),
        }
    };
    if let Some(inner) = inner.upgrade() {
        inner.end(why);
    }
}

pub(super) async fn write_loop(
    inner: Weak<Inner>,
    session: Arc<RelaySession<BoxIo>>,
    mut ctl: mpsc::Receiver<Vec<u8>>,
    mut data: mpsc::Receiver<Vec<u8>>,
    mut ended: watch::Receiver<Option<String>>,
    info: ServerInfo,
) {
    let mut pings = tokio::time::interval(PING_EVERY);
    pings.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut bucket = Bucket::of(&info);
    let mut sent: u64 = 0;
    let why = loop {
        // The end's future drops the watch's guard before the select sees its
        // output: a guard there may not live across any branch's await.
        let frame = tokio::select! {
            biased;
            _ = async { drop(ended.wait_for(Option::is_some).await) } => None,
            Some(frame) = ctl.recv() => Some(frame),
            Some(frame) = data.recv() => {
                if let Some(bucket) = bucket.as_mut() {
                    bucket.take(frame.len()).await;
                }
                Some(frame)
            }
            _ = pings.tick() => {
                sent += 1;
                Some(frame::ping(sent.to_be_bytes()))
            }
        };
        let Some(frame) = frame else {
            let _ = session.send_close(1000, "").await;
            return;
        };
        if let Err(e) = session.send_binary(&frame).await {
            break format!("a write to the server failed: {e}");
        }
    };
    if let Some(inner) = inner.upgrade() {
        inner.end(why);
    }
}

/// The rate that a server names in its info, kept as Go's client keeps it,
/// but by waiting where Go's client drops.
struct Bucket {
    rate: f64,
    burst: f64,
    tokens: f64,
    at: Instant,
}

impl Bucket {
    fn of(info: &ServerInfo) -> Option<Bucket> {
        (info.bytes_per_second > 0).then(|| {
            let burst = info.burst.max((frame::MAX_PACKET + frame::KEY + frame::HEADER) as u64) as f64;
            Bucket { rate: info.bytes_per_second as f64, burst, tokens: burst, at: Instant::now() }
        })
    }

    async fn take(&mut self, bytes: usize) {
        let need = (bytes as f64).min(self.burst);
        loop {
            let now = Instant::now();
            let since = now.saturating_duration_since(self.at).as_secs_f64();
            self.tokens = (self.tokens + self.rate * since).min(self.burst);
            self.at = now;
            if self.tokens >= need {
                self.tokens -= bytes as f64;
                return;
            }
            tokio::time::sleep(Duration::from_secs_f64((need - self.tokens) / self.rate)).await;
        }
    }
}
