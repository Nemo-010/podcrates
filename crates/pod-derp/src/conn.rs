//! One connection to a DERP server, and the links on it. The handshake is
//! DERP's: the server's key, this end's key with its info sealed to it, the
//! server's info sealed back. Then a reader gives each packet to its link,
//! answers the server's pings, and ends the links of a peer that the server
//! says is gone; it never waits for a link, as derper drops a client that
//! reads nothing for 2 s (`DefaultTCPWiteTimeout`). A writer sends the
//! control packets (`OPEN`, `ACK`, `RESET`, pongs) before the `DATA`, pings
//! the server each [`PING_EVERY`], and keeps to the rate that a server names
//! in its info. A node takes the links that clients open ([`Conn::accept`]);
//! a client opens them ([`Conn::open_link`]).

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use pod_core::entropy::Entropy;
use pod_core::{Class, Event, Events, Failure, Stage};
use tokio::sync::{mpsc, watch};
use tokio::time::Instant;

use super::dial::{self, BoxIo};
use super::frame::{self, Decoder, Frame};
use super::key::{Key, Secret, ServerInfo};
use super::link::{self, Link, Shared};
use super::packet::{self, Body, LinkId, Packet};
use super::servers::Server;
use crate::Names;

// DERP's handshake, the reader and the writer of a connection.
mod wire;

/// The bound of each step of DERP's handshake, as derper bounds its own.
pub const HANDSHAKE_LIMIT: Duration = Duration::from_secs(10);
/// How often this end pings the server, which answers each ping: a read
/// that waits longer than [`dial::IDLE_LIMIT`] finds a dead link.
pub const PING_EVERY: Duration = Duration::from_secs(10);
/// The most links on one connection, and from one peer.
pub const MAX_LINKS: usize = 256;
pub const MAX_PER_PEER: usize = 32;
/// The frames that wait for the writer, of each kind.
const QUEUE: usize = 64;
/// The most `RESET`s each second for packets of links that this end has not.
const RESETS_PER_SECOND: u32 = 10;

/// The kind of the event of a server's words on a connection.
pub const HEALTH: &str = "derp.health";

/// What a connection is for.
pub struct Setup {
    pub secret: Arc<Secret>,
    /// A node takes the links that clients open; a client takes none.
    pub serves: bool,
    /// The sink of the lines for the user: a server's words ([`HEALTH`]).
    pub events: Arc<dyn Events>,
    /// The program's name in the client's info and its `User-Agent`.
    pub names: Names,
}

/// A connection to a DERP server. Its clones are one connection; it ends
/// when [`Conn::close`] is called, when the server ends it, or when its last
/// clone goes.
#[derive(Clone)]
pub struct Conn {
    inner: Arc<Inner>,
}

struct Inner {
    server: Server,
    me: Key,
    server_key: Key,
    info: ServerInfo,
    ctl: mpsc::Sender<Vec<u8>>,
    data: mpsc::Sender<Vec<u8>>,
    links: Mutex<HashMap<(Key, LinkId), Arc<Shared>>>,
    incoming: Option<(mpsc::Sender<Link>, tokio::sync::Mutex<mpsc::Receiver<Link>>)>,
    ended: watch::Sender<Option<String>>,
    events: Arc<dyn Events>,
    resets: Mutex<(Instant, u32)>,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

impl Conn {
    /// DERP over `io`, a stream to `server`: the WebSocket, the handshake,
    /// and the tasks that read and write. A failure of the handshake is of
    /// the stage `Relay`.
    pub async fn start(server: Server, io: BoxIo, setup: Setup) -> Result<Conn, Failure> {
        let session = dial::upgrade(io, &server, &setup.names.user_agent).await?;
        let mut decoder = Decoder::new();
        let shook = wire::handshake(&session, &mut decoder, &setup.secret, &server, &setup.names.app).await;
        let (server_key, info) = shook.map_err(|(class, text)| Failure::new(Stage::Relay, class, text))?;
        let (ctl, ctl_rx) = mpsc::channel(QUEUE);
        let (data, data_rx) = mpsc::channel(QUEUE);
        let incoming = setup.serves.then(|| {
            let (sender, receiver) = mpsc::channel(QUEUE);
            (sender, tokio::sync::Mutex::new(receiver))
        });
        let (ended, _) = watch::channel(None);
        let inner = Arc::new(Inner {
            server,
            me: setup.secret.public(),
            server_key,
            info,
            ctl,
            data,
            links: Mutex::new(HashMap::new()),
            incoming,
            ended,
            events: setup.events,
            resets: Mutex::new((Instant::now(), 0)),
        });
        let session = Arc::new(session);
        let (read_end, write_end) = (inner.ended.subscribe(), inner.ended.subscribe());
        tokio::spawn(wire::read_loop(Arc::downgrade(&inner), session.clone(), decoder, read_end));
        tokio::spawn(wire::write_loop(Arc::downgrade(&inner), session, ctl_rx, data_rx, write_end, info));
        Ok(Conn { inner })
    }

    pub fn server(&self) -> &Server {
        &self.inner.server
    }

    /// This end's key on the server.
    pub fn key(&self) -> Key {
        self.inner.me
    }

    pub fn server_key(&self) -> Key {
        self.inner.server_key
    }

    pub fn info(&self) -> ServerInfo {
        self.inner.info
    }

    /// Why the connection ended; `None` while it lives.
    pub fn why_ended(&self) -> Option<String> {
        self.inner.ended.borrow().clone()
    }

    /// Until the connection ended: why, in a sentence.
    pub async fn ended(&self) -> String {
        let mut seen = self.inner.ended.subscribe();
        let why = match seen.wait_for(Option::is_some).await {
            Ok(why) => why.clone().unwrap_or_default(),
            Err(_) => "it closed".to_string(),
        };
        format!("the connection to the DERP server {} ended: {why}", self.inner.server)
    }

    /// End the connection, and each link on it.
    pub fn close(&self) {
        self.inner.end("this end closed it".to_string());
    }

    /// The links on the connection.
    pub fn links(&self) -> usize {
        lock(&self.inner.links).len()
    }

    /// A new link to the end of `peer`, whose `OPEN` goes at once; it is the
    /// peer's once [`Link::opened`] says so.
    pub fn open_link(&self, peer: Key, entropy: &mut dyn Entropy) -> Result<Link, Failure> {
        if let Some(why) = self.why_ended() {
            let text = format!("the connection to the DERP server {} ended: {why}", self.inner.server);
            return Err(Failure::new(Stage::Relay, Class::Unavailable, text));
        }
        let mut id = [0u8; packet::ID];
        entropy.fill(&mut id).map_err(|e| Failure::new(Stage::Relay, Class::Unavailable, e.to_string()))?;
        let shared = Shared::opening(peer, id, Instant::now());
        lock(&self.inner.links).insert((peer, id), shared.clone());
        tokio::spawn(link::drive(shared.clone(), self.clone()));
        Ok(Link::new(shared))
    }

    /// The next link that a client opened; `None` at a client, and once the
    /// connection ended.
    pub async fn accept(&self) -> Option<Link> {
        let (_, receiver) = self.inner.incoming.as_ref()?;
        let mut receiver = receiver.lock().await;
        tokio::select! {
            link = receiver.recv() => link,
            _ = self.ended() => None,
        }
    }

    pub(super) async fn send_data(&self, peer: Key, packet: Vec<u8>) -> Result<(), String> {
        let frame = frame::send_packet(&peer.0, &packet);
        self.inner.data.send(frame).await.map_err(|_| self.gone())
    }

    pub(super) async fn send_ctl(&self, peer: Key, packet: Vec<u8>) -> Result<(), String> {
        let frame = frame::send_packet(&peer.0, &packet);
        self.inner.ctl.send(frame).await.map_err(|_| self.gone())
    }

    fn gone(&self) -> String {
        let why = self.why_ended().unwrap_or_else(|| "its writer stopped".to_string());
        format!("the connection to the DERP server {} ended: {why}", self.inner.server)
    }

    pub(super) fn forget(&self, peer: &Key, id: &LinkId) {
        lock(&self.inner.links).remove(&(*peer, *id));
    }
}

impl Inner {
    /// The connection ends with `why`, once; each link on it fails.
    fn end(&self, why: String) {
        let first = self.ended.send_if_modified(|ended| {
            if ended.is_some() {
                return false;
            }
            *ended = Some(why.clone());
            true
        });
        if !first {
            return;
        }
        let text = format!("the connection to the DERP server {} ended: {why}", self.server);
        let links: Vec<Arc<Shared>> = lock(&self.links).values().cloned().collect();
        for shared in links {
            shared.fail(&text, false);
        }
    }

    fn handle(self: &Arc<Self>, frame: Frame) {
        match frame {
            Frame::RecvPacket { src, packet } => self.dispatch(Key(src), &packet),
            // Never a wait in the reader: a pong that finds no room is lost,
            // and the server pings again.
            Frame::Ping(data) => {
                let _ = self.ctl.try_send(frame::pong(data));
            }
            Frame::Pong(_) | Frame::KeepAlive | Frame::Other { .. } => {}
            Frame::PeerGone { key, reason } => {
                let why = match reason {
                    Some(frame::gone::NOT_HERE) => "the DERP server does not know the far end",
                    _ => "the far end left the DERP server",
                };
                self.fail_peer(Key(key), why);
            }
            Frame::Health(text) if text.is_empty() => {}
            Frame::Health(text) => {
                self.events.event(Event::warn(HEALTH, format!("the DERP server {} says: {text}", self.server)))
            }
            Frame::Restarting { reconnect_ms, .. } => {
                self.end(format!("the DERP server restarts, and asks for a new connection after {reconnect_ms} ms"))
            }
            Frame::ServerKey { .. } | Frame::ServerInfo { .. } => {
                self.end("the DERP server began its handshake again".to_string())
            }
        }
    }

    fn dispatch(self: &Arc<Self>, peer: Key, bytes: &[u8]) {
        // Another program's packet to this key is dropped.
        let Ok(packet) = Packet::decode(bytes) else { return };
        let now = Instant::now();
        let found = lock(&self.links).get(&(peer, packet.link)).cloned();
        if let Some(shared) = found {
            shared.on_packet(packet.body, now);
            return;
        }
        match packet.body {
            Body::Open => self.accept(peer, packet.link, now),
            Body::Reset(_) => {}
            _ => self.reset(peer, packet.link, "no such link: it ended, or this end started again"),
        }
    }

    /// A client opened a link to this node.
    fn accept(self: &Arc<Self>, peer: Key, id: LinkId, now: Instant) {
        let Some((sender, _)) = &self.incoming else {
            self.reset(peer, id, "this end opens links, and takes none");
            return;
        };
        let full = {
            let links = lock(&self.links);
            let from_peer = links.keys().filter(|(from, _)| *from == peer).count();
            links.len() >= MAX_LINKS || from_peer >= MAX_PER_PEER
        };
        if full {
            self.reset(peer, id, "the node holds as many links as it takes");
            return;
        }
        let shared = Shared::answering(peer, id, now);
        lock(&self.links).insert((peer, id), shared.clone());
        tokio::spawn(link::drive(shared.clone(), Conn { inner: self.clone() }));
        if sender.try_send(Link::new(shared.clone())).is_err() {
            // The link that came back is dropped: the node takes no more now.
            shared.fail("the node takes no more links now", true);
        }
    }

    /// A `RESET` of a link that this end has not, a few each second at most.
    fn reset(&self, peer: Key, id: LinkId, why: &str) {
        {
            let mut resets = lock(&self.resets);
            let now = Instant::now();
            if now.saturating_duration_since(resets.0) >= Duration::from_secs(1) {
                *resets = (now, 0);
            }
            if resets.1 >= RESETS_PER_SECOND {
                return;
            }
            resets.1 += 1;
        }
        let packet = Packet { link: id, body: Body::Reset(why.to_string()) }.encode();
        let _ = self.ctl.try_send(frame::send_packet(&peer.0, &packet));
    }

    fn fail_peer(&self, peer: Key, why: &str) {
        let links: Vec<Arc<Shared>> =
            lock(&self.links).iter().filter(|((from, _), _)| *from == peer).map(|(_, shared)| shared.clone()).collect();
        for shared in links {
            shared.fail(why, false);
        }
    }
}
