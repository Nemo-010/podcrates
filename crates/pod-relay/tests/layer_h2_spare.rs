//! A session of the resumable layer over HTTP/2 (PodUtils/podssh#262): its
//! links are streams of extended CONNECT (RFC 8441) to a stand-in of TLS on
//! the loopback whose HTTP/2 is h2's own server, and whose far end keeps
//! the session as podssh's relay role does. A stand-in TCP proxy before it
//! holds each byte of its first connection once the test says so, with no
//! word to either end, as a cut of the client's leg does. The spare link
//! must take a new TCP connection, as the held one would hold its CONNECT
//! too, and the session must resume on it soon after the spare's wait. The
//! first link of a new session must also leave the held connection, after
//! the waits of its CONNECT's answer and of a PING.

#[allow(dead_code)]
mod cert {
    include!("../../pod-tls/tests/common/cert_for_test.rs");
}

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use pod_relay::Context;
use pod_relay::cache::Cache;
use pod_relay::forward_layer::{Dialer, carry};
use pod_relay::relay::Relay;
use pod_relay::settings::Settings as RelaySettings;
use pod_session::client;
use pod_session::keep::Keeper;
use pod_session::resume::Note;
use pod_session::ws_link::Link;
use pod_session::{Ask, OsEntropy, Role, Settings};
use pod_ws::Trust;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio::net::{TcpListener, TcpStream};

const NAME: &str = "relay.layer-h2.test";
const TOKEN: &str = "token-of-the-test";
const PIPE: usize = 256 * 1024;
const LIMIT: Duration = Duration::from_secs(60);

/// A stand-in relay role of TLS and HTTP/2 for [`NAME`]: each CONNECT is a
/// link of the layer to a far end that keeps its sessions, whose target
/// echoes each byte. Its port and the root of its certificate.
async fn role(tag: &str) -> (u16, PathBuf) {
    let (acceptor, _) = cert::server_for(NAME).unwrap();
    let mut tls = (**acceptor.config()).clone();
    tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let keeper: Arc<Keeper<DuplexStream>> = Arc::new(Keeper::new(Duration::from_secs(600)));
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let (acceptor, keeper) = (acceptor.clone(), keeper.clone());
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else { return };
                let mut builder = h2::server::Builder::new();
                builder.enable_connect_protocol();
                let Ok(mut connection) = builder.handshake::<_, Bytes>(tls).await else { return };
                while let Some(Ok((request, respond))) = connection.accept().await {
                    tokio::spawn(far_end(request, respond, keeper.clone()));
                }
            });
        }
    });
    let dir = std::env::temp_dir().join(format!("pod-relay-layer-h2-{}-{tag}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let root = dir.join("root.pem");
    let der = cert::encoding::self_signed_inner(&cert::encoding::anchor_name(NAME), true).der;
    std::fs::write(&root, cert::encoding::pem(&der)).unwrap();
    (port, root)
}

/// One link of the layer on a CONNECT: a resume goes on with its session's
/// target; a new session's target echoes.
async fn far_end(
    request: http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    keeper: Arc<Keeper<DuplexStream>>,
) {
    let token = request.headers().get("x-relay-token").and_then(|v| v.to_str().ok());
    let status = if token == Some(TOKEN) { 200 } else { 403 };
    let head = http::Response::builder().status(status).body(()).unwrap();
    let Ok(send) = respond.send_response(head, status != 200) else { return };
    if status != 200 {
        return;
    }
    let ws = pod_ws::server::session(pod_ws::h2_road::duplex(send, request.into_body()), Vec::new(), None);
    let link = Link::start_by(ws, Vec::new(), "the client");
    let settings = Settings::default();
    let Ok(accepted) = pod_session::far::accept(link, Role::SERVE, settings, &keeper.sessions, &mut OsEntropy).await
    else {
        return;
    };
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
}

/// Copy `from` into `to`, holding each piece while `held` is set.
async fn pass<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(mut from: R, mut to: W, held: Arc<AtomicBool>) {
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let n = match from.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        while held.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        if to.write_all(&buf[..n]).await.is_err() {
            return;
        }
    }
}

/// A TCP proxy to `port` that counts its connections, and holds each byte
/// of the first one both ways while the flag that it gives is set.
async fn proxy(port: u16) -> (u16, Arc<AtomicUsize>, Arc<AtomicBool>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let at = listener.local_addr().unwrap().port();
    let (accepts, held) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicBool::new(false)));
    let (count, hold) = (accepts.clone(), held.clone());
    tokio::spawn(async move {
        while let Ok((client, _)) = listener.accept().await {
            let first = count.fetch_add(1, Ordering::SeqCst) == 0;
            let held = if first { hold.clone() } else { Arc::new(AtomicBool::new(false)) };
            tokio::spawn(async move {
                let Ok(server) = TcpStream::connect(("127.0.0.1", port)).await else { return };
                let (cr, cw) = client.into_split();
                let (sr, sw) = server.into_split();
                tokio::spawn(pass(cr, sw, held.clone()));
                pass(sr, cw, held).await;
            });
        }
    });
    (at, accepts, held)
}

/// The context of the client: the relay's name on the loopback, the
/// test's token, and HTTP/2 for each host.
fn context() -> Context {
    let lo: IpAddr = "127.0.0.1".parse().unwrap();
    let resolve = Arc::new(pod_proxy::resolve::System::with_pins(vec![(NAME.to_string(), lo)]));
    let settings = pod_proxy::Settings::new("pod-relay", pod_proxy::ProxyChoice::Direct);
    let dialer = Arc::new(pod_proxy::Dialer::new(settings, resolve));
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let tls = Arc::new(pod_tls::Context::new(provider, pod_tls::Settings::new(pod_tls::Words::new("pod-relay"))));
    let way = pod_ws::Way::new(tls, dialer, "pod-relay/test");
    let settings = RelaySettings { token: Some(TOKEN.into()), h2: Some("yes".into()), ..RelaySettings::default() };
    Context::new(way, Cache::none()).with_settings(settings)
}

/// `bytes` through the session and back from the echo, within `limit`.
async fn round(app: &mut DuplexStream, bytes: &[u8], limit: Duration) -> Result<(), String> {
    app.write_all(bytes).await.map_err(|e| e.to_string())?;
    let mut got = vec![0u8; bytes.len()];
    match tokio::time::timeout(limit, app.read_exact(&mut got)).await {
        Ok(Ok(_)) if got == bytes => Ok(()),
        Ok(Ok(_)) => Err("other bytes came back".into()),
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err(format!("no echo within {} ms", limit.as_millis())),
    }
}

/// The first link's TCP connection goes silent: the spare beside it opens
/// a second TCP connection, and the session resumes on it within the
/// spare's longest wait and a few seconds of work; the held connection
/// would hold the spare's CONNECT until the heartbeat found the link dead.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_spare_beside_a_silent_connection_of_http2_takes_a_new_one() {
    pod_testkit::need_loopback!();
    let (role_port, root) = role("spare").await;
    let dir = root.parent().unwrap().to_path_buf();
    let (port, accepts, held) = proxy(role_port).await;
    let ctx = context();
    let relay = Relay { host: NAME.into(), port };
    let dialer = Dialer::new(&ctx, relay, "target.test", 22, Trust::File(root)).unwrap();
    let first = tokio::time::timeout(LIMIT, dialer.link(&mut |_| {})).await.expect("the first link in time");
    let first = first.unwrap_or_else(|missed| panic!("the first link: {:?}", missed.lines("target.test:22")));
    let settings = Settings { spare_links: true, ..Settings::default() };
    let client = client::start(first, Ask::New, settings, &mut OsEntropy).await.expect("the session starts");
    let (mut app, theirs) = tokio::io::duplex(PIPE);
    let notes: Arc<Mutex<Vec<Note>>> = Arc::default();
    let heard = notes.clone();
    tokio::spawn(async move {
        let note = move |n: Note| heard.lock().unwrap().push(n);
        carry(&dialer, client, theirs, note).await
    });
    // Warm: the link's round trip is known, so the spare's wait is short.
    for n in 0..5u8 {
        round(&mut app, &[n; 64], LIMIT).await.expect("an echo before the cut");
    }
    assert_eq!(accepts.load(Ordering::SeqCst), 1, "the first link opened one connection");
    held.store(true, Ordering::SeqCst);
    let cut = Instant::now();
    // The spare's longest wait is the timer under test; the work after it
    // (TCP, TLS, HTTP/2, the resume) scales on an emulator.
    let bound = pod_session::beside::SPARE_AFTER + pod_testkit::host::scaled(Duration::from_secs(4));
    let resumed = round(&mut app, b"after the cut", bound).await;
    let notes = notes.lock().unwrap().clone();
    resumed.unwrap_or_else(|why| panic!("the session resumed after {:?}: {why}; notes {notes:?}", cut.elapsed()));
    assert_eq!(accepts.load(Ordering::SeqCst), 2, "the spare opened a second connection; notes {notes:?}");
    assert!(notes.iter().any(|n| matches!(n, Note::Spare { .. })), "a spare opened: {notes:?}");
    assert!(notes.iter().any(|n| matches!(n, Note::Resumed { .. })), "the spare took the session: {notes:?}");
    let _ = std::fs::remove_dir_all(dir);
}

/// The first session's TCP connection goes silent: a new session to the
/// same host first asks for a place on it, gets no answer to its CONNECT
/// nor to a PING, and opens a second TCP connection, on which it works;
/// the held connection would hold the CONNECT for the whole timeout.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_new_session_beside_a_silent_connection_of_http2_takes_a_new_one() {
    pod_testkit::need_loopback!();
    let (role_port, root) = role("new").await;
    let dir = root.parent().unwrap().to_path_buf();
    let (port, accepts, held) = proxy(role_port).await;
    let ctx = context();
    let relay = Relay { host: NAME.into(), port };
    let one = Dialer::new(&ctx, relay.clone(), "target.test", 22, Trust::File(root.clone())).unwrap();
    let first = tokio::time::timeout(LIMIT, one.link(&mut |_| {})).await.expect("the first link in time");
    let first = first.unwrap_or_else(|missed| panic!("the first link: {:?}", missed.lines("target.test:22")));
    let _kept = client::start(first, Ask::New, Settings::default(), &mut OsEntropy).await.expect("the first session");
    assert_eq!(accepts.load(Ordering::SeqCst), 1, "the first session opened one connection");
    held.store(true, Ordering::SeqCst);
    let cut = Instant::now();
    // The waits of the CONNECT's answer and of the PING are the timers
    // under test; the work after them (TCP, TLS, HTTP/2, the session)
    // scales on an emulator.
    let bound =
        pod_ws::h2_road::ANSWER_WAIT + pod_ws::h2_road::PING_WAIT + pod_testkit::host::scaled(Duration::from_secs(4));
    let two = Dialer::new(&ctx, relay, "target.test", 22, Trust::File(root)).unwrap();
    let second = async {
        let link = two.link(&mut |_| {}).await.map_err(|missed| format!("{:?}", missed.lines("target.test:22")))?;
        let session = client::start(link, Ask::New, Settings::default(), &mut OsEntropy).await;
        session.map_err(|e| format!("the session: {e:?}"))
    };
    let second = tokio::time::timeout(bound, second).await;
    let second = second.unwrap_or_else(|_| panic!("no second session within {:?}", cut.elapsed()));
    let second = second.unwrap_or_else(|why| panic!("the second session after {:?}: {why}", cut.elapsed()));
    assert_eq!(accepts.load(Ordering::SeqCst), 2, "the second session opened a second connection");
    let (mut app, theirs) = tokio::io::duplex(PIPE);
    tokio::spawn(async move { carry(&two, second, theirs, |_| {}).await });
    round(&mut app, b"on the new connection", bound).await.expect("an echo on the second session");
    let _ = std::fs::remove_dir_all(dir);
}
