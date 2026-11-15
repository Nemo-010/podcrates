//! The IAP road against a stand-in of IAP's relay on the loopback: TLS for
//! `tunnel.cloudproxy.app` with the stand-in's root in a file, reached
//! through the caller's way, whose dialer takes port 443 to the stand-in.
//! A session opens on gcloud's upgrade with the token in its header alone,
//! as the way's user agent, and carries bytes both ways in IAP's messages;
//! a Close that refuses the account, before the session or on it, and a
//! refused upgrade are typed failures, and no refusal shows the token.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pod_core::{Class, Failure, Stage};
use pod_egress::Note;
use pod_egress::iap::carry::{self, Dial, Dialing, Ended, NotOpen};
use pod_egress::iap::{self, Resume, Target};
use pod_tls::Trust;
use pod_ws::Way;
use pod_ws::client::ConnectError;
use pod_ws::frame::{self as wsf, Frame, Role};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::net::TcpListener;

// Shared test support; this file uses part of it.
#[allow(dead_code)]
mod cert {
    include!("../../pod-tls/tests/common/cert_for_test.rs");
}

#[path = "common/way.rs"]
mod way;

const TOKEN: &str = "ya29.TEST-TOKEN-NOT-A-CREDENTIAL";
const LIMIT: Duration = Duration::from_secs(20);

/// What the stand-in does after the head of an upgrade.
#[derive(Clone, Copy)]
enum Mode {
    /// The connect's success, then each data message back as data.
    Echo,
    /// A Close with this code before the session.
    CloseFirst(u16),
    /// The connect's success, then a Close with this code.
    CloseAfter(u16),
    /// 403, with a body that quotes the request.
    Refuse,
}

type Seen = Arc<Mutex<Vec<String>>>;

fn target() -> Target {
    Target::new("a-project", "us-central1-a", "a-vm", 22).unwrap()
}

fn root_file(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pod-egress-iap-{}-{tag}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("root.pem");
    let der = cert::encoding::self_signed_inner(&cert::encoding::anchor_name(iap::HOST), true).der;
    std::fs::write(&path, cert::encoding::pem(&der)).unwrap();
    path
}

fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.split("\r\n")
        .filter_map(|l| l.split_once(':'))
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.trim())
}

/// IAP's messages, laid out by hand: a tag, then a length and its bytes.
fn array(tag: u16, bytes: &[u8]) -> Vec<u8> {
    let mut m = tag.to_be_bytes().to_vec();
    m.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    m.extend_from_slice(bytes);
    m
}

async fn send<S: AsyncWrite + Unpin>(s: &mut S, opcode: u8, payload: Vec<u8>) -> std::io::Result<()> {
    s.write_all(&wsf::encode(&Frame { fin: true, opcode, payload }, Role::Server, [0; 4])).await
}

fn close(code: u16) -> Vec<u8> {
    [&code.to_be_bytes()[..], b"said so"].concat()
}

async fn serve<S: AsyncRead + AsyncWrite + Unpin>(mut s: S, mode: Mode, seen: Seen) {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match s.read(&mut byte).await {
            Ok(1) => head.push(byte[0]),
            _ => return,
        }
    }
    let head = String::from_utf8_lossy(&head).into_owned();
    seen.lock().unwrap().push(head.clone());
    if let Mode::Refuse = mode {
        let body = format!("denied: {}", head.replace("\r\n", " "));
        let answer = format!("HTTP/1.1 403 Forbidden\r\nContent-Length: {}\r\n\r\n{body}", body.len());
        let _ = s.write_all(answer.as_bytes()).await;
        return;
    }
    let answer = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Accept: {}\r\nSec-WebSocket-Protocol: {}\r\n\r\n",
        pod_ws::handshake::accept_key(header(&head, "Sec-WebSocket-Key").unwrap_or_default()),
        iap::SUBPROTOCOL
    );
    if s.write_all(answer.as_bytes()).await.is_err() {
        return;
    }
    let first = match mode {
        Mode::CloseFirst(code) => send(&mut s, wsf::OPCODE_CLOSE, close(code)).await,
        _ => send(&mut s, wsf::OPCODE_BINARY, array(1, b"a-sid")).await,
    };
    if first.is_err() || matches!(mode, Mode::CloseFirst(_)) {
        return;
    }
    if let Mode::CloseAfter(code) = mode {
        let _ = send(&mut s, wsf::OPCODE_CLOSE, close(code)).await;
        return;
    }
    let (mut buf, mut chunk) = (Vec::new(), vec![0u8; 32 * 1024]);
    loop {
        while let Ok(Some((f, used))) = wsf::decode(&buf, Role::Client) {
            buf.drain(..used);
            if f.opcode != wsf::OPCODE_BINARY {
                return;
            }
            // Data comes back as data; an acknowledgement asks for nothing.
            if f.payload.starts_with(&4u16.to_be_bytes()) && send(&mut s, wsf::OPCODE_BINARY, f.payload).await.is_err()
            {
                return;
            }
        }
        match s.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
}

/// A stand-in of IAP's relay, with TLS for its name.
async fn stand_in(mode: Mode) -> (u16, Seen) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen: Seen = Arc::default();
    let acceptor = cert::server_for(iap::HOST).unwrap().0;
    let shared = seen.clone();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let (seen, acceptor) = (shared.clone(), acceptor.clone());
            tokio::spawn(async move {
                if let Ok(tls) = acceptor.accept(tcp).await {
                    serve(tls, mode, seen).await;
                }
            });
        }
    });
    (port, seen)
}

/// The links of a session, each through `way` with the token.
fn dial(way: Way, trust: Trust) -> Dial<pod_ws::url::Stream, ConnectError> {
    let target = target();
    Arc::new(move |resume: Option<Resume>| -> Dialing<pod_ws::url::Stream, ConnectError> {
        let (way, trust, target) = (way.clone(), trust.clone(), target.clone());
        Box::pin(async move { iap::connect(&target, resume.as_ref(), TOKEN, &way, &trust, LIMIT).await })
    })
}

fn quiet() -> Note {
    Arc::new(pod_core::NoEvents)
}

/// The session goes to IAP's name on port 443 through the way, with TLS for
/// that name; the upgrade is gcloud's, with the token in its header alone
/// and the way's user agent; then bytes go both ways.
#[tokio::test]
async fn an_iap_session_goes_through_the_way_with_its_token_in_a_header() {
    pod_testkit::need_loopback!();
    let (port, seen) = stand_in(Mode::Echo).await;
    let (way, asked) = way::aimed(port);
    let root = root_file("session");
    let (stream, carried) =
        carry::open(dial(way, Trust::File(root.clone())), quiet()).await.unwrap_or_else(|e| panic!("{e}"));
    let (mut from, mut to) = tokio::io::split(stream);
    let sent: Vec<u8> = (0..40_000u32).map(|i| (i % 251) as u8).collect();
    to.write_all(&sent).await.unwrap();
    let mut back = vec![0u8; sent.len()];
    tokio::time::timeout(LIMIT, from.read_exact(&mut back)).await.unwrap().unwrap();
    assert!(back == sent, "the bytes came back changed");
    assert_eq!(carried.get(), None, "the session is open");
    assert_eq!(*asked.lock().unwrap(), vec![format!("{}:443", iap::HOST)]);
    let head = seen.lock().unwrap()[0].clone();
    let line = head.lines().next().unwrap();
    assert_eq!(
        line,
        "GET /v4/connect?project=a-project&port=22&newWebsocket=True&zone=us-central1-a&instance=a-vm\
         &interface=nic0 HTTP/1.1"
    );
    assert_eq!(header(&head, "Authorization"), Some(format!("Bearer {TOKEN}").as_str()));
    assert_eq!(header(&head, "Sec-WebSocket-Protocol"), Some(iap::SUBPROTOCOL));
    assert_eq!(header(&head, "Origin"), Some(iap::ORIGIN));
    assert_eq!(header(&head, "User-Agent"), Some(way::USER_AGENT));
    let _ = std::fs::remove_dir_all(root.parent().unwrap());
}

/// A Close 4033 before the session is a refusal of the upgrade's stage; a
/// Close 4047 is no such VM, at the origin; a Close 4033 on an open session
/// ends it with the same failure; a refused upgrade is the dial's own
/// failure, of the class refused, and shows no part of the token.
#[tokio::test]
async fn an_iap_refusal_of_the_account_is_a_typed_failure() {
    pod_testkit::need_loopback!();
    let root = root_file("refusal");
    let trust = Trust::File(root.clone());
    for (code, stage, class) in [
        (4033, Stage::WebSocket, Class::Refused),
        (4047, Stage::Origin, Class::NotFound),
        (4003, Stage::Origin, Class::Unavailable),
    ] {
        let (port, _) = stand_in(Mode::CloseFirst(code)).await;
        let not = carry::open(dial(way::aimed(port).0, trust.clone()), quiet()).await.err().expect("no session");
        assert!(matches!(&not, NotOpen::Closed { code: Some(c), .. } if *c == code), "{not}");
        let failure = Failure::from(not);
        assert_eq!((failure.stage, failure.class), (stage, class), "{code}: {failure}");
        assert!(failure.text().contains(&code.to_string()), "{failure}");
    }
    let (port, _) = stand_in(Mode::CloseAfter(4033)).await;
    let (_stream, mut carried) = carry::open(dial(way::aimed(port).0, trust.clone()), quiet()).await.unwrap();
    let end = tokio::time::timeout(LIMIT, carried.ended()).await.unwrap();
    assert!(matches!(&end, Ended::Closed { code: Some(4033), .. }), "{end:?}");
    let failure = end.failure().expect("a refusal is a failure");
    assert_eq!((failure.stage, failure.class), (Stage::WebSocket, Class::Refused), "{failure}");
    assert!(Ended::Normal.failure().is_none());
    let (port, seen) = stand_in(Mode::Refuse).await;
    let not = carry::open(dial(way::aimed(port).0, trust), quiet()).await.err().expect("no session");
    assert_eq!(seen.lock().unwrap().len(), 1, "the stand-in saw the upgrade");
    let NotOpen::Dial(ConnectError::Refused { status: 403, body }) = &not else { panic!("{not}") };
    assert!(body.starts_with("denied: GET /v4/connect?"), "{body}");
    assert!(!body.contains("TEST-TOKEN"), "the token was shown: {body}");
    let failure = Failure::from(not);
    assert_eq!((failure.stage, failure.class), (Stage::WebSocket, Class::Refused), "{failure}");
    let _ = std::fs::remove_dir_all(root.parent().unwrap());
}
