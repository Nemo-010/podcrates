//! The EICE road against a stand-in of an endpoint on the loopback: TLS for
//! the endpoint's DNS name with the stand-in's root in a file, reached
//! through the caller's way, whose dialer takes port 443 to the stand-in.
//! The upgrade goes to `/openTunnel` with a URL presigned for it, as the
//! way's user agent, and binary messages go both ways after it; a refusal
//! that quotes what it was sent is a typed failure that shows no part of
//! the credential or of the URL; a credential that cannot go in a URL is
//! refused before anything connects.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pod_core::{Class, Failure, Stage};
use pod_egress::eice::{self, Credentials, Endpoint, Target};
use pod_tls::Trust;
use pod_ws::client::ConnectError;
use pod_ws::frame::{self as wsf, Frame, Role};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::net::TcpListener;
use zeroize::Zeroizing;

// Shared test support; this file uses part of it.
#[allow(dead_code)]
mod cert {
    include!("../../pod-tls/tests/common/cert_for_test.rs");
}

#[path = "common/way.rs"]
mod way;

const DNS: &str = "eice-0123456789example.b67b86ba.ec2-instance-connect-endpoint.us-west-2.amazonaws.com";
const KEY: &str = "AKIDEXAMPLE";
const TOKEN: &str = "IQoJb3JpZ2luX2VjEXAMPLE/Token+With=Signs";
const LIMIT: Duration = Duration::from_secs(20);

/// What the stand-in does after the head of an upgrade.
#[derive(Clone, Copy)]
enum Mode {
    /// 101, then an echo of each binary message.
    Echo,
    /// 403, with a body that quotes the credential and the request line.
    Refuse,
}

/// The head of each upgrade that the stand-in read, and the SNI.
type Seen = Arc<Mutex<Vec<(String, Option<String>)>>>;

fn credentials(secret: &str) -> Credentials {
    Credentials {
        access_key_id: Zeroizing::new(KEY.into()),
        secret_access_key: Zeroizing::new(secret.into()),
        session_token: Some(Zeroizing::new(TOKEN.into())),
    }
}

fn target() -> Target {
    Target { address: "10.0.1.5".parse().unwrap(), port: 22, max_duration: Some(600) }
}

fn root_file(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pod-egress-eice-{}-{tag}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("root.pem");
    let der = cert::encoding::self_signed_inner(&cert::encoding::anchor_name(DNS), true).der;
    std::fs::write(&path, cert::encoding::pem(&der)).unwrap();
    path
}

async fn head_of<S: AsyncRead + Unpin>(s: &mut S) -> Option<String> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match s.read(&mut byte).await {
            Ok(1) => head.push(byte[0]),
            _ => return None,
        }
    }
    Some(String::from_utf8_lossy(&head).into_owned())
}

fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.split("\r\n")
        .filter_map(|l| l.split_once(':'))
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.trim())
}

async fn serve<S: AsyncRead + AsyncWrite + Unpin>(mut s: S, sni: Option<String>, mode: Mode, seen: Seen) {
    let Some(head) = head_of(&mut s).await else { return };
    seen.lock().unwrap().push((head.clone(), sni));
    let line = head.lines().next().unwrap_or_default().to_string();
    if let Mode::Refuse = mode {
        let body = format!("denied for {KEY} ({TOKEN}): {line}");
        let answer =
            format!("HTTP/1.1 403 Forbidden\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
        let _ = s.write_all(answer.as_bytes()).await;
        return;
    }
    let key = header(&head, "Sec-WebSocket-Key").unwrap_or_default();
    let answer = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Accept: {}\r\n\r\n",
        pod_ws::handshake::accept_key(key)
    );
    if s.write_all(answer.as_bytes()).await.is_err() {
        return;
    }
    let (mut buf, mut chunk) = (Vec::new(), vec![0u8; 16 * 1024]);
    loop {
        while let Ok(Some((f, used))) = wsf::decode(&buf, Role::Client) {
            buf.drain(..used);
            if f.opcode != wsf::OPCODE_BINARY {
                return;
            }
            let back = Frame { fin: true, opcode: wsf::OPCODE_BINARY, payload: f.payload };
            if s.write_all(&wsf::encode(&back, Role::Server, [0; 4])).await.is_err() {
                return;
            }
        }
        match s.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
}

/// A stand-in of the endpoint, with TLS for its name.
async fn stand_in(mode: Mode) -> (u16, Seen) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen: Seen = Arc::default();
    let acceptor = cert::server_for(DNS).unwrap().0;
    let shared = seen.clone();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let (seen, acceptor) = (shared.clone(), acceptor.clone());
            tokio::spawn(async move {
                if let Ok(tls) = acceptor.accept(tcp).await {
                    let sni = tls.get_ref().1.server_name().map(str::to_string);
                    serve(tls, sni, mode, seen).await;
                }
            });
        }
    });
    (port, seen)
}

/// The tunnel goes to the endpoint's name on port 443 through the way, with
/// TLS for that name; the upgrade is awscrt's, to a URL presigned for this
/// target, with the way's user agent and no subprotocol; then bytes go both
/// ways in binary messages.
#[tokio::test]
async fn an_eice_tunnel_goes_through_the_way_with_a_url_signed_for_it() {
    pod_testkit::need_loopback!();
    let (port, seen) = stand_in(Mode::Echo).await;
    let (way, asked) = way::aimed(port);
    let root = root_file("tunnel");
    let endpoint = Endpoint::parse(DNS).unwrap();
    let session = eice::connect(&endpoint, &target(), &credentials("secret"), &way, &Trust::File(root.clone()), LIMIT)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    session.send_binary(b"SSH-2.0-test\r\n").await.unwrap();
    let back = tokio::time::timeout(LIMIT, session.read_frame()).await.unwrap().unwrap();
    assert_eq!((back.opcode, back.payload.as_slice()), (wsf::OPCODE_BINARY, &b"SSH-2.0-test\r\n"[..]));
    assert_eq!(*asked.lock().unwrap(), vec![format!("{DNS}:443")]);
    let (head, sni) = seen.lock().unwrap()[0].clone();
    assert_eq!(sni.as_deref(), Some(DNS));
    let line = head.lines().next().unwrap();
    let want = "GET /openTunnel?instanceConnectEndpointId=eice-0123456789example&remotePort=22\
                &privateIpAddress=10.0.1.5&maxTunnelDuration=600&X-Amz-Algorithm=AWS4-HMAC-SHA256\
                &X-Amz-Credential=AKIDEXAMPLE%2F";
    assert!(line.starts_with(want), "{line}");
    for part in ["%2Fus-west-2%2Fec2-instance-connect%2Faws4_request&", "&X-Amz-Expires=60&", "&X-Amz-Signature="] {
        assert!(line.contains(part), "{part}: {line}");
    }
    assert!(line.contains("&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEXAMPLE%2FToken%2BWith%3DSigns&"), "{line}");
    assert_eq!(header(&head, "Host"), Some(DNS));
    assert_eq!(header(&head, "User-Agent"), Some(way::USER_AGENT));
    assert_eq!(header(&head, "Sec-WebSocket-Protocol"), None);
    let _ = std::fs::remove_dir_all(root.parent().unwrap());
}

/// A refusal that quotes the key, the token and the request line shows
/// none of them, and is a failure of the upgrade, of the class refused.
#[tokio::test]
async fn an_eice_refusal_is_a_typed_failure_and_shows_no_credential() {
    pod_testkit::need_loopback!();
    let (port, seen) = stand_in(Mode::Refuse).await;
    let (way, _) = way::aimed(port);
    let root = root_file("refusal");
    let endpoint = Endpoint::parse(DNS).unwrap();
    let (target, credentials, trust) = (target(), credentials("secret"), Trust::File(root.clone()));
    let Err(e) = eice::connect(&endpoint, &target, &credentials, &way, &trust, LIMIT).await else {
        panic!("the endpoint took the tunnel")
    };
    let ConnectError::Refused { status: 403, body } = &e else { panic!("{e}") };
    assert!(body.starts_with("denied for <not shown>"), "{body}");
    for secret in [KEY, "IQoJb3JpZ2luX2VjEXAMPLE", "X-Amz-Signature", "X-Amz-Credential", "Token%2BWith"] {
        assert!(!body.contains(secret), "{secret}: {body}");
    }
    assert_eq!(seen.lock().unwrap().len(), 1, "the stand-in saw the upgrade");
    let failure = Failure::from(e);
    assert_eq!((failure.stage, failure.class), (Stage::WebSocket, Class::Refused));
    assert!(!failure.chain().contains(KEY), "{}", failure.chain());
    let _ = std::fs::remove_dir_all(root.parent().unwrap());
}

/// A credential with a space cannot go in a URL: it is refused by its
/// name, before the way dials anything.
#[tokio::test]
async fn an_eice_credential_that_cannot_go_in_a_url_is_refused_before_a_dial() {
    pod_testkit::need_loopback!();
    let (port, seen) = stand_in(Mode::Echo).await;
    let (way, asked) = way::aimed(port);
    let endpoint = Endpoint::parse(DNS).unwrap();
    let spaced = Credentials { access_key_id: Zeroizing::new("AKID WITH SPACE".into()), ..credentials("secret") };
    let Err(e) = eice::connect(&endpoint, &target(), &spaced, &way, &Trust::Default, LIMIT).await else {
        panic!("a credential with a space was taken")
    };
    let ConnectError::Config(why) = &e else { panic!("{e}") };
    assert!(why.contains("access key id") && !why.contains("WITH SPACE"), "{why}");
    assert!(asked.lock().unwrap().is_empty(), "the way dialed {:?}", asked.lock().unwrap());
    assert!(seen.lock().unwrap().is_empty());
    let failure = Failure::from(e);
    assert_eq!((failure.stage, failure.class), (Stage::WebSocket, Class::Config));
}
