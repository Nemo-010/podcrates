//! The headers of the caller for a host (`pod_ws::Headers`, a credential of
//! a gate in front of the relay such as Cloudflare Access) on each road of
//! the crate, against a stand-in on the loopback that reads each request's
//! head: the upgrade of HTTP/1.1 over TLS, the CONNECT of HTTP/2 (RFC
//! 8441), the cleartext road, a WebSocket that a URL names, an HTTPS POST,
//! and plain `ws://` to the loopback. The stand-in quotes the value that it
//! got back in each refusal, as a careless edge may: no refusal shows it,
//! and a 401 or a 403 keeps its status. A value with a control character
//! is refused before any connection.

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use pod_ws::headers::{Header, MASK, Zeroizing};
use pod_ws::{ConnectError, Endpoint, Headers, Trust, Way, WsClientConfig, h2_road};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;

#[allow(dead_code)]
mod cert {
    include!("../../pod-tls/tests/common/cert_for_test.rs");
}
mod common;

const NAME: &str = "relay.access.test";
const TOKEN: &str = "token-of-the-test";
const ID: &str = "made-up-id.access";
const SECRET: &str = "made-up-secret-of-the-test-0123";
const PATH: &str = "/connect/127.0.0.1/22";
const LIMIT: Duration = Duration::from_secs(20);

/// The access headers for [`NAME`], none for another host.
fn access(host: &str) -> Vec<Header> {
    if host != NAME {
        return Vec::new();
    }
    vec![("CF-Access-Client-Id", Zeroizing::new(ID.into())), ("CF-Access-Client-Secret", Zeroizing::new(SECRET.into()))]
}

/// A request's head as the stand-in got it: its target and its headers,
/// names in lowercase, in their order where HTTP/1.1 carried them.
#[derive(Debug, Clone)]
struct Asked {
    target: String,
    headers: Vec<(String, String)>,
}

impl Asked {
    fn get(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(n, _)| n == name).map(|(_, v)| v.as_str())
    }

    /// The names from the token on, as HTTP/1.1 carried them.
    fn after_token(&self) -> Vec<&str> {
        let names: Vec<&str> = self.headers.iter().map(|(n, _)| n.as_str()).collect();
        let at = names.iter().position(|n| *n == "x-relay-token").unwrap_or(names.len());
        names[at..].iter().copied().take(3).collect()
    }
}

#[derive(Default)]
struct Seen {
    accepted: AtomicUsize,
    asked: Mutex<Vec<Asked>>,
}

impl Seen {
    fn last(&self) -> Asked {
        self.asked.lock().unwrap().last().cloned().expect("a request")
    }
}

/// What the stand-in answers to `asked`: a target that ends in `/401` or
/// `/403` is that refusal, with the secret that came quoted back; else the
/// answer of `ok`.
fn refusal_of(asked: &Asked) -> Option<(u16, String)> {
    let status = [401u16, 403].into_iter().find(|s| asked.target.ends_with(&format!("/{s}")))?;
    Some((status, format!("access denied for {}", asked.get("cf-access-client-secret").unwrap_or("none"))))
}

/// The stand-in: TLS for [`NAME`] (HTTP/2 with extended CONNECT, or
/// HTTP/1.1, as ALPN chose) on one port, plain TCP on the other.
async fn stand_in() -> (u16, u16, Arc<Seen>) {
    let (acceptor, _) = cert::server_for(NAME).unwrap();
    let mut tls = (**acceptor.config()).clone();
    tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
    let (secure, plain) =
        (TcpListener::bind("127.0.0.1:0").await.unwrap(), TcpListener::bind("127.0.0.1:0").await.unwrap());
    let ports = (secure.local_addr().unwrap().port(), plain.local_addr().unwrap().port());
    let seen: Arc<Seen> = Arc::default();
    let kept = seen.clone();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = secure.accept().await {
            let (acceptor, seen) = (acceptor.clone(), kept.clone());
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else { return };
                seen.accepted.fetch_add(1, Ordering::SeqCst);
                if tls.get_ref().1.alpn_protocol() == Some(b"h2".as_slice()) {
                    serve_h2(tls, seen).await;
                } else {
                    serve_h1(tls, seen).await;
                }
            });
        }
    });
    let kept = seen.clone();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = plain.accept().await {
            kept.accepted.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(serve_h1(tcp, kept.clone()));
        }
    });
    (ports.0, ports.1, seen)
}

async fn serve_h1<S: AsyncRead + AsyncWrite + Unpin>(mut io: S, seen: Arc<Seen>) {
    let Ok((head, _)) = pod_proxy::http::request::read_request(&mut io, Vec::new()).await else { return };
    let asked = Asked { target: head.target.clone(), headers: head.headers.clone() };
    seen.asked.lock().unwrap().push(asked.clone());
    if let Some((status, words)) = refusal_of(&asked) {
        let body = words.into_bytes();
        let head = format!("HTTP/1.1 {status} No\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
        let _ = io.write_all(&[head.into_bytes(), body].concat()).await;
        return close(io).await;
    }
    if head.method == "POST" {
        let _ = io.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}").await;
        return close(io).await;
    }
    let Ok(key) = pod_ws::server::check_upgrade(&head) else { return };
    let _ = io.write_all(&pod_ws::server::switching(&key)).await;
    // Held open until the client goes.
    let mut rest = [0u8; 64];
    while matches!(tokio::io::AsyncReadExt::read(&mut io, &mut rest).await, Ok(n) if n > 0) {}
}

/// End the answer, then read until the client goes: a socket closed with
/// bytes of the request unread (a body) sends a reset, which can come
/// before the client reads the answer.
async fn close<S: AsyncRead + AsyncWrite + Unpin>(mut io: S) {
    let _ = tokio::io::AsyncWriteExt::shutdown(&mut io).await;
    let mut rest = [0u8; 256];
    let drain = async { while matches!(tokio::io::AsyncReadExt::read(&mut io, &mut rest).await, Ok(n) if n > 0) {} };
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), drain).await;
}

async fn serve_h2<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(io: S, seen: Arc<Seen>) {
    let mut builder = h2::server::Builder::new();
    builder.enable_connect_protocol();
    let Ok(mut connection) = builder.handshake::<_, Bytes>(io).await else { return };
    while let Some(Ok((request, mut respond))) = connection.accept().await {
        let headers = request.headers().iter();
        let headers = headers.map(|(n, v)| (n.as_str().to_string(), v.to_str().unwrap_or_default().to_string()));
        let target = request.uri().path().to_string();
        let asked = Asked { target, headers: headers.collect() };
        seen.asked.lock().unwrap().push(asked.clone());
        let refused = refusal_of(&asked);
        let status = refused.as_ref().map_or(200, |(status, _)| *status);
        let answer = http::Response::builder().status(status).body(()).unwrap();
        let Ok(mut send) = respond.send_response(answer, false) else { continue };
        match refused {
            Some((_, words)) => drop(send.send_data(Bytes::from(words), true)),
            // The stream of a session stays until the connection ends.
            None => std::mem::forget((send, request)),
        }
    }
}

fn root_file(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pod-ws-caller-headers-{}-{tag}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("root.pem");
    let der = cert::encoding::self_signed_inner(&cert::encoding::anchor_name(NAME), true).der;
    std::fs::write(&path, cert::encoding::pem(&der)).unwrap();
    path
}

fn way(headers: Headers) -> Way {
    let lo: IpAddr = "127.0.0.1".parse().unwrap();
    common::way_with_pins(&[(NAME, lo)]).with_headers(headers)
}

fn config(port: u16, path: &str, root: &std::path::Path, headers: Headers) -> WsClientConfig {
    WsClientConfig {
        endpoint: Endpoint { host: NAME.into(), port, path: path.into() },
        trust: Trust::File(root.to_path_buf()),
        server_name: NAME.into(),
        timeout: LIMIT,
        idle_timeout: Some(LIMIT),
        way: way(headers),
        limits: pod_ws::Limits::default(),
    }
}

/// A refusal of `status` whose words show no value of the caller.
fn assert_masked(e: &ConnectError, status: u16) {
    let ConnectError::Refused { status: got, body } = e else { panic!("a refusal: {e:?}") };
    assert_eq!(*got, status, "the status stays: {e:?}");
    assert_eq!(body, &format!("access denied for {MASK}"), "{e:?}");
    assert!(!e.to_string().contains(SECRET), "{e}");
}

/// The upgrade of HTTP/1.1 over TLS and the CONNECT of HTTP/2 carry the
/// headers after the token; a 401 and a 403 keep their status and show no
/// value.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_tls_roads_carry_the_headers_after_the_token() {
    pod_testkit::need_loopback!();
    let root = root_file("tls");
    let (port, _, seen) = stand_in().await;
    let headers = Headers::new(access);
    pod_ws::connect(&config(port, PATH, &root, headers.clone()), TOKEN).await.expect("a session over HTTP/1.1");
    let asked = seen.last();
    assert_eq!(asked.after_token(), ["x-relay-token", "cf-access-client-id", "cf-access-client-secret"]);
    assert_eq!((asked.get("cf-access-client-id"), asked.get("cf-access-client-secret")), (Some(ID), Some(SECRET)));
    let pool = h2_road::Pool::new();
    let config_h2 = config(port, PATH, &root, headers.clone());
    let (_session, road) = h2_road::connect(&pool, &config_h2, TOKEN).await.expect("a session over HTTP/2");
    assert!(matches!(road, h2_road::Road::Stream { .. }), "{road:?}");
    let asked = seen.last();
    assert_eq!(asked.get("x-relay-token"), Some(TOKEN));
    assert_eq!((asked.get("cf-access-client-id"), asked.get("cf-access-client-secret")), (Some(ID), Some(SECRET)));
    for status in [401, 403] {
        let path = format!("/connect/deny.example/{status}");
        let e = pod_ws::connect(&config(port, &path, &root, headers.clone()), TOKEN).await.unwrap_err();
        assert_masked(&e, status);
        let e = h2_road::connect(&pool, &config(port, &path, &root, headers.clone()), TOKEN).await.unwrap_err();
        assert_masked(&e, status);
    }
    // Another host gets none: the function of the caller decides.
    let other = Headers::new(|_| Vec::new());
    pod_ws::connect(&config(port, PATH, &root, other), TOKEN).await.expect("a session");
    assert_eq!(seen.last().get("cf-access-client-secret"), None);
    let _ = std::fs::remove_dir_all(root.parent().unwrap());
}

/// The cleartext road and `ws://` carry the headers only where the caller
/// allows them in cleartext; `wss://` and an HTTPS POST carry them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cleartext_carries_the_headers_only_where_the_caller_allows_it() {
    pod_testkit::need_loopback!();
    let root = root_file("cleartext");
    let (port, plain, seen) = stand_in().await;
    for (allowed, sent) in [(false, None), (true, Some(SECRET))] {
        let headers = Headers::new(access).in_cleartext(allowed);
        pod_ws::cleartext::connect(&config(plain, PATH, &root, headers.clone()), TOKEN).await.expect("cleartext");
        let asked = seen.last();
        assert_eq!(asked.get("cf-access-client-secret"), sent, "allowed: {allowed}");
        if allowed {
            assert_eq!(asked.after_token(), ["x-relay-token", "cf-access-client-id", "cf-access-client-secret"]);
        }
        let url = pod_ws::url::WsUrl::parse(&format!("ws://{NAME}:{plain}/x")).unwrap();
        pod_ws::url::dial(&url, &way(headers), &Trust::Default, LIMIT, None).await.expect("ws://");
        assert_eq!(seen.last().get("cf-access-client-secret"), sent, "ws:// allowed: {allowed}");
    }
    let trust = Trust::File(root.clone());
    let url = pod_ws::url::WsUrl::parse(&format!("wss://{NAME}:{port}/x")).unwrap();
    pod_ws::url::dial(&url, &way(Headers::new(access)), &trust, LIMIT, None).await.expect("wss://");
    assert_eq!(seen.last().get("cf-access-client-id"), Some(ID));
    let denied = pod_ws::url::WsUrl::parse(&format!("wss://{NAME}:{port}/deny/403")).unwrap();
    let e = pod_ws::url::dial(&denied, &way(Headers::new(access)), &trust, LIMIT, None).await.err().unwrap();
    assert_masked(&e, 403);
    let posted =
        pod_ws::client::https_post_json(&way(Headers::new(access)), NAME, port, "/v1/mint", b"{}", &trust, LIMIT)
            .await
            .expect("a POST");
    assert_eq!(posted.status, 200);
    assert_eq!(seen.last().get("cf-access-client-secret"), Some(SECRET));
    let refused =
        pod_ws::client::https_post_json(&way(Headers::new(access)), NAME, port, "/deny/401", b"{}", &trust, LIMIT)
            .await
            .expect("an answer");
    assert_eq!(refused.status, 401);
    assert_eq!(refused.body_text(200), format!("access denied for {MASK}"));
    let _ = std::fs::remove_dir_all(root.parent().unwrap());
}

/// A name or a value that would break the request is refused before any
/// connection, by the header's name and never its value.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_control_character_is_refused_before_any_byte() {
    pod_testkit::need_loopback!();
    let root = root_file("control");
    let (port, plain, seen) = stand_in().await;
    for bad in ["\r\nX-Evil: 1", "\0", "\x7f", "\x1b[2J"] {
        let value = format!("{SECRET}{bad}");
        let headers =
            Headers::new(move |_| vec![("CF-Access-Client-Secret", Zeroizing::new(value.clone()))]).in_cleartext(true);
        let pool = h2_road::Pool::new();
        let errors = [
            pod_ws::connect(&config(port, PATH, &root, headers.clone()), TOKEN).await.err(),
            h2_road::connect(&pool, &config(port, PATH, &root, headers.clone()), TOKEN).await.err(),
            pod_ws::cleartext::connect(&config(plain, PATH, &root, headers.clone()), TOKEN).await.err(),
        ];
        for e in errors {
            let e = e.expect("a refusal");
            assert!(matches!(e, ConnectError::Config(_)), "{e:?}");
            let said = e.to_string();
            assert!(said.contains("CF-Access-Client-Secret") && !said.contains(SECRET), "{said}");
        }
    }
    assert_eq!(seen.accepted.load(Ordering::SeqCst), 0, "no connection");
    let _ = std::fs::remove_dir_all(root.parent().unwrap());
}

/// Plain `ws://` to the loopback carries them as TLS does: the loopback is
/// this host.
#[cfg(feature = "plain-ws")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn plain_ws_to_the_loopback_carries_the_headers() {
    pod_testkit::need_loopback!();
    let (_, plain, seen) = stand_in().await;
    let extra = Headers::new(|_| access(NAME)).for_host("127.0.0.1").unwrap();
    pod_ws::plain::connect_loopback_carrying("127.0.0.1", plain, "/v1/node/x", TOKEN, &extra, LIMIT, None)
        .await
        .expect("a session");
    let asked = seen.last();
    assert_eq!(asked.after_token(), ["x-relay-token", "cf-access-client-id", "cf-access-client-secret"]);
    let e = pod_ws::plain::connect_loopback_carrying("127.0.0.1", plain, "/v1/node/403", TOKEN, &extra, LIMIT, None)
        .await
        .err()
        .unwrap();
    assert_masked(&e, 403);
}
