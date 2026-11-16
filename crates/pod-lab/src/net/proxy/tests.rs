//! The stand-ins with the served ports of a command, on the loopback of the
//! test: the stand-in proxy and the stand-in server run in threads, and
//! "the command" is a server of the test.

use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use pod_hostprobe::probes::send::hello::client_hello;

use super::BODY;
use crate::net::local::Local;
use crate::net::tls::{Cas, client, server_name};
use crate::net::wire::{header, read_head, status};
use crate::net::{Ca, LISTED, NO_PROXY, Net, OPEN, OTHER, Proxy, credential};

const WAIT: Duration = Duration::from_secs(10);
/// The body of each answer of the server of the command.
const SERVED: &str = "served by the command\n";

static OPEN_LAB: Net = Net { proxy: Some(Proxy { auth: true, silent: &[22], ..OPEN }), ..NO_PROXY };
static TERMINATE: Net = Net { proxy: Some(Proxy { reterminate: &[LISTED], refuse_upgrade: true, ..OPEN }), ..NO_PROXY };
static SNI: Net = Net { outside_v4: true, sni: Some(&[LISTED]), ..NO_PROXY };

/// A listener of the test, and a thread that runs `each` on each
/// connection.
fn listen(each: impl Fn(TcpStream) + Send + Sync + 'static) -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let each = Arc::new(each);
    std::thread::spawn(move || {
        for tcp in l.incoming().flatten() {
            let each = Arc::clone(&each);
            std::thread::spawn(move || each(tcp));
        }
    });
    port
}

/// The plain server of the command: `served` and the first bytes it
/// reads.
fn echo() -> u16 {
    listen(|mut s| {
        let mut b = [0u8; 64];
        let n = s.read(&mut b).unwrap_or(0);
        let _ = s.write_all(format!("served {}", String::from_utf8_lossy(&b[..n])).as_bytes());
    })
}

/// The stand-in proxy of `net` with the served ports of `served`.
fn proxy(net: &'static Net, served: Local) -> (u16, Arc<Cas>) {
    let cas = Arc::new(Cas::new().unwrap());
    let served: &'static Local = Box::leak(Box::new(served));
    let c = Arc::clone(&cas);
    let port = listen(move |tcp| super::proxy(&c, net, net.proxy.as_ref().unwrap(), tcp, None, served));
    (port, cas)
}

/// A `CONNECT` to `target`: the status and the stream.
fn via(proxy: u16, target: &str, auth: bool) -> (u16, TcpStream) {
    let mut s = TcpStream::connect(("127.0.0.1", proxy)).unwrap();
    s.set_read_timeout(Some(WAIT)).unwrap();
    let auth = if auth { format!("Proxy-Authorization: {}\r\n", credential()) } else { String::new() };
    s.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n{auth}\r\n").as_bytes()).unwrap();
    let head = read_head(&mut s).unwrap();
    (status(&head).unwrap(), s)
}

/// Write `what`, and read to the end.
fn said(mut s: impl Read + Write, what: &str) -> String {
    s.write_all(what.as_bytes()).unwrap();
    let mut got = Vec::new();
    let _ = s.read_to_end(&mut got);
    String::from_utf8_lossy(&got).into_owned()
}

#[test]
fn a_connect_to_a_name_of_the_lab_at_a_served_port_reaches_the_command() {
    pod_testkit::need_loopback!();
    let port = echo();
    let (at, _) = proxy(&OPEN_LAB, Local { ports: vec![port, 22], roots: None });
    for host in [LISTED, OTHER, "localhost", "127.0.0.1"] {
        let (code, s) = via(at, &format!("{host}:{port}"), true);
        assert_eq!(code, 200, "{host}");
        assert_eq!(said(s, "hello"), "served hello", "{host}");
    }
    // The rules of the class come first: the credential, the silent port.
    assert_eq!(via(at, &format!("{LISTED}:{port}"), false).0, 407);
    let (code, mut s) = via(at, &format!("{LISTED}:22"), true);
    s.write_all(b"SSH-2.0-test\r\n").unwrap();
    s.set_read_timeout(Some(Duration::from_millis(300))).unwrap();
    let silent =
        matches!(s.read(&mut [0u8; 8]), Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut));
    assert!(code == 200 && silent, "port 22: {code}, silent {silent}");
    // A name outside the lab, and a port that the command does not serve,
    // get the stand-in server.
    let get = format!("GET / HTTP/1.1\r\nHost: {LISTED}\r\n\r\n");
    for target in [format!("relay.example:{port}"), format!("{LISTED}:{}", echo())] {
        let (code, s) = via(at, &target, true);
        assert_eq!(code, 200, "{target}");
        assert!(said(s, &get).ends_with(BODY), "{target}");
    }
}

/// The TLS server of the command: a leaf of `LISTED` that `ca` signs, and
/// one answer with [`SERVED`].
fn tls_server(ca: &Cas) -> u16 {
    let config = ca.server(LISTED, Ca::Server).unwrap();
    listen(move |tcp| {
        let Ok(conn) = rustls::ServerConnection::new(Arc::clone(&config)) else { return };
        let mut s = rustls::StreamOwned::new(conn, tcp);
        if read_head(&mut s).is_ok() {
            super::answer(&mut s, "200 OK", SERVED);
        }
        s.conn.send_close_notify();
        let _ = s.flush();
    })
}

/// A TLS client of `LISTED` on `tcp` that trusts `root` alone.
fn tls(tcp: TcpStream, root: &Cas, ca: Ca) -> rustls::StreamOwned<rustls::ClientConnection, TcpStream> {
    let config = client(&[root.of(ca).der.clone()], true).unwrap();
    let conn = rustls::ClientConnection::new(config, server_name(LISTED).unwrap()).unwrap();
    rustls::StreamOwned::new(conn, tcp)
}

#[test]
fn a_served_port_that_the_class_terminates_is_checked_with_the_roots_and_refuses_an_upgrade() {
    pod_testkit::need_loopback!();
    let command = Cas::new().unwrap();
    let port = tls_server(&command);
    let get = format!("GET / HTTP/1.1\r\nHost: {LISTED}\r\n\r\n");
    // No roots: 502 for the name that the class terminates, a splice for
    // another name.
    let (at, _) = proxy(&TERMINATE, Local { ports: vec![port], roots: None });
    let (code, s) = via(at, &format!("{LISTED}:{port}"), false);
    assert_eq!(code, 502);
    assert!(said(s, "").contains("--serve-ca"));
    let (code, s) = via(at, &format!("{OTHER}:{port}"), false);
    assert_eq!(code, 200);
    assert!(said(tls(s, &command, Ca::Server), &get).ends_with(SERVED));
    // With the roots of the command: the leaf of the CA of the proxy, the
    // request to the command, and 403 for an upgrade.
    let mut roots = rustls::RootCertStore::empty();
    roots.add(command.server.der.clone()).unwrap();
    let (at, lab) = proxy(&TERMINATE, Local { ports: vec![port], roots: Some(Arc::new(roots)) });
    let (code, s) = via(at, &format!("{LISTED}:{port}"), false);
    assert_eq!(code, 200);
    let answer = said(tls(s, &lab, Ca::Proxy), &get);
    assert!(answer.starts_with("HTTP/1.1 200") && answer.ends_with(SERVED), "{answer:?}");
    let (_, s) = via(at, &format!("{LISTED}:{port}"), false);
    let upgrade = format!("GET / HTTP/1.1\r\nHost: {LISTED}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n");
    let answer = said(tls(s, &lab, Ca::Proxy), &upgrade);
    assert!(answer.starts_with("HTTP/1.1 403"), "{answer:?}");
    assert_eq!(header(&answer, "content-length"), Some("0"));
}

/// The stand-in server of `SNI` with the served ports of `served`.
fn sni_server(served: Local) -> (u16, Arc<Cas>) {
    let cas = Arc::new(Cas::new().unwrap());
    let served: &'static Local = Box::leak(Box::new(served));
    let c = Arc::clone(&cas);
    let port = listen(move |tcp| super::server(&c, &SNI, tcp, None, Ca::Server, false, served));
    (port, cas)
}

/// A ClientHello with `name` to the stand-in server: the answer, or
/// `reset`.
fn hello(at: u16, name: Option<&str>) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", at)).unwrap();
    s.set_read_timeout(Some(WAIT)).unwrap();
    s.write_all(&client_hello(name, [7; 32])).unwrap();
    let mut got = Vec::new();
    match s.read_to_end(&mut got) {
        Err(e) if e.kind() == ErrorKind::ConnectionReset => "reset".to_string(),
        _ => String::from_utf8_lossy(&got).into_owned(),
    }
}

#[test]
fn a_client_hello_with_a_listed_name_reaches_the_first_served_port() {
    pod_testkit::need_loopback!();
    // The server of the command reads the whole first record.
    let port = listen(|mut s| {
        let mut head = [0u8; 5];
        if s.read_exact(&mut head).is_ok() {
            let mut body = vec![0u8; usize::from(u16::from_be_bytes([head[3], head[4]]))];
            if s.read_exact(&mut body).is_ok() {
                let _ = s.write_all(SERVED.as_bytes());
            }
        }
    });
    let (at, _) = sni_server(Local { ports: vec![port], roots: None });
    assert_eq!(hello(at, Some(LISTED)), SERVED);
    assert_eq!(hello(at, Some(OTHER)), "reset");
    assert_eq!(hello(at, None), "reset");
    // Where no server of the command listens, the stand-in answers.
    let (at, cas) = sni_server(Local { ports: vec![1], roots: None });
    let tcp = TcpStream::connect(("127.0.0.1", at)).unwrap();
    tcp.set_read_timeout(Some(WAIT)).unwrap();
    let get = format!("GET / HTTP/1.1\r\nHost: {LISTED}\r\n\r\n");
    assert!(said(tls(tcp, &cas, Ca::Server), &get).ends_with(BODY));
}
