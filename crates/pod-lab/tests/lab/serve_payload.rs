//! The payloads of the served ports: this binary with `--payload KIND`
//! inside a network lab with `Options::serve`. Each one runs a server of
//! the command on `127.0.0.1:PORT` of the lab, then reaches it only by the
//! path of the class, and checks the rules of the class on the bytes.

use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::sync::Arc;

use pod_lab::net::{LISTED, OTHER};

use crate::net_payload::{connect, issuer, tls, via};

/// The body of each answer of the server of the command.
pub const SERVED: &str = "served by the command\n";
/// The files of the TLS server of the command in the directory of a case:
/// the CA (PEM), the leaf of `listed.test` (DER) and its P-256 scalar.
pub const CA_FILE: &str = "ca.pem";
pub const LEAF_FILE: &str = "leaf.der";
pub const KEY_FILE: &str = "leaf.key";

type Out = Result<String, String>;

pub fn main(kind: &str) -> Option<Out> {
    let (what, rest) = kind.split_once(':')?;
    let port = |p: &str| p.parse::<u16>().map_err(|_| format!("the port {p:?}"));
    Some(match (what, rest.split_once(':')) {
        ("serve-open", None) => port(rest).and_then(open),
        ("serve-noca", None) => port(rest).and_then(no_ca),
        ("serve-sni", None) => port(rest).and_then(sni),
        ("serve-tls", Some((p, dir))) => port(p).and_then(|p| terminated(p, Path::new(dir))),
        _ => return None,
    })
}

/// A server of the command on `127.0.0.1:port`: `each` on each connection,
/// in a thread.
fn listen(port: u16, each: fn(TcpStream)) -> Result<(), String> {
    let l = TcpListener::bind(("127.0.0.1", port)).map_err(|e| format!("a listener on port {port}: {e}"))?;
    std::thread::spawn(move || {
        for tcp in l.incoming().flatten() {
            std::thread::spawn(move || each(tcp));
        }
    });
    Ok(())
}

/// The plain server: `served` and the first bytes it reads.
fn echo(mut s: TcpStream) {
    let mut b = [0u8; 64];
    let n = s.read(&mut b).unwrap_or(0);
    let _ = s.write_all(format!("served {}", String::from_utf8_lossy(&b[..n])).as_bytes());
}

/// Write `what`, and read to the end: a reset or an end with no
/// `close_notify` keeps the bytes that came.
fn said(s: &mut (impl Read + Write), what: &str) -> Result<String, String> {
    s.write_all(what.as_bytes()).map_err(|e| format!("a write: {e}"))?;
    let mut got = Vec::new();
    match s.read_to_end(&mut got) {
        Err(e) if e.kind() == ErrorKind::ConnectionReset && got.is_empty() => Ok("reset".to_string()),
        _ => Ok(String::from_utf8_lossy(&got).into_owned()),
    }
}

/// `proxy-only`: the loopback and a name of the lab at the served port reach
/// the command with the credential; with none, 407; a port that the
/// command does not serve gets the stand-in.
fn open(port: u16) -> Out {
    listen(port, echo)?;
    for host in ["127.0.0.1", LISTED] {
        let (c, mut s) = via(&format!("{host}:{port}"), true)?;
        let got = said(&mut s, "ping")?;
        if (c, got.as_str()) != (200, "served ping") {
            return Err(format!("CONNECT {host}:{port}: {c} {got:?}"));
        }
    }
    let (no_auth, _) = via(&format!("{LISTED}:{port}"), false)?;
    let (c, mut s) = via(&format!("{LISTED}:80"), true)?;
    let got = said(&mut s, &format!("GET / HTTP/1.1\r\nHost: {LISTED}\r\n\r\n"))?;
    if no_auth != 407 || c != 200 || !got.ends_with("pod-lab stand-in\n") {
        return Err(format!("no credential {no_auth}, port 80 {c} {got:?}"));
    }
    Ok("127.0.0.1 and listed.test reach the command, 407 with no credential, port 80 the stand-in".to_string())
}

/// `proxy-tls-reterminate` with no roots of the command: 502 for the name
/// that the class terminates, a splice for another name.
fn no_ca(port: u16) -> Out {
    listen(port, echo)?;
    let (terminated, mut s) = via(&format!("{LISTED}:{port}"), true)?;
    let why = said(&mut s, "")?;
    let (c, mut s) = via(&format!("{OTHER}:{port}"), true)?;
    let got = said(&mut s, "ping")?;
    if terminated != 502 || !why.contains("--serve-ca") || (c, got.as_str()) != (200, "served ping") {
        return Err(format!("{LISTED}: {terminated} {why:?}; {OTHER}: {c} {got:?}"));
    }
    Ok("listed.test 502 with no roots, other.test reaches the command".to_string())
}

/// The TLS server of the command, with the leaf of `listed.test` of `dir`.
fn tls_config(dir: &Path) -> Result<Arc<rustls::ServerConfig>, String> {
    let read = |f: &str| std::fs::read(dir.join(f)).map_err(|e| format!("{f}: {e}"));
    let key = p256::ecdsa::SigningKey::from_slice(&read(KEY_FILE)?).map_err(|e| format!("the key: {e}"))?;
    let leaf = rustls_pki_types::CertificateDer::from(read(LEAF_FILE)?);
    let pair = pod_tls::server::certified_key(vec![leaf], key).map_err(|e| e.to_string())?;
    pod_tls::server::server_config_for(
        Arc::new(pod_tls::crypto::provider()),
        pod_tls::server::Served::new(Some(pair)),
        &[],
    )
    .map_err(|e| e.to_string())
}

/// A TLS client of `listed.test` that trusts the CA of the command alone.
fn command_client(
    tcp: TcpStream,
    dir: &Path,
) -> Result<rustls::StreamOwned<rustls::ClientConnection, TcpStream>, String> {
    let pem = std::fs::read(dir.join(CA_FILE)).map_err(|e| format!("{CA_FILE}: {e}"))?;
    let mut roots = rustls::RootCertStore::empty();
    for c in pod_tls::bundle::pem_certificates(&pem)? {
        roots.add(c).map_err(|e| e.to_string())?;
    }
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(pod_tls::crypto::provider()))
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let name = rustls_pki_types::ServerName::try_from(LISTED.to_string()).map_err(|e| e.to_string())?;
    let conn = rustls::ClientConnection::new(Arc::new(config), name).map_err(|e| e.to_string())?;
    Ok(rustls::StreamOwned::new(conn, tcp))
}

/// `ws-upgrade-refused` with the roots of the command: the proxy shows its
/// own leaf for `listed.test`, passes a request to the command, and refuses
/// an upgrade; `other.test` reaches the TLS of the command itself.
fn terminated(port: u16, dir: &Path) -> Out {
    let config = tls_config(dir)?;
    let l = TcpListener::bind(("127.0.0.1", port)).map_err(|e| format!("a listener on port {port}: {e}"))?;
    std::thread::spawn(move || {
        for tcp in l.incoming().flatten() {
            let config = Arc::clone(&config);
            std::thread::spawn(move || {
                let Ok(conn) = rustls::ServerConnection::new(config) else { return };
                let mut s = rustls::StreamOwned::new(conn, tcp);
                let mut head = Vec::new();
                let mut b = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") && matches!(s.read(&mut b), Ok(1)) {
                    head.push(b[0]);
                }
                let text =
                    format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{SERVED}", SERVED.len());
                let _ = s.write_all(text.as_bytes());
                s.conn.send_close_notify();
                let _ = s.flush();
            });
        }
    });
    let upgrade = "Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: cGF5bG9hZCBvZiBwb2QtbGFi\r\n";
    let mut got = Vec::new();
    let mut by = "";
    for extra in ["", upgrade] {
        let (c, tcp) = via(&format!("{LISTED}:{port}"), true)?;
        if c != 200 {
            return Err(format!("CONNECT {LISTED}:{port}: {c}"));
        }
        let mut s = tls(tcp, LISTED, true).map_err(|e| format!("TLS to {LISTED}: {e}"))?;
        by = issuer(&s);
        got.push(said(&mut s, &format!("GET / HTTP/1.1\r\nHost: {LISTED}\r\n{extra}\r\n"))?);
    }
    if !got[0].starts_with("HTTP/1.1 200") || !got[0].ends_with(SERVED) {
        return Err(format!("a plain GET: {:?}", got[0]));
    }
    let upgrade = got[1].split(' ').nth(1).unwrap_or("none").to_string();
    let (c, tcp) = via(&format!("{OTHER}:{port}"), true)?;
    let mut s = command_client(tcp, dir)?;
    let other = said(&mut s, &format!("GET / HTTP/1.1\r\nHost: {LISTED}\r\n\r\n"))?;
    if c != 200 || !other.ends_with(SERVED) {
        return Err(format!("{OTHER}: {c} {other:?}"));
    }
    Ok(format!(
        "listed.test by the {by} CA, get served by the command, upgrade {upgrade}, other.test by the CA of the command"
    ))
}

/// `sni-allowlist`: the server of the command reads the first TLS record
/// and answers [`SERVED`].
fn record(mut s: TcpStream) {
    let mut head = [0u8; 5];
    if s.read_exact(&mut head).is_ok() {
        let mut body = vec![0u8; usize::from(u16::from_be_bytes([head[3], head[4]]))];
        if s.read_exact(&mut body).is_ok() {
            let _ = s.write_all(SERVED.as_bytes());
        }
    }
}

/// A ClientHello with `name` to `192.0.2.1:443`: the answer, or `reset`.
fn hello(name: Option<&str>) -> Out {
    let mut s = connect("192.0.2.1:443").map_err(|e| format!("a connect to 192.0.2.1:443: {e}"))?;
    let bytes = pod_hostprobe::probes::send::hello::client_hello(name, [7; 32]);
    let mut got = Vec::new();
    s.write_all(&bytes).map_err(|e| format!("a write: {e}"))?;
    Ok(match s.read_to_end(&mut got) {
        Err(e) if e.kind() == ErrorKind::ConnectionReset => "reset".to_string(),
        _ if got == SERVED.as_bytes() => "reaches the command".to_string(),
        r => format!("{r:?} {:?}", String::from_utf8_lossy(&got)),
    })
}

/// `sni-allowlist`: a ClientHello with the listed name reaches the command;
/// another name and no name get a reset.
fn sni(port: u16) -> Out {
    listen(port, record)?;
    Ok(format!("{LISTED} {}, {OTHER} {}, no name {}", hello(Some(LISTED))?, hello(Some(OTHER))?, hello(None)?))
}
