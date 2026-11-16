//! The check of a network lab from inside, before the command: each
//! [`NetFact`] through the stand-ins, with a limit of time on each step.

use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

use rustls_pki_types::CertificateDer;

use super::tls::{client, server_name};
use super::wire::{read_head, status};
use super::{Ca, LISTED, NetFact, OUTSIDE_V4, PROXY_PORT, Started, TLS_PORT, credential, outside_v6};
use crate::check::{Seen, State};

/// The time of a connect and of each read of the check.
const WAIT: Duration = Duration::from_secs(5);
/// How long a silent port must send no byte.
const SILENCE: Duration = Duration::from_secs(1);

fn seen(fact: NetFact, state: State, errno: Option<i32>, detail: impl Into<String>) -> Seen {
    Seen { what: fact.name(), state, errno, detail: detail.into() }
}

fn holds(fact: NetFact, detail: impl Into<String>) -> Seen {
    seen(fact, State::Holds, None, detail)
}

fn fails(fact: NetFact, detail: impl Into<String>) -> Seen {
    seen(fact, State::Fails, None, detail)
}

fn connect(at: SocketAddr) -> std::io::Result<TcpStream> {
    let s = TcpStream::connect_timeout(&at, WAIT)?;
    s.set_read_timeout(Some(WAIT))?;
    s.set_write_timeout(Some(WAIT))?;
    Ok(s)
}

fn outside_v4() -> SocketAddr {
    SocketAddr::from((OUTSIDE_V4, TLS_PORT))
}

/// A `CONNECT` to `target` through the stand-in proxy: its status and the
/// stream after the head.
fn via_proxy(target: &str, with_credential: bool) -> Result<(u16, TcpStream), String> {
    let mut s = connect(SocketAddr::from(([127, 0, 0, 1], PROXY_PORT))).map_err(|e| format!("the proxy: {e}"))?;
    let auth = if with_credential { format!("Proxy-Authorization: {}\r\n", credential()) } else { String::new() };
    let req = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n{auth}\r\n");
    s.write_all(req.as_bytes()).map_err(|e| format!("a write to the proxy: {e}"))?;
    let head = read_head(&mut s)?;
    let code = status(&head).ok_or_else(|| format!("the proxy gave no status: {head:?}"))?;
    Ok((code, s))
}

/// A TLS handshake on `tcp` with `name`, trusting `roots` alone.
fn handshake(
    tcp: TcpStream,
    name: &str,
    roots: &[CertificateDer<'static>],
    sni: bool,
) -> Result<rustls::StreamOwned<rustls::ClientConnection, TcpStream>, std::io::Error> {
    let other = |e: String| std::io::Error::other(e);
    let config = client(roots, sni).map_err(other)?;
    let conn =
        rustls::ClientConnection::new(config, server_name(name).map_err(other)?).map_err(std::io::Error::other)?;
    let mut s = rustls::StreamOwned::new(conn, tcp);
    while s.conn.is_handshaking() {
        s.conn.complete_io(&mut s.sock)?;
    }
    Ok(s)
}

/// One request on `s`, and the status of its answer.
fn request(s: &mut impl ReadWrite, extra: &str) -> Result<u16, String> {
    let req = format!("GET / HTTP/1.1\r\nHost: {LISTED}\r\n{extra}\r\n");
    s.write_all(req.as_bytes()).map_err(|e| format!("a write of the request: {e}"))?;
    let head = read_head(s)?;
    status(&head).ok_or_else(|| format!("no status: {head:?}"))
}

trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}

/// TLS through the proxy to `LISTED`, trusting each CA of the lab, then
/// one request with `extra` headers.
fn https_get(lab: &Started, extra: &str) -> Result<u16, String> {
    let (code, tcp) = via_proxy(&format!("{LISTED}:{TLS_PORT}"), true)?;
    if code != 200 {
        return Err(format!("the CONNECT got {code}"));
    }
    let roots = [lab.cas.of(Ca::Server).der.clone(), lab.cas.of(Ca::Proxy).der.clone()];
    let mut s = handshake(tcp, LISTED, &roots, true).map_err(|e| format!("TLS: {e}"))?;
    request(&mut s, extra)
}

fn issuer(fact: NetFact, lab: &Started, name: &str, ca: Ca) -> Seen {
    let other = if ca == Ca::Proxy { Ca::Server } else { Ca::Proxy };
    let mut each = Vec::new();
    for (trust, want) in [(ca, true), (other, false)] {
        let (code, tcp) = match via_proxy(&format!("{name}:{TLS_PORT}"), true) {
            Ok(r) => r,
            Err(why) => return fails(fact, why),
        };
        if code != 200 {
            return fails(fact, format!("the CONNECT got {code}"));
        }
        let r = handshake(tcp, name, &[lab.cas.of(trust).der.clone()], true);
        each.push(match (r, want) {
            (Ok(_), true) | (Err(_), false) => continue,
            (Err(e), true) => format!("with {} alone: {e}", trust.name()),
            (Ok(_), false) => format!("{} alone also takes the chain", trust.name()),
        });
    }
    match each.first() {
        None => holds(fact, format!("the chain ends at {}", ca.name())),
        Some(why) => fails(fact, why.clone()),
    }
}

fn silent(fact: NetFact, port: u16) -> Seen {
    let (code, mut s) = match via_proxy(&format!("{LISTED}:{port}"), true) {
        Ok(r) => r,
        Err(why) => return fails(fact, why),
    };
    if code != 200 {
        return fails(fact, format!("the CONNECT got {code}; the profile wants 200"));
    }
    if let Err(e) = s.write_all(b"SSH-2.0-podlab\r\n") {
        return fails(fact, format!("a write of the banner: {e}"));
    }
    let _ = s.set_read_timeout(Some(SILENCE));
    match s.read(&mut [0u8; 64]) {
        Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
            holds(fact, format!("200, then no byte in {} s", SILENCE.as_secs()))
        }
        Ok(0) => fails(fact, "the proxy closed the connection"),
        Ok(n) => fails(fact, format!("the proxy sent {n} bytes")),
        Err(e) => fails(fact, format!("a read: {e}")),
    }
}

fn hello(fact: NetFact, lab: &Started, name: Option<&str>, passes: bool) -> Seen {
    let tcp = match connect(outside_v4()) {
        Ok(s) => s,
        Err(e) => return fails(fact, format!("connect(192.0.2.1:443): {e}")),
    };
    let r = handshake(tcp, name.unwrap_or("192.0.2.1"), &[lab.cas.of(Ca::Server).der.clone()], name.is_some());
    match (r, passes) {
        (Ok(_), true) => holds(fact, "the handshake completed"),
        (Err(e), true) => fails(fact, format!("the handshake: {e}")),
        (Err(e), false) if e.kind() == ErrorKind::ConnectionReset => {
            seen(fact, State::Holds, e.raw_os_error(), "the connection was reset")
        }
        (Err(e), false) => fails(fact, format!("the handshake: {e}; the profile wants a reset")),
        (Ok(_), false) => fails(fact, "the handshake completed; the profile wants a reset"),
    }
}

fn no_resolver(fact: NetFact) -> Seen {
    if let Ok(mut a) = ("example.com", 443).to_socket_addrs()
        && let Some(a) = a.next()
    {
        return fails(fact, format!("example.com resolved to {a}"));
    }
    let text = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
    if let Some(l) = text.lines().find(|l| l.trim_start().starts_with("nameserver")) {
        return fails(fact, format!("/etc/resolv.conf names a server: {}", l.trim()));
    }
    // With no server, the C libraries ask 127.0.0.1.
    match connect(SocketAddr::from(([127, 0, 0, 1], 53))) {
        Ok(_) => fails(fact, "a TCP connect to 127.0.0.1:53 succeeded"),
        Err(e) => holds(fact, format!("the lookup failed; no nameserver line; 127.0.0.1:53: {e}")),
    }
}

/// A TCP connect to `at` that must succeed.
fn reaches(fact: NetFact, at: SocketAddr) -> Seen {
    match connect(at) {
        Ok(_) => holds(fact, format!("connect({at}) succeeded")),
        Err(e) => seen(fact, State::Fails, e.raw_os_error(), format!("connect({at}): {e}")),
    }
}

/// Measure `fact` through the stand-ins of `lab`; `None`: the stand-ins
/// did not start.
pub fn measure(fact: NetFact, lab: Option<&Started>) -> Seen {
    let Some(lab) = lab else {
        return seen(fact, State::Unseen, None, "the stand-ins of the lab did not start");
    };
    match fact {
        NetFact::NoRouteV4 => match connect(outside_v4()) {
            Err(e) if e.raw_os_error() == Some(101) => seen(fact, State::Holds, Some(101), format!("{e}")),
            Err(e) => seen(fact, State::Fails, e.raw_os_error(), format!("{e}; the profile wants ENETUNREACH")),
            Ok(_) => fails(fact, "the connect succeeded; the profile wants ENETUNREACH"),
        },
        NetFact::Connect { host, port, status } => match via_proxy(&format!("{host}:{port}"), true) {
            Ok((code, _)) if code == status => holds(fact, format!("the proxy gave {code}")),
            Ok((code, _)) => fails(fact, format!("the proxy gave {code}; the profile wants {status}")),
            Err(why) => fails(fact, why),
        },
        NetFact::NeedsCredential => match via_proxy(&format!("{LISTED}:{TLS_PORT}"), false) {
            Ok((407, _)) => holds(fact, "the proxy gave 407"),
            Ok((code, _)) => fails(fact, format!("the proxy gave {code}; the profile wants 407")),
            Err(why) => fails(fact, why),
        },
        NetFact::LiteralReset => match via_proxy("192.0.2.1:443", true) {
            Ok((code, _)) => fails(fact, format!("the proxy gave {code}; the profile wants a reset")),
            Err(why) => holds(fact, format!("no answer: {why}")),
        },
        NetFact::Issuer { name, ca } => issuer(fact, lab, name, ca),
        NetFact::Silent { port } => silent(fact, port),
        NetFact::GetPasses => match https_get(lab, "") {
            Ok(200) => holds(fact, "200"),
            Ok(code) => fails(fact, format!("{code}; the profile wants 200")),
            Err(why) => fails(fact, why),
        },
        NetFact::UpgradeRefused => {
            let up = "Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: cG9kLWxhYiBzdGFuZC1pbg==\r\n";
            match https_get(lab, up) {
                Ok(403) => holds(fact, "403"),
                Ok(code) => fails(fact, format!("{code}; the profile wants 403")),
                Err(why) => fails(fact, why),
            }
        }
        NetFact::Hello { name, passes } => hello(fact, lab, name, passes),
        NetFact::NoResolver => no_resolver(fact),
        NetFact::LiteralReaches => match connect(outside_v4()) {
            Err(e) => seen(fact, State::Fails, e.raw_os_error(), format!("connect(192.0.2.1:443): {e}")),
            Ok(tcp) => match handshake(tcp, "192.0.2.1", &[lab.cas.of(Ca::Server).der.clone()], false) {
                Ok(_) => holds(fact, "the certificate names 192.0.2.1"),
                Err(e) => fails(fact, format!("the handshake: {e}")),
            },
        },
        NetFact::LoopbackReaches => reaches(fact, SocketAddr::from(([127, 0, 0, 1], TLS_PORT))),
        NetFact::V6Reaches => reaches(fact, SocketAddr::from((outside_v6(), TLS_PORT))),
    }
}
