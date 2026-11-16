//! The rows that send a packet past the host, to the targets of
//! [`crate::Settings::network`]: a `CONNECT` through the proxy of
//! `HTTPS_PROXY` (its status, never its body), a TLS handshake (the
//! certificate of `SSL_CERT_FILE` that issued the chain of the server), a
//! lookup of a name. Each runs in its own child, where the caller turned
//! the setting on, with a time limit on each step; else it is a skip that
//! names the setting. The spawner gives the targets to the child in
//! [`NETWORK_VARIABLE`]. A reason holds no name of a target, no host of a
//! proxy, no credential and no byte of a body: a report goes to other
//! people.

use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

use super::network::{CERT_VARIABLE, PROXY_VARIABLES};
use super::*;
use crate::Network;
use crate::verdict::items;

pub mod hello;

/// The variable that gives the targets of the setting to a probe child.
pub const NETWORK_VARIABLE: &str = "POD_HOSTPROBE_NETWORK";

/// The reason of each row that sends a packet out, where the setting is
/// off.
pub const OFF: &str = "off: Settings::network is not set, and no row sends a packet past the host";

pub const CONNECT_NAME: &str = "CONNECT(HTTPS_PROXY, name)";
pub const CONNECT_NO_CREDENTIAL: &str = "CONNECT(HTTPS_PROXY, name) with no credential";
pub const CONNECT_OTHER: &str = "CONNECT(HTTPS_PROXY, other)";
pub const CONNECT_CLOSED: &str = "CONNECT(HTTPS_PROXY, name:closed port)";
pub const CONNECT_LITERAL: &str = "CONNECT(HTTPS_PROXY, literal)";
pub const TLS_NAME: &str = "TLS(name)";
pub const TLS_OTHER: &str = "TLS(other)";
pub const TLS_LITERAL: &str = "TLS(literal) with no name";
pub const LOOKUP_NAME: &str = "getaddrinfo(name)";

/// The rows of this module, in the order of [`super::PROBES`].
pub const NETWORK_ROWS: &[&str] = &[
    CONNECT_NAME,
    CONNECT_NO_CREDENTIAL,
    CONNECT_OTHER,
    CONNECT_CLOSED,
    CONNECT_LITERAL,
    TLS_NAME,
    TLS_OTHER,
    TLS_LITERAL,
    LOOKUP_NAME,
];

/// True where `name` is a host name or an address that crosses the
/// variable: no space, no `;` and no `=`.
fn plain(name: &str) -> bool {
    !name.is_empty() && name.len() <= 253 && name.bytes().all(|b| b.is_ascii_graphic() && b != b';' && b != b'=')
}

/// The text of the setting for [`NETWORK_VARIABLE`]; `None` where a name
/// is not a host name.
pub fn encode(n: &Network) -> Option<String> {
    let other = n.other.as_deref().unwrap_or("");
    if !plain(&n.name) || !(other.is_empty() || plain(other)) {
        return None;
    }
    let literal = n.literal.map(|a| a.to_string()).unwrap_or_default();
    Some(format!(
        "name={};port={};other={other};closed={};literal={literal};wait={}",
        n.name, n.port, n.closed_port, n.wait_ms
    ))
}

/// The setting of a text of [`encode`].
pub fn decode(text: &str) -> Option<Network> {
    let get = |key: &str| text.split(';').find_map(|kv| kv.strip_prefix(key)?.strip_prefix('='));
    let some = |v: &str| (!v.is_empty()).then(|| v.to_string());
    Some(Network {
        name: get("name").filter(|n| plain(n))?.to_string(),
        port: get("port")?.parse().ok()?,
        other: get("other").and_then(some),
        closed_port: get("closed")?.parse().ok()?,
        literal: match get("literal")? {
            "" => None,
            a => Some(a.parse().ok()?),
        },
        wait_ms: get("wait")?.parse().ok()?,
    })
}

/// The setting in a probe child.
fn setting() -> Result<Network, Outcome> {
    let text = std::env::var(NETWORK_VARIABLE).map_err(|_| Outcome::skip(None, OFF))?;
    decode(&text).ok_or_else(|| Outcome::skip(None, format!("{NETWORK_VARIABLE} is not a setting of this crate")))
}

/// The proxy of a URL of a variable of a proxy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyUrl {
    pub host: String,
    pub port: u16,
    /// The value of `Proxy-Authorization` where the URL has a credential.
    pub auth: Option<String>,
}

/// The bytes of a `%XX` text.
fn unescape(text: &str) -> String {
    let b = text.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let hex = |c: Option<&u8>| c.and_then(|c| (*c as char).to_digit(16));
        if b[i] == b'%'
            && let (Some(h), Some(l)) = (hex(b.get(i + 1)), hex(b.get(i + 2)))
        {
            out.push((h * 16 + l) as u8);
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The HTTP proxy of the URL `value` of the variable `name`, with no
/// scheme or `http`; with no port, curl's 1080. A reason names the
/// variable alone, never the host or the credential.
pub fn proxy_url(name: &str, value: &str) -> Result<ProxyUrl, String> {
    let rest = match value.split_once("://") {
        Some((s, r)) if s.eq_ignore_ascii_case("http") => r,
        Some(_) => return Err(format!("{name} names a proxy that is not http")),
        None => value,
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let (auth, at) = match authority.rsplit_once('@') {
        Some((cred, at)) => {
            let (user, password) = cred.split_once(':').unwrap_or((cred, ""));
            let pair = format!("{}:{}", unescape(user), unescape(password));
            (Some(format!("Basic {}", hello::base64(pair.as_bytes()))), at)
        }
        None => (None, authority),
    };
    let (host, port) = match at.strip_prefix('[') {
        Some(v6) => match v6.split_once(']') {
            Some((h, tail)) => (h, tail.strip_prefix(':')),
            None => return Err(format!("{name} has an IPv6 host with no ']'")),
        },
        None => match at.rsplit_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (at, None),
        },
    };
    let port = match port {
        None | Some("") => 1080,
        Some(p) => p.parse().map_err(|_| format!("{name} has a port that is not a number"))?,
    };
    if host.is_empty() {
        return Err(format!("{name} names no host"));
    }
    Ok(ProxyUrl { host: host.to_string(), port, auth })
}

/// The proxy of the first variable of a proxy that is set, in the order of
/// curl. `Ok(None)`: no variable names one.
pub fn host_proxy() -> Result<Option<ProxyUrl>, String> {
    for &name in PROXY_VARIABLES {
        if let Some(v) = std::env::var_os(name).filter(|v| !v.is_empty()) {
            return proxy_url(name, &v.to_string_lossy()).map(Some);
        }
    }
    Ok(None)
}

/// The target of a `CONNECT`: an IPv6 literal in brackets.
pub fn authority(host: &str, port: u16) -> String {
    if host.contains(':') { format!("[{host}]:{port}") } else { format!("{host}:{port}") }
}

/// A TCP connect to `host:port` with the limit of each address. The lookup
/// of a name that fails is a skip; a refused connect is the denial of its
/// errno. `what` names the peer in a reason.
fn dial(host: &str, port: u16, wait: Duration, what: &str) -> Result<TcpStream, Outcome> {
    let addrs: Vec<SocketAddr> = match (host, port).to_socket_addrs() {
        Ok(a) => a.collect(),
        Err(_) => return Err(Outcome::skip(None, format!("the lookup of {what} failed"))),
    };
    let mut last = Outcome::skip(None, format!("the lookup of {what} gave no address"));
    for a in addrs {
        match TcpStream::connect_timeout(&a, wait) {
            Ok(s) => {
                let _ = s.set_read_timeout(Some(wait));
                let _ = s.set_write_timeout(Some(wait));
                return Ok(s);
            }
            Err(e) => {
                last = match e.raw_os_error() {
                    Some(n) => Outcome { reason: format!("connect to {what} refused"), ..Outcome::denied(Errno(n)) },
                    None => Outcome::skip(None, format!("no answer of {what} in the limit")),
                };
            }
        }
    }
    Err(last)
}

/// What a `CONNECT` got: the status and the stream after the head, or the
/// end of the stream before a status.
enum Got {
    Status(u16, TcpStream),
    End(hello::End),
}

/// A `CONNECT` to `target` through `p`, with its credential where `auth`.
/// The head alone: no byte of a body.
fn connect(p: &ProxyUrl, target: &str, auth: bool, wait: Duration) -> Result<Got, Outcome> {
    let mut s = dial(&p.host, p.port, wait, "the proxy")?;
    let cred = match (&p.auth, auth) {
        (Some(a), true) => format!("Proxy-Authorization: {a}\r\n"),
        _ => String::new(),
    };
    let req = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n{cred}\r\n");
    if let Err(e) = s.write_all(req.as_bytes()) {
        return Ok(Got::End(hello::End::of(&e)));
    }
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match s.read(&mut b) {
            Ok(0) if head.is_empty() => return Ok(Got::End(hello::End::Closed)),
            Ok(0) => break,
            Ok(_) => head.push(b[0]),
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Ok(Got::End(hello::End::of(&e))),
        }
        if head.len() > 16 * 1024 {
            break;
        }
    }
    let line = String::from_utf8_lossy(&head);
    match line.split(' ').nth(1).and_then(|c| c.parse::<u16>().ok()) {
        Some(code) if line.starts_with("HTTP/") => Ok(Got::Status(code, s)),
        _ => Ok(Got::End(hello::End::Garbled)),
    }
}

fn wait_of(n: &Network) -> Duration {
    Duration::from_millis(u64::from(n.wait_ms.max(1)))
}

/// The proxy of the host, or the skip of the row.
fn need_proxy() -> Result<ProxyUrl, Outcome> {
    match host_proxy() {
        Ok(Some(p)) => Ok(p),
        Ok(None) => Err(Outcome::skip(None, "no variable names a proxy")),
        Err(why) => Err(Outcome::skip(None, why)),
    }
}

/// A `CONNECT` row: `status N`, or `status none; end WORD`.
fn connect_row(target: impl Fn(&Network) -> Option<String>, auth: bool, closed: bool) -> Outcome {
    let n = match setting() {
        Ok(n) => n,
        Err(o) => return o,
    };
    let Some(target) = target(&n) else { return Outcome::skip(None, "the setting gives no such target") };
    let p = match need_proxy() {
        Ok(p) => p,
        Err(o) => return o,
    };
    match connect(&p, &target, auth, wait_of(&n)) {
        Err(o) => o,
        Ok(Got::End(e)) => Outcome::ok_with(items(&[("status", "none"), ("end", &e.word())])),
        Ok(Got::Status(code, mut s)) if closed && code == 200 => {
            // A banner of SSH, then one byte in the limit, or none.
            let _ = s.write_all(b"SSH-2.0-pod-hostprobe\r\n");
            let _ = s.set_read_timeout(Some(wait_of(&n).min(Duration::from_secs(1))));
            let bytes = matches!(s.read(&mut [0u8; 1]), Ok(1));
            Outcome::ok_with(items(&[("status", "200"), ("bytes", if bytes { "1" } else { "0" })]))
        }
        Ok(Got::Status(code, _)) => Outcome::ok_with(items(&[("status", &code.to_string())])),
    }
}

pub(in crate::probes) fn s_connect_name() -> Outcome {
    connect_row(|n| Some(authority(&n.name, n.port)), true, false)
}

pub(in crate::probes) fn s_connect_no_credential() -> Outcome {
    connect_row(|n| Some(authority(&n.name, n.port)), false, false)
}

pub(in crate::probes) fn s_connect_other() -> Outcome {
    connect_row(|n| Some(authority(n.other.as_deref()?, n.port)), true, false)
}

pub(in crate::probes) fn s_connect_closed() -> Outcome {
    connect_row(|n| Some(authority(&n.name, n.closed_port)), true, true)
}

pub(in crate::probes) fn s_connect_literal() -> Outcome {
    connect_row(|n| Some(authority(&n.literal?.to_string(), n.port)), true, false)
}

/// A handshake row: through the proxy of the host where a variable names
/// one, else direct (to the literal of the setting where it has one). The
/// items: `path proxy` or `path direct`; the status of the `CONNECT`;
/// `hello 1`, the count of the certificates, and `issuer file; ca N` (the
/// certificate of `SSL_CERT_FILE` that issued the chain), `issuer other`
/// or `issuer none` (no file); else `hello 0; end WORD`.
fn tls_row(host: impl Fn(&Network) -> Option<String>, sni: bool) -> Outcome {
    let n = match setting() {
        Ok(n) => n,
        Err(o) => return o,
    };
    let Some(host) = host(&n) else { return Outcome::skip(None, "the setting gives no such target") };
    let wait = wait_of(&n);
    let proxy = match host_proxy() {
        Ok(p) => p,
        Err(why) => return Outcome::skip(None, why),
    };
    let mut out: Vec<(&str, String)> = Vec::new();
    let mut s = match &proxy {
        Some(p) => {
            out.push(("path", "proxy".to_string()));
            match connect(p, &authority(&host, n.port), true, wait) {
                Err(o) => return o,
                Ok(Got::Status(200, s)) => s,
                Ok(Got::Status(code, _)) => {
                    out.push(("status", code.to_string()));
                    return Outcome::ok_with(pairs(&out));
                }
                Ok(Got::End(e)) => {
                    out.extend([("status", "none".to_string()), ("end", e.word())]);
                    return Outcome::ok_with(pairs(&out));
                }
            }
        }
        None => {
            out.push(("path", "direct".to_string()));
            let to = n.literal.map_or(host.clone(), |a| a.to_string());
            match dial(&to, n.port, wait, "the server") {
                Ok(s) => s,
                Err(o) => return o,
            }
        }
    };
    let mut random = [0u8; 32];
    if let Err(e) = sys::getrandom(&mut random) {
        return Outcome::skip(Some(e), "getrandom for the ClientHello failed");
    }
    let name = (sni && host.parse::<IpAddr>().is_err()).then_some(host.as_str());
    let chain = match s.write_all(&hello::client_hello(name, random)) {
        Err(e) => Err(hello::End::of(&e)),
        Ok(()) => hello::server_certificates(&mut s),
    };
    match chain {
        Err(e) => out.extend([("hello", "0".to_string()), ("end", e.word())]),
        Ok(chain) => {
            out.extend([("hello", "1".to_string()), ("certs", chain.len().to_string())]);
            match std::env::var_os(CERT_VARIABLE).filter(|v| !v.is_empty()).map(std::fs::read) {
                None | Some(Err(_)) => out.push(("issuer", "none".to_string())),
                Some(Ok(pem)) => match hello::issuer_in(&chain, &hello::pem_certificates(&pem)) {
                    Some(i) => out.extend([("issuer", "file".to_string()), ("ca", i.to_string())]),
                    None => out.push(("issuer", "other".to_string())),
                },
            }
        }
    }
    Outcome::ok_with(pairs(&out))
}

fn pairs(out: &[(&str, String)]) -> String {
    let refs: Vec<(&str, &str)> = out.iter().map(|(k, v)| (*k, v.as_str())).collect();
    items(&refs)
}

pub(in crate::probes) fn s_tls_name() -> Outcome {
    tls_row(|n| Some(n.name.clone()), true)
}

pub(in crate::probes) fn s_tls_other() -> Outcome {
    tls_row(|n| n.other.clone(), true)
}

pub(in crate::probes) fn s_tls_literal() -> Outcome {
    tls_row(|n| Some(n.literal?.to_string()), false)
}

/// A lookup of the name of the setting by the resolver of the C library,
/// in a thread, with the limit: `resolved 1; addresses N` or `resolved 0`.
pub(in crate::probes) fn s_lookup_name() -> Outcome {
    let n = match setting() {
        Ok(n) => n,
        Err(o) => return o,
    };
    let (tx, rx) = std::sync::mpsc::channel();
    let target = (n.name.clone(), n.port);
    if std::thread::Builder::new().spawn(move || tx.send(target.to_socket_addrs().map(|a| a.count()))).is_err() {
        return Outcome::skip(None, "no thread for the lookup");
    }
    match rx.recv_timeout(wait_of(&n)) {
        Ok(Ok(count)) if count > 0 => Outcome::ok_with(items(&[("resolved", "1"), ("addresses", &count.to_string())])),
        Ok(_) => Outcome::ok_with(items(&[("resolved", "0")])),
        Err(_) => Outcome::ok_with(items(&[("resolved", "0"), ("end", "silent")])),
    }
}

#[cfg(test)]
mod tests;
