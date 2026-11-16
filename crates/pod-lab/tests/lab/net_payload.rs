//! The payloads of the network classes: this binary with `--payload KIND`
//! inside a lab. Each one reads the lab as a program does: the proxy of
//! `HTTPS_PROXY` and the roots of `SSL_CERT_FILE`. It gives one line when
//! the class is what it must be, else the fault; a second line names the
//! certificate file, which the stand-in removes after the run.

use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

use pod_lab::net::{LISTED, OTHER};

type Out = Result<String, String>;

pub fn main(kind: &str) -> Option<Out> {
    let out = match kind {
        "proxy-only" => proxy_only(),
        "reterminate" => reterminate(),
        "per-name" => per_name(),
        "sni" => sni(),
        "nodns" => nodns(),
        "ws" => ws(),
        "v6" => v6(),
        "tool-vars" => tool_vars(),
        "sigpipe" => sigpipe(),
        _ => return crate::way_out_payload::main(kind),
    };
    let file = std::env::var("SSL_CERT_FILE").unwrap_or_default();
    Some(out.map(|line| format!("{line}\ncert {file}")))
}

const WAIT: Duration = Duration::from_secs(5);

pub fn connect(at: &str) -> std::io::Result<TcpStream> {
    let a: SocketAddr = at.parse().map_err(std::io::Error::other)?;
    let s = TcpStream::connect_timeout(&a, WAIT)?;
    s.set_read_timeout(Some(WAIT))?;
    Ok(s)
}

/// The proxy of `HTTPS_PROXY`: its address, and its credential as
/// `user:password`, where it has one.
fn proxy() -> Result<(String, Option<String>), String> {
    let url = std::env::var("HTTPS_PROXY").map_err(|_| "no HTTPS_PROXY".to_string())?;
    let rest = url.strip_prefix("http://").ok_or(format!("HTTPS_PROXY is {url}"))?.trim_end_matches('/');
    Ok(match rest.rsplit_once('@') {
        Some((auth, at)) => (at.to_string(), Some(auth.to_string())),
        None => (rest.to_string(), None),
    })
}

fn head(s: &mut impl Read) -> Result<String, String> {
    let mut h = Vec::new();
    let mut b = [0u8; 1];
    while !h.ends_with(b"\r\n\r\n") {
        match s.read(&mut b) {
            Ok(1) => h.push(b[0]),
            r => return Err(format!("the head: {r:?} after {:?}", String::from_utf8_lossy(&h))),
        }
    }
    Ok(String::from_utf8_lossy(&h).into_owned())
}

fn code(head: &str) -> u16 {
    head.split(' ').nth(1).and_then(|c| c.parse().ok()).unwrap_or(0)
}

/// A `CONNECT` to `target` through the proxy, with its credential where
/// `auth`: the status, and the stream.
pub fn via(target: &str, auth: bool) -> Result<(u16, TcpStream), String> {
    use base64::Engine as _;
    let (at, cred) = proxy()?;
    let mut s = connect(&at).map_err(|e| format!("the proxy at {at}: {e}"))?;
    let line = match cred.filter(|_| auth) {
        Some(c) => format!("Proxy-Authorization: Basic {}\r\n", base64::engine::general_purpose::STANDARD.encode(c)),
        None => String::new(),
    };
    s.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n{line}\r\n").as_bytes())
        .map_err(|e| e.to_string())?;
    Ok((code(&head(&mut s)?), s))
}

/// A TLS client that trusts the roots of `SSL_CERT_FILE`.
pub fn tls(
    tcp: TcpStream,
    name: &str,
    sni: bool,
) -> std::io::Result<rustls::StreamOwned<rustls::ClientConnection, TcpStream>> {
    let file = std::env::var("SSL_CERT_FILE").map_err(|_| std::io::Error::other("no SSL_CERT_FILE"))?;
    let pem = std::fs::read(&file)?;
    let mut roots = rustls::RootCertStore::empty();
    for c in pod_tls::bundle::pem_certificates(&pem).map_err(std::io::Error::other)? {
        roots.add(c).map_err(std::io::Error::other)?;
    }
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(pod_tls::crypto::provider()))
        .with_safe_default_protocol_versions()
        .map_err(std::io::Error::other)?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.enable_sni = sni;
    let server = rustls_pki_types::ServerName::try_from(name.to_string()).map_err(std::io::Error::other)?;
    let conn = rustls::ClientConnection::new(Arc::new(config), server).map_err(std::io::Error::other)?;
    let mut s = rustls::StreamOwned::new(conn, tcp);
    while s.conn.is_handshaking() {
        s.conn.complete_io(&mut s.sock)?;
    }
    Ok(s)
}

/// The issuer of the leaf: the name of the CA of the lab in its DER.
pub fn issuer(s: &rustls::StreamOwned<rustls::ClientConnection, TcpStream>) -> &'static str {
    let leaf = s.conn.peer_certificates().and_then(|c| c.first()).map(|c| c.as_ref().to_vec()).unwrap_or_default();
    let has = |n: &[u8]| leaf.windows(n.len()).any(|w| w == n);
    if has(b"pod-lab proxy CA") {
        "proxy"
    } else if has(b"pod-lab server CA") {
        "server"
    } else {
        "unknown"
    }
}

/// A `GET` on `s` with `extra` headers: the status.
fn get(s: &mut (impl Read + Write), extra: &str) -> Result<u16, String> {
    s.write_all(format!("GET / HTTP/1.1\r\nHost: {LISTED}\r\n{extra}\r\n").as_bytes()).map_err(|e| e.to_string())?;
    Ok(code(&head(s)?))
}

fn no_route() -> Result<(), String> {
    match connect("192.0.2.1:443") {
        Err(e) if e.raw_os_error() == Some(101) => Ok(()),
        r => Err(format!("a direct connect: {r:?}; the lab wants ENETUNREACH")),
    }
}

fn proxy_only() -> Out {
    let (c, tcp) = via(&format!("{LISTED}:443"), true)?;
    if c != 200 {
        return Err(format!("CONNECT with the credential: {c}"));
    }
    let mut s = tls(tcp, LISTED, true).map_err(|e| format!("TLS: {e}"))?;
    let got = get(&mut s, "")?;
    let (no_auth, _) = via(&format!("{LISTED}:443"), false)?;
    let (port22, _) = via(&format!("{LISTED}:22"), true)?;
    if (got, no_auth, port22) != (200, 407, 403) {
        return Err(format!("GET {got}, no credential {no_auth}, port 22 {port22}"));
    }
    no_route()?;
    match UdpSocket::bind("0.0.0.0:0") {
        Err(e) if e.kind() == ErrorKind::PermissionDenied => {}
        r => return Err(format!("a UDP socket: {r:?}; the lab wants EPERM")),
    }
    Ok("200 with the credential, 407 with none, 403 for port 22, no direct route, no udp".to_string())
}

/// A client that ends its connection with a reset after the handshake, so
/// that a write of the stand-in gets `EPIPE`; then a second client still
/// gets its answer: the stand-in lives (PodUtils/podvm#455).
fn sigpipe() -> Out {
    let (c, tcp) = via(&format!("{LISTED}:443"), true)?;
    if c != 200 {
        return Err(format!("CONNECT with the credential: {c}"));
    }
    let s = tls(tcp, LISTED, true).map_err(|e| format!("TLS: {e}"))?;
    reset(&s.sock)?;
    drop(s);
    std::thread::sleep(Duration::from_millis(300));
    let (c, tcp) = via(&format!("{LISTED}:443"), true).map_err(|e| format!("the CONNECT after the reset: {e}"))?;
    let mut s = tls(tcp, LISTED, true).map_err(|e| format!("TLS after the reset: {e}"))?;
    let got = get(&mut s, "")?;
    Ok(format!("a reset after the handshake, then CONNECT {c} and GET {got}"))
}

/// `SO_LINGER` of 0 s: the close of `s` sends a reset, not a FIN.
fn reset(s: &TcpStream) -> Result<(), String> {
    use linux_raw_sys::net::{SO_LINGER, SOL_SOCKET};
    use std::os::fd::AsRawFd as _;
    let linger: [i32; 2] = [1, 0];
    let args =
        [s.as_raw_fd() as u64, u64::from(SOL_SOCKET), u64::from(SO_LINGER), linger.as_ptr() as usize as u64, 8, 0];
    // SAFETY: the kernel reads 8 bytes of `linger`, which lives until the call ends.
    unsafe { pod_hostprobe::sys::sys(i64::from(linux_raw_sys::general::__NR_setsockopt), args) }
        .map(|_| ())
        .map_err(|e| format!("SO_LINGER: {}", e.name()))
}

fn reterminate() -> Out {
    let mut by = Vec::new();
    for name in [LISTED, OTHER] {
        let (c, tcp) = via(&format!("{name}:443"), true)?;
        if c != 200 {
            return Err(format!("CONNECT {name}: {c}"));
        }
        by.push(issuer(&tls(tcp, name, true).map_err(|e| format!("TLS to {name}: {e}"))?));
    }
    let (c, mut s) = via(&format!("{LISTED}:22"), true)?;
    s.write_all(b"SSH-2.0-payload\r\n").map_err(|e| e.to_string())?;
    s.set_read_timeout(Some(Duration::from_millis(500))).map_err(|e| e.to_string())?;
    let silent =
        matches!(s.read(&mut [0u8; 8]), Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut));
    if c != 200 || !silent {
        return Err(format!("port 22: {c}, silent {silent}"));
    }
    Ok(format!("{LISTED} by the {} CA, {OTHER} by the {} CA, port 22 silent", by[0], by[1]))
}

fn per_name() -> Out {
    let (a, _) = via(&format!("{LISTED}:443"), true)?;
    let (b, _) = via(&format!("{OTHER}:443"), true)?;
    let literal = match via("192.0.2.1:443", true) {
        Ok((c, _)) => format!("{c}"),
        Err(_) => "a reset".to_string(),
    };
    Ok(format!("{LISTED} {a}, {OTHER} {b}, a literal gets {literal}"))
}

fn hello(at: &str, name: Option<&str>) -> String {
    let tcp = match connect(&format!("{at}:443")) {
        Ok(t) => t,
        Err(e) => return format!("no connect: {e}"),
    };
    match tls(tcp, name.unwrap_or(at), name.is_some()) {
        Ok(_) => "passes".to_string(),
        Err(e) if e.kind() == ErrorKind::ConnectionReset => "reset".to_string(),
        Err(e) => format!("{e}"),
    }
}

fn sni() -> Out {
    if std::env::var_os("HTTPS_PROXY").is_some() {
        return Err("HTTPS_PROXY is set".to_string());
    }
    let lab = "192.0.2.1";
    let out = format!(
        "{LISTED} {}, {OTHER} {}, no name {}",
        hello(lab, Some(LISTED)),
        hello(lab, Some(OTHER)),
        hello(lab, None)
    );
    // The filter is on each address, not on the addresses of the lab alone.
    let other = "198.51.100.7";
    Ok(format!("{out}; at {other}: {LISTED} {}, no name {}", hello(other, Some(LISTED)), hello(other, None)))
}

fn nodns() -> Out {
    if let Ok(a) = ("example.com", 443).to_socket_addrs() {
        return Err(format!("example.com resolved: {:?}", a.collect::<Vec<_>>()));
    }
    let mut s = tls(connect("192.0.2.1:443").map_err(|e| e.to_string())?, "192.0.2.1", false)
        .map_err(|e| format!("TLS to 192.0.2.1: {e}"))?;
    Ok(format!("no lookup, TLS to 192.0.2.1 gets {}", get(&mut s, "")?))
}

fn ws() -> Out {
    let upgrade = "Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: cGF5bG9hZCBvZiBwb2QtbGFi\r\n";
    let mut out = Vec::new();
    for extra in ["", upgrade] {
        let (c, tcp) = via(&format!("{LISTED}:443"), true)?;
        if c != 200 {
            return Err(format!("CONNECT: {c}"));
        }
        let mut s = tls(tcp, LISTED, true).map_err(|e| format!("TLS: {e}"))?;
        out.push(get(&mut s, extra)?);
    }
    Ok(format!("get {}, upgrade {}", out[0], out[1]))
}

fn v6() -> Out {
    no_route()?;
    connect("127.0.0.1:443").map_err(|e| format!("127.0.0.1:443: {e}"))?;
    connect("[fd00:6c61:62::1]:443").map_err(|e| format!("the IPv6 address: {e}"))?;
    // A program reads the routes: the IPv6 default route is on a device
    // that is not the loopback.
    let routes = std::fs::read_to_string("/proc/net/ipv6_route").map_err(|e| format!("/proc/net/ipv6_route: {e}"))?;
    if !pod_dns_default(&routes) {
        return Err(format!("no IPv6 default route on a device: {routes}"));
    }
    Ok("no IPv4 route, the loopback and IPv6 reach, an IPv6 default route".to_string())
}

/// The test of `pod_dns::route::default_route_in` for IPv6: `::/0` on a
/// device that is not the loopback.
fn pod_dns_default(text: &str) -> bool {
    text.lines().any(|l| l.starts_with("00000000000000000000000000000000 00 ") && !l.ends_with(" lo"))
}

/// The variables of a proxy of other tools than curl name the stand-in
/// proxy of the lab, as `HTTPS_PROXY` does (T-760).
fn tool_vars() -> Out {
    let url = std::env::var("HTTPS_PROXY").map_err(|_| "no HTTPS_PROXY".to_string())?;
    for v in pod_lab::net::vars::URL_VARIABLES {
        let got = std::env::var(v).unwrap_or_default();
        if got != url {
            return Err(format!("{v} is {got:?}, not the stand-in proxy"));
        }
    }
    let address = std::env::var("CLOUDSDK_PROXY_ADDRESS").unwrap_or_default();
    if address != "127.0.0.1" {
        return Err(format!("CLOUDSDK_PROXY_ADDRESS is {address:?}"));
    }
    Ok("the proxy variables of each tool name the stand-in proxy".to_string())
}
