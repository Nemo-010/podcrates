//! The work of the stand-in process on each connection: the stand-in proxy
//! (`CONNECT` and a plain request) and the stand-in server (TLS, then
//! HTTP). After a 200, the proxy is the server of the target itself: the
//! lab has no route out.

use std::io::{Read, Write};
use std::net::{IpAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use super::tls::Cas;
use super::wire::{first_line, header, peek_record, read_head, reset, server_name, target};
use super::{Ca, Net, Proxy, credential};

/// The time that a stand-in waits for a peer.
const WAIT: Duration = Duration::from_secs(30);

/// The body of each answer of the stand-in server.
pub const BODY: &str = "pod-lab stand-in\n";

fn answer(s: &mut impl Write, status: &str, body: &str) {
    let text = format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
    let _ = s.write_all(text.as_bytes());
    let _ = s.flush();
}

/// Read one request, and answer it: 403 for an upgrade where `refuse`, else
/// 200 with [`BODY`].
fn http(s: &mut (impl Read + Write), refuse: bool) {
    let Ok(head) = read_head(s) else { return };
    if refuse && header(&head, "upgrade").is_some() {
        answer(s, "403 Forbidden", "");
    } else {
        answer(s, "200 OK", BODY);
    }
}

/// TLS with the leaf of `name` signed by `ca`, then one request.
fn tls(cas: &Cas, tcp: TcpStream, name: &str, ca: Ca, refuse: bool) {
    let Ok(config) = cas.server(name, ca) else { return };
    let Ok(conn) = rustls::ServerConnection::new(config) else { return };
    let mut s = rustls::StreamOwned::new(conn, tcp);
    http(&mut s, refuse);
    s.conn.send_close_notify();
    let _ = s.flush();
}

/// The stand-in server on one connection: a TLS handshake where the first
/// record is one, else plain HTTP. `name` is the name of the target where
/// the client gives none.
pub fn server(cas: &Cas, net: &Net, tcp: TcpStream, name: Option<&str>, ca: Ca, refuse: bool) {
    let _ = tcp.set_read_timeout(Some(WAIT));
    let record = match peek_record(&tcp) {
        Ok(r) => r,
        Err(_) => return,
    };
    let Some(record) = record else {
        let mut tcp = tcp;
        http(&mut tcp, refuse);
        return;
    };
    let given = server_name(&record).ok().flatten();
    if let Some(list) = net.sni
        && !given.as_deref().is_some_and(|n| list.contains(&n))
    {
        reset(tcp);
        return;
    }
    // A ClientHello with no name: the leaf of the address that it reached.
    let local = tcp.local_addr().map(|a| a.ip().to_canonical().to_string()).unwrap_or_default();
    let name = given.as_deref().or(name).unwrap_or(&local).to_string();
    tls(cas, tcp, &name, ca, refuse);
}

/// The stand-in proxy on one connection.
pub fn proxy(cas: &Cas, net: &Net, rules: &Proxy, mut tcp: TcpStream) {
    let _ = tcp.set_read_timeout(Some(WAIT));
    let Ok(head) = read_head(&mut tcp) else { return };
    if rules.auth && header(&head, "proxy-authorization") != Some(credential().as_str()) {
        let text = "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"pod-lab\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        let _ = tcp.write_all(text.as_bytes());
        return;
    }
    let (method, to, _) = first_line(&head);
    if method != "CONNECT" {
        // A plain request: `GET http://host/ HTTP/1.1`.
        let host = to.split("://").nth(1).and_then(|r| r.split(['/', ':']).next()).unwrap_or("").to_ascii_lowercase();
        if rules.timeout.contains(&host.as_str()) {
            answer(&mut tcp, "504 Gateway Timeout", "");
        } else if rules.refuse_upgrade && header(&head, "upgrade").is_some() {
            answer(&mut tcp, "403 Forbidden", "");
        } else {
            answer(&mut tcp, "200 OK", BODY);
        }
        return;
    }
    let Some((host, port)) = target(to) else {
        answer(&mut tcp, "400 Bad Request", "");
        return;
    };
    if !rules.ports.is_empty() && !rules.ports.contains(&port) {
        answer(&mut tcp, "403 Forbidden", "");
        return;
    }
    if rules.reset_literals && host.parse::<IpAddr>().is_ok() {
        reset(tcp);
        return;
    }
    if rules.timeout.contains(&host.as_str()) {
        answer(&mut tcp, "504 Gateway Timeout", "");
        return;
    }
    if tcp.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").is_err() {
        return;
    }
    if rules.silent.contains(&port) {
        // Read each byte, and send none.
        let mut sink = [0u8; 4096];
        while matches!(tcp.read(&mut sink), Ok(n) if n > 0) {}
        return;
    }
    if rules.reterminate.contains(&host.as_str()) {
        let _ = tcp.set_read_timeout(Some(WAIT));
        if let Ok(Some(_)) = peek_record(&tcp) {
            tls(cas, tcp, &host, Ca::Proxy, rules.refuse_upgrade);
        }
        return;
    }
    server(cas, net, tcp, Some(&host), Ca::Server, false);
}

/// The work of one accepted connection, in a thread of its own.
pub fn spawn(cas: &Arc<Cas>, net: &'static Net, tcp: TcpStream, is_proxy: bool) {
    let cas = Arc::clone(cas);
    let _ = std::thread::Builder::new().spawn(move || match (&net.proxy, is_proxy) {
        (Some(rules), true) => proxy(&cas, net, rules, tcp),
        _ => server(&cas, net, tcp, None, Ca::Server, false),
    });
}
