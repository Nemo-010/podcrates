//! The bytes between the command and the real network, through the way
//! out (`out`): after the rules of the class, the stand-in proxy asks the
//! way out for a stream to the target and answers 200. Then it splices the
//! two streams, or, where the proxy of the class terminates TLS, it
//! terminates the TLS of the command with a leaf of its own CA for the
//! name, checks the real server with the roots of the host, and passes the
//! plain text between the two. Where the class refuses an upgrade, the
//! first request of the command with `Upgrade` gets 403.

use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::time::Duration;

use pod_hostprobe::sys as k;
use rustls::Connection;

use super::out::WayOut;
use super::proxy::answer;
use super::tls::{Cas, server_name};
use super::wire::{header, peek_record, read_head};
use super::{Ca, Proxy};

/// The time of a handshake and of the first request.
const WAIT: Duration = Duration::from_secs(30);
/// A stream with no byte in either direction for this long ends.
const IDLE_MS: i64 = 10 * 60 * 1000;

/// A `CONNECT` to `host:port` of the real network, which the rules of the
/// class passed.
pub fn outside(cas: &Cas, rules: &Proxy, mut tcp: TcpStream, out: &WayOut, host: &str, port: u16) {
    let up = match out.ask(host, port) {
        Ok(s) => s,
        Err(why) => {
            answer(&mut tcp, "502 Bad Gateway", &format!("pod-lab: the way out: {why}\n"));
            return;
        }
    };
    if tcp.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").is_err() {
        return;
    }
    match (&out.roots, rules.reterminate.is_empty()) {
        (_, true) => splice(tcp, up),
        (Some(roots), false) => {
            let _ = reterminate(cas, tcp, up, host, rules.refuse_upgrade, roots);
        }
        (None, false) => {}
    }
}

/// Copy each direction in a thread of its own, and shut the write side
/// at the end of the other.
pub fn splice(a: TcpStream, b: TcpStream) {
    let (Ok(a2), Ok(b2)) = (a.try_clone(), b.try_clone()) else { return };
    let one = std::thread::Builder::new().spawn(move || {
        let (mut from, mut to) = (a2, b2);
        let _ = std::io::copy(&mut from, &mut to);
        let _ = to.shutdown(Shutdown::Write);
    });
    let (mut from, mut to) = (b, a);
    let _ = std::io::copy(&mut from, &mut to);
    let _ = to.shutdown(Shutdown::Write);
    if let Ok(t) = one {
        let _ = t.join();
    }
}

/// Run the handshake of `conn` on `sock` to its end.
fn handshake(conn: &mut Connection, sock: &mut TcpStream) -> std::io::Result<()> {
    while conn.is_handshaking() {
        conn.complete_io(sock)?;
    }
    Ok(())
}

/// Write `data` as plain text of `conn`, and each record to `sock`.
fn send(conn: &mut Connection, sock: &mut TcpStream, mut data: &[u8]) -> std::io::Result<()> {
    while !data.is_empty() {
        let n = conn.writer().write(data)?;
        while conn.wants_write() {
            conn.write_tls(sock)?;
        }
        data = &data[n..];
    }
    Ok(())
}

/// The plain text that `from` holds, written to `to`. `Ok(false)`: the
/// peer of `from` closed.
fn drain(from: &mut Connection, to: &mut Connection, to_sock: &mut TcpStream) -> std::io::Result<bool> {
    let mut buf = [0u8; 16 * 1024];
    loop {
        match from.reader().read(&mut buf) {
            Ok(0) => return Ok(false),
            Ok(n) => send(to, to_sock, &buf[..n])?,
            Err(e) if e.kind() == ErrorKind::WouldBlock => return Ok(true),
            Err(e) => return Err(e),
        }
    }
}

/// One side: the TLS of `conn` on `sock`.
struct Side {
    conn: Connection,
    sock: TcpStream,
}

/// The plain text of a side, read as a stream.
struct Plain<'a>(&'a mut Side);

impl Read for Plain<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            match self.0.conn.reader().read(buf) {
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    if !take(self.0)? {
                        return Ok(0);
                    }
                }
                r => return r,
            }
        }
    }
}

/// Read the records that `sock` holds into `conn`. `Ok(false)`: the end.
fn take(side: &mut Side) -> std::io::Result<bool> {
    if side.conn.read_tls(&mut side.sock)? == 0 {
        return Ok(false);
    }
    side.conn.process_new_packets().map_err(std::io::Error::other)?;
    while side.conn.wants_write() {
        side.conn.write_tls(&mut side.sock)?;
    }
    Ok(true)
}

/// The plain text of two TLS streams, each way, until one ends.
fn pump(a: &mut Side, b: &mut Side) -> std::io::Result<()> {
    loop {
        if !drain(&mut a.conn, &mut b.conn, &mut b.sock)? || !drain(&mut b.conn, &mut a.conn, &mut a.sock)? {
            return Ok(());
        }
        let mut fds = [
            k::PollFd { fd: a.sock.as_raw_fd(), events: k::POLLIN, revents: 0 },
            k::PollFd { fd: b.sock.as_raw_fd(), events: k::POLLIN, revents: 0 },
        ];
        match k::ppoll(&mut fds, IDLE_MS) {
            Ok(0) => return Ok(()),
            Ok(_) => {}
            Err(e) if e == k::EINTR => continue,
            Err(e) => return Err(std::io::Error::from_raw_os_error(e.0)),
        }
        if fds[0].revents != 0 && !take(a)? {
            return Ok(());
        }
        if fds[1].revents != 0 && !take(b)? {
            return Ok(());
        }
    }
}

/// End a side with `close_notify`.
fn close(s: &mut Side) {
    s.conn.send_close_notify();
    while s.conn.wants_write() {
        if s.conn.write_tls(&mut s.sock).is_err() {
            break;
        }
    }
}

/// The TLS of the command, terminated with a leaf of the CA of the proxy
/// for `host`; the real server, checked with `roots`.
fn reterminate(
    cas: &Cas,
    tcp: TcpStream,
    up: TcpStream,
    host: &str,
    refuse: bool,
    roots: &Arc<rustls::RootCertStore>,
) -> Result<(), String> {
    let _ = tcp.set_read_timeout(Some(WAIT));
    if !matches!(peek_record(&tcp), Ok(Some(_))) {
        return Err("the command sent no TLS".to_string());
    }
    let config = cas.server(host, Ca::Proxy)?;
    let mut c = Side { conn: rustls::ServerConnection::new(config).map_err(|e| e.to_string())?.into(), sock: tcp };
    handshake(&mut c.conn, &mut c.sock).map_err(|e| format!("the TLS of the command: {e}"))?;
    let head = read_head(&mut Plain(&mut c))?;
    if refuse && header(&head, "upgrade").is_some() {
        let text = "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        let _ = send(&mut c.conn, &mut c.sock, text.as_bytes());
        close(&mut c);
        return Ok(());
    }
    let _ = up.set_read_timeout(Some(WAIT));
    let mut u = Side { conn: client(roots, host)?, sock: up };
    handshake(&mut u.conn, &mut u.sock).map_err(|e| format!("the TLS of the server: {e}"))?;
    send(&mut u.conn, &mut u.sock, head.as_bytes()).map_err(|e| e.to_string())?;
    let _ = c.sock.set_read_timeout(None);
    let _ = u.sock.set_read_timeout(None);
    let r = pump(&mut c, &mut u).map_err(|e| e.to_string());
    close(&mut c);
    close(&mut u);
    r
}

/// A TLS client of the real server `host` that trusts `roots`.
fn client(roots: &Arc<rustls::RootCertStore>, host: &str) -> Result<Connection, String> {
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(pod_tls::crypto::provider()))
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_root_certificates(Arc::clone(roots))
        .with_no_client_auth();
    let conn = rustls::ClientConnection::new(Arc::new(config), server_name(host)?).map_err(|e| e.to_string())?;
    Ok(conn.into())
}
