//! The rows of the socket classes of podssh and podnet: a TCP bind alone,
//! `listen(2)` after that bind, a UDP socket and its connect of each
//! family, a raw and a packet socket, and a TCP connect to the loopback.
//! Each row runs in its own child, and none sends a packet past the
//! loopback.

use super::*;

/// `IPPROTO_ICMP`: a raw socket of this protocol is the one of `ping`.
const IPPROTO_ICMP: u64 = 1;
/// The time limit of a TCP connect to the loopback. The kernel answers a
/// connect there at once; a filter that drops the packets gives no answer.
const CONNECT_WAIT_MS: i64 = 2000;
/// `SOCK_NONBLOCK` is `O_NONBLOCK` on each architecture.
const SOCK_NONBLOCK: u64 = sys::O_NONBLOCK;
const POLLOUT: i16 = linux_raw_sys::general::POLLOUT as i16;

/// The address `[::1]:port`, `struct sockaddr_in6`.
pub(super) fn loopback6(port: u16) -> [u8; 28] {
    let mut a = [0u8; 28];
    a[0..2].copy_from_slice(&(sys::AF_INET6 as u16).to_ne_bytes());
    a[2..4].copy_from_slice(&port.to_be_bytes());
    a[23] = 1;
    a
}

/// A TCP socket of IPv4, or the denial of `socket(2)`.
fn tcp4(flags: u64) -> Result<i64, Outcome> {
    sys::socket(sys::AF_INET, sys::SOCK_STREAM | sys::SOCK_CLOEXEC | flags, 0).map_err(refused("socket(2)"))
}

/// The denial of the step `call`, with the step in the reason.
fn refused(call: &'static str) -> impl Fn(Errno) -> Outcome {
    move |e| Outcome { reason: format!("{call} refused"), ..Outcome::denied(e) }
}

/// A TCP bind of `127.0.0.1:0` on `fd`.
fn bind_loopback(fd: i64) -> Result<i64, Errno> {
    let a = sys::sockaddr_in([127, 0, 0, 1], 0);
    sys::bind(fd, a.as_ptr() as u64, a.len() as u64)
}

pub(super) fn p_bind() -> Outcome {
    let fd = match tcp4(0) {
        Ok(fd) => fd,
        Err(o) => return o,
    };
    let r = bind_loopback(fd);
    let _ = sys::close(fd);
    Outcome::from(r)
}

/// `listen(2)` alone: a bind that fails is a precondition, so the row
/// tells a refused listen from a refused bind.
pub(super) fn p_listen_after_bind() -> Outcome {
    let fd = match sys::socket(sys::AF_INET, sys::SOCK_STREAM | sys::SOCK_CLOEXEC, 0) {
        Ok(fd) => fd,
        Err(e) => return precondition("socket(AF_INET, SOCK_STREAM)", e),
    };
    let r = match bind_loopback(fd) {
        Ok(_) => Outcome::from(sys::listen(fd, 1)),
        Err(e) => precondition("bind(127.0.0.1:0)", e),
    };
    let _ = sys::close(fd);
    r
}

/// A UDP socket of `family` and its connect to `addr`. The connect sends
/// no packet: it sets the peer of the socket.
fn udp(family: u64, addr: &[u8]) -> Outcome {
    let fd = match sys::socket(family, sys::SOCK_DGRAM | sys::SOCK_CLOEXEC, 0) {
        Ok(fd) => fd,
        Err(e) => return refused("socket(2)")(e),
    };
    let r = sys::connect(fd, addr);
    let _ = sys::close(fd);
    match r {
        Ok(_) => Outcome::ok(),
        Err(e) => refused("connect(2)")(e),
    }
}

pub(super) fn p_udp4() -> Outcome {
    udp(sys::AF_INET, &sys::sockaddr_in([127, 0, 0, 1], 9))
}

/// A host with no IPv6 gives `EAFNOSUPPORT` on the socket: a denial, as no
/// UDP of the family can pass.
pub(super) fn p_udp6() -> Outcome {
    udp(sys::AF_INET6, &loopback6(9))
}

fn raw(family: u64, protocol: u64) -> Outcome {
    match sys::socket(family, sys::SOCK_RAW | sys::SOCK_CLOEXEC, protocol) {
        Ok(fd) => {
            let _ = sys::close(fd);
            Outcome::ok()
        }
        Err(e) => Outcome::denied(e),
    }
}

pub(super) fn p_raw_inet() -> Outcome {
    raw(sys::AF_INET, IPPROTO_ICMP)
}

/// Protocol 0: the socket gets no packet, so it reads nothing of the host.
pub(super) fn p_packet() -> Outcome {
    raw(sys::AF_PACKET, 0)
}

/// What a TCP connect to a port of `127.0.0.1` got.
pub(super) enum Answer {
    /// A listener took it.
    Listener,
    /// A reset: the loopback answers, and no listener has the port.
    Reset,
    /// The kernel refused it: its errno.
    Refused(Errno),
    /// No answer in the time limit.
    Silent,
}

/// A TCP connect to `127.0.0.1:port` that waits at most
/// [`CONNECT_WAIT_MS`]. `Err`: the denial of `socket(2)`.
pub(super) fn connect_loopback(port: u16) -> Result<Answer, Outcome> {
    let fd = tcp4(SOCK_NONBLOCK)?;
    let addr = sys::sockaddr_in([127, 0, 0, 1], port);
    let first = sys::connect(fd, &addr);
    let answer = match first {
        Ok(_) => Answer::Listener,
        Err(sys::EINPROGRESS) => {
            let mut p = [sys::PollFd { fd: fd as i32, events: POLLOUT, revents: 0 }];
            match sys::ppoll(&mut p, CONNECT_WAIT_MS) {
                Ok(0) => Answer::Silent,
                // A second connect gives the result of the first: 0 or
                // `EISCONN` where it is connected, else its error.
                _ => match sys::connect(fd, &addr) {
                    Ok(_) | Err(sys::EISCONN) => Answer::Listener,
                    Err(sys::ECONNREFUSED) => Answer::Reset,
                    Err(e) => Answer::Refused(e),
                },
            }
        }
        Err(sys::ECONNREFUSED) => Answer::Reset,
        Err(e) => Answer::Refused(e),
    };
    let _ = sys::close(fd);
    Ok(answer)
}

/// `ECONNREFUSED` is the loopback's answer, not a denial: the row is `ok`
/// with the errno in its reason. `ENETUNREACH` (no loopback) and `EACCES`
/// (a policy on each connect) are denials.
pub(super) fn p_connect_loopback() -> Outcome {
    match connect_loopback(1) {
        Err(o) => o,
        Ok(Answer::Listener) => Outcome::ok_with("a listener took the connect"),
        Ok(Answer::Reset) => {
            let e = sys::ECONNREFUSED;
            Outcome::ok_with(format!("{} ({}): the loopback answers, and no listener has port 1", e.name(), e.0))
        }
        Ok(Answer::Refused(e)) => Outcome::denied(e),
        Ok(Answer::Silent) => {
            Outcome::skip(None, format!("no answer in {CONNECT_WAIT_MS} ms: a filter drops the packets"))
        }
    }
}
