//! The lab facts of the classes of podssh and podnet: the sockets that
//! listen, UDP, raw sockets and the loopback; the absent paths, the
//! terminal, the lines of the ids, `HOME` and the read-only mounts. Each is
//! measured in the lab process itself, before the command.

use pod_hostprobe::sys::{self as k, Errno};

use crate::check::{Seen, State};
use crate::inside::{errno_words, seen, tcp_socket};
use crate::profile::LabFact;

const EPERM: Errno = k::EPERM;
const EACCES: Errno = k::EACCES;
const EAFNOSUPPORT: Errno = Errno(linux_raw_sys::errno::EAFNOSUPPORT as i32);
const ENETUNREACH: Errno = Errno(linux_raw_sys::errno::ENETUNREACH as i32);
const EAGAIN: Errno = k::EWOULDBLOCK;
const IPPROTO_ICMP: u64 = 1;

fn c(path: &str) -> k::CBuf {
    k::CBuf::new(path).expect("a path of a profile has no NUL")
}

fn id(nr: i64) -> u32 {
    // SAFETY: no pointer; getuid and getgid always succeed.
    unsafe { k::sys(nr, [0; 6]) }.map_or(0, |n| n as u32)
}

/// The address `[::1]:port`.
fn loopback6(port: u16) -> [u8; 28] {
    let mut a = [0u8; 28];
    a[0..2].copy_from_slice(&(k::AF_INET6 as u16).to_ne_bytes());
    a[2..4].copy_from_slice(&port.to_be_bytes());
    a[23] = 1;
    a
}

/// [`LabFact::BindAllowed`] and [`LabFact::ListenRefused`]: a TCP bind of
/// `127.0.0.1:0`, then `listen(2)`.
pub fn listen(fact: LabFact) -> Seen {
    let fd = match tcp_socket(fact, k::AF_INET) {
        Ok(fd) => fd,
        Err(s) => return s,
    };
    let a = k::sockaddr_in([127, 0, 0, 1], 0);
    let bound = k::bind(fd, a.as_ptr() as u64, a.len() as u64);
    let listened = bound.map(|_| k::listen(fd, 1));
    let _ = k::close(fd);
    match (fact, listened) {
        (LabFact::BindAllowed, Ok(_)) => seen(fact, State::Holds, None, "bind(127.0.0.1:0) succeeded"),
        (LabFact::BindAllowed, Err(e)) => {
            seen(fact, State::Fails, Some(e), format!("bind(127.0.0.1:0): {}", errno_words(e)))
        }
        (_, Err(e)) => {
            seen(fact, State::Unseen, Some(e), format!("the bind failed, so no listen ran: {}", errno_words(e)))
        }
        (_, Ok(Err(e))) if e == EACCES || e == EPERM => {
            seen(fact, State::Holds, Some(e), format!("listen: {}", errno_words(e)))
        }
        (_, Ok(Err(e))) => {
            seen(fact, State::Fails, Some(e), format!("listen: {}; the profile wants EACCES or EPERM", errno_words(e)))
        }
        (_, Ok(Ok(_))) => seen(fact, State::Fails, None, "listen succeeded; the profile wants EACCES or EPERM"),
    }
}

/// [`LabFact::UdpRefused`]: a UDP socket of each family, and its connect to
/// the loopback.
pub fn udp(fact: LabFact) -> Seen {
    let v4 = k::sockaddr_in([127, 0, 0, 1], 9);
    let v6 = loopback6(9);
    for (family, name, addr) in [(k::AF_INET, "IPv4", &v4[..]), (k::AF_INET6, "IPv6", &v6[..])] {
        let fd = match k::socket(family, k::SOCK_DGRAM | k::SOCK_CLOEXEC, 0) {
            Err(e) if e == EPERM || e == EACCES => continue,
            // No IPv6 here: no UDP of the family can pass.
            Err(e) if e == EAFNOSUPPORT && family == k::AF_INET6 => continue,
            Err(e) => {
                let why = format!("a UDP socket of {name}: {}", errno_words(e));
                return seen(fact, State::Fails, Some(e), why);
            }
            Ok(fd) => fd,
        };
        let r = k::connect(fd, addr);
        let _ = k::close(fd);
        match r {
            Err(e) if e == EPERM || e == EACCES => {}
            Err(e) => return seen(fact, State::Fails, Some(e), format!("UDP connect of {name}: {}", errno_words(e))),
            Ok(_) => return seen(fact, State::Fails, None, format!("a UDP socket and connect of {name} succeeded")),
        }
    }
    seen(fact, State::Holds, None, "each UDP socket or its connect was refused")
}

/// [`LabFact::RawRefused`]: a raw ICMP socket of `AF_INET`, and a packet
/// socket.
pub fn raw(fact: LabFact) -> Seen {
    let tries =
        [("socket(AF_INET, SOCK_RAW)", k::AF_INET, IPPROTO_ICMP), ("socket(AF_PACKET, SOCK_RAW)", k::AF_PACKET, 0)];
    for (call, family, protocol) in tries {
        match k::socket(family, k::SOCK_RAW | k::SOCK_CLOEXEC, protocol) {
            Err(e) if e == EPERM => {}
            // A kernel with no packet family.
            Err(e) if e == EAFNOSUPPORT && family == k::AF_PACKET => {}
            Err(e) => {
                return seen(
                    fact,
                    State::Fails,
                    Some(e),
                    format!("{call}: {}; the profile wants EPERM", errno_words(e)),
                );
            }
            Ok(fd) => {
                let _ = k::close(fd);
                return seen(fact, State::Fails, None, format!("{call} succeeded; the profile wants EPERM"));
            }
        }
    }
    seen(fact, State::Holds, Some(EPERM), "each raw and packet socket gives EPERM")
}

/// [`LabFact::NoLoopback`]: a TCP connect of `127.0.0.1:1`.
pub fn no_loopback(fact: LabFact) -> Seen {
    let fd = match tcp_socket(fact, k::AF_INET) {
        Ok(fd) => fd,
        Err(s) => return s,
    };
    let r = k::connect(fd, &k::sockaddr_in([127, 0, 0, 1], 1));
    let _ = k::close(fd);
    match r {
        Err(e) if e == ENETUNREACH => seen(fact, State::Holds, Some(e), format!("connect: {}", errno_words(e))),
        Err(e) => seen(fact, State::Fails, Some(e), format!("connect: {}; the loopback answers", errno_words(e))),
        Ok(_) => seen(fact, State::Fails, None, "connect succeeded; the loopback answers"),
    }
}

/// [`LabFact::Absent`].
pub fn absent(fact: LabFact, path: &str) -> Seen {
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => seen(fact, State::Holds, None, format!("{path}: ENOENT")),
        Err(e) => seen(fact, State::Fails, None, format!("{path}: {e}; the profile wants ENOENT")),
        Ok(_) => seen(fact, State::Fails, None, format!("{path} exists")),
    }
}

/// [`LabFact::NoControllingTerminal`]: the field `tty_nr` of
/// `/proc/self/stat`.
pub fn no_ctty(fact: LabFact) -> Seen {
    let text = match std::fs::read_to_string("/proc/self/stat") {
        Ok(t) => t,
        Err(e) => return seen(fact, State::Unseen, None, format!("/proc/self/stat: {e}")),
    };
    // The fields after the name: state, ppid, pgrp, session, tty_nr.
    let tty = text.rsplit_once(')').and_then(|(_, rest)| rest.split_whitespace().nth(4)?.parse::<i64>().ok());
    match tty {
        Some(0) => seen(fact, State::Holds, None, "tty_nr is 0"),
        Some(n) => seen(fact, State::Fails, None, format!("tty_nr is {n}; the profile wants no terminal")),
        None => seen(fact, State::Unseen, None, "no field tty_nr in /proc/self/stat"),
    }
}

/// [`LabFact::TtyOpens`]: an open of `/dev/tty` with no wait, then a read
/// that finds no data.
pub fn tty_opens(fact: LabFact) -> Seen {
    let flags = k::O_RDWR | k::O_NOCTTY | k::O_NONBLOCK | k::O_CLOEXEC;
    let fd = match k::open(&c("/dev/tty"), flags, 0) {
        Ok(fd) => fd,
        Err(e) => return seen(fact, State::Fails, Some(e), format!("open(/dev/tty): {}", errno_words(e))),
    };
    let mut b = [0u8; 1];
    let r = k::read(fd, &mut b);
    let _ = k::close(fd);
    match r {
        Err(e) if e == EAGAIN => seen(fact, State::Holds, Some(e), "/dev/tty opened; a read has no data"),
        Err(e) => seen(fact, State::Fails, Some(e), format!("a read of /dev/tty: {}", errno_words(e))),
        Ok(n) => seen(fact, State::Fails, None, format!("a read of /dev/tty gave {n} bytes; the profile wants none")),
    }
}

/// [`LabFact::NoPasswdEntry`]: the third field of each line.
pub fn no_passwd_entry(fact: LabFact) -> Seen {
    for (file, id) in [("/etc/passwd", id(k::SYS_GETUID)), ("/etc/group", id(k::SYS_GETGID))] {
        let text = match std::fs::read_to_string(file) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return seen(fact, State::Unseen, None, format!("{file}: {e}")),
        };
        let id = id.to_string();
        if text.lines().any(|l| l.split(':').nth(2) == Some(id.as_str())) {
            return seen(fact, State::Fails, None, format!("{file} has a line of the id {id}"));
        }
    }
    seen(fact, State::Holds, None, "no line of the uid or of the gid")
}

/// [`LabFact::HomeNoexec`]: the mount flags of `HOME`, and a new file in it.
pub fn home_noexec(fact: LabFact) -> Seen {
    let Ok(home) = std::env::var("HOME") else {
        return seen(fact, State::Fails, None, "HOME is not set");
    };
    match k::statfs(&c(&home)).map(|s| s.flag(k::ST_NOEXEC)) {
        Ok(Some(true)) => {}
        Ok(Some(false)) => return seen(fact, State::Fails, None, format!("{home} is not on a noexec mount")),
        Ok(None) => return seen(fact, State::Unseen, None, "statfs gave no mount flags"),
        Err(e) => return seen(fact, State::Fails, Some(e), format!("statfs({home}): {}", errno_words(e))),
    }
    let probe = format!("{}/.podlab-{}", home.trim_end_matches('/'), k::getpid());
    match k::open(&c(&probe), k::O_WRONLY | k::O_CREAT | k::O_EXCL | k::O_CLOEXEC, 0o600) {
        Ok(fd) => {
            let _ = k::close(fd);
            let _ = k::unlink(&c(&probe));
            seen(fact, State::Holds, None, format!("{home} is writable and noexec"))
        }
        Err(e) => seen(fact, State::Fails, Some(e), format!("a new file in {home}: {}", errno_words(e))),
    }
}

/// [`LabFact::ReadOnlyMount`]: the mount flags of `path`.
pub fn read_only(fact: LabFact, path: &str) -> Seen {
    match k::statfs(&c(path)).map(|s| s.flag(k::ST_RDONLY)) {
        Ok(Some(true)) => seen(fact, State::Holds, None, format!("{path} is read-only")),
        Ok(Some(false)) => seen(fact, State::Fails, None, format!("{path} is on a mount that is not read-only")),
        Ok(None) => seen(fact, State::Unseen, None, "statfs gave no mount flags"),
        Err(e) => seen(fact, State::Fails, Some(e), format!("statfs({path}): {}", errno_words(e))),
    }
}
