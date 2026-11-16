//! The network namespace of a lab: the loopback up, the addresses of the
//! stand-ins on it, the files of the resolver, and the listening sockets of
//! the stand-ins. It runs in the new network namespace, before the lab
//! leaves the user namespace that owns it, as each change needs
//! `CAP_NET_ADMIN` there, and a port below 1024 `CAP_NET_BIND_SERVICE`.

use std::net::{Ipv4Addr, SocketAddr, TcpListener};

use pod_hostprobe::sys::{self as k, Errno};

use super::{Net, OUTSIDE_V4, PROXY_PORT, TLS_PORT, outside_v6};
use crate::hold::words;

/// The interface ioctls of `netdevice(7)`: the same number on each target.
const SIOCGIFFLAGS: u64 = 0x8913;
const SIOCSIFFLAGS: u64 = 0x8914;
const SIOCSIFADDR: u64 = 0x8916;
const SIOCGIFINDEX: u64 = 0x8933;
const IFF_UP: u16 = 1;

/// The listening sockets of a lab, made before the stand-in process starts,
/// so that a connect of the check from inside finds them.
#[derive(Debug)]
pub struct Ready {
    /// The stand-in proxy, where the class has one.
    pub proxy: Option<TcpListener>,
    /// The stand-in TLS server on each address of the lab.
    pub servers: Vec<TcpListener>,
}

/// One `ioctl(2)` of an interface request of `len` bytes.
fn ioctl(fd: i64, req: u64, buf: &mut [u8]) -> Result<(), Errno> {
    // SAFETY: the pointer is to a live buffer at least as long as the
    // request of `req`.
    unsafe { k::sys(k::SYS_IOCTL, [fd as u64, req, buf.as_mut_ptr() as u64, 0, 0, 0]) }.map(|_| ())
}

/// A `struct ifreq` of `name` (40 bytes, the size on a 64-bit target).
fn ifreq(name: &str) -> [u8; 40] {
    let mut r = [0u8; 40];
    r[..name.len()].copy_from_slice(name.as_bytes());
    r
}

/// The loopback up: the kernel gives it `127.0.0.1/8` (and `::1`).
fn loopback_up(fd: i64) -> Result<(), String> {
    let mut r = ifreq("lo");
    ioctl(fd, SIOCGIFFLAGS, &mut r).map_err(|e| words("ioctl(SIOCGIFFLAGS, lo)", e))?;
    let flags = u16::from_ne_bytes([r[16], r[17]]) | IFF_UP;
    r[16..18].copy_from_slice(&flags.to_ne_bytes());
    ioctl(fd, SIOCSIFFLAGS, &mut r).map_err(|e| words("ioctl(SIOCSIFFLAGS, lo)", e))
}

/// `192.0.2.1` on the alias `lo:1`: the kernel gives the class mask, and a
/// prefix on the loopback is local, so each address of `192.0.2.0/24`
/// reaches a socket bound to `0.0.0.0`.
fn outside_v4_up(fd: i64) -> Result<(), String> {
    let mut r = ifreq("lo:1");
    r[16..18].copy_from_slice(&(k::AF_INET as u16).to_ne_bytes());
    r[20..24].copy_from_slice(&OUTSIDE_V4);
    ioctl(fd, SIOCSIFADDR, &mut r).map_err(|e| words("ioctl(SIOCSIFADDR, lo:1, 192.0.2.1)", e))
}

/// The index of the device `name`.
fn index(fd: i64, name: &str) -> Result<i32, String> {
    let mut r = ifreq(name);
    ioctl(fd, SIOCGIFINDEX, &mut r).map_err(|e| words(&format!("ioctl(SIOCGIFINDEX, {name})"), e))?;
    Ok(i32::from_ne_bytes([r[16], r[17], r[18], r[19]]))
}

/// The IPv6 address of the lab on the loopback, with a prefix of 128, and
/// the dummy device with the IPv6 default route.
fn outside_v6_up() -> Result<(), String> {
    let fd = k::socket(k::AF_INET6, k::SOCK_DGRAM | k::SOCK_CLOEXEC, 0)
        .map_err(|e| format!("no IPv6 here: {}", words("socket(AF_INET6)", e)))?;
    let out = (|| {
        let index_lo = index(fd, "lo")?;
        // struct in6_ifreq: the address, the prefix length, the index.
        let mut a = [0u8; 24];
        a[..16].copy_from_slice(&outside_v6().octets());
        a[16..20].copy_from_slice(&128u32.to_ne_bytes());
        a[20..24].copy_from_slice(&index_lo.to_ne_bytes());
        ioctl(fd, SIOCSIFADDR, &mut a).map_err(|e| words("ioctl(SIOCSIFADDR, lo, the IPv6 address)", e))?;
        super::link::v6_default_route(|name| index(fd, name))
    })();
    let _ = k::close(fd);
    out
}

fn listen(at: SocketAddr) -> Result<TcpListener, String> {
    // A new IPv6 address can be tentative for a short time.
    let mut tries = 0;
    loop {
        match TcpListener::bind(at) {
            Err(e) if e.raw_os_error() == Some(99) && tries < 50 => {
                tries += 1;
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            r => return r.map_err(|e| format!("a listener on {at}: {e}")),
        }
    }
}

/// The text of `/etc/nsswitch.conf` with `hosts: files dns`, so that no
/// module of the C library asks a daemon of the host for a name.
fn nsswitch(text: &str) -> String {
    let mut out: String =
        text.lines().filter(|l| !l.trim_start().starts_with("hosts:")).map(|l| format!("{l}\n")).collect();
    out.push_str("hosts: files dns\n");
    out
}

/// The files of the resolver of a lab with no name server, each bound over
/// the file of the host where the host has one.
fn no_resolver() -> Result<(), String> {
    let bind = crate::mounts::bind_text;
    bind("/etc/resolv.conf", "options attempts:1 timeout:1\n")?;
    bind("/etc/hosts", "127.0.0.1 localhost\n::1 localhost\n")?;
    match std::fs::read_to_string("/etc/nsswitch.conf") {
        Ok(text) => bind("/etc/nsswitch.conf", &nsswitch(&text)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("/etc/nsswitch.conf: {e}")),
    }
}

/// Set the network namespace of `net`, and open the sockets of its
/// stand-ins.
pub fn prepare(net: &Net) -> Result<Ready, String> {
    let fd = k::socket(k::AF_INET, k::SOCK_DGRAM | k::SOCK_CLOEXEC, 0).map_err(|e| words("socket(AF_INET)", e))?;
    let up = loopback_up(fd)
        .and_then(|_| if net.outside_v4 { outside_v4_up(fd) } else { Ok(()) })
        .and_then(|_| if net.each_v4 { super::link::each_v4_local(index(fd, "lo")?) } else { Ok(()) });
    let _ = k::close(fd);
    up?;
    if net.outside_v6 {
        outside_v6_up()?;
    }
    if net.no_resolver {
        no_resolver()?;
    }
    let proxy = match net.proxy {
        Some(_) => Some(listen(SocketAddr::from((Ipv4Addr::LOCALHOST, PROXY_PORT)))?),
        None => None,
    };
    let mut servers = vec![listen(SocketAddr::from((Ipv4Addr::UNSPECIFIED, TLS_PORT)))?];
    if net.outside_v6 {
        servers.push(listen(SocketAddr::from((outside_v6(), TLS_PORT)))?);
    }
    Ok(Ready { proxy, servers })
}

#[cfg(test)]
mod tests {
    #[test]
    fn nsswitch_keeps_each_line_but_hosts() {
        let text = "passwd: files systemd\nhosts: files resolve [!UNAVAIL=return] dns\ngroup: files\n";
        assert_eq!(super::nsswitch(text), "passwd: files systemd\ngroup: files\nhosts: files dns\n");
    }
}
