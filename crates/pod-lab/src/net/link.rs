//! The routes and the device of a network lab by `NETLINK_ROUTE`: a local
//! route of each IPv4 address on the loopback (the filter of `sni-allowlist`
//! on each address), and a dummy device with an IPv6 address and an IPv6
//! default route (`ipv6-only`). A real host of the class shows that route
//! in `/proc/net/ipv6_route`; a route on the loopback is the reject entry.

use pod_hostprobe::sys::{self as k, Errno};

use super::outside_v6;
use crate::hold::words;

/// The dummy device of `ipv6-only` (podnet's profile).
pub const DUMMY: &str = "lab0";
/// The address of the lab on [`DUMMY`]: the host part 2 of the prefix of
/// [`super::OUTSIDE_V6`], length 64.
pub fn dummy_v6() -> std::net::Ipv6Addr {
    let mut o = outside_v6().octets();
    o[15] = 2;
    o.into()
}

const NETLINK_ROUTE: u64 = 0;
const RTM_NEWLINK: u16 = 16;
const RTM_NEWADDR: u16 = 20;
const RTM_NEWROUTE: u16 = 24;
const NLMSG_ERROR: u16 = 2;
const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_ACK: u16 = 0x4;
const NLM_F_EXCL: u16 = 0x200;
const NLM_F_CREATE: u16 = 0x400;
const IFLA_IFNAME: u16 = 3;
const IFLA_LINKINFO: u16 = 18;
const IFLA_INFO_KIND: u16 = 1;
const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const IFA_F_NODAD: u8 = 0x02;
const RTA_DST: u16 = 1;
const RTA_OIF: u16 = 4;
const RT_TABLE_MAIN: u8 = 254;
const RT_TABLE_LOCAL: u8 = 255;
const RTPROT_STATIC: u8 = 4;
const RT_SCOPE_UNIVERSE: u8 = 0;
const RT_SCOPE_HOST: u8 = 254;
const RTN_UNICAST: u8 = 1;
const RTN_LOCAL: u8 = 2;
const IFF_UP: u32 = 1;
const NLMSGHDR: usize = 16;

/// Add one attribute, with its padding to 4 bytes.
fn attr(buf: &mut Vec<u8>, kind: u16, data: &[u8]) {
    buf.extend_from_slice(&((4 + data.len()) as u16).to_ne_bytes());
    buf.extend_from_slice(&kind.to_ne_bytes());
    buf.extend_from_slice(data);
    buf.resize(buf.len().next_multiple_of(4), 0);
}

/// A request of `kind` with its fixed header `body`; the attributes follow.
fn request(kind: u16, create: bool, body: &[u8]) -> Vec<u8> {
    let mut msg = vec![0u8; NLMSGHDR];
    let mut flags = NLM_F_REQUEST | NLM_F_ACK;
    if create {
        flags |= NLM_F_CREATE | NLM_F_EXCL;
    }
    msg[4..6].copy_from_slice(&kind.to_ne_bytes());
    msg[6..8].copy_from_slice(&flags.to_ne_bytes());
    msg[8..12].copy_from_slice(&1u32.to_ne_bytes());
    msg.extend_from_slice(body);
    msg
}

/// Send `msg` to the kernel and read its acknowledgement.
fn talk(mut msg: Vec<u8>) -> Result<(), Errno> {
    let len = msg.len() as u32;
    msg[0..4].copy_from_slice(&len.to_ne_bytes());
    let fd = k::socket(k::AF_NETLINK, k::SOCK_RAW | k::SOCK_CLOEXEC, NETLINK_ROUTE)?;
    let out = (|| {
        k::write(fd, &msg)?;
        let mut answer = [0u8; 1024];
        let n = k::read(fd, &mut answer)? as usize;
        match ack(&answer[..n]) {
            Some(0) => Ok(()),
            Some(e) => Err(Errno(e)),
            // EPROTO: the kernel answered with no acknowledgement.
            None => Err(Errno(71)),
        }
    })();
    let _ = k::close(fd);
    out
}

/// The error code of a netlink acknowledgement (0 is success).
pub(crate) fn ack(answer: &[u8]) -> Option<i32> {
    if answer.len() < NLMSGHDR + 4 || u16::from_ne_bytes([answer[4], answer[5]]) != NLMSG_ERROR {
        return None;
    }
    let e = i32::from_ne_bytes([answer[16], answer[17], answer[18], answer[19]]);
    Some(-e)
}

/// `struct ifinfomsg` with the flag up.
fn ifinfo(index: i32, up: bool) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[4..8].copy_from_slice(&index.to_ne_bytes());
    if up {
        b[8..12].copy_from_slice(&IFF_UP.to_ne_bytes());
        b[12..16].copy_from_slice(&IFF_UP.to_ne_bytes());
    }
    b
}

/// The request of a dummy device `name`, up.
pub(crate) fn dummy_request(name: &str) -> Vec<u8> {
    let mut msg = request(RTM_NEWLINK, true, &ifinfo(0, true));
    let mut bytes = name.as_bytes().to_vec();
    bytes.push(0);
    attr(&mut msg, IFLA_IFNAME, &bytes);
    let mut info = Vec::new();
    attr(&mut info, IFLA_INFO_KIND, b"dummy");
    attr(&mut msg, IFLA_LINKINFO, &info);
    msg
}

/// The request of the IPv6 address of [`dummy_v6`]/64 on the device
/// `index`, with no duplicate address detection.
pub(crate) fn address_request(index: i32) -> Vec<u8> {
    // struct ifaddrmsg: the family, the prefix length, the flags, the scope,
    // the index.
    let mut body = [0u8; 8];
    body[0] = k::AF_INET6 as u8;
    body[1] = 64;
    body[2] = IFA_F_NODAD;
    body[4..8].copy_from_slice(&index.to_ne_bytes());
    let mut msg = request(RTM_NEWADDR, true, &body);
    let a = dummy_v6().octets();
    attr(&mut msg, IFA_LOCAL, &a);
    attr(&mut msg, IFA_ADDRESS, &a);
    msg
}

/// The request of a route with a prefix of length 0 through the device
/// `index`: in IPv6 the default route of the main table; in IPv4 a local
/// route of each address (the table `local`).
pub(crate) fn route_request(v6: bool, index: i32) -> Vec<u8> {
    // struct rtmsg: the family, the lengths of the destination and the
    // source, the TOS, the table, the protocol, the scope, the type, flags.
    let (family, table, scope, kind) = if v6 {
        (k::AF_INET6 as u8, RT_TABLE_MAIN, RT_SCOPE_UNIVERSE, RTN_UNICAST)
    } else {
        (k::AF_INET as u8, RT_TABLE_LOCAL, RT_SCOPE_HOST, RTN_LOCAL)
    };
    let body = [family, 0, 0, 0, table, RTPROT_STATIC, scope, kind, 0, 0, 0, 0];
    let mut msg = request(RTM_NEWROUTE, true, &body);
    let dst: &[u8] = if v6 { &[0; 16] } else { &[0; 4] };
    attr(&mut msg, RTA_DST, dst);
    attr(&mut msg, RTA_OIF, &index.to_ne_bytes());
    msg
}

/// Each IPv4 address but the loopback reaches a socket of the lab bound to
/// `0.0.0.0`: a local route of `0.0.0.0/0` on the loopback (`index`).
pub fn each_v4_local(lo: i32) -> Result<(), String> {
    talk(route_request(false, lo)).map_err(|e| words("RTM_NEWROUTE local 0.0.0.0/0 dev lo", e))
}

/// The dummy device [`DUMMY`], up, with [`dummy_v6`]/64 and the IPv6
/// default route through it. `index` gives the index of a device by name.
pub fn v6_default_route(index: impl Fn(&str) -> Result<i32, String>) -> Result<(), String> {
    talk(dummy_request(DUMMY)).map_err(|e| words("RTM_NEWLINK dummy lab0", e))?;
    let i = index(DUMMY)?;
    talk(address_request(i)).map_err(|e| words("RTM_NEWADDR lab0, the IPv6 address", e))?;
    talk(route_request(true, i)).map_err(|e| words("RTM_NEWROUTE default dev lab0", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_has_its_kind_its_flags_and_padded_attributes() {
        let m = route_request(false, 1);
        assert_eq!(u16::from_ne_bytes([m[4], m[5]]), RTM_NEWROUTE);
        assert_eq!(u16::from_ne_bytes([m[6], m[7]]), NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL);
        // The header, the rtmsg, RTA_DST of 4 bytes and RTA_OIF.
        assert_eq!(m.len(), 16 + 12 + 8 + 8);
        assert_eq!(&m[16..28], &[2, 0, 0, 0, 255, 4, 254, 2, 0, 0, 0, 0]);
        let d = dummy_request("lab0");
        assert_eq!(d.len() % 4, 0);
        assert!(d.windows(5).any(|w| w == b"dummy"));
    }

    #[test]
    fn the_address_of_the_dummy_is_two_of_the_prefix_of_the_lab() {
        assert_eq!(dummy_v6().to_string(), "fd00:6c61:62::2");
        let m = address_request(7);
        assert_eq!(&m[16..20], &[10, 64, IFA_F_NODAD, 0]);
        assert_eq!(&m[20..24], &7i32.to_ne_bytes());
    }

    #[test]
    fn an_acknowledgement_gives_its_errno() {
        let mut a = vec![0u8; 36];
        a[4..6].copy_from_slice(&NLMSG_ERROR.to_ne_bytes());
        a[16..20].copy_from_slice(&(-17i32).to_ne_bytes());
        assert_eq!(ack(&a), Some(17));
        a[16..20].copy_from_slice(&0i32.to_ne_bytes());
        assert_eq!(ack(&a), Some(0));
        assert_eq!(ack(&a[..10]), None);
    }
}
