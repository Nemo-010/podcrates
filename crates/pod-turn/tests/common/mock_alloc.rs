// The Allocate of the mock TURN server: REQUESTED-TRANSPORT, and the
// options of RFC 8656, 7.2 in the mock's own reading: REQUESTED-ADDRESS-FAMILY,
// ADDITIONAL-ADDRESS-FAMILY (ADDRESS-ERROR-CODE when it has no IPv6),
// EVEN-PORT with its reservation of the next port, RESERVATION-TOKEN, and
// DONT-FRAGMENT (420 when the knob says the mock cannot set DF).

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use pod_turn::stun::{self, Class};
use tokio::net::UdpSocket;

use super::mock::{Alloc, Mock, SUCCESS, Session, spawn_relay};

const IPV4: u8 = 1;
const IPV6: u8 = 2;

impl Mock {
    pub(super) async fn allocate(
        &self,
        session: &mut Session,
        read: &stun::Message<'_>,
        user: &str,
        key: &[u8],
        lifetime: u32,
    ) -> (u16, Vec<u8>) {
        let (method, id) = (stun::ALLOCATE, read.id);
        let fail = |code| (code, self.error(method, &id, code, &[], Some(key)));
        if session.alloc.is_some() {
            return fail(437);
        }
        if read.attribute(stun::REQUESTED_TRANSPORT) != Some(&[17, 0, 0, 0][..]) {
            return fail(442);
        }
        if read.attribute(stun::DONT_FRAGMENT).is_some() && !self.knobs.dont_fragment {
            let unknown = stun::DONT_FRAGMENT.to_be_bytes();
            return (420, self.error(method, &id, 420, &[(stun::UNKNOWN_ATTRIBUTES, &unknown)], Some(key)));
        }
        let family = |kind| read.attribute(kind).and_then(|v| v.first().copied());
        let (requested, additional) = (family(stun::REQUESTED_ADDRESS_FAMILY), family(stun::ADDITIONAL_ADDRESS_FAMILY));
        let even = read.attribute(stun::EVEN_PORT).map(|v| v.first().is_some_and(|b| b & 0x80 != 0));
        let token = read.attribute(stun::RESERVATION_TOKEN);
        let reserve_with_both = even == Some(true) && additional.is_some();
        let token_with_more = token.is_some() && (even.is_some() || requested.is_some() || additional.is_some());
        if reserve_with_both || token_with_more || (requested.is_some() && additional.is_some()) {
            return fail(400);
        }
        if additional.is_some_and(|f| f != IPV6) {
            return fail(400);
        }
        if requested == Some(IPV6) && !self.knobs.ipv6 {
            return fail(440);
        }
        let relay = match token {
            Some(token) => {
                let token = <[u8; 8]>::try_from(token).unwrap_or_default();
                let Some(relay) = self.control.lock().unwrap().reserved.remove(&token) else { return fail(508) };
                relay
            }
            None => match even {
                None => Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap()),
                Some(reserve) => self.even_relay(reserve).await,
            },
        };
        let port = relay.local_addr().unwrap().port();
        let next = (even == Some(true)).then(|| (port + 1).to_be_bytes());
        let token = next.map(|p| [b'm', b'o', b'c', b'k', 0, 0, p[0], p[1]]);
        spawn_relay(relay.clone(), session.client, self.relayed.clone());
        let alloc = Alloc { owner: user.into(), relay, permissions: HashSet::new(), channels: HashMap::new() };
        session.alloc = Some(alloc);
        let v6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port);
        let v4 = SocketAddr::new(IpAddr::V4([127, 0, 0, 1].into()), port);
        let relayed: Vec<SocketAddr> = match (requested, additional) {
            (Some(IPV6), _) => vec![v6],
            (_, Some(_)) if self.knobs.ipv6 => vec![v4, v6],
            _ => vec![v4],
        };
        let relayed: Vec<Vec<u8>> = relayed.iter().map(|a| stun::write_address(*a, Some(&id))).collect();
        let (mapped, life) = (stun::write_address(session.client, Some(&id)), lifetime.to_be_bytes());
        let mut attributes: Vec<(u16, &[u8])> =
            relayed.iter().map(|r| (stun::XOR_RELAYED_ADDRESS, r.as_slice())).collect();
        attributes.extend([(stun::XOR_MAPPED_ADDRESS, mapped.as_slice()), (stun::LIFETIME, &life)]);
        attributes.extend(token.as_ref().map(|t| (stun::RESERVATION_TOKEN, t.as_slice())));
        let no_ipv6 = [[IPV6, 0, 4, 40].as_slice(), b"no IPv6"].concat();
        if additional.is_some() && !self.knobs.ipv6 {
            attributes.push((stun::ADDRESS_ERROR_CODE, &no_ipv6));
        }
        (SUCCESS, self.answer(method, Class::Success, &id, &attributes, Some(key)))
    }

    /// A relay socket of an even port; with `reserve`, the socket of the
    /// next port too, kept in the control by its token.
    async fn even_relay(&self, reserve: bool) -> Arc<UdpSocket> {
        loop {
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let port = socket.local_addr().unwrap().port();
            if port % 2 == 1 {
                continue;
            }
            if !reserve {
                return Arc::new(socket);
            }
            let Ok(next) = UdpSocket::bind(("127.0.0.1", port + 1)).await else { continue };
            let p = (port + 1).to_be_bytes();
            let token = [b'm', b'o', b'c', b'k', 0, 0, p[0], p[1]];
            self.control.lock().unwrap().reserved.insert(token, Arc::new(next));
            return Arc::new(socket);
        }
    }
}
