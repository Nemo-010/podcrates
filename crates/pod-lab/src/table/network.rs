//! The network classes: `proxy-only` (PodUtils/podrunner#180,
//! PodUtils/podssh#268) and the six classes of podnet's data
//! (PodUtils/podnet#592, `docs/lab-profiles/` of podnet at `dbd432c`).
//! Each lab is a network namespace with no route out and the stand-ins of
//! `crate::net` on its loopback. A part that podnet did not measure says
//! "Assumed:" in its text, with what is assumed: the lab holds the form of
//! the class that podssh or podnet named, and a real network can differ.

use super::parts::UDP_REFUSED;
use super::*;
use crate::net::{Ca, LISTED, NO_PROXY, Net, NetFact, OPEN, OTHER, Proxy};

const fn fact(f: NetFact) -> Observe {
    Observe::Lab(LabFact::Net(f))
}

const fn part(name: &'static str, about: &'static str, observe: &'static [Observe], net: &'static Net) -> Part {
    Part { name, about, observe, hold: Hold::LabNet(net) }
}

/// The ports of the proxy of podssh's `proxy-only` host.
const WEB_PORTS: &[u16] = &[443, 80, 8443];

static PROXY_ONLY: Net = Net { proxy: Some(Proxy { auth: true, ports: WEB_PORTS, ..OPEN }), ..NO_PROXY };

static RETERMINATE: Net = Net { proxy: Some(Proxy { reterminate: &[LISTED], silent: &[22], ..OPEN }), ..NO_PROXY };

static PER_NAME: Net = Net { proxy: Some(Proxy { timeout: &[OTHER], reset_literals: true, ..OPEN }), ..NO_PROXY };

static SNI: Net = Net { outside_v4: true, sni: Some(&[LISTED]), ..NO_PROXY };

static NO_DNS: Net = Net { outside_v4: true, no_resolver: true, ..NO_PROXY };

static WS: Net = Net { proxy: Some(Proxy { reterminate: &[LISTED], refuse_upgrade: true, ..OPEN }), ..NO_PROXY };

static V6: Net = Net { outside_v6: true, ..NO_PROXY };

pub(super) const PROXY_ONLY_PARTS: &[Part] = &[
    part(
        "direct-refused",
        "a direct TCP connect to an address outside fails",
        &[fact(NetFact::NoRouteV4)],
        &PROXY_ONLY,
    ),
    part(
        "proxy-reaches",
        "a CONNECT through the proxy with its credential reaches a TLS server",
        &[
            fact(NetFact::Connect { host: LISTED, port: 443, status: 200 }),
            fact(NetFact::Issuer { name: LISTED, ca: Ca::Server }),
        ],
        &PROXY_ONLY,
    ),
    part("proxy-credential", "a CONNECT with no credential gets 407", &[fact(NetFact::NeedsCredential)], &PROXY_ONLY),
    part(
        "port-refused",
        "the proxy reaches the ports 443, 80 and 8443 only: port 22 gets 403",
        &[fact(NetFact::Connect { host: LISTED, port: 22, status: 403 })],
        &PROXY_ONLY,
    ),
    UDP_REFUSED,
];

pub(super) const TLS_RETERMINATED: &[Part] = &[
    part(
        "tls-reterminated",
        "the proxy shows its own CA for a listed name, and passes another name. Assumed: the names that a real proxy terminates",
        &[fact(NetFact::Issuer { name: LISTED, ca: Ca::Proxy }), fact(NetFact::Issuer { name: OTHER, ca: Ca::Server })],
        &RETERMINATE,
    ),
    part(
        "ssh-port-silent",
        "CONNECT to port 22 gets 200, then no byte. Assumed: port 22; podnet measured the form on other ports",
        &[fact(NetFact::Silent { port: 22 })],
        &RETERMINATE,
    ),
];

pub(super) const PER_NAME_PARTS: &[Part] = &[part(
    "answer-per-name",
    "the proxy answers 200 for one name, 504 for another, and a reset for an IP literal. Assumed: the 504",
    &[
        fact(NetFact::Connect { host: LISTED, port: 443, status: 200 }),
        fact(NetFact::Connect { host: OTHER, port: 443, status: 504 }),
        fact(NetFact::LiteralReset),
    ],
    &PER_NAME,
)];

pub(super) const SNI_PARTS: &[Part] = &[part(
    "sni-reset",
    "a ClientHello with a name not on the list, or with no name, is reset. Assumed: the whole class",
    &[
        fact(NetFact::Hello { name: Some(LISTED), passes: true }),
        fact(NetFact::Hello { name: Some(OTHER), passes: false }),
        fact(NetFact::Hello { name: None, passes: false }),
    ],
    &SNI,
)];

pub(super) const NO_DNS_PARTS: &[Part] = &[
    part("no-resolver", "a lookup of a name fails", &[fact(NetFact::NoResolver)], &NO_DNS),
    part(
        "literal-reaches",
        "a TCP connect to an IP literal reaches out. Assumed: the stand-in server of the lab",
        &[fact(NetFact::LiteralReaches)],
        &NO_DNS,
    ),
];

pub(super) const WS_PARTS: &[Part] = &[part(
    "upgrade-refused",
    "the proxy passes a plain request and refuses the WebSocket upgrade. Assumed: the whole class",
    &[fact(NetFact::GetPasses), fact(NetFact::UpgradeRefused)],
    &WS,
)];

pub(super) const IPV6_ONLY: &[Part] = &[
    part(
        "no-ipv4-route",
        "a TCP connect to an IPv4 address outside fails; the loopback stays",
        &[fact(NetFact::NoRouteV4), fact(NetFact::LoopbackReaches)],
        &V6,
    ),
    part(
        "ipv6-reaches",
        "a TCP connect to an IPv6 address succeeds. Assumed: the stand-in server of the lab",
        &[fact(NetFact::V6Reaches)],
        &V6,
    ),
];
