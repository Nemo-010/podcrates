//! The network classes: `proxy-only` (PodUtils/podrunner#180,
//! PodUtils/podssh#268) and the six classes of podnet's data
//! (PodUtils/podnet#592, `docs/lab-profiles/` of podnet at `dbd432c`).
//! Each lab is a network namespace with no route out and the stand-ins of
//! `crate::net` on its loopback. A part that podnet did not measure says
//! "Assumed:" in its text, with what is assumed: the lab holds the form of
//! the class that podssh or podnet named, and a real network can differ.
//!
//! A row of `pod-hostprobe` sees what a host shows of its way out with no
//! packet out: the variable of a proxy, the certificate file, the resolver
//! and the default routes. Those facts are parts of their own, so that a
//! check of a report gives them a verdict. A fact that needs a packet
//! through a proxy or to a server reads the rows that send a packet out
//! (`pod_hostprobe::probes::NETWORK_ROWS`): a report holds them where its
//! caller set `Settings::network`, else they are unseen. The lab measures
//! the same rows against its stand-ins, and checks the fact of its own
//! stand-ins beside them. The upgrade of a WebSocket has no row.

use super::parts::UDP_REFUSED;
use super::*;
use crate::net::{Ca, LISTED, NO_PROXY, Net, NetFact, OPEN, OTHER, Proxy};
use pod_hostprobe::probes::{
    CONNECT_CLOSED, CONNECT_LITERAL, CONNECT_NAME, CONNECT_NO_CREDENTIAL, CONNECT_OTHER, TLS_LITERAL, TLS_NAME,
    TLS_OTHER,
};

const fn fact(f: NetFact) -> Observe {
    Observe::Lab(LabFact::Net(f))
}

/// A fact that the lab checks of its own stand-ins, beside the rows.
const fn lab_check(f: NetFact) -> Observe {
    Observe::LabCheck(LabFact::Net(f))
}

/// A row that sends a packet out gives `key value`.
const fn sends(name: &'static str, key: &'static str, value: &'static str) -> Observe {
    row(name, Expect::Value { key, value })
}

const PROXY: &str = "getenv(HTTPS_PROXY)";
const ROUTE4: &str = "read(/proc/net/route)";
const ROUTE6: &str = "read(/proc/net/ipv6_route)";
const RESOLVER: &str = "read(/etc/resolv.conf)";

/// The variable of a proxy names an HTTP proxy.
const PROXY_SET: &[Observe] =
    &[row(PROXY, Expect::Value { key: "set", value: "1" }), row(PROXY, Expect::Value { key: "scheme", value: "http" })];

/// No variable names a proxy.
const NO_PROXY_SET: &[Observe] = &[row(PROXY, Expect::Value { key: "set", value: "0" })];

/// No default route of IPv4. The main table alone: a host can refuse a
/// route out with a filter, and a route of another table is not in the
/// file. The lab checks its own namespace with a connect out.
const NO_ROUTE_V4: Observe = row(ROUTE4, Expect::Shows { key: "default", value: "0" });

const fn proxy_variable(net: &'static Net) -> Part {
    part("proxy-variable", "HTTPS_PROXY names an HTTP proxy", PROXY_SET, net)
}

const fn no_proxy(net: &'static Net) -> Part {
    part("no-proxy", "no variable names a proxy", NO_PROXY_SET, net)
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
        &[NO_ROUTE_V4, row(ROUTE6, Expect::Shows { key: "default", value: "0" }), lab_check(NetFact::NoRouteV4)],
        &PROXY_ONLY,
    ),
    proxy_variable(&PROXY_ONLY),
    part(
        "proxy-reaches",
        "a CONNECT through the proxy with its credential reaches a TLS server",
        &[
            sends(CONNECT_NAME, "status", "200"),
            sends(TLS_NAME, "hello", "1"),
            lab_check(NetFact::Connect { host: LISTED, port: 443, status: 200 }),
            lab_check(NetFact::Issuer { name: LISTED, ca: Ca::Server }),
        ],
        &PROXY_ONLY,
    ),
    part(
        "proxy-credential",
        "a CONNECT with no credential gets 407",
        &[sends(CONNECT_NO_CREDENTIAL, "status", "407"), lab_check(NetFact::NeedsCredential)],
        &PROXY_ONLY,
    ),
    part(
        "port-refused",
        "the proxy reaches the ports 443, 80 and 8443 only: port 22 gets 403",
        &[sends(CONNECT_CLOSED, "status", "403"), lab_check(NetFact::Connect { host: LISTED, port: 22, status: 403 })],
        &PROXY_ONLY,
    ),
    UDP_REFUSED,
];

pub(super) const TLS_RETERMINATED: &[Part] = &[
    proxy_variable(&RETERMINATE),
    part(
        "cert-file",
        "SSL_CERT_FILE names a file of certificates",
        &[row("getenv(SSL_CERT_FILE)+read", Expect::Shows { key: "set", value: "1" })],
        &RETERMINATE,
    ),
    part(
        "tls-reterminated",
        "the proxy shows its own CA for a listed name, and passes another name. Assumed: the names that a real proxy terminates",
        &[
            sends(TLS_NAME, "issuer", "file"),
            sends(TLS_OTHER, "hello", "1"),
            lab_check(NetFact::Issuer { name: LISTED, ca: Ca::Proxy }),
            lab_check(NetFact::Issuer { name: OTHER, ca: Ca::Server }),
        ],
        &RETERMINATE,
    ),
    part(
        "ssh-port-silent",
        "CONNECT to port 22 gets 200, then no byte. Assumed: port 22; podnet measured the form on other ports",
        &[
            sends(CONNECT_CLOSED, "status", "200"),
            sends(CONNECT_CLOSED, "bytes", "0"),
            lab_check(NetFact::Silent { port: 22 }),
        ],
        &RETERMINATE,
    ),
];

pub(super) const PER_NAME_PARTS: &[Part] = &[
    proxy_variable(&PER_NAME),
    part(
        "answer-per-name",
        "the proxy answers 200 for one name, 504 for another, and a reset for an IP literal. Assumed: the 504",
        &[
            sends(CONNECT_NAME, "status", "200"),
            sends(CONNECT_OTHER, "status", "504"),
            sends(CONNECT_LITERAL, "end", "reset"),
            lab_check(NetFact::Connect { host: LISTED, port: 443, status: 200 }),
            lab_check(NetFact::Connect { host: OTHER, port: 443, status: 504 }),
            lab_check(NetFact::LiteralReset),
        ],
        &PER_NAME,
    ),
];

pub(super) const SNI_PARTS: &[Part] = &[
    no_proxy(&SNI),
    part(
        "sni-reset",
        "a ClientHello with a name not on the list, or with no name, is reset. Assumed: the whole class",
        &[
            sends(TLS_NAME, "hello", "1"),
            sends(TLS_OTHER, "end", "reset"),
            sends(TLS_LITERAL, "end", "reset"),
            lab_check(NetFact::Hello { name: Some(LISTED), passes: true }),
            lab_check(NetFact::Hello { name: Some(OTHER), passes: false }),
            lab_check(NetFact::Hello { name: None, passes: false }),
        ],
        &SNI,
    ),
];

pub(super) const NO_DNS_PARTS: &[Part] = &[
    no_proxy(&NO_DNS),
    // With no nameserver line, the C libraries ask 127.0.0.1:53. A server
    // of the file can be out of reach: the rows show the class, and the
    // lab checks a lookup of its own.
    part(
        "no-resolver",
        "a lookup of a name fails",
        &[
            row(RESOLVER, Expect::Shows { key: "nameservers", value: "0" }),
            row(RESOLVER, Expect::Shows { key: "127.0.0.1:53", value: "refused" }),
            lab_check(NetFact::NoResolver),
        ],
        &NO_DNS,
    ),
    part(
        "literal-reaches",
        "a TCP connect to an IP literal reaches out. Assumed: the stand-in server of the lab",
        &[sends(TLS_LITERAL, "hello", "1"), lab_check(NetFact::LiteralReaches)],
        &NO_DNS,
    ),
];

pub(super) const WS_PARTS: &[Part] = &[
    proxy_variable(&WS),
    part(
        "upgrade-refused",
        "the proxy passes a plain request and refuses the WebSocket upgrade. Assumed: the whole class",
        &[fact(NetFact::GetPasses), fact(NetFact::UpgradeRefused)],
        &WS,
    ),
];

pub(super) const IPV6_ONLY: &[Part] = &[
    part(
        "no-ipv4-route",
        "a TCP connect to an IPv4 address outside fails; the loopback stays",
        &[NO_ROUTE_V4, row("connect(127.0.0.1:1)", Expect::Allowed), lab_check(NetFact::NoRouteV4)],
        &V6,
    ),
    // A row of a default route of IPv6 waits for a lab that holds one:
    // the address of the lab is on its loopback.
    part(
        "ipv6-reaches",
        "a TCP connect to an IPv6 address succeeds. Assumed: the stand-in server of the lab",
        &[sends(TLS_LITERAL, "hello", "1"), lab_check(NetFact::V6Reaches)],
        &V6,
    ),
];
