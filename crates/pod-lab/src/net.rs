//! The network labs: a network namespace with its loopback up, and the
//! stand-ins of a class on it. The stand-ins are a process of the lab
//! (`standin`): a stand-in HTTP `CONNECT` proxy on `127.0.0.1:3128` and a
//! stand-in TLS server on port 443, with two certificate authorities that
//! the lab makes for each run (`tls`). No stand-in reaches out of the
//! namespace: each answer of "the outside" comes from the stand-in itself,
//! but where the caller asks for a way out (`out`): then the stand-in proxy
//! passes a `CONNECT` to a name that is not of the lab ([`is_lab_name`]) to
//! the real network, through a process outside the namespace (`relay`).
//!
//! [`Net`] is the data of the stand-ins of a profile; [`NetFact`] is a fact
//! that the lab measures from inside (`measure`).

mod measure;
mod out;
mod pass;
mod proxy;
mod relay;
mod setup;
mod standin;
mod tls;
pub mod vars;
mod wire;

pub use measure::measure;
pub(crate) use out::{WayOut, start as start_way_out};
pub use setup::{Ready, prepare};
pub use standin::{Started, not_dumpable, start};

/// The port of the stand-in proxy, on `127.0.0.1` of the lab.
pub const PROXY_PORT: u16 = 3128;
/// The port of the stand-in TLS server.
pub const TLS_PORT: u16 = 443;
/// An address outside: TEST-NET-1 (RFC 5737). A lab of direct connects
/// puts `192.0.2.0/24` on its loopback; in another lab no route reaches it.
pub const OUTSIDE_V4: [u8; 4] = [192, 0, 2, 1];
/// The IPv6 address of `ipv6-only` on the loopback: a unique local address.
pub const OUTSIDE_V6: [u16; 8] = [0xfd00, 0x6c61, 0x62, 0, 0, 0, 0, 1];
/// The name on the list of a class.
pub const LISTED: &str = "listed.test";
/// A name that is not on the list of a class.
pub const OTHER: &str = "other.test";
/// The user of the credential of the stand-in proxy of `proxy-only`.
pub const PROXY_USER: &str = "podlab";
/// Its password: a made-up value of the lab, not a secret.
pub const PROXY_PASSWORD: &str = "made-up-podlab-password";
/// The variables of a proxy. The lab removes each one from the
/// environment of the command, then sets the first four to its stand-in
/// proxy where the class has one.
pub const PROXY_VARIABLES: &[&str] =
    &["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy"];
/// The variable of the certificate file of the lab.
pub const CERT_VARIABLE: &str = "SSL_CERT_FILE";

/// The stand-ins of a network lab.
#[derive(Debug, PartialEq, Eq)]
pub struct Net {
    /// The stand-in proxy, or no proxy: the command then gets no variable
    /// of a proxy.
    pub proxy: Option<Proxy>,
    /// `192.0.2.1/24` on the loopback: a direct connect to an address of
    /// it reaches the stand-in server.
    pub outside_v4: bool,
    /// [`OUTSIDE_V6`] on the loopback, with the stand-in server there.
    pub outside_v6: bool,
    /// The names that the stand-in server takes in a ClientHello; another
    /// name, or none, gets a TCP reset. `None`: each name.
    pub sni: Option<&'static [&'static str]>,
    /// `/etc/resolv.conf` with no server, `/etc/hosts` with `localhost`
    /// alone, and `hosts: files dns` in `/etc/nsswitch.conf`.
    pub no_resolver: bool,
}

/// The rules of the stand-in proxy.
#[derive(Debug, PartialEq, Eq)]
pub struct Proxy {
    /// A request with no credential, or another one, gets 407.
    pub auth: bool,
    /// The ports that a `CONNECT` can reach; another port gets 403. Empty:
    /// each port.
    pub ports: &'static [u16],
    /// The names that get 504.
    pub timeout: &'static [&'static str],
    /// A `CONNECT` to an IP literal gets a reset with no answer.
    pub reset_literals: bool,
    /// The names whose TLS the proxy terminates with its own CA.
    pub reterminate: &'static [&'static str],
    /// The ports where the proxy answers 200, then sends no byte.
    pub silent: &'static [u16],
    /// A request with `Upgrade` gets 403: in the TLS that the proxy
    /// terminates, and in a plain request.
    pub refuse_upgrade: bool,
}

/// A proxy with no rule: each `CONNECT` gets 200.
pub const OPEN: Proxy = Proxy {
    auth: false,
    ports: &[],
    timeout: &[],
    reset_literals: false,
    reterminate: &[],
    silent: &[],
    refuse_upgrade: false,
};

/// A lab with no proxy and no address outside.
pub const NO_PROXY: Net = Net { proxy: None, outside_v4: false, outside_v6: false, sni: None, no_resolver: false };

impl Net {
    /// The mechanism in words, for a verdict and for `podlab list`.
    pub fn words(&self) -> String {
        let mut w = vec!["a network namespace with no route out".to_string()];
        if let Some(p) = &self.proxy {
            let auth = if p.auth { " with a credential" } else { "" };
            w.push(format!("a stand-in proxy on 127.0.0.1:{PROXY_PORT}{auth}"));
        }
        if self.outside_v4 {
            w.push("a stand-in server on 192.0.2.0/24".to_string());
        }
        if self.outside_v6 {
            w.push("a stand-in server on an IPv6 address".to_string());
        }
        if self.sni.is_some() {
            w.push("a filter of the TLS server name".to_string());
        }
        if self.no_resolver {
            w.push("no name server".to_string());
        }
        w.join(", ")
    }

    /// True where the stand-ins speak TLS with the CA of the proxy.
    pub fn proxy_ca(&self) -> bool {
        self.proxy.as_ref().is_some_and(|p| !p.reterminate.is_empty())
    }
}

/// The certificate authorities of a lab.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ca {
    /// The CA of the stand-in proxy, for the names that it terminates.
    Proxy,
    /// The CA of the stand-in servers: the public roots of the lab.
    Server,
}

impl Ca {
    pub fn name(self) -> &'static str {
        match self {
            Ca::Proxy => "the CA of the proxy",
            Ca::Server => "the CA of the server",
        }
    }
}

/// A fact of a network class, measured in the lab before the command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetFact {
    /// A TCP connect to `192.0.2.1:443` gives `ENETUNREACH`.
    NoRouteV4,
    /// A `CONNECT` through the proxy, with the credential, gets `status`.
    Connect { host: &'static str, port: u16, status: u16 },
    /// A `CONNECT` with no credential gets 407.
    NeedsCredential,
    /// A `CONNECT` to `192.0.2.1:443`: the proxy closes with no answer.
    LiteralReset,
    /// A TLS handshake through the proxy to `name:443`: the chain of the
    /// server ends at `ca`, and at no other CA of the lab.
    Issuer { name: &'static str, ca: Ca },
    /// A `CONNECT` to `port` gets 200, then no byte comes after a banner.
    Silent { port: u16 },
    /// An HTTPS `GET` of `listed.test` through the proxy gets 200.
    GetPasses,
    /// The same `GET` with `Upgrade: websocket` gets 403.
    UpgradeRefused,
    /// A ClientHello to `192.0.2.1:443` with this name (or with no name):
    /// a ServerHello comes back where `passes`, else a TCP reset.
    Hello { name: Option<&'static str>, passes: bool },
    /// A lookup of a name fails, `/etc/resolv.conf` names no server, and
    /// no server takes a TCP connect on port 53.
    NoResolver,
    /// A TCP connect to `192.0.2.1:443`, and a TLS handshake that checks
    /// the address in the certificate.
    LiteralReaches,
    /// A TCP connect to the IPv6 address of the lab, port 443, reaches the
    /// stand-in server.
    V6Reaches,
}

impl NetFact {
    /// The fact in words, for a verdict.
    pub fn name(self) -> String {
        match self {
            NetFact::NoRouteV4 => "connect(192.0.2.1:443) gives ENETUNREACH".to_string(),
            NetFact::Connect { host, port, status } => format!("CONNECT {host}:{port} through the proxy gets {status}"),
            NetFact::NeedsCredential => "CONNECT with no credential gets 407".to_string(),
            NetFact::LiteralReset => "CONNECT 192.0.2.1:443 gets a reset with no answer".to_string(),
            NetFact::Issuer { name, ca } => format!("TLS to {name} through the proxy shows {}", ca.name()),
            NetFact::Silent { port } => format!("CONNECT to port {port} gets 200, then no byte after a banner"),
            NetFact::GetPasses => format!("an HTTPS GET of {LISTED} through the proxy gets 200"),
            NetFact::UpgradeRefused => format!("a WebSocket upgrade of {LISTED} through the proxy gets 403"),
            NetFact::Hello { name: Some(n), passes: true } => format!("a ClientHello for {n} gets a ServerHello"),
            NetFact::Hello { name: Some(n), passes: false } => format!("a ClientHello for {n} gets a reset"),
            NetFact::Hello { name: None, passes: true } => "a ClientHello with no name gets a ServerHello".to_string(),
            NetFact::Hello { name: None, passes: false } => "a ClientHello with no name gets a reset".to_string(),
            NetFact::NoResolver => "a lookup of a name fails, and no name server answers".to_string(),
            NetFact::LiteralReaches => "TLS to 192.0.2.1:443 checks the address in the certificate".to_string(),
            NetFact::V6Reaches => "connect([fd00:6c61:62::1]:443) reaches the stand-in server".to_string(),
        }
    }
}

/// True where `host` (a name or an address of a `CONNECT`) is of the lab:
/// its two names, `localhost`, its addresses outside (`192.0.2.0/24`,
/// [`OUTSIDE_V6`]) and the loopback. The stand-ins answer it; a way out
/// never dials it.
pub fn is_lab_name(host: &str) -> bool {
    use std::net::IpAddr;
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(a)) => a.is_loopback() || a.is_unspecified() || a.octets()[..3] == OUTSIDE_V4[..3],
        Ok(IpAddr::V6(a)) => {
            a.is_loopback()
                || a.is_unspecified()
                || a == outside_v6()
                || a.to_ipv4_mapped().is_some_and(|v4| is_lab_name(&v4.to_string()))
        }
        Err(_) => {
            let name = host.trim_end_matches('.');
            [LISTED, OTHER, "localhost"].contains(&name) || name.ends_with(".localhost")
        }
    }
}

/// The text of [`OUTSIDE_V6`].
pub fn outside_v6() -> std::net::Ipv6Addr {
    let [a, b, c, d, e, f, g, h] = OUTSIDE_V6;
    std::net::Ipv6Addr::new(a, b, c, d, e, f, g, h)
}

/// The URL of the stand-in proxy, with its credential where it asks for
/// one.
pub fn proxy_url(proxy: &Proxy) -> String {
    let auth = if proxy.auth { format!("{PROXY_USER}:{PROXY_PASSWORD}@") } else { String::new() };
    format!("http://{auth}127.0.0.1:{PROXY_PORT}")
}

/// The targets of the rows that send a packet out
/// (`pod_hostprobe::Settings::network`), in a lab of `net`: the two names
/// of the lab, the port of the stand-in server, the closed port 22, and the
/// address outside (of IPv6 in a lab of IPv6).
pub fn lab_targets(net: &Net) -> pod_hostprobe::Network {
    let literal = if net.outside_v6 {
        std::net::IpAddr::V6(outside_v6())
    } else {
        std::net::IpAddr::V4(std::net::Ipv4Addr::from(OUTSIDE_V4))
    };
    pod_hostprobe::Network {
        other: Some(OTHER.to_string()),
        literal: Some(literal),
        ..pod_hostprobe::Network::new(LISTED, TLS_PORT)
    }
}

/// The value of `Proxy-Authorization` for the credential of the lab.
pub fn credential() -> String {
    use base64::Engine as _;
    let pair = format!("{PROXY_USER}:{PROXY_PASSWORD}");
    format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(pair))
}
