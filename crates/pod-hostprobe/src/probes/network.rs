//! What a host shows of its way out, with no packet past the loopback: the
//! variable of a proxy and its scheme, the certificate file, the resolver
//! of `/etc/resolv.conf`, and a default route of IPv4 and of IPv6. A row
//! that would reach the network is not here: a probe of a host of a user
//! sends nothing out.

use super::sockets::{Answer, connect_loopback};
use super::*;
use crate::verdict::items;

/// The variables of a proxy for HTTPS, in the order of curl: the first one
/// that is set and not empty names the proxy.
pub const PROXY_VARIABLES: &[&str] = &["https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY"];

/// The variable of the certificate file of OpenSSL, rustls-native-certs
/// and Go.
pub const CERT_VARIABLE: &str = "SSL_CERT_FILE";

/// `RTF_UP` and `RTF_REJECT` of `linux/route.h`.
const RTF_UP: u32 = 0x0001;
const RTF_REJECT: u32 = 0x0200;

/// The items of the proxy URL `value` of the variable `name`: its scheme,
/// whether it holds a credential, and its port. The host and the
/// credential are not in the items: a report goes to other people.
pub fn proxy_items(name: &str, value: &str) -> String {
    let (scheme, rest) = match value.split_once("://") {
        Some((s, r)) => (s.to_ascii_lowercase(), r),
        None => ("none".to_string(), value),
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let (credential, host) = match authority.rsplit_once('@') {
        Some((_, h)) => ("1", h),
        None => ("0", authority),
    };
    // The port follows the last colon, after the brackets of an IPv6 host.
    let tail = host.rsplit_once(']').map_or(host, |(_, t)| t);
    let port = match tail.rsplit_once(':') {
        Some((_, p)) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => p,
        _ => "none",
    };
    items(&[("set", "1"), ("variable", name), ("scheme", &scheme), ("credential", credential), ("port", port)])
}

pub(super) fn p_proxy_variable() -> Outcome {
    for &name in PROXY_VARIABLES {
        if let Some(v) = std::env::var_os(name).filter(|v| !v.is_empty()) {
            return Outcome::ok_with(proxy_items(name, &v.to_string_lossy()));
        }
    }
    Outcome::ok_with(items(&[("set", "0")]))
}

/// The certificates of a PEM text.
pub fn certificates(pem: &[u8]) -> usize {
    pem.split(|&b| b == b'\n').filter(|l| l.starts_with(b"-----BEGIN CERTIFICATE-----")).count()
}

/// The path is not in the reason: it can name a directory of the user.
pub(super) fn p_cert_file() -> Outcome {
    let Some(path) = std::env::var_os(CERT_VARIABLE).filter(|v| !v.is_empty()) else {
        return Outcome::ok_with(items(&[("set", "0")]));
    };
    match std::fs::read(&path) {
        Ok(pem) => Outcome::ok_with(items(&[("set", "1"), ("certificates", &certificates(&pem).to_string())])),
        Err(e) => match e.raw_os_error() {
            Some(n) => Outcome { reason: items(&[("set", "1")]), ..Outcome::denied(Errno(n)) },
            None => Outcome::skip(None, format!("{CERT_VARIABLE}: {e}")),
        },
    }
}

/// The `nameserver` lines of a text of `/etc/resolv.conf`.
pub fn nameservers(text: &str) -> usize {
    text.lines().filter(|l| l.split_whitespace().next() == Some("nameserver")).count()
}

/// With no `nameserver` line, the C libraries ask `127.0.0.1:53`: the row
/// then tries a TCP connect there, on the loopback alone.
pub(super) fn p_resolver() -> Outcome {
    let (count, absent) = match std::fs::read_to_string("/etc/resolv.conf") {
        Ok(t) => (nameservers(&t), false),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (0, true),
        Err(e) => match e.raw_os_error() {
            Some(n) => return Outcome::denied(Errno(n)),
            None => return Outcome::skip(None, format!("/etc/resolv.conf: {e}")),
        },
    };
    let local = if count > 0 {
        None
    } else {
        Some(match connect_loopback(53) {
            Ok(Answer::Listener) => "answers".to_string(),
            Ok(Answer::Reset) => "refused".to_string(),
            Ok(Answer::Silent) => "silent".to_string(),
            Ok(Answer::Refused(e)) => e.name(),
            Err(o) => return o,
        })
    };
    let count = count.to_string();
    let mut out = vec![("nameservers", count.as_str())];
    if absent {
        out.push(("file", "absent"));
    }
    if let Some(local) = &local {
        out.push(("127.0.0.1:53", local));
    }
    Outcome::ok_with(items(&out))
}

/// Whether a text of `/proc/net/route` has a default route that is up:
/// destination 0 and mask 0.
pub fn default_v4(text: &str) -> bool {
    text.lines().skip(1).any(|l| {
        let f: Vec<&str> = l.split_whitespace().collect();
        let flags = f.get(3).and_then(|x| u32::from_str_radix(x, 16).ok()).unwrap_or(0);
        f.get(1) == Some(&"00000000") && f.get(7) == Some(&"00000000") && flags & RTF_UP != 0
    })
}

/// Whether a text of `/proc/net/ipv6_route` has a default route that is up
/// and is no reject route (the "unreachable" entry on `lo`).
pub fn default_v6(text: &str) -> bool {
    text.lines().any(|l| {
        let f: Vec<&str> = l.split_whitespace().collect();
        let flags = f.get(8).and_then(|x| u32::from_str_radix(x, 16).ok()).unwrap_or(0);
        f.first().is_some_and(|d| d.len() == 32 && d.bytes().all(|b| b == b'0'))
            && f.get(1) == Some(&"00")
            && flags & RTF_UP != 0
            && flags & RTF_REJECT == 0
    })
}

fn routes(file: &str, default: fn(&str) -> bool) -> Result<Outcome, std::io::Error> {
    let text = std::fs::read_to_string(file)?;
    Ok(Outcome::ok_with(items(&[("default", if default(&text) { "1" } else { "0" })])))
}

fn io_outcome(file: &str, r: Result<Outcome, std::io::Error>) -> Outcome {
    match r {
        Ok(o) => o,
        Err(e) => match e.raw_os_error() {
            Some(n) => Outcome::denied(Errno(n)),
            None => Outcome::skip(None, format!("{file}: {e}")),
        },
    }
}

/// The routes of the network namespace of the probe, main table.
pub(super) fn p_route4() -> Outcome {
    io_outcome("/proc/net/route", routes("/proc/net/route", default_v4))
}

/// A kernel with no IPv6 has no `/proc/net/ipv6_route` beside
/// `/proc/net/route`: no route of IPv6. Not a socket of the family: a
/// filter of the host can refuse it with another errno.
pub(super) fn p_route6() -> Outcome {
    let file = "/proc/net/ipv6_route";
    match routes(file, default_v6) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && exists("/proc/net/route") => {
            Outcome::ok_with(items(&[("default", "0"), ("ipv6", "absent")]))
        }
        r => io_outcome(file, r),
    }
}

#[cfg(test)]
mod tests;
