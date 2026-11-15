//! The way out of the tests: TLS on ring, as each test of podcrates runs
//! it, a dialer through a proxy or none, and each name of the tests pinned
//! to its address. The words and the user agent are podssh's, as its binary
//! gives them.

#![allow(dead_code)]

use std::net::IpAddr;
use std::sync::Arc;

use pod_proxy::{Dialer, ProxyChoice, Settings};
use pod_tls::{Context, Words};
use pod_ws::Way;

/// The user agent of the tests.
pub const USER_AGENT: &str = "podssh/0.0.0-test";

/// A way through `proxy`, with each name of `pins` at its address.
pub fn through(proxy: ProxyChoice, pins: &[(&str, IpAddr)]) -> Way {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let tls = Arc::new(Context::new(provider, pod_tls::Settings::new(Words::new("podssh"))));
    let pins = pins.iter().map(|(name, ip)| (name.to_string(), *ip)).collect();
    let resolve = Arc::new(pod_proxy::resolve::System::with_pins(pins));
    Way::new(tls, Arc::new(Dialer::new(Settings::new("podssh", proxy), resolve)), USER_AGENT)
}

/// A direct way.
pub fn direct() -> Way {
    through(ProxyChoice::Direct, &[])
}

/// A direct way, with each name of `names` at the loopback.
pub fn loopback(names: &[&str]) -> Way {
    let lo: IpAddr = "127.0.0.1".parse().unwrap();
    let pins: Vec<(&str, IpAddr)> = names.iter().map(|n| (*n, lo)).collect();
    through(ProxyChoice::Direct, &pins)
}
