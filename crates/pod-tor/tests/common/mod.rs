//! The way out of the tests: a dialer of `pod-proxy` through a proxy or
//! none, and TLS on ring, as each test of podcrates runs it.

#![allow(dead_code)]

use std::sync::Arc;

use pod_proxy::{Dialer, Environment, Proxy, ProxyChoice, Settings};
use pod_tls::{Context, Words};
use pod_ws::Way;

/// The user agent of the tests.
pub const USER_AGENT: &str = "pod-tor/0.0.0-test";

/// The provider of rustls of the tests, as the process default: Arti takes
/// the default provider.
pub fn provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// A way through `proxy`.
pub fn way(proxy: ProxyChoice) -> Way {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let tls = Arc::new(Context::new(provider, pod_tls::Settings::new(Words::new("pod-tor"))));
    let resolve = Arc::new(pod_proxy::resolve::System::default());
    Way::new(tls, Arc::new(Dialer::new(Settings::new("pod-tor", proxy), resolve)), USER_AGENT)
}

/// A way through the proxy of `url`.
pub fn via(url: &str) -> Way {
    way(ProxyChoice::Via(Proxy::parse(url).expect("a proxy URL")))
}

/// A direct way.
pub fn direct() -> Way {
    way(ProxyChoice::Direct)
}

/// A way through the proxy of the environment of the process.
pub fn from_environment() -> Way {
    way(ProxyChoice::FromEnvironment(Environment::read(&|name| std::env::var_os(name))))
}
