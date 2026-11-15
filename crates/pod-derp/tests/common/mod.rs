//! The way out of the tests that reach a real server: TLS on ring, as each
//! test of podcrates runs it, the system's resolver, and a proxy: none, or
//! the proxy of the environment for a live test.

#![allow(dead_code)]

use std::sync::Arc;

use pod_proxy::resolve::System;
use pod_proxy::{Client, Dialer, Environment, ProxyChoice};
use pod_tls::{Context, Words};

/// The name of the tests on the wire.
pub const USER_AGENT: &str = "pod-derp-test";

/// The way out and the client of a probe, through `proxy`.
pub fn way_of(proxy: ProxyChoice) -> (pod_ws::Way, Client) {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let tls = Arc::new(Context::new(provider, pod_tls::Settings::new(Words::new("pod-derp"))));
    let settings = pod_proxy::Settings::new("pod-derp", proxy);
    let dial: Arc<dyn pod_core::Dial> = Arc::new(Dialer::new(settings, Arc::new(System::new())));
    let client = Client::new(tls.clone(), dial.clone()).with_user_agent(USER_AGENT);
    (pod_ws::Way::new(tls, dial, USER_AGENT), client)
}

/// [`way_of`] with no proxy.
pub fn direct() -> (pod_ws::Way, Client) {
    way_of(ProxyChoice::Direct)
}

/// [`way_of`] with the proxy of the environment (`HTTPS_PROXY`, `NO_PROXY`),
/// for a live test.
pub fn from_environment() -> (pod_ws::Way, Client) {
    way_of(ProxyChoice::FromEnvironment(Environment::read(&|name| std::env::var_os(name))))
}
