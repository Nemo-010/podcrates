//! The TLS, the dial and the host of the tests: ring, the default roots, a
//! direct dial with the system resolver.

use std::sync::Arc;

pub fn tls() -> Arc<pod_tls::Context> {
    let settings = pod_tls::Settings::new(pod_tls::Words::new("pod-cloudflare"));
    Arc::new(pod_tls::Context::new(Arc::new(rustls::crypto::ring::default_provider()), settings))
}

/// A direct dial with the system resolver.
pub fn dial() -> Arc<dyn pod_core::Dial> {
    let settings = pod_proxy::Settings::new("pod-cloudflare", pod_proxy::ProxyChoice::Direct);
    Arc::new(pod_proxy::Dialer::new(settings, Arc::new(pod_proxy::resolve::System::new())))
}

/// A dial through the proxy `url`.
pub fn proxied(url: &str) -> Arc<dyn pod_core::Dial> {
    let proxy = pod_proxy::Proxy::parse(url).expect("a proxy URL");
    let settings = pod_proxy::Settings::new("pod-cloudflare", pod_proxy::ProxyChoice::Via(proxy));
    Arc::new(pod_proxy::Dialer::new(settings, Arc::new(pod_proxy::resolve::System::new())))
}

/// The host of the tests: [`tls`], [`dial`], no services.
pub fn host() -> crate::Host {
    crate::Host::new(tls(), dial())
}
