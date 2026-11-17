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

/// The words of podnet, the first consumer: the tests check that its texts
/// come through.
pub fn podnet_words() -> crate::Words {
    crate::Words {
        name: "podnet".into(),
        protocol: "--protocol".into(),
        udp_off: "PODNET_UDP=off".into(),
        strict: "Set PODNET_VERIFY_STRICT=1 to make this an error".into(),
        resolve: "give the address with --resolve HOST=IP, or use --no-verify".into(),
        tcp_origin: "Use --forward with \"podnet connect\", or --port for an HTTP origin.".into(),
    }
}

/// The host of the tests: [`tls`], [`dial`], no services, the words of
/// podnet.
pub fn host() -> crate::Host {
    let mut host = crate::Host::new(tls(), dial());
    host.settings.words = podnet_words();
    host
}
