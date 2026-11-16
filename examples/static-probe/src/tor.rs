//! pod-tor: a bridge line of each transport, and the bootstrap of arti
//! (its SQLite in C among it), which links in. The bootstrap runs only where
//! `STATIC_PROBE_TOR` names a directory, as it writes there and reaches the
//! network.

use std::time::Duration;

pub fn tor() -> String {
    let provider = std::sync::Arc::new(pod_tls::crypto::provider());
    let tls = pod_tls::Context::new(provider, pod_tls::Settings::new(pod_tls::Words::new("static-probe")));
    let settings = pod_proxy::Settings::new("static-probe", pod_proxy::ProxyChoice::Direct);
    let dialer = pod_proxy::Dialer::new(settings, std::sync::Arc::new(pod_proxy::resolve::System::new()));
    let way = pod_ws::Way::new(std::sync::Arc::new(tls), std::sync::Arc::new(dialer), "static-probe");
    let lines = [
        "meek_lite 192.0.2.18:80 BE776A53492E1E044A26F17306E1BC46A55A1625 url=https://meek.example/ front=front.example",
        "webtunnel [2001:db8::1]:443 0123456789ABCDEF0123456789ABCDEF01234567 url=https://bridge.example/path",
    ];
    let bridges: Vec<pod_tor::Bridge> = lines.iter().filter_map(|l| pod_tor::Bridge::parse(l).ok()).collect();
    let summary = pod_tor::bridges::summary(&bridges);
    let Some(home) = std::env::var_os("STATIC_PROBE_TOR") else {
        return format!("pod-tor: {summary}");
    };
    let home = std::path::PathBuf::from(home);
    let options = pod_tor::Options {
        state_dir: home.join("state"),
        cache_dir: home.join("cache"),
        way,
        first_hop_ports: Some(vec![443]),
        trust_directories: false,
        network: None,
        bridges,
        trust: pod_tls::Trust::Default,
    };
    let Ok(rt) = tokio::runtime::Builder::new_current_thread().enable_all().build() else {
        return "pod-tor: no runtime".into();
    };
    match rt.block_on(pod_tor::Tor::bootstrap(&options, Duration::from_secs(60))) {
        Ok(_) => format!("pod-tor: {summary}, bootstrapped"),
        Err(e) => format!("pod-tor: {summary}, {e}"),
    }
}
