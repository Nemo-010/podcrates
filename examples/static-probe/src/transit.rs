//! pod-transit: the words of a pair, the line of the relay, and a dialer of
//! the transit road through the probe's way, so that the meeting, the link
//! of pod-session and the WebSocket of pod-ws link in.

pub fn transit() -> String {
    let provider = std::sync::Arc::new(pod_tls::crypto::provider());
    let tls = pod_tls::Context::new(provider, pod_tls::Settings::new(pod_tls::Words::new("static-probe")));
    let settings = pod_proxy::Settings::new("static-probe", pod_proxy::ProxyChoice::Direct);
    let dialer = pod_proxy::Dialer::new(settings, std::sync::Arc::new(pod_proxy::resolve::System::new()));
    let way = pod_ws::Way::new(std::sync::Arc::new(tls), std::sync::Arc::new(dialer), "static-probe");
    let keys = pod_transit::Keys::of_pair("0123456789abcdef0123456789abcdef", "static-probe");
    let Ok(side) = pod_transit::Side::random(&mut pod_core::entropy::OsEntropy) else {
        return "pod-transit: no random bytes".into();
    };
    let line = pod_transit::token::line(&keys, &side).len();
    let Ok(url) = pod_ws::url::WsUrl::parse(&pod_transit::default_url()) else {
        return "pod-transit: no relay's URL".into();
    };
    let config = pod_transit::Config::new(url, way);
    let dialer = pod_transit::Dialer::new(config, keys).map_or_else(|e| e.to_string(), |d| d.url().shown());
    format!("pod-transit: a line of {line} bytes, the relay {dialer}")
}
