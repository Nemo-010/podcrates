//! pod-iroh: iroh's own ticket parsed, and a node's record of pkarr signed
//! and read back, with no network; an endpoint (iroh, QUIC, the patched
//! relay client) is made only where `STATIC_PROBE_IROH` names a relay URL,
//! as it reaches the network.

use std::sync::Arc;

/// The test vector of iroh-tickets 1.0.0: a key at the relay
/// `http://derp.me./` and at `127.0.0.1:1024`.
const TICKET: &str =
    "endpointacxfr74igmsbvsbnn73wcecg5vt3kbzncqwfrdiampuufwnhkublmaqacbuhi5dqhixs6zdfojyc43lffyxqcad7aaaadaai";

pub fn iroh() -> String {
    let ticket = match pod_iroh::ticket::parse(TICKET) {
        Ok(addr) => format!("the ticket of {}", pod_iroh::keys::fingerprint(&addr.id)),
        Err(e) => e,
    };
    let place = pod_iroh::keys::Place::Ephemeral;
    let secret = match pod_iroh::keys::load_in(&[], &place, &mut pod_core::entropy::OsEntropy) {
        Ok(key) => key.secret,
        Err(e) => return format!("pod-iroh: {ticket}, no key: {e}"),
    };
    let relay = pod_iroh::relays::parse_url("https://relay.example").ok();
    let roads = pod_iroh::pkarr::Roads { relay, ..Default::default() };
    let record = pod_iroh::pkarr::record::packet(&secret, &roads, pod_iroh::pkarr::TTL)
        .and_then(|packet| pod_iroh::pkarr::read(&secret.public(), &packet.to_relay_payload()))
        .map_or_else(|e| e, |record| format!("a record of {} relay", record.relays.len()));
    let Some(url) = std::env::var_os("STATIC_PROBE_IROH") else {
        return format!("pod-iroh: {ticket}, {record}");
    };
    let relays = url.to_str().and_then(|u| pod_iroh::relays::parse_url(u).ok()).into_iter().collect();
    let provider = Arc::new(pod_tls::crypto::provider());
    let tls = Arc::new(pod_tls::Context::new(provider, pod_tls::Settings::new(pod_tls::Words::new("static-probe"))));
    let options = pod_iroh::Options {
        relays,
        udp: pod_iroh::Udp::Off,
        ..pod_iroh::Options::new(tls, Arc::new(pod_proxy::resolve::System::new()))
    };
    let Ok(rt) = tokio::runtime::Builder::new_current_thread().enable_all().build() else {
        return "pod-iroh: no runtime".into();
    };
    let bound = rt.block_on(async {
        let endpoint = pod_iroh::bind(&options).await.map_err(|e| e.to_string())?;
        let id = pod_iroh::keys::fingerprint(&endpoint.id());
        endpoint.close().await;
        Ok::<_, String>(id)
    });
    format!("pod-iroh: {ticket}, {record}, an endpoint {}", bound.unwrap_or_else(|e| e))
}
