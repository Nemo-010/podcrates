//! pod-relay: a forward session of a context that is offline, so that the
//! opener, the failover, the token and the roads link in and nothing
//! connects; the blocking facade's runtime; the pool, the code, the grants
//! and the TLS of the QUIC road. pod-piping and pod-opentunnel: a client
//! whose dial fails at once, so that its exchange links in and nothing
//! connects.

use std::sync::Arc;

use pod_relay::cache::Cache;
use pod_relay::{Context, Settings};

pub fn relay() -> String {
    let provider = Arc::new(pod_tls::crypto::provider());
    let tls = pod_tls::Context::new(provider.clone(), pod_tls::Settings::new(pod_tls::Words::new("static-probe")));
    let settings = pod_proxy::Settings::new("static-probe", pod_proxy::ProxyChoice::Direct);
    let dialer = pod_proxy::Dialer::new(settings, Arc::new(pod_proxy::resolve::System::new()));
    let way = pod_ws::Way::new(Arc::new(tls), Arc::new(dialer), "static-probe");
    let piping = piping(Arc::new(way.clone()));
    let opentunnel = opentunnel(Arc::new(way.clone()), provider.clone());
    let ctx = Context::new(way, Cache::none()).with_settings(Settings { offline: true, ..Settings::default() });
    let relays = pod_relay::relay::select_relays(None, None, &[]).map_or(0, |list| list.hosts.len());
    let path = pod_relay::relay::forward_path("probe.example", 22).unwrap_or_default();
    let opened = match pod_relay::blocking::Client::new(pod_relay::blocking::Config::new(ctx)) {
        Ok(client) => match pod_relay::relay::select_relays(None, None, &[]) {
            Ok(list) => {
                client.open_forward(&list, "probe.example", 22).map_or_else(|e| e.to_string(), |_| "opened".into())
            }
            Err(e) => e,
        },
        Err(e) => e.to_string(),
    };
    let pool =
        pod_relay::pool::parse_pool(br#"{"pool":[]}"#, pod_relay::default_relay_host()).err().unwrap_or_default();
    let grant = pod_relay::grant::parse_public("ssh-ed25519 AAAA probe").is_some();
    let quic = pod_relay::quic_road::dial::tls(provider, &pod_tls::roots_from_compiled_set())
        .map_or_else(|e| e, |_| "a QUIC TLS".into());
    format!(
        "pod-relay: {relays} hosts, {path}, offline: {opened}, a pool: {pool}, a grant key: {grant}, {quic}, a code of {} s; \
         {piping}; {opentunnel}",
        pod_relay::code::LIFETIME.as_secs()
    )
}

/// pod-piping: the TLS dial of `way` (made, not called), the public servers,
/// and a link of a client whose dial fails.
fn piping(way: Arc<pod_ws::Way>) -> String {
    use pod_piping::dial::{Dial, Dialing};
    let _tls: Dial = pod_piping::dial::tls(way, pod_tls::Trust::Default);
    let offline: Dial = Arc::new(|_: &pod_piping::Server| -> Dialing { Box::pin(async { Err("offline".into()) }) });
    let http = pod_piping::Http::new(pod_piping::Server::default(), offline, "static-probe");
    let say: pod_piping::Say = Arc::new(|_| {});
    let dialer = pod_piping::Dialer::new(pod_piping::Secret::of_pair("probe", "probe"), http, say);
    let linked = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(runtime) => runtime.block_on(dialer.link()).map_or_else(|e| e, |_| "a link".into()),
        Err(e) => e.to_string(),
    };
    format!("pod-piping: {} public servers, offline: {linked}", pod_piping::server::public().len())
}

/// pod-opentunnel: the dials of `way` (made, not called), the API and a
/// client whose dials fail, and the TLS of a node with `provider`.
fn opentunnel(way: Arc<pod_ws::Way>, provider: Arc<rustls::crypto::CryptoProvider>) -> String {
    use pod_opentunnel::dial::{Dial, Dialing, Visit};
    let _tls: Dial = pod_opentunnel::dial::tls(way.clone(), pod_tls::Trust::Default);
    let _tcp: Visit = pod_opentunnel::dial::tcp(way.clone());
    let offline: Dial =
        Arc::new(|_: &pod_opentunnel::Service| -> Dialing { Box::pin(async { Err("offline".into()) }) });
    let visit: Visit = Arc::new(|_: &str| -> Dialing { Box::pin(async { Err("offline".into()) }) });
    let api = pod_opentunnel::api::Api::new(pod_opentunnel::Service::hosted(), offline, "static-probe");
    let say: pod_opentunnel::Say = Arc::new(|_| {});
    let name = pod_opentunnel::Name::parse("probe.abcdefghijkl.opentunnel.xyz");
    let served = pod_tls::server::Served::new(None);
    let acceptor =
        pod_tls::server::acceptor_for(provider, served, &[]).map_or_else(|e| e.to_string(), |_| "a TLS".into());
    let reached = match (tokio::runtime::Builder::new_current_thread().enable_all().build(), name) {
        (Ok(runtime), Ok(name)) => {
            let dialer = pod_opentunnel::Dialer::new(name, visit, way, pod_tls::Trust::Default, say);
            let health = runtime.block_on(api.health()).map_or_else(|e| e, |status| status.to_string());
            let link = runtime.block_on(dialer.link()).map_or_else(|e| e, |_| "a link".into());
            format!("{health}, {link}")
        }
        (Err(e), _) => e.to_string(),
        (_, Err(e)) => e,
    };
    format!("pod-opentunnel: offline: {reached}, a node's {acceptor}")
}
