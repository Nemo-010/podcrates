//! pod-cloudflare: a named tunnel against an edge on the loopback that
//! refuses the connection, so that the engine, the HTTP/2 leg, the TLS of
//! the edge, the ingress, the origins and the protocol link in; and one
//! message of Cap'n Proto that reads back. No call leaves the host.

use std::sync::Arc;

use pod_cloudflare::cloudflare::schema::{ConnectRequest, ConnectionType, decode_connect_request};
use pod_cloudflare::config::{Config, Credentials, Protocol, Transport};
use pod_cloudflare::ingress::{Ingress, Service};
use pod_cloudflare::tunnel::TunnelBuilder;

pub fn cloudflare(dial: Arc<dyn pod_core::Dial>) -> String {
    let request =
        ConnectRequest { dest: "http://probe.example/".into(), conn_type: ConnectionType::Http, metadata: vec![] };
    let bytes = pod_cloudflare::cloudflare::schema::encode_connect_request(&request);
    let read = pod_cloudflare::cloudflare::capnp::Message::parse(&bytes)
        .ok()
        .flatten()
        .and_then(|(message, _)| decode_connect_request(&message.root().ok()?).ok())
        .is_some_and(|back| back.dest == request.dest);
    let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(runtime) => runtime,
        Err(e) => return format!("pod-cloudflare: no runtime: {e}"),
    };
    let tls = Arc::new(pod_tls::Context::new(
        Arc::new(pod_tls::crypto::provider()),
        pod_tls::Settings::new(pod_tls::Words::new("static-probe")),
    ));
    let mut host = pod_cloudflare::Host::new(tls, dial);
    host.settings.edge = Some(vec![std::net::SocketAddr::from(([127, 0, 0, 1], 1))]);
    host.settings.udp = pod_cloudflare::udp::Choice::Off;
    // A made-up tunnel, not a credential: the edge on the loopback refuses
    // the connection before any registration.
    let credentials =
        Credentials::Explicit { account_tag: "probe".into(), tunnel_id: Default::default(), secret: vec![0; 32] };
    let config = Config {
        credentials,
        protocol: Protocol::Http2,
        transport: Transport::Direct,
        ingress: Ingress::default().catch_all(Service::HelloWorld),
        ha_connections: 1,
        ..Config::default()
    };
    let started = runtime.block_on(async {
        let tunnel = TunnelBuilder::quick(Arc::new(host)).config(config).build()?;
        tunnel.start().await
    });
    format!(
        "pod-cloudflare: a message that reads back {read}, a start against a closed edge: {}",
        started.map_or_else(|e| format!("{} ({})", e.class, e.stage.name()), |_| "registered".into())
    )
}
