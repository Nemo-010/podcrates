//! A QUIC connection in memory: a local server in the place of the edge,
//! and a client with the transport configuration of the client of the
//! edge. A test serves the streams of the edge on the client side.

use std::sync::Arc;

use noq::{ClientConfig, Endpoint};

use crate::cloudflare::quic::transport_config;

/// The two sides of a QUIC connection in memory.
pub struct Pair {
    /// The connection on the side of the edge.
    pub edge: noq::Connection,
    /// The connection on the side of the client.
    pub client: noq::Connection,
    _endpoints: (Endpoint, Endpoint),
}

/// Open a connection from a client endpoint to a server endpoint on the
/// loopback (the name `edge.test`, the ALPN `podnet-test`).
pub async fn local_pair() -> Pair {
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["edge.test".to_string()]).unwrap().self_signed(&key).unwrap();
    let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(key.serialize_der().into());
    let mut server_tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert.der().clone()], key_der)
        .unwrap();
    server_tls.alpn_protocols = vec![b"podnet-test".to_vec()];
    let server_crypto = noq::crypto::rustls::QuicServerConfig::try_from(server_tls).unwrap();
    let server = pod_quic::endpoint::server(
        pod_quic::endpoint::server_config(Arc::new(server_crypto)).unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let addr = server.local_addr().unwrap();
    let tls = tls().client_config_with(&[cert.pem().as_bytes()], &[b"podnet-test"]).unwrap();
    let crypto = noq::crypto::rustls::QuicClientConfig::try_from(tls).unwrap();
    let mut config = ClientConfig::new(Arc::new(crypto));
    config.transport_config(Arc::new(transport_config(1252)));
    let client = pod_quic::endpoint::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let connecting = client.connect_with(config, addr, "edge.test").unwrap();
    let (edge, client_conn) =
        tokio::join!(async { server.accept().await.unwrap().await.unwrap() }, async { connecting.await.unwrap() });
    Pair { edge, client: client_conn, _endpoints: (server, client) }
}

/// The TLS of the client of the pair: ring, no extra settings.
fn tls() -> Arc<pod_tls::Context> {
    let settings = pod_tls::Settings::new(pod_tls::Words::new("pod-cloudflare"));
    Arc::new(pod_tls::Context::new(Arc::new(rustls::crypto::ring::default_provider()), settings))
}
