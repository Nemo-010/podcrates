//! The stand-in ntfy server of `ntfy.rs` behind TLS for [`NAME`], which
//! the way of the tests finds on the loopback: it offers HTTP/2 and
//! HTTP/1.1 by ALPN, or HTTP/1.1 alone. On HTTP/2 a GET of a topic with no
//! `poll` is a stream, and the POSTs go on the same connection.

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use pod_wormhole::Config;
use pod_wormhole::ntfy::Point;
use tokio::net::TcpListener;

use super::ntfy::{Ntfy, Reply, Script, State, route, serve_http1, state_with};

// The certificates of the tests of pod-tls, minted in pure Rust.
#[allow(dead_code, unused_imports)]
mod cert {
    include!("../../../pod-tls/tests/common/cert_for_test.rs");
}

/// The name of the stand-in, which its certificate holds.
pub const NAME: &str = "ntfy.test";

/// The protocols that the stand-in offers by ALPN.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Offer {
    Both,
    Http1Only,
}

/// A stand-in behind TLS that offers `offer` and answers as `script` says.
pub async fn start(offer: Offer, script: Script) -> Ntfy {
    let (acceptor, _) = cert::server_for(NAME).expect("a certificate of the test");
    let mut tls = (**acceptor.config()).clone();
    tls.alpn_protocols = match offer {
        Offer::Both => vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        Offer::Http1Only => vec![b"http/1.1".to_vec()],
    };
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("a port of the loopback");
    let port = listener.local_addr().expect("its address").port();
    let state = state_with(script);
    let kept = state.clone();
    let task = tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let (acceptor, state) = (acceptor.clone(), kept.clone());
            let conn = {
                let mut s = state.lock().unwrap();
                s.connections += 1;
                s.connections
            };
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else { return };
                if tls.get_ref().1.alpn_protocol() == Some(b"h2".as_slice()) {
                    serve_h2(tls, state, conn).await;
                } else {
                    serve_http1(tls, state, conn).await;
                }
            });
        }
    });
    let url = Point::parse(&format!("https://{NAME}:{port}/")).unwrap();
    Ntfy::of(url, state, task)
}

/// The settings of the tests with the way that finds [`NAME`] on the
/// loopback and the trust of the root of its certificate.
pub fn config() -> Config {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let tls = Arc::new(pod_tls::Context::new(provider, pod_tls::Settings::new(pod_tls::Words::new("pod-wormhole"))));
    let lo: IpAddr = "127.0.0.1".parse().unwrap();
    let resolve = Arc::new(pod_proxy::resolve::System::with_pins(vec![(NAME.to_string(), lo)]));
    let settings = pod_proxy::Settings::new("pod-wormhole", pod_proxy::ProxyChoice::Direct);
    let way = pod_ws::Way::new(tls, Arc::new(pod_proxy::Dialer::new(settings, resolve)), "pod-wormhole/test");
    let mut config = Config::new(super::APPID, "pod-wormhole-test", "0.0.0", way);
    config.trust = pod_ws::Trust::File(root());
    config
}

/// The root of the certificates of [`NAME`], in a file of this process.
fn root() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pod-wormhole-ntfy-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("root.pem");
    let der = cert::encoding::self_signed_inner(&cert::encoding::anchor_name(NAME), true).der;
    std::fs::write(&path, cert::encoding::pem(&der)).unwrap();
    path
}

/// The streams of one connection of HTTP/2, each in a task of its own.
async fn serve_h2<S>(tls: S, state: Arc<Mutex<State>>, conn: u64)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let Ok(mut connection) = h2::server::handshake(tls).await else { return };
    while let Some(Ok((request, mut respond))) = connection.accept().await {
        let state = state.clone();
        tokio::spawn(async move {
            let method = request.method().as_str().to_string();
            let target = request.uri().path_and_query().map(|p| p.to_string()).unwrap_or_default();
            let mut body = request.into_body();
            let mut bytes = Vec::new();
            while let Some(Ok(part)) = body.data().await {
                let _ = body.flow_control().release_capacity(part.len());
                bytes.extend_from_slice(&part);
            }
            match route(&state, conn, true, &method, &target, &bytes) {
                Reply::Whole(status, answer) => {
                    let head = http::Response::builder().status(status).body(()).unwrap();
                    let Ok(mut send) = respond.send_response(head, false) else { return };
                    let _ = send.send_data(Bytes::from(answer), true);
                }
                Reply::Stream(first, mut more) => {
                    let head = http::Response::builder().status(200).body(()).unwrap();
                    let Ok(mut send) = respond.send_response(head, false) else { return };
                    for line in first {
                        if send.send_data(Bytes::from(format!("{line}\n")), false).is_err() {
                            return;
                        }
                    }
                    while let Some(line) = more.recv().await {
                        if send.send_data(Bytes::from(format!("{line}\n")), false).is_err() {
                            return;
                        }
                    }
                }
            }
        });
    }
}
