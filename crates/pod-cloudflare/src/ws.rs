//! The edge side of a WebSocket-carried raw stream.
//!
//! A quick tunnel is an HTTP tunnel, but it proxies WebSocket upgrades. That is
//! enough to carry *anything*: the origin exposes a WebSocket endpoint, each
//! connection is bridged to a raw stream (TCP or unix), and a client on the far
//! side turns local sockets into WebSocket connections. This is the websocat /
//! wstunnel idea, and it removes the HTTP-only limit without needing the edge to
//! understand the payload.
//!
//! One WebSocket message maps to one write, so binary framing is preserved and
//! interactive protocols (SSH, RDP, databases, raw sockets) work unchanged.
//!
//! The WebSocket and its bridge are `pod-ws`, with the limits of
//! tokio-tungstenite. The client side (the dial of a forward) is the
//! consumer's.

use crate::fail::{Context, IoFail, Result};
use pod_core::Stage;
use pod_ws::Limits;
use tokio_util::compat::{FuturesAsyncReadCompatExt, FuturesAsyncWriteCompatExt};

use crate::cloudflare::stream as cqstream;
use crate::ingress::{ForwardTarget, OriginOptions, Service};
use crate::metrics::Metrics;
use crate::origin::Origins;
use crate::proxy::{EdgeReader, EdgeWriter, header_value, write_response_meta};

/// The default of [`crate::Settings::forward_path`]: the path of the
/// WebSocket of a forward rule with no path. It is podnet's wire, and the
/// client of the consumer dials the same path.
pub const DEFAULT_PATH: &str = "/__podnet/ws";

/// [`forward_path_with`] and [`DEFAULT_PATH`].
pub fn forward_path(ingress: &crate::ingress::Ingress) -> Option<String> {
    forward_path_with(ingress, DEFAULT_PATH)
}

/// The path of the first forward rule of `ingress`; `default` for a rule
/// with no path. `None` also when the `path:` of the rule is a regular
/// expression with a special character: it names no one URL.
pub fn forward_path_with(ingress: &crate::ingress::Ingress, default: &str) -> Option<String> {
    let rule = ingress.rules.iter().find(|rule| matches!(rule.service, Service::Forward(_)))?;
    match &rule.path {
        None => Some(default.to_string()),
        Some(pattern) => pattern.literal_path(),
    }
}

/// The wss:// URL of the forward endpoint at `path` of the public URL `url`.
pub fn forward_url(url: &str, path: &str) -> Option<String> {
    let rest =
        url.strip_prefix("https://").map(|r| ("wss", r)).or_else(|| url.strip_prefix("http://").map(|r| ("ws", r)))?;
    let host = rest.1.split('/').next()?;
    let path = if path.starts_with('/') { path.to_string() } else { format!("/{path}") };
    Some(format!("{}://{host}{path}", rest.0))
}

/// Compute `Sec-WebSocket-Accept` for a client's `Sec-WebSocket-Key`.
pub use pod_ws::handshake::accept_key;

/// The byte counts of a bridge, in the counters of the tunnel.
struct Counted<'a>(&'a Metrics);

impl pod_ws::Tally for Counted<'_> {
    fn add_in(&self, bytes: u64) {
        self.0.add_in(bytes);
    }
    fn add_out(&self, bytes: u64) {
        self.0.add_out(bytes);
    }
}

/// Serve one inbound WebSocket upgrade from the edge, bridging it to `target`.
pub async fn serve_websocket(
    origins: &Origins,
    target: &ForwardTarget,
    request: &cqstream::ConnectRequest,
    reader: EdgeReader,
    mut writer: EdgeWriter,
    metrics: &Metrics,
) -> Result<()> {
    let Some(key) = header_value(request, "sec-websocket-key") else {
        return write_response_meta(&mut writer, 400, &plain("missing Sec-WebSocket-Key")).await;
    };

    // Dial first: the visitor gets 101 only for a target that answers, else
    // 502.
    let service = match target {
        ForwardTarget::Tcp(addr) => Service::Tcp(addr.clone()),
        ForwardTarget::Unix(path) => Service::Unix(path.clone()),
    };
    let io = match origins.dial(&service, &OriginOptions::default()).await {
        Ok(io) => io,
        Err(err) => {
            const TEXT: &str = "the forward target does not answer\n";
            write_response_meta(&mut writer, 502, &plain(TEXT)).await?;
            futures::io::AsyncWriteExt::write_all(&mut writer, TEXT.as_bytes())
                .await
                .io_fail(Stage::EdgeStream, "writing to the edge")?;
            futures::io::AsyncWriteExt::close(&mut writer).await.io_fail(Stage::EdgeStream, "writing to the edge")?;
            return Err(err).with_context(|| format!("dialing forward target {}", target.describe()));
        }
    };

    let headers = vec![
        ("Upgrade".to_string(), "websocket".to_string()),
        ("Connection".to_string(), "Upgrade".to_string()),
        ("Sec-WebSocket-Accept".to_string(), accept_key(key)),
    ];
    write_response_meta(&mut writer, 101, &headers).await?;

    // The edge stream is a QUIC bidi pair; join it into one socket for the
    // WebSocket codec. `into_inner` recovers the noq halves from the
    // futures-io wrappers used by the request framing.
    let socket = tokio::io::join(reader.compat(), writer.compat_write());
    let session = pod_ws::server::session(socket, Vec::new(), None).with_limits(Limits::TUNGSTENITE);
    pod_ws::bridge(session, io, &Counted(metrics)).await.context("the bridge of the forward WebSocket")
}

fn plain(message: &str) -> Vec<(String, String)> {
    vec![
        ("Content-Type".to_string(), "text/plain; charset=utf-8".to_string()),
        ("Content-Length".to_string(), message.len().to_string()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A forward target that does not answer gives 502, not
    /// 101 and then a closed WebSocket.
    #[tokio::test]
    async fn a_target_that_does_not_answer_gives_502() {
        pod_testkit::need_loopback!();
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = closed.local_addr().unwrap();
        drop(closed);
        let request = cqstream::ConnectRequest {
            dest: "https://x/__podnet/ws".into(),
            conn_type: cqstream::ConnectionType::Websocket,
            metadata: vec![("HttpHeader:Sec-Websocket-Key".into(), "dGhlIHNhbXBsZSBub25jZQ==".into())],
        };
        let (near, far) = tokio::io::duplex(1 << 16);
        let reader: EdgeReader = Box::pin(futures::io::empty());
        let writer: EdgeWriter = Box::pin(tokio_util::compat::TokioAsyncWriteCompatExt::compat_write(near));
        let target = ForwardTarget::Tcp(addr.to_string());
        let origins = Origins::new(crate::testing::tls());
        let result = serve_websocket(&origins, &target, &request, reader, writer, &Metrics::new()).await;
        assert!(result.is_err());
        let mut far = tokio_util::compat::TokioAsyncReadCompatExt::compat(far);
        let (_, meta) = cqstream::read_connect_response(&mut far).await.unwrap();
        assert!(meta.contains(&("HttpStatus".to_string(), "502".to_string())), "{meta:?}");
        assert!(!meta.iter().any(|(k, _)| k.contains("Sec-WebSocket-Accept")), "{meta:?}");
    }

    // The forward endpoint of a public URL.
    #[test]
    fn the_forward_url_of_a_public_url() {
        assert_eq!(
            forward_url("https://a-b.trycloudflare.com", DEFAULT_PATH).as_deref(),
            Some("wss://a-b.trycloudflare.com/__podnet/ws")
        );
        assert_eq!(forward_url("https://h.example/x/", "raw").as_deref(), Some("wss://h.example/raw"));
        assert_eq!(forward_url("ftp://h", "/x"), None);
        let ingress = crate::ingress::Ingress::new().rule_with(crate::ingress::IngressRule {
            hostname: None,
            path: Some(crate::ingress::PathPattern::prefix(DEFAULT_PATH)),
            service: Service::Forward(ForwardTarget::Tcp("127.0.0.1:22".into())),
            origin: OriginOptions::default(),
        });
        assert_eq!(forward_path(&ingress).as_deref(), Some(DEFAULT_PATH));
        assert_eq!(forward_path(&crate::ingress::Ingress::new()), None);
    }
}
