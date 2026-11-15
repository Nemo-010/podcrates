//! The way to a DERP server: TLS over TCP through the caller's way out
//! (`pod_ws::Way`: its dialer, its proxy, its TLS context and trust store);
//! then a WebSocket at `/derp` with the subprotocol `derp`, which derper's
//! handler requires (tailscale/tailscale:derp/derpserver/websocket.go at
//! v1.104.4), and which Tailscale's own client in a browser offers. No relay
//! token goes with it: a token goes to the deployment that minted it alone.
//!
//! A [`Dial`] gives the byte stream before the upgrade, so that a test can
//! give a pipe to a stand-in in place of TLS.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use pod_core::{Class, Failure, Stage};
use pod_ws::{RelaySession, Trust, Way};
use tokio::io::{AsyncRead, AsyncWrite};

use super::servers::Server;

/// The path of DERP's WebSocket.
pub const PATH: &str = "/derp";
/// The subprotocol of DERP's WebSocket.
pub const SUBPROTOCOL: &str = "derp";
/// The bound of the connection, of TLS and of the upgrade, each.
pub const CONNECT_LIMIT: Duration = Duration::from_secs(20);
/// The bound of each read: a server answers the pings of [`super::conn`]
/// each 10 s, so silence this long is a dead link.
pub const IDLE_LIMIT: Duration = Duration::from_secs(30);
/// The bound of each write.
pub const WRITE_LIMIT: Duration = Duration::from_secs(20);
/// The largest message read: a server's writer may join several frames.
pub const RECEIVE_CAP: usize = 1 << 20;

/// A byte stream to a server, before its upgrade.
pub trait Io: AsyncRead + AsyncWrite + Unpin + Send + 'static {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> Io for T {}

/// A boxed [`Io`].
pub type BoxIo = Box<dyn Io>;
/// A dial in progress.
pub type Dialing = Pin<Box<dyn Future<Output = Result<BoxIo, Failure>> + Send>>;
/// How to reach a server: TLS through the proxy ([`tls`]), or a test's pipe.
pub type Dial = Arc<dyn Fn(&Server) -> Dialing + Send + Sync>;

/// TLS to each server, through `way`, verified with `trust`.
pub fn tls(way: Way, trust: Trust) -> Dial {
    Arc::new(move |server: &Server| -> Dialing {
        let (server, trust, way) = (server.clone(), trust.clone(), way.clone());
        Box::pin(async move {
            let host = server.host.as_str();
            let opened = way.open_tls(host, server.port, host, &trust, CONNECT_LIMIT, &[]);
            let (tls, _) = opened.await.map_err(|e| {
                let (stage, class) = e.stage_and_class();
                Failure::caused(stage, class, format!("{server}: {e}"), e)
            })?;
            Ok(Box::new(tls) as BoxIo)
        })
    })
}

/// The upgrade request, as the WebSocket of Tailscale's own client asks
/// for it, with `key` as its `Sec-WebSocket-Key`; `user_agent` names the
/// program.
pub fn request(server: &Server, key: &str, user_agent: &str) -> Vec<u8> {
    let host = if server.port == super::servers::PORT { server.host.clone() } else { server.authority() };
    let mut out = String::with_capacity(256);
    out.push_str(&format!("GET {PATH} HTTP/1.1\r\n"));
    out.push_str(&format!("Host: {host}\r\n"));
    out.push_str(&format!("User-Agent: {}\r\n", pod_core::text::one_line(user_agent)));
    out.push_str("Upgrade: websocket\r\n");
    out.push_str("Connection: Upgrade\r\n");
    out.push_str(&format!("Sec-WebSocket-Key: {key}\r\n"));
    out.push_str("Sec-WebSocket-Version: 13\r\n");
    out.push_str(&format!("Sec-WebSocket-Protocol: {SUBPROTOCOL}\r\n"));
    out.push_str("\r\n");
    out.into_bytes()
}

/// The WebSocket of DERP over `io`, a stream to `server`.
pub async fn upgrade(io: BoxIo, server: &Server, user_agent: &str) -> Result<RelaySession<BoxIo>, Failure> {
    let key = pod_ws::handshake::generate_key().map_err(Failure::from)?;
    let ask = request(server, &key, user_agent);
    let asked = pod_ws::client::upgrade_with(io, &ask, &key);
    let (io, pending) = match tokio::time::timeout(CONNECT_LIMIT, asked).await {
        Err(_) => {
            let text = format!("{server} did not answer the upgrade within {} s", CONNECT_LIMIT.as_secs());
            return Err(Failure::new(Stage::WebSocket, Class::Timeout, text));
        }
        Ok(Err(e)) => {
            let (stage, class) = e.stage_and_class();
            return Err(Failure::caused(stage, class, format!("{server} refused DERP's WebSocket: {e}"), e));
        }
        Ok(Ok(upgraded)) => upgraded,
    };
    let session = RelaySession::new(io, pending, Some(IDLE_LIMIT), WRITE_LIMIT).without_pings();
    session.set_receive_cap(RECEIVE_CAP);
    Ok(session)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_upgrade_asks_for_derp_s_subprotocol_at_its_path_and_names_no_token() {
        let server = Server::parse("tc301a.ipn.dev").unwrap();
        let text = String::from_utf8(request(&server, "dGhlIHNhbXBsZSBub25jZQ==", "podssh/1.0")).unwrap();
        assert!(text.starts_with("GET /derp HTTP/1.1\r\nHost: tc301a.ipn.dev\r\n"), "{text}");
        assert!(text.contains("\r\nSec-WebSocket-Protocol: derp\r\n"));
        assert!(text.contains("\r\nUser-Agent: podssh/1.0\r\n"), "the program's own name: {text}");
        assert!(text.contains("\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"));
        assert!(text.ends_with("\r\n\r\n"));
        assert!(!text.to_ascii_lowercase().contains("token"), "no credential goes to a DERP server");
        let other = Server::parse("127.0.0.1:8443").unwrap();
        assert!(String::from_utf8(request(&other, "k", "a")).unwrap().contains("\r\nHost: 127.0.0.1:8443\r\n"));
    }
}
