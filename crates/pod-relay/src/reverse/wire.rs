//! How a runner reaches the relay: TLS for each real use, or plain `ws://` to
//! a stand-in relay on the loopback, for the tests of an embedder (feature
//! `plain-ws`, podssh T-068) and for podnet's binary with a relay on the
//! loopback (call C101). An
//! operator's leg of a carrier (podssh T-595) is a pipe to the relay role's
//! side in its own process, through the role's [`Door`].

use std::time::Duration;

use pod_core::BoxFuture;
use pod_ws::client::{ConnectError, WsClientConfig, connect};
use pod_ws::session::RelaySession;
use tokio::io::DuplexStream;

/// The relay role's side of a carrier's node in this process: the role of
/// `pod-relay-serve` gives one. It opens a socket at `path` as the role's
/// own client, within `limit`, with no connection and no token: the stream
/// is the door.
pub trait Door: Send + Sync + 'static {
    /// A socket of the role at `path`.
    fn open<'a>(
        &'a self,
        path: &'a str,
        limit: Duration,
    ) -> BoxFuture<'a, Result<RelaySession<DuplexStream>, ConnectError>>;
    /// What the door is, for a debug line.
    fn label(&self) -> String;
}

/// A carrier's [`Door`]: `Copy`, as each wire is, so the role lives as long
/// as the process, which runs one carrier.
#[derive(Clone, Copy)]
pub struct Carrier(&'static dyn Door);

impl Carrier {
    /// The carrier of `door`, which lives as long as the process.
    pub fn of(door: impl Door) -> Carrier {
        Carrier(Box::leak(Box::new(door)))
    }

    /// The door.
    pub fn door(self) -> &'static dyn Door {
        self.0
    }
}

impl PartialEq for Carrier {
    fn eq(&self, other: &Carrier) -> bool {
        std::ptr::addr_eq(self.0, other.0)
    }
}

impl Eq for Carrier {}

impl std::fmt::Debug for Carrier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Carrier({})", self.0.label())
    }
}

/// The wire of a socket to the relay.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Wire {
    /// TLS to the relay, through the proxy when one is set.
    #[default]
    Tls,
    /// Plain `ws://` to a stand-in relay on the loopback, for tests. A host
    /// that is not the loopback is refused before any connection, so a token
    /// never leaves the host in clear (`pod_ws::plain`).
    #[cfg(feature = "plain-ws")]
    PlainLoopback,
    /// The relay role's side of a carrier's node, in this process: no
    /// connection, no token.
    Carrier(Carrier),
}

/// A socket to the relay, on either wire.
pub(crate) enum Socket {
    Tls(RelaySession),
    #[cfg(feature = "plain-ws")]
    Plain(RelaySession<tokio::net::TcpStream>),
    Carrier(RelaySession<DuplexStream>),
}

/// Connect on `wire` with `token`, as `config` says.
pub(crate) async fn open(wire: Wire, config: &WsClientConfig, token: &str) -> Result<Socket, ConnectError> {
    match wire {
        Wire::Tls => connect(config, token).await.map(Socket::Tls),
        #[cfg(feature = "plain-ws")]
        Wire::PlainLoopback => {
            let at = &config.endpoint;
            let extra = config.way.extra(&at.host)?;
            let (path, idle) = (&at.path, config.idle_timeout);
            pod_ws::plain::connect_loopback_carrying(&at.host, at.port, path, token, &extra, config.timeout, idle)
                .await
                .map(Socket::Plain)
        }
        // The stream is the door: the role takes no token.
        Wire::Carrier(carrier) => carrier.door().open(&config.endpoint.path, config.timeout).await.map(Socket::Carrier),
    }
}

/// What the facade's forward stream uses of a socket.
#[cfg(feature = "blocking")]
impl Socket {
    pub(crate) async fn read_frame(&self) -> Result<pod_ws::Frame, pod_ws::SessionError> {
        match self {
            Socket::Tls(s) => s.read_frame().await,
            #[cfg(feature = "plain-ws")]
            Socket::Plain(s) => s.read_frame().await,
            Socket::Carrier(s) => s.read_frame().await,
        }
    }

    pub(crate) async fn send_binary(&self, payload: &[u8]) -> Result<(), pod_ws::SessionError> {
        match self {
            Socket::Tls(s) => s.send_binary(payload).await,
            #[cfg(feature = "plain-ws")]
            Socket::Plain(s) => s.send_binary(payload).await,
            Socket::Carrier(s) => s.send_binary(payload).await,
        }
    }

    pub(crate) async fn send_close(&self, code: u16, reason: &str) -> Result<(), pod_ws::SessionError> {
        match self {
            Socket::Tls(s) => s.send_close(code, reason).await,
            #[cfg(feature = "plain-ws")]
            Socket::Plain(s) => s.send_close(code, reason).await,
            Socket::Carrier(s) => s.send_close(code, reason).await,
        }
    }

    pub(crate) fn close_sent(&self) -> bool {
        match self {
            Socket::Tls(s) => s.close_sent(),
            #[cfg(feature = "plain-ws")]
            Socket::Plain(s) => s.close_sent(),
            Socket::Carrier(s) => s.close_sent(),
        }
    }
}

#[cfg(all(test, feature = "plain-ws"))]
mod tests {
    use super::*;
    use pod_ws::headers::{MASK, Zeroizing};
    use pod_ws::{Endpoint, Headers};
    use tokio::io::AsyncWriteExt;

    const SECRET: &str = "made-up-secret-of-the-test-0123";

    /// A stand-in that keeps each request's header names, and answers a
    /// path that ends in `/403` with the secret that came, quoted back.
    async fn stand_in(names: tokio::sync::mpsc::UnboundedSender<Vec<String>>) -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut tcp, _)) = listener.accept().await {
                let Ok((head, _)) = pod_proxy::http::request::read_request(&mut tcp, Vec::new()).await else {
                    continue;
                };
                let _ = names.send(head.headers.iter().map(|(n, _)| n.clone()).collect());
                let answer = match pod_ws::server::check_upgrade(&head) {
                    Ok(_) if head.target.ends_with("/403") => {
                        let body = format!("denied {}", head.header("cf-access-client-secret").unwrap_or_default());
                        format!("HTTP/1.1 403 No\r\nContent-Length: {}\r\n\r\n{body}", body.len()).into_bytes()
                    }
                    Ok(key) => pod_ws::server::switching(&key),
                    Err(refused) => refused.answer(),
                };
                let _ = tcp.write_all(&answer).await;
                tokio::spawn(async move {
                    let mut rest = [0u8; 64];
                    while matches!(tokio::io::AsyncReadExt::read(&mut tcp, &mut rest).await, Ok(n) if n > 0) {}
                });
            }
        });
        port
    }

    /// A node's and an operator's socket carry the caller's headers after
    /// the token, before the dialect; a 403 keeps its status and shows no
    /// value.
    #[tokio::test]
    async fn a_reverse_socket_carries_the_caller_s_headers() {
        pod_testkit::need_loopback!();
        let (tell, mut told) = tokio::sync::mpsc::unbounded_channel();
        let port = stand_in(tell).await;
        let headers = Headers::new(|_| vec![("CF-Access-Client-Secret", Zeroizing::new(SECRET.into()))]);
        let config = |path: &str| WsClientConfig {
            endpoint: Endpoint { host: "127.0.0.1".into(), port, path: path.into() },
            trust: pod_ws::Trust::Default,
            server_name: "127.0.0.1".into(),
            timeout: Duration::from_secs(20),
            idle_timeout: None,
            way: crate::testing::way().with_headers(headers.clone()),
            limits: pod_ws::Limits::RELAY,
        };
        for path in ["/v1/node/podssh-p-0123", "/v1/connect/podssh-p-0123"] {
            assert!(open(Wire::PlainLoopback, &config(path), "tok").await.is_ok(), "{path}");
            let names = told.recv().await.unwrap();
            let at = names.iter().position(|n| n == "x-relay-token").expect("the token");
            assert_eq!(names[at..], ["x-relay-token", "cf-access-client-secret", "x-podssh-proto"], "{path}");
        }
        let Err(e) = open(Wire::PlainLoopback, &config("/v1/node/403"), "tok").await else { panic!("a refusal") };
        assert_eq!(e, ConnectError::Refused { status: 403, body: format!("denied {MASK}") });
    }
}
