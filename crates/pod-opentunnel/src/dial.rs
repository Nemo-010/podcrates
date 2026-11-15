//! The ways to an OpenTunnel service, through the caller's [`Way`]: TLS to
//! its API's host through the way's dialer, verified with the provider and
//! the trust store of its TLS context, for the API and the bridges
//! ([`tls`]); and a TCP stream through the same dialer to a tunnel's name on
//! port 443, before TLS, for a client, whose TLS goes to the node and is
//! checked there ([`tcp`]). A proxy gets the name, never an address, so the
//! host needs no DNS. No credential of the caller goes to the service: the
//! bearer token of a tunnel is the service's own, in a header alone.
//!
//! A [`Dial`] and a [`Visit`] give byte streams, so that a test gives pipes
//! to a stand-in in their place.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use pod_tls::Trust;
use pod_ws::Way;
use tokio::io::{AsyncRead, AsyncWrite};

use super::Service;

/// The bound of the TCP connection, and of TLS, each.
pub const CONNECT_LIMIT: Duration = Duration::from_secs(20);

/// A byte stream to the service.
pub trait Io: AsyncRead + AsyncWrite + Unpin + Send + 'static {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> Io for T {}

/// A boxed [`Io`].
pub type BoxIo = Box<dyn Io>;
/// A dial in progress.
pub type Dialing = Pin<Box<dyn Future<Output = Result<BoxIo, String>> + Send>>;
/// How to reach the API's host, after TLS: [`tls`], or a test's pipe.
pub type Dial = Arc<dyn Fn(&Service) -> Dialing + Send + Sync>;
/// How a client reaches a tunnel's name on port 443, before TLS: [`tcp`],
/// or a test's pipe.
pub type Visit = Arc<dyn Fn(&str) -> Dialing + Send + Sync>;

/// TLS to the service's API host, through `way`, verified with `trust`.
pub fn tls(way: Arc<Way>, trust: Trust) -> Dial {
    Arc::new(move |service: &Service| -> Dialing {
        let (service, trust, way) = (service.clone(), trust.clone(), way.clone());
        Box::pin(async move {
            let host = service.host.as_str();
            let opened = way.open_tls(host, service.port, host, &trust, CONNECT_LIMIT, &[]);
            let (tls, _) = opened.await.map_err(|e| format!("{service}: {e}"))?;
            Ok(Box::new(tls) as BoxIo)
        })
    })
}

/// TCP to each name on port 443, through `way`.
pub fn tcp(way: Arc<Way>) -> Visit {
    Arc::new(move |name: &str| -> Dialing {
        let (name, way) = (name.to_string(), way.clone());
        Box::pin(async move {
            let tcp =
                way.tcp(&name, super::PORT, CONNECT_LIMIT).await.map_err(|e| format!("{name}:{}: {e}", super::PORT))?;
            Ok(Box::new(tcp.io) as BoxIo)
        })
    })
}
