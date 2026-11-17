//! What the consumer gives the tunnel: the TLS of the binary, the way out,
//! the resolver, its own services, the relay and WARP, and the settings
//! (section 1, rules 4 to 7 and 10). The crate keeps no process state.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use futures::future::BoxFuture;
use pod_core::{BoxedIo, Dial, NoObserver, Observer};

use crate::cloudflare::stream::ConnectRequest;
use crate::ingress::Service;
use crate::proxy::{EdgeReader, EdgeWriter};

/// The services of the consumer that a rule of the ingress can name
/// ([`Service::Static`] and [`Service::Custom`]): the consumer builds and
/// serves them.
pub trait ServiceDispatch: Send + Sync {
    /// Check and build the service of rule `index` before the tunnel
    /// starts. An error stops the start (a missing directory, for example).
    fn prepare(&self, index: usize, service: &Service) -> anyhow::Result<()>;

    /// Answer one request of the edge for rule `index`. `host` is the host
    /// of the request.
    fn serve<'a>(
        &'a self,
        index: usize,
        request: &'a ConnectRequest,
        host: &'a str,
        reader: EdgeReader,
        writer: EdgeWriter,
    ) -> BoxFuture<'a, anyhow::Result<()>>;
}

/// A consumer with no services of its own: a rule that names one is
/// refused when the tunnel starts.
pub struct NoServices;

impl ServiceDispatch for NoServices {
    fn prepare(&self, _index: usize, service: &Service) -> anyhow::Result<()> {
        anyhow::bail!("the service {} needs the consumer, which gives none", service.describe())
    }

    fn serve<'a>(
        &'a self,
        _index: usize,
        _request: &'a ConnectRequest,
        _host: &'a str,
        _reader: EdgeReader,
        _writer: EdgeWriter,
    ) -> BoxFuture<'a, anyhow::Result<()>> {
        Box::pin(async { anyhow::bail!("the consumer serves no service") })
    }
}

/// One WARP session and the QUIC endpoint in it, for the leg `quic+warp`.
pub struct WarpSession {
    /// The QUIC endpoint over the datagrams of the session.
    pub endpoint: noq::Endpoint,
    /// True when the session closed.
    pub closed: Box<dyn Fn() -> bool + Send + Sync>,
    /// What keeps the session open; dropped with the session.
    pub keep: Box<dyn std::any::Any + Send + Sync>,
}

/// The WARP sessions of the consumer (`pod-warp` through the consumer's
/// device and identity).
pub trait WarpSessions: Send + Sync {
    /// Open a new session. The first call registers the device or loads
    /// it; a later call opens a session with the same device.
    fn open(&self) -> BoxFuture<'_, anyhow::Result<WarpSession>>;
}

/// The SRV records of a name from the system resolver of the consumer
/// (`/etc/resolv.conf`): the second step of the discovery of the edge.
pub trait SystemSrv: Send + Sync {
    /// The targets and the ports of the SRV records of `name`.
    fn srv<'a>(&'a self, name: &'a str) -> BoxFuture<'a, anyhow::Result<Vec<(String, u16)>>>;
}

/// The relay for the leg `http2+relay`.
#[derive(Clone)]
pub struct EdgeRelay {
    /// A TCP connection through the relay.
    pub dial: Arc<dyn Dial>,
    /// The run of the relay: the limits of the relay in use give the budget
    /// of a connection (`pod_relay::relay::byte_budget`, `time_budget`).
    pub context: Arc<pod_relay::Context>,
}

/// The settings of a tunnel. A consumer fills them from its variables.
#[derive(Clone, Debug)]
pub struct Settings {
    /// The edge addresses in place of the discovery (podnet's `PODNET_EDGE`,
    /// cloudflared's `--edge`).
    pub edge: Option<Vec<SocketAddr>>,
    /// What the tunnel does with UDP (podnet's `PODNET_UDP`).
    pub udp: crate::udp::Choice,
    /// The most time for the provision of a quick tunnel (podnet's
    /// `PODNET_READY_TIMEOUT` makes it shorter).
    pub provision_budget: Duration,
    /// The name and the version of the client that the edge sees
    /// (`podnet/0.4.0`).
    pub client_version: String,
    /// The user agent of the WebSocket dial of a forward.
    pub ws_user_agent: String,
    /// A check of the public URL that fails is an error, not a warning
    /// (podnet's `PODNET_VERIFY_STRICT`).
    pub verify_strict: bool,
}

impl Default for Settings {
    fn default() -> Self {
        let version = concat!("pod-cloudflare/", env!("CARGO_PKG_VERSION"));
        Self {
            edge: None,
            udp: crate::udp::Choice::Probe,
            provision_budget: crate::quicktunnel::PROVISION_BUDGET,
            client_version: version.to_string(),
            ws_user_agent: version.to_string(),
            verify_strict: false,
        }
    }
}

/// What the consumer gives the tunnel.
#[derive(Clone)]
pub struct Host {
    /// The TLS of the binary: the provider, the roots, the groups.
    pub tls: Arc<pod_tls::Context>,
    /// The way out of each TCP connection: direct or through the proxy.
    pub dial: Arc<dyn Dial>,
    /// The resolver: the SRV record of the edge by DNS over HTTPS, and the
    /// step that answers a name.
    pub resolver: Arc<pod_dns::Resolver>,
    /// The SRV records of the system resolver; `None`: the discovery skips
    /// this step.
    pub system_srv: Option<Arc<dyn SystemSrv>>,
    /// The services of the consumer.
    pub services: Arc<dyn ServiceDispatch>,
    /// The counters of the decisions (the leg that won).
    pub observer: Arc<dyn Observer>,
    /// The relay of the leg `http2+relay`.
    pub relay: Option<EdgeRelay>,
    /// The WARP sessions of the leg `quic+warp`.
    pub warp: Option<Arc<dyn WarpSessions>>,
    pub settings: Settings,
}

impl Host {
    /// A host with the TLS `tls` and the way out `dial`, the resolver of
    /// `pod-dns` with its default settings over the same way, no services,
    /// no relay and no WARP.
    pub fn new(tls: Arc<pod_tls::Context>, dial: Arc<dyn Dial>) -> Host {
        let resolver = pod_dns::Resolver::new(pod_dns::Settings::default()).with_doh(tls.clone(), dial.clone());
        Host {
            tls,
            dial,
            resolver: Arc::new(resolver),
            system_srv: None,
            services: Arc::new(NoServices),
            observer: Arc::new(NoObserver),
            relay: None,
            warp: None,
            settings: Settings::default(),
        }
    }

    /// The HTTP client over the TLS and the way out of the host.
    pub fn client(&self) -> pod_proxy::Client {
        pod_proxy::Client::new(self.tls.clone(), self.dial.clone())
    }

    /// Send `request` with [`Host::client`]. A failure keeps its stage
    /// ([`crate::fail::stage_of`]) and names the request, with no query.
    pub async fn send(&self, request: pod_proxy::client::Request) -> anyhow::Result<pod_proxy::http::Response> {
        let url = request.url.split(['?', '#']).next().unwrap_or_default();
        let what = format!("{} {url}", request.method);
        self.client().send(request).await.map_err(|failure| {
            let stage = failure.stage;
            crate::fail::at(stage, anyhow::Error::new(failure).context(what))
        })
    }

    /// The step of the chain of the resolver that answers `host` now:
    /// `literal`, `pin`, `system`, `doh` or `none`.
    pub async fn answering_step(&self, host: &str) -> &'static str {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        let found = self.resolver.find(host, 0, deadline, None).await;
        found.map_or("none", |f| f.source.name())
    }

    /// The label of the proxy that a TCP connection to `host:port` goes
    /// through, or `None` for a direct connection.
    pub fn proxy_for(&self, host: &str, port: u16) -> Option<String> {
        self.dial.proxy_label(&pod_core::Target::new(host, port))
    }

    /// Open TCP to `target` through the way out, in at most `limit`.
    pub async fn connect(&self, target: &pod_core::Target, limit: Duration) -> anyhow::Result<BoxedIo> {
        let deadline = tokio::time::Instant::now() + limit;
        let connected = self.dial.dial(target, deadline).await.map_err(anyhow::Error::new)?;
        Ok(connected.io)
    }
}
