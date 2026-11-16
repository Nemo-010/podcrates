//! An iroh endpoint set up as the other roads are:
//!
//! - no address lookup (pkarr, DNS, mDNS): a peer is dialled by its key and
//!   its relay;
//! - the relays given; the table of [`crate::relays`] by default, whose first
//!   relay that answers `/ping` the caller gives alone (PodUtils/podssh@T-165);
//! - the caller's proxy for the relay's dial ([`Options::proxy`]): iroh's own
//!   selection reads `HTTP_PROXY` first and knows no `ALL_PROXY` or
//!   `NO_PROXY`. An HTTP CONNECT proxy, or a SOCKS5 one, through the patch
//!   of iroh-relay in `vendor/` (PodUtils/podssh@T-280,
//!   `vendor/patches/iroh-relay/`);
//! - the caller's resolver ([`crate::resolve`]), the caller's TLS provider,
//!   and the caller's trust store for the relay's certificate;
//! - UDP only after a datagram came back: a round trip of QUIC address
//!   discovery to the home relay in the endpoint's first report, before
//!   anything is dialled or served ([`crate::probe`], PodUtils/podssh@T-359);
//!   the relay alone, else;
//! - QUIC's settings of [`crate::tuning`]: the arm that the caller gives,
//!   else the default arm (PodUtils/podssh@T-665).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use iroh::dns::DnsResolver;
use iroh::endpoint::{BindOpts, QuicTransportConfig, presets};
use iroh::tls::CaTlsConfig;
use iroh::{Endpoint, NetReportConfig, RelayConfig, RelayMap, RelayMode, RelayUrl, SecretKey};
use pod_core::Resolve;
use pod_proxy::{Carrier, ProxyChoice, ProxyKind};
use pod_tls::{Context, Trust};

use crate::tuning::Tuning;

/// The relays to use, and the endpoint's way out.
#[derive(Clone)]
pub struct Options {
    /// The relays: iroh takes the one with the least latency as the home
    /// relay, so a caller that wants the first that answers gives that one
    /// alone ([`crate::relays::home`]). Empty is the table of
    /// [`crate::relays::default_urls`].
    pub relays: Vec<RelayUrl>,
    /// The TLS context of the binary: its provider, for QUIC and for the
    /// relay's TLS, and the roots of [`Options::trust`].
    pub tls: Arc<Context>,
    /// The resolver of the relay's name and of the proxy's name.
    pub resolve: Arc<dyn Resolve>,
    /// How the relay's connection goes out: iroh dials the relay itself and
    /// takes a proxy's URL, not a dialer. A choice of the environment is
    /// asked for the first relay, with the pins of `resolve`.
    pub proxy: ProxyChoice,
    /// The trust anchors for the relay's certificate.
    pub trust: Trust,
    /// Whether to try direct UDP when a probe allows it.
    pub udp: Udp,
    /// This end's key: a new one when `None` (PodUtils/podssh@T-163 keeps one
    /// in a file).
    pub secret: Option<SecretKey>,
    /// Whether this end takes sessions, as a node does.
    pub accepts: bool,
    /// The trust for the relay's certificate in place of `trust`, as an
    /// embedder or a test gives it. A command line never sets it.
    pub relay_tls: Option<CaTlsConfig>,
    /// The port of the relays' QUIC address discovery in place of iroh's
    /// 7842, as a test gives it. A command line never sets it.
    pub qad_port: Option<u16>,
    /// QUIC's settings (PodUtils/podssh@T-665): the arm that the consumer
    /// read from [`crate::tuning::QUIC_ENV`] with
    /// [`Tuning::from_value`], or a test's own; `None` is the arm of
    /// [`crate::tuning::DEFAULT`].
    pub quic: Option<Tuning>,
}

impl Options {
    /// The options of an endpoint with the TLS of `tls` and the resolver
    /// `resolve`: the table of relays, no proxy, the default trust, the
    /// probe of UDP, a new key, no sessions taken, and the default arm of
    /// QUIC.
    pub fn new(tls: Arc<Context>, resolve: Arc<dyn Resolve>) -> Options {
        Options {
            relays: Vec::new(),
            tls,
            resolve,
            proxy: ProxyChoice::Direct,
            trust: Trust::Default,
            udp: Udp::Probe,
            secret: None,
            accepts: false,
            relay_tls: None,
            qad_port: None,
            quic: None,
        }
    }
}

impl std::fmt::Debug for Options {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Options")
            .field("relays", &self.relays)
            .field("resolve", &self.resolve.label())
            .field("proxy", &self.proxy)
            .field("trust", &self.trust)
            .field("udp", &self.udp)
            .field("secret", &self.secret.as_ref().map(|s| s.public()))
            .field("accepts", &self.accepts)
            .field("qad_port", &self.qad_port)
            .field("quic", &self.quic)
            .finish_non_exhaustive()
    }
}

/// Whether the endpoint may use direct UDP paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Udp {
    /// After a datagram came back: a QUIC address discovery's round trip to
    /// the home relay (see [`crate::probe`]).
    Probe,
    /// After a UDP socket binds, with nothing sent: for a relay that runs no
    /// QUIC address discovery.
    On,
    /// Never: the relay carries each byte.
    Off,
}

/// The variable of the consumer that chooses: `off` makes the relay carry
/// each byte, as the checks of a sandbox need (PodUtils/podssh@T-156); `on`
/// takes UDP after a bind alone, for a relay that runs no QUIC address
/// discovery; anything else is the probe. The crate reads no variable: the
/// consumer gives its value to [`Udp::from_value`], and [`crate::probe`]
/// names it in its words.
pub const UDP_ENV: &str = "PODSSH_IROH_UDP";

impl Udp {
    /// The choice of the variable's value: [`Udp::Off`] or [`Udp::On`] when
    /// it says `off` or `on`; else [`Udp::Probe`].
    pub fn from_value(value: Option<&str>) -> Udp {
        match value.map(str::trim) {
            Some(v) if v.eq_ignore_ascii_case("off") => Udp::Off,
            Some(v) if v.eq_ignore_ascii_case("on") => Udp::On,
            _ => Udp::Probe,
        }
    }
}

/// Why an endpoint could not be made.
#[derive(Debug)]
pub enum BindError {
    /// The proxy setting cannot be used.
    Proxy(String),
    /// The trust store cannot be read.
    Trust(String),
    /// iroh refused the configuration, or could not bind.
    Iroh(String),
}

impl std::fmt::Display for BindError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BindError::Proxy(why) => write!(f, "the proxy setting is not usable for the iroh relay: {why}"),
            BindError::Trust(why) => write!(f, "the trust store for the iroh relay: {why}"),
            BindError::Iroh(why) => write!(f, "the iroh endpoint could not start: {why}"),
        }
    }
}

impl std::error::Error for BindError {}

/// The relays that an endpoint uses when it is given none: the table of
/// [`crate::relays::default_urls`], n0's public relays.
pub fn default_relays() -> Vec<RelayUrl> {
    crate::relays::defaults()
}

/// The relay map of `relays`, or of the table when it is empty; each relay's
/// QUIC address discovery on iroh's port, or on `qad_port`.
fn relay_mode(relays: &[RelayUrl], qad_port: Option<u16>) -> RelayMode {
    let relays = if relays.is_empty() { default_relays() } else { relays.to_vec() };
    let configs = relays.into_iter().map(|url| {
        let mut config = RelayConfig::from(url);
        if let (Some(port), Some(quic)) = (qad_port, config.quic.as_mut()) {
            quic.port = port;
        }
        config
    });
    RelayMode::Custom(configs.collect::<RelayMap>())
}

/// The proxy for the first relay, as the caller chooses it, as the URL that
/// iroh takes; `None` for a direct dial. iroh takes one proxy for each
/// relay, so the `NO_PROXY` of a choice of the environment is read for the
/// first. The proxy's address is resolved here, by the caller's resolver,
/// so iroh resolves no name at all. A proxy on a Unix socket or at a
/// command is refused: iroh dials a proxy on TCP alone.
///
/// A SOCKS5 proxy keeps its scheme at that address (PodUtils/podssh@T-280):
/// the relay dial of the patched iroh-relay sends the relay's name with
/// `socks5://` and `socks5h://` alike, so this host needs no DNS for it.
async fn proxy_url(
    choice: &ProxyChoice,
    mode: &RelayMode,
    resolve: &dyn Resolve,
) -> Result<Option<url::Url>, BindError> {
    let urls: Vec<RelayUrl> = mode.relay_map().urls();
    let first = urls.first();
    let host = first.and_then(|relay| relay.host_str().map(str::to_string)).unwrap_or_default();
    let port = first.and_then(|relay| relay.port_or_known_default()).unwrap_or(443);
    let proxy = match choice {
        ProxyChoice::Direct => return Ok(None),
        ProxyChoice::Via(proxy) => proxy.clone(),
        ProxyChoice::FromEnvironment(environment) => {
            match environment.proxy_at(&host, port, &resolve.pinned(&host)).map_err(BindError::Proxy)? {
                Some(proxy) => proxy,
                None => return Ok(None),
            }
        }
    };
    if *proxy.carrier() != Carrier::Tcp {
        let why = format!("{}: iroh dials the relay through a proxy on TCP alone", proxy.label());
        return Err(BindError::Proxy(why));
    }
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(15);
    let addrs = resolve
        .resolve(&proxy.host, proxy.port, deadline)
        .await
        .map_err(|why| BindError::Proxy(format!("could not resolve the proxy {}: {why}", proxy.host)))?;
    let addr = addrs.first().ok_or_else(|| BindError::Proxy(format!("the proxy {} has no address", proxy.host)))?;
    let url = url::Url::parse(&proxy.url_at(*addr)).map_err(|e| BindError::Proxy(e.to_string()))?;
    // The patched SOCKS5 dial and reqwest decode the user and the password
    // themselves, and send them as RFC 1929 says: only `CONNECT` has iroh's
    // flaw.
    if proxy.kind == ProxyKind::Http {
        sendable(&url)?;
    }
    Ok(Some(url))
}

/// Whether iroh can give an HTTP proxy the user name and password of `url`.
/// iroh puts the URL's text in `Proxy-Authorization` as it is, escapes and
/// all, and in base64url, where RFC 7617 asks for base64: the proxy would
/// refuse a name or password that needed an escape, or whose base64 holds
/// `+` or `/`, and say nothing of why. Such credentials are refused here,
/// with the reason.
fn sendable(url: &url::Url) -> Result<(), BindError> {
    use base64::Engine as _;
    let (user, password) = (url.username(), url.password().unwrap_or_default());
    if user.is_empty() && password.is_empty() {
        return Ok(());
    }
    let pair = format!("{user}:{password}");
    let escaped = pair.contains('%');
    let differs = base64::engine::general_purpose::STANDARD.encode(pair.as_bytes()).contains(['+', '/']);
    if escaped || differs {
        return Err(BindError::Proxy(
            "the iroh road would send the proxy's user name and password in a form that the proxy refuses \
             (iroh sends them escaped, and in base64url); use the relay road, or a password of letters and \
             digits"
                .into(),
        ));
    }
    Ok(())
}

/// The trust for the relay's certificate: the roots of `trust` in the
/// caller's context, through rustls's own WebPKI verifier. A caller's own
/// configuration holds roots that cannot be listed, and is refused.
fn relay_tls(tls: &Context, trust: &Trust) -> Result<CaTlsConfig, BindError> {
    let roots = tls.roots_for(trust).map_err(|e| BindError::Trust(e.to_string()))?.roots;
    let roots = Arc::new(roots);
    Ok(CaTlsConfig::custom_server_cert_verifier(Arc::new(move |provider| {
        rustls::client::WebPkiServerVerifier::builder_with_provider(roots.clone(), provider)
            .build()
            .map(|verifier| verifier as Arc<dyn rustls::client::danger::ServerCertVerifier>)
            .map_err(std::io::Error::other)
    })))
}

/// An endpoint, what its probe of UDP found, and the QUIC settings that it took
/// (PodUtils/podssh@T-665), with a line for each of them that iroh's types
/// refused.
#[derive(Debug)]
pub struct Opened {
    pub endpoint: Endpoint,
    pub udp: crate::probe::Answer,
    pub quic: Tuning,
    pub kept: Vec<String>,
}

impl Opened {
    /// What the endpoint says of its QUIC: nothing with iroh's own settings,
    /// else the arm, and each setting whose iroh's own value was kept.
    pub fn quic_lines(&self) -> Vec<String> {
        if self.quic == Tuning::IROH && self.kept.is_empty() {
            return Vec::new();
        }
        let mut lines = vec![format!("QUIC: {}", self.quic)];
        lines.extend(self.kept.iter().map(|line| format!("QUIC: {line}")));
        lines
    }
}

/// How long the endpoint that a probe gave up on may take to close.
const CLOSE_LIMIT: Duration = Duration::from_secs(3);

/// What each endpoint of one [`open`] shares: the one made without UDP after
/// a probe takes the same.
struct Parts {
    tls: CaTlsConfig,
    mode: RelayMode,
    proxy: Option<url::Url>,
    quic: QuicTransportConfig,
}

/// An endpoint with `options`; with the ALPN of the sessions when it takes
/// them.
pub async fn bind(options: &Options) -> Result<Endpoint, BindError> {
    Ok(open(options).await?.endpoint)
}

/// An endpoint with `options`, and what the probe of UDP found. Its UDP
/// sockets stay only after a QUIC address discovery to the home relay came
/// back within [`crate::probe::REPORT_LIMIT`]; else the endpoint is made
/// again without them, with the same key, before it dials or serves.
pub async fn open(options: &Options) -> Result<Opened, BindError> {
    open_with(options, crate::probe::udp).await
}

/// [`open`], with the bind of the probe given, so that a test can plant a
/// refusal.
pub(crate) async fn open_with(
    options: &Options,
    bind_probe: fn() -> std::io::Result<SocketAddr>,
) -> Result<Opened, BindError> {
    use crate::probe::Answer;
    let tuning = options.quic.unwrap_or_default();
    let (quic, kept) = tuning.config();
    let tls = match &options.relay_tls {
        Some(tls) => tls.clone(),
        None => relay_tls(&options.tls, &options.trust)?,
    };
    let mode = relay_mode(&options.relays, options.qad_port);
    let proxy = proxy_url(&options.proxy, &mode, &*options.resolve).await?;
    let parts = Parts { tls, mode, proxy, quic };
    let opened = |endpoint: Endpoint, udp: Answer| Opened { endpoint, udp, quic: tuning, kept: kept.clone() };
    let addr = match options.udp {
        Udp::Off => return Ok(opened(make(&parts, options, false, None).await?, Answer::Off)),
        Udp::Probe | Udp::On => match bind_probe() {
            Ok(addr) => addr,
            Err(e) => return Ok(opened(make(&parts, options, false, None).await?, Answer::Refused(e))),
        },
    };
    let endpoint = make(&parts, options, true, None).await?;
    if options.udp == Udp::On {
        return Ok(opened(endpoint, Answer::BindOnly(addr)));
    }
    let started = tokio::time::Instant::now();
    let came_back = crate::probe::round_trip(&endpoint, crate::probe::REPORT_LIMIT).await == Some(true);
    let took = started.elapsed();
    if came_back {
        return Ok(opened(endpoint, Answer::Answered(took)));
    }
    // The same key for the endpoint that takes its place: a node's ticket,
    // and a client's allowlisted key, name it.
    let secret = endpoint.secret_key().clone();
    let _ = tokio::time::timeout(CLOSE_LIMIT, endpoint.close()).await;
    let endpoint = make(&parts, options, false, Some(secret)).await?;
    Ok(opened(endpoint, Answer::Unknown(took)))
}

/// One endpoint of `parts`, with UDP sockets (not required) or none, and
/// `secret` in place of the options' key.
async fn make(parts: &Parts, options: &Options, udp: bool, secret: Option<SecretKey>) -> Result<Endpoint, BindError> {
    // The HTTPS probe of the relays picks the home relay when no UDP path
    // exists, and it goes through the proxy; the captive portal check is
    // one more connection, plain HTTP, that a sandbox's proxy refuses.
    let mut report = NetReportConfig::default();
    report.https_probes = true;
    report.captive_portal_check = false;
    // The caller's provider, for QUIC and for the relay's TLS: one provider
    // in the binary.
    let mut builder = Endpoint::builder(presets::Empty)
        .crypto_provider(options.tls.provider().clone())
        .clear_address_lookup()
        .relay_mode(parts.mode.clone())
        .dns_resolver(DnsResolver::custom(crate::resolve::Chain::new(options.resolve.clone())))
        .ca_tls_config(parts.tls.clone())
        .net_report_config(report)
        // QUIC's settings, for the connections that it dials and that it
        // takes.
        .transport_config(parts.quic.clone())
        // iroh's own UDP sockets are required by default: a host that
        // refuses UDP would stop the endpoint. They come back below, not
        // required, for the probe.
        .clear_ip_transports();
    if let Some(url) = &parts.proxy {
        builder = builder.proxy_url(url.clone());
    }
    if udp {
        let optional = || BindOpts::default().set_is_required(false);
        for any in ["0.0.0.0:0", "[::]:0"] {
            builder = builder.bind_addr_with_opts(any, optional()).map_err(|e| BindError::Iroh(e.to_string()))?;
        }
    }
    if let Some(secret) = secret.or_else(|| options.secret.clone()) {
        builder = builder.secret_key(secret);
    }
    // The ALPN of lanes first (PodUtils/podssh@T-666): the accepting end
    // chooses, and a client of before offers the first alone.
    if options.accepts {
        builder = builder.alpns(vec![crate::ALPN_LANES.to_vec(), crate::ALPN.to_vec()]);
    }
    builder.bind().await.map_err(|e| BindError::Iroh(e.to_string()))
}

#[cfg(test)]
#[path = "endpoint_udp_tests.rs"]
mod udp_tests;

#[cfg(test)]
mod tests {
    use super::sendable;

    fn url(text: &str) -> url::Url {
        url::Url::parse(text).unwrap()
    }

    #[test]
    fn plain_credentials_and_none_go_to_the_proxy() {
        assert!(sendable(&url("http://127.0.0.1:3128")).is_ok());
        assert!(sendable(&url("http://user:Secret123@127.0.0.1:3128")).is_ok());
    }

    #[test]
    fn credentials_that_iroh_would_send_wrong_are_refused() {
        // An escape: iroh would send `p%40ss`, not `p@ss`.
        assert!(sendable(&url("http://user:p%40ss@127.0.0.1:3128")).is_err());
        // `a:~~~` is `YTp+fn4=` in base64, and `YTp-fn4=` in base64url.
        assert!(sendable(&url("http://a:~~~@127.0.0.1:3128")).is_err());
    }
}
