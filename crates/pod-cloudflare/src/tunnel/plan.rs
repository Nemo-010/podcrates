//! The plan of the legs: which legs to try, in which order, with which
//! limits; the credentials and the edge addresses that each leg needs.

use super::*;

pub(super) async fn resolve_credentials(
    host: &Host,
    credentials: &Credentials,
    service_url: &str,
    user_agent: &str,
) -> Result<(rpc::TunnelAuth, Uuid, Option<String>)> {
    match credentials {
        Credentials::Quick => {
            let tunnel = crate::quicktunnel::provision(
                host,
                service_url,
                crate::quicktunnel::AuthMode::Public,
                user_agent,
                Duration::from_secs(30),
                host.settings.provision_budget,
            )
            .await
            .context("provisioning quick tunnel")
            .map_err(|e| {
                // Issue 210: a 429 is a refusal for now (75), with the wait
                // in the error report.
                let class = match crate::quicktunnel::retry_of(&e) {
                    Some(r) if r.status == 429 => Class::TempFail,
                    _ => Class::Unavailable,
                };
                crate::fail::fault(class, e)
            })?;
            let secret = tunnel.secret_bytes().map_err(|e| anyhow::anyhow!(e)).context("the quick tunnel secret")?;
            let url = validate_quick_hostname(&tunnel.hostname)?;
            let tunnel_id = Uuid::parse_str(&tunnel.id).context("quick tunnel id is not a UUID")?;
            Ok((rpc::TunnelAuth { account_tag: tunnel.account_tag, tunnel_secret: secret }, tunnel_id, Some(url)))
        }
        Credentials::Token(token) => {
            let (auth, tunnel_id) = split_explicit(parse_token(token)?)?;
            Ok((auth, tunnel_id, None))
        }
        Credentials::File(path) => {
            let (auth, tunnel_id) = split_explicit(parse_credentials_file(path)?)?;
            Ok((auth, tunnel_id, None))
        }
        Credentials::Explicit { account_tag, tunnel_id, secret } => {
            Ok((rpc::TunnelAuth { account_tag: account_tag.clone(), tunnel_secret: secret.clone() }, *tunnel_id, None))
        }
    }
}

pub(super) fn split_explicit(credentials: Credentials) -> Result<(rpc::TunnelAuth, Uuid)> {
    match credentials {
        Credentials::Explicit { account_tag, tunnel_id, secret } => {
            Ok((rpc::TunnelAuth { account_tag, tunnel_secret: secret }, tunnel_id))
        }
        _ => bail!("expected explicit credentials"),
    }
}

/// Edge addresses for a direct dial on port 7844.
///
/// `PODNET_EDGE` overrides discovery with a comma-separated `host:port` list, the
/// way `cloudflared --edge` does. It exists for a self-hosted or pinned edge,
/// and it is also the only way to test the `auto` fallback deliberately: point
/// it at an address nothing answers on and direct must fail where discovery
/// would have succeeded.
/// One way to reach the edge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LegKind {
    /// QUIC on UDP 7844.
    QuicDirect,
    /// HTTP/2 on TCP 7844.
    H2Direct,
    /// QUIC inside a WARP MASQUE tunnel on TCP 443.
    QuicWarp,
    /// HTTP/2 to TCP 7844 in a WebSocket to a relay on TCP 443.
    H2Relay,
}

impl std::fmt::Display for LegKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            LegKind::QuicDirect => "quic",
            LegKind::H2Direct => "http2",
            LegKind::QuicWarp => "quic+warp",
            LegKind::H2Relay => "http2+relay",
        })
    }
}

/// The edge legs to try, in order, for a protocol and a transport.
pub fn leg_plan(protocol: Protocol, transport: Transport) -> Result<Vec<LegKind>> {
    use LegKind::*;
    Ok(match (transport, protocol) {
        (Transport::Direct, Protocol::Quic) => vec![QuicDirect],
        (Transport::Direct, Protocol::Http2) => vec![H2Direct],
        (Transport::Direct, Protocol::Auto) => vec![QuicDirect, H2Direct],
        (Transport::Warp, Protocol::Http2) => {
            bail!("the WARP transport carries QUIC only; use --protocol quic or auto")
        }
        (Transport::Warp, _) => vec![QuicWarp],
        (Transport::Auto, Protocol::Quic) => vec![QuicDirect, QuicWarp],
        (Transport::Auto, Protocol::Http2) => vec![H2Direct],
        (Transport::Auto, Protocol::Auto) => vec![QuicDirect, H2Direct, QuicWarp],
        (Transport::Relay, Protocol::Quic) => {
            bail!("the relay carries TCP only; use --protocol http2 or auto")
        }
        (Transport::Relay, _) => vec![H2Relay],
    })
}

pub(crate) use crate::services::edge_region_name;

/// With a proxy, `--protocol auto` does not try QUIC on UDP 7844: no proxy
/// carries UDP, so the packets go around the proxy or are lost. QUIC inside
/// WARP stays, because MASQUE runs on TCP 443 through the proxy. Gives the
/// plan and the line that says why.
pub fn plan_with_proxy(plan: Vec<LegKind>, protocol: Protocol, proxy: Option<&str>) -> (Vec<LegKind>, Option<String>) {
    let Some(proxy) = proxy else {
        return (plan, None);
    };
    if !plan.contains(&LegKind::QuicDirect) {
        return (plan, None);
    }
    // Issue 182: an explicit --protocol quic keeps the leg, with a word
    // that it does not use the proxy.
    if !matches!(protocol, Protocol::Auto) {
        return (
            plan,
            Some(format!(
                "a proxy is set ({proxy}); QUIC uses UDP 7844 and goes around the proxy, so it can fail here (--protocol http2 goes through the proxy)"
            )),
        );
    }
    let kept: Vec<LegKind> = plan.into_iter().filter(|k| *k != LegKind::QuicDirect).collect();
    (kept, Some(format!("a proxy is set ({proxy}); no proxy carries UDP, so podnet does not try QUIC on UDP 7844")))
}

/// Apply `PODNET_UDP` and the result of the UDP probe to the plan. `off`
/// removes QUIC on UDP 7844. With `probe`, a refused probe removes it; an
/// unknown or answered probe keeps the order. The probe runs only for
/// `--protocol auto`, so `egress` is `None` for an explicit protocol.
pub fn plan_with_udp(
    plan: Vec<LegKind>,
    udp: crate::udp::Choice,
    egress: Option<&crate::udp::Egress>,
) -> Result<(Vec<LegKind>, Option<String>)> {
    use crate::udp::{Choice, Egress};
    if !plan.contains(&LegKind::QuicDirect) {
        return Ok((plan, None));
    }
    let why = match (udp, egress) {
        (Choice::Off, _) => "PODNET_UDP=off".to_string(),
        (Choice::Probe, Some(Egress::Refused(detail))) => {
            format!("the UDP probe was refused ({detail})")
        }
        (Choice::Probe, Some(other)) => {
            tracing::debug!(result = other.name(), detail = other.detail(), "UDP probe");
            return Ok((plan, None));
        }
        _ => return Ok((plan, None)),
    };
    let kept: Vec<LegKind> = plan.into_iter().filter(|k| *k != LegKind::QuicDirect).collect();
    if kept.is_empty() {
        return Err(crate::fail::fault(
            Class::Config,
            anyhow::anyhow!("{why}, and the only leg is QUIC on UDP 7844: use --protocol auto or http2"),
        ));
    }
    Ok((kept, Some(format!("{why}: podnet does not try QUIC on UDP 7844"))))
}

/// The tries of the first registration of a leg.
pub(super) const REGISTER_TRIES: u32 = 3;

/// The shortest and the longest wait between two tries of a registration.
pub(super) const REGISTER_WAIT_MIN: Duration = Duration::from_secs(1);

pub(super) const REGISTER_WAIT_MAX: Duration = Duration::from_secs(5);

/// The budget of a leg whose one try has the budget `one_try`:
/// [`REGISTER_TRIES`] tries and the longest wait between two tries.
pub(super) const fn leg_budget(one_try: Duration) -> Duration {
    one_try.saturating_mul(REGISTER_TRIES).saturating_add(REGISTER_WAIT_MAX.saturating_mul(REGISTER_TRIES - 1))
}

/// The budget of one try of the QUIC leg on one edge address: the QUIC
/// handshake and the registration.
pub(super) const QUIC_TRY_BUDGET: Duration = quic_dial::HANDSHAKE_TIMEOUT.saturating_add(REGISTER_TIMEOUT);

/// The time limit of a leg attempt with `--leg-failover serial` when
/// another leg can follow (issue 273): the budget of the leg, from the
/// limits of its steps. A slow edge in these limits is not stopped. A try
/// over more than one edge address can take longer; the limit then stops
/// it, and the next leg starts. The WARP leg has no limit.
pub(super) fn attempt_limit(kind: LegKind) -> Option<Duration> {
    match kind {
        LegKind::QuicDirect => Some(leg_budget(QUIC_TRY_BUDGET)),
        LegKind::H2Direct | LegKind::H2Relay => Some(leg_budget(crate::edge_h2::TRY_BUDGET)),
        LegKind::QuicWarp => None,
    }
}

/// Run `attempt` again when the edge refuses the registration and asks for
/// a retry (`retry: yes`), at most [`REGISTER_TRIES`] times, after the wait
/// that it asks for (1 s to 5 s). A new quick tunnel can be "not found" at
/// the edge for a moment after its provision; before, the first refusal
/// ended the leg, and with one leg the start exited 69.
pub(super) async fn register_retrying<T, F, Fut>(mut attempt: F) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    let mut tries = 1;
    loop {
        let err = match attempt().await {
            Ok(value) => return Ok(value),
            Err(err) => err,
        };
        let refused = err.chain().find_map(|e| e.downcast_ref::<rpc::Refused>()).filter(|r| r.should_retry).cloned();
        match refused {
            Some(refused) if tries < REGISTER_TRIES => {
                let wait = refused.retry_after.clamp(REGISTER_WAIT_MIN, REGISTER_WAIT_MAX);
                info!(
                    cause = %refused.cause,
                    try_ = tries,
                    wait_s = wait.as_secs(),
                    "the edge refused the registration and asks for a retry; podnet tries again"
                );
                tokio::time::sleep(wait).await;
                tries += 1;
            }
            _ => return Err(err),
        }
    }
}

/// Give `attempt` the time limit `limit` (see [`attempt_limit`]). A
/// filtered port does not answer, so the next leg does not wait for the
/// end of each timeout of the transport.
pub(super) async fn bounded<T>(
    limit: Option<Duration>,
    attempt: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    let Some(limit) = limit else {
        return attempt.await;
    };
    match tokio::time::timeout(limit, attempt).await {
        Ok(result) => result,
        Err(_) => bail!("the attempt did not complete in {}s", limit.as_secs()),
    }
}

/// The edge list of the settings, which replaces edge discovery (as
/// `cloudflared --edge` does); `None` when it is not set or empty.
pub(crate) fn edge_override(settings: &crate::Settings) -> Option<Vec<edge::EdgeAddr>> {
    let list = settings.edge.as_ref()?;
    (!list.is_empty()).then(|| list.iter().map(|socket| edge::EdgeAddr::new(*socket)).collect())
}

/// The target of the UDP probe: the first address of the edge list of the
/// settings, else the probe address of the edge.
pub(super) fn probe_target(settings: &crate::Settings) -> std::net::SocketAddr {
    settings.edge.as_ref().and_then(|list| list.first().copied()).unwrap_or_else(crate::udp::default_probe_target)
}

pub(super) async fn direct_targets(host: &Host) -> Result<Vec<edge::EdgeAddr>> {
    if let Some(list) = edge_override(&host.settings) {
        return Ok(list);
    }
    let discovered = crate::edge_discovery::discover(host, IpVersionFilter::Auto).await.context("edge discovery")?;
    if discovered.is_empty() {
        bail!("edge discovery returned no addresses");
    }
    Ok(discovered)
}
