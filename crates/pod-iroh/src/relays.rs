//! The relays of the iroh road (PodUtils/podssh@T-165): a table of defaults, in
//! order; the flag `--iroh-relay` and the variable [`ENV`], which replace it,
//! the flag first; and the failover: the first relay of the list that answers
//! `/ping`, through the caller's way out and with its trust store, is the home
//! relay. iroh itself would pick the relay with the least latency, in no order,
//! and could change it during a run, and with it a node's ticket.

use std::time::{Duration, Instant};

use iroh::RelayUrl;
use pod_core::Target;
use pod_proxy::{Cut, Missed, authority, http};
use pod_tls::Trust;
use pod_ws::Way;

/// The relays when nothing is set, in order: n0's public relays, as iroh
/// names them (`defaults::prod`: North America east and west, Europe, Asia
/// and Pacific), the endpoints of the role `relay` of `n0-iroh-relay`
/// (`pod-services`). A consumer puts its own relay first when it runs one.
pub fn default_urls() -> Vec<String> {
    let service = pod_services::get("n0-iroh-relay").expect("pod-services holds the service n0-iroh-relay");
    service.endpoints_of("relay").map(|e| e.url()).collect()
}

/// The variable of the consumer that replaces the table, as `--iroh-relay`
/// does: the consumer reads it and gives its value to [`select`].
pub const ENV: &str = "PODSSH_IROH_RELAY";

/// The bound on each relay's `/ping`, the connection included.
pub const PING_LIMIT: Duration = Duration::from_secs(5);

/// Where a list of relays came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Flag,
    Variable,
    Table,
}

/// The table, as URLs.
pub fn defaults() -> Vec<RelayUrl> {
    default_urls().iter().map(|text| parse_url(text).expect("each relay of the table is a relay URL")).collect()
}

/// One relay: `https://HOST[:PORT]`, where HOST is a name or an IPv4
/// address that [`pod_core::names::check_host`] takes. User information, a
/// path, a query and a fragment are refused: iroh puts its own path after
/// the origin.
pub fn parse_url(text: &str) -> Result<RelayUrl, String> {
    let url = url::Url::parse(text.trim()).map_err(|e| format!("{text:?} is not a URL: {e}"))?;
    if url.scheme() != "https" {
        return Err(format!("{text:?}: an iroh relay is reached over https:// only"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(format!("{text:?}: a relay URL takes no user name or password"));
    }
    if url.path() != "/" || url.query().is_some() || url.fragment().is_some() {
        return Err(format!("{text:?}: a relay URL is https://HOST[:PORT], with no path, query or fragment"));
    }
    let host = url.host_str().ok_or_else(|| format!("{text:?} names no host"))?;
    pod_core::names::check_host(host).map_err(|why| format!("{text:?}: {why}"))?;
    Ok(RelayUrl::from(url))
}

/// The relays of a list, `URL[,URL...]`, in order and once each.
pub fn parse_list(text: &str) -> Result<Vec<RelayUrl>, String> {
    let mut relays: Vec<RelayUrl> = Vec::new();
    for word in text.split(',').map(str::trim) {
        if word.is_empty() {
            return Err(format!("{text:?}: an empty relay in the list"));
        }
        let relay = parse_url(word)?;
        if !relays.contains(&relay) {
            relays.push(relay);
        }
    }
    Ok(relays)
}

/// The relays to use: the flag's, else the variable's (an empty variable is
/// none), else the table.
pub fn select(flag: Option<&str>, variable: Option<String>) -> Result<(Vec<RelayUrl>, Source), String> {
    if let Some(text) = flag {
        return parse_list(text).map(|list| (list, Source::Flag)).map_err(|why| format!("--iroh-relay: {why}"));
    }
    if let Some(text) = variable.filter(|v| !v.trim().is_empty()) {
        return parse_list(&text).map(|list| (list, Source::Variable)).map_err(|why| format!("{ENV}: {why}"));
    }
    Ok((defaults(), Source::Table))
}

/// A relay's answer to `/ping`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pong {
    pub elapsed: Duration,
    /// How the connection went: `directly`, or the proxy's `CONNECT` or
    /// `SOCKS5 CONNECT`.
    pub way: String,
}

/// `GET /ping` on `relay`, through `way`, with its certificate checked
/// against `trust`, within `limit`.
pub async fn ping(relay: &RelayUrl, trust: &Trust, way: &Way, limit: Duration) -> Result<Pong, String> {
    ping_kept(relay, trust, way, limit).await.map_err(|missed| missed.why)
}

/// [`ping`], with how the connection ended beside the words of a failure,
/// which a doctor counts (PodUtils/podssh@T-604): the dial's or the
/// handshake's cut, or the bound's; an answer of another status has none.
pub async fn ping_kept(relay: &RelayUrl, trust: &Trust, way: &Way, limit: Duration) -> Result<Pong, Missed> {
    let host = relay.host_str().ok_or_else(|| Missed::words(format!("{relay}: no host")))?;
    let port = relay.port_or_known_default().unwrap_or(443);
    let started = Instant::now();
    let how = through(way, host, port);
    let answer = async {
        let (mut tls, _) = way
            .open_tls(host, port, host, trust, limit, &[])
            .await
            .map_err(|e| Missed { why: format!("{host}: {e}"), cut: e.cut() })?;
        let host_header = if port == 443 { host.to_string() } else { authority(host, port) };
        http::exchange(&mut tls, &way.user_agent, "GET", &host_header, "/ping", &[], b"", 4096)
            .await
            .map_err(|e| Missed::words(format!("{host}: /ping: {e} ({how})")))
    };
    let response = tokio::time::timeout(limit, answer).await.map_err(|_| Missed {
        why: format!("{host}: /ping did not answer within {} s ({how})", limit.as_secs()),
        cut: Some(Cut::TimedOut),
    })??;
    if response.status != 200 {
        let why = format!("{host}: /ping answered HTTP {} {} ({how})", response.status, response.body_text(120));
        return Err(Missed::words(why));
    }
    Ok(Pong { elapsed: started.elapsed(), way: how })
}

/// How a connection to `host:port` goes through `way`, in words: `directly`,
/// or the proxy's `CONNECT` or `SOCKS5 CONNECT` (PodUtils/podssh@T-280).
fn through(way: &Way, host: &str, port: u16) -> String {
    match way.dial.proxy_label(&Target::new(host, port)) {
        None => "directly".to_string(),
        Some(proxy) => {
            let request = if proxy.starts_with("socks5") { "SOCKS5 CONNECT" } else { "CONNECT" };
            format!("{request} {} through {proxy}", authority(host, port))
        }
    }
}

/// The relays to give iroh: the first of `relays` that answers `/ping`
/// alone, as the home relay; else all of them, for iroh's own probes. With
/// the reason of each relay that did not answer before one did.
pub async fn home(relays: &[RelayUrl], trust: &Trust, way: &Way) -> (Vec<RelayUrl>, Vec<String>) {
    let mut missed = Vec::new();
    for relay in relays {
        match ping(relay, trust, way, PING_LIMIT).await {
            Ok(_) => return (vec![relay.clone()], missed),
            Err(why) => missed.push(why),
        }
    }
    (relays.to_vec(), missed)
}
