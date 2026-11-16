//! Whether the WebSocket upgrade to the relay is refused on the way: the
//! cue to try the carrier when the user did not ask for it. The relay's own
//! refusals are plain text
//! that starts with the word of their path, or the path (`reverse:
//! forbidden`, `/x: not found`; docs/relay.md, "Errors and close codes"), or
//! name a token; a proxy's are its own page, with a status of a refusal, or
//! a `426` of a relay that got the request with its `Upgrade` taken off on
//! the way. A connection that ends with no answer, or a gateway's `5xx`, is
//! no cue: a relay that went away looks the same, and the user asks for the
//! carrier there.
//!
//! [`upgrade`] asks the relay for a node's socket with no token: the relay
//! refuses it with its own word and changes nothing, so the probe costs one
//! request, at a node's start.

use std::time::Duration;

use pod_relay::relay::Relay;
use pod_tls::Trust;
use pod_ws::Way;
use pod_ws::client::ConnectError;

/// Whether a refusal of the upgrade is the way's (`pod_relay::way_refusal`).
pub use pod_relay::way_refusal::upgrade_refused;

/// What the probe found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Probe {
    /// The relay answered the upgrade itself.
    Passes,
    /// Something on the way refused it, with what it said.
    Refused(String),
    /// The relay was not reached, so the probe tells nothing of the upgrade.
    Unknown(String),
}

/// One upgrade of `/v1/node/<name>` at `relay`, with no token, through
/// `way`, within `limit` for each step.
pub async fn upgrade(relay: &Relay, name: &str, way: &Way, trust: &Trust, limit: Duration) -> Probe {
    if pod_core::names::check_node_name(name).is_err() {
        return Probe::Unknown("the pair's name is not one that the relay takes".into());
    }
    let tls = match way.open_tls(&relay.host, relay.port, &relay.host, trust, limit, &[]).await {
        Ok((tls, _)) => tls,
        Err(e) => return Probe::Unknown(e.to_string()),
    };
    let key = match pod_ws::handshake::generate_key() {
        Ok(key) => key,
        Err(e) => return Probe::Unknown(e.to_string()),
    };
    let host = match relay.port {
        443 => relay.host.clone(),
        port => pod_proxy::host::authority(&relay.host, port),
    };
    let request = request(&host, name, &key, &way.user_agent);
    match tokio::time::timeout(limit, pod_ws::client::upgrade_with(tls, &request, &key)).await {
        Err(_) => Probe::Unknown(format!("no answer to the upgrade within {} s", limit.as_secs())),
        Ok(Ok(_)) => Probe::Passes,
        Ok(Err(e)) if upgrade_refused(&e) => Probe::Refused(e.to_string()),
        // The relay's own refusal; a gateway's 5xx says that it was not reached.
        Ok(Err(ConnectError::Refused { status, .. })) if status < 500 => Probe::Passes,
        Ok(Err(e)) => Probe::Unknown(e.to_string()),
    }
}

/// The upgrade of a node's socket with no `X-Relay-Token`, with the user
/// agent `agent`, made one line.
fn request(host: &str, name: &str, key: &str, agent: &str) -> Vec<u8> {
    let agent = pod_core::text::one_line(agent);
    let mut out = format!("GET /v1/node/{name} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {agent}\r\n");
    out.push_str("Upgrade: websocket\r\nConnection: Upgrade\r\n");
    out.push_str(&format!("Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"));
    out.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refused(status: u16, body: &str) -> ConnectError {
        ConnectError::Refused { status, body: body.into() }
    }

    #[test]
    fn the_relay_s_own_refusals_are_not_the_way_s() {
        for (status, body) in [
            (403, "reverse: forbidden"),
            (403, "missing or wrong token"),
            (403, "trace: missing or wrong token"),
            (403, "connect: not in the ALLOW list"),
            (403, "forward: missing or wrong token"),
            (400, "connect: refused by fault injection"),
            (404, "Reverse: no such pair"),
            (405, "/v1/node/x: not found"),
        ] {
            assert!(!upgrade_refused(&refused(status, body)), "{status} {body}");
        }
    }

    #[test]
    fn a_proxy_s_page_and_a_426_are_the_way_s_and_a_drop_or_a_gateway_is_no_cue() {
        assert!(upgrade_refused(&refused(403, "Forbidden: WebSocket upgrades are not allowed by policy")));
        assert!(upgrade_refused(&refused(403, "Access denied by the egress proxy")));
        assert!(upgrade_refused(&refused(400, "Bad Request")));
        assert!(upgrade_refused(&refused(426, "connect: upgrade required")), "the Upgrade was taken off on the way");
        let dropped = "the relay closed the connection before answering the upgrade";
        assert!(!upgrade_refused(&ConnectError::Upgrade(dropped.into())), "a relay that went away looks the same");
        assert!(!upgrade_refused(&refused(502, "error code: 502")), "a gateway's failure");
        assert!(!upgrade_refused(&refused(503, "")));
        assert!(!upgrade_refused(&ConnectError::Tls("unknown issuer".into())));
        assert!(!upgrade_refused(&ConnectError::Http("x".into())));
    }

    #[test]
    fn the_probe_names_no_token() {
        let text = String::from_utf8(request("tcp.ssh.relay.ajam.dev", "abc", "dGhlIHNhbXBsZSBub25jZQ==", "podssh/1"))
            .unwrap();
        assert!(text.starts_with("GET /v1/node/abc HTTP/1.1\r\nHost: tcp.ssh.relay.ajam.dev\r\n"), "{text}");
        assert!(text.contains("\r\nUpgrade: websocket\r\n") && text.ends_with("\r\n\r\n"), "{text}");
        assert!(!text.to_ascii_lowercase().contains("token"), "a probe sends no credential");
    }
}
