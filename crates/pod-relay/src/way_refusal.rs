//! Whether the WebSocket upgrade to the relay is refused on the way, not by
//! the relay: the cue to carry a session or a link of the layer on the HTTP
//! road (PodUtils/podssh#287), or a node on the carrier (`pod-piping`). The
//! relay's own refusals are plain text that starts with the word of their
//! path, or the path (`reverse: forbidden`, `/x: not found`), or name a
//! token; a proxy's are its own page, with a status of a refusal, or a
//! `426` of a relay that got the request with its `Upgrade` taken off on
//! the way. A connection that ends with no answer, or a gateway's `5xx`, is
//! no cue: a relay that went away looks the same.

use pod_ws::ConnectError;

/// The words that begin the relay's refusals.
const RELAY_WORDS: &[&str] = &[
    "reverse:", "connect:", "forward:", "relay:", "trace:", "mint:", "pair:", "status:", "stop:", "node:", "layer:",
    "http:",
];

/// Whether `e`, the end of a WebSocket upgrade to the relay, is a refusal on
/// the way rather than the relay's own.
pub fn upgrade_refused(e: &ConnectError) -> bool {
    match e {
        ConnectError::Refused { status: 426, .. } => true,
        ConnectError::Refused { status: 400 | 403 | 405 | 501, body } => !relay_word(body),
        _ => false,
    }
}

/// The relay's words: its path's word or the path first, a token, or its
/// list of the forward road's targets. A proxy's page may say "not allowed"
/// too, so that alone is not the relay's.
fn relay_word(body: &str) -> bool {
    let body = body.trim_start().to_ascii_lowercase();
    RELAY_WORDS.iter().any(|word| body.starts_with(word))
        || (body.starts_with('/') && body.contains(": "))
        || body.contains("token")
        || body.contains("allow list")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The tests of the words are in `pod-piping`'s probe, which takes
    /// this function; here, the two kinds once.
    #[test]
    fn a_proxy_s_page_is_the_way_s_and_the_relay_s_word_is_not() {
        let refused = |status, body: &str| ConnectError::Refused { status, body: body.into() };
        assert!(upgrade_refused(&refused(403, "Forbidden: WebSocket upgrades are not allowed by policy")));
        assert!(!upgrade_refused(&refused(403, "layer: missing or wrong token")));
    }
}
