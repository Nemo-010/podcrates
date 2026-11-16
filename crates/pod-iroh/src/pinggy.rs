//! The form of a node's Pinggy address, as a node's record of pkarr names it
//! (PodUtils/podssh@T-548): `NAME#SHA256:PIN`, the name of the node's
//! tunnel and the pin of its TLS key. The Pinggy road itself (its client,
//! its node, its TLS) is the consumer's: this crate checks the form of the
//! text alone, so that a record carries no value that the road would refuse,
//! and writes it back as podssh's road reads it (`pinggy::Address::parse`
//! of podssh-relay). The form is a format of the wire of podssh's nodes, so
//! it stays: a pin in OpenSSH's form, not `pod_tls::mutual::Pin`'s
//! `sha256/` form.

use base64::Engine as _;
use sha2::Digest as _;

/// The word before a pin's digest, as OpenSSH names a key's.
pub const PIN_PREFIX: &str = "SHA256:";

/// The SHA-256 of a certificate's SubjectPublicKeyInfo, whole.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Pin([u8; 32]);

impl Pin {
    /// The pin of a SubjectPublicKeyInfo's DER.
    pub fn of_spki(spki: &[u8]) -> Pin {
        Pin(sha2::Sha256::digest(spki).into())
    }

    /// `SHA256:` and 43 characters of base64, with or without its `=`.
    pub fn parse(text: &str) -> Result<Pin, String> {
        let bad = || format!("a pin is {PIN_PREFIX} and the 43 characters of base64 that the node says");
        let digest = text.trim().strip_prefix(PIN_PREFIX).ok_or_else(bad)?.trim_end_matches('=');
        let bytes = base64::engine::general_purpose::STANDARD_NO_PAD.decode(digest).map_err(|_| bad())?;
        Ok(Pin(bytes.try_into().map_err(|_| bad())?))
    }

    /// The 32 bytes of the digest.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Display for Pin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{PIN_PREFIX}{}", base64::engine::general_purpose::STANDARD_NO_PAD.encode(self.0))
    }
}

impl std::fmt::Debug for Pin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

/// A node's name at Pinggy and the pin of its certificate's key:
/// `NAME#SHA256:...`. A name with no pin is no address: TLS would then
/// prove nothing.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Address {
    /// The tunnel's name, a DNS name in lower case.
    pub name: String,
    pub pin: Pin,
}

impl Address {
    /// `NAME#PIN`. The name is a DNS name ([`is_name`]); case does not
    /// matter, and a scheme, a path or the port 443 is taken off, as a node
    /// may say its tunnel's address with them. The refusal says which half
    /// is wrong, never with its text.
    pub fn parse(text: &str) -> Result<Address, String> {
        let Some((name, pin)) = text.trim().split_once('#') else {
            return Err(format!(
                "a node's address at Pinggy is NAME#{PIN_PREFIX}..., as the node's line names it: the pin of the \
                 node's certificate goes with its tunnel's name"
            ));
        };
        Ok(Address { name: name_of(name)?, pin: Pin::parse(pin)? })
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}#{}", self.name, self.pin)
    }
}

/// The tunnel's name of `text`: `SCHEME://HOST[:443][/...]` or `HOST[:443]`,
/// in lower case, when it is a DNS name.
fn name_of(text: &str) -> Result<String, String> {
    let bad = || "a node's name at Pinggy is its tunnel's name, as the node says it".to_string();
    let rest = text.trim().split_once("://").map_or(text.trim(), |(_, rest)| rest);
    let authority = rest.split(['/', '?']).next().unwrap_or_default();
    let host = match authority.rsplit_once(':') {
        Some((host, "443")) => host,
        Some(_) => return Err(bad()),
        None => authority,
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if is_name(&host) { Ok(host) } else { Err(bad()) }
}

/// A DNS name of two labels or more, each of 1 to 63 of `[a-z0-9-]` that
/// neither begins nor ends with `-`, the last one not all digits.
pub fn is_name(text: &str) -> bool {
    let labels: Vec<&str> = text.split('.').collect();
    let label_ok = |label: &&str| {
        !label.is_empty()
            && label.len() <= 63
            && label.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    };
    let top_ok = labels.last().is_some_and(|top| !top.bytes().all(|b| b.is_ascii_digit()));
    text.len() <= 253 && labels.len() >= 2 && labels.iter().all(label_ok) && top_ok
}
