//! The readers of the wire that the fuzz targets of `fuzz/` call (feature
//! `fuzzing`): a message of the bridge, a data frame, an answer of the API
//! (a tunnel and the state of its certificate), a service's URL and a
//! node's name. No consumer turns it on.

use serde_json::Value;

use crate::Service;
use crate::api::{ApiError, Cert, Tunnel};
use crate::client::Name;
use crate::wire::{self, Down};

/// The server's message in `text`, as a bridge reads it.
pub fn message(text: &str) -> Result<Option<Down>, String> {
    wire::decode(text)
}

/// The connection and the bytes of a data frame.
pub fn frame(bytes: &[u8]) -> Option<(u32, &[u8])> {
    wire::split_frame(bytes)
}

/// The tunnel of an answer of the API, as `POST /api/tunnel` gives it.
pub fn tunnel(text: &str) -> Result<Tunnel, ApiError> {
    let value: Value = serde_json::from_str(text).map_err(|e| ApiError::Unreached(e.to_string()))?;
    crate::api::tunnel(&value)
}

/// The state of a certificate in an answer of the API.
pub fn cert(text: &str) -> Result<Cert, ApiError> {
    let value: Value = serde_json::from_str(text).map_err(|e| ApiError::Unreached(e.to_string()))?;
    crate::api::cert(&value)
}

/// A service's URL, as a user names one.
pub fn service(text: &str) -> Result<Service, String> {
    Service::parse(text)
}

/// A node's name, as a client takes it.
pub fn name(text: &str) -> Result<Name, String> {
    Name::parse(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_reader_takes_its_own_form() {
        let open = r#"{"type":"open","conn":7,"peer":"203.0.113.9:4000","sni":"r.abc.opentunnel.xyz","alpn":""}"#;
        assert!(matches!(message(open), Ok(Some(Down::Open { conn: 7, .. }))));
        assert_eq!(frame(&[0, 0, 0, 7, b'x']), Some((7, &b"x"[..])));
        let made = r#"{"id":"abcdefghijkl","hostname":"abcdefghijkl.opentunnel.xyz"}"#;
        assert_eq!(tunnel(made).map(|t| t.id).ok().as_deref(), Some("abcdefghijkl"));
        assert!(matches!(cert(r#"{"state":{"type":"issuing"}}"#), Ok(Cert::Issuing)));
        assert_eq!(service("https://opentunnel.xyz").map(|s| s.port), Ok(443));
        assert!(name("r7k2qmx4.abcdefghijkl.opentunnel.xyz").is_ok());
    }
}
