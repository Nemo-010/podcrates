//! Provision an anonymous Cloudflare "quick tunnel", the way `cloudflared` does.
//!
//! # What this reproduces
//!
//! `cloudflared tunnel --url ...` calls `POST https://api.trycloudflare.com/tunnel`
//! with an empty body and **no credentials of any kind**. The response carries a
//! tunnel id, an account tag, a 32-byte secret (base64 in JSON) and the public
//! hostname. The request is plain HTTPS on port 443.
//!
//! References in the `cloudflared` source:
//!
//! * `cmd/cloudflared/tunnel/quick_tunnel.go` - `RunQuickTunnel` performs the
//!   POST; `QuickTunnelResponse` is the response shape.
//! * `cmd/cloudflared/tunnel/cmd.go` - `quick-service` defaults to
//!   `https://api.trycloudflare.com`.
//! * `quicktunnelauth` - when an email allow-list is requested the client sends
//!   `{"auth_mode":"otp"}` instead of an empty body. The allow-list itself never
//!   leaves the client; Cloudflare only learns that OTP is required.
//!
//! # What this does NOT do
//!
//! It does not open the tunnel edge connection. See [`crate::tunnel`].

mod error;
pub use error::*;

use std::sync::Arc;

use pod_core::{Class, Dial, Failure, Stage};
use serde::{Deserialize, Serialize};

use crate::Host;

mod retry;
pub use retry::parse_retry_after;

pub use crate::services::default_quick_service;

/// The anonymous provisioning response. Only the fields the crate uses are modelled;
/// cloudflared's `QuickTunnel` also carries `name`, which is unused here.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct QuickTunnel {
    /// Tunnel UUID.
    pub id: String,
    /// The public hostname, e.g. `foo-bar.trycloudflare.com`.
    pub hostname: String,
    /// Hex account tag the tunnel is billed/attributed to.
    pub account_tag: String,
    /// Base64-encoded 32-byte tunnel secret. Sent to the edge verbatim by
    /// cloudflared (`connection.Credentials.TunnelSecret`), not hashed.
    pub secret: String,
}

impl QuickTunnel {
    /// The public URL for this tunnel.
    pub fn url(&self) -> String {
        format!("https://{}", self.hostname)
    }

    /// The raw secret bytes, decoded from base64.
    ///
    /// This is the value cloudflared puts on the wire as `TunnelAuth.tunnelSecret`
    /// without any hashing step, so a reimplementation must not transform it.
    pub fn secret_bytes(&self) -> Result<Vec<u8>, Failure> {
        decode_base64(&self.secret).ok_or_else(|| {
            let text = format!("tunnel secret is not valid base64 ({} bytes of text)", self.secret.len());
            Failure::new(Stage::EdgeRegister, Class::Protocol, text)
        })
    }
}

/// Top-level envelope: `{"success":bool,"result":{...},"errors":[...]}`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct QuickTunnelResponse {
    pub success: bool,
    #[serde(default)]
    pub result: Option<QuickTunnel>,
    #[serde(default)]
    pub errors: Vec<QuickTunnelError>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct QuickTunnelError {
    #[serde(default)]
    pub code: i64,
    #[serde(default)]
    pub message: String,
}

/// How the tunnel should be authenticated for visitors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMode {
    /// Anyone with the URL can reach the origin. Empty request body.
    Public,
    /// Visitors must pass a one-time PIN before reaching the origin.
    /// Request body is `{"auth_mode":"otp"}`.
    ///
    /// Note that the allow-list is enforced by the *client*, exactly as
    /// `cloudflared --allowed-mail` does: Cloudflare is told only that OTP is
    /// required, never which addresses are acceptable.
    Otp,
}

impl AuthMode {
    /// The request body to POST. `None` means an empty body.
    pub fn request_body(self) -> Option<&'static str> {
        match self {
            AuthMode::Public => None,
            AuthMode::Otp => Some(r#"{"auth_mode":"otp"}"#),
        }
    }
}

/// Provision a quick tunnel: `POST <endpoint>/tunnel`, with the client of
/// `host`.
///
/// `via` is a way out for this request only. With `None`, the request
/// takes the way out of `host`.
pub async fn request_quick_tunnel(
    host: &Host,
    endpoint: &str,
    auth_mode: AuthMode,
    user_agent: &str,
    timeout: std::time::Duration,
    via: Option<Arc<dyn Dial>>,
) -> Result<QuickTunnel, Failure> {
    request_once(host, endpoint, auth_mode, user_agent, timeout, via).await.map_err(Failure::from)
}

/// One provision request; [`ProvisionError`] says what a retry can do.
async fn request_once(
    host: &Host,
    endpoint: &str,
    auth_mode: AuthMode,
    user_agent: &str,
    timeout: std::time::Duration,
    via: Option<Arc<dyn Dial>>,
) -> Result<QuickTunnel, ProvisionError> {
    let url = format!("{}/tunnel", endpoint.trim_end_matches('/'));
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err(ProvisionError::BadEndpoint(url));
    }
    let mut request = pod_proxy::client::Request::new("POST", url)
        .header("Content-Type", "application/json")
        .header("User-Agent", user_agent)
        .timeout(timeout)
        .via(via);
    request.body = auth_mode.request_body().map(Into::into);
    let response = host.send(request).await;
    let response = response.map_err(ProvisionError::Http)?;
    let status = response.status;
    let text = response.text();
    let retry_after = response.header("retry-after").and_then(parse_retry_after);
    match parse_quick_tunnel_response(status, &text) {
        Err(ProvisionError::Status { code, body, .. }) => Err(ProvisionError::Status { code, body, retry_after }),
        other => other,
    }
}

/// The longest time that [`provision`] tries.
pub const PROVISION_BUDGET: std::time::Duration = std::time::Duration::from_secs(300);
/// The most attempts of [`provision`].
pub const PROVISION_ATTEMPTS: u32 = 5;

/// [`request_quick_tunnel`] with retries: a 429, a 5xx and a transport
/// error are tried again, after `Retry-After` or else a backoff with jitter
/// (2, 4, 8, 16 s), up to [`PROVISION_ATTEMPTS`] attempts in `budget`.
/// Another 4xx fails at once. A `Retry-After` that is longer than the time
/// left fails with the wait in the error.
pub async fn provision(
    host: &Host,
    endpoint: &str,
    auth_mode: AuthMode,
    user_agent: &str,
    timeout: std::time::Duration,
    budget: std::time::Duration,
) -> Result<QuickTunnel, Failure> {
    let start = std::time::Instant::now();
    let policy = crate::config::ReconnectPolicy {
        initial: std::time::Duration::from_secs(2),
        max: std::time::Duration::from_secs(16),
        ..Default::default()
    };
    let mut attempt = 0;
    let mut dns = retry::Dns::default();
    loop {
        attempt += 1;
        let err = match request_once(host, endpoint, auth_mode, user_agent, timeout, None).await {
            Ok(tunnel) => return Ok(tunnel),
            Err(err) => err,
        };
        let wait = match &err {
            ProvisionError::Status { code, retry_after, .. } if *code == 429 || (500..600).contains(code) => {
                retry_after.unwrap_or_else(|| policy.backoff_with_jitter(attempt))
            }
            // A refusal of the proxy and a TLS failure do not change on a
            // retry.
            ProvisionError::Http(inner)
                if matches!(crate::fail::stage_of(inner), Some(Stage::Proxy | Stage::Tls | Stage::Network)) =>
            {
                return Err(err.into());
            }
            // A name that does not resolve: one retry, then only when the
            // answering step changed (T-170).
            ProvisionError::Http(inner) if retry::is_dns(inner) => {
                if !dns.again(host, endpoint).await {
                    return Err(err.into());
                }
                policy.backoff_with_jitter(attempt)
            }
            ProvisionError::Http(_) => policy.backoff_with_jitter(attempt),
            _ => return Err(err.into()),
        };
        let left = budget.saturating_sub(start.elapsed());
        if attempt >= PROVISION_ATTEMPTS || wait > left {
            if wait > left {
                tracing::warn!(
                    "the quick-tunnel service asks to wait {} s, more than the {} s left",
                    wait.as_secs(),
                    left.as_secs()
                );
            }
            return Err(err.into());
        }
        tracing::warn!(attempt, retry_in = ?wait, "provisioning failed: {err}; trying again");
        tokio::time::sleep(wait).await;
    }
}

/// The public host of a quick-tunnel URL, validated against the
/// `*.trycloudflare.com` allowlist so a hostile API response cannot point the
/// tool at another host.
pub fn validate_quick_hostname(raw: &str) -> Result<String, Failure> {
    let refuse = |text: String| Failure::new(Stage::EdgeRegister, Class::Protocol, text);
    let host = raw
        .trim()
        .trim_end_matches('/')
        .strip_prefix("https://")
        .unwrap_or(raw.trim().trim_end_matches('/'))
        .to_ascii_lowercase();
    let bad = host.is_empty() || host.contains(['/', '\\', '@', '?', '#', ':', '[', ']', ' ']);
    if bad {
        return Err(refuse(format!("quick tunnel returned a malformed hostname: {raw:?}")));
    }
    let zone = crate::services::text(crate::services::QUICK, "tunnel-zone");
    let Some(sub) = host.strip_suffix(&format!(".{zone}")) else {
        return Err(refuse(format!("quick tunnel hostname is not under {zone}: {host}")));
    };
    if sub.is_empty()
        || sub.contains('.')
        || sub.starts_with('-')
        || sub.ends_with('-')
        || sub.len() > 63
        || !sub.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(refuse(format!("quick tunnel hostname label is invalid: {host}")));
    }
    Ok(format!("https://{host}"))
}

/// Parse and validate a provisioning response body.
///
/// Split out from [`request_quick_tunnel`] so it can be tested against captured
/// real responses without a live service.
pub(crate) fn parse_quick_tunnel_response(status: u16, body: &str) -> Result<QuickTunnel, ProvisionError> {
    if !(200..300).contains(&status) {
        // The body of an error, for a terminal: 1 KiB at most, with no
        // control characters.
        let mut clipped = crate::text::clean(body.trim());
        if clipped.len() > 1024 {
            let mut cut = 1024;
            while !clipped.is_char_boundary(cut) {
                cut -= 1;
            }
            clipped.truncate(cut);
        }
        return Err(ProvisionError::Status { code: status, body: clipped, retry_after: None });
    }

    // The provisioning body carries the tunnel's `secret`, `account_tag` and `id`,
    // which are the credentials the edge expects at registration. A decode
    // failure therefore has a body that is mostly credentials, and this error
    // reaches the operator's stderr and any CI log. Redact before including any
    // of it.
    let parsed: QuickTunnelResponse =
        serde_json::from_str(body).map_err(|e| ProvisionError::Decode(format!("{e}; body was: {}", redact(body))))?;

    if !parsed.success {
        return Err(ProvisionError::Service(parsed.errors));
    }

    parsed.result.ok_or(ProvisionError::MissingResult)
}

/// Replace the credential-bearing fields of a provisioning body with a marker,
/// then clip it to something readable.
///
/// A provisioning response is mostly secret: `secret` is a 32-byte base64 blob
/// and `account_tag` identifies the account, and both are what the edge expects
/// at registration. Including the body in an error is useful for debugging a
/// malformed response, but including the credentials in a log is a leak its
/// readers cannot see. So the values are replaced rather than the whole body
/// dropped, which keeps the diagnostic and loses nothing that matters.
fn redact(body: &str) -> String {
    const REDACTED: &str = "<redacted>";
    let mut out = String::with_capacity(body.len());
    // One pass over the body, checking each key at every position. The keys are
    // few and the body is short, so matching repeatedly per key would work too,
    // but a single cursor cannot get the boundaries wrong: `copied` is always
    // bytes the scan has already accepted.
    let keys: [&str; 4] = ["secret", "account_tag", "tunnel_secret", "id"];
    let mut i = 0;
    while i < body.len() {
        let mut matched: Option<&str> = None;
        for key in keys {
            let needle = format!("\"{key}\"");
            if body[i..].starts_with(&needle) {
                matched = Some(key);
                break;
            }
        }
        let Some(key) = matched else {
            let ch = body[i..].chars().next().expect("i is a boundary");
            out.push(ch);
            i += ch.len_utf8();
            continue;
        };
        // Copy the key and its colon, then replace the value in quotes.
        let needle_len = key.len() + 2;
        let after_key = i + needle_len;
        let Some(colon) = body[after_key..].find(':') else {
            break;
        };
        let after_colon = after_key + colon + 1;
        let Some(open) = body[after_colon..].find('"').map(|p| after_colon + p + 1) else {
            break;
        };
        let Some(close) = body[open + 1..].find('"').map(|p| open + 1 + p) else {
            break;
        };
        out.push_str(&body[i..open + 1]);
        out.push_str(REDACTED);
        i = close + 1;
    }
    truncate(&out, 200)
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        // Clip on a character boundary: a raw byte cut can land inside a
        // multi-byte character and panic on the next slice.
        let mut cut = n;
        while cut > 0 && !s.is_char_boundary(cut) {
            cut -= 1;
        }
        format!("{}...", &s[..cut])
    }
}

/// Minimal standard base64 decoder for the tunnel secret.
///
/// Hand-rolled rather than pulling in a dependency: the secret is standard
/// base64 with padding, and this keeps the dependency list small.
fn decode_base64(input: &str) -> Option<Vec<u8>> {
    fn value(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }

    let bytes: Vec<u8> = input.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;

    for &b in &bytes {
        if b == b'=' {
            break;
        }
        let v = value(b)?;
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xFF) as u8);
        }
    }

    if out.is_empty() { None } else { Some(out) }
}

#[cfg(test)]
mod tests;
