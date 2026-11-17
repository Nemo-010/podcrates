//! The HTTP/2 edge transport.
//!
//! # Why this is the important one
//!
//! The Cloudflare edge accepts the tunnel protocol on two transports. QUIC
//! (ALPN `argotunnel`) is the default and the faster, but it needs UDP. HTTP/2
//! is TCP, and TCP is reachable in places UDP is not: through an HTTP CONNECT
//! proxy, through an SSH relay, and on any network that blocks or drops
//! outbound UDP. So a client that only speaks QUIC works on a normal host and
//! fails silently in exactly the constrained environments where a tunnel is
//! most useful.
//!
//! # The handshake, which is not the usual one
//!
//! Normally a client offers `h2` in ALPN and speaks HTTP/2 as the client. This
//! transport does neither:
//!
//! * **SNI is `h2.cftunnel.com`** while the connection is opened to an IP from
//!   the SRV record, so TLS must be configured with that name and the address
//!   taken separately.
//! * **No ALPN is offered at all.** cloudflared omits the extension and then
//!   runs an HTTP/2 *server* on the connection, because the edge initiates every
//!   stream. Offering `h2` changes the handshake and breaks it.
//! * **The edge opens the control stream**, identified by a request header
//!   `Cf-Cloudflared-Proxy-Connection-Upgrade: control-stream`. There is no
//!   client-initiated registration call; the client answers the request.
//!
//! Getting any one of those wrong produces a connection that opens and then
//! does nothing, which is why each is asserted in the tests here.

use std::sync::Arc;

/// The header that marks a stream as the control stream rather than a visitor.
pub const CONTROL_STREAM_HEADER: &str = "Cf-Cloudflared-Proxy-Connection-Upgrade";

/// The value that header carries for the control stream.
pub const CONTROL_STREAM_VALUE: &str = "control-stream";

/// Header carrying the visitor's origin destination.
pub const PROXY_SRC_HEADER: &str = "Cf-Cloudflared-Proxy-Src";

/// Headers are encoded as base64 of the name, then base64 of the value, joined
/// by `;` and repeated after a colon. That is not a conventional format; it is
/// what `connection/header.go` does.
///
/// Only the response direction uses it. `RequestUserHeaders` is defined in
/// header.go and referenced nowhere else upstream, because the edge sends the
/// visitor request as ordinary HTTP/2 headers; only an origin response has to
/// be serialized, so that HTTP/2 header validation is not applied to values
/// that came from an HTTP/1 origin.
pub const RESPONSE_HEADERS_HEADER: &str = "cf-cloudflared-response-headers";
pub const RESPONSE_META_HEADER: &str = "cf-cloudflared-response-meta";

/// Base64 alphabet, standard encoding.
const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encode bytes as standard base64 with no padding.
///
/// `connection/header.go` uses `base64.RawStdEncoding`: the standard alphabet
/// with the `=` padding omitted. Emitting padding here produces a value the
/// edge's decoder rejects.
pub fn base64_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(B64[((n >> 18) & 63) as usize] as char);
        out.push(B64[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(B64[((n >> 6) & 63) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(B64[(n & 63) as usize] as char);
        }
    }
    out
}

/// Decode standard base64, ignoring whitespace.
pub fn base64_decode(input: &str) -> Option<Vec<u8>> {
    fn value(c: u8) -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => u32::from(c - b'A'),
            b'a'..=b'z' => u32::from(c - b'a') + 26,
            b'0'..=b'9' => u32::from(c - b'0') + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        })
    }

    let bytes: Vec<u8> = input.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0;
    for b in &bytes {
        if *b == b'=' {
            break;
        }
        let v = value(*b)?;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xFF) as u8);
        }
    }
    Some(out)
}

/// Encode a header list the way `connection/header.go` does.
///
/// Each header becomes `base64(name):base64(value)`, separated by `;`, with no
/// trailing separator. The base64 layer is what lets arbitrary header bytes
/// survive an HTTP header value.
pub fn encode_headers(headers: &[(String, String)]) -> String {
    let mut out = String::new();
    for (name, value) in headers {
        if !out.is_empty() {
            out.push(';');
        }
        out.push_str(&base64_encode(canonical_header_name(name).as_bytes()));
        out.push(':');
        out.push_str(&base64_encode(value.as_bytes()));
    }
    out
}

/// Canonicalize a header name the way Go's `textproto.CanonicalMIMEHeaderKey` does.
///
/// The edge's Go code reads headers into a map, which canonicalizes every name
/// before it is written back, so the serialized form carries `Content-Type`
/// rather than `content-type`. Names are case-insensitive on the wire
/// (RFC 9110 section 5.1) so this is cosmetic rather than a correctness
/// requirement, but matching the reference keeps the encoding verifiable.
pub fn canonical_header_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut capitalize = true;
    for ch in name.chars() {
        if ch == '-' {
            out.push('-');
            capitalize = true;
            continue;
        }
        // A name with anything other than token characters is left alone,
        // exactly as Go does: canonicalization stops at the first byte that is
        // not a letter, digit or dash.
        if !(ch.is_ascii_alphanumeric() || ch == '-') {
            return name.to_string();
        }
        if capitalize {
            out.extend(ch.to_uppercase());
            capitalize = false;
        } else {
            out.extend(ch.to_lowercase());
        }
    }
    out
}

/// Decode the format produced by [`encode_headers`].
pub fn decode_headers(encoded: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for entry in encoded.split(';') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let Some((name, value)) = entry.split_once(':') else {
            continue;
        };
        let (Some(name), Some(value)) = (base64_decode(name), base64_decode(value)) else {
            continue;
        };
        if let (Ok(n), Ok(v)) = (String::from_utf8(name), String::from_utf8(value)) {
            out.push((n, v));
        }
    }
    out
}

/// Classify a stream the edge opened, from its headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamKind {
    /// The registration and configuration stream.
    Control,
    /// A visitor's request to the origin.
    Visitor { address: String, port: u32 },
    /// A configuration push from the edge.
    Configuration,
    /// Something this client does not implement.
    Unknown,
}

/// Decide what a stream is for.
///
/// The order matters: a configuration push is checked before the visitor case,
/// because an update-configuration request can also carry a proxy-source
/// header and would otherwise be misrouted to an origin.
pub fn classify_stream(headers: &[(String, String)]) -> StreamKind {
    let get = |name: &str| headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.clone());

    match get(CONTROL_STREAM_HEADER).as_deref() {
        Some("update-configuration") => return StreamKind::Configuration,
        Some(CONTROL_STREAM_VALUE) => return StreamKind::Control,
        _ => {}
    }

    if let Some(src) = get(PROXY_SRC_HEADER).filter(|s| !s.is_empty()) {
        // The value is `host:port`.
        let (address, port) =
            src.rsplit_once(':').map(|(h, p)| (h.to_string(), p.parse().unwrap_or(0))).unwrap_or((src, 0));
        return StreamKind::Visitor { address, port };
    }

    StreamKind::Visitor { address: String::new(), port: 0 }
}

/// The TLS configuration for the HTTP/2 edge transport.
///
/// `alpn` must be empty. cloudflared does not offer ALPN on this path, and
/// offering `h2` changes the handshake.
pub fn edge_tls(tls: &pod_tls::Context) -> Result<Arc<rustls::ClientConfig>, pod_core::Failure> {
    super::edge_tls_config(tls, &[])
}

/// Build the visitor request to send to an origin.
///
/// The edge hands over the visitor's request with its headers as ordinary
/// HTTP/2 headers, so they are forwarded as they arrive. Only two classes are
/// dropped: the `cf-` families, which describe the edge connection rather than
/// the message, and the hop-by-hop headers, which HTTP/2 forbids on a stream
/// (RFC 9113 section 8.2.2).
///
pub fn build_visitor_request(
    method: &str,
    path: &str,
    authority: &str,
    headers: &[(String, String)],
) -> http::Request<()> {
    // The edge replays these to the origin, so control headers and the
    // hop-by-hop ones are dropped rather than forwarded.
    let replayed: Vec<(String, String)> =
        headers.iter().filter(|(name, _)| !is_control_header(name) && !is_hop_by_hop(name)).cloned().collect();

    // Build the request so that one bad header costs only that header.
    //
    // The original chained every header onto one `Request::builder` and, on
    // failure, replaced the entire request with `http::Request::new(())`, which
    // is a bare GET to `/` with no headers: one bad header turned any request
    // into a GET of the root. Not chaining is not enough either, because a
    // poisoned builder rejects everything after it and still fails at `body()`.
    // So the head is built first and each header is validated on its own, and the
    // invalid ones are dropped individually, which is what an intermediary does.
    let mut head = match http::Request::builder().method(method).uri(path).header("host", authority).body(()) {
        Ok(request) => request,
        Err(e) => {
            // Only the method and the URI can fail here, and both come from the
            // edge. Reporting beats forwarding something else.
            tracing::warn!(error = %e, "could not build the visitor request");
            return http::Request::new(());
        }
    };

    // Append rather than replace, so the host set above survives.
    for (name, value) in &replayed {
        match (http::header::HeaderName::try_from(name.as_str()), http::HeaderValue::try_from(value.as_str())) {
            (Ok(name), Ok(value)) => {
                head.headers_mut().append(name, value);
            }
            _ => {
                tracing::warn!(header = name, "dropped a header the HTTP/2 layer refused");
            }
        }
    }
    head
}

/// Headers that describe one hop rather than the message.
///
/// RFC 9110 section 7.6.1, plus the two the edge handles itself. Sending any of
/// these on an HTTP/2 stream makes the origin or the edge act on a connection
/// that does not exist.
pub fn build_origin_response(status: u16, headers: &[(String, String)]) -> (u16, Vec<(String, String)>) {
    let mut real: Vec<(String, String)> = Vec::with_capacity(headers.len());
    let mut serialized: Vec<(String, String)> = Vec::new();

    for (name, value) in headers {
        let lower = name.to_ascii_lowercase();
        if lower == "content-length" {
            // Meaningful in HTTP/2 and used by the edge, so it goes on the
            // wire as well as inside the serialized blob.
            real.push((lower.clone(), value.clone()));
        }
        if !is_control_header(&lower) && !is_hop_by_hop(&lower) {
            // Hop-by-hop headers are dropped here for the same reason they are
            // dropped on the request path: they describe one connection, and the
            // edge is framing the body itself. Replaying an origin's
            // `Transfer-Encoding: chunked` next to the edge's own HTTP/2 framing
            // gives the visitor two disagreeing answers about where the body
            // ends, which is the shape of a response-splitting bug.
            //
            // The serialized blob is validated by neither HTTP/2 nor the origin,
            // so skipping validation is the reason the value is serialized at
            // all. That is not a reason to replay a connection-scoped header.
            serialized.push((name.clone(), value.clone()));
        }
    }

    real.push((RESPONSE_HEADERS_HEADER.to_string(), encode_headers(&serialized)));
    // The edge records who answered. "origin" says the origin served it.
    real.push((RESPONSE_META_HEADER.to_string(), r#"{"src":"origin"}"#.to_string()));

    // HTTP/2 has no 101 (RFC 9113 section 8.1.1); the edge expects 200.
    let status = if status == 101 { 200 } else { status };
    (status, real)
}

/// Decode the serialized response headers off an origin response.
///
/// A malformed entry is skipped rather than failing the response: one bad
/// header should not cost the visitor the whole page.
pub fn decode_origin_response(headers: &[(String, String)]) -> Vec<(String, String)> {
    let get = |want: &str| headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(want)).map(|(_, v)| v.clone());
    match get(RESPONSE_HEADERS_HEADER) {
        Some(encoded) => decode_headers(&encoded),
        None => headers.iter().filter(|(k, _)| !is_control_header(k)).cloned().collect(),
    }
}

/// Whether the response meta header says an origin answered, rather than
/// cloudflared serving the error itself.
pub fn served_by_origin(headers: &[(String, String)]) -> bool {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(RESPONSE_META_HEADER))
        .map(|(_, v)| v.contains(r#""src":"origin""#))
        .unwrap_or(false)
}

/// Headers that describe one hop rather than the message.
///
/// RFC 9110 section 7.6.1. Sending any of these on an HTTP/2 stream makes the
/// origin or the edge act on a connection that does not exist.
pub fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

/// The header names that the `Connection` values in `values` list (RFC
/// 9110 section 7.6.1), in lower case. These headers are also hop-by-hop.
/// The tokens `close`, `keep-alive` and `upgrade` are ignored, and the
/// framing headers `host`, `content-length` and `transfer-encoding` are
/// never named.
pub fn connection_named<'a>(values: impl IntoIterator<Item = &'a str>) -> Vec<String> {
    values
        .into_iter()
        .flat_map(|value| value.split(','))
        .map(|token| token.trim().to_ascii_lowercase())
        .filter(|token| {
            !token.is_empty()
                && !matches!(
                    token.as_str(),
                    "close" | "keep-alive" | "upgrade" | "host" | "content-length" | "transfer-encoding"
                )
        })
        .collect()
}

/// Which headers belong to the visitor rather than to the edge connection.
///
/// Anything with a `:` prefix is HTTP/2 pseudo-headers, and the `cf-` families
/// are Cloudflare's own bookkeeping; forwarding either confuses the origin.
pub fn is_control_header(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.starts_with(':')
        || lower.starts_with("cf-int-")
        || lower.starts_with("cf-cloudflared-")
        || lower.starts_with("cf-proxy-")
}

#[cfg(test)]
mod protocol_tests;
#[cfg(test)]
mod tests;
