//! The HTTP/2 edge transport.
//!
//! # Why this transport is necessary
//!
//! The Cloudflare edge accepts the tunnel protocol on two transports. QUIC
//! (ALPN `argotunnel`) is the default and the faster transport, but it needs
//! UDP. HTTP/2 uses TCP. TCP gets through where UDP does not: through an HTTP
//! CONNECT proxy, through an SSH relay, and on each network that blocks or
//! drops outbound UDP. A client with QUIC only works on a normal host. It
//! fails with no message in the restricted environments where a tunnel is
//! most necessary.
//!
//! # The handshake is not the usual one
//!
//! Usually a client offers `h2` in ALPN and speaks HTTP/2 as the client. This
//! transport does neither:
//!
//! * **SNI is `h2.cftunnel.com`**, and the connection goes to an IP from the
//!   SRV record. Thus TLS gets that name and the address separately.
//! * **The client offers no ALPN.** cloudflared omits the extension. It then
//!   runs an HTTP/2 *server* on the connection, because the edge opens each
//!   stream. An offer of `h2` changes the handshake and breaks it.
//! * **The edge opens the control stream.** The request header
//!   `Cf-Cloudflared-Proxy-Connection-Upgrade: control-stream` identifies it.
//!   The client sends no registration call of its own; it answers the request.
//!
//! An error in one of these items gives a connection that opens and then does
//! nothing. Thus the tests here check each item.

use std::sync::Arc;

/// The header that marks a stream as the control stream, not a visitor.
pub const CONTROL_STREAM_HEADER: &str = "Cf-Cloudflared-Proxy-Connection-Upgrade";

/// The value of that header on the control stream.
pub const CONTROL_STREAM_VALUE: &str = "control-stream";

/// The header with the origin destination of the visitor.
pub const PROXY_SRC_HEADER: &str = "Cf-Cloudflared-Proxy-Src";

/// The header with the serialized headers of an origin response. Each header
/// is the base64 of the name, a colon, and the base64 of the value. A `;`
/// joins the headers. This format is not a standard; it is the format of
/// `connection/header.go`.
///
/// Only the response direction uses it. header.go defines
/// `RequestUserHeaders`, but no other upstream file uses it: the edge sends
/// the visitor request as usual HTTP/2 headers. Only an origin response is
/// serialized, so that the HTTP/2 header checks do not apply to values from
/// an HTTP/1 origin.
pub const RESPONSE_HEADERS_HEADER: &str = "cf-cloudflared-response-headers";
pub const RESPONSE_META_HEADER: &str = "cf-cloudflared-response-meta";

/// The base64 alphabet of the standard encoding.
const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encode bytes as standard base64 with no padding.
///
/// `connection/header.go` uses `base64.RawStdEncoding`: the standard alphabet
/// with no `=` padding. The decoder of the edge refuses a value with padding.
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

/// Decode standard base64. Whitespace is ignored.
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
/// Each header becomes `base64(name):base64(value)`. A `;` separates two
/// headers; no separator follows the last header. The base64 layer lets each
/// byte of a header go through an HTTP header value unchanged.
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

/// Canonicalize a header name as Go's `textproto.CanonicalMIMEHeaderKey` does.
///
/// The Go code of the edge reads headers into a map. The map canonicalizes
/// each name before the write, so the serialized form has `Content-Type`,
/// not `content-type`. On the wire, names are not case-sensitive (RFC 9110
/// section 5.1). Thus this change is only cosmetic. But the same output as
/// the reference lets a test verify the encoding.
pub fn canonical_header_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut capitalize = true;
    for ch in name.chars() {
        if ch == '-' {
            out.push('-');
            capitalize = true;
            continue;
        }
        // Go keeps a name with a character that is not a token character:
        // canonicalization stops at the first byte that is not a letter, a
        // digit or a dash. Do the same.
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

/// The kind of a stream that the edge opened, from its headers.
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
/// The order is important. The check of a configuration push comes before the
/// visitor case. An update-configuration request can also have a proxy-source
/// header, and the visitor case would then send it to an origin.
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
/// `alpn` must be empty. cloudflared offers no ALPN on this path. An offer of
/// `h2` changes the handshake.
pub fn edge_tls(tls: &pod_tls::Context) -> Result<Arc<rustls::ClientConfig>, pod_core::Failure> {
    super::edge_tls_config(tls, &[])
}

/// Build the visitor request to send to an origin.
///
/// The edge gives the request of the visitor with its headers as usual HTTP/2
/// headers. Thus the headers go to the origin as they arrive. Only two
/// classes are dropped. The `cf-` families tell about the edge connection,
/// not the message. HTTP/2 forbids the hop-by-hop headers on a stream (RFC
/// 9113 section 8.2.2).
pub fn build_visitor_request(
    method: &str,
    path: &str,
    authority: &str,
    headers: &[(String, String)],
) -> http::Request<()> {
    // These headers go again to the origin. Thus drop the control headers and
    // the hop-by-hop headers.
    let replayed: Vec<(String, String)> =
        headers.iter().filter(|(name, _)| !is_control_header(name) && !is_hop_by_hop(name)).cloned().collect();

    // A bad header must drop only that header. A chain of each header on one
    // `Request::builder` fails at `body()` after one bad header. The fallback
    // `http::Request::new(())` is a GET of `/` with no headers, so one bad
    // header changes each request into a GET of the root. A builder with an
    // error also refuses each later header. Thus build the head first, check
    // each header alone, and drop each bad header alone, as an intermediary
    // does.
    let mut head = match http::Request::builder().method(method).uri(path).header("host", authority).body(()) {
        Ok(request) => request,
        Err(e) => {
            // Only the method and the URI can fail here. Both come from the
            // edge. A report is better than a request that is not the request
            // of the visitor.
            tracing::warn!(error = %e, "could not build the visitor request");
            return http::Request::new(());
        }
    };

    // Append, do not replace, to keep the host of the head.
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

/// The status and the headers of an origin response for the edge.
///
/// The headers go serialized in [`RESPONSE_HEADERS_HEADER`], with no control
/// header and no hop-by-hop header (RFC 9110 section 7.6.1). A hop-by-hop
/// header on an HTTP/2 stream makes the origin or the edge act on a
/// connection that does not exist. `content-length` also goes on the wire.
/// A status 101 becomes 200.
pub fn build_origin_response(status: u16, headers: &[(String, String)]) -> (u16, Vec<(String, String)>) {
    let mut real: Vec<(String, String)> = Vec::with_capacity(headers.len());
    let mut serialized: Vec<(String, String)> = Vec::new();

    for (name, value) in headers {
        let lower = name.to_ascii_lowercase();
        if lower == "content-length" {
            // HTTP/2 has this header and the edge uses it. Thus it goes on the
            // wire and also in the serialized blob.
            real.push((lower.clone(), value.clone()));
        }
        if !is_control_header(&lower) && !is_hop_by_hop(&lower) {
            // Drop the hop-by-hop headers here for the same reason as on the
            // request path: they tell about one connection, and the edge frames
            // the body itself. A `Transfer-Encoding: chunked` of the origin
            // next to the HTTP/2 framing of the edge gives the visitor two
            // different ends of the body. That is the shape of a
            // response-splitting bug.
            //
            // Neither HTTP/2 nor the origin checks the serialized blob. The
            // serialization exists to skip that check. That is not a reason to
            // send again a header of one connection.
            serialized.push((name.clone(), value.clone()));
        }
    }

    real.push((RESPONSE_HEADERS_HEADER.to_string(), encode_headers(&serialized)));
    // The edge records the source of the answer. "origin" tells that the
    // origin served it.
    real.push((RESPONSE_META_HEADER.to_string(), r#"{"src":"origin"}"#.to_string()));

    // HTTP/2 has no 101 (RFC 9113 section 8.1.1); the edge expects 200.
    let status = if status == 101 { 200 } else { status };
    (status, real)
}

/// Decode the serialized response headers of an origin response.
///
/// A bad entry is skipped and the response stays: one bad header must not
/// cost the visitor the full page.
pub fn decode_origin_response(headers: &[(String, String)]) -> Vec<(String, String)> {
    let get = |want: &str| headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(want)).map(|(_, v)| v.clone());
    match get(RESPONSE_HEADERS_HEADER) {
        Some(encoded) => decode_headers(&encoded),
        None => headers.iter().filter(|(k, _)| !is_control_header(k)).cloned().collect(),
    }
}

/// True when the response meta header tells that an origin answered. False
/// when cloudflared served the error itself.
pub fn served_by_origin(headers: &[(String, String)]) -> bool {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(RESPONSE_META_HEADER))
        .map(|(_, v)| v.contains(r#""src":"origin""#))
        .unwrap_or(false)
}

/// The headers that tell about one hop, not about the message.
///
/// RFC 9110 section 7.6.1. One of these headers on an HTTP/2 stream makes the
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

/// True for a header of the edge connection, false for a header of the
/// visitor.
///
/// A name with the prefix `:` is an HTTP/2 pseudo-header. The `cf-` families
/// are the records of Cloudflare. Each of them confuses the origin.
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
