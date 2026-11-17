//! The heads of HTTP/1.1: the request to the origin, the answer of the
//! origin, and the `ConnectResponse` to the edge.

use crate::fail::{IoFail, OrFail, Result, bail};
use http::{HeaderName, HeaderValue};
use pod_core::{Class, Stage};

use super::copy::{futures_close, futures_write_all};
use super::{EdgeWriter, cqstream};
use crate::cloudflare::http2::{connection_named, is_hop_by_hop};
use crate::cloudflare::stream::{HTTP_HEADER_KEY, HTTP_HOST_KEY, HTTP_METHOD_KEY};
use crate::ingress::OriginOptions;
use crate::proxy::path_and_query;

pub(crate) const MAX_HEAD_BYTES: usize = 32 * 1024;

/// The most header lines of an origin answer: an answer can have many
/// Set-Cookie lines. MAX_HEAD_BYTES limits the head too.
pub(crate) const MAX_HEADERS: usize = 256;

// ── Response helpers ────────────────────────────────────────────────────────

pub async fn write_simple_response(
    writer: &mut EdgeWriter,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> Result<()> {
    write_simple_response_with(writer, status, content_type, body, &[]).await
}

pub async fn write_simple_response_with(
    writer: &mut EdgeWriter,
    status: u16,
    content_type: &str,
    body: &[u8],
    extra: &[(String, String)],
) -> Result<()> {
    // A reply that the client makes (the PIN page, the unlock
    // redirect, an error) is not stored by a cache.
    let mut headers = vec![
        ("Content-Type".to_string(), content_type.to_string()),
        ("Content-Length".to_string(), body.len().to_string()),
        ("Cache-Control".to_string(), "no-store".to_string()),
    ];
    headers.extend(extra.iter().cloned());
    write_response_meta(writer, status, &headers).await?;
    if !body.is_empty() {
        futures_write_all(writer, body).await?;
    }
    futures_close(writer).await
}

/// Build the metadata pairs of the `ConnectResponse`. The status is a bare
/// `HttpStatus`. Each header must be `HttpHeader:<Name>`, else the edge drops
/// it.
pub(crate) fn response_meta_pairs(status: u16, headers: &[(String, String)]) -> Vec<(String, String)> {
    let prefix = format!("{HTTP_HEADER_KEY}:");
    let mut meta: Vec<(String, String)> = Vec::with_capacity(headers.len() + 1);
    meta.push((cqstream::HTTP_STATUS_KEY.to_string(), status.to_string()));
    for (name, value) in headers {
        let key = if name == cqstream::HTTP_STATUS_KEY || name.starts_with(&prefix) {
            name.clone()
        } else {
            format!("{prefix}{name}")
        };
        meta.push((key, value.clone()));
    }
    meta
}

pub async fn write_response_meta(writer: &mut EdgeWriter, status: u16, headers: &[(String, String)]) -> Result<()> {
    let meta = response_meta_pairs(status, headers);
    let refs: Vec<(&str, &str)> = meta.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    cqstream::write_connect_response(writer, "", &refs).await?;
    Ok(())
}

// ── Request head ────────────────────────────────────────────────────────────

/// The HTTP/1.1 head of the request to the origin.
///
/// The method, the target and the host come from the edge (the QUIC leg has
/// no HTTP parser before this) or from `httpHostHeader`: each one with a
/// control character, a space or a line break is an error. A
/// header with a bad name or value is dropped. The hop-by-hop headers and
/// the headers that `Connection` names stay on their hop, but
/// `Transfer-Encoding` stays: a chunked request body goes to the origin as
/// it is.
pub fn build_request_head(
    request: &cqstream::ConnectRequest,
    options: &OriginOptions,
    upgrade: bool,
) -> Result<String> {
    let method = request.meta(HTTP_METHOD_KEY).unwrap_or("GET");
    if http::Method::from_bytes(method.as_bytes()).is_err() {
        bail!(Stage::EdgeStream, Class::Protocol, "the request method {method:?} is not a token");
    }
    let path = request_path(&request.dest);
    if !path.bytes().all(|b| b > b' ' && b != 0x7f) {
        bail!(Stage::EdgeStream, Class::Protocol, "the request target {path:?} has a space or a control character");
    }
    let host = match &options.http_host_header {
        Some(host) => host.clone(),
        None => request.meta(HTTP_HOST_KEY).unwrap_or_default().to_string(),
    };
    if HeaderValue::from_bytes(host.as_bytes()).is_err() {
        let from = if options.http_host_header.is_some() { "httpHostHeader" } else { "the request" };
        bail!(Stage::EdgeStream, Class::Protocol, "the Host {host:?} of {from} has a control character");
    }
    let prefix = format!("{HTTP_HEADER_KEY}:");
    let headers =
        || request.metadata.iter().filter_map(|(key, value)| Some((key.strip_prefix(&prefix)?, value.as_str())));
    let named =
        connection_named(headers().filter(|(name, _)| name.eq_ignore_ascii_case("connection")).map(|(_, value)| value));

    let mut head = String::with_capacity(256);
    head.push_str(method);
    head.push(' ');
    head.push_str(&path);
    head.push_str(" HTTP/1.1\r\n");
    if !host.is_empty() {
        head.push_str("Host: ");
        head.push_str(&host);
        head.push_str("\r\n");
    }
    let mut saw_upgrade = false;
    for (name, value) in headers() {
        let lower = name.to_ascii_lowercase();
        if lower == "host" {
            continue;
        }
        if options.strip_accept_encoding && lower == "accept-encoding" {
            continue;
        }
        if lower == "upgrade" && upgrade {
            saw_upgrade = true;
        } else if drop_for_origin(&lower, &named) {
            continue;
        }
        if HeaderName::from_bytes(name.as_bytes()).is_err() || HeaderValue::from_bytes(value.as_bytes()).is_err() {
            tracing::warn!(header = %name.escape_debug(), "a request header is not valid HTTP; it is dropped");
            continue;
        }
        head.push_str(name);
        head.push_str(": ");
        head.push_str(value);
        head.push_str("\r\n");
    }
    if upgrade {
        if !saw_upgrade {
            head.push_str("Upgrade: websocket\r\n");
        }
        head.push_str("Connection: Upgrade\r\n");
    } else {
        head.push_str("Connection: close\r\n");
    }
    head.push_str("\r\n");
    Ok(head)
}

/// True when the request header `lower` (in lower case) stays out of the head
/// to the origin: a hop-by-hop header but `Transfer-Encoding`, or a header
/// that `Connection` names.
pub(crate) fn drop_for_origin(lower: &str, named: &[String]) -> bool {
    (is_hop_by_hop(lower) && lower != "transfer-encoding") || named.iter().any(|n| n == lower)
}

pub(crate) fn request_path(dest: &str) -> String {
    path_and_query(dest)
}

pub fn header_value<'a>(request: &'a cqstream::ConnectRequest, name: &str) -> Option<&'a str> {
    let prefix = format!("{HTTP_HEADER_KEY}:");
    request.metadata.iter().find_map(|(key, value)| {
        key.strip_prefix(&prefix).filter(|header| header.eq_ignore_ascii_case(name)).map(|_| value.as_str())
    })
}

pub fn content_length(request: &cqstream::ConnectRequest) -> Option<u64> {
    header_value(request, "content-length").and_then(|v| v.parse().ok())
}

pub(crate) fn is_chunked(request: &cqstream::ConnectRequest) -> bool {
    header_value(request, "transfer-encoding").map(|v| v.to_ascii_lowercase().contains("chunked")).unwrap_or(false)
}

pub(crate) fn is_upgrade(request: &cqstream::ConnectRequest) -> bool {
    header_value(request, "upgrade").is_some()
        || header_value(request, "connection").map(|v| v.to_ascii_lowercase().contains("upgrade")).unwrap_or(false)
}

/// The edge marks an upgrade by connection type, and may not keep the
/// `Upgrade`/`Connection` headers in the metadata, so check both.
pub fn is_websocket(request: &cqstream::ConnectRequest) -> bool {
    request.conn_type == cqstream::ConnectionType::Websocket || is_upgrade(request)
}

// ── Response head ───────────────────────────────────────────────────────────

/// The Content-Length of an origin answer, after a check of its framing.
/// Each Content-Length value (also each item of a list) must
/// be the same number (RFC 9110 section 8.6). A Content-Length together
/// with a Transfer-Encoding that is not chunked is an error. With a chunked
/// Transfer-Encoding, the chunks frame the body (RFC 9112 section 6.3).
pub(crate) fn response_length(headers: &[(String, String)]) -> Result<Option<u64>> {
    let mut length = None;
    for (_, value) in headers.iter().filter(|(name, _)| name.eq_ignore_ascii_case("content-length")) {
        for item in value.split(',') {
            let item = item.trim();
            let n = item.parse::<u64>().ok().filter(|_| item.bytes().all(|b| b.is_ascii_digit())).or_fail(
                Stage::Origin,
                Class::Protocol,
                format!("the origin answer has a bad Content-Length {item:?}"),
            )?;
            if length.is_some_and(|l| l != n) {
                bail!(
                    Stage::Origin,
                    Class::Protocol,
                    "the origin answer has conflicting framing: two Content-Length values"
                );
            }
            length = Some(n);
        }
    }
    let encodings: Vec<String> = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("transfer-encoding"))
        .map(|(_, value)| value.to_ascii_lowercase())
        .collect();
    if length.is_some() && !encodings.is_empty() {
        if encodings.iter().any(|v| v.contains("chunked")) {
            return Ok(None);
        }
        bail!(
            Stage::Origin,
            Class::Protocol,
            "the origin answer has conflicting framing: Content-Length and Transfer-Encoding"
        );
    }
    Ok(length)
}

pub(crate) async fn read_response_head<R>(io: &mut R) -> Result<(u16, Vec<(String, String)>, Vec<u8>)>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    let mut tmp = [0u8; 2048];
    loop {
        let n = tokio::io::AsyncReadExt::read(io, &mut tmp)
            .await
            .io_fail(Stage::Origin, "reading the answer of the origin")?;
        if n == 0 {
            bail!(Stage::Origin, Class::Unavailable, "origin closed before sending a response head");
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.len() > MAX_HEAD_BYTES {
            bail!(Stage::Origin, Class::Protocol, "origin response head exceeds {MAX_HEAD_BYTES} bytes");
        }
        let parsed = {
            let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
            let mut response = httparse::Response::new(&mut headers);
            match response.parse(&buf).or_fail(Stage::Origin, Class::Protocol, "the answer head of the origin")? {
                httparse::Status::Complete(consumed) => {
                    let status = response.code.or_fail(Stage::Origin, Class::Protocol, "no status code")?;
                    let pairs = response
                        .headers
                        .iter()
                        .map(|h| (h.name.to_string(), String::from_utf8_lossy(h.value).into_owned()))
                        .collect::<Vec<_>>();
                    Some((status, pairs, consumed))
                }
                httparse::Status::Partial => None,
            }
        };
        if let Some((status, pairs, consumed)) = parsed {
            let leftover = buf.split_off(consumed);
            return Ok((status, pairs, leftover));
        }
    }
}

pub(crate) fn headers_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
}
