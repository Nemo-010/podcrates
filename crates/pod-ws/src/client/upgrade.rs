//! The WebSocket upgrade over a stream of the caller: the request, the
//! answer's head, the check of its key, and the words of a refusal.

use std::time::Duration;

use pod_proxy::http;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{ConnectError, UPGRADE_HEAD};
use crate::handshake;

/// Send the upgrade request and read the answer. On `101`, returns the stream
/// and any bytes that arrived after the response head (the relay dials the
/// target first, so its first frame can share a segment with the headers). On
/// any other status, reads a little of the body for the error message.
pub async fn upgrade<S>(tls: S, host_header: &str, path: &str, token: &str) -> Result<(S, Vec<u8>), ConnectError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let key = handshake::generate_key().map_err(|e| ConnectError::Upgrade(e.to_string()))?;
    upgrade_with(tls, &handshake::build_request(host_header, path, token, &key), &key).await
}

/// [`upgrade`] with a request that the caller built with `key`, as another
/// road's upgrade needs. The `Location` of a redirect comes back as
/// the body of the refusal, without its query, which a login page may fill.
pub async fn upgrade_with<S>(tls: S, request: &[u8], key: &str) -> Result<(S, Vec<u8>), ConnectError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    upgrade_answering(tls, request, key).await.map(|(tls, pending, _)| (tls, pending))
}

/// [`upgrade_with`], with the subprotocol that the answer names
/// (`Sec-WebSocket-Protocol`), if one: a caller that offered one checks it
/// (RFC 6455, section 4.1).
pub async fn upgrade_answering<S>(
    mut tls: S,
    request: &[u8],
    key: &str,
) -> Result<(S, Vec<u8>, Option<String>), ConnectError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let io = |e: std::io::Error| ConnectError::Upgrade(e.to_string());
    tls.write_all(request).await.map_err(io)?;
    tls.flush().await.map_err(io)?;

    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 2048];
    let head_end = loop {
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break end + 4;
        }
        if buf.len() > UPGRADE_HEAD {
            return Err(ConnectError::Upgrade("no end of the response headers within 16 KiB".into()));
        }
        let n = tls.read(&mut chunk).await.map_err(io)?;
        if n == 0 {
            return Err(ConnectError::Upgrade("the relay closed the connection before answering the upgrade".into()));
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let (status, reason, headers) = http::parse_head(&head).map_err(ConnectError::Upgrade)?;
    if status == 101 {
        handshake::check_response(&head, key).map_err(|e| ConnectError::Upgrade(e.to_string()))?;
        let protocol =
            headers.iter().find(|(name, _)| name == "sec-websocket-protocol").map(|(_, p)| p.trim().to_string());
        return Ok((tls, buf.split_off(head_end), protocol));
    }
    let location = headers.iter().find(|(name, _)| name == "location").map(|(_, to)| to);
    if let Some(to) = location.filter(|_| (300..400).contains(&status)) {
        let to = to.split(['?', '#']).next().unwrap_or_default();
        return Err(ConnectError::Refused { status, body: format!("a redirect to {}", pod_core::text::one_line(to)) });
    }
    // Not upgraded: the body says why. A short, bounded read; on any trouble
    // the status line alone is reported.
    let body = tokio::time::timeout(Duration::from_secs(3), http::read_response(&mut tls, buf, 4096))
        .await
        .ok()
        .and_then(Result::ok)
        .map(|r| r.body_text(200))
        .filter(|b| !b.is_empty())
        .unwrap_or(reason);
    Err(ConnectError::Refused { status, body })
}
