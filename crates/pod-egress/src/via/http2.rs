//! HTTP/2's CONNECT inside the second proxy's TLS (RFC 9113, section 8.5):
//! `:method CONNECT` and `:authority` alone, no `:scheme` and no `:path`, as
//! h2 sends a CONNECT with no `:protocol`. A 2xx opens the tunnel: its DATA
//! frames carry the bytes both ways, and END_STREAM is TCP's half-close.
//! Each tunnel is a stream, so several go on one connection, which a task
//! drives while a handle or a stream of it lasts.

use std::time::Duration;

use bytes::Bytes;
use h2::client::SendRequest;
use h2::{Reason, RecvStream};
use pod_core::Stage;
use pod_proxy::DialError;
use tokio::io::{AsyncRead, AsyncWrite};

use super::{Said, Stream, Via};

/// The windows that the client grants, as WARP's road grants them: a few
/// round trips of a fast link, where HTTP/2's own 64 KiB would hold a copy
/// to one window for each round trip.
const STREAM_WINDOW: u32 = 4 << 20;
const CONNECTION_WINDOW: u32 = 8 << 20;

/// Why a CONNECT over HTTP/2 gave no tunnel.
pub(super) enum Failed {
    /// The proxy answered it: a status, a stream reset with CONNECT_ERROR,
    /// or no answer in time.
    Answer(DialError),
    /// HTTP/2 did not carry it: the connection ended, or the proxy reset
    /// the stream for another reason.
    Carried(String),
}

/// HTTP/2's handshake on `tls`; the connection is driven in a task of its
/// own, which ends with the connection.
pub(super) async fn handshake<S>(tls: S, via: &Via, timeout: Duration) -> Result<SendRequest<Bytes>, DialError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut builder = h2::client::Builder::new();
    builder.initial_window_size(STREAM_WINDOW).initial_connection_window_size(CONNECTION_WINDOW);
    let shown = via.shown();
    let (sender, connection) = tokio::time::timeout(timeout, builder.handshake::<_, Bytes>(tls))
        .await
        .map_err(|_| DialError::Timeout {
            step: format!("HTTP/2's handshake with {shown}"),
            after: timeout,
            stage: Stage::Proxy,
        })?
        .map_err(|e| DialError::ProxyProtocol { proxy: shown, detail: format!("HTTP/2: {e}") })?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    Ok(sender)
}

/// CONNECT `target` on the connection of `sender`, within `timeout`.
pub(super) async fn connect(
    sender: SendRequest<Bytes>,
    via: &Via,
    said: &Said<'_>,
    target: &str,
    timeout: Duration,
) -> Result<Stream, Failed> {
    let request = request(via, target, said.user_agent).map_err(|why| Failed::Answer(DialError::InvalidTarget(why)))?;
    let asked = async {
        let mut sender = sender.ready().await.map_err(|e| Failed::Carried(format!("HTTP/2: {e}")))?;
        let (response, send) =
            sender.send_request(request, false).map_err(|e| Failed::Carried(format!("HTTP/2: {e}")))?;
        let response = response.await.map_err(|e| answered(via, target, e))?;
        Ok::<_, Failed>((response, send))
    };
    let step = format!("the CONNECT of {target} with {}", via.shown());
    let (response, send) = tokio::time::timeout(timeout, asked)
        .await
        .map_err(|_| Failed::Answer(DialError::Timeout { step, after: timeout, stage: Stage::Proxy }))??;
    let status = response.status();
    if !status.is_success() {
        let head = head(&response);
        let reason = status.canonical_reason().unwrap_or_default().to_string();
        return Err(Failed::Answer(super::refused(via, said, target, status.as_u16(), reason, &head)));
    }
    Ok(pod_ws::h2_road::duplex(send, response.into_body()))
}

/// The CONNECT's request, with Basic as a value that HPACK never indexes.
fn request(via: &Via, target: &str, user_agent: &str) -> Result<http::Request<()>, String> {
    let mut builder =
        http::Request::builder().method(http::Method::CONNECT).uri(target).header(http::header::USER_AGENT, user_agent);
    if let Some(value) = via.authorization() {
        let mut value = http::HeaderValue::from_str(&value).map_err(|_| "the credentials are no header's value")?;
        value.set_sensitive(true);
        builder = builder.header(http::header::PROXY_AUTHORIZATION, value);
    }
    builder.body(()).map_err(|e| format!("{target}: {e}"))
}

/// A stream's failure before its answer. CONNECT_ERROR is the proxy's word
/// that its TCP connection to the target failed (RFC 9113, section 8.5).
fn answered(via: &Via, target: &str, e: h2::Error) -> Failed {
    if e.reason() == Some(Reason::CONNECT_ERROR) && !e.is_go_away() {
        return Failed::Answer(DialError::ProxyRefused {
            proxy: via.shown(),
            target: target.to_string(),
            status: 502,
            reason: "its connection to the target failed (CONNECT_ERROR)".into(),
        });
    }
    Failed::Carried(format!("HTTP/2 did not carry the CONNECT: {e}"))
}

/// The answer's head as HTTP/1.1 writes one, for the words of a `407`.
fn head(response: &http::Response<RecvStream>) -> String {
    let mut head = format!("HTTP/2 {}\r\n", response.status().as_u16());
    for value in response.headers().get_all(http::header::PROXY_AUTHENTICATE) {
        head.push_str("Proxy-Authenticate: ");
        head.push_str(value.to_str().unwrap_or_default());
        head.push_str("\r\n");
    }
    head
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The CONNECT of RFC 9113: an authority alone, and Basic sensitive.
    #[test]
    fn the_connect_names_the_authority_alone_and_hides_basic_from_hpack() {
        let via = Via::parse("https://proxy.example").unwrap().with_credentials("u:p").unwrap();
        let request = request(&via, "[2001:db8::1]:22", "podssh/test").unwrap();
        assert_eq!(request.method(), http::Method::CONNECT);
        assert_eq!(request.uri().authority().map(|a| a.as_str()), Some("[2001:db8::1]:22"));
        assert_eq!(request.uri().scheme(), None);
        assert!(request.headers()[http::header::PROXY_AUTHORIZATION].is_sensitive());
        let bare = request_of("https://proxy.example");
        assert!(bare.headers().get(http::header::PROXY_AUTHORIZATION).is_none());
    }

    fn request_of(url: &str) -> http::Request<()> {
        request(&Via::parse(url).unwrap(), "h.example:22", "podssh/test").unwrap()
    }
}
