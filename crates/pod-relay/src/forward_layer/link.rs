//! One link of a session of the layer: a WebSocket to `/v1/layer/HOST/PORT`,
//! or, where the way refused the upgrade, a session of the HTTP road to
//! `/v1/http/open-layer/HOST/PORT` (PodUtils/podssh#287). Both are byte
//! streams that carry the layer's records; a road that failed gives its
//! words on the read after its last byte, as a WebSocket link does.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use pod_session::ws_link;
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};

use crate::http_road::client::{End, Ended};

/// A link of the layer.
pub enum Link {
    /// A WebSocket upgrade of the forward opener, or of the loopback.
    Ws(ws_link::Link),
    /// A session of the HTTP road: the caller's end of its pipe, and its end.
    Road { stream: DuplexStream, ended: Arc<Ended> },
}

impl Link {
    /// Whether the HTTP road carries this link.
    pub fn by_road(&self) -> bool {
        matches!(self, Link::Road { .. })
    }
}

/// The error that a road's end gives after its last byte: none for a clean
/// end or for an end not known yet.
fn road_error(ended: &Ended) -> Option<io::Error> {
    match ended.get()? {
        End::Closed { code: 1000, .. } => None,
        End::Closed { code, reason } => Some(io::Error::other(format!(
            "the relay closed the link of the HTTP road ({code} {})",
            pod_core::text::one_line(&reason)
        ))),
        End::Failed(why) => Some(io::Error::other(why)),
    }
}

impl AsyncRead for Link {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Link::Ws(link) => Pin::new(link).poll_read(cx, buf),
            Link::Road { stream, ended } => {
                let before = buf.filled().len();
                match Pin::new(stream).poll_read(cx, buf) {
                    Poll::Ready(Ok(())) if buf.filled().len() == before && buf.remaining() > 0 => {
                        Poll::Ready(road_error(ended).map_or(Ok(()), Err))
                    }
                    other => other,
                }
            }
        }
    }
}

impl AsyncWrite for Link {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Link::Ws(link) => Pin::new(link).poll_write(cx, buf),
            Link::Road { stream, .. } => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Link::Ws(link) => Pin::new(link).poll_flush(cx),
            Link::Road { stream, .. } => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Link::Ws(link) => Pin::new(link).poll_shutdown(cx),
            Link::Road { stream, .. } => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A road link gives its bytes, then the words of a failed road on the
    /// read after them; a clean end of the road is the end of the link.
    #[tokio::test]
    async fn a_road_link_ends_with_the_words_of_its_road() {
        for (end, error) in [
            (Some(End::Failed("the relay forgot the session".into())), Some("the relay forgot the session")),
            (Some(End::Closed { code: 1000, reason: "target closed".into() }), None),
            (
                Some(End::Closed { code: 1011, reason: "layer\nfault".into() }),
                Some("the relay closed the link of the HTTP road (1011 layer fault)"),
            ),
            (None, None),
        ] {
            let (stream, mut far) = tokio::io::duplex(64);
            let ended = Arc::new(Ended::default());
            if let Some(end) = end {
                ended.set_once(end);
            }
            let mut link = Link::Road { stream, ended };
            assert!(link.by_road());
            far.write_all(b"abc").await.unwrap();
            drop(far);
            let mut got = [0u8; 3];
            link.read_exact(&mut got).await.unwrap();
            assert_eq!(&got, b"abc");
            let rest = link.read(&mut [0u8; 8]).await;
            match error {
                Some(words) => assert_eq!(rest.unwrap_err().to_string(), words),
                None => assert_eq!(rest.unwrap(), 0),
            }
        }
    }
}
