//! The scan of the frames that the edge sends: a GOAWAY of the edge drains
//! the connection.

use super::*;

/// The bytes that the edge (the HTTP/2 client) sends before its frames.
pub(super) const CLIENT_PREFACE_LEN: usize = 24;

/// The HTTP/2 frame type of GOAWAY.
pub(super) const FRAME_GOAWAY: u8 = 0x7;

/// Find a GOAWAY frame in the bytes from the edge.
///
/// h2 gives the end of the connection (`accept` gives `None`) only after
/// each open stream ends. A long stream (a WebSocket) can keep a connection
/// that takes no new stream open for hours, and the tunnel does not replace
/// it. This scan reads the frame headers as the bytes pass, so the drain
/// signal comes when GOAWAY arrives.
#[derive(Debug)]
pub(super) struct FrameScan {
    preface_left: usize,
    header: [u8; 9],
    header_len: usize,
    skip: usize,
}

impl FrameScan {
    pub(super) fn new() -> Self {
        Self { preface_left: CLIENT_PREFACE_LEN, header: [0; 9], header_len: 0, skip: 0 }
    }

    /// Read `data`; true when it has the header of a GOAWAY frame.
    pub(super) fn feed(&mut self, mut data: &[u8]) -> bool {
        let mut goaway = false;
        while !data.is_empty() {
            if self.preface_left > 0 {
                let n = self.preface_left.min(data.len());
                self.preface_left -= n;
                data = &data[n..];
            } else if self.skip > 0 {
                let n = self.skip.min(data.len());
                self.skip -= n;
                data = &data[n..];
            } else {
                let n = (9 - self.header_len).min(data.len());
                self.header[self.header_len..self.header_len + n].copy_from_slice(&data[..n]);
                self.header_len += n;
                data = &data[n..];
                if self.header_len == 9 {
                    let h = self.header;
                    self.skip = u32::from_be_bytes([0, h[0], h[1], h[2]]) as usize;
                    self.header_len = 0;
                    goaway |= h[3] == FRAME_GOAWAY;
                }
            }
        }
        goaway
    }
}

/// The connection of the edge, with a [`FrameScan`] on the bytes it reads.
pub(super) struct GoawayScan<T> {
    pub(super) inner: T,
    pub(super) scan: FrameScan,
    pub(super) seen: Option<Arc<tokio::sync::Notify>>,
}

impl<T: AsyncRead + Unpin> AsyncRead for GoawayScan<T> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let this = &mut *self;
        let poll = std::pin::Pin::new(&mut this.inner).poll_read(cx, buf);
        if poll.is_ready()
            && this.seen.is_some()
            && this.scan.feed(&buf.filled()[before..])
            && let Some(seen) = this.seen.take()
        {
            seen.notify_one();
        }
        poll
    }
}

impl<T: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for GoawayScan<T> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, data)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}
