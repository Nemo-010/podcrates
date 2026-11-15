//! A bound on the failed reads in a row of the socket of an endpoint.
//!
//! The receive loop of noq answers `ECONNRESET` and `EMSGSIZE` with a new
//! read, before its work limiter. A way that fails each read with one of
//! those keeps one worker of the runtime busy with no yield, and the driver
//! holds the lock of the endpoint, so the drop of the endpoint hangs too.
//! Past [`FAILED_READS_MOST`] failed reads in a row, this socket gives
//! `BrokenPipe`, which noq does not skip: the driver ends, and the caller
//! dials again. A read that succeeds or waits starts the count again.

use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::task::{Context, Poll};

use noq::udp::RecvMeta;
use noq::{AsyncUdpSocket, UdpSender};

/// The most failed reads in a row before the socket ends. A real socket
/// gives one `ECONNRESET` for each ICMP error, then waits: it never comes
/// near this count.
pub const FAILED_READS_MOST: u32 = 256;

/// `inner` with a bound on its failed reads in a row.
#[derive(Debug)]
pub struct Bounded {
    inner: Box<dyn AsyncUdpSocket>,
    failed: u32,
}

impl Bounded {
    pub fn new(inner: Box<dyn AsyncUdpSocket>) -> Bounded {
        Bounded { inner, failed: 0 }
    }
}

impl AsyncUdpSocket for Bounded {
    fn create_sender(&self) -> Pin<Box<dyn UdpSender>> {
        self.inner.create_sender()
    }

    fn poll_recv(
        &mut self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        match self.inner.poll_recv(cx, bufs, meta) {
            Poll::Ready(Err(e)) => {
                self.failed = self.failed.saturating_add(1);
                if self.failed < FAILED_READS_MOST {
                    return Poll::Ready(Err(e));
                }
                let words = format!("{} failed reads in a row on the socket of QUIC; the last: {e}", self.failed);
                Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, words)))
            }
            other => {
                self.failed = 0;
                other
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_receive_segments(&self) -> NonZeroUsize {
        self.inner.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

#[cfg(test)]
#[path = "bounded_tests.rs"]
mod tests;
