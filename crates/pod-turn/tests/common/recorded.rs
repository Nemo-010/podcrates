// A UDP socket on 127.0.0.1 that keeps each datagram that it sends and
// receives, so that a test reads the wire of a server of another party; it
// can change one answer on the way in.

use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use pod_core::{Datagrams, RecvMeta, Transmit};
use pod_turn::stun::{self, MESSAGE_INTEGRITY_SHA256};

#[derive(Debug)]
pub struct Recorded {
    socket: pod_core::SystemDatagrams,
    pub sent: Mutex<Vec<Vec<u8>>>,
    pub received: Mutex<Vec<Vec<u8>>>,
    /// The type of a STUN message whose next copy gets the last byte of its
    /// MESSAGE-INTEGRITY-SHA256 changed before the client reads it.
    tamper: Mutex<Option<u16>>,
}

impl Recorded {
    pub async fn bind() -> Arc<Recorded> {
        let socket = pod_core::SystemDatagrams::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        Arc::new(Recorded { socket, sent: Mutex::default(), received: Mutex::default(), tamper: Mutex::default() })
    }

    /// Change the MESSAGE-INTEGRITY-SHA256 of the next message of `kind`.
    pub fn tamper(&self, kind: u16) {
        *self.tamper.lock().unwrap() = Some(kind);
    }

    /// The type of message that waits for its change; `None` after it.
    pub fn tamper_pending(&self) -> Option<u16> {
        *self.tamper.lock().unwrap()
    }

    fn change(&self, datagram: &mut [u8]) {
        let mut tamper = self.tamper.lock().unwrap();
        let Some(kind) = *tamper else { return };
        let Ok(message) = stun::decode(datagram) else { return };
        if message.kind != kind {
            return;
        }
        let Some(value) = message.attribute(MESSAGE_INTEGRITY_SHA256) else { return };
        // The value is a slice of the datagram: its last byte is at this offset.
        let last = value.as_ptr() as usize - datagram.as_ptr() as usize + value.len() - 1;
        datagram[last] ^= 0x01;
        *tamper = None;
    }
}

impl Datagrams for Recorded {
    fn poll_writable(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.socket.poll_writable(cx)
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        let sent = self.socket.try_send(transmit);
        if sent.is_ok() {
            self.sent.lock().unwrap().push(transmit.contents.to_vec());
        }
        sent
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let polled = self.socket.poll_recv(cx, bufs, meta);
        if let Poll::Ready(Ok(n)) = &polled {
            let mut received = self.received.lock().unwrap();
            for (buf, meta) in bufs.iter_mut().zip(meta.iter()).take(*n) {
                self.change(&mut buf[..meta.len]);
                received.push(buf[..meta.len].to_vec());
            }
        }
        polled
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }
}

/// The client's source of the recorded socket.
pub struct RecordedSource(pub Arc<Recorded>);

impl pod_turn::UdpSource for RecordedSource {
    fn open<'a>(
        &'a self,
        server: &'a pod_core::Target,
        _deadline: tokio::time::Instant,
    ) -> pod_core::BoxFuture<'a, Result<pod_turn::Opened, pod_core::Failure>> {
        Box::pin(async move {
            let pod_core::Target::Addr(addr) = server else { panic!("the tests use addresses") };
            Ok((self.0.clone() as Arc<dyn Datagrams>, *addr))
        })
    }
}

/// The STUN messages of `datagrams`; ChannelData is left out.
pub fn messages(datagrams: &[Vec<u8>]) -> Vec<stun::Message<'_>> {
    datagrams.iter().filter(|d| d.first().is_some_and(|b| b >> 6 == 0)).filter_map(|d| stun::decode(d).ok()).collect()
}
