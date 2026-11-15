use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::Waker;
use std::time::Duration;

use pod_core::Datagrams;

use super::*;
use crate::socket::DatagramSocket;

/// A way whose each read fails with `ConnectionReset` while `failing` is
/// set, and waits after that. It counts its reads.
#[derive(Debug, Default)]
struct Failing {
    failing: AtomicBool,
    reads: AtomicUsize,
}

impl Failing {
    fn new() -> Arc<Failing> {
        let way = Arc::new(Failing::default());
        way.failing.store(true, Ordering::SeqCst);
        way
    }
}

impl Datagrams for Failing {
    fn poll_writable(&self, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn try_send(&self, _t: &pod_core::Transmit<'_>) -> io::Result<()> {
        Ok(())
    }

    fn poll_recv(
        &self,
        _cx: &mut Context<'_>,
        _bufs: &mut [IoSliceMut<'_>],
        _meta: &mut [pod_core::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        match self.failing.load(Ordering::SeqCst) {
            true => Poll::Ready(Err(io::ErrorKind::ConnectionReset.into())),
            false => Poll::Pending,
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok("192.0.2.9:4433".parse().unwrap())
    }
}

fn read(socket: &mut Bounded) -> Poll<io::Result<usize>> {
    let mut buf = [0u8; 64];
    let mut bufs = [IoSliceMut::new(&mut buf)];
    let mut meta = [RecvMeta::default()];
    socket.poll_recv(&mut Context::from_waker(Waker::noop()), &mut bufs, &mut meta)
}

/// Each failed read passes through below the bound; the read at the bound
/// is `BrokenPipe` with the count; a read that waits starts the count
/// again.
#[test]
fn the_failed_read_at_the_bound_is_a_broken_pipe() {
    let way = Failing::new();
    let mut socket = Bounded::new(Box::new(DatagramSocket::new(way.clone())));
    for _ in 1..FAILED_READS_MOST {
        match read(&mut socket) {
            Poll::Ready(Err(e)) => assert_eq!(e.kind(), io::ErrorKind::ConnectionReset),
            other => panic!("{other:?}"),
        }
    }
    way.failing.store(false, Ordering::SeqCst);
    assert!(read(&mut socket).is_pending());
    way.failing.store(true, Ordering::SeqCst);
    for _ in 1..FAILED_READS_MOST {
        assert!(matches!(read(&mut socket), Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::ConnectionReset));
    }
    match read(&mut socket) {
        Poll::Ready(Err(e)) => {
            assert_eq!(e.kind(), io::ErrorKind::BrokenPipe);
            assert!(e.to_string().starts_with("256 failed reads in a row"), "{e}");
        }
        other => panic!("{other:?}"),
    }
}

/// podssh's measure (PodUtils/podssh#253): an endpoint over a way that
/// fails each read. The driver ends near the bound, the CPU stays free,
/// and the drop of the endpoint returns.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_endpoint_over_a_way_that_fails_each_read_ends_its_driver() {
    let way = Failing::new();
    let endpoint = crate::over(way.clone(), None).expect("an endpoint");
    tokio::time::sleep(Duration::from_millis(300)).await;
    let reads = way.reads.load(Ordering::SeqCst);
    assert!(reads <= 2 * FAILED_READS_MOST as usize, "{reads} reads: the driver spins");
    let dropped = tokio::task::spawn_blocking(move || drop(endpoint));
    tokio::time::timeout(Duration::from_secs(5), dropped).await.expect("the drop hangs").unwrap();
}
