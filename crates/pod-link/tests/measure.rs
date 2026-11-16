//! The measurement of the link (T-777): throughput, round trips,
//! allocations for each `DATA` frame and the peak of the live heap, on the
//! memory carrier and, with the feature `tcp`, on the tcp carrier over the
//! loopback. One line for each result: `MEASURE scen=NAME key=value ...`.
//! It is no gate: run it by hand, in release mode,
//!
//! ```sh
//! cargo test --release -p pod-link --all-features --test measure -- --ignored --nocapture
//! ```
//!
//! The counting allocator is the allocator of this test binary alone; the
//! crate has none (design rule 7). Both ends run in this process, so the
//! counts are of the two ends and of the runtime.

mod common;

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use pod_link::{Link, Settings, Stream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Notify;

/// The allocator of this binary: the system allocator with counts.
struct Counting;

static ALLOCS: AtomicU64 = AtomicU64::new(0);
static ALLOC_BYTES: AtomicU64 = AtomicU64::new(0);
static LIVE: AtomicU64 = AtomicU64::new(0);
static PEAK: AtomicU64 = AtomicU64::new(0);

// SAFETY: each call goes to the system allocator with the same arguments;
// the counts are atomics and change no memory of the caller.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        count(layout.size() as u64);
        // SAFETY: the caller keeps the contract of `GlobalAlloc::alloc`.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size() as u64, Ordering::Relaxed);
        // SAFETY: `ptr` came from `alloc` of this allocator with `layout`.
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        LIVE.fetch_sub(layout.size() as u64, Ordering::Relaxed);
        count(new_size as u64);
        // SAFETY: the caller keeps the contract of `GlobalAlloc::realloc`.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

fn count(size: u64) {
    ALLOCS.fetch_add(1, Ordering::Relaxed);
    ALLOC_BYTES.fetch_add(size, Ordering::Relaxed);
    let live = LIVE.fetch_add(size, Ordering::Relaxed) + size;
    PEAK.fetch_max(live, Ordering::Relaxed);
}

#[global_allocator]
static COUNTING: Counting = Counting;

/// The counts from a mark.
struct Heap {
    allocs: u64,
    bytes: u64,
    live: u64,
}

impl Heap {
    fn mark() -> Heap {
        let live = LIVE.load(Ordering::Relaxed);
        PEAK.store(live, Ordering::Relaxed);
        Heap { allocs: ALLOCS.load(Ordering::Relaxed), bytes: ALLOC_BYTES.load(Ordering::Relaxed), live }
    }

    /// The allocations, their bytes and the peak of the live bytes above
    /// the mark.
    fn since(&self) -> (u64, u64, u64) {
        (
            ALLOCS.load(Ordering::Relaxed) - self.allocs,
            ALLOC_BYTES.load(Ordering::Relaxed) - self.bytes,
            PEAK.load(Ordering::Relaxed).saturating_sub(self.live),
        )
    }
}

/// The bytes of each bulk run, over all its streams.
const BULK: usize = 256 << 20;

/// The bytes of each write of a bulk stream.
const WRITE: usize = 64 << 10;

/// The round trips of each latency run.
const TRIPS: usize = 2000;

/// The role of a stream: its first byte.
const ROLE_BULK: u8 = b'B';
const ROLE_ECHO: u8 = b'E';

/// The listener side: a bulk stream reads to its end, then writes the
/// count of its bytes (8 bytes) and closes; an echo stream gives each
/// message of 64 bytes back.
fn serve(link: Link) -> Arc<Link> {
    let link = Arc::new(link);
    let accepting = link.clone();
    tokio::spawn(async move {
        while let Ok(mut stream) = accepting.accept().await {
            tokio::spawn(async move {
                let mut role = [0u8; 1];
                if stream.read_exact(&mut role).await.is_err() {
                    return;
                }
                if role[0] == ROLE_BULK {
                    let mut buf = vec![0u8; WRITE];
                    let mut total = 0u64;
                    while let Ok(n @ 1..) = stream.read(&mut buf).await {
                        total += n as u64;
                    }
                    let _ = stream.write_all(&total.to_be_bytes()).await;
                } else {
                    let mut msg = [0u8; 64];
                    while stream.read_exact(&mut msg).await.is_ok() {
                        if stream.write_all(&msg).await.is_err() {
                            return;
                        }
                    }
                }
                let _ = stream.shutdown().await;
            });
        }
    });
    link
}

/// Write `bytes` on a new bulk stream, or until `stop` when it is given,
/// and wait for the count of the far end: a byte counts when the reader
/// took it and acknowledged the end.
async fn bulk(dialer: &Link, bytes: usize, stop: Option<Arc<AtomicBool>>) -> u64 {
    let mut stream = dialer.open().expect("a stream");
    stream.write_all(&[ROLE_BULK]).await.expect("the role");
    let chunk = vec![0x5au8; WRITE];
    let mut sent = 0usize;
    loop {
        let done = match &stop {
            Some(flag) => flag.load(Ordering::Relaxed),
            None => sent >= bytes,
        };
        if done {
            break;
        }
        stream.write_all(&chunk).await.expect("a bulk write");
        sent += WRITE;
    }
    stream.shutdown().await.expect("the close of a bulk stream");
    let mut count = [0u8; 8];
    stream.read_exact(&mut count).await.expect("the count of the far end");
    let got = u64::from_be_bytes(count);
    assert_eq!(got, sent as u64, "the far end took each byte");
    got
}

async fn echo_stream(dialer: &Link) -> Stream {
    let mut stream = dialer.open().expect("a stream");
    stream.write_all(&[ROLE_ECHO]).await.expect("the role");
    stream
}

/// The round trips of 64 bytes on `stream`, sorted.
async fn trips(stream: &mut Stream) -> Vec<Duration> {
    let mut msg = [7u8; 64];
    let mut out = Vec::with_capacity(TRIPS);
    for _ in 0..TRIPS {
        let t = Instant::now();
        stream.write_all(&msg).await.expect("a message");
        stream.read_exact(&mut msg).await.expect("its echo");
        out.push(t.elapsed());
    }
    out.sort();
    out
}

fn pct(sorted: &[Duration], p: usize) -> f64 {
    let i = (sorted.len() * p / 100).min(sorted.len() - 1);
    sorted[i].as_secs_f64() * 1e6
}

/// One carrier: a fresh pair of links for each run.
type Pair = fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = (Link, Link)>>>;

async fn run_carrier(name: &str, pair: Pair) {
    let frame = Settings::default().frame_size;
    for streams in [1usize, 8] {
        let scen = format!("bulk-{streams}");
        let mut rates = Vec::new();
        for run in 1..=3 {
            let (dialer, listener) = pair().await;
            let _far = serve(listener);
            let dialer = Arc::new(dialer);
            let heap = Heap::mark();
            let t = Instant::now();
            let mut each = Vec::new();
            for _ in 0..streams {
                let d = dialer.clone();
                each.push(tokio::spawn(async move { bulk(&d, BULK / streams, None).await }));
            }
            let mut total = 0;
            for e in each {
                total += e.await.expect("a bulk stream");
            }
            let secs = t.elapsed().as_secs_f64();
            let (allocs, bytes, peak) = heap.since();
            let frames = total.div_ceil(frame as u64);
            let rate = total as f64 / secs / 1e9;
            rates.push(rate);
            println!(
                "MEASURE scen={scen} carrier={name} run={run} bytes={total} secs={secs:.3} gb_s={rate:.2} frames={frames} allocs={allocs} allocs_per_frame={:.2} alloc_bytes_per_frame={} peak_live={peak}",
                allocs as f64 / frames as f64,
                bytes / frames,
            );
            dialer.close().await;
        }
        rates.sort_by(f64::total_cmp);
        println!(
            "MEASURE scen={scen} carrier={name} summary median_gb_s={:.2} min_gb_s={:.2} max_gb_s={:.2}",
            rates[1], rates[0], rates[2]
        );
    }

    let (dialer, listener) = pair().await;
    let _far = serve(listener);
    let mut stream = echo_stream(&dialer).await;
    let idle = trips(&mut stream).await;
    println!(
        "MEASURE scen=rtt-idle carrier={name} trips={TRIPS} p50_us={:.1} p99_us={:.1}",
        pct(&idle, 50),
        pct(&idle, 99)
    );
    let dialer = Arc::new(dialer);
    let stop = Arc::new(AtomicBool::new(false));
    let load = {
        let (d, s) = (dialer.clone(), stop.clone());
        tokio::spawn(async move { bulk(&d, 0, Some(s)).await })
    };
    tokio::time::sleep(Duration::from_millis(50)).await;
    let busy = trips(&mut stream).await;
    stop.store(true, Ordering::Relaxed);
    let moved = load.await.expect("the bulk stream");
    println!(
        "MEASURE scen=rtt-bulk carrier={name} trips={TRIPS} p50_us={:.1} p99_us={:.1} bulk_bytes={moved}",
        pct(&busy, 50),
        pct(&busy, 99)
    );
    drop(stream);
    dialer.close().await;
}

/// The wake latency of the host: the time from `notify_one` to the run of
/// the task that waits.
async fn wake_latency() {
    let go = Arc::new(Notify::new());
    let back = Arc::new(Notify::new());
    let at = Arc::new(std::sync::Mutex::new(Instant::now()));
    let waiter = {
        let (go, back, at) = (go.clone(), back.clone(), at.clone());
        tokio::spawn(async move {
            let mut out = Vec::with_capacity(TRIPS);
            for _ in 0..TRIPS {
                go.notified().await;
                out.push(at.lock().unwrap().elapsed());
                back.notify_one();
            }
            out
        })
    };
    for _ in 0..TRIPS {
        *at.lock().unwrap() = Instant::now();
        go.notify_one();
        back.notified().await;
    }
    let mut out = waiter.await.expect("the waiter");
    out.sort();
    println!("MEASURE scen=wake samples={TRIPS} p50_us={:.1} p99_us={:.1}", pct(&out, 50), pct(&out, 99));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "a measurement, not a check: run it in release mode with --nocapture"]
async fn measure() {
    println!(
        "MEASURE scen=host cpus={} debug={}",
        std::thread::available_parallelism().map_or(0, |n| n.get()),
        cfg!(debug_assertions)
    );
    wake_latency().await;
    run_carrier("memory", || Box::pin(common::over_memory(Settings::default(), Settings::default()))).await;
    #[cfg(feature = "tcp")]
    run_carrier("tcp", || Box::pin(over_tcp())).await;
}

/// The two ends of a link over the tcp carrier on the loopback.
#[cfg(feature = "tcp")]
async fn over_tcp() -> (Link, Link) {
    use common::tcp::{Direct, at, bound, carrier, id};
    use pod_link::{Carrier, Listener, Role};
    let (server, client) = (id(1), id(2));
    let listening = carrier(1, Arc::new(Direct::default()), &[client.public()]);
    let dialing = carrier(2, Arc::new(Direct::default()), &[]);
    let mut door = bound(&listening).await;
    let address = at(&server.public(), &door);
    let (near, far) = tokio::join!(dialing.dial(&address), door.accept_peer());
    let (near, far) = (near.expect("the dial"), far.expect("the accept"));
    // `door` drops here: the link keeps its accepted carrier.
    (
        Link::new(near, Role::Dialer, Settings::default()).expect("the dialer"),
        Link::new(far.io, Role::Listener, Settings::default()).expect("the listener"),
    )
}
