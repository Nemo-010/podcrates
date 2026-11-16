//! The data path of the link allocates nothing for each `DATA` frame
//! (T-778): a bulk run of 64 MiB over the memory carrier, after its first
//! frames, makes at most [`MARGIN`] allocations in the process. The
//! counting allocator is the allocator of this test binary alone (design
//! rule 7), and the binary has one test, so no other test counts.

mod common;

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use pod_link::Settings;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Counting;

static ON: AtomicBool = AtomicBool::new(false);
static ALLOCS: AtomicU64 = AtomicU64::new(0);

// SAFETY: each call goes to the system allocator with the same arguments;
// the counts are atomics.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if ON.load(Ordering::Relaxed) {
            ALLOCS.fetch_add(1, Ordering::Relaxed);
        }
        // SAFETY: the caller keeps the contract of `GlobalAlloc::alloc`.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: `ptr` came from this allocator with `layout`.
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if ON.load(Ordering::Relaxed) {
            ALLOCS.fetch_add(1, Ordering::Relaxed);
        }
        // SAFETY: the caller keeps the contract of `GlobalAlloc::realloc`.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static COUNTING: Counting = Counting;

/// The allocations that a run of 64 MiB (4096 frames of 16 KiB) can make.
const MARGIN: u64 = 16;

/// The bytes of each write of the bulk stream.
const WRITE: usize = 64 << 10;

#[tokio::test(flavor = "current_thread")]
async fn a_bulk_run_allocates_nothing_for_each_data_frame() {
    let (dialer, listener) = common::over_memory(Settings::default(), Settings::default()).await;
    let reader = tokio::spawn(async move {
        let mut stream = listener.accept().await.expect("the bulk stream");
        let mut buf = vec![0u8; WRITE];
        let mut total = 0u64;
        while let Ok(n @ 1..) = stream.read(&mut buf).await {
            total += n as u64;
        }
        total
    });
    let mut stream = dialer.open().expect("a stream");
    let chunk = vec![0x5au8; WRITE];
    // The first frames grow the windows, the queues and the buffers.
    for _ in 0..16 {
        stream.write_all(&chunk).await.expect("a write");
    }
    ON.store(true, Ordering::Relaxed);
    for _ in 0..1024 {
        stream.write_all(&chunk).await.expect("a write");
    }
    ON.store(false, Ordering::Relaxed);
    stream.shutdown().await.expect("the close");
    assert_eq!(reader.await.expect("the reader"), 1040 * WRITE as u64);
    let allocs = ALLOCS.load(Ordering::Relaxed);
    assert!(allocs <= MARGIN, "{allocs} allocations for 4096 DATA frames of 16 KiB: over {MARGIN}");
}
