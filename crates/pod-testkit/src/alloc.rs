//! A counter of the allocations of a scope (T-824). A test binary makes
//! [`Counting`] its allocator, then [`count`] gives the allocations that a
//! closure made on this thread; the allocations of other threads, and those
//! out of a scope, do not count. A binary that does not set the allocator
//! counts nothing: [`count`] says so with `None`.
//!
//! ```ignore
//! #[global_allocator]
//! static ALLOC: pod_testkit::alloc::Counting = pod_testkit::alloc::Counting;
//! ```

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicBool, Ordering};

/// The system allocator, with a count for each thread in a scope.
pub struct Counting;

thread_local! {
    static ON: Cell<bool> = const { Cell::new(false) };
    static ALLOCS: Cell<u64> = const { Cell::new(0) };
}

/// Set at the first allocation through [`Counting`].
static INSTALLED: AtomicBool = AtomicBool::new(false);

fn note() {
    INSTALLED.store(true, Ordering::Relaxed);
    // A thread that is ending has no local: it counts nothing.
    let _ = ON.try_with(|on| {
        if on.get() {
            let _ = ALLOCS.try_with(|n| n.set(n.get() + 1));
        }
    });
}

// SAFETY: each call goes to the system allocator with the same arguments;
// the counts are of this thread, in cells with a const start.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        note();
        // SAFETY: the caller keeps the contract of `GlobalAlloc::alloc`.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        note();
        // SAFETY: the caller keeps the contract of `GlobalAlloc::alloc_zeroed`.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: `ptr` came from this allocator with `layout`.
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        note();
        // SAFETY: the caller keeps the contract of `GlobalAlloc::realloc`.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

/// The value of `f`, and the allocations that it made on this thread;
/// `None` for the count where [`Counting`] is not the allocator.
pub fn count<R>(f: impl FnOnce() -> R) -> (R, Option<u64>) {
    // An allocation that proves the allocator, out of the scope.
    drop(std::hint::black_box(Box::new(0u8)));
    ALLOCS.with(|n| n.set(0));
    ON.with(|on| on.set(true));
    let value = f();
    ON.with(|on| on.set(false));
    let made = ALLOCS.with(|n| n.get());
    (value, INSTALLED.load(Ordering::Relaxed).then_some(made))
}
