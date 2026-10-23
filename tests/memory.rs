//! Observe the Argon2 workspace while it is still allocated, immediately before
//! deallocation. This catches regressions to Argon2's non-wiping allocating API.
use std::{
    alloc::{GlobalAlloc, Layout, System},
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

struct ObservedAllocator;

const WORKSPACE_BYTES: usize = 65536 * 1024;
static OBSERVE: AtomicBool = AtomicBool::new(false);
static WORKSPACES: AtomicUsize = AtomicUsize::new(0);
static DIRTY_WORKSPACES: AtomicUsize = AtomicUsize::new(0);

// SAFETY: allocation operations delegate unchanged to System. Observation never
// allocates or panics and only reads the initialized Argon2 block array before
// returning it to System. This test binary has a single test.
unsafe impl GlobalAlloc for ObservedAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        unsafe { System.realloc(ptr, layout, size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if OBSERVE.load(Ordering::Relaxed)
            && layout.size() == WORKSPACE_BYTES
            && layout.align() == std::mem::align_of::<argon2::Block>()
        {
            WORKSPACES.fetch_add(1, Ordering::Relaxed);
            let bytes = unsafe { std::slice::from_raw_parts(ptr, layout.size()) };
            if bytes.iter().any(|byte| *byte != 0) {
                DIRTY_WORKSPACES.fetch_add(1, Ordering::Relaxed);
            }
        }
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: ObservedAllocator = ObservedAllocator;

#[test]
fn argon2_workspace_is_wiped_before_deallocation() {
    let vector: Vec<_> = include_str!("vectors.txt")
        .lines()
        .nth(1)
        .unwrap()
        .split('\t')
        .collect();
    let bits: String = hex::decode(vector[1])
        .unwrap()
        .iter()
        .map(|byte| format!("{byte:08b}"))
        .collect();
    OBSERVE.store(true, Ordering::Relaxed);
    let secret = paper_pgp::backup::derive(&bits, true);
    OBSERVE.store(false, Ordering::Relaxed);
    let secret = secret.unwrap();
    assert_eq!(hex::encode(secret.as_ref()), vector[2]);
    assert_eq!(WORKSPACES.load(Ordering::Relaxed), 1);
    assert_eq!(DIRTY_WORKSPACES.load(Ordering::Relaxed), 0);
}
