#![no_std]
//! Comparator module for the CRYPTO_TRANSFER_VERIFY family.
//!
//! Scores a miner's integer answer against the reference value, in basis points (0..=10000),
//! following the network's reference rule: Exact, AbsTol, RelTol, PassFail.

const ONE: i64 = 10_000;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    core::arch::wasm32::unreachable()
}

const HEAP_LEN: usize = 4096;
static mut HEAP: [u8; HEAP_LEN] = [0; HEAP_LEN];
static mut NEXT: usize = 0;

/// Hands out space for the 16-byte comparison spec. Space is reused once the heap wraps.
#[no_mangle]
pub extern "C" fn imw_alloc(size: i32) -> i32 {
    let size = if size < 1 { 1 } else { size as usize };
    if size > HEAP_LEN {
        return 0;
    }
    unsafe {
        let mut start = (NEXT + 7) & !7;
        if start + size > HEAP_LEN {
            start = 0;
        }
        NEXT = start + size;
        (core::ptr::addr_of_mut!(HEAP) as *mut u8).add(start) as i32
    }
}

#[no_mangle]
pub extern "C" fn imw_free(_ptr: i32, _size: i32) {}

fn linear_decay(err: i64, tol: i64) -> i64 {
    if tol <= 0 {
        return if err == 0 { ONE } else { 0 };
    }
    let window = tol.saturating_mul(2);
    if err >= window {
        return 0;
    }
    ONE.saturating_mul(window.wrapping_sub(err)) / window
}

#[no_mangle]
pub extern "C" fn imw_score_deterministic(truth: i64, miner: i64, spec_ptr: i32) -> i64 {
    let (code, tol) = unsafe {
        let p = spec_ptr as usize as *const i64;
        (p.read_unaligned(), p.add(1).read_unaligned())
    };
    let diff = miner.wrapping_sub(truth).wrapping_abs();
    match code as i32 {
        1 => linear_decay(diff, tol),
        2 => {
            let mut denom = truth.wrapping_abs();
            if denom < 1 {
                denom = 1;
            }
            let q = (diff as i128) * (ONE as i128) / (denom as i128);
            let err = if q >= i64::MIN as i128 && q <= i64::MAX as i128 { q as i64 } else { i64::MAX };
            linear_decay(err, tol)
        }
        _ => {
            if miner == truth {
                ONE
            } else {
                0
            }
        }
    }
}
