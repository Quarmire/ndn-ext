//! Async USB TX ring (libusb URBs). `rusb`'s synchronous `write_bulk` submits one
//! transfer and blocks for its completion (~0.7ms round-trip), hiding the device's
//! true ~5µs/MPDU rate — measured: the kernel pipelines back-to-back transfers
//! 5µs apart, ours 700µs apart (140× gap). This ring **submits ahead**: many
//! transfers in flight, completions handled on one dedicated event thread, so the
//! USB transfer rate stops bounding throughput. Built on `libusb1-sys` (the same
//! libusb backend `rusb` already uses — no new USB dependency). Linux-only.

use std::os::raw::{c_int, c_void};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use libusb1_sys as ffi;
use ndn_transport::FaceError;
use rusb::{Context, DeviceHandle, UsbContext};

use super::init_err;

const LIBUSB_TRANSFER_COMPLETED: c_int = 0;

struct Counters {
    completed: AtomicU64,
    bytes: AtomicU64,
    errors: AtomicU64,
    outstanding: AtomicI64,
}

/// Per-transfer user data: owns the TX buffer (kept alive until completion) and a
/// handle to the shared counters. Boxed, passed as the transfer's `user_data`,
/// reclaimed (and the buffer freed) in the completion callback.
struct Job {
    _buf: Vec<u8>,
    counters: Arc<Counters>,
}

extern "system" fn on_complete(t: *mut ffi::libusb_transfer) {
    unsafe {
        let job = Box::from_raw((*t).user_data as *mut Job);
        job.counters.outstanding.fetch_sub(1, Ordering::Relaxed);
        if (*t).status == LIBUSB_TRANSFER_COMPLETED {
            job.counters.completed.fetch_add(1, Ordering::Relaxed);
            job.counters.bytes.fetch_add((*t).actual_length as u64, Ordering::Relaxed);
        } else {
            job.counters.errors.fetch_add(1, Ordering::Relaxed);
        }
        ffi::libusb_free_transfer(t);
        // `job` (and its buffer) dropped here.
    }
}

struct SendCtx(*mut ffi::libusb_context);
unsafe impl Send for SendCtx {}

/// An async TX ring over one bulk-OUT endpoint. NOTE: while a ring is active, do
/// NOT also do synchronous transfers (e.g. RX `read_bulk`) on the same context —
/// libusb event completions would be consumed by the ring's event thread. The ring
/// is for TX-saturating workloads; pause the RX drain first.
pub struct TxRing {
    handle: Arc<DeviceHandle<Context>>,
    ep: u8,
    counters: Arc<Counters>,
    running: Arc<AtomicBool>,
    event_thread: Option<JoinHandle<()>>,
    max_outstanding: i64,
}

impl TxRing {
    pub fn new(handle: Arc<DeviceHandle<Context>>, ep: u8, max_outstanding: usize) -> Self {
        let counters = Arc::new(Counters {
            completed: AtomicU64::new(0),
            bytes: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            outstanding: AtomicI64::new(0),
        });
        let running = Arc::new(AtomicBool::new(true));
        let ctx = SendCtx(handle.context().as_raw());
        let r2 = running.clone();
        let event_thread = std::thread::spawn(move || {
            let ctx = ctx; // move the raw ctx in
            let tv = libc::timeval { tv_sec: 0, tv_usec: 100_000 };
            while r2.load(Ordering::Relaxed) {
                unsafe {
                    ffi::libusb_handle_events_timeout(ctx.0, &tv);
                }
            }
        });
        TxRing {
            handle,
            ep,
            counters,
            running,
            event_thread: Some(event_thread),
            max_outstanding: max_outstanding as i64,
        }
    }

    /// Submit a pre-built USB bulk for async TX. Spins (backpressure) when
    /// `max_outstanding` transfers are already in flight.
    pub fn submit(&self, buf: Vec<u8>) -> Result<(), FaceError> {
        while self.counters.outstanding.load(Ordering::Relaxed) >= self.max_outstanding {
            std::hint::spin_loop();
        }
        unsafe {
            let t = ffi::libusb_alloc_transfer(0);
            if t.is_null() {
                return Err(init_err("mt7612u tx ring: alloc_transfer failed".into()));
            }
            let job = Box::new(Job {
                counters: self.counters.clone(),
                _buf: buf,
            });
            let len = job._buf.len() as c_int;
            let ptr = job._buf.as_ptr() as *mut u8;
            let job_raw = Box::into_raw(job);
            ffi::libusb_fill_bulk_transfer(
                t,
                self.handle.as_raw(),
                self.ep,
                ptr,
                len,
                on_complete,
                job_raw as *mut c_void,
                1000,
            );
            self.counters.outstanding.fetch_add(1, Ordering::Relaxed);
            let r = ffi::libusb_submit_transfer(t);
            if r != 0 {
                self.counters.outstanding.fetch_sub(1, Ordering::Relaxed);
                drop(Box::from_raw(job_raw));
                ffi::libusb_free_transfer(t);
                return Err(init_err(format!("mt7612u tx ring: submit_transfer {r}")));
            }
        }
        Ok(())
    }

    pub fn completed(&self) -> u64 {
        self.counters.completed.load(Ordering::Relaxed)
    }
    pub fn errors(&self) -> u64 {
        self.counters.errors.load(Ordering::Relaxed)
    }
    pub fn outstanding(&self) -> i64 {
        self.counters.outstanding.load(Ordering::Relaxed)
    }

    /// Wait until all in-flight transfers complete (or `timeout` elapses).
    pub fn drain(&self, timeout: Duration) {
        let start = Instant::now();
        while self.outstanding() > 0 && start.elapsed() < timeout {
            std::thread::sleep(Duration::from_micros(100));
        }
    }

    /// Ground-truth saturation: send `count` copies of `buf` as fast as the device
    /// will accept them, using the canonical libusb streaming pattern — pre-submit
    /// `max_outstanding` transfers, then **resubmit each transfer from inside its own
    /// completion callback** on the event thread. The submitting (main) thread does
    /// nothing but wait, so it never contends with the event thread for CPU or the
    /// libusb lock. This is the difference between `submit()`'s ~500µs/transfer
    /// (main-thread spin-refill) and the device's true back-to-back rate (~26µs).
    /// Returns `(completed, errors)`. All transfers point at one shared buffer.
    pub fn saturate(&self, buf: Vec<u8>, count: usize) -> (u64, u64) {
        let initial = (self.max_outstanding as usize).min(count);
        let st = Box::new(SatState {
            to_submit: AtomicI64::new(count as i64 - initial as i64),
            completed: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            inflight: AtomicI64::new(0),
            handle: self.handle.as_raw(),
            ep: self.ep,
            buf_ptr: buf.as_ptr() as *mut u8,
            buf_len: buf.len() as c_int,
            _buf: buf,
        });
        let st_raw = Box::into_raw(st);
        unsafe {
            let s = &*st_raw;
            for _ in 0..initial {
                let t = ffi::libusb_alloc_transfer(0);
                if t.is_null() {
                    s.errors.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                ffi::libusb_fill_bulk_transfer(
                    t,
                    s.handle,
                    s.ep,
                    s.buf_ptr,
                    s.buf_len,
                    on_sat_complete,
                    st_raw as *mut c_void,
                    1000,
                );
                s.inflight.fetch_add(1, Ordering::Relaxed);
                if ffi::libusb_submit_transfer(t) != 0 {
                    s.inflight.fetch_sub(1, Ordering::Relaxed);
                    s.errors.fetch_add(1, Ordering::Relaxed);
                    ffi::libusb_free_transfer(t);
                }
            }
            // Wait for the self-sustaining ring to drain (event thread does all work).
            while s.inflight.load(Ordering::Relaxed) > 0 {
                std::thread::sleep(Duration::from_micros(50));
            }
            let done = s.completed.load(Ordering::Relaxed);
            let errs = s.errors.load(Ordering::Relaxed);
            drop(Box::from_raw(st_raw));
            (done, errs)
        }
    }
}

/// Shared state for `saturate` — one instance backs every transfer in the ring
/// (passed as `user_data`), so it must outlive all in-flight transfers. The event
/// thread (callback) and the main thread touch only the atomics; the raw handle /
/// buffer pointers are read-only after construction.
struct SatState {
    to_submit: AtomicI64,
    completed: AtomicU64,
    errors: AtomicU64,
    inflight: AtomicI64,
    handle: *mut ffi::libusb_device_handle,
    ep: u8,
    buf_ptr: *mut u8,
    buf_len: c_int,
    _buf: Vec<u8>,
}

/// Completion callback for `saturate`: count the result, then — while work remains
/// — **resubmit this same transfer** to keep the ring full without any main-thread
/// involvement. libusb explicitly permits resubmitting a transfer from within its
/// own callback; this is the documented streaming pattern.
extern "system" fn on_sat_complete(t: *mut ffi::libusb_transfer) {
    unsafe {
        let s = &*((*t).user_data as *const SatState);
        if (*t).status == LIBUSB_TRANSFER_COMPLETED {
            s.completed.fetch_add(1, Ordering::Relaxed);
        } else {
            s.errors.fetch_add(1, Ordering::Relaxed);
        }
        if s.to_submit.fetch_sub(1, Ordering::Relaxed) > 0 {
            if ffi::libusb_submit_transfer(t) != 0 {
                s.errors.fetch_add(1, Ordering::Relaxed);
                s.inflight.fetch_sub(1, Ordering::Relaxed);
                ffi::libusb_free_transfer(t);
            }
        } else {
            s.inflight.fetch_sub(1, Ordering::Relaxed);
            ffi::libusb_free_transfer(t);
        }
    }
}

impl Drop for TxRing {
    fn drop(&mut self) {
        self.drain(Duration::from_secs(2));
        self.running.store(false, Ordering::Relaxed);
        if let Some(j) = self.event_thread.take() {
            let _ = j.join();
        }
    }
}
