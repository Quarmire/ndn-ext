//! Linux-only: sample on-CPU threads without `perf` (the sampler of `carrier_bench`, for the
//! examples that do not carry it). A per-thread CPU-time timer (`timer_create`, CPUCLOCK_SCHED of
//! the tid) signals its own thread; the handler stores the interrupted instruction pointer. A
//! thread that was inside a system call is interrupted on its way back to user space, so its
//! sample lands on the libc wrapper of the call: kernel time shows as that call.
//!
//! `dump` writes one TSV line per (thread name, module, offset): the count. Resolve the offsets
//! with `nm`/`addr2line` against the module's file.

#![allow(unsafe_code)]

use std::collections::BTreeMap;
use std::io::Write as _;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

const CAP: usize = 1 << 19;
static IDX: AtomicUsize = AtomicUsize::new(0);
static TID: [AtomicU64; CAP] = [const { AtomicU64::new(0) }; CAP];
static RIP: [AtomicU64; CAP] = [const { AtomicU64::new(0) }; CAP];

extern "C" fn on_prof(_sig: libc::c_int, _info: *mut libc::siginfo_t, ctx: *mut libc::c_void) {
    // SAFETY: the kernel passes a ucontext_t for a SA_SIGINFO handler; gettid takes no pointers.
    let (rip, tid) = unsafe {
        let uc = ctx as *const libc::ucontext_t;
        (
            (*uc).uc_mcontext.gregs[libc::REG_RIP as usize] as u64,
            libc::syscall(libc::SYS_gettid) as u64,
        )
    };
    let i = IDX.fetch_add(1, Ordering::Relaxed);
    if i < CAP {
        TID[i].store(tid, Ordering::Relaxed);
        RIP[i].store(rip, Ordering::Relaxed);
    }
}

/// Start a 1 kHz (nominal; the kernel checks CPU timers at its tick) CPU-time sampler on each tid.
pub fn start(tids: &[u32]) {
    // SAFETY: plain libc calls with initialised structures; the handler only touches statics.
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_prof as extern "C" fn(_, _, _) as usize;
        sa.sa_flags = libc::SA_SIGINFO | libc::SA_RESTART;
        libc::sigemptyset(&mut sa.sa_mask);
        assert_eq!(libc::sigaction(libc::SIGPROF, &sa, std::ptr::null_mut()), 0);
        for &tid in tids {
            let clock: libc::clockid_t = ((!(tid as i32)) << 3) | 4 | 2;
            let mut ev: libc::sigevent = std::mem::zeroed();
            ev.sigev_notify = libc::SIGEV_THREAD_ID;
            ev.sigev_signo = libc::SIGPROF;
            ev.sigev_notify_thread_id = tid as i32;
            let mut timer: libc::timer_t = std::ptr::null_mut();
            if libc::timer_create(clock, &mut ev, &mut timer) != 0 {
                eprintln!(
                    "timer_create for {tid}: {}",
                    std::io::Error::last_os_error()
                );
                continue;
            }
            let every = libc::timespec {
                tv_sec: 0,
                tv_nsec: 1_000_000,
            };
            let spec = libc::itimerspec {
                it_interval: every,
                it_value: every,
            };
            libc::timer_settime(timer, 0, &spec, std::ptr::null_mut());
        }
    }
}

fn samples() -> Vec<(u32, u64)> {
    let n = IDX.load(Ordering::Relaxed).min(CAP);
    (0..n)
        .map(|i| {
            (
                TID[i].load(Ordering::Relaxed) as u32,
                RIP[i].load(Ordering::Relaxed),
            )
        })
        .collect()
}

/// Write the samples taken so far to `path`, by the thread names in `names`.
pub fn dump(path: &str, names: &BTreeMap<u32, String>) {
    let maps: Vec<(u64, u64, u64, String)> = std::fs::read_to_string("/proc/self/maps")
        .unwrap()
        .lines()
        .filter_map(|l| {
            let mut f = l.split_whitespace();
            let (range, _perm, off, _dev, _ino) =
                (f.next()?, f.next()?, f.next()?, f.next()?, f.next()?);
            let file = f.next()?.to_owned();
            let (lo, hi) = range.split_once('-')?;
            Some((
                u64::from_str_radix(lo, 16).ok()?,
                u64::from_str_radix(hi, 16).ok()?,
                u64::from_str_radix(off, 16).ok()?,
                file,
            ))
        })
        .collect();
    let mut counts: BTreeMap<(String, String, u64), u64> = BTreeMap::new();
    let all = samples();
    for &(tid, rip) in &all {
        let name = names
            .get(&tid)
            .cloned()
            .unwrap_or_else(|| format!("tid{tid}"));
        let (module, off) = maps
            .iter()
            .find(|(lo, hi, _, _)| (*lo..*hi).contains(&rip))
            .map_or(("?".to_owned(), rip), |(lo, _, off, file)| {
                (file.clone(), rip - lo + off)
            });
        *counts.entry((name, module, off)).or_default() += 1;
    }
    let mut f = std::fs::File::create(path).unwrap();
    for ((name, module, off), n) in counts {
        writeln!(f, "{name}\t{module}\t{off:#x}\t{n}").unwrap();
    }
    println!("profile: {} samples written to {path}", all.len());
}
