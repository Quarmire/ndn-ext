//! What `carrier_bench` and `side_ping` share: the per-thread CPU of a window (from /proc, Linux
//! only), the two runtimes, and the median and trimmed percentiles they report.

use std::collections::BTreeMap;
use std::sync::Arc;

#[derive(Clone, Debug)]
pub struct ThreadCpu {
    pub name: String,
    /// On-CPU time and time waiting on a run queue, ns (schedstat).
    pub ns: u64,
    pub waited_ns: u64,
    /// User and system ticks (stat), 1/100 s.
    pub user: u64,
    pub sys: u64,
}

pub fn threads() -> BTreeMap<u32, ThreadCpu> {
    let mut out = BTreeMap::new();
    for e in std::fs::read_dir("/proc/self/task").unwrap().flatten() {
        let tid: u32 = e.file_name().to_string_lossy().parse().unwrap();
        let p = e.path();
        let (Ok(stat), Ok(sched)) = (
            std::fs::read_to_string(p.join("stat")),
            std::fs::read_to_string(p.join("schedstat")),
        ) else {
            continue;
        };
        let (open, close) = (stat.find('(').unwrap(), stat.rfind(')').unwrap());
        let rest: Vec<&str> = stat[close + 2..].split(' ').collect();
        let mut sched = sched.split(' ');
        out.insert(
            tid,
            ThreadCpu {
                name: stat[open + 1..close].to_owned(),
                ns: sched.next().unwrap().parse().unwrap(),
                waited_ns: sched.next().unwrap().parse().unwrap(),
                user: rest[11].parse().unwrap(),
                sys: rest[12].parse().unwrap(),
            },
        );
    }
    out
}

/// CPU per thread over a window: cores used, the system share of it, and the share of the
/// window the thread waited on a run queue.
pub fn cpu_line(
    before: &BTreeMap<u32, ThreadCpu>,
    after: &BTreeMap<u32, ThreadCpu>,
    wall: f64,
) -> String {
    let mut rows = Vec::new();
    for (tid, a) in after {
        let Some(b) = before.get(tid) else { continue };
        let cores = a.ns.saturating_sub(b.ns) as f64 / 1e9 / wall;
        let (u, s) = (a.user - b.user, a.sys - b.sys);
        if cores < 0.005 {
            continue;
        }
        let system = if u + s == 0 {
            0.0
        } else {
            s as f64 / (u + s) as f64
        };
        let queued = a.waited_ns.saturating_sub(b.waited_ns) as f64 / 1e9 / wall;
        rows.push(format!(
            "{}#{tid} {cores:.2} cores ({:.0}% system, {:.0}% of the window waiting for a CPU)",
            a.name,
            system * 100.0,
            queued * 100.0
        ));
    }
    rows.join(", ")
}

pub fn runtime(name: &str, workers: usize) -> Arc<tokio::runtime::Runtime> {
    Arc::new(
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(workers)
            .thread_name(name)
            .enable_all()
            .build()
            .unwrap(),
    )
}

/// Median, minimum and maximum.
pub fn median(v: &mut [f64]) -> (f64, f64, f64) {
    v.sort_by(f64::total_cmp);
    (v[v.len() / 2], v[0], v[v.len() - 1])
}

/// p50, p99 and mean of the samples after the lowest and the highest percent are dropped.
pub fn trimmed(samples: &mut [f64]) -> (f64, f64, f64) {
    samples.sort_by(f64::total_cmp);
    let kept = &samples[samples.len() / 100..samples.len() - samples.len() / 100];
    let mean = kept.iter().sum::<f64>() / kept.len() as f64;
    (kept[kept.len() / 2], kept[kept.len() * 99 / 100], mean)
}
