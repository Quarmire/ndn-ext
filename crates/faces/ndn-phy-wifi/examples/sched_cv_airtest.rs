//! Face-level confirmation (#74): the REAL `FaceScheduler` consumer, disciplined through the REAL
//! driver `mesh_common_view` → `ingest_common_view` path, reaches sub-µs common-view from a neighbour's
//! hardware timing beacon — no AP, no NTP. Proves the wired path end-to-end, not just the pieces.
//!
//!   sudo NDN_PID=a81a NDN_ROLE=master ./sched_cv_airtest 40 25          # o5p-0: HW timing beacon
//!   sudo NDN_PID=a81a NDN_ROLE=slave  NDN_SCHED_SLOT=8:3000 NDN_SCHED_CLOCK=cv \
//!        ./sched_cv_airtest 40 25                                        # o5p-1: real scheduler
//!
//! The slave feeds every mesh beacon into `FaceScheduler::ingest_common_view` (exactly as the medium RX
//! reader does) and reports `time_status()`: whether it hw-synced and the jitter of the disciplined
//! offset = the precision the scheduler's `CommonView` epoch actually achieves.

use std::sync::Arc;
use std::time::{Duration, Instant};

use ndn_phy_wifi::{Bandwidth, FaceScheduler, LibUsbRtl88xxBackend};
use ndn_frame_io::FrameIo;

const BSSID: [u8; 6] = [0x02, 0x4e, 0x44, 0x4e, 0xca, 0xfe]; // locally-administered (mesh)

fn timing_beacon() -> Vec<u8> {
    let mut f = Vec::with_capacity(64);
    f.extend_from_slice(&[0x80, 0x00, 0x00, 0x00]);
    f.extend_from_slice(&[0xff; 6]);
    f.extend_from_slice(&BSSID);
    f.extend_from_slice(&BSSID);
    f.extend_from_slice(&[0x00, 0x00]); // seq
    f.extend_from_slice(&[0u8; 8]); // Timestamp — HW fills at TX
    f.extend_from_slice(&[0x64, 0x00, 0x00, 0x00]); // interval + cap
    f.extend_from_slice(&[0x00, 0x04, b'N', b'D', b'N', b'T']);
    f.extend_from_slice(&[0x01, 0x01, 0x8b]);
    f
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ch: u8 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(40);
    let secs: u64 = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(25);
    let pid: u16 = std::env::var("NDN_PID")
        .ok()
        .and_then(|s| u16::from_str_radix(s.trim_start_matches("0x"), 16).ok())
        .unwrap_or(0xa81a);
    let master = std::env::var("NDN_ROLE").as_deref() == Ok("master");

    let d = Arc::new(LibUsbRtl88xxBackend::open_monitor_pid(pid, ch)?);
    let _pump = d.spawn_rx_pump(8);
    let deadline = Instant::now() + Duration::from_secs(secs);

    if master {
        // Reference node: arm the hardware timing beacon (a self-contained window) and hold.
        d.emit_timing_frame(&timing_beacon(), 100)?;
        println!(
            "sched_cv_airtest MASTER: HW timing beacon armed on {BSSID:02x?} ch{ch} for {secs}s"
        );
        while Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        let _ = d.stop_timing_beacon();
        return Ok(());
    }

    // Slave: the REAL FaceScheduler in CommonView mode. NDN_SCHED_SLOT + NDN_SCHED_CLOCK=cv must be set.
    let sched = Arc::new(
        FaceScheduler::from_env(None, Bandwidth::default(), 1500)
            .ok_or("set NDN_SCHED_SLOT (+ NDN_SCHED_CLOCK=cv)")?,
    );
    println!("sched_cv_airtest SLAVE: {}", sched.describe());

    // Feed the scheduler EXACTLY as the medium RX reader does: on_rx_stamp for every frame, and poll the
    // driver's mesh_common_view → ingest_common_view for each fresh neighbour beacon.
    let mut last_cv = 0u64;
    let mut offsets: Vec<i64> = Vec::new();
    let warmup = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if let Ok(Ok(f)) = tokio::time::timeout(Duration::from_millis(5), d.recv_frame()).await
            && let Some(s) = f.stamp.as_ref()
        {
            sched.on_rx_stamp(s);
        }
        if let Some(mcv) = d.mesh_common_view()
            && mcv.count != last_cv
        {
            last_cv = mcv.count;
            sched.ingest_mesh_beacon(mcv.peer_tsf, mcv.our_rxtsfl, mcv.bssid);
            if Instant::now() >= warmup
                && let Some(off) = sched.cv_offset_us()
            {
                offsets.push(off);
            }
        }
    }

    let st = sched.time_status();
    println!(
        "\n=== SLAVE RESULT ===\nhw_synced={}  common_view_now={} µs  offset={:?} µs  beacons={}",
        st.hw_synced,
        st.now_us,
        st.offset_us,
        offsets.len(),
    );
    if offsets.len() >= 3 {
        let diffs: Vec<i64> = offsets
            .windows(2)
            .map(|w| w[1] - w[0])
            .filter(|d| d.abs() < 100_000)
            .collect();
        let mean = diffs.iter().sum::<i64>() as f64 / diffs.len().max(1) as f64;
        let var = diffs
            .iter()
            .map(|&x| (x as f64 - mean).powi(2))
            .sum::<f64>()
            / diffs.len().max(1) as f64;
        let (lo, hi) = (offsets.iter().min().unwrap(), offsets.iter().max().unwrap());
        println!(
            "scheduler CommonView precision: first-diff std={:.2} µs, offset spread={} µs  → {}",
            var.sqrt(),
            hi - lo,
            if var.sqrt() < 10.0 {
                "SUB-µs..µs HARDWARE common-view, self-contained (no AP)"
            } else {
                "check sync"
            },
        );
    } else {
        println!("no mesh beacons heard — is the master emitting on this channel?");
    }
    Ok(())
}
