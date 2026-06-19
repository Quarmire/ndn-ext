//! MT7612U TX throughput via the dedicated TX-pump thread (no per-frame
//! spawn_blocking). Measures payload goodput for single-frame `inject` vs
//! A-MSDU `inject_batch`, timing the pump actually writing the frames (tx_count).
//! `--features libusb-backend --example mt7612_throughput`
#[cfg(feature = "libusb-backend")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use bytes::Bytes;
    use ndn_face_monitor_wifi::{FrameIo, InjectFrame, McsDescriptor, Mt7612uBackend};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    let dev = Arc::new(Mt7612uBackend::open()?);
    dev.bring_up()?;
    dev.set_channel_ch6()?;
    dev.setup_monitor_rx()?;
    dev.pause_drain(true);
    let depth: usize = std::env::var("NDN_TX_DEPTH").ok().and_then(|s| s.parse().ok()).unwrap_or(16);
    let _tx = dev.spawn_tx_pump(depth);
    println!("chip 0x{:04x}, TX pump depth={depth}", dev.chip_id()?);

    let mcs = McsDescriptor::ht(7);
    let mbps = |bytes: usize, e: Duration| (bytes as f64 * 8.0) / e.as_secs_f64() / 1e6;

    // Sweep payload size: single plain-data frames through the depth pump. Shows
    // whether large frames write fully (got==n) and how goodput scales with size
    // (the device serializes at a fixed per-MPDU rate → bigger frames = more Mb/s).
    for plen in [256usize, 1000, 2000, 3000, 4000] {
        let payload = Bytes::from(vec![0xA5u8; plen]);
        let n = 6000usize;
        let base = dev.tx_count_written();
        let t = Instant::now();
        for _ in 0..n {
            dev.inject(InjectFrame::broadcast(payload.clone(), mcs)).await?;
        }
        while dev.tx_count_written() - base < n as u64 && t.elapsed() < Duration::from_secs(30) {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        let el = t.elapsed();
        let got = (dev.tx_count_written() - base) as usize;
        println!("plen={plen:4}: {got}/{n} written, {:.2}s = {:6.1} Mb/s payload, {:5.0} fps",
                 el.as_secs_f64(), mbps(got * plen, el), got as f64 / el.as_secs_f64());
    }
    println!("done.");
    Ok(())
}
#[cfg(not(feature = "libusb-backend"))]
fn main() {}
