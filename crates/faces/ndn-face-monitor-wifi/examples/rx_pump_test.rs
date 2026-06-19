//! USB RX pipelining probe: count frames received via `recv_frame` during a
//! high-rate peer flood, with and without the background RX pump. Pumped keeps
//! several bulk-IN transfers in flight so the RX FIFO doesn't overflow between
//! reads (the userspace-RX throughput ceiling).
//!
//! Usage: `rx_pump_test [ch] [secs] [depth]`   env RX_PUMP=1 to enable the pump
#[cfg(feature = "libusb-backend")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use ndn_face_monitor_wifi::{LibUsbRtl88xxBackend, FrameIo};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    let mut a = std::env::args().skip(1);
    let ch: u8 = a.next().and_then(|s| s.parse().ok()).unwrap_or(149);
    let secs: u64 = a.next().and_then(|s| s.parse().ok()).unwrap_or(8);
    let depth: usize = a.next().and_then(|s| s.parse().ok()).unwrap_or(4);

    let b = Arc::new(LibUsbRtl88xxBackend::open_monitor(ch)?);
    let pumped = std::env::var("RX_PUMP").is_ok();
    let _pump = pumped.then(|| b.spawn_rx_pump(depth));
    println!(
        "counting recv_frame frames for {secs}s on ch{ch}, RX pump {}",
        if pumped { format!("ON (depth {depth})") } else { "OFF".into() }
    );

    let t0 = Instant::now();
    let mut total = 0u64;
    let mut from_peer = 0u64;
    while t0.elapsed().as_secs() < secs {
        if let Ok(Ok(f)) =
            tokio::time::timeout(Duration::from_millis(300), b.recv_frame()).await
        {
            total += 1;
            if matches!(f.addr, Some(a) if a[..4] == [0x02, 0x4e, 0x44, 0x4e]) {
                from_peer += 1;
            }
        }
    }
    let dt = t0.elapsed().as_secs_f64();
    println!(
        "received {total} frames ({from_peer} from peer) in {dt:.1}s = {:.0} fr/s",
        total as f64 / dt
    );
    Ok(())
}

#[cfg(not(feature = "libusb-backend"))]
fn main() {
    eprintln!("rebuild with `--features libusb-backend` (needs an RTL8812EU dongle)");
}
