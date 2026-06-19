//! Diagnose MT7612U control-transfer latency (the replay bottleneck): time bulk
//! register writes before vs after the MCU is running.
//! `cargo run -p ndn-face-monitor-wifi --features libusb-backend --example mt7612_bench`
#[cfg(feature = "libusb-backend")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use ndn_face_monitor_wifi::Mt7612uBackend;
    use std::time::Instant;

    let dev = Mt7612uBackend::open()?;
    let bench = |label: &str, n: u32, dev: &Mt7612uBackend| -> Result<(), Box<dyn std::error::Error>> {
        // write a benign register (MT_MAC_SYS_CTRL) n times
        let t = Instant::now();
        for _ in 0..n {
            dev.wr(0x1004, 0x0000_000c)?;
        }
        let us = t.elapsed().as_micros() as f64 / n as f64;
        println!("  {label}: {us:.1} µs/write ({:.1} ms for {n})", us * n as f64 / 1000.0);
        Ok(())
    };
    let bench_rd = |label: &str, n: u32, dev: &Mt7612uBackend| -> Result<(), Box<dyn std::error::Error>> {
        let t = Instant::now();
        for _ in 0..n {
            let _ = dev.rr(0x1004)?;
        }
        let us = t.elapsed().as_micros() as f64 / n as f64;
        println!("  {label}: {us:.1} µs/read");
        Ok(())
    };

    println!("=== pre-firmware (cold) ===");
    bench("write", 300, &dev)?;
    bench_rd("read", 300, &dev)?;

    println!("loading firmware ...");
    dev.load_firmware()?;
    dev.start_mcu()?;

    println!("=== post-firmware (MCU running) ===");
    bench("write", 300, &dev)?;
    bench_rd("read", 300, &dev)?;
    Ok(())
}
#[cfg(not(feature = "libusb-backend"))]
fn main() {}
