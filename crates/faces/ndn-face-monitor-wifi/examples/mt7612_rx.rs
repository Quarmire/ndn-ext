//! MT7612U bring-up step 3: firmware + MCU + MAC init replay + promiscuous
//! monitor RX, then listen on bulk-IN for ambient frames. Reports whether ANY
//! RX bursts arrive (the "is the receiver alive" check) and a hexdump of the
//! first few. `cargo run -p ndn-face-monitor-wifi --features libusb-backend --example mt7612_rx`
#[cfg(feature = "libusb-backend")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use ndn_face_monitor_wifi::Mt7612uBackend;
    use std::time::{Duration, Instant};

    println!("opening MT7612U ...");
    let dev = Mt7612uBackend::open()?;
    println!("full bring-up (firmware + MAC/BB init + 473 MCU cmds) ...");
    dev.bring_up()?;
    println!("chip 0x{:04x}  MAC {:02x?}", dev.chip_id()?, dev.mac_address()?);
    println!("tuning RF to channel 6 (2.4GHz) ...");
    dev.set_channel_ch6()?;
    dev.setup_monitor_rx()?;
    dev.pause_drain(true); // stop the init-time drain stealing RX frames
    println!("listening 5s on bulk-IN for ambient frames ...");

    let mut buf = vec![0u8; 8192];
    let deadline = Instant::now() + Duration::from_secs(5);
    let (mut bursts, mut bytes, mut shown) = (0u32, 0usize, 0u32);
    while Instant::now() < deadline {
        let n = dev.read_rx(&mut buf)?;
        if n > 0 {
            bursts += 1;
            bytes += n;
            if shown < 3 {
                shown += 1;
                let head = &buf[..n.min(48)];
                println!("  RX burst {n} bytes: {}",
                    head.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" "));
            }
        }
    }
    println!("\nRESULT: {bursts} RX bursts, {bytes} bytes total in 5s.");
    if bursts > 0 {
        println!("  ✅ RX path is ALIVE (frames arriving on bulk-IN).");
    } else {
        println!("  ❌ no RX — likely needs the MCU channel-set commands (RF not tuned).");
    }
    let _ = std::thread::sleep(Duration::from_millis(0));
    Ok(())
}
#[cfg(not(feature = "libusb-backend"))]
fn main() {}
