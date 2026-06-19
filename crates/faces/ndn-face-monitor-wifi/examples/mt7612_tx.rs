//! MT7612U TX radiation test: bring up the device, tune to channel 6, then
//! transmit probe-request frames on ep 0x07 — first the captured kernel bulk
//! verbatim (`tx_raw_probe`), then frames built by our own `transmit()` with a
//! distinct source MAC. Verify radiation by capturing on a *second* receiver
//! (the Realtek wlu1 in kernel monitor mode on ch6) and looking for the frames.
//! `cargo run -p ndn-face-monitor-wifi --features libusb-backend --example mt7612_tx`
#[cfg(feature = "libusb-backend")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use ndn_face_monitor_wifi::Mt7612uBackend;
    use std::time::Duration;

    println!("opening MT7612U ...");
    let dev = Mt7612uBackend::open()?;
    println!("bring-up + channel 6 ...");
    dev.bring_up()?;
    dev.set_channel_ch6()?;
    dev.setup_monitor_rx()?; // enables MT_MAC_SYS_CTRL ENABLE_TX
    dev.pause_drain(true);
    std::thread::sleep(Duration::from_millis(200));

    // Our own probe request, distinct SA 02:11:22:33:44:55 so it's
    // distinguishable from the verbatim kernel probe (SA 8a:0a:96:d7:24:48).
    let mut frame: Vec<u8> = Vec::new();
    frame.extend_from_slice(&[0x40, 0x00]); // FC: mgmt / probe-request
    frame.extend_from_slice(&[0x00, 0x00]); // duration
    frame.extend_from_slice(&[0xff; 6]); // DA broadcast
    frame.extend_from_slice(&[0x02, 0x11, 0x22, 0x33, 0x44, 0x55]); // SA
    frame.extend_from_slice(&[0xff; 6]); // BSSID broadcast
    frame.extend_from_slice(&[0x00, 0x00]); // seq
    frame.extend_from_slice(&[0x00, 0x00]); // SSID IE (wildcard)
    frame.extend_from_slice(&[0x01, 0x08, 0x0c, 0x12, 0x18, 0x24, 0x30, 0x48, 0x60, 0x6c]); // rates

    let n = 400u32;
    println!("TX {n}× verbatim kernel probe (SA 8a:0a:96:d7:24:48) ...");
    let mut ok = 0u32;
    for _ in 0..n {
        if dev.tx_raw_probe().is_ok() {
            ok += 1;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    println!("  verbatim TX: {ok}/{n} writes accepted");

    println!("TX {n}× our transmit() probe (SA 02:11:22:33:44:55) ...");
    let mut ok2 = 0u32;
    for _ in 0..n {
        if dev.transmit(&frame).is_ok() {
            ok2 += 1;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    println!("  transmit() TX: {ok2}/{n} writes accepted");
    println!("done — check the monitor receiver for probe requests.");
    Ok(())
}
#[cfg(not(feature = "libusb-backend"))]
fn main() {}
