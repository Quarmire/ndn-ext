//! Bring up and hold a single-tone CW carrier for N seconds (default 12). This
//! keys the PA directly, bypassing the MAC and BB modulator — so a peer/SDR
//! seeing RF energy proves the analog TX path is alive and isolates any
//! frame-TX gap to the MAC/BB datapath. Measure on the OPi with
//! `iw dev wlu1u2 survey dump` (channel-active/noise) before vs during.
//!
//! ```text
//! cargo run --example tone_hold -p ndn-face-monitor-wifi \
//!     --features libusb-backend -- [channel] [secs]
//! ```

#[cfg(feature = "libusb-backend")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use ndn_face_monitor_wifi::LibUsbRtl88xxBackend;

    let channel: u8 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(161);
    let secs: u64 = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(12);

    let b = LibUsbRtl88xxBackend::open()?;
    b.bring_up(channel)?;
    println!("up on ch{channel}; enabling single tone for {secs}s…");
    b.single_tone(true)?;
    std::thread::sleep(std::time::Duration::from_secs(secs));
    b.single_tone(false)?;
    println!("tone off");
    Ok(())
}

#[cfg(not(feature = "libusb-backend"))]
fn main() {}
