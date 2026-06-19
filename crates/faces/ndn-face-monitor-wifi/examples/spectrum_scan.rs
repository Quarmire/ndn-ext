//! Spectrum-occupancy scan (ACS) — the cognitive-radio sensing front-end.
//!
//! Hops a list of 5 GHz channels and reads the chip's **CLM** (Channel Load
//! Measurement) engine on each: the BB counts 4 µs samples where the medium is
//! busy (energy above CCA), so this senses ALL occupancy — including
//! non-decodable interference that frame-counting misses. The result is a
//! channel busy-% map the named-data radio can use to pick clear spectrum
//! (frequency agility), instead of discovering congestion the hard way (e.g.
//! ch149's ~15% delivery hit vs a quiet channel).
//!
//! Usage: `spectrum_scan [window_ms] [ch ch ...]`
//!   window_ms  per-channel measurement window (default 50 ms)
//!   ch...      channels to scan (default: non-DFS UNII-1 + UNII-3)
#[cfg(feature = "libusb-backend")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use ndn_face_monitor_wifi::{ChannelBw, LibUsbRtl88xxBackend};
    use std::sync::Arc;

    let mut args = std::env::args().skip(1);
    let window_ms: u32 = args.next().and_then(|s| s.parse().ok()).unwrap_or(50);
    let channels: Vec<u8> = {
        let rest: Vec<u8> = args.filter_map(|s| s.parse().ok()).collect();
        if rest.is_empty() {
            // non-DFS, legal-to-TX 5 GHz: UNII-1 (36–48) + UNII-3 (149–165).
            vec![36, 40, 44, 48, 149, 153, 157, 161, 165]
        } else {
            rest
        }
    };

    // Bring up on the first channel; we re-tune per channel below.
    let backend = Arc::new(LibUsbRtl88xxBackend::open_monitor(channels[0])?);
    let window_us = window_ms * 1000;
    // RADIO_FAST_HOP=1 uses set_channel_fast (RF-only retune) for same-BW hops.
    let fast = std::env::var("RADIO_FAST_HOP").is_ok();
    println!(
        "spectrum scan — CLM busy-% over {window_ms} ms/channel ({} hop)\n",
        if fast { "fast" } else { "full" }
    );
    println!("  chan   freq(MHz)   switch   busy%   bar");
    for (i, &ch) in channels.iter().enumerate() {
        let t = std::time::Instant::now();
        // First hop must lay down the 20 MHz datapath; later hops can be fast.
        if fast && i > 0 {
            backend.set_channel_fast(ch)?;
        } else {
            backend.set_channel(ch, ChannelBw::Bw20)?;
        }
        let switch_us = t.elapsed().as_micros();
        std::thread::sleep(std::time::Duration::from_millis(15)); // BB settle
        let freq = 5000 + 5 * (ch as u32);
        match backend.measure_clm(window_us) {
            Ok(busy) => {
                let bar: String = "#".repeat((busy as usize) / 5);
                println!("  {ch:>4}   {freq:>7}   {switch_us:>5}us   {busy:>3}   {bar}");
            }
            Err(e) => println!("  {ch:>4}   {freq:>7}   {switch_us:>5}us   ERR ({e})"),
        }
    }
    println!("\n(higher busy% = more congested; pick the clearest for TX)");
    Ok(())
}

#[cfg(not(feature = "libusb-backend"))]
fn main() {
    eprintln!("rebuild with `--features libusb-backend` (needs an RTL8812EU dongle)");
}
