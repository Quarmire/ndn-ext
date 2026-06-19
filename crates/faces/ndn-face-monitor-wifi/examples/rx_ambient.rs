//! Self-test the Mac dongle's RX frontend and (optionally) count frames whose
//! body carries a magic marker, to confirm a reciprocal link from a peer.
#[cfg(feature = "libusb-backend")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use ndn_face_monitor_wifi::LibUsbRtl88xxBackend;
    let ch: u8 = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(149);
    let secs = std::env::args().nth(2).and_then(|s| s.parse().ok()).unwrap_or(8u64);
    let b = LibUsbRtl88xxBackend::open_monitor(ch)?;
    if let Ok(s) = std::env::var("RADIO_BW") {
        use ndn_face_monitor_wifi::ChannelBw;
        let bw = match s.as_str() {
            "40" => ChannelBw::Bw40,
            "80" => ChannelBw::Bw80,
            "10" => ChannelBw::Nb10,
            "5" => ChannelBw::Nb5,
            _ => ChannelBw::Bw20,
        };
        b.set_channel(ch, bw)?;
        println!("RX bandwidth {s} MHz");
    }
    println!("listening on ch{ch} for {secs}s…");
    let magic = b"OPI-RECIP-TEST";
    let t0 = std::time::Instant::now();
    let (mut n, mut hits) = (0u32, 0u32);
    while t0.elapsed().as_secs() < secs {
        if let Some(f) = b.recv_raw(500)? {
            n += 1;
            if f.windows(magic.len()).any(|w| w == magic) {
                hits += 1;
            }
        }
    }
    println!("ch{ch}: {n} frames total, {hits} carrying the peer marker", );
    Ok(())
}
#[cfg(not(feature = "libusb-backend"))]
fn main() {}
