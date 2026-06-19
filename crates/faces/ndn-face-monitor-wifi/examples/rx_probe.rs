//! Diagnostic: receive on `ch` for `secs` and report, per raw bulk-IN buffer,
//! whether it contains the OPi inject's source MAC (02:de:ad:be:ef:00), the
//! "OPI-RECIP-TEST" marker, and the partial MAC `de ad be ef`. Prints the first
//! buffer that matches the MAC (hex) so we can see the frame structure. This
//! tells us definitively whether fc:23 receives the OPi kernel injection.
#[cfg(feature = "libusb-backend")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use ndn_face_monitor_wifi::LibUsbRtl88xxBackend;
    let ch: u8 = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(149);
    let secs: u64 = std::env::args().nth(2).and_then(|s| s.parse().ok()).unwrap_or(8);
    let b = LibUsbRtl88xxBackend::open_monitor(ch)?;
    println!("rx_probe on ch{ch} for {secs}s…");
    let mac: &[u8] = &[0x02, 0xde, 0xad, 0xbe, 0xef, 0x00];
    let mac_part: &[u8] = &[0xde, 0xad, 0xbe, 0xef];
    let marker = b"OPI-RECIP-TEST";
    let (mut bufs, mut hit_mac, mut hit_part, mut hit_marker) = (0u32, 0u32, 0u32, 0u32);
    let mut shown = false;
    let t0 = std::time::Instant::now();
    while t0.elapsed().as_secs() < secs {
        if let Some(f) = b.recv_raw(500)? {
            bufs += 1;
            let has = |p: &[u8]| f.windows(p.len()).any(|w| w == p);
            if has(mac) { hit_mac += 1; }
            if has(mac_part) { hit_part += 1; }
            if has(marker) { hit_marker += 1; }
            if !shown && has(mac_part) {
                shown = true;
                let n = f.len().min(160);
                println!("first buf w/ de:ad:be:ef ({} B): {}", f.len(),
                         f[..n].iter().map(|x| format!("{x:02x}")).collect::<Vec<_>>().join(" "));
            }
        }
    }
    println!("buffers={bufs}  with_full_MAC={hit_mac}  with_deadbeef={hit_part}  with_marker={hit_marker}");
    Ok(())
}
#[cfg(not(feature = "libusb-backend"))]
fn main() {}
