//! Discriminate FEM-LNA-off (analog gain lost) from chip-AGC-insensitive: read
//! the DIG IGI (0x1d70 [6:0]=A, [14:8]=B), count ambient, then force a very
//! sensitive IGI and re-count. If ambient jumps -> it was digital AGC; if it
//! stays low -> the FEM LNA gain is gone (analog), no digital gain recovers it.
#[cfg(feature = "libusb-backend")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use ndn_face_monitor_wifi::LibUsbRtl88xxBackend;
    let b = LibUsbRtl88xxBackend::open_monitor(149)?;
    let count = |secs: u64| -> Result<u32, Box<dyn std::error::Error>> {
        let t0 = std::time::Instant::now();
        let mut n = 0;
        while t0.elapsed().as_secs() < secs {
            if b.recv_raw(200)?.is_some() { n += 1; }
        }
        Ok(n)
    };
    println!("IGI 0x1d70 = {:#010x}", b.read32(0x1d70)?);
    println!("baseline ambient (4s): {}", count(4)?);
    // Force both paths' IGI to 0x20 (very sensitive / high gain).
    let v = (b.read32(0x1d70)? & !0x7f7f) | 0x2020;
    b.write32(0x1d70, v)?;
    println!("forced IGI -> {:#010x}", b.read32(0x1d70)?);
    println!("ambient after forcing sensitive IGI (4s): {}", count(4)?);
    // also try forcing the path-A RX AGC table gain high via 0x1d70 readback
    println!("IGI now reads {:#010x} (did AGC overwrite?)", b.read32(0x1d70)?);
    Ok(())
}
#[cfg(not(feature = "libusb-backend"))]
fn main() {}
