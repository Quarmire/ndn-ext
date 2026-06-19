//! Verify the DM watchdog: thermal + DIG. Prints IGI (0x1d70) + the OFDM
//! false-alarm count each tick while DIG adapts the RX initial gain.
#[cfg(feature = "libusb-backend")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use ndn_face_monitor_wifi::{LibUsbRtl88xxBackend, RfPath};
    let b = LibUsbRtl88xxBackend::open_monitor(161)?;
    let igi0 = b.read32(0x1d70)? & 0x7f;
    println!(
        "initial IGI=0x{igi0:02x}, thermal={}",
        b.read_thermal(RfPath::A)?
    );
    for i in 0..6 {
        std::thread::sleep(std::time::Duration::from_millis(800));
        let fa = (b.read32(0x2d04)? >> 16)
            + (b.read32(0x2d08)? & 0xffff)
            + (b.read32(0x2d08)? >> 16)
            + (b.read32(0x2d10)? & 0xffff)
            + (b.read32(0x2d20)? & 0xffff)
            + (b.read32(0x2d20)? >> 16);
        let igi = b.dig_tick()?;
        println!("tick {i}: FA={fa:<6} -> IGI=0x{igi:02x}");
    }
    Ok(())
}
#[cfg(not(feature = "libusb-backend"))]
fn main() {}
