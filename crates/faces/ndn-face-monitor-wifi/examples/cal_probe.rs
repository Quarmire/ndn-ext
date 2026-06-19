//! Probe whether the firmware IQK/DPK calibration actually completes on this
//! device. Composes bring-up from the public steps and reads the firmware
//! done-flag at BB `0x2d9c` (IQK writes `0xaa`; the driver-side DPK loop polls
//! `0x55`) before/after each cal, with timing. A cal that never raises its flag
//! on this dongle is a concrete, per-device explanation for a dead TX path.
//!
//! ```text
//! cargo run --example cal_probe -p ndn-face-monitor-wifi \
//!     --features libusb-backend -- [channel]
//! ```

#[cfg(feature = "libusb-backend")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use ndn_face_monitor_wifi::LibUsbRtl88xxBackend;
    use std::time::{Duration, Instant};

    let channel: u8 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(161);
    let b = LibUsbRtl88xxBackend::open()?;
    b.power_on()?;
    b.download_firmware(LibUsbRtl88xxBackend::firmware_nic())?;
    b.mac_init()?;
    b.monitor_cfg()?;
    b.send_general_info()?;
    b.phy_init()?;
    b.set_channel_bw20(channel)?;

    let f = |b: &LibUsbRtl88xxBackend| b.read8(0x2d9c).unwrap_or(0xee);
    // Firmware liveness + H2C ring pointers.
    println!(
        "REG_MCUFW_CTRL(0x80) = {:#06x}  (want 0xc078 = fw alive)",
        b.read16(0x80)?
    );
    let rp = |b: &LibUsbRtl88xxBackend| b.read32(0x10d0).unwrap_or(0);
    let wp = |b: &LibUsbRtl88xxBackend| b.read32(0x10d4).unwrap_or(0);
    println!("H2C ring rd/wr ptr   = {:#x} / {:#x}", rp(&b), wp(&b));
    println!("0x2d9c pre-IQK   = {:#04x}", f(&b));

    let (rp0, wp0) = (rp(&b), wp(&b));
    let t = Instant::now();
    b.fw_iqk(false, false)?;
    println!(
        "H2C ring rd/wr ptr   = {:#x} / {:#x}  (rd advanced: {}, wr advanced: {})",
        rp(&b),
        wp(&b),
        rp(&b) != rp0,
        wp(&b) != wp0
    );
    println!(
        "0x2d9c post-IQK  = {:#04x}  (want 0xaa)  [{:?}]",
        f(&b),
        t.elapsed()
    );

    // Watch the flag evolve across the DPK window.
    let t = Instant::now();
    b.fw_dpk()?;
    print!("0x2d9c DPK watch :");
    for _ in 0..20 {
        print!(" {:#04x}", f(&b));
        std::thread::sleep(Duration::from_millis(20));
    }
    println!("  [{:?}]", t.elapsed());
    Ok(())
}

#[cfg(not(feature = "libusb-backend"))]
fn main() {}
