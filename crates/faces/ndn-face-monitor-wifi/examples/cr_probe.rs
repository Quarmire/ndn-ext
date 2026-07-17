//! Where does the 8812AU wedge? — task #22.
//!
//! `REG_CR` tells cold from live (measured):
//! ```text
//!   cold (just enumerated) : 0xeaea   (USB core answers 0xEA/byte, MAC unpowered)
//!   after power_on         : 0x0000
//!   after mac_enable_dma   : 0x063f
//!   fully brought up       : 0x06ff
//! ```
//! A previous process leaves the chip live at 0x06ff — `timeout`/Ctrl-C kill it
//! without running any cleanup.
//!
//! Modes:
//!  - (default) bring-up only. Loops clean over a live chip — NOT the wedge.
//!  - `full` — the whole nan_ndp path: calibration, TX power, RX DMA, then drain
//!    frames for a few seconds. This is what the wedge needs, so run it repeatedly.
//!
//! ⚠ Do NOT call `power_off()` to "reset" a live chip: ACT_TO_CARDEMU faults with
//! `usb: Input/Output Error` on a LIVE chip and drops the device off the bus.
//! Tried and reverted.
//!
//!   sudo NDN_RADIO_NO_RESET=1 LD_LIBRARY_PATH=$(nix path-info nixpkgs#libusb1)/lib \
//!       ./target/debug/examples/cr_probe [full]
#[cfg(feature = "libusb-backend")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use ndn_face_monitor_wifi::Rtl8812auBackend;
    let full = std::env::args().nth(1).as_deref() == Some("full");
    let b = Rtl8812auBackend::open()?;
    let cr = |b: &Rtl8812auBackend| b.read16(0x0100).map(|v| format!("{v:#06x}"));

    println!("on open:              REG_CR = {}", cr(&b)?);
    b.power_on()?;
    b.mac_enable_dma()?;
    b.init_llt()?;
    b.download_firmware()?;
    b.mac_config()?;
    b.mac_init_queues()?;
    println!("brought up:           REG_CR = {}", cr(&b)?);
    if !full {
        return Ok(());
    }

    // Everything the real node does beyond a bare bring-up. Each step reports, so
    // a wedge names the step it died in rather than the process just vanishing.
    b.bb_config()?;
    println!("  bb_config ok");
    b.rf_config()?;
    println!("  rf_config ok");
    b.set_channel(6)?;
    println!("  set_channel ok");
    b.iq_calibrate()?;
    println!("  iq_calibrate ok");
    b.lc_calibrate()?;
    println!("  lc_calibrate ok");
    b.set_tx_power(0x3f)?;
    println!("  set_tx_power ok");
    b.start_rx_dma()?;
    println!("  start_rx_dma ok — draining 5s of frames");

    let t0 = std::time::Instant::now();
    let mut frames = 0u32;
    while t0.elapsed() < std::time::Duration::from_secs(5) {
        match b.poll_frame() {
            Ok(Some(_)) => frames += 1,
            Ok(None) => {}
            Err(e) => {
                println!("  RX FAILED after {frames} frames: {e}");
                return Ok(());
            }
        }
    }
    println!("drained {frames} frames; REG_CR = {}", cr(&b)?);
    Ok(())
}
#[cfg(not(feature = "libusb-backend"))]
fn main() {
    eprintln!("build with --features libusb-backend");
}
