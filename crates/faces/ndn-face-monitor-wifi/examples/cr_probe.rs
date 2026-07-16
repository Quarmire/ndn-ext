//! Is the 8812AU's MAC cold or already live? — and does a bring-up survive it?
//!
//! Diagnostic for the wedge in task #22. `REG_CR` distinguishes the two states,
//! which is otherwise invisible and easy to guess wrong:
//!
//! ```text
//!   cold (just enumerated) : REG_CR = 0xeaea   (the USB core answers 0xEA per
//!                                               byte while the MAC is unpowered)
//!   after power_on         : REG_CR = 0x0000
//!   after mac_enable_dma   : REG_CR = 0x063f
//!   fully brought up       : REG_CR = 0x06ff
//! ```
//!
//! Run it twice in a row: the second run starts on a live chip (0x06ff), which is
//! the state a previous process leaves behind — `timeout`/Ctrl-C kill it without
//! running any cleanup.
//!
//! ⚠ Do NOT "fix" that by calling `power_off()` first: ACT_TO_CARDEMU faults with
//! `usb: Input/Output Error` on a live chip and drops the device off the bus (it
//! re-enumerates cold some seconds later). That was tried and reverted.
//!
//!   sudo NDN_RADIO_NO_RESET=1 LD_LIBRARY_PATH=$(nix path-info nixpkgs#libusb1)/lib \
//!       ./target/debug/examples/cr_probe
#[cfg(feature = "libusb-backend")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use ndn_face_monitor_wifi::Rtl8812auBackend;
    let b = Rtl8812auBackend::open()?;
    println!("on open:              REG_CR(0x100) = {:#06x}", b.read16(0x0100)?);
    b.power_on()?;
    println!("after power_on:       REG_CR = {:#06x}", b.read16(0x0100)?);
    b.mac_enable_dma()?;
    println!("after mac_enable_dma: REG_CR = {:#06x}", b.read16(0x0100)?);
    b.init_llt()?;
    b.download_firmware()?;
    b.mac_config()?;
    b.mac_init_queues()?;
    println!("fully up:             REG_CR = {:#06x}", b.read16(0x0100)?);
    Ok(())
}
#[cfg(not(feature = "libusb-backend"))]
fn main() {
    eprintln!("build with --features libusb-backend");
}
