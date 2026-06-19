//! Verify the FEM pinmux registers after bring_up (should match kernel golden:
//! REG_LED_CFG 0x4c = 0x0122e282, REG_PAD_CTRL1 0x64 = 0x3c201000).
#[cfg(feature = "libusb-backend")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use ndn_face_monitor_wifi::LibUsbRtl88xxBackend;
    let b = LibUsbRtl88xxBackend::open_monitor(149)?;
    println!("REG_LED_CFG  0x4c = {:#010x}  (kernel 0x0122e282)", b.read32(0x004c)?);
    println!("REG_PAD_CTRL1 0x64 = {:#010x}  (kernel 0x3c201000)", b.read32(0x0064)?);
    Ok(())
}
#[cfg(not(feature = "libusb-backend"))]
fn main() {}
