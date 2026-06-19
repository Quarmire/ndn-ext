//! Read the RFE pin / RF-mode registers after a full bring_up and compare to
//! the values rfe_ctrl() should have left (BB_PATH_AB, RFE 21). If they don't
//! hold, a later step is clobbering the FEM control config.
#[cfg(feature = "libusb-backend")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use ndn_face_monitor_wifi::LibUsbRtl88xxBackend;
    let b = LibUsbRtl88xxBackend::open_monitor(149)?;
    let chk = |name: &str, addr: u16, want: u32| -> Result<(), Box<dyn std::error::Error>> {
        let got = b.read32(addr)?;
        println!("  {name} 0x{addr:04x} = {got:#010x}  want {want:#010x}  {}",
                 if got == want { "OK" } else { "** MISMATCH **" });
        Ok(())
    };
    println!("RFE pin / mode regs after bring_up (BB_PATH_AB, RFE 21):");
    chk("RFE_A0 ", 0x1840, 0x0000_2000)?;
    chk("RFE_A1 ", 0x1844, 0x0000_3000)?;
    chk("RFE_B0 ", 0x4140, 0x0020_0000)?;
    chk("RFE_B1 ", 0x4144, 0x0000_0030)?;
    chk("RFMODEB", 0x4100, 0x0003_3312)?;
    // RF mode path A (0x1800-region equivalent)
    println!("  RFMODEA 0x1808 = {:#010x}", b.read32(0x1808)?);
    println!("  0x1884 (rxmode?) = {:#010x}", b.read32(0x1884)?);
    // FEM-control GPIO pinmux — do our writes hold? (kernel golden values)
    println!("FEM pinmux (kernel: 0x40=0x1403020c, 0x4c=0x0122e282, 0x64=0x3c201000):");
    chk("GPIO_MUX", 0x0040, 0x1403_020c)?;
    chk("LED_CFG ", 0x004c, 0x0122_e282)?;
    chk("PAD_CTL1", 0x0064, 0x3c20_1000)?;
    // RF mode register 0x00 per path: [19:16]=mode, [4:0]=gain
    use ndn_face_monitor_wifi::RfPath;
    let a = b.rf_read(RfPath::A, 0x00, 0xfffff)?;
    let bb = b.rf_read(RfPath::B, 0x00, 0xfffff)?;
    println!(
        "RF 0x00: pathA={a:#07x} (mode={:#x} gain={:#x})  pathB={bb:#07x} (mode={:#x} gain={:#x})",
        (a >> 16) & 0xf,
        a & 0x1f,
        (bb >> 16) & 0xf,
        bb & 0x1f
    );
    Ok(())
}
#[cfg(not(feature = "libusb-backend"))]
fn main() {}
