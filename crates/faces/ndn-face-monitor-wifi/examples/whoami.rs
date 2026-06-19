//! Identify the plugged-in RTL8812EU by its programmed MAC (REG_MACID 0x0610)
//! and read the channel/gain RF state, to tell which physical unit is present.
#[cfg(feature = "libusb-backend")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use ndn_face_monitor_wifi::{LibUsbRtl88xxBackend, RfPath};
    let b = LibUsbRtl88xxBackend::open_monitor(149)?;
    let mut mac = [0u8; 6];
    for (i, m) in mac.iter_mut().enumerate() {
        *m = b.read8(0x0610 + i as u16)?;
    }
    println!(
        "MAC = {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    );
    println!("RF_A 0x18 (chan/bw) = {:#07x}", b.rf_read(RfPath::A, 0x18, 0xfffff)?);
    println!("RF_A 0x00 (gain)    = {:#07x}", b.rf_read(RfPath::A, 0x00, 0xfffff)?);
    println!("RF_B 0x18 (chan/bw) = {:#07x}", b.rf_read(RfPath::B, 0x18, 0xfffff)?);
    // BT-coex grant readback: indirect read of BTC reg 0x38 (strobe 0x1700,
    // data 0x1708). [15:8] must read 0x77 (GNT_WL=1) or TX sits ~50 dB low.
    b.write32(0x1700, 0x800f_0000 | 0x38)?;
    let btc38 = b.read32(0x1708)?;
    println!(
        "BTC 0x38 = {:#010x}  -> GNT_WL[15:8] = {:#04x} (want 0x77)",
        btc38,
        (btc38 >> 8) & 0xff
    );
    println!("0x18a0 = {:#010x}", b.read32(0x18a0)?);
    println!("0x18e8 = {:#010x}", b.read32(0x18e8)?);
    Ok(())
}
#[cfg(not(feature = "libusb-backend"))]
fn main() {}
