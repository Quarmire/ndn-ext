//! Read the board's RFE type from logical EFUSE (offset 0xCA = EEPROM_RFE_OPTION
//! for 8822B/C/E) and compare to our hardcoded RFE_TYPE=21. The BL-M8812EU2 has
//! external FEMs; the RFE type drives their PA/LNA/TRSW control.
#[cfg(feature = "libusb-backend")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use ndn_face_monitor_wifi::LibUsbRtl88xxBackend;
    let b = LibUsbRtl88xxBackend::open_monitor(149)?;
    let phys = b.efuse_dump_physical()?;
    let logi = LibUsbRtl88xxBackend::efuse_decode_logical(&phys)?;
    let at = |o: usize| logi.get(o).copied().unwrap_or(0xff);
    println!("logical EFUSE len={}", logi.len());
    println!("0xCA RFE_OPTION    = {:#04x} ({})   [we hardcode RFE_TYPE=21=0x15]", at(0xca), at(0xca));
    // nearby RF/antenna-relevant bytes for context
    for o in [0xb8usize, 0xbf, 0xc8, 0xc9, 0xcb, 0xcc] {
        println!("  0x{:02x} = {:#04x}", o, at(o));
    }
    Ok(())
}
#[cfg(not(feature = "libusb-backend"))]
fn main() {}
