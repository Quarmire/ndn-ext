//! MT7612U bring-up step 1-2: open the dongle and download firmware (ROM patch +
//! ILM/DLM). Reports endpoints, firmware versions, and the MCU readiness state.
//! Run with the MT7612U (`0e8d:7612`) plugged in:
//! `cargo run -p ndn-face-monitor-wifi --features libusb-backend --example mt7612_fwload`
#[cfg(feature = "libusb-backend")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use ndn_face_monitor_wifi::Mt7612uBackend;

    println!("opening MT7612U ...");
    let dev = Mt7612uBackend::open()?;
    let (build, ver) = dev.fw_versions();
    println!("firmware blob: build=0x{build:04x} ver=0x{ver:04x}");

    println!("firmware already running? {}", dev.firmware_running());
    println!("downloading firmware (ROM patch + ILM/DLM) ...");
    dev.load_firmware()?;
    println!("✅ firmware download completed; starting MCU ...");
    let (com_reg0, ready) = dev.start_mcu()?;
    println!("MCU COM_REG0 = 0x{com_reg0:08x}  ready(bit0)={ready}");
    if ready {
        println!("🎉 MCU is RUNNING — firmware bring-up works.");
    } else {
        println!("MCU not signalling ready yet (COM_REG0 above) — refine readiness condition.");
    }

    // Efuse sanity: chip ID + factory MAC (proves efuse access post-firmware).
    let chip = dev.chip_id()?;
    let mac = dev.mac_address()?;
    println!("chip ID = 0x{chip:04x}  MAC = {}",
        mac.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":"));
    Ok(())
}
#[cfg(not(feature = "libusb-backend"))]
fn main() {}
