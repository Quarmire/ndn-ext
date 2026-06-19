//! MT7612U data-frame TX rate sweep: send the SAME NDN data frame on the data
//! endpoint (ep 0x04, data TXWI wcid=0xff/no-ACK) at three TXWI rates, distinct
//! source MACs, so a monitor receiver shows which radiate. Settles whether
//! data-frame radiation depends on the rate (the kernel injected at CCK 1M).
//!   rate 0x0000 CCK-1M  -> SA ..01   (the kernel's choice)
//!   rate 0x2000 OFDM-6M -> SA ..02
//!   rate 0x4001 HT-MCS1 -> SA ..03   (what FrameIo inject uses)
//!   mgmt OFDM control   -> SA ..04   (sanity: TX works at all)
#[cfg(feature = "libusb-backend")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use ndn_face_monitor_wifi::{McsDescriptor, Mt7612uBackend};
    use std::time::Duration;

    let dev = Mt7612uBackend::open()?;
    dev.bring_up()?;
    dev.set_channel_ch6()?;
    dev.setup_monitor_rx()?;
    dev.pause_drain(true);
    std::thread::sleep(Duration::from_millis(200));
    println!("chip 0x{:04x}", dev.chip_id()?);

    let data = |sa: u8| -> Vec<u8> {
        let mut f = vec![0x08u8, 0x00, 0x00, 0x00];
        f.extend_from_slice(&[0xff; 6]);
        f.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, sa]);
        f.extend_from_slice(&[0xff; 6]);
        f.extend_from_slice(&[0x00, 0x00]);
        f.extend_from_slice(&[0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x86, 0x24]);
        f.extend_from_slice(b"DIAGDATA");
        f
    };
    let mgmt = {
        let mut f = vec![0x40u8, 0x00, 0x00, 0x00];
        f.extend_from_slice(&[0xff; 6]);
        f.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x04]);
        f.extend_from_slice(&[0xff; 6]);
        f.extend_from_slice(&[0x00, 0x00]);
        f.extend_from_slice(&[0x00, 0x00]);
        f.extend_from_slice(&[0x01, 0x08, 0x0c, 0x12, 0x18, 0x24, 0x30, 0x48, 0x60, 0x6c]);
        f
    };

    for (rate, sa, label) in [(0x0000u16, 0x01u8, "data CCK-1M"), (0x2000, 0x02, "data OFDM-6M"), (0x4001, 0x03, "data HT-MCS1")] {
        let f = data(sa);
        let mut ok = 0u32;
        for _ in 0..200 {
            if dev.tx_data_at(&f, rate).is_ok() {
                ok += 1;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        println!("{label} (SA ..{sa:02}): {ok}/200 accepted");
    }
    let mut ok = 0u32;
    for _ in 0..200 {
        if dev.transmit(&mgmt).is_ok() {
            ok += 1;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    println!("mgmt OFDM control (SA ..04): {ok}/200 accepted");
    println!("done — search receiver for SA 02:00:00:00:00:0{{1,2,3,4}}.");
    Ok(())
}
#[cfg(not(feature = "libusb-backend"))]
fn main() {}
