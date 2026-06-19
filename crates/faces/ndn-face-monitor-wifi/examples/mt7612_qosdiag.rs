//! MT7612U QoS-data / A-MSDU radiation diagnostic. Sends, on the data endpoint
//! (ep 0x04, data TXWI), three frame types with distinct source MACs, to learn
//! whether QoS-data (the prerequisite for A-MSDU aggregation) radiates:
//!   plain data (FC 0x08)        -> SA ..01  (control; known to radiate)
//!   QoS data, no A-MSDU (0x88)  -> SA ..02
//!   QoS data + A-MSDU (2 sub)   -> SA ..03
#[cfg(feature = "libusb-backend")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use ndn_face_monitor_wifi::Mt7612uBackend;
    use std::time::Duration;

    let dev = Mt7612uBackend::open()?;
    dev.bring_up()?;
    dev.set_channel_ch6()?;
    dev.setup_monitor_rx()?;
    dev.pause_drain(true);
    std::thread::sleep(Duration::from_millis(200));
    println!("chip 0x{:04x}", dev.chip_id()?);

    let snap = [0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x86, 0x24];
    let hdr = |fc0: u8, sa: u8| -> Vec<u8> {
        let mut f = vec![fc0, 0x00, 0x00, 0x00];
        f.extend_from_slice(&[0xff; 6]); // addr1
        f.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, sa]); // addr2 = SA
        f.extend_from_slice(&[0xff; 6]); // addr3
        f.extend_from_slice(&[0x00, 0x00]); // seq
        f
    };
    // plain data
    let plain = {
        let mut f = hdr(0x08, 0x01);
        f.extend_from_slice(&snap);
        f.extend_from_slice(&[0x01u8; 256]);
        f
    };
    // QoS data, single MSDU (no A-MSDU): QoS ctrl 0x0000
    let qos = {
        let mut f = hdr(0x88, 0x02);
        f.extend_from_slice(&[0x00, 0x00]); // QoS Control, TID 0, no A-MSDU
        f.extend_from_slice(&snap);
        f.extend_from_slice(&[0x02u8; 256]);
        f
    };
    // QoS data + A-MSDU: QoS ctrl 0x0080 (A-MSDU Present bit7 of first octet) + 2 subframes
    let amsdu = {
        let mut f = hdr(0x88, 0x03);
        f.extend_from_slice(&[0x80, 0x00]); // QoS Control: A-MSDU Present
        for _ in 0..2 {
            let pl = [0x03u8; 256];
            f.extend_from_slice(&[0xff; 6]); // sub DA
            f.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x03]); // sub SA
            f.extend_from_slice(&((8 + pl.len()) as u16).to_be_bytes()); // len
            f.extend_from_slice(&snap);
            f.extend_from_slice(&pl);
            // pad subframe to 4 (only between subframes; simple: pad each)
            while f.len() % 4 != 0 {
                f.push(0);
            }
        }
        f
    };

    for (label, frame) in [("plain(..01)", &plain), ("qos(..02)", &qos), ("amsdu(..03)", &amsdu)] {
        let mut ok = 0u32;
        for _ in 0..200 {
            if dev.tx_data_at(frame, 0x4001).is_ok() {
                ok += 1;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        println!("{label}: {ok}/200 accepted (len {})", frame.len());
    }
    println!("done — check receiver for SA 02:00:00:00:00:0{{1,2,3}}.");
    Ok(())
}
#[cfg(not(feature = "libusb-backend"))]
fn main() {}
