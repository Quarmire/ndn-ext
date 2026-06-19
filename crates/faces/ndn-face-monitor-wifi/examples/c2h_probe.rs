//! Drain the chip's C2H (chip-to-host) channel after a FW IQK and dump every
//! C2H packet — sub-cmd 0x00 is firmware DEBUG text, 0x01 is an H2C ack. This
//! tells us whether the firmware actually runs the IQK (and what it complains
//! about) versus silently consuming the H2C.

#[cfg(feature = "libusb-backend")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use ndn_face_monitor_wifi::LibUsbRtl88xxBackend;

    let channel: u8 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(161);
    let b = LibUsbRtl88xxBackend::open()?;
    b.bring_up(channel)?; // full bring-up so the RX path (and thus C2H) is up

    // Sanity: is RX delivering any bulk-IN buffers at all?
    let mut raw = 0;
    for _ in 0..50 {
        if b.recv_raw(20)?.is_some() {
            raw += 1;
        }
    }
    println!("# RX sanity: {raw}/50 non-empty bulk-IN reads");

    // Fire the IQK, then drain C2H for ~2s.
    b.fw_iqk(false, false)?;
    println!("# IQK sent; draining C2H…");

    let mut c2h_count = 0;
    let mut total_units = 0u32;
    for _ in 0..400 {
        let Some(buf) = b.recv_raw(20)? else { continue };
        // Walk the aggregated RX units.
        let mut off = 0usize;
        while off + 24 <= buf.len() {
            let dw0 = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap());
            let pkt_len = (dw0 & 0x3fff) as usize;
            let drvinfo = ((dw0 >> 16) & 0xf) as usize * 8;
            let shift = ((dw0 >> 24) & 0x3) as usize;
            if pkt_len == 0 {
                break;
            }
            total_units += 1;
            let dw2 = u32::from_le_bytes(buf[off + 8..off + 12].try_into().unwrap());
            let is_c2h = (dw2 >> 28) & 1 != 0;
            let body = off + 24;
            if is_c2h && body + pkt_len <= buf.len() {
                let c2h = &buf[body..body + pkt_len];
                let cmd_id = c2h[0];
                let seq = c2h.get(1).copied().unwrap_or(0);
                let sub = c2h.get(2).copied().unwrap_or(0);
                if cmd_id == 0xff {
                    c2h_count += 1;
                    let ascii: String = c2h[3..]
                        .iter()
                        .map(|&x| {
                            if (0x20..0x7f).contains(&x) {
                                x as char
                            } else {
                                '.'
                            }
                        })
                        .collect();
                    println!(
                        "C2H sub=0x{sub:02x} seq=0x{seq:02x} len={pkt_len}: {:02x?}  | {ascii}",
                        &c2h[..pkt_len.min(24)]
                    );
                }
            }
            let adv = (24 + drvinfo + shift + pkt_len + 7) & !7;
            off += adv.max(8);
        }
    }
    println!(
        "# {c2h_count} C2H packets out of {total_units} RX units; 0x2d9c = {:#04x}",
        b.read8(0x2d9c)?
    );
    Ok(())
}

#[cfg(not(feature = "libusb-backend"))]
fn main() {}
