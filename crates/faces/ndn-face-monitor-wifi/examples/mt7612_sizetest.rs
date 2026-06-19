//! MT7612→MT7612 max-MPDU-size cap test. The chip advertises HT A-MSDU 3839B /
//! VHT max-MPDU 3895B and the TXWI len_ctl is 12-bit (4095) — so single MPDUs
//! should truncate past ~3.8-4KB. This verifies it on-air: one MT7612 TXes frames
//! of increasing size (size encoded in the payload), a second MT7612 (promiscuous
//! monitor RX) witnesses which sizes arrive and at what actual length.
//!
//!   RX witness (Mac):  NDN_ROLE=rx  --features libusb-backend --example mt7612_sizetest
//!   TX (OPi):          NDN_ROLE=tx  ... (after the RX side is listening)
//! Both tune 5GHz ch36/80. TX uses VHT80 MCS9. A frame "claims" its intended size
//! in payload[0..2]=MAGIC, [2..4]=size(LE); RX prints, per claimed size, how many
//! arrived and the actual received bulk length (truncation shows as actual≪claimed).
#[cfg(feature = "libusb-backend")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use ndn_face_monitor_wifi::{McsDescriptor, Mt7612uBackend};
    use std::time::{Duration, Instant};

    const MAGIC: [u8; 4] = [0x5A, 0xCA, 0x99, 0x71];
    const SIZES: [usize; 11] =
        [4096, 5000, 5300, 5500, 5700, 6000, 6500, 7000, 7935, 9000, 11000];

    let role = std::env::var("NDN_ROLE").unwrap_or_default();
    let dev = Mt7612uBackend::open()?;
    dev.bring_up()?;
    // 5GHz ch36/80 needs the ch6 baseline first on a cold device (delta blob).
    dev.set_channel_ch6()?;
    dev.set_channel_5g80()?;
    let chip = dev.chip_id()?;
    println!("chip 0x{chip:04x}, role={role}, 5GHz ch36/80");

    // Build a frame of `plen` payload bytes tagged with MAGIC + intended size.
    let mk = |plen: usize| -> Vec<u8> {
        let mut f = vec![0x08u8, 0x00, 0x00, 0x00];
        f.extend_from_slice(&[0xff; 6]); // addr1 broadcast
        f.extend_from_slice(&[0x02, 0x53, 0x5a, 0x54, 0x00, 0x01]); // addr2 SA
        f.extend_from_slice(&[0xff; 6]); // addr3
        f.extend_from_slice(&[0x00, 0x00]); // seq
        f.extend_from_slice(&[0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x86, 0x24]); // LLC
        let body_start = f.len();
        f.extend_from_slice(&MAGIC);
        f.extend_from_slice(&(plen as u16).to_le_bytes());
        while f.len() < body_start + plen {
            f.push(0xC3);
        }
        f
    };

    if role == "scan" {
        // Wide scan for the register holding the ~5800B single-MPDU cap: flag any
        // value that looks like the cap in bytes (~5600-6200) or pages (~22-26 @256B,
        // ~44-48 @128B), or a 12-16 bit subfield in those ranges.
        let ranges = [
            (0x0400u32, 0x0460u32), (0x0a40, 0x0a80), (0x1200, 0x1260),
            (0x1300, 0x1360), (0x1600, 0x1700), (0x1230, 0x1240),
        ];
        let interesting = |v: u32| -> bool {
            let cand = |x: u32| (5600..=6200).contains(&x) || (22..=26).contains(&x) || (44..=48).contains(&x);
            cand(v) || cand(v & 0xffff) || cand((v >> 16) & 0xffff) || cand(v & 0xfff) || cand((v >> 12) & 0xfff)
        };
        println!("--- wide register scan (flagging cap-like values) ---");
        for (lo, hi) in ranges {
            let mut a = lo;
            while a <= hi {
                if let Ok(v) = dev.rr(a) {
                    if v != 0 && v != 0xffffffff && interesting(v) {
                        println!("  *CAND* 0x{a:04x} = 0x{v:08x} ({v})");
                    }
                }
                a += 4;
            }
        }
        println!("scan done.");
        return Ok(());
    }
    if role == "tx" {
        // Dump TX/PSE/PBF/FCE candidate registers — hunting the value that caps a
        // single MPDU at ~5800B (≈45 pages of 128B). Look for ~5760/6000/0x16xx/45.
        let dump: &[(u32, &str)] = &[
            (0x0400, "PBF_SYS_CTRL"), (0x0404, "PBF_CFG"), (0x0408, "PBF_TX_MAX_PCNT"),
            (0x040c, "PBF_RX_MAX_PCNT"), (0x0410, "PBF_0410"), (0x0414, "PBF_0414"),
            (0x0420, "PBF_0420"), (0x0800, "FCE_PSE_CTRL"), (0x09a4, "FCE_TX_MAXCNT"),
            (0x09c4, "FCE_PDMA_GCONF"), (0x0a6c, "FCE_SKIP_FS"), (0x0a4c, "FCE_0a4c"),
            (0x1004, "MAC_SYS_CTRL"), (0x1610, "TX_MAX_LEN?"), (0x1690, "TX_1690"),
            (0x131c, "TX_131c"), (0x13b4, "TX_13b4"),
        ];
        println!("--- register dump ---");
        for (a, name) in dump {
            match dev.rr(*a) {
                Ok(v) => println!("  0x{a:04x} {name:16} = 0x{v:08x} ({v})"),
                Err(_) => println!("  0x{a:04x} {name:16} = <read err>"),
            }
        }
        // Hunt the CO-LIMIT register that now caps at ~24 pages / ~6144B (binding
        // behind 0x1238). Flag any field ≈ 23-26 pages or ≈ 5900-6300 bytes.
        println!("--- co-limit scan (fields ~23-26 pages / ~5900-6300B) ---");
        let coflag = |x: u32| (23..=26).contains(&x) || (5900..=6300).contains(&x);
        let hit = |v: u32| coflag(v) || coflag(v & 0xffff) || coflag((v >> 16) & 0xffff)
            || coflag(v & 0xfff) || coflag((v >> 8) & 0xff) || coflag(v & 0xff) || coflag((v >> 16) & 0xff);
        for base in [0x0400u32, 0x0500, 0x0a00, 0x1200, 0x1300, 0x1340, 0x1600] {
            let mut a = base;
            while a < base + 0x100 {
                if let Ok(v) = dev.rr(a) {
                    if v != 0 && v != 0xffff_ffff && hit(v) {
                        println!("  *CO* 0x{a:04x} = 0x{v:08x}");
                    }
                }
                a += 4;
            }
        }
        // NDN_POKE="addr:val;addr:val" (hex) — raise a candidate before the sweep.
        if let Ok(p) = std::env::var("NDN_POKE") {
            for pair in p.split(';').filter(|s| !s.is_empty()) {
                let mut it = pair.split(':');
                let a = u32::from_str_radix(it.next().unwrap().trim_start_matches("0x"), 16).unwrap();
                let v = u32::from_str_radix(it.next().unwrap().trim_start_matches("0x"), 16).unwrap();
                let _ = dev.wr(a, v);
                println!("POKE 0x{a:04x} = 0x{v:08x} -> readback 0x{:08x}", dev.rr(a).unwrap_or(0));
            }
        }
        let mcs = McsDescriptor::vht(9);
        for plen in SIZES {
            let frame = mk(plen);
            let mut ok = 0;
            for _ in 0..120 {
                if dev.tx_data_sync(&frame, &mcs).is_ok() {
                    ok += 1;
                }
                std::thread::sleep(Duration::from_millis(2));
            }
            println!("TX size={plen:5} (frame {} B): {ok}/120 USB-accepted", frame.len());
            std::thread::sleep(Duration::from_millis(300));
        }
        println!("TX done.");
    } else {
        // RX witness: promiscuous monitor, record per-claimed-size arrivals + actual len.
        dev.setup_monitor_rx()?;
        dev.pause_drain(true);
        let mut buf = vec![0u8; 32768];
        let mut seen: std::collections::BTreeMap<u16, (u32, usize, usize)> = Default::default();
        let start = Instant::now();
        println!("RX listening 45s...");
        while start.elapsed() < Duration::from_secs(45) {
            let n = dev.read_rx(&mut buf)?;
            if n == 0 {
                continue;
            }
            // find MAGIC anywhere in the received bulk
            if let Some(p) = buf[..n].windows(4).position(|w| w == MAGIC) {
                if p + 6 <= n {
                    let claimed = u16::from_le_bytes([buf[p + 4], buf[p + 5]]);
                    let e = seen.entry(claimed).or_insert((0, usize::MAX, 0));
                    e.0 += 1;
                    e.1 = e.1.min(n);
                    e.2 = e.2.max(n);
                }
            }
        }
        println!("--- RX results (claimed size → count, min/max received bulk bytes) ---");
        for (sz, (cnt, mn, mx)) in &seen {
            println!("  claimed={sz:5}: {cnt:4} rx, bulk {mn}..{mx} B");
        }
        if seen.is_empty() {
            println!("  (nothing received — check channel/timing/TX running)");
        }
    }
    Ok(())
}
#[cfg(not(feature = "libusb-backend"))]
fn main() {}
