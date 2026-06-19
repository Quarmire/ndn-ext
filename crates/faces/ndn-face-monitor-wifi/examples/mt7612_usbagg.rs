//! MT7612U USB-aggregation test: pack K plain-data MPDUs (distinct source MACs
//! ..01..0K) into one bulk transfer via tx_data_agg, repeat N times. If the
//! device chains units per transfer, all K SAs appear on air ~N times and the
//! goodput jumps ~K×. Capture on a monitor-otherbss receiver.
//! `--features libusb-backend --example mt7612_usbagg`
#[cfg(feature = "libusb-backend")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use ndn_face_monitor_wifi::Mt7612uBackend;
    use std::time::{Duration, Instant};

    let dev = Mt7612uBackend::open()?;
    dev.bring_up()?;
    dev.set_channel_ch6()?;
    dev.setup_monitor_rx()?;
    dev.pause_drain(true);
    std::thread::sleep(Duration::from_millis(200));
    println!("chip 0x{:04x}", dev.chip_id()?);

    let k: usize = std::env::var("NDN_AGG_K").ok().and_then(|s| s.parse().ok()).unwrap_or(4);
    let plen = 256usize;
    let snap = [0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x86, 0x24];
    let frame = |sa: u8| -> Vec<u8> {
        let mut f = vec![0x08u8, 0x00, 0x00, 0x00];
        f.extend_from_slice(&[0xff; 6]);
        f.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, sa]);
        f.extend_from_slice(&[0xff; 6]);
        f.extend_from_slice(&[0x00, 0x00]);
        f.extend_from_slice(&snap);
        f.extend_from_slice(&vec![0xA5u8; plen]);
        f
    };
    let frames: Vec<Vec<u8>> = (1..=k as u8).map(frame).collect();
    let refs: Vec<&[u8]> = frames.iter().map(|f| f.as_slice()).collect();

    let n = 4000usize;
    let mut ok = 0u32;
    let mut bytes = 0usize;
    let t = Instant::now();
    for _ in 0..n {
        match dev.tx_data_agg(&refs, 0x4007) {
            Ok(w) => {
                ok += 1;
                bytes += w;
            }
            Err(_) => {}
        }
    }
    let el = t.elapsed();
    let payload = ok as usize * k * plen;
    println!("USB-agg K={k}: {ok}/{n} aggregates written ({} bulk B), {:.2}s", bytes, el.as_secs_f64());
    println!("  payload goodput: {:.1} Mb/s, {:.0} MPDU/s",
             payload as f64 * 8.0 / el.as_secs_f64() / 1e6, (ok as usize * k) as f64 / el.as_secs_f64());
    println!("done — receiver should show SA 02:00:00:00:00:0{{1..{k}}} each ~{n}x if chaining works.");
    Ok(())
}
#[cfg(not(feature = "libusb-backend"))]
fn main() {}
