//! Frequency agility: CLM-driven channel selection + a rendezvous beacon.
//!
//! The named-data radio shouldn't sit on a congested channel (ch149 cost ~15%
//! delivery vs a quiet channel). This demonstrates the agility cycle:
//!
//! - SENSE: measure CLM busy-% on candidate channels.
//! - SELECT: pick the clearest as the data channel.
//! - ANNOUNCE: return to a well-known rendezvous channel and broadcast a presence
//!   beacon naming the chosen data channel, so peers follow without association.
//! - OPERATE: hop to the data channel and carry named data there.
//!
//! Rendezvous design (control-channel announce + agile data channel): a fixed,
//! well-known rendezvous channel is the meeting point; each node spends most of
//! its time on its (dynamically-selected) data channel but periodically returns
//! to the rendezvous channel to (a) broadcast where it is and (b) hear peers.
//! The beacon payload is `b"RZV"` + `[data_channel, busy_pct]` so a peer (or a
//! kernel-monitor sniffer) can read the announced channel straight from the air.
//! A fuller version makes the beacon a proper named NDN record carrying the CLM
//! map (collaborative spectrum sensing), and dwells/hops on a schedule.
//!
//! Usage: `freq_agile [rendezvous_ch] [candidate ch ...]`
#[cfg(feature = "libusb-backend")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use bytes::Bytes;
    use ndn_face_monitor_wifi::{
        ChannelBw, InjectFrame, LibUsbRtl88xxBackend, McsDescriptor, FrameIo,
    };
    use std::sync::Arc;

    let mut args = std::env::args().skip(1);
    let rendezvous_ch: u8 = args.next().and_then(|s| s.parse().ok()).unwrap_or(149);
    let candidates: Vec<u8> = {
        let rest: Vec<u8> = args.filter_map(|s| s.parse().ok()).collect();
        if rest.is_empty() {
            vec![36, 40, 44, 48, 153, 157, 161, 165]
        } else {
            rest
        }
    };
    let window_us = 50_000; // 50 ms CLM window per candidate

    let backend = Arc::new(LibUsbRtl88xxBackend::open_monitor(rendezvous_ch)?);

    // 1+2. SENSE + SELECT: one CLM scan → print the map, pick the clearest.
    // (`backend.pick_clear_channel(&candidates, window_us)` does steps 1+2 in one
    // call for real faces; here we scan inline so we can print the whole map.)
    println!("[sense] scanning {} candidates with CLM…", candidates.len());
    let mut map: Vec<(u8, u8)> = Vec::with_capacity(candidates.len());
    for &ch in &candidates {
        backend.set_channel(ch, ChannelBw::Bw20)?;
        std::thread::sleep(std::time::Duration::from_millis(15));
        let busy = backend.measure_clm(window_us).unwrap_or(100);
        println!("        ch{ch:<3} busy {busy:>3}%");
        map.push((ch, busy));
    }
    let (data_ch, busy) = *map.iter().min_by_key(|(_, b)| *b).expect("non-empty candidates");
    println!("[select] clearest data channel = ch{data_ch} ({busy}% busy)");

    // 3. ANNOUNCE: presence beacon on the rendezvous channel.
    backend.set_channel(rendezvous_ch, ChannelBw::Bw20)?;
    let beacon: Bytes = {
        let mut v = b"RZV".to_vec();
        v.push(data_ch);
        v.push(busy);
        Bytes::from(v)
    };
    println!("[announce] beaconing data ch{data_ch} on rendezvous ch{rendezvous_ch}…");
    for _ in 0..200 {
        backend
            .inject(InjectFrame::broadcast(beacon.clone(), McsDescriptor::ht(1)))
            .await?;
    }

    // 4. OPERATE: carry data on the selected channel.
    backend.set_channel(data_ch, ChannelBw::Bw20)?;
    let data: Bytes = (0..200u32).map(|i| (i & 0xff) as u8).collect();
    println!("[operate] sending data on ch{data_ch}…");
    for _ in 0..2000 {
        backend
            .inject(InjectFrame::broadcast(data.clone(), McsDescriptor::ht(5)))
            .await?;
    }
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    println!("[done] sensed → selected ch{data_ch} → announced on ch{rendezvous_ch} → operated");
    Ok(())
}

#[cfg(not(feature = "libusb-backend"))]
fn main() {
    eprintln!("rebuild with `--features libusb-backend` (needs an RTL8812EU dongle)");
}
