//! A-MPDU burst flood — throughput probe for hardware MPDU aggregation.
//!
//! Sends `total` frames as A-MPDU bursts of `burst` MPDUs each (one PHY preamble
//! and one USB bulk-OUT per burst) versus one-MPDU-per-TX. Amortizing the
//! preamble/IFS and the USB round-trip is the lever toward the VHT PHY rate.
//!
//! Usage: `ampdu_flood [ch] [total] [mcs] [burst] [psize]`
//!   env RADIO_VHT=1, RADIO_NSS=2, AMPDU_OFF=1 (single-MPDU baseline)
#[cfg(feature = "libusb-backend")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use bytes::Bytes;
    use ndn_face_monitor_wifi::{
        BROADCAST, DEFAULT_SRC, InjectFrame, LibUsbRtl88xxBackend, McsDescriptor, FrameIo,
    };
    use std::sync::Arc;

    let mut a = std::env::args().skip(1);
    let ch: u8 = a.next().and_then(|s| s.parse().ok()).unwrap_or(149);
    let total: usize = a.next().and_then(|s| s.parse().ok()).unwrap_or(10000);
    let mcs: u8 = a.next().and_then(|s| s.parse().ok()).unwrap_or(7);
    let burst: usize = a.next().and_then(|s| s.parse().ok()).unwrap_or(16);
    let psize: usize = a.next().and_then(|s| s.parse().ok()).unwrap_or(256);

    let b = Arc::new(LibUsbRtl88xxBackend::open_monitor(ch)?);
    if let Ok(s) = std::env::var("RADIO_BW") {
        use ndn_face_monitor_wifi::ChannelBw;
        let bw = match s.as_str() {
            "40" => ChannelBw::Bw40,
            "80" => ChannelBw::Bw80,
            "10" => ChannelBw::Nb10,
            "5" => ChannelBw::Nb5,
            _ => ChannelBw::Bw20,
        };
        b.set_channel(ch, bw)?;
        println!("bandwidth {s} MHz");
    }
    if let Ok(p) = std::env::var("RADIO_TXPWR")
        && let Ok(idx) = u32::from_str_radix(p.trim_start_matches("0x"), 16)
    {
        b.set_tx_power(idx)?;
        println!("TX power idx {idx:#x}");
    }
    let vht = std::env::var("RADIO_VHT").is_ok();
    let nss2 = std::env::var("RADIO_NSS").map(|s| s == "2").unwrap_or(false);
    let desc = match (vht, nss2) {
        (true, true) => McsDescriptor::vht_2ss(mcs),
        (true, false) => McsDescriptor::vht(mcs),
        (false, _) => McsDescriptor::ht(mcs),
    };
    let off = std::env::var("AMPDU_OFF").is_ok();
    let amsdu = std::env::var("AMSDU").is_ok();
    let data: Bytes = (0..psize as u32).map(|i| (i & 0xff) as u8).collect();
    let rate = if vht { "VHT" } else { "HT" };
    let mode = if off {
        "single-MPDU (baseline)".to_string()
    } else if amsdu {
        format!("A-MSDU ({burst} MSDUs/MPDU)")
    } else {
        format!("A-MPDU bursts of {burst}")
    };
    println!("flooding {total} x {psize}B at {rate} MCS{mcs}, {mode}");

    let t0 = std::time::Instant::now();
    let mut sent = 0usize;
    // PIPELINE=<n>: keep n A-MSDU bulk-OUT writes in flight (fill the inter-transfer
    // bus gaps) instead of awaiting each serially — the lever once USB-bandwidth-bound.
    if let Ok(p) = std::env::var("PIPELINE") {
        let n: usize = p.parse().unwrap_or(4);
        let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(n));
        let mut handles = Vec::new();
        let mpdus = total / burst;
        for _ in 0..mpdus {
            let permit = sem.clone().acquire_owned().await.unwrap();
            let (b2, d) = (b.clone(), data.clone());
            handles.push(tokio::spawn(async move {
                let payloads: Vec<Bytes> = (0..burst).map(|_| d.clone()).collect();
                let _ = b2.inject_amsdu(&payloads, desc, BROADCAST, DEFAULT_SRC).await;
                drop(permit);
            }));
        }
        for h in handles {
            let _ = h.await;
        }
        sent = mpdus * burst;
        let dt = t0.elapsed().as_secs_f64();
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        println!(
            "transmitted {sent} frames in {dt:.2}s ({:.0} fps, {:.1} Mb/s offered) [pipeline {n}]",
            sent as f64 / dt,
            (sent * psize * 8) as f64 / dt / 1e6
        );
        return Ok(());
    }
    while sent < total {
        let n = burst.min(total - sent);
        if off {
            for _ in 0..n {
                b.inject(InjectFrame::broadcast(data.clone(), desc)).await?;
            }
        } else if let Ok(g) = std::env::var("USBAGG") {
            // USBAGG=<k>: pack k A-MSDU MPDUs (each `burst` MSDUs) into one bulk-OUT.
            let k: usize = g.parse().unwrap_or(4);
            let mpdus: Vec<Vec<Bytes>> =
                (0..k).map(|_| (0..burst).map(|_| data.clone()).collect()).collect();
            b.inject_amsdu_usbagg(&mpdus, desc, BROADCAST, DEFAULT_SRC).await?;
            sent += burst * k - n; // account: this path sent burst*k MSDUs
        } else if amsdu {
            let payloads: Vec<Bytes> = (0..n).map(|_| data.clone()).collect();
            b.inject_amsdu(&payloads, desc, BROADCAST, DEFAULT_SRC).await?;
        } else {
            let frames: Vec<InjectFrame> =
                (0..n).map(|_| InjectFrame::broadcast(data.clone(), desc)).collect();
            b.inject_ampdu(frames).await?;
        }
        sent += n;
    }
    let dt = t0.elapsed().as_secs_f64();
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    println!(
        "transmitted {sent} frames in {dt:.2}s ({:.0} fps, {:.1} Mb/s offered)",
        sent as f64 / dt,
        (sent * psize * 8) as f64 / dt / 1e6
    );
    Ok(())
}

#[cfg(not(feature = "libusb-backend"))]
fn main() {
    eprintln!("rebuild with `--features libusb-backend` (needs an RTL8812EU dongle)");
}
