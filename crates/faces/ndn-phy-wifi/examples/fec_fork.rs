//! Task #33, piece 1: does the plan's `link_fec_redundancy` lift delivery **on
//! air**, driven through the face's `planned` cell rather than the bench's
//! application-layer `coded_shape`?
//!
//! #32 wired the knob and proved it on the loopback bus (a K=2 generation grew
//! from 3 frames to 7 when the plan forced R=5). This session's standing lesson is
//! that loopback-green is not on-air-true, so that is not a finish line.
//!
//! One-way by design (like `burst_fork`/`reach_fork`): no Interest/Data round-trip,
//! no stop-and-wait, so nothing confounds the FEC effect. A "generation" is K
//! source frames; the face batches them and emits K+R coded frames, and the RX
//! face recovers all K from any K of the N. We count how many generations arrive
//! **complete** as R climbs — that, not frame count, is the delivery the redundancy
//! budget is spent to buy.
//!
//! The R is driven ENTIRELY by the plan cell. The face is constructed with R=0, so
//! any parity on air is the plan's doing and nothing else — the strongest form of
//! the #32 proof, now on real radios.
//!
//!   # peer first
//!   sudo NDN_RADIO_NO_RESET=1 LD_LIBRARY_PATH=$(nix path-info nixpkgs#libusb1)/lib \
//!       ./fec_fork rx 260
//!   sudo NDN_RADIO_NO_RESET=1 LD_LIBRARY_PATH=... ./fec_fork tx
#[cfg(feature = "libusb-backend")]
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use bytes::Bytes;
    use ndn_phy_wifi::{Rtl8812auBackend, WifiPhy};
    use ndn_frame_io::{FaceId, FrameFormat};
    use ndn_radio_cognition::TxParams;
    use ndn_transport::Transport;
    use std::collections::BTreeMap;
    use std::sync::{Arc, RwLock};
    use std::time::{Duration, Instant};

    // K source frames per generation; sweep R (parity). PER_R generations per R.
    const K: usize = 4;
    const RS: [u16; 4] = [0, 1, 2, 4];
    const PER_R: usize = 40;
    // One source frame's payload size — a mid-size frame well under MONITOR_MTU, so
    // each send_bytes is exactly one on-air frame (no LP fragmentation in play; we
    // drive the transport directly, below the LpLinkService).
    const FRAME_LEN: usize = 1400;
    const MAGIC: &[u8; 2] = b"FK";
    const WINDOW: Duration = Duration::from_millis(500);

    let mode = std::env::args().nth(1).unwrap_or_else(|| "rx".into());
    let secs: u64 = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(260);
    // FK_CH lets a liveness sweep try channels when ch6 looks jammed. Both ends
    // must agree; monitor-mode injection needs no association, so any channel works.
    let ch: u8 = std::env::var("FK_CH")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(6);

    let b = Rtl8812auBackend::open()?.with_format(FrameFormat::default());
    b.power_on()?;
    b.mac_enable_dma()?;
    b.init_llt()?;
    b.download_firmware()?;
    b.mac_config()?;
    b.mac_init_queues()?;
    b.bb_config()?;
    b.rf_config()?;
    b.set_channel(ch)?;
    b.iq_calibrate()?;
    b.lc_calibrate()?;
    b.set_tx_power(0x3f)?;
    b.start_rx_dma()?;
    let b = Arc::new(b);
    b.spawn_rx_pump(1);
    println!("8812AU pid={:#06x} up on ch{ch}", b.pid());

    // The face is built with R=0. All parity comes from the plan cell — so a
    // non-zero count on air is proof the plan reached the air, not the constructor.
    let cell = Arc::new(RwLock::new(None::<TxParams>));
    let face = WifiPhy::new(FaceId(7), b.clone())
        .with_link_fec(K, 0, WINDOW)
        .with_planned_params(cell.clone());

    if mode == "tx" {
        println!("tx: K={K}, sweeping R={RS:?}, {PER_R} generations each");
        for &r in &RS {
            *cell.write().unwrap() = Some(TxParams {
                link_fec_redundancy: Some(r),
                ..Default::default()
            });
            // Let the cell settle before the first generation of this R.
            tokio::time::sleep(Duration::from_millis(50)).await;
            for g in 0..PER_R {
                for k in 0..K {
                    // FK | R | gen_id(2) | frag(1), padded. gen_id is unique across the
                    // whole run so the receiver never conflates two generations.
                    let gen_id = (r as usize * PER_R + g) as u16;
                    let mut p = Vec::with_capacity(FRAME_LEN);
                    p.extend_from_slice(MAGIC);
                    p.push(r as u8);
                    p.extend_from_slice(&gen_id.to_le_bytes());
                    p.push(k as u8);
                    while p.len() < FRAME_LEN {
                        p.push((p.len() & 0xff) as u8);
                    }
                    face.send_bytes(Bytes::from(p)).await?;
                    // Small inter-frame gap; burst is a settled non-factor
                    // (burst_fork), and this keeps the pump from starving.
                    tokio::time::sleep(Duration::from_millis(2)).await;
                }
                // Idle a generation-worth so one generation's frames never bleed
                // into the next on the wire.
                tokio::time::sleep(Duration::from_millis(30)).await;
            }
            println!("tx: R={r} done ({PER_R} generations)");
        }
        println!("tx: done");
        return Ok(());
    }

    // rx: recover generations and count, per R, how many arrived COMPLETE (all K
    // source frames delivered — the FEC feature hands up recovered sources).
    println!("rx: recovering generations for {secs}s (K={K}) …");
    // (R, gen_id) -> set of distinct source frag indices delivered.
    let mut seen: BTreeMap<(u8, u16), std::collections::HashSet<u8>> = BTreeMap::new();
    let t0 = Instant::now();
    while t0.elapsed() < Duration::from_secs(secs) {
        match tokio::time::timeout(Duration::from_millis(500), face.recv_bytes()).await {
            Ok(Ok(payload)) => {
                let f = &payload[..];
                if f.len() < 6 || &f[0..2] != MAGIC {
                    continue;
                }
                let r = f[2];
                let gen_id = u16::from_le_bytes([f[3], f[4]]);
                let frag = f[5];
                if RS.contains(&(r as u16)) && (frag as usize) < K {
                    seen.entry((r, gen_id)).or_default().insert(frag);
                }
            }
            Ok(Err(_)) | Err(_) => continue,
        }
    }

    println!("\n  generations delivered COMPLETE / {PER_R} sent\n");
    println!("{:>4}  {:>10}  {:>12}", "R", "on air", "complete");
    for &r in &RS {
        let complete = (0..PER_R)
            .filter(|g| {
                let gen_id = (r as usize * PER_R + g) as u16;
                seen.get(&(r as u8, gen_id)).map(|s| s.len()).unwrap_or(0) >= K
            })
            .count();
        // K+R frames per generation went on air (before loss).
        println!(
            "{:>4}  {:>10}  {:>7}/{:<4}",
            r,
            K as u16 + r,
            complete,
            PER_R
        );
    }
    println!(
        "\n  Delivery must RISE with R. R=0 recovers a generation only if all K\n  \
         source frames happened to arrive; each added parity frame lets one more\n  \
         lost frame be recovered. Flat or falling => the plan's redundancy is not\n  \
         reaching the air (or the link is too clean to lose anything — check that\n  \
         R=0 is below 100%)."
    );
    Ok(())
}

#[cfg(not(feature = "libusb-backend"))]
fn main() {
    eprintln!("build with --features libusb-backend");
}
