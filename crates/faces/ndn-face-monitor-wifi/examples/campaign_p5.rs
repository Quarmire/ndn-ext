//! **P5 — the pre-registered campaign** (docs/p5-preregistration.md — read it FIRST; the claims,
//! counters and pass thresholds are fixed there before any run, per the gate rule).
//!
//! Three roles on one channel:
//! * `bulk` — saturating sender of `/bulk` (claim + lease per env); prints sent + claim counters.
//! * `lat`  — paced sender of `/alarm` (the latency-class group); measures each frame's GATE WAIT
//!   (the access-delay metric the lanes bound) and prints max/mean/count.
//! * `obs`  — receiver; counts heard frames per group (the delivery metric).
//!
//! Every node registers the same groups via `with_bloom_latency` — the P1 "one filter, one map"
//! path, on air for the first time: frames carry Tier-0 filters, the RX gate and the scheduler
//! both read them, `/alarm` is latency-class in every node's table.
//!
//! ```sh
//! # obs (o5p-1 881a)         # lat (o5p-2 8812au)        # bulk (o5p-0 a81a)
//! ./campaign_p5 obs 149 40   ./campaign_p5 lat 149 40    ./campaign_p5 bulk 149 40
//! # arms via env: NDN_SCHED_SLOT=8:20000 NDN_SCHED_RESERVE={0|4} NDN_SCHED_CLAIM=1
//! #               NDN_SCHED_LEASE={1|8}  (see the prereg doc for the arm matrix)
//! ```

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("campaign_p5 drives a USB monitor radio — run it on the OPi");
}

#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use bytes::Bytes;
    use ndn_face_monitor_wifi::{FaceId, OPEN_GROUP_KEY, RadioBearer, RadioId, RadioMediumFace};
    use ndn_radio_cognition::RadioCapability;
    use ndn_transport::Transport;

    let args: Vec<String> = std::env::args().collect();
    let role = args.get(1).cloned().unwrap_or_else(|| "obs".into());
    let channel: u8 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(149);
    let secs: u64 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(40);
    let pid = u16::from_str_radix(&std::env::var("NDN_PID").unwrap_or_else(|_| "a81a".into()), 16)?;
    let lat_per_sec: u64 = std::env::var("RATE").ok().and_then(|s| s.parse().ok()).unwrap_or(20);

    /// Claim-C v2: bulk frames are MTU-SIZED so a lease-held slot is substantially OCCUPIED, not
    /// merely owned — v1 measured ~15-B frames at ~7% duty, and a lease's collision pressure is
    /// its airtime, not its slot count. 1400 B ≈ 1.9 ms at 6M ≈ ~10 frames fill a 20 ms slot.
    const BULK_PAYLOAD: usize = 1400;

    fn pkt_sized(group: &str, seq: u32, total: usize) -> Bytes {
        // Data(0x06) [ Name(0x07)[c1,c2] Content(0x15) pad ] with proper TLV lengths (0xfd u16
        // form above 252) — the tiny-frame builder's single-byte lengths cap at 255 B total.
        fn tlv(t: u8, v: &[u8]) -> Vec<u8> {
            let mut o = vec![t];
            if v.len() < 253 {
                o.push(v.len() as u8);
            } else {
                o.push(0xfd);
                o.extend_from_slice(&(v.len() as u16).to_be_bytes());
            }
            o.extend_from_slice(v);
            o
        }
        let sseq = seq.to_string();
        let mut name_v = Vec::new();
        name_v.extend(tlv(0x08, group.as_bytes()));
        name_v.extend(tlv(0x08, sseq.as_bytes()));
        let name = tlv(0x07, &name_v);
        let mut body = name;
        if total > 0 {
            let overhead = body.len() + 8; // outer TLV + content header slack
            let pad = total.saturating_sub(overhead);
            body.extend(tlv(0x15, &vec![0xa5u8; pad]));
        }
        Bytes::from(tlv(0x06, &body))
    }

    fn pkt(group: &str, seq: u32) -> Bytes {
        pkt_sized(group, seq, 0)
    }

    #[allow(dead_code)]
    fn unused(group: &str, seq: u32) -> Bytes {
        let s = seq.to_string();
        let comps: [&[u8]; 2] = [group.as_bytes(), s.as_bytes()];
        let mut name = Vec::new();
        for c in comps {
            name.push(0x08);
            name.push(c.len() as u8);
            name.extend_from_slice(c);
        }
        let mut tlv = vec![0x07, name.len() as u8];
        tlv.extend_from_slice(&name);
        let mut d = vec![0x06, tlv.len() as u8];
        d.extend_from_slice(&tlv);
        Bytes::from(d)
    }

    /// First name component (same inline parser as slot_ab_onair — the exact shape `pkt` emits).
    fn first_component(wire: &[u8]) -> Option<String> {
        let w = wire;
        if *w.first()? != 0x06 {
            return None;
        }
        let name = w.get(2..)?;
        if *name.first()? != 0x07 {
            return None;
        }
        let comps = name.get(2..)?;
        if *comps.first()? != 0x08 {
            return None;
        }
        let len = *comps.get(1)? as usize;
        Some(String::from_utf8_lossy(comps.get(2..2 + len)?).to_string())
    }

    let open = ndn_radio_drivers::open_named_radio(pid, channel)?;
    let cap = ndn_radio_cognition::RadioCapability::wifi_monitor_5ghz(vec![channel]);
    // TX power (claim-C prereg + bench power hygiene): TXAGC index via RadioKnobs — clamped to the
    // B210-verified monotone range by the driver (061274c). Unset = calibrated default.
    let txpwr: Option<u32> = std::env::var("NDN_RADIO_TXPWR").ok().and_then(|v| v.parse().ok());
    if let (Some(idx), Some(knobs)) = (txpwr, open.knobs.as_ref()) {
        knobs.set_tx_power(idx)?;
    }
    // OBS is raw-only: no medium, no second recv_frame consumer (the batch-1 half-split lesson).
    let raw_rx: Option<std::sync::Arc<dyn ndn_radio_hal::FrameIo>> =
        if role == "obs" { Some(open.io.clone()) } else { None };
    let medium = if role == "obs" {
        None
    } else {
        Some(Arc::new(
            RadioMediumFace::new(FaceId(1), vec![RadioBearer::from_open(RadioId(0), open, cap)])
                .with_bloom_latency(
                    &OPEN_GROUP_KEY,
                    &[b"/bulk".as_slice(), b"/alarm".as_slice(), b"/light".as_slice()],
                    &[b"/alarm".as_slice()],
                )
                .build(),
        ))
    };
    let nonce_hex = |m: &ndn_face_monitor_wifi::RunningMedium| -> String {
        m.source_nonce().map(|n| n.iter().map(|b| format!("{b:02x}")).collect()).unwrap_or_default()
    };
    println!(
        "role={role} ch{channel} pid={pid:04x} {secs}s txpwr={} nonce={} bulk_payload={BULK_PAYLOAD}",
        txpwr.map(|i| i.to_string()).unwrap_or_else(|| "default".into()),
        medium.as_ref().map(|m| nonce_hex(m)).unwrap_or_else(|| "raw".into())
    );

    match role.as_str() {
        "bulk" => {
            let medium = medium.clone().expect("bulk uses the medium");
            let end = Instant::now() + Duration::from_secs(secs);
            let mut seq = 0u32;
            while Instant::now() < end {
                if medium.send_bytes(pkt_sized("bulk", seq, BULK_PAYLOAD)).await.is_ok() {
                    seq += 1;
                }
            }
            println!("=== bulk ===");
            println!("sent              : {seq}");
        }
        "lat" => {
            let medium = medium.clone().expect("lat uses the medium");
            let gap = Duration::from_micros(1_000_000 / lat_per_sec.max(1));
            let end = Instant::now() + Duration::from_secs(secs);
            let (mut seq, mut waits_us) = (0u32, Vec::new());
            while Instant::now() < end {
                let t = Instant::now();
                if medium.send_bytes(pkt("alarm", seq)).await.is_ok() {
                    seq += 1;
                    waits_us.push(t.elapsed().as_micros() as u64);
                }
                tokio::time::sleep(gap).await;
            }
            waits_us.sort_unstable();
            let max = waits_us.last().copied().unwrap_or(0);
            let mean = waits_us.iter().sum::<u64>() / waits_us.len().max(1) as u64;
            let p99 = waits_us[(waits_us.len() * 99 / 100).min(waits_us.len().saturating_sub(1))];
            println!("=== lat ===");
            println!("sent              : {seq}");
            println!("gate wait µs      : max {max}  p99 {p99}  mean {mean}   <-- the access-delay metric");
        }
        _ => {
            // OBS is RAW-ONLY (claim-C batch-1 lesson, discarded): with both the raw RSSI meter
            // and the medium's RX reader consuming one recv_frame stream, each saw ~HALF the
            // frames — 150/282 alarms, 13157/26550 bulk, the 50% split signature on both groups
            // at once. One consumer or the counts are fiction. So obs never builds the medium's
            // RX side at all: /light is injected RAW (legacy broadcast shape — A attributes it on
            // the parse path), and the meter is the sole recv_frame consumer.
            let light = {
                let io = raw_rx.clone().expect("obs keeps the raw io");
                tokio::spawn(async move {
                    let mut seq = 0u32;
                    let end = Instant::now() + Duration::from_secs(secs);
                    // A fixed locally-administered source: /light's owner nonce. Stable across the
                    // run so A's per-slot evidence stays a singleton (no P4 discounting).
                    let src = [0x02u8, 0x4c, 0x49, 0x54, 0x45, 0x01]; // "LITE"-ish, U/L=local
                    while Instant::now() < end {
                        let f = ndn_radio_hal::InjectFrame {
                            payload: pkt("light", seq),
                            tx: ndn_radio_hal::TxIntent::ROBUST,
                            dst: ndn_radio_hal::BROADCAST,
                            src,
                            addr3: None,
                        };
                        let _ = io.inject(f).await;
                        seq += 1;
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                    seq
                })
            };
            let raw = raw_rx.expect("obs keeps the raw io");
            let mut heard: BTreeMap<String, (u64, i64, u64)> = BTreeMap::new();
            let end = Instant::now() + Duration::from_secs(secs);
            while Instant::now() < end {
                match tokio::time::timeout(Duration::from_millis(300), raw.recv_frame()).await {
                    Ok(Ok(f)) => {
                        let g = first_component(&f.payload).unwrap_or_else(|| "?".into());
                        let e = heard.entry(g).or_default();
                        e.0 += 1;
                        if let Some(r) = f.rssi_dbm {
                            e.1 += i64::from(r);
                            e.2 += 1;
                        }
                    }
                    _ => continue,
                }
            }
            println!("light sent        : {}", light.await.unwrap_or(0));
            println!("=== obs ===");
            for (g, (c, rs, rn)) in &heard {
                let rssi = if *rn > 0 { format!("{} dBm", rs / *rn as i64) } else { "-".into() };
                println!("heard /{g:<8}: {c:<7} rssi mean {rssi}");
            }
        }
    }
    // Nonce at END too: if it differs from the header, a §2 rotation boundary fell inside the run
    // and any DEAF_SRC keyed on the start nonce silently broke — the run is instrument-invalid.
    if let Some(m) = &medium {
        println!("nonce(end)        : {}", nonce_hex(m));
    }
    // Every role reports the scheduler's own instrumentation — the counters the prereg names.
    if let Some(s) = medium.as_ref().and_then(|m| m.scheduler()) {
        let (attempts, wins) = s.claim_counts();
        let (elections, ewins, holds) = s.election_counts();
        println!("claim attempts/wins: {attempts} / {wins}");
        println!("elections paid/won : {elections} / {ewins}   hold continuations: {holds}");
        println!("ambient frames    : {}", s.ambient_frames());
    }
    Ok(())
}
