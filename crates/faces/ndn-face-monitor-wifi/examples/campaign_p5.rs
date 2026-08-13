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

    fn pkt(group: &str, seq: u32) -> Bytes {
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
    // The obs role reads raw frames for RSSI; the same Arc<dyn FrameIo> also feeds the bearer
    // (the driver's RX pump fans in one stream — recv_frame consumers compete, which is fine for
    // obs: its medium side only TRANSMITS /light, and a stolen frame on the TX-side reader costs
    // nothing the meter was owed).
    let raw_rx = if role == "obs" { Some(open.io.clone()) } else { None };
    // TX power (claim-C prereg + bench power hygiene): TXAGC index 0..63 via RadioKnobs — the
    // campaign backends do NOT read NDN_RADIO_TXPWR natively (only the 8821c does), so the tool
    // applies it explicitly and prints what it applied. Unset = the driver's calibrated default.
    let txpwr: Option<u32> = std::env::var("NDN_RADIO_TXPWR").ok().and_then(|v| v.parse().ok());
    if let (Some(idx), Some(knobs)) = (txpwr, open.knobs.as_ref()) {
        knobs.set_tx_power(idx)?;
    }
    let cap = RadioCapability::wifi_monitor_5ghz(vec![channel]);
    let medium = Arc::new(
        RadioMediumFace::new(FaceId(1), vec![RadioBearer::from_open(RadioId(0), open, cap)])
            // One filter, one map, on air: every node registers the same groups under the open
            // key; /alarm is latency-class in every node's table (the shared map).
            .with_bloom_latency(
                &OPEN_GROUP_KEY,
                &[b"/bulk".as_slice(), b"/alarm".as_slice(), b"/light".as_slice()],
                &[b"/alarm".as_slice()],
            )
            .build(),
    );
    println!(
        "role={role} ch{channel} pid={pid:04x} {secs}s txpwr={}",
        txpwr.map(|i| i.to_string()).unwrap_or_else(|| "default".into())
    );

    match role.as_str() {
        "bulk" => {
            let end = Instant::now() + Duration::from_secs(secs);
            let mut seq = 0u32;
            while Instant::now() < end {
                if medium.send_bytes(pkt("bulk", seq)).await.is_ok() {
                    seq += 1;
                }
            }
            println!("=== bulk ===");
            println!("sent              : {seq}");
        }
        "lat" => {
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
            // OBS reads RAW frames (FrameIo::recv_frame) rather than the medium: CapturedFrame
            // carries rssi_dbm, which the Transport surface drops — and per-group RSSI is the
            // claim-C instrument (TXAGC verification + the capture-asymmetry diagnostic). The
            // payload is the same NDN wire the medium parses, so the counter semantics match.
            // Cost, stated: the obs node no longer exercises the RX gate/scheduler paths — it is a
            // meter, and the /light sender below still runs through the full medium TX path.
            let light = {
                let m = medium.clone();
                tokio::spawn(async move {
                    let mut seq = 0u32;
                    let end = Instant::now() + Duration::from_secs(secs);
                    while Instant::now() < end {
                        let _ = m.send_bytes(pkt("light", seq)).await;
                        seq += 1;
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                    seq
                })
            };
            let io = medium.scheduler(); // keep the medium alive for /light
            let _ = io;
            let raw = raw_rx.expect("obs keeps the raw io");
            let mut heard: BTreeMap<String, (u64, i64, u64)> = BTreeMap::new(); // count, rssi sum, rssi n
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
    // Every role reports the scheduler's own instrumentation — the counters the prereg names.
    if let Some(s) = medium.scheduler() {
        let (attempts, wins) = s.claim_counts();
        let (elections, ewins, holds) = s.election_counts();
        println!("claim attempts/wins: {attempts} / {wins}");
        println!("elections paid/won : {elections} / {ewins}   hold continuations: {holds}");
        println!("ambient frames    : {}", s.ambient_frames());
    }
    Ok(())
}
