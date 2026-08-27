//! **P5 campaign (c) — #101 filter false-positive sweep over E** (docs/p5c-eswep-prereg.md — read
//! it FIRST; claims, arms and thresholds are fixed there before any run, per the gate rule).
//!
//! Extends #106 (Tier-0 shadow mode at ONE E) into a swept curve over E = the receiver's
//! registered-prefix count, with the receiver-side baselines (NDN-NIC, Tier-1) on the SAME capture.
//!
//! Two roles:
//! * `esrc` — sends small objects `/p<i>/<seq>`, `i` cycling over UNIV prefixes, via a
//!   `with_tx_bloom` medium so each frame carries its OBJECT's real prefix-set Tier-0 filter in
//!   `addr1‖addr2` (the production `Tier0Addresser` packing path), nonce in `addr3`.
//! * `ecap` — raw-captures every attributable frame `(reassembled 12-byte filter, /p<i>/<seq>)`,
//!   then post-processes the whole E-sweep across all four arms offline and prints the matrix.
//!
//! FP is a function of the in-frame BITS + the query masks, not of link margin — so every arm and
//! every E sees the identical capture; channel/distance/drift are held fixed by construction. The
//! only on-air fact under test is that the Tier-0 bits SURVIVE the air (reassembly) with ZERO false
//! negatives, across E.
//!
//! ```sh
//! # esrc (o5p-0 a81a)                         # ecap (o5p-1 881a)
//! sudo NDN_PID=a81a NDN_RADIO_TX_RATE=4 ./campaign_e_sweep esrc 149 60
//! sudo NDN_PID=881a NDN_RADIO_TX_RATE=4 ./campaign_e_sweep ecap 149 60
//! ```

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("campaign_e_sweep drives a USB monitor radio — run it on the OPi");
}

#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use bytes::Bytes;
    use ndn_phy_wifi::ndn_nic::NdnNicFilter;
    use ndn_phy_wifi::tier1::Tier1;
    use ndn_phy_wifi::{
        FaceId, OPEN_GROUP_KEY, PrefixFilter, RadioBearer, RadioId, RadioMediumFace,
    };
    use ndn_transport::Transport;

    /// Universe of distinct registered-eligible prefixes `/p0 … /p{UNIV-1}`. E is swept up to
    /// UNIV/2 so a false-positive denominator (true negatives) always exists.
    const UNIV: u32 = 128;
    const E_VALUES: [u32; 7] = [1, 2, 4, 8, 16, 32, 64];
    /// Tier-1 BF-FIB sizing — the #92 receiver table (larger than Tier-0's 96 in-frame bits, the
    /// whole point of the "relays need Tier-1" thesis). 2048 bits/table, k=4 (matches Tier-0's k).
    const TIER1_BITS: usize = 2048;

    let args: Vec<String> = std::env::args().collect();
    let role = args.get(1).cloned().unwrap_or_else(|| "ecap".into());
    let channel: u8 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(149);
    let secs: u64 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(60);
    let pid = u16::from_str_radix(
        &std::env::var("NDN_PID").unwrap_or_else(|_| "a81a".into()),
        16,
    )?;

    /// Data(0x06)[ Name(0x07)[ comp(0x08)"p{i}", comp(0x08)"{seq}" ] ] — the exact shape `inner_name`
    /// + `ndn_name_to_slash` turn into `/p{i}/{seq}`, and small so the frame rate stays high.
    fn pkt(i: u32, seq: u32) -> Bytes {
        let g = format!("p{i}");
        let s = seq.to_string();
        let comps: [&[u8]; 2] = [g.as_bytes(), s.as_bytes()];
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

    /// Parse `/p{i}/{seq}` back out of a captured payload — returns None for anything not ours
    /// (ambient ch149 traffic), which is exactly how the capture population is gated to our frames.
    fn parse_ours(wire: &[u8]) -> Option<(u32, u32)> {
        if *wire.first()? != 0x06 {
            return None;
        }
        let name = wire.get(2..)?;
        if *name.first()? != 0x07 {
            return None;
        }
        let mut c = name.get(2..)?;
        let mut comps: Vec<String> = Vec::new();
        for _ in 0..2 {
            if *c.first()? != 0x08 {
                return None;
            }
            let len = *c.get(1)? as usize;
            comps.push(String::from_utf8_lossy(c.get(2..2 + len)?).to_string());
            c = c.get(2 + len..)?;
        }
        let i: u32 = comps[0].strip_prefix('p')?.parse().ok()?;
        let seq: u32 = comps[1].parse().ok()?;
        (i < UNIV).then_some((i, seq))
    }

    let open = ndn_radio_drivers::open_named_radio(pid, channel)?;
    let cap = ndn_radio_cognition::RadioCapability::wifi_monitor_5ghz(vec![channel]);
    let raw_rx: Option<Arc<dyn ndn_radio_hal::FrameIo>> = if role == "ecap" {
        Some(open.io.clone())
    } else {
        None
    };
    let medium = if role == "ecap" {
        None
    } else {
        Some(Arc::new(
            // TX-only bloom: each object's own prefix-set filter is packed per-frame. No RX gate,
            // no slot map (this is a filter experiment; the scheduler is deliberately out of frame).
            RadioMediumFace::new(
                FaceId(1),
                vec![RadioBearer::from_open(RadioId(0), open, cap)],
            )
            .with_tx_bloom(OPEN_GROUP_KEY)
            .build(),
        ))
    };
    let nonce_hex = |m: &ndn_phy_wifi::RunningMedium| -> String {
        m.source_nonce()
            .map(|n| n.iter().map(|b| format!("{b:02x}")).collect())
            .unwrap_or_default()
    };
    println!(
        "role={role} ch{channel} pid={pid:04x} {secs}s UNIV={UNIV} nonce={}",
        medium
            .as_ref()
            .map(|m| nonce_hex(m))
            .unwrap_or_else(|| "raw".into())
    );

    if role == "esrc" {
        let med = medium.clone().expect("esrc uses the medium");
        let end = Instant::now() + Duration::from_secs(secs);
        let (mut seq, mut sent) = (0u32, 0u64);
        while Instant::now() < end {
            let i = seq % UNIV; // uniform cycle over the whole universe
            if med.send_bytes(pkt(i, seq)).await.is_ok() {
                sent += 1;
            }
            seq += 1;
        }
        println!("=== esrc ===");
        println!("sent              : {sent}");
        println!("nonce(end)        : {}", nonce_hex(&med));
        return Ok(());
    }

    // ── ecap: capture, then sweep ────────────────────────────────────────────────────────────
    let raw = raw_rx.expect("ecap keeps the raw io");
    // (12-byte reassembled Tier-0 filter, i, seq) per attributable frame.
    let mut cap_frames: Vec<([u8; 16], u32, u32)> = Vec::with_capacity(20_000);
    let end = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < end {
        match tokio::time::timeout(Duration::from_millis(300), raw.recv_frame()).await {
            Ok(Ok(f)) => {
                let Some((i, seq)) = parse_ours(&f.payload) else {
                    continue;
                };
                // Reassemble addr1‖addr2 → the on-air Tier-0 filter (group=addr1 hi, addr=addr2 lo).
                let (Some(a1), Some(a2)) = (f.group, f.addr) else {
                    continue;
                };
                let mut w = [0u8; 16];
                w[..6].copy_from_slice(&a1);
                w[6..12].copy_from_slice(&a2);
                cap_frames.push((w, i, seq));
            }
            _ => continue,
        }
    }

    let n = cap_frames.len();
    println!("=== ecap ===");
    println!("captured (ours)   : {n}   <-- N; 0 ⇒ instrument-invalid (silent-zero guard)");
    if n == 0 {
        return Ok(());
    }

    let key = &OPEN_GROUP_KEY.0;
    // Wilson 95% score interval for a proportion — honest small-count error bars.
    fn wilson(k: u64, nn: u64) -> (f64, f64, f64) {
        if nn == 0 {
            return (0.0, 0.0, 0.0);
        }
        let z = 1.96f64;
        let p = k as f64 / nn as f64;
        let nf = nn as f64;
        let denom = 1.0 + z * z / nf;
        let centre = (p + z * z / (2.0 * nf)) / denom;
        let half = (z * ((p * (1.0 - p) + z * z / (4.0 * nf)) / nf).sqrt()) / denom;
        (p, (centre - half).max(0.0), (centre + half).min(1.0))
    }

    struct Row {
        e: u32,
        // (fp, tn, fn, tp) per arm
        none: (u64, u64, u64, u64),
        tier0: (u64, u64, u64, u64),
        nic: (u64, u64, u64, u64),
        tier1: (u64, u64, u64, u64),
    }
    let mut rows: Vec<Row> = Vec::new();

    for &e in &E_VALUES {
        // Registered prefixes /p0 … /p{e-1} and the derived filters.
        let regs: Vec<String> = (0..e).map(|i| format!("/p{i}")).collect();
        let masks: Vec<PrefixFilter> = regs
            .iter()
            .map(|p| PrefixFilter::mask_for(key, p.as_bytes()))
            .collect();
        let nic = NdnNicFilter::paper_default(key, &regs);
        let mut t1 = Tier1::new(key, TIER1_BITS, 4);
        for p in &regs {
            t1.register_prefix(p.as_bytes());
        }

        let (mut none, mut tier0, mut nic_c, mut tier1_c) = (
            (0u64, 0u64, 0u64, 0u64),
            (0u64, 0u64, 0u64, 0u64),
            (0u64, 0u64, 0u64, 0u64),
            (0u64, 0u64, 0u64, 0u64),
        );
        for (w, i, seq) in &cap_frames {
            let relevant = *i < e; // ground truth: object /p{i}/… is under a registered prefix
            let full = format!("/p{i}/{seq}");
            let frame = PrefixFilter::from_wire(*w);
            let admits = [
                true,                                     // none
                masks.iter().any(|m| frame.may_match(m)), // tier0 (on-air bits)
                nic.may_serve(full.as_bytes()),           // ndn-nic (receiver-side)
                t1.lookup(full.as_bytes()).fib,           // tier1 (receiver-side)
            ];
            for (arm, &adm) in [&mut none, &mut tier0, &mut nic_c, &mut tier1_c]
                .into_iter()
                .zip(admits.iter())
            {
                match (adm, relevant) {
                    (true, false) => arm.0 += 1,  // FP
                    (false, false) => arm.1 += 1, // TN
                    (false, true) => arm.2 += 1,  // FN
                    (true, true) => arm.3 += 1,   // TP
                }
            }
        }
        rows.push(Row {
            e,
            none,
            tier0,
            nic: nic_c,
            tier1: tier1_c,
        });
    }

    // ── Report ───────────────────────────────────────────────────────────────────────────────
    let fp_rate = |a: &(u64, u64, u64, u64)| -> (f64, f64, f64) { wilson(a.0, a.0 + a.1) };
    let fn_ct = |a: &(u64, u64, u64, u64)| a.2;

    println!(
        "\nFALSE-POSITIVE rate vs E (FP / negatives), Wilson 95% CI.  receiver state: \
         tier0=0 B  ndn-nic/tier1={} B",
        TIER1_BITS / 8
    );
    println!(
        "{:>4} {:>8} {:>22} {:>22} {:>22}",
        "E", "neg", "tier0 FP", "ndn-nic FP", "tier1 FP"
    );
    let fp1_tier0 = fp_rate(&rows[0].tier0).0; // FP(1) for the independence prediction
    for r in &rows {
        let neg = r.tier0.0 + r.tier0.1;
        let f = |a: &(u64, u64, u64, u64)| {
            let (p, lo, hi) = fp_rate(a);
            format!("{:6.3}% [{:5.2},{:5.2}]", p * 100.0, lo * 100.0, hi * 100.0)
        };
        println!(
            "{:>4} {:>8} {:>22} {:>22} {:>22}",
            r.e,
            neg,
            f(&r.tier0),
            f(&r.nic),
            f(&r.tier1)
        );
    }

    println!("\nTier-0 curve check — measured FP(E) vs independence prediction 1-(1-FP(1))^E:");
    println!("{:>4} {:>12} {:>12}", "E", "measured", "predicted");
    for r in &rows {
        let meas = fp_rate(&r.tier0).0;
        let pred = 1.0 - (1.0 - fp1_tier0).powi(r.e as i32);
        println!("{:>4} {:>11.3}% {:>11.3}%", r.e, meas * 100.0, pred * 100.0);
    }

    // Safety invariant + crossover (the #101 thesis).
    let tier0_fn: u64 = rows.iter().map(|r| fn_ct(&r.tier0)).sum();
    let tier1_fn: u64 = rows.iter().map(|r| fn_ct(&r.tier1)).sum();
    let nic_fn: u64 = rows.iter().map(|r| fn_ct(&r.nic)).sum();
    println!(
        "\nSAFETY INVARIANT (must be 0):  tier0 FN = {tier0_fn}   tier1 FN = {tier1_fn}   \
         (ndn-nic FN = {nic_fn})"
    );
    let cross = |sel: fn(&Row) -> &(u64, u64, u64, u64)| -> String {
        rows.iter()
            .find(|r| fp_rate(sel(r)).0 >= 0.05)
            .map(|r| r.e.to_string())
            .unwrap_or_else(|| format!(">{}", E_VALUES.last().unwrap()))
    };
    println!(
        "CROSSOVER (smallest E with FP ≥ 5%):  tier0 E*={}   ndn-nic E*={}   tier1 E*={}",
        cross(|r| &r.tier0),
        cross(|r| &r.nic),
        cross(|r| &r.tier1)
    );
    println!(
        "#101 thesis (Tier-0 belongs at small E; relays need the larger Tier-1 table) supported iff \
         tier0 E* < tier1/ndn-nic E*."
    );
    Ok(())
}
