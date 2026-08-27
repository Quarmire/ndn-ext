//! **On-air confirmation of the two #82 claims that were only ever loopback-verified.**
//!
//! 1. **Tier-0 addressing survives link-FEC.** Coded frames must carry the object's prefix-set
//!    filter across `addr1 ‖ addr2` with the ephemeral nonce in `addr3`, so a receiver registered on
//!    that prefix admits them. Before the fix the sink pinned only `dst`, leaving the sender's fixed
//!    `DEFAULT_SRC` in `addr2` — the receiver reassembled half a filter and dropped the frame. A
//!    false negative, not a lost optimisation.
//! 2. **The medium actuates a plan-decided rate.** A `RadioPlan` deciding an MCS must change what
//!    goes on air; the medium modelled rate as pure bearer state and applied nothing.
//!
//! Both are unfalsifiable from the transmitter — the whole failure mode of #82 was code that looks
//! right from the deciding side. So the receiver is the instrument: it reassembles `addr1 ‖ addr2`,
//! runs the **real** `NameGate`, and reads each frame's decoded rate off the RX descriptor.
//!
//! ## The A/B
//!
//! `tx` alternates two arms every `PERIOD` frames, so both see the same channel, the same distance
//! and the same interference — the only difference is the address layout:
//!
//! * `new` — the shipped path: `RadioMediumFace` with `with_bloom` + `with_link_fec`.
//! * `old` — a faithful replay of the pre-fix sink, injected directly on the same radio:
//!   `addr1` = filter hi (the old pin's `dst`), `addr2` = `DEFAULT_SRC`, no `addr3`. This is the
//!   deleted code's exact output; reproducing it here rather than adding a "be broken" flag to
//!   production keeps the defect out of the shipping path while still measuring it on real air.
//!
//! Every frame carries a plaintext `T0AB|<arm>|<mcs>|<seq>` marker after the NDN name so the
//! receiver can attribute a capture to its arm without trusting the addressing under test.
//!
//! ## Running it (see the hardware runbook)
//!
//! ```text
//! # o5p-0, the a81a (0bda:a81a) — capable VHT transmitter
//! sudo NDN_PID=a81a ./tier0_fec_onair tx 149 60
//! # o5p-1, the 881a (0bda:881a) — receiver
//! sudo NDN_PID=881a ./tier0_fec_onair rx 149 60
//! ```
//!
//! Env: `NDN_PID` (hex USB pid, default `a81a`), `PERIOD` (frames per arm, default 40),
//! `MCS_LIST` (comma-separated plan MCS cycle, default `4,5,7`), `FEC_K`, `FEC_R`.

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("tier0_fec_onair drives a USB monitor radio — run it on the OPi");
}

#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU16, Ordering};
    use std::time::{Duration, Instant};

    use bytes::Bytes;
    use ndn_phy_wifi::{
        DEFAULT_SRC, FrameIo, InjectFrame, LossMeter, McsDescriptor, McsPolicy, NameGate,
        OPEN_GROUP_KEY, PrefixFilter, RadioBearer, RadioId, RadioMediumFace, RatePolicy, RxFilter,
        TxIntent,
    };
    use ndn_radio_cognition::{RadioCapability, RateParams, TxParams, WifiRate};
    use ndn_transport::Transport;

    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).cloned().unwrap_or_else(|| "rx".into());
    let channel: u8 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(149);
    let secs: u64 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(60);
    let pid = u16::from_str_radix(
        &std::env::var("NDN_PID").unwrap_or_else(|_| "a81a".into()),
        16,
    )?;
    let period: usize = std::env::var("PERIOD")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(40);
    let mcs_list: Vec<u8> = std::env::var("MCS_LIST")
        .unwrap_or_else(|_| "4,5,7".into())
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect();
    let fec_k: usize = std::env::var("FEC_K")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(4);
    let fec_r: u16 = std::env::var("FEC_R")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(2);

    // The producer publishes under /x/y; the receiver registers the coarser /x — the aggregation
    // case, and the one where a half-filter is guaranteed to miss.
    let key = OPEN_GROUP_KEY;
    let publish_prefix = b"/x/y".as_slice();
    let register_prefix = b"/x".as_slice();

    /// A minimal Data packet: `Data(0x06){ Name(0x07){ GenericNameComponent(0x08)* } }` followed by
    /// the arm marker, which rides after the Name so `inner_name` still parses it.
    fn data_pkt(comps: &[&[u8]], marker: &[u8]) -> Bytes {
        let mut name = Vec::new();
        for c in comps {
            name.push(0x08);
            name.push(c.len() as u8);
            name.extend_from_slice(c);
        }
        let mut name_tlv = vec![0x07, name.len() as u8];
        name_tlv.extend_from_slice(&name);
        let mut body = name_tlv;
        body.extend_from_slice(marker);
        let mut d = vec![0x06, body.len() as u8];
        d.extend_from_slice(&body);
        Bytes::from(d)
    }

    let open = ndn_radio_drivers::open_named_radio(pid, channel)?;
    let cap = RadioCapability::wifi_monitor_5ghz(vec![channel]);
    println!("tier0_fec_onair {mode} pid={pid:04x} ch{channel} {secs}s");

    if mode == "tx" {
        let radio = open.io.clone();
        // The plan cell the cognitive control plane would write; here the example drives it so the
        // rate under test is unambiguous.
        let plan = Arc::new(std::sync::RwLock::new(None::<TxParams>));
        let rate = Arc::new(
            RatePolicy::new(McsPolicy::Fixed(McsDescriptor::CONSERVATIVE))
                .with_planned(plan.clone()),
        );
        let medium = RadioMediumFace::new(
            ndn_phy_wifi::FaceId(1),
            vec![RadioBearer::from_open(RadioId(0), open, cap)],
        )
        .with_bloom(&key, &[publish_prefix])
        .with_link_fec(
            fec_k,
            Duration::from_millis(50),
            Arc::new(AtomicU16::new(fec_r)),
            Arc::new(LossMeter::default()),
        )
        .with_rate_policy(rate)
        .build();

        // The old sink's exact output: addr1 = the filter's high half (all its pin carried),
        // addr2 = the face's fixed DEFAULT_SRC, addr3 = None.
        let mut f = PrefixFilter::new();
        f.insert_name(&key.0, b"/x/y/obj");
        let old_wire = f.to_wire();
        let old_dst: [u8; 6] = old_wire[..6].try_into().unwrap();

        let deadline = Instant::now() + Duration::from_secs(secs);
        let (mut seq, mut sent_new, mut sent_old) = (0u32, 0u32, 0u32);
        while Instant::now() < deadline {
            let arm_new = (seq as usize / period) % 2 == 0;
            let mcs = mcs_list[(seq as usize / period / 2) % mcs_list.len()];
            *plan.write().unwrap() = Some(TxParams {
                rate: RateParams::Wifi(WifiRate {
                    mcs: Some(mcs),
                    ..Default::default()
                }),
                ..Default::default()
            });
            let marker = format!(
                "T0AB|{}|{}|{}",
                if arm_new { "new" } else { "old" },
                mcs,
                seq
            );
            let wire = data_pkt(&[b"x", b"y", b"obj"], marker.as_bytes());
            if arm_new {
                medium.send_bytes(wire).await?;
                sent_new += 1;
            } else {
                // Direct injection, bypassing the medium — this arm must NOT get the fix.
                radio.set_rate(McsDescriptor::ht(mcs))?;
                radio
                    .inject(InjectFrame {
                        payload: wire,
                        tx: TxIntent::CONSERVATIVE,
                        dst: old_dst,
                        src: DEFAULT_SRC,
                        addr3: None,
                    })
                    .await?;
                sent_old += 1;
            }
            seq += 1;
            tokio::time::sleep(Duration::from_millis(8)).await;
        }
        println!("tx done: new={sent_new} old={sent_old} (FEC k={fec_k} R={fec_r})");
        return Ok(());
    }

    // ── RX: the instrument ────────────────────────────────────────────────────────────────────
    // The gate is the real one, built exactly as a receiver registered on /x would build it.
    let gate = NameGate::new(
        RxFilter::Bloom(vec![PrefixFilter::mask_for(&key.0, register_prefix)].into()),
        None,
    );
    let radio = open.io;

    #[derive(Default)]
    struct Arm {
        heard: u64,
        admitted: u64,
        rejected: u64,
        default_src_in_addr2: u64,
        addr3_present: u64,
        rates: BTreeMap<u8, u64>,
    }
    let mut arms: BTreeMap<String, Arm> = BTreeMap::new();
    let mut untagged = 0u64;

    let deadline = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < deadline {
        let Ok(Ok(fr)) = tokio::time::timeout(Duration::from_millis(500), radio.recv_frame()).await
        else {
            continue;
        };
        // Attribute by the plaintext marker, never by the addressing under test.
        let Some(pos) = fr.payload.windows(5).position(|w| w == b"T0AB|") else {
            untagged += 1;
            continue;
        };
        let tail = String::from_utf8_lossy(&fr.payload[pos..]).to_string();
        let mut it = tail.split('|').skip(1);
        let (Some(arm), Some(mcs_txt)) = (it.next(), it.next()) else {
            untagged += 1;
            continue;
        };
        let want_mcs: u8 = mcs_txt.parse().unwrap_or(255);
        let e = arms.entry(format!("{arm}/plan{want_mcs}")).or_default();
        e.heard += 1;
        if gate.admits(fr.group, fr.addr, &fr.payload) {
            e.admitted += 1;
        } else {
            e.rejected += 1;
        }
        if fr.addr == Some(DEFAULT_SRC) {
            e.default_src_in_addr2 += 1;
        }
        if fr.addr3.is_some() {
            e.addr3_present += 1;
        }
        if let Some(m) = fr.mcs_index {
            *e.rates.entry(m).or_default() += 1;
        }
    }

    println!("\n=== TIER-0 UNDER LINK-FEC, ON AIR ===");
    println!(
        "{:<14} {:>6} {:>9} {:>9} {:>12} {:>7}  {}",
        "arm/plan", "heard", "admitted", "REJECTED", "addr2=DEF_SRC", "addr3", "decoded rates"
    );
    for (k, a) in &arms {
        let rates = a
            .rates
            .iter()
            .map(|(m, n)| format!("mcs{m}:{n}"))
            .collect::<Vec<_>>()
            .join(" ");
        println!(
            "{:<14} {:>6} {:>9} {:>9} {:>12} {:>7}  {}",
            k, a.heard, a.admitted, a.rejected, a.default_src_in_addr2, a.addr3_present, rates
        );
    }
    println!("untagged frames (other traffic on channel): {untagged}");
    println!(
        "\nCLAIM 1 holds iff every `new/*` row is admitted==heard with rejected==0 and \
         addr2=DEF_SRC==0, while `old/*` rows are rejected — that is the false negative the fix \
         removed, measured on real air rather than in loopback."
    );
    println!(
        "CLAIM 2 holds iff each row's decoded rates track its plan MCS. A row whose rates ignore \
         the plan is a rate that was decided and never actuated."
    );
    Ok(())
}
