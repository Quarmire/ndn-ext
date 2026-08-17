//! **Does the slot MAC actually reduce collisions on air?** The validation the whole
//! #84/#87/#88/#89/#94/#95 set has been missing — every one of those changes is offline-verified
//! only, and they all touch the code that decides when a node may transmit.
//!
//! Two nodes, both transmitting their own name-group as fast as the rate allows, each also receiving.
//! Run it twice:
//!
//! * **arm OFF** — `NDN_SCHED_SLOT` unset: no gate, both nodes transmit whenever they like and
//!   collide at each other's receiver.
//! * **arm ON**  — `NDN_SCHED_SLOT=8:20000`: each name-group owns one of 8 × 20 ms slots, so the two
//!   nodes transmit at different times and should hear more of each other.
//!
//! The headline number is **`heard_peer`** at each node. If the slot discipline works, it rises from
//! OFF to ON. That is a claim about delivery under contention, which needs no clock agreement at the
//! *receiver* — only that the two transmitters share one (wall-clock NTP here, which is why the slot
//! is 20 ms and not 3: the slot must be much larger than the clock skew between the nodes).
//!
//! It also prints **which slot each name owns**, keyed exactly as the gate keys it (name hash folded
//! with the channel, #89). If both names land in the same slot the arms are not comparable — the
//! scheduler cannot separate transmitters it has assigned to the same turn — so the tool says so
//! rather than letting a null result look like a refutation.
//!
//! ## BLOCKED 2026-08-10 — ran, measured nothing, and the null was the instrument
//!
//! First attempt gave `heard_peer = 0` at BOTH nodes in the OFF arm. That is not a baseline, it is a
//! dead link: with zero as the floor the ON arm cannot be compared to anything. Do not read such a
//! run as "slotting does not help".
//!
//! Root cause, from dmesg on o5p-1: `usb 5-1: USB disconnect, device number 103` followed by `new
//! high-speed USB device number 104` — **the 881a dropped off the bus mid-run and re-enumerated**,
//! on a USB 2.0 (high-speed) port. Its TX had already collapsed to 66 frames in 40 s (vs the a81a's
//! 2952), and afterwards even the known-good `tier0_fec_onair` could not open it
//! (`no RTL8812AU at index 0`). Same failure family as `a81a-usb-brownout-on-tx`.
//!
//! So this A/B needs a second transmitter that can sustain TX *and* RX. The 881a cannot today:
//! besides the brownout, an 8812AU doing both starves its own TX on USB bandwidth (the documented
//! `NDN_NO_PUMP` finding), which is likely what the 66-frame figure really was. Options, none free:
//! a healthier second 5 GHz radio; a powered hub for the 881a; or a redesign that validates slot
//! *alignment* from one TX and one RX rather than delivery under contention from two TX.
//!
//! ```sh
//! # o5p-0 (a81a)                            # o5p-1 (881a)
//! NDN_PID=a81a ./slot_ab_onair 149 30 a b   NDN_PID=881a ./slot_ab_onair 149 30 b a
//! # then repeat both with NDN_SCHED_SLOT=8:20000
//! ```

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("slot_ab_onair drives a USB monitor radio — run it on the OPi");
}

#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use bytes::Bytes;
    use ndn_face_monitor_wifi::{FaceId, RadioBearer, RadioId, RadioMediumFace};
    use ndn_radio_cognition::{RadioCapability, SlotSchedule, prefix_hash};
    use ndn_transport::Transport;

    let args: Vec<String> = std::env::args().collect();
    let channel: u8 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(149);
    let secs: u64 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(30);
    let mine = args.get(3).cloned().unwrap_or_else(|| "a".into());
    let peer = args.get(4).cloned().unwrap_or_else(|| "b".into());
    let pid = u16::from_str_radix(&std::env::var("NDN_PID").unwrap_or_else(|_| "a81a".into()), 16)?;
    // Well under the 881a's measured ~200 frame/s RX ceiling, so the ceiling cannot masquerade as
    // on-air loss (see the `wifi-drop-ratio-is-rx-ceiling` note — that mistake has been made here).
    let per_sec: u64 = std::env::var("RATE").ok().and_then(|s| s.parse().ok()).unwrap_or(100);

    fn data_pkt(group: &str, seq: u32) -> Bytes {
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

    /// First name component of a captured wire — how a frame is attributed to a sender.
    ///
    /// Parsed inline against the exact shape `data_pkt` emits (`06 L | 07 L | 08 L <comp>`), rather
    /// than widening the crate's API for a test tool. Short lengths only, which is all this sends.
    fn first_component(wire: &[u8]) -> Option<String> {
        let w = wire;
        if *w.first()? != 0x06 {
            return None; // not a Data packet
        }
        let name = w.get(2..)?; // skip Data type+len
        if *name.first()? != 0x07 {
            return None; // no Name TLV where one is expected
        }
        let comps = name.get(2..)?; // skip Name type+len
        if *comps.first()? != 0x08 {
            return None; // not a GenericNameComponent
        }
        let len = *comps.get(1)? as usize;
        let v = comps.get(2..2 + len)?;
        Some(String::from_utf8_lossy(v).to_string())
    }

    // Report the slot map the gate will use, so a same-slot collision of the two names is visible
    // rather than silently making the arms incomparable.
    let sched_env = std::env::var("NDN_SCHED_SLOT").ok();
    let keyed = |g: &str| {
        prefix_hash(&[g.as_bytes()]) ^ u64::from(channel).wrapping_mul(0x9E37_79B9)
    };
    if let Some(spec) = &sched_env {
        let mut it = spec.split(':');
        let slots: u64 = it.next().and_then(|s| s.parse().ok()).unwrap_or(8);
        let slot_us: u64 = it.next().and_then(|s| s.parse().ok()).unwrap_or(20_000);
        let s = SlotSchedule::new(slot_us, slots);
        let (ms, ps) = (s.owner_slot(keyed(&mine)), s.owner_slot(keyed(&peer)));
        println!("SCHED ON  {slots} x {slot_us}us   /{mine} owns slot {ms}   /{peer} owns slot {ps}");
        if ms == ps {
            // For the ORIGINAL slot A/B a same-slot pair is useless (the schedule can't separate
            // them). For the **D1 co-owner sub-draw** it is exactly the case under test:
            // `owner_slot = hash % N` collided, both names co-own slot {ms}, and without the sub-draw
            // both transmit deaf and collide. Set NDN_SCHED_D1=1 to read this as the intended mode.
            let d1 = std::env::var("NDN_SCHED_D1").as_deref() == Ok("1");
            println!(
                "{} BOTH NAMES OWN SLOT {ms} (hash % {slots} collision){}",
                if d1 { "== D1 co-ownership mode:" } else { "!!" },
                if d1 {
                    " — the co-owner sub-draw should let them take turns (watch co_owner_subdraws)"
                } else {
                    " — useless for the plain slot A/B; pick different names, or set NDN_SCHED_D1=1"
                }
            );
        }
    } else {
        println!("SCHED OFF (NDN_SCHED_SLOT unset) — free-running, the contention baseline");
    }

    let open = ndn_radio_drivers::open_named_radio(pid, channel)?;
    let cap = RadioCapability::wifi_monitor_5ghz(vec![channel]);
    let medium = Arc::new(
        RadioMediumFace::new(
            FaceId(1),
            vec![RadioBearer::from_open(RadioId(0), open, cap)],
        )
        .build(),
    );
    println!("ch{channel} pid={pid:04x} tx=/{mine} listening-for=/{peer} {secs}s at {per_sec}/s\n");

    // TX: our own group, paced.
    let tx = {
        let m = medium.clone();
        let g = mine.clone();
        tokio::spawn(async move {
            let mut seq = 0u32;
            let gap = Duration::from_micros(1_000_000 / per_sec.max(1));
            let end = Instant::now() + Duration::from_secs(secs);
            while Instant::now() < end {
                if m.send_bytes(data_pkt(&g, seq)).await.is_ok() {
                    seq += 1;
                }
                tokio::time::sleep(gap).await;
            }
            seq
        })
    };

    // RX: count what we hear, by first name component.
    let mut heard: BTreeMap<String, u64> = BTreeMap::new();
    let mut unparsed = 0u64;
    let end = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < end {
        match tokio::time::timeout(Duration::from_millis(300), medium.recv_bytes_with_addr()).await {
            Ok(Ok((wire, _))) => match first_component(&wire) {
                Some(g) => *heard.entry(g).or_default() += 1,
                None => unparsed += 1,
            },
            _ => continue,
        }
    }
    let sent = tx.await.unwrap_or(0);

    let heard_peer = heard.get(&peer).copied().unwrap_or(0);
    println!("=== result ===");
    println!("sent (/{mine})      : {sent}");
    println!("heard_peer (/{peer}): {heard_peer}   <-- the number to compare across arms");
    for (g, c) in &heard {
        if *g != peer {
            println!("  other /{g}: {c}");
        }
    }
    println!("unparsed          : {unparsed}");
    // The channel's own load, separate from ours. Until 2026-08-11 every one of these frames marked
    // a slot busy and silently vetoed the claim, which is why an evidence-gated claim measured ~0
    // gain while the same claim with the gate forced open measured 4×. If this number is large and
    // the claim still shows no gain, the suppressor is somewhere else — do not re-blame ambient load.
    if let Some(s) = medium.scheduler() {
        println!("ambient frames    : {}   <-- other people's traffic; no longer vetoes a claim", s.ambient_frames());
        // The claim path's own instrumentation. `attempts ≈ sent` with a gate that is plainly
        // throttling means each waiting frame contended exactly once and then slept through every
        // slot it could have taken — the 2026-08-11 defect. Many attempts, few wins means the
        // contention is happening and losing, which is a different bug in a different place.
        let (attempts, wins) = s.claim_counts();
        println!("claim attempts/wins: {attempts} / {wins}");
        // D1: the co-owner sub-draw firing on air. > 0 means this node HEARD a different group's hash
        // in its own slot (a real hash % N co-owner) and bought within-slot turn-taking instead of a
        // deaf collision. 0 with NDN_SCHED_NO_SUBDRAW=1 (the baseline) or with no co-owner in range.
        println!("co_owner_subdraws  : {}   <-- D1: turns bought on a shared slot", s.co_owner_subdraws());
        // D1 diagnosis: is the owner path reaching the check, is detection firing, and what does the
        // per-slot witness actually hold at RUNTIME (which channel-keys, unlike the header's printout)?
        let (ce_calls, ce_true, per) = s.co_owner_debug();
        let ms = s.debug_owner_slot(prefix_hash(&[mine.as_bytes()]), ndn_radio_cognition::LeaseClass::Bulk);
        let ps = s.debug_owner_slot(prefix_hash(&[peer.as_bytes()]), ndn_radio_cognition::LeaseClass::Bulk);
        println!("  DBG runtime slots: /{mine}->{ms:?}  /{peer}->{ps:?}   (co_owner_evident calls {ce_calls}, true {ce_true})");
        for (k, (w, h)) in per.iter().enumerate() {
            if *w != 0 || *h != 0 {
                println!("  DBG slot {k}: witness {w:#018x}  last_heard {h}");
            }
        }
    }
    println!(
        "\nCompare heard_peer between the OFF and ON arms at BOTH nodes. Slotting should raise it: \
         the two transmitters stop overlapping. A fall, or no change, is a real result — say so."
    );
    Ok(())
}
