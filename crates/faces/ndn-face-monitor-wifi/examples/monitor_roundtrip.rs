//! Phase-1 witness: a real NDN Interest/Data round-trip over raw 802.11
//! monitor-mode injection, through `MonitorWifiFace` + the engine's
//! `LpLinkService` (so NDNLPv2 fragmentation/reassembly runs over the air).
//!
//! One binary, three modes:
//!
//!   # board A — producer: answers /bench/rt/<size>/<seq> with <size> bytes,
//!   # the size is read from the name so one producer serves the whole sweep.
//!   sudo ./monitor_roundtrip <iface> respond /bench/rt [mtu=2296]
//!
//!   # board B — consumer (ad-hoc): fetch COUNT objects of one SIZE
//!   sudo ./monitor_roundtrip <iface> fetch /bench/rt [size=4000] [count=20] [mcs=1]
//!
//!   # board B — consumer (goodput sweep): sweep object sizes, print a table of
//!   # delivery% / RTT / goodput / est. fragments — the MTU-bump A/B instrument.
//!   sudo ./monitor_roundtrip <iface> bench /bench/rt [count=40] [mcs=1] [prod_mtu=2296]
//!
//! There is no forwarder in the path — this drives the Face directly. The
//! bytes on the air are spec NDN-over-NDNLPv2: `LpLinkService::send` LP-wraps
//! (and fragments >MTU), so a >MTU Data exercises fragment + reassemble across
//! injected frames. Because we bypass the engine, `LpLinkService::recv` hands
//! back the raw LP wire (the engine's decode stage normally decapsulates), so
//! this example decapsulates + reassembles itself via [`decapsulate`]. The name
//! is the only addressing: the producer never learns the consumer's MAC.

#[cfg(target_os = "linux")]
mod imp {
    use std::str::FromStr;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use bytes::Bytes;
    use ndn_coding::{FecPolicy, segment_payload};
    use ndn_face_monitor_wifi::{AfPacketBackend, FrameFormat, McsDescriptor, MonitorWifiFace};
    use ndn_packet::encode::{DataBuilder, encode_interest, ensure_nonce};
    use ndn_packet::fragment::ReassemblyBuffer;
    use ndn_packet::lp::extract_fragment;
    use ndn_packet::{Data, Interest, Name};
    use ndn_transport::FaceId;

    /// Recover a network-layer packet (Interest/Data) from a wire the
    /// `LpLinkService` handed up. Mirrors what the engine's decode stage does:
    /// non-LP wires pass through; single-fragment LpPackets yield their
    /// `Fragment` (0x50) payload; multi-fragment LpPackets are reassembled via
    /// `reasm` (returns `None` until the group completes).
    pub fn decapsulate(raw: &Bytes, reasm: &mut ReassemblyBuffer) -> Option<Bytes> {
        if raw.first() != Some(&0x64) {
            return Some(raw.clone()); // already a network packet
        }
        if let Some(h) = extract_fragment(raw) {
            let frag = raw.slice(h.frag_start..h.frag_end);
            return reasm.process(0, h.sequence, h.frag_index, h.frag_count, frag);
        }
        // Single-fragment LpPacket: pull the inner Fragment (0x50) TLV value.
        let (_t, tn) = ndn_tlv::read_varu64(raw).ok()?;
        let (outer_len, ln) = ndn_tlv::read_varu64(&raw[tn..]).ok()?;
        let body_start = tn + ln;
        let inner = raw.get(body_start..body_start + outer_len as usize)?;
        let mut pos = 0;
        while pos < inner.len() {
            let (t, a) = ndn_tlv::read_varu64(&inner[pos..]).ok()?;
            pos += a;
            let (l, b) = ndn_tlv::read_varu64(&inner[pos..]).ok()?;
            pos += b;
            let l = l as usize;
            if t == 0x50 {
                let off = body_start + pos;
                return Some(raw.slice(off..off + l));
            }
            pos += l;
        }
        None
    }

    /// Express one Interest and return the matching `Data` (with its RTT), or
    /// `None` on a 1 s timeout. The shared receive primitive for every fetch
    /// path; `reasm` reassembles a producer that LP-fragments its reply.
    async fn request_data(
        face: &ndn_transport::Face,
        name: &Name,
        reasm: &mut ReassemblyBuffer,
    ) -> Result<Option<(f64, Data)>, Box<dyn std::error::Error>> {
        let interest = ensure_nonce(&encode_interest(name, None));
        let start = Instant::now();
        face.link_service
            .send(face.transport.as_ref(), interest, None)
            .await?;
        let deadline = Duration::from_millis(1000);
        loop {
            let remaining = deadline.saturating_sub(start.elapsed());
            if remaining.is_zero() {
                return Ok(None);
            }
            let frame = match tokio::time::timeout(
                remaining,
                face.link_service.recv(face.transport.as_ref()),
            )
            .await
            {
                Ok(Ok(f)) => f,
                Ok(Err(e)) => return Err(e.into()),
                Err(_) => return Ok(None),
            };
            let Some(pkt) = decapsulate(&frame.wire, reasm) else {
                continue;
            };
            if pkt.first() != Some(&0x06) {
                continue; // not Data
            }
            let Ok(data) = Data::decode(pkt) else {
                continue;
            };
            if *data.name == *name {
                let rtt = start.elapsed().as_secs_f64() * 1e3;
                return Ok(Some((rtt, data)));
            }
        }
    }

    /// Fetch one plain (uncoded) object: `(rtt_ms, content_len)` or `None`.
    async fn fetch_one(
        face: &ndn_transport::Face,
        name: &Name,
        reasm: &mut ReassemblyBuffer,
    ) -> Result<Option<(f64, usize)>, Box<dyn std::error::Error>> {
        Ok(request_data(face, name, reasm)
            .await?
            .map(|(rtt, d)| (rtt, d.content().map(Bytes::len).unwrap_or(0))))
    }

    /// FEC shape for a `size`-byte object: K source segments each sized to fit
    /// one injected frame (no LP fragmentation), plus parity. `N = K + parity`
    /// where parity ≈ 50% — generous so recovery is near-certain; the consumer
    /// only *fetches* parity it actually needs (adaptive over-fetch), so the
    /// redundancy is a ceiling, not a fixed cost.
    pub fn coded_shape(size: usize) -> (u16, u16) {
        // Leave headroom under MONITOR_MTU for FecMetadata + Data TLV/sig.
        const SEG_TARGET: usize = 2000;
        let k = size.div_ceil(SEG_TARGET).clamp(1, 200) as u16;
        let parity = (k / 2).max(2);
        (k, (k + parity).min(255))
    }

    /// Fetch one **coded** object: request segment indices in order, feeding a
    /// `CodedAssembler`, until it recovers (any K-of-N) or the parity is
    /// exhausted. Returns `(rtt_ms, segments_requested)` on recovery. A lost
    /// segment just advances to the next index (a parity), so one bad frame is
    /// recoverable — unlike an uncoded multi-fragment Data, where it is fatal.
    async fn fetch_coded(
        face: &ndn_transport::Face,
        prefix: &str,
        size: usize,
        generation: u64,
        reasm: &mut ReassemblyBuffer,
    ) -> Result<Option<(f64, usize)>, Box<dyn std::error::Error>> {
        use ndn_coding::CodedAssembler;
        let (_, n_hint) = coded_shape(size);
        let mut asm = CodedAssembler::new();
        let start = Instant::now();
        let mut requested = 0usize;
        let mut idx = 0u16;
        loop {
            // Stop once we have requested every available segment (N, learned
            // from metadata once the first segment lands; the hint until then).
            let n = asm.n().unwrap_or(n_hint);
            if idx >= n {
                return Ok(None); // too many losses — parity exhausted
            }
            let name = Name::from_str(&format!("{prefix}/{size}/{generation}/{idx}"))?;
            idx += 1;
            requested += 1;
            if let Some((_, data)) = request_data(face, &name, reasm).await? {
                let content = data.content().map(Bytes::as_ref).unwrap_or(&[]);
                if let Ok(Some(_payload)) = asm.absorb_content(content) {
                    let rtt = start.elapsed().as_secs_f64() * 1e3;
                    return Ok(Some((rtt, requested)));
                }
            }
        }
    }

    /// Fragments the producer emits for a `size`-byte object at `prod_mtu`,
    /// matching `LpLinkService`'s rule (`fragment_packet` payload cap =
    /// `mtu - FRAG_OVERHEAD`). `+~70` accounts for the signed-Data TLV overhead
    /// the producer adds on top of the raw content.
    fn est_fragments(size: usize, prod_mtu: usize) -> usize {
        const FRAG_OVERHEAD: usize = 50;
        let wire = size + 70;
        let cap = prod_mtu.saturating_sub(FRAG_OVERHEAD).max(1);
        if wire + 4 <= prod_mtu {
            1
        } else {
            wire.div_ceil(cap)
        }
    }

    pub async fn run(args: Vec<String>) -> Result<(), Box<dyn std::error::Error>> {
        let (iface, mode, prefix) = match &args[..] {
            [i, m, p, ..] => (i.clone(), m.clone(), p.clone()),
            _ => {
                eprintln!("usage: monitor_roundtrip <iface> respond       <prefix> [mtu]");
                eprintln!("       monitor_roundtrip <iface> respond-coded <prefix> [mtu]");
                eprintln!(
                    "       monitor_roundtrip <iface> fetch         <prefix> [size] [count] [mcs]"
                );
                eprintln!(
                    "       monitor_roundtrip <iface> bench         <prefix> [count] [mcs] [prod_mtu]"
                );
                eprintln!("       monitor_roundtrip <iface> bench-coded   <prefix> [count] [mcs]");
                std::process::exit(2);
            }
        };
        let backend = Arc::new(AfPacketBackend::new(&iface, FrameFormat::default())?);
        let prefix_name = Name::from_str(&prefix)?;

        match mode.as_str() {
            "respond" => {
                let mtu: usize = args
                    .get(3)
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(ndn_face_monitor_wifi::MONITOR_MTU);
                let face = MonitorWifiFace::new(FaceId(1), backend)
                    .with_mtu(mtu)
                    .into_face();
                let mut reasm = ReassemblyBuffer::new(Duration::from_secs(2));
                let prefix_len = prefix_name.components().len();
                println!("responding under {prefix}/<size>/<seq> at MTU {mtu} on {iface} …");
                loop {
                    let frame = face.link_service.recv(face.transport.as_ref()).await?;
                    let Some(pkt) = decapsulate(&frame.wire, &mut reasm) else {
                        continue;
                    };
                    if pkt.first() != Some(&0x05) {
                        continue; // not an Interest
                    }
                    let Ok(interest) = Interest::decode(pkt) else {
                        continue;
                    };
                    if !interest.name.has_prefix(&prefix_name) {
                        continue;
                    }
                    // Requested object size = the name component after the prefix.
                    let size = interest
                        .name
                        .components()
                        .get(prefix_len)
                        .and_then(|c| std::str::from_utf8(&c.value).ok())
                        .and_then(|s| s.parse::<usize>().ok())
                        .unwrap_or(1000);
                    let payload = vec![0x5Au8; size];
                    let data = DataBuilder::new((*interest.name).clone(), &payload)
                        .freshness(Duration::from_secs(1))
                        .sign_digest_sha256();
                    face.link_service
                        .send(face.transport.as_ref(), data, None)
                        .await?;
                }
            }
            "respond-coded" => {
                let mtu: usize = args
                    .get(3)
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(ndn_face_monitor_wifi::MONITOR_MTU);
                let face = MonitorWifiFace::new(FaceId(1), backend)
                    .with_mtu(mtu)
                    .into_face();
                let mut reasm = ReassemblyBuffer::new(Duration::from_secs(2));
                let p = prefix_name.components().len();
                println!("responding CODED under {prefix}/<size>/<gen>/<idx> on {iface} …");
                loop {
                    let frame = face.link_service.recv(face.transport.as_ref()).await?;
                    let Some(pkt) = decapsulate(&frame.wire, &mut reasm) else {
                        continue;
                    };
                    if pkt.first() != Some(&0x05) {
                        continue;
                    }
                    let Ok(interest) = Interest::decode(pkt) else {
                        continue;
                    };
                    if !interest.name.has_prefix(&prefix_name) {
                        continue;
                    }
                    // /prefix/<size>/<gen>/<idx>
                    let comps = interest.name.components();
                    let num = |i: usize| {
                        comps
                            .get(i)
                            .and_then(|c| std::str::from_utf8(&c.value).ok())
                            .and_then(|s| s.parse::<u64>().ok())
                    };
                    let (Some(size), Some(generation), Some(idx)) =
                        (num(p), num(p + 1), num(p + 2))
                    else {
                        continue;
                    };
                    let (k, n) = coded_shape(size as usize);
                    let Some(policy) = FecPolicy::systematic(k, n) else {
                        continue;
                    };
                    let payload = vec![0x5Au8; size as usize];
                    let Ok(segs) = segment_payload(&payload, &policy, generation) else {
                        continue;
                    };
                    let Some(seg) = segs.iter().find(|s| s.index as u64 == idx) else {
                        continue; // idx >= n
                    };
                    let data = DataBuilder::new((*interest.name).clone(), seg.content.as_ref())
                        .freshness(Duration::from_secs(1))
                        .sign_digest_sha256();
                    face.link_service
                        .send(face.transport.as_ref(), data, None)
                        .await?;
                }
            }
            "fetch" => {
                let size: usize = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(4000);
                let count: usize = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(20);
                let mcs: u8 = args.get(5).and_then(|s| s.parse().ok()).unwrap_or(1);
                let face = MonitorWifiFace::new(FaceId(2), backend)
                    .with_fixed_mcs(McsDescriptor {
                        index: mcs,
                        short_gi: false,
                        vht: false,
                        nss: 1,
                        stbc: false,
                        ldpc: false,                    })
                    .into_face();
                let mut reasm = ReassemblyBuffer::new(Duration::from_secs(2));
                println!("fetching {count}×{size} B under {prefix} at MCS{mcs} on {iface} …");
                let mut ok = 0usize;
                for i in 0..count {
                    let name = Name::from_str(&format!("{prefix}/{size}/{i}"))?;
                    match fetch_one(&face, &name, &mut reasm).await? {
                        Some((rtt, len)) => {
                            ok += 1;
                            println!("  {name}: {rtt:.1} ms, {len} B");
                        }
                        None => println!("  {name}: TIMEOUT"),
                    }
                }
                println!("\n{ok}/{count} satisfied");
                if ok == 0 {
                    std::process::exit(1);
                }
            }
            "bench" => {
                let count: usize = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(40);
                let mcs: u8 = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(1);
                let prod_mtu: usize = args
                    .get(5)
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(ndn_face_monitor_wifi::MONITOR_MTU);
                let face = MonitorWifiFace::new(FaceId(2), backend)
                    .with_fixed_mcs(McsDescriptor {
                        index: mcs,
                        short_gi: false,
                        vht: false,
                        nss: 1,
                        stbc: false,
                        ldpc: false,                    })
                    .into_face();
                let mut reasm = ReassemblyBuffer::new(Duration::from_secs(2));
                let sizes = [256usize, 800, 1400, 2200, 4000, 8000, 16000];
                println!(
                    "goodput sweep on {iface}, MCS{mcs}, producer MTU {prod_mtu}, \
                     {count} objects/size\n"
                );
                println!(
                    "{:>7}  {:>5}  {:>9}  {:>10}  {:>12}",
                    "size", "frags", "delivery", "RTT med ms", "goodput Mbps"
                );
                for &size in &sizes {
                    let mut rtts: Vec<f64> = Vec::new();
                    let mut delivered_bytes = 0usize;
                    let batch_start = Instant::now();
                    for i in 0..count {
                        let name = Name::from_str(&format!("{prefix}/{size}/{i}"))?;
                        if let Some((rtt, len)) = fetch_one(&face, &name, &mut reasm).await? {
                            rtts.push(rtt);
                            delivered_bytes += len;
                        }
                    }
                    let elapsed = batch_start.elapsed().as_secs_f64();
                    rtts.sort_by(|a, b| a.partial_cmp(b).unwrap());
                    let med = rtts.get(rtts.len() / 2).copied().unwrap_or(f64::NAN);
                    // Stop-and-wait goodput: delivered payload over total wall
                    // time (timeouts included — losses cost a full 1 s).
                    let mbps = (delivered_bytes as f64 * 8.0) / elapsed / 1e6;
                    println!(
                        "{:>7}  {:>5}  {:>5}/{:<3}  {:>10.1}  {:>12.2}",
                        size,
                        est_fragments(size, prod_mtu),
                        rtts.len(),
                        count,
                        med,
                        mbps,
                    );
                }
            }
            "bench-coded" => {
                let count: usize = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(40);
                let mcs: u8 = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(1);
                let face = MonitorWifiFace::new(FaceId(2), backend)
                    .with_fixed_mcs(McsDescriptor {
                        index: mcs,
                        short_gi: false,
                        vht: false,
                        nss: 1,
                        stbc: false,
                        ldpc: false,                    })
                    .into_face();
                let mut reasm = ReassemblyBuffer::new(Duration::from_secs(2));
                let sizes = [256usize, 800, 1400, 2200, 4000, 8000, 16000];
                println!("CODED (K-of-N FEC) sweep on {iface}, MCS{mcs}, {count} objects/size\n");
                println!(
                    "{:>7}  {:>7}  {:>9}  {:>9}  {:>10}",
                    "size", "K/N", "recovery", "segs/obj", "RTT med ms"
                );
                for &size in &sizes {
                    let (k, n) = coded_shape(size);
                    let mut recovered = 0usize;
                    let mut seg_counts: Vec<usize> = Vec::new();
                    let mut rtts: Vec<f64> = Vec::new();
                    for i in 0..count {
                        if let Some((rtt, segs)) =
                            fetch_coded(&face, &prefix, size, i as u64, &mut reasm).await?
                        {
                            recovered += 1;
                            seg_counts.push(segs);
                            rtts.push(rtt);
                        }
                    }
                    rtts.sort_by(|a, b| a.partial_cmp(b).unwrap());
                    let med = rtts.get(rtts.len() / 2).copied().unwrap_or(f64::NAN);
                    let avg_segs = if seg_counts.is_empty() {
                        0.0
                    } else {
                        seg_counts.iter().sum::<usize>() as f64 / seg_counts.len() as f64
                    };
                    println!(
                        "{:>7}  {:>3}/{:<3}  {:>5}/{:<3}  {:>9.1}  {:>10.1}",
                        size, k, n, recovered, count, avg_segs, med
                    );
                }
            }
            other => {
                eprintln!("unknown mode {other:?} (respond|respond-coded|fetch|bench|bench-coded)");
                std::process::exit(2);
            }
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    imp::run(std::env::args().skip(1).collect()).await
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("monitor_roundtrip requires Linux AF_PACKET monitor-mode injection.");
    std::process::exit(1);
}
