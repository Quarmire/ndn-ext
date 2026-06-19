//! OPi-side reception RX stack — the cooperative back-channel that closes the
//! on-air control loop.
//!
//! Runs our monitor face on a Linux monitor interface (AF_PACKET), receives the
//! named-radio TX, measures the per-neighbour RSSI we hear it at, and **broadcasts
//! reception reports** so the transmitter learns its *measured outbound* link
//! quality (not a reciprocity guess) and can adapt for real.
//!
//! Run on the OPi (needs CAP_NET_RAW → sudo):
//!   sudo RADIO_IFACE=wlu1 ./reception_rx
//! Env: RADIO_IFACE (default wlu1), RADIO_REPORT_MS (report cadence, default 1000),
//! RADIO_REPORT_MCS (HT MCS for the report TX, default 1 = robust).

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("reception_rx is Linux-only (AF_PACKET monitor) — run it on the OPi");
}

#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use ndn_face_monitor_wifi::{AfPacketBackend, FrameFormat, RadioControl, FrameIo};
    use ndn_radio_cognition::{RadioCapability, RadioId};

    // Build the rtl88x2eu cfg80211-monitor injection frame for `payload`:
    // EXACTLY-14-byte radiotap (driver hard-requires len==14) + an 802.11 MGMT
    // **Action** frame (the only type the driver dumps raw; DATA gets mangled).
    // 14-byte radiotap = base(8) + FLAGS(1) + RATE(1) + ANTENNA(1) + MCS(3),
    // present bits {1,2,11,19}; MCS sets the HT rate. Action body = [category=0x7f]
    // [action=0] + payload; addr2 = src so the listener can filter.
    fn build_action_inject(payload: &[u8], src: [u8; 6], mcs: u8) -> Vec<u8> {
        let mut f = Vec::with_capacity(14 + 26 + payload.len());
        // --- radiotap (14 bytes) ---
        f.extend_from_slice(&[0x00, 0x00]); // version, pad
        f.extend_from_slice(&14u16.to_le_bytes()); // len = 14
        let present: u32 = (1 << 1) | (1 << 2) | (1 << 11) | (1 << 19); // FLAGS|RATE|ANTENNA|MCS
        f.extend_from_slice(&present.to_le_bytes());
        f.push(0x00); // FLAGS
        f.push(0x02); // RATE (overridden by MCS below)
        f.push(0x00); // ANTENNA
        f.push(0x07); // MCS.known = HAVE_MCS|HAVE_BW|HAVE_GI
        f.push(0x00); // MCS.flags = BW20, long GI
        f.push(mcs); // MCS.index
        debug_assert_eq!(f.len(), 14);
        // --- 802.11 MGMT Action, 3-addr ---
        f.extend_from_slice(&[0xd0, 0x00]); // frame control: MGMT|ACTION
        f.extend_from_slice(&[0x00, 0x00]); // duration
        f.extend_from_slice(&[0xff; 6]); // addr1 = broadcast
        f.extend_from_slice(&src); // addr2 = src
        f.extend_from_slice(&[0xff; 6]); // addr3 = bssid (broadcast)
        f.extend_from_slice(&[0x00, 0x00]); // seq
        // --- action body: category, action, then our payload ---
        f.push(0x7f); // category = vendor-specific (parser accepts any)
        f.push(0x00); // action
        f.extend_from_slice(payload);
        f
    }

    // node-id from a 6-byte MAC (big-endian) — both ends agree, so the TX can find
    // the entry where we reported hearing *it*.
    fn mac_node(mac: [u8; 6]) -> u64 {
        let mut v = 0u64;
        for b in mac {
            v = (v << 8) | b as u64;
        }
        v
    }
    // The transmitter's source MAC (DEFAULT_SRC) → its node id.
    const TX_SRC: [u8; 6] = [0x02, 0x4e, 0x44, 0x4e, 0x00, 0x01];
    // Our (OPi) node id — distinct from the TX.
    const RX_NODE: u64 = 0x02_5252_5800_0001; // "RRX"

    let iface = std::env::var("RADIO_IFACE").unwrap_or_else(|_| "wlu1".into());
    let report_ms: u128 = std::env::var("RADIO_REPORT_MS").ok().and_then(|v| v.parse().ok()).unwrap_or(1000);
    let report_mcs: u8 = std::env::var("RADIO_REPORT_MCS").ok().and_then(|v| v.parse().ok()).unwrap_or(1);
    let report_burst: u32 = std::env::var("RADIO_REPORT_BURST").ok().and_then(|v| v.parse().ok()).unwrap_or(1);

    let backend = Arc::new(AfPacketBackend::new(&iface, FrameFormat::default())?);
    let radio = RadioId(0);

    let mut control = RadioControl::new(ndn_radio_cognition::RadioPolicy::default())
        .with_node_id(RX_NODE)
        .with_report_interval(report_ms as u64);
    control.register_radio(radio, ndn_face_monitor_wifi::FaceId(0), RadioCapability::wifi_monitor_5ghz(vec![]));

    let tx_node = mac_node(TX_SRC);
    println!("reception_rx on {iface}: RX_NODE={RX_NODE:#x} listening for TX_SRC node {tx_node:#x}; reports every {report_ms}ms at HT MCS{report_mcs}");

    // Diagnostic: tight inject loop (no recv) to test whether the kernel monitor
    // actually radiates our injected frames. RADIO_FLOOD=<n> sends n report frames
    // as fast as possible, then exits.
    if let Ok(n) = std::env::var("RADIO_FLOOD") {
        let n: u64 = n.parse().unwrap_or(20000);
        let rep = ndn_radio_cognition::encode_report(&ndn_radio_cognition::ReceptionReport {
            node_id: RX_NODE,
            seq: 1,
            ts_ms: 0,
            heard_neighbors: vec![(tx_node, -50)],
            heard_prefixes: vec![],
            spectrum: vec![],
        });
        // Embed the rx_ambient detector magic so the Mac can unambiguously confirm
        // these frames radiated + decoded.
        let payload = [b"OPI-RECIP-TEST".as_slice(), &rep].concat();
        let frame = build_action_inject(&payload, TX_SRC, report_mcs);
        println!("FLOOD: injecting {n} action frames ({} B on air, 14B radiotap) at HT MCS{report_mcs}…", frame.len());
        let mut ok = 0u64;
        let mut err = 0u64;
        for _ in 0..n {
            match backend.inject_raw(&frame).await {
                Ok(()) => ok += 1,
                Err(_) => err += 1,
            }
        }
        println!("FLOOD done: {ok} OK, {err} ERR");
        return Ok(());
    }

    let started = Instant::now();
    let now_ms = || started.elapsed().as_millis() as u64;
    let mut heard = 0u64;
    let mut total = 0u64;
    let mut last_rx_ms = 0u64;
    let mut last_log = Instant::now();

    loop {
        // RX: receive a frame, feed its RSSI into the sense bus keyed by the TX node.
        // Bounded wait so the loop stays responsive (reports, logging) even when no
        // decodable frame arrives for a while.
        match tokio::time::timeout(Duration::from_millis(50), backend.recv_frame()).await {
            Ok(Ok(f)) => {
                total += 1;
                let from = f.addr.unwrap_or([0; 6]);
                if from == TX_SRC {
                    heard += 1;
                    last_rx_ms = now_ms();
                    control.observe_rx(radio, tx_node, f.rssi_dbm, now_ms());
                }
            }
            Ok(Err(e)) => {
                eprintln!("recv error: {e}");
            }
            Err(_timeout) => {} // no decodable frame this slice — fall through
        }

        // TURN-TAKING: only broadcast reports when we're NOT actively receiving the
        // peer's data (half-duplex — TX'ing reports would clobber RX). When idle,
        // burst hard (RADIO_REPORT_BURST) to beat the lossy kernel-monitor inject.
        let idle = now_ms().saturating_sub(last_rx_ms) > 500;
        if idle && let Some(report) = control.outgoing_report(now_ms()) {
            let frame = build_action_inject(&report, TX_SRC, report_mcs);
            for _ in 0..report_burst {
                if let Err(e) = backend.inject_raw(&frame).await {
                    println!("  [report inject ERR: {e}]");
                    break;
                }
            }
        }
        if last_log.elapsed().as_secs() >= 2 {
            let rssi = control
                .neighbor_rssi(radio, tx_node)
                .map(|r| format!("{r} dBm"))
                .unwrap_or_else(|| "—".into());
            println!("recv total={total} (TX-matched {heard}); measured outbound-link RSSI = {rssi}");
            last_log = Instant::now();
            heard = 0;
            total = 0;
        }
    }
}
