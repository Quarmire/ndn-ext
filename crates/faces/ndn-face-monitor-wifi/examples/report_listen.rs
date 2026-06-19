//! Mac-side reception-report listener — the TX node's half of the closed loop.
//! Listens on the libusb radio for neighbour reception reports (sent as 802.11
//! Action frames) and ingests them, so the transmitter learns its **measured
//! outbound** link quality (what a peer reports hearing us at) instead of a
//! synthetic/reciprocity guess.
//!
//! Run (TX node, dongle attached):
//!   cargo run -p ndn-face-monitor-wifi --features libusb-backend --example report_listen
//! Env: RADIO_CH (default 149).

#[cfg(not(feature = "libusb-backend"))]
fn main() {
    eprintln!("build with --features libusb-backend");
}

#[cfg(feature = "libusb-backend")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::time::Instant;

    use ndn_face_monitor_wifi::{ChannelBw, LibUsbRtl88xxBackend, RadioControl};
    use ndn_radio_cognition::{RadioCapability, RadioId, decode_report};

    fn mac_node(mac: [u8; 6]) -> u64 {
        let mut v = 0u64;
        for b in mac {
            v = (v << 8) | b as u64;
        }
        v
    }
    const TX_SRC: [u8; 6] = [0x02, 0x4e, 0x44, 0x4e, 0x00, 0x01];

    // The libusb RX buffer is [chip RX descriptor][802.11][…report…] — the chip's
    // own RX format, NOT radiotap. Rather than assume the prefix layout, scan for a
    // decodable report (its magic 0xCD + version are gated by decode_report, so
    // false positives are effectively impossible).
    const REPORT_MAGIC: u8 = 0xCD;
    fn report_in(frame: &[u8]) -> Option<&[u8]> {
        for i in 0..frame.len().saturating_sub(2) {
            if frame[i] == REPORT_MAGIC && decode_report(&frame[i..]).is_some() {
                return Some(&frame[i..]);
            }
        }
        None
    }

    let ch: u8 = std::env::var("RADIO_CH").ok().and_then(|v| v.parse().ok()).unwrap_or(149);
    let backend = LibUsbRtl88xxBackend::open_monitor(ch)?;
    backend.set_channel(ch, ChannelBw::Bw80)?;

    let radio = RadioId(0);
    let me = mac_node(TX_SRC);
    let mut control = RadioControl::new(ndn_radio_cognition::RadioPolicy::default()).with_node_id(me);
    control.register_radio(radio, ndn_face_monitor_wifi::FaceId(0), RadioCapability::wifi_monitor_5ghz(vec![ch]));

    println!("report_listen on ch{ch}: my node {me:#x}; waiting for reception reports…");
    let started = Instant::now();
    let now_ms = || started.elapsed().as_millis() as u64;
    let mut reports = 0u64;
    let mut total = 0u64;
    let mut last_reporter: Option<u64> = None;
    let mut last_log = Instant::now();

    loop {
        if let Some(f) = backend.recv_raw(200)? {
            total += 1;
            if let Some(payload) = report_in(&f)
                && let Some(rep) = decode_report(payload)
            {
                reports += 1;
                last_reporter = Some(rep.node_id);
                control.ingest_report(radio, payload, now_ms());
            }
        }
        if last_log.elapsed().as_secs() >= 2 {
            // Our measured OUTBOUND link = how the reporter (OPi) hears us, which
            // ingest stored keyed by the reporter's node id.
            let outbound = last_reporter
                .and_then(|n| control.neighbor_rssi(radio, n))
                .map(|r| format!("{r} dBm"))
                .unwrap_or_else(|| "—".into());
            println!("frames={total} reports={reports}; learned MEASURED-OUTBOUND = {outbound}");
            last_log = Instant::now();
            total = 0;
        }
    }
}
