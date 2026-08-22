//! A live named-time node on a real monitor-wifi radio (the doc's "runs on hardware" seam).
//! Opens a Realtek USB radio, pipelines RX with the async-URB pump (the better USB data path),
//! wraps it as a FrameIoTransport, and runs a TimeService (OS-clock source) that ingests peer
//! beacons and broadcasts its own. Two instances (distinct node ids) on radios in RF range are an
//! on-air 2-node convergence: watch `peer_beacons_heard` climb.
//!
//! Args: `<node_id> <chip> [channel] [secs] [pid_hex]`
//!   chip = `8733` (RTL8731BU/8733BU, the *radiating* transmitter) or `8812` (RTL8812EU/8822E).
//!   pid_hex pins a specific 8812-class dongle when several are attached (e.g. `a81a`).
use ndn_frame_io::{FrameFormat, FrameIo};
use ndn_radio_drivers::{LibUsbRtl88xxBackend, PowerTracker, Rtl8733buBackend, Rtl8812auBackend};
use ndn_time::{ClockCapability, KeyId, TimePolicy};
use ndn_time_driver::wifi::FrameIoTransport;
use ndn_time_driver::{ClockSink, DevAuth, TimeService};
use ndn_time_sources::OsClock;
use std::sync::{Arc, Mutex};
use std::time::Duration;

struct PrintClock(Mutex<Option<i64>>);
impl ClockSink for PrintClock {
    fn set_clock_ms(&self, ms: i64) {
        *self.0.lock().unwrap() = Some(ms);
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let id: u64 = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    let chip: String = std::env::args().nth(2).unwrap_or_else(|| "8812".into());
    let ch: u8 = std::env::args().nth(3).and_then(|s| s.parse().ok()).unwrap_or(36);
    let secs: u64 = std::env::args().nth(4).and_then(|s| s.parse().ok()).unwrap_or(20);
    let pid: Option<u16> = std::env::args()
        .nth(5)
        .and_then(|s| u16::from_str_radix(&s, 16).ok());
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    rt.block_on(async move {
        // Open + bring up the radio, then pipeline RX with the shared async-URB pump (depth 4) so a
        // busy channel isn't dropped between reads. The 8733b brings up a *radiating* TX with
        // thermal power-tracking (kept alive for the run); the 8812-class is RX-capable monitor.
        let mut _tracker: Option<PowerTracker> = None;
        let radio: Arc<dyn FrameIo> = if chip == "8733" {
            let r = Arc::new(Rtl8733buBackend::open()?);
            _tracker = Some(r.bring_up_tx_tracked(ch)?);
            r.spawn_rx_pump(4);
            println!("named-time node {id} up: 8733b ch{ch} (radiating TX), RX pump depth 4");
            r
        } else if chip == "8812au" {
            // RTL8812AU — full-IQK great TX/RX. Route it through RawNdn framing (its default is
            // NAN/Raw80211) + legacy 6M inject, so it interops with the 8733b/8812EU beacons.
            let r = Arc::new(
                Rtl8812auBackend::open()?
                    .with_format(FrameFormat::RawNdn { ethertype: 0x8624 }),
            );
            r.bring_up_monitor(ch)?;
            r.spawn_rx_pump(4);
            println!("named-time node {id} up: 8812AU ch{ch} (RawNdn, legacy 6M), RX pump depth 4");
            r
        } else {
            let r = Arc::new(match pid {
                Some(p) => LibUsbRtl88xxBackend::open_monitor_pid(p, ch)?,
                None => LibUsbRtl88xxBackend::open_monitor(ch)?,
            });
            // Beacon at robust legacy 6 Mbps (0x04), like real 802.11 beacons — so a legacy-only
            // receiver (the 8733b, no HT/VHT demod) can decode us. Default HT/VHT would be deaf to it.
            r.set_fixed_desc_rate(Some(0x04));
            r.spawn_rx_pump(4);
            println!("named-time node {id} up: 8812-class ch{ch} (legacy 6M beacons), RX pump depth 4");
            r
        };

        let clock = Arc::new(PrintClock(Mutex::new(None)));
        let transport = Arc::new(FrameIoTransport::new(radio));
        let svc = Arc::new(TimeService::new(
            id,
            KeyId(id),
            ClockCapability::ntp_uplink(),
            // Relaxed demo policy: trust the local NTP clock at low stakes (the default high-stakes
            // floor correctly withholds clock_ms until authenticated peers agree + distance-bound).
            TimePolicy {
                required_uncertainty_ns: 10_000_000, // 10 ms, above the OS clock's 5 ms
                floor: ndn_time::provenance::StakesFloor::low(),
                ..TimePolicy::default()
            },
            vec![Box::new(OsClock::new(5_000_000))], // 5 ms OS clock as the local source
            transport,
            Arc::new(DevAuth),
            clock.clone(),
        ));
        // Run the live loop (RX-ingest task + cadence tick/beacon) and report status each second:
        // clock_ms is the disciplined estimate, peer_beacons_heard counts beacons heard over the air.
        let runner = svc.clone();
        tokio::spawn(async move { runner.run(Duration::from_millis(500)).await });
        for t in 0..secs {
            tokio::time::sleep(Duration::from_secs(1)).await;
            println!(
                "[{t:>3}s] clock_ms={:?} peer_beacons_heard={}",
                *clock.0.lock().unwrap(),
                svc.peer_ingests()
            );
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}
