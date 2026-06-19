//! On-air A/B: drive the **real** cognitive control plane on a real RTL88xx radio
//! and compare it against fixed-MCS "blast" baselines on **airtime per satisfied
//! Interest** — the on-air counterpart of the analytic `airtime_ab` harness.
//!
//! Build/run (TX node, dongle attached):
//!   cargo run -p ndn-face-monitor-wifi --features libusb-backend --example airtime_ab_onair
//!
//! Env knobs: `RADIO_CH` (default 165, a quiet 5 GHz channel), `RADIO_FRAMES`
//! (per arm, default 2000), `RADIO_PAYLOAD` (bytes, default 1000), `RADIO_RSSI`
//! (synthetic link RSSI fed to the adaptive arm, default -65 — see note), and
//! `RADIO_MODE` = `bandit` | `calibrated` | `static` (default `bandit`).
//!
//! Procedure (the established method): on the RX node (e.g. the OPi on the SAME
//! channel) capture with BPF and read the kernel's "received by filter" count —
//! `tcpdump -i <mon> -w /dev/null` and read its stderr stats; NEVER tcpdump-to-SD
//! (it understates), NEVER `-e` for delivery counts. Each frame's first payload
//! byte is its arm id (0=mcs1, 1=mcs5, 2=mcs9, 3=adaptive), so bucket by it. Then
//! delivered/airtime per arm = (received_in_bucket) ... and airtime-per-satisfied =
//! (this run's printed airtime for that arm) / (received_in_bucket).
//!
//! Note on the adaptive arm: a one-way injection benchmark has no link feedback, so
//! the loop is fed a synthetic `RADIO_RSSI` (representing the link) and runs
//! open-loop on it — it still exercises the real decision + actuators (rate, power,
//! channel, CSD, EDCCA). A fully closed on-air loop needs the RX to beacon RSSI
//! back (the reception-report channel) — that's the next phase.

#[cfg(not(feature = "libusb-backend"))]
fn main() {
    eprintln!("build with --features libusb-backend to run the on-air A/B");
}

#[cfg(feature = "libusb-backend")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::sync::Arc;

    use bytes::Bytes;
    use ndn_face_monitor_wifi::measure::frame_airtime_us;
    use ndn_face_monitor_wifi::{
        ChannelBw, FrameIo, InjectFrame, LibUsbRtl88xxBackend, McsDescriptor, RadioControl,
    };
    use ndn_radio_cognition::{
        NameContext, PolicyConfig, RadioCapability, RadioId, TxParams, prefix_hash,
    };

    fn env_u32(k: &str, d: u32) -> u32 {
        std::env::var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(d)
    }

    let ch = env_u32("RADIO_CH", 149) as u8;
    let frames = env_u32("RADIO_FRAMES", 5000);
    let payload = env_u32("RADIO_PAYLOAD", 1000) as usize;
    let txpwr = env_u32("RADIO_TXPWR", 0x30); // moderate: full power overloads a close RX
    let rssi = std::env::var("RADIO_RSSI").ok().and_then(|v| v.parse().ok()).unwrap_or(-65i8);
    let mode = std::env::var("RADIO_MODE").unwrap_or_else(|_| "bandit".into());
    // Run a single arm ("mcs1"|"mcs5"|"mcs9"|"adaptive") so each RX capture window
    // maps to exactly one arm; unset = all arms in sequence.
    let only = std::env::var("RADIO_ARM").ok();
    let want = |a: &str| only.as_deref().is_none_or(|o| o == a);

    let radio = RadioId(0);
    let backend = Arc::new(LibUsbRtl88xxBackend::open_monitor(ch)?);
    backend.set_channel(ch, ChannelBw::Bw80)?; // 80 MHz VHT, matching the template
    backend.set_tx_power(txpwr)?;

    // Build the control plane and bind its actuator to this backend.
    let mut control = match mode.as_str() {
        "static" => RadioControl::new(ndn_radio_cognition::RadioPolicy::default()),
        "calibrated" => RadioControl::new_calibrated(PolicyConfig::default(), 0.9, 1.0),
        _ => RadioControl::new_bandit(PolicyConfig::default(), 0.4),
    };
    control.register_radio(radio, ndn_face_monitor_wifi::FaceId(0), RadioCapability::wifi_monitor_5ghz(vec![ch]));
    let _cell = control.libusb_actuator(radio, backend.clone());
    let px = prefix_hash(&[b"airtime-ab"]);
    control.set_active(vec![NameContext::new(px)]);
    control.observe_rx(radio, 1, Some(rssi), 0); // synthetic link for the adaptive arm

    let desc = |p: &TxParams| McsDescriptor {
        index: p.mcs.unwrap_or(1),
        short_gi: p.short_gi,
        vht: p.vht,
        nss: p.nss.unwrap_or(1),
        stbc: p.stbc,
        ldpc: p.ldpc,
    };
    let template = |mcs: u8| TxParams {
        mcs: Some(mcs),
        vht: true,
        nss: Some(1),
        bw: Some(2),
        ldpc: true,
        ..Default::default()
    };
    let mk_payload = |arm: u8, seq: u32| -> Bytes {
        let mut v = vec![0u8; payload];
        v[0] = arm;
        v[1..5].copy_from_slice(&seq.to_le_bytes());
        Bytes::from(v)
    };

    println!("on-air A/B  ch{ch}@80MHz  txpwr=0x{txpwr:02x}  {frames} frames/arm  {payload} B  mode={mode}  synth-rssi={rssi}");
    println!("src MAC for RX filter: 02:4e:44:4e:00:01   arm={}", only.as_deref().unwrap_or("ALL"));
    println!("{:>10}  {:>6}  {:>12}  {:>8}", "arm", "frames", "airtime(ms)", "avg_mcs");

    // --- fixed-MCS baselines ---
    for (arm, mcs) in [(0u8, 1u8), (1, 5), (2, 9)] {
        if !want(&format!("mcs{mcs}")) {
            continue;
        }
        let p = template(mcs);
        let d = desc(&p);
        backend.set_channel(ch, ChannelBw::Bw80)?;
        let mut airtime = 0.0f64;
        for seq in 0..frames {
            backend
                .inject(InjectFrame::broadcast(mk_payload(arm, seq), d))
                .await?;
            airtime += frame_airtime_us(&p, payload) as f64;
        }
        println!("{:>10}  {:>6}  {:>12.1}  {:>8}", format!("fixed-mcs{mcs}"), frames, airtime / 1000.0, mcs);
    }

    // --- adaptive arm (the control plane decides per frame) ---
    if want("adaptive") {
    let mut airtime = 0.0f64;
    let mut mcs_sum = 0u64;
    for seq in 0..frames {
        let plans = control.tick_now(seq as u64); // decides + applies channel/power/CSD/EDCCA
        let p = plans
            .first()
            .and_then(|pl| pl.allocations.first())
            .map(|a| a.params)
            .unwrap_or_else(|| template(5));
        backend
            .inject(InjectFrame::broadcast(mk_payload(3, seq), desc(&p)))
            .await?;
        airtime += frame_airtime_us(&p, payload) as f64;
        mcs_sum += p.mcs.unwrap_or(0) as u64;
    }
    println!(
        "{:>10}  {:>6}  {:>12.1}  {:>8.1}",
        "adaptive",
        frames,
        airtime / 1000.0,
        mcs_sum as f64 / frames as f64
    );
    }

    println!("\nRead each arm's 'received by filter' at the RX (filter: wlan src 02:4e:44:4e:00:01).");
    println!("airtime-per-satisfied(arm) = printed airtime(arm) / received(arm). Lowest wins.");
    let t = control.telemetry();
    println!("strategy={}  worst-objective={:.3}", t.strategy, t.objective);
    Ok(())
}
