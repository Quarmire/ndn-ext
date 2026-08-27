//! On-air validation of the frame-free occupancy wire (#30): bring up a real
//! RTL88xx radio, bind it to the cognitive control plane as BOTH actuator and
//! sensor, and let the face's own sampler feed `rx_activity/s` → `busy_pct` into
//! the sense bus at bring-up. Prints the sensed busy% each second, and — via a
//! `tracing` subscriber filtered to `named_radio` — shows the `occupancy_sample`
//! events that the `ndn-observability` OTLP-span pipeline carries.
//!
//!   cargo run -p ndn-phy-wifi --features libusb-backend --example occupancy_onair
//!   env: OCC_CH (default 6), OCC_SECS (default 20), OCC_INTERVAL_MS (default 1000)
//!
//! Validate: on a busy channel busy% rises and tracks the ambient frame rate; on a
//! quiet channel it reads ~0 — the same signal `sense_probe` measured, now flowing
//! through the face into the policy without decoding a frame in software.

#[cfg(not(feature = "libusb-backend"))]
fn main() {
    eprintln!("build with --features libusb-backend to run the on-air occupancy validation");
}

#[cfg(feature = "libusb-backend")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::sync::Arc;
    use std::time::Duration;

    use ndn_phy_wifi::{ChannelBw, FaceId, LibUsbRtl88xxBackend, RadioControl};
    use ndn_radio_cognition::{NameContext, RadioCapability, RadioId, RadioPolicy, prefix_hash};

    // Show the frame-free `occupancy_sample` + `decision` events (target
    // `named_radio*`) — the exact tracing spans/events the OTLP publisher exports.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "named_radio=debug".into()),
        )
        .with_target(true)
        .init();

    let env_u64 = |k: &str, d: u64| {
        std::env::var(k)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(d)
    };
    // The cognitive control plane runs on the RTL8822E (0bda:a81a) — the chip
    // LibUsbRtl88xxBackend actually drives (and the only RTL part that implements
    // RadioKnobs). Default to it explicitly; open_monitor() would grab the first
    // Realtek PID (an 8812au) and fail the 8822E bring-up.
    let pid = env_u64("OCC_PID", 0xa81a) as u16;
    let ch = env_u64("OCC_CH", 149) as u8; // 5 GHz monitor (8822E bring-up path)
    let secs = env_u64("OCC_SECS", 20);
    let interval = Duration::from_millis(env_u64("OCC_INTERVAL_MS", 1000));

    let radio = RadioId(0);
    let backend = Arc::new(LibUsbRtl88xxBackend::open_monitor_pid(pid, ch)?);
    let _ = ChannelBw::Bw20; // bring_up already tuned the channel
    println!(
        "RTL8822E (0bda:{pid:04x}) up on ch{ch}; sampling occupancy every {interval:?} for {secs}s"
    );

    // Bring-up: build the plane, bind the backend as actuator, then start the
    // face's frame-free occupancy sampler over the same handle (ACT + SENSE).
    let mut control = RadioControl::new(RadioPolicy::default());
    control.register_radio(
        radio,
        FaceId(0),
        RadioCapability::wifi_monitor_5ghz(vec![ch]),
    );
    let _cell = control.libusb_actuator(radio, backend.clone());
    // An active object so each tick makes a real decision — its `decision` span
    // tree then shows the sensed occupancy as a decision INPUT beside the chosen
    // OUTPUT params ("why").
    control.set_active(vec![NameContext::new(prefix_hash(&[b"occupancy-onair"]))]);
    let control = Arc::new(control);
    let _sampler = control.start_occupancy_sampling(radio, ch, backend.clone(), interval);

    for _ in 0..secs {
        tokio::time::sleep(Duration::from_secs(1)).await;
        // Run a decision so the input→output span tree emits with live occupancy.
        control.tick_now(control.now_ms());
        match control.busy_pct(radio, ch) {
            Some(b) => println!("  ch{ch}: sensed busy = {b}%"),
            None => println!("  ch{ch}: (no sample yet)"),
        }
    }
    Ok(())
}
