//! MT7612U driven by the named-radio cognition plane. Shows roadmap step #1: the
//! MT7612 declares a 2.4 GHz capability pool, binds the SAME generic
//! `LibUsbActuator` the RTL backend uses (via the shared `RadioKnobs` trait), and
//! one sense→decide→act tick has the plane choose `TxParams` and apply
//! channel/power to the MT7612 — no backend-specific control code.
//! `cargo run -p ndn-face-monitor-wifi --features libusb-backend --example mt7612_cognition`
#[cfg(feature = "libusb-backend")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use ndn_face_monitor_wifi::{FaceId, Mt7612uBackend, RadioControl};
    use ndn_radio_cognition::{NameContext, RadioCapability, RadioId, RadioPolicy, prefix_hash};
    use std::sync::Arc;

    let dev = Arc::new(Mt7612uBackend::open()?);
    dev.bring_up()?;
    println!("chip 0x{:04x} — wiring MT7612 into the cognition plane", dev.chip_id()?);

    let radio = RadioId(0);
    let mut control = RadioControl::new(RadioPolicy::default());
    // The MT7612 as a 2.4 GHz pool of capability (channel 6 only for now).
    control.register_radio(radio, FaceId(0), RadioCapability::wifi_monitor_2ghz(vec![6]));
    // Bind the generic actuator: `Arc<Mt7612uBackend>` coerces to
    // `Arc<dyn RadioKnobs>` — identical call to the RTL backend, no special case.
    let _planned = control.libusb_actuator(radio, dev.clone());
    control.set_active(vec![NameContext::new(prefix_hash(&[b"mt7612-demo"]))]);
    control.observe_rx(radio, 1, Some(-60), 0); // synthetic link so a rate is chosen

    // One SENSE→DECIDE→ACT tick: the plane decides TxParams and the actuator
    // applies channel/power to the MT7612 (via RadioKnobs) + stages the per-frame
    // params in the shared cell a face's select_mcs would read.
    let plans = control.tick_now(0);
    println!(
        "cognition produced {} plan(s); MT7612 tuned + per-frame params staged via RadioKnobs.",
        plans.len()
    );
    Ok(())
}
#[cfg(not(feature = "libusb-backend"))]
fn main() {}
