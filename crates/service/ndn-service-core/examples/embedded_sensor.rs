//! The embedded **leaf producer** in miniature: a temperature sensor frames typed
//! readings, names them, (optionally) seals them with a symmetric scope key, and
//! emits them through a [`PublicationSink`] — exactly the code you would write on
//! an ESP32-class device, run here on the host so you can watch the bytes.
//!
//! The point of the example: the *same* `Publisher` you see here compiles for bare
//! metal with no `std`, no runtime, no sync engine:
//!
//! ```text
//! # this example (host):
//! cargo run -p ndn-service-core --example embedded_sensor --features seal
//!
//! # the same producer, cross-compiled for a Cortex-M4F MCU:
//! cargo build -p ndn-service-core --no-default-features --features seal \
//!     --target thumbv7em-none-eabihf
//! ```
//!
//! The role split (see `docs/specs/service-layer.md`): the leaf does the cheap part
//! — frame → name → seal → emit. A *gateway* (a capable node) holds the heavy
//! machinery and ingests these named publications into the full `Topic<T>` / SVS
//! world. Here, the `gateway` closures stand in for that node.

use ndn_service_core::Frame;
use ndn_service_core::publish::{Publication, PublicationSink, Publisher, ScopeKey};
use ndn_service_macro::Frame;

/// A typed sensor reading — the structured "response with data". `#[derive(Frame)]`
/// gives it wire framing; the gateway decodes with this very same type, so leaf and
/// node never disagree about the format. Integer fields only — no FPU on the leaf.
#[derive(Frame, Clone, Debug, PartialEq)]
struct Reading {
    /// Temperature in tenths of a degree Celsius (e.g. 213 = 21.3 °C).
    decicelsius: i32,
    /// Relative humidity, percent.
    humidity_pct: u32,
}

/// A sink standing in for the leaf's radio. It "broadcasts" each publication (here,
/// records it for the gateway to pick up) and prints what went on air. On a real
/// ESP32 this would push `publication.payload` under `publication.name` onto
/// ESP-NOW, a monitor-mode 802.11 frame, or a UART.
#[derive(Default)]
struct RadioSink {
    on_air: Vec<Publication>,
}

impl PublicationSink for RadioSink {
    // This leaf's "transmit" cannot fail; a real one would surface a link error.
    type Error = core::convert::Infallible;

    fn deliver(&mut self, publication: &Publication) -> Result<(), Self::Error> {
        println!(
            "    on air: {}  ({} payload bytes)",
            publication.name,
            publication.payload.len()
        );
        self.on_air.push(publication.clone());
        Ok(())
    }
}

fn main() {
    // ---- 1. Plaintext feed -------------------------------------------------
    // A sensor publishes a typed, named, append-only feed. No runtime, no engine.
    println!("== leaf publishes a typed feed: /sensor/lab-3/temp/seq=N ==");
    let mut sensor = Publisher::<Reading>::new("/sensor/lab-3/temp".parse().unwrap());
    let mut radio = RadioSink::default();

    for r in [
        Reading { decicelsius: 213, humidity_pct: 41 },
        Reading { decicelsius: 215, humidity_pct: 42 },
        Reading { decicelsius: 208, humidity_pct: 44 },
    ] {
        sensor.publish(&r, &mut radio).unwrap();
    }

    // The gateway picks the publications off the air and decodes with the same
    // `Frame` type. (Sequence == index here, since the feed is append-only from 0.)
    println!("  gateway decodes the feed:");
    for publication in &radio.on_air {
        let reading = Reading::decode(&publication.payload).unwrap();
        println!(
            "    {} -> {:.1} °C, {}% RH",
            publication.name,
            reading.decicelsius as f32 / 10.0,
            reading.humidity_pct
        );
    }

    // ---- 2. Confidential feed ---------------------------------------------
    // The gateway handed this leaf a 32-byte scope key out of band (it ran the
    // heavy ABE-by-role / sealed-box distribution; the leaf just holds the key).
    println!("\n== leaf publishes a CONFIDENTIAL feed (symmetric scope key) ==");
    let scope_key = ScopeKey::from_bytes([7u8; 32]);
    // `publisher_id` (here 1) must be unique among leaves sharing the scope key —
    // it is the high 4 bytes of the AEAD nonce, so two leaves never collide.
    let mut secure_sensor =
        Publisher::<Reading>::sealed("/sensor/lab-3/secure".parse().unwrap(), scope_key.clone(), 1);
    let mut secure_radio = RadioSink::default();

    secure_sensor
        .publish(&Reading { decicelsius: 221, humidity_pct: 39 }, &mut secure_radio)
        .unwrap();

    // On air the payload is the `ContentKey` wire layout: nonce ‖ tag ‖ ciphertext.
    // The ciphertext is opaque without the key.
    let sealed = &secure_radio.on_air[0];
    let ciphertext = &sealed.payload[28..]; // skip nonce(12) + tag(16)
    println!(
        "  on-air payload = nonce ‖ tag ‖ ciphertext ({} B); ciphertext head: {:02x?}…",
        sealed.payload.len(),
        &ciphertext[..ciphertext.len().min(8)]
    );

    // A member gateway holding the scope key opens it — the AAD is the publication
    // name (the leaf bound it automatically), the nonce rides on the wire — then
    // decodes the same `Frame`. (A capable node would open with `ContentKey`
    // directly; the bytes are identical.)
    let aad = sealed.name.encode_to_tlv();
    let opened = scope_key.open(&aad, &sealed.payload).expect("scope key opens it");
    let reading = Reading::decode(&opened).unwrap();
    println!(
        "  member gateway (has key) reads: {:.1} °C, {}% RH",
        reading.decicelsius as f32 / 10.0,
        reading.humidity_pct
    );

    // An outsider with the wrong key gets nothing — fail closed.
    let outsider = ScopeKey::from_bytes([0u8; 32]);
    match outsider.open(&aad, &sealed.payload) {
        Some(_) => println!("  outsider read it?!  (must not happen)"),
        None => println!("  outsider (wrong key) is denied — AEAD authentication fails"),
    }
}
