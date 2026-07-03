//! Layer: extension — the **named-time runtime** (the actuator + carriage).
//!
//! This is where the pure `ndn-time` core becomes a running clock. The
//! [`Timekeeper`] is a sans-IO state machine (like the radio plane's
//! `MediumState`/`RadioPolicy`): a host drives it on a cadence, feeding it
//! local-source [`Reading`](ndn_time_sources::Reading)s and *validated* peer
//! beacons, and it returns a [`TickOutcome`] naming the actuation — steer the
//! clock, write `NodeSignals.clock_ms`, publish a fresh beacon.
//!
//! [`beacon_wire`] is the encoding of a time-beacon's Data Content — the one
//! wire format named-time adds, carried as opaque bytes inside a signed Data
//! under `/<scope>/time/<node>/<seq>` (no new NDN wire crate; the signature is
//! what makes it trustworthy).
//!
//! ## The host's driver loop (the I/O this crate deliberately omits)
//!
//! ```text
//! loop {
//!     for src in &mut sources {                       // OS clock, GNSS, …
//!         if let Some(r) = src.poll() { tk.ingest_local_reading(&r, wall_now()); }
//!     }
//!     while let Some(data) = time_sub.try_recv() {    // SVS/pubsub carriage
//!         let safe = validator.verify(data)?;         // security: SafeData
//!         let d = beacon_wire::decode(safe.content())?;
//!         tk.ingest_beacon(peer_id(&safe), &d.into_beacon(mono_now(), prov(&safe)), wall_now());
//!     }
//!     let out = tk.tick(mono_now(), wall_now());
//!     match out.discipline { Slew{rate_ppb} => steer(rate_ppb), Step{..} => step(), .. }
//!     if let Some(ms) = out.clock_ms { signals.set_clock_ms(node, ms); }
//!     if let Some(b) = out.beacon { publish(sign(beacon_wire::encode(b.seq, b.wall_ns, b.uncertainty_ns, &b.cap))); }
//!     sleep(cadence);
//! }
//! ```
//!
//! That loop needs a face, an SVS group, a `Validator`, a `Signer`, and a
//! `SignalStore` — all of which the app already has. Wiring it to a concrete
//! engine (and integration-testing it in `ndn-sim` with real forwarders) is the
//! remaining step; everything above the I/O line is here and unit-tested.

pub mod beacon_wire;
pub mod runtime;

pub use beacon_wire::{BEACON_WIRE_VERSION, DecodedBeacon, decode, encode};
pub use runtime::{OutboundBeacon, TickOutcome, Timekeeper};
