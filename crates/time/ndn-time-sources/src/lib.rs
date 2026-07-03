//! Layer: extension — concrete **local** time sources with pluggable backends.
//!
//! A *source* turns a clock backend (the OS clock, a GNSS receiver, an RTC, an
//! uplink) into a [`Reading`] — a wall-clock estimate with its honest
//! uncertainty and the [`ClockCapability`](ndn_time::ClockCapability) that
//! produced it — which the `ndn-time` discipline loop combines. Sources are
//! **push, not pull**, exactly like `ndn-signal-sources`: a driver loop calls
//! [`TimeSource::poll`] on a cadence and the latest reading is what the loop
//! consumes; nothing blocks a hot path.
//!
//! This crate is only the I/O backends that read a node's *own* clocks. The
//! pure `PeerDerived` path — a *validated* peer beacon turned into a discipline
//! sample — lives in the `ndn-time` core as
//! [`TimeBeacon`](ndn_time::TimeBeacon), because it is pure and NDN-coupled, not
//! hardware I/O.
//!
//! ## Backends here
//!
//! - [`OsClock`] — the operating-system wall clock (`SystemTime` + monotonic
//!   `Instant`). Always available; ms-class.
//! - [`nmea::GnssSource`] — a GNSS receiver, fed NMEA sentences. The **parsing**
//!   ([`nmea::parse_rmc_unix_ns`]) is pure and lives here; the serial read that
//!   *feeds* it is the host's job (`source.feed(line)`), so this crate pulls no
//!   serial dependency. Tens-of-ns class once a fix is present.
//! - [`MockSource`] — a scripted reading, for tests and for driving the loop
//!   with no hardware.
//!
//! An SNTP uplink and a concrete serial/RTC driver are natural additions behind
//! their own features; an SNTP client in particular is just a two-way exchange,
//! so it would reuse `ndn_time::measure::two_way` for the offset.

use ndn_time::{ClockCapability, TimeInterval};

pub mod mock;
pub mod nmea;
pub mod os_clock;

pub use mock::MockSource;
pub use nmea::GnssSource;
pub use os_clock::OsClock;

/// One clock reading: a wall estimate with uncertainty, the capability that
/// produced it, and the local monotonic time it was taken.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Reading {
    /// Wall-clock estimate as an interval (center ± uncertainty), Unix ns.
    pub wall: TimeInterval,
    /// The clock that produced this reading (its holdover, traceability, …) —
    /// feeds the anchor election weight and holdover aging downstream.
    pub cap: ClockCapability,
    /// Local monotonic clock (ns) when the reading was taken — anchors aging and
    /// the skew regression in the discipline loop.
    pub captured_mono_ns: u64,
}

/// A source of *local* time. Poll it on a cadence; `None` means "nothing new
/// since the last poll".
pub trait TimeSource {
    /// The latest reading, if the backend has one.
    fn poll(&mut self) -> Option<Reading>;

    /// A stable label for logs and telemetry (e.g. `"os-clock"`, `"gnss-nmea"`).
    fn label(&self) -> &'static str;
}
