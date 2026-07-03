//! The operating-system wall clock as a time source.

use std::time::{Instant, SystemTime, UNIX_EPOCH};

use ndn_time::capability::{Holdover, TimeSourceKind, Traceability};
use ndn_time::{ClockCapability, TimeInterval};

use crate::{Reading, TimeSource};

/// Reads the OS wall clock (`SystemTime`) alongside a monotonic origin
/// (`Instant`). Its capability is that of a typically-NTP-disciplined host
/// clock: UTC-traceable but only ms-class and freely disciplinable, so it enters
/// the anchor election as a *low* candidate that any tight local reference
/// out-elects.
pub struct OsClock {
    epoch: Instant,
    uncertainty_ns: u64,
}

impl OsClock {
    /// A source claiming `uncertainty_ns` half-width on its wall reading.
    pub fn new(uncertainty_ns: u64) -> Self {
        Self {
            epoch: Instant::now(),
            uncertainty_ns,
        }
    }

    fn capability(&self) -> ClockCapability {
        ClockCapability {
            kind: TimeSourceKind::Ntp,
            // A stock OS clock is usually NTP-disciplined; if it is not, the
            // uncertainty the caller set should say so.
            traceable: Traceability::Utc,
            holdover: Holdover {
                drift_ppm: 20.0,
                allan_dev_1s: 1e-8,
                aging_ppm_per_day: 0.1,
                temp_sensitive: false,
            },
            base_uncertainty_ns: self.uncertainty_ns,
            disciplinable: true,
            reference_only: false,
        }
    }
}

impl Default for OsClock {
    /// 5 ms uncertainty — a reasonable default for an NTP-disciplined host.
    fn default() -> Self {
        Self::new(5_000_000)
    }
}

impl TimeSource for OsClock {
    fn poll(&mut self) -> Option<Reading> {
        let wall_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()?
            .as_nanos() as i64;
        let mono = self.epoch.elapsed().as_nanos() as u64;
        Some(Reading {
            wall: TimeInterval::new(wall_ns, self.uncertainty_ns),
            cap: self.capability(),
            captured_mono_ns: mono,
        })
    }

    fn label(&self) -> &'static str {
        "os-clock"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_clock_reads_a_plausible_wall_and_monotone_mono() {
        let mut c = OsClock::default();
        let r1 = c.poll().expect("os clock reads");
        // A sane wall time: well after 2020 (1.5e18 ns) and before year ~2100.
        assert!(r1.wall.center_ns > 1_500_000_000_000_000_000);
        assert_eq!(r1.wall.radius_ns, 5_000_000);
        assert!(r1.cap.disciplinable);
        // Monotonic capture does not regress across polls.
        let r2 = c.poll().unwrap();
        assert!(r2.captured_mono_ns >= r1.captured_mono_ns);
    }

    #[test]
    fn custom_uncertainty_is_reported() {
        let mut c = OsClock::new(250_000_000); // a quarter-second, undisciplined
        assert_eq!(c.poll().unwrap().wall.radius_ns, 250_000_000);
    }
}
