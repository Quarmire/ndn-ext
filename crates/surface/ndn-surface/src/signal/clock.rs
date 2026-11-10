//! The clock signals are dated and judged by (signals.md §3.3, §13.8).
//!
//! `SignalOptions::clock` stays the source of raw time. What the layer reads is
//! `max(raw, floor-continued)`: **floor-continued** starts one µs above the device's durable
//! floor ([`Device::signal_clock_floor`](ndn_data::Device::signal_clock_floor), a time this device
//! dated signals by before, reserved ahead) and runs on by the progress of time since: a
//! monotonic clock when the raw clock is the system's (immune to the system clock stepping), the
//! raw clock's own forward progress when a host gave one. So:
//!
//! - a run never starts at or below the floor, whatever the raw clock says after a restart;
//! - the reading never steps back while the process runs, whatever the raw clock does: a clock
//!   that stepped back is held where it was, and runs on from there;
//! - the reading is the raw clock whenever that is the later one, so a raw clock that is right
//!   (or ahead of everything dated before) is never altered.
//!
//! The floor never moves a sender's clock forward to real time: a clock that stays behind real
//! time still dates signals that are expired for receivers (§13.8).

use std::sync::Mutex;
use std::time::Instant;

use super::{SignalClock, system_us};

/// The layer's clock: µs since the Unix epoch, never decreasing.
pub(super) struct Clock {
    raw: Option<SignalClock>,
    state: Mutex<State>,
}

struct State {
    /// The last reading: raw, or floor-continued when that was later.
    reading: u64,
    /// The system clock's progress source: when `reading` last advanced by it.
    at: Instant,
    /// A host clock's progress source: what it read last.
    last_raw: u64,
}

impl Clock {
    /// A clock over `raw` (the system's when `None`) whose first reading is above `floor`.
    pub(super) fn new(raw: Option<SignalClock>, floor: u64) -> Clock {
        let last_raw = raw.as_ref().map_or(0, |c| c());
        Clock {
            raw,
            state: Mutex::new(State {
                reading: floor.saturating_add(1),
                at: Instant::now(),
                last_raw,
            }),
        }
    }

    /// The time now: at least the raw clock's, at least floor-continued, never less than a
    /// reading before.
    pub(super) fn now(&self) -> u64 {
        let raw = self.raw.as_ref().map_or_else(system_us, |c| c());
        let mut s = self.state.lock().expect("signal clock lock");
        let progress = if self.raw.is_none() {
            let now = Instant::now();
            let ran = now.saturating_duration_since(s.at);
            s.at = now;
            u64::try_from(ran.as_micros()).unwrap_or(u64::MAX)
        } else {
            let ran = raw.saturating_sub(s.last_raw);
            s.last_raw = raw;
            ran
        };
        s.reading = raw.max(s.reading.saturating_add(progress));
        s.reading
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn host(start: u64) -> (Arc<AtomicU64>, Clock, impl Fn(u64) -> Clock) {
        let now = Arc::new(AtomicU64::new(start));
        let read = Arc::clone(&now);
        let raw: SignalClock = Arc::new(move || read.load(Ordering::SeqCst));
        let clock = Clock::new(Some(Arc::clone(&raw)), 0);
        let with_floor = move |floor| Clock::new(Some(Arc::clone(&raw)), floor);
        (now, clock, with_floor)
    }

    /// A raw clock above the floor is the reading, to the µs.
    #[test]
    fn a_raw_clock_above_the_floor_is_read_as_it_is() {
        let (now, _, with_floor) = host(5_000_000);
        let clock = with_floor(1_000);
        assert_eq!(clock.now(), 5_000_000);
        now.store(5_000_123, Ordering::SeqCst);
        assert_eq!(clock.now(), 5_000_123);
    }

    /// After a restart with the raw clock behind the floor, the reading starts above the floor and
    /// runs on at the raw clock's pace, not below the floor and not frozen.
    #[test]
    fn a_raw_clock_behind_the_floor_is_continued_from_the_floor() {
        let (now, _, with_floor) = host(1_000_000);
        let clock = with_floor(9_000_000);
        assert_eq!(
            clock.now(),
            9_000_001,
            "the first reading is one µs above the floor"
        );
        now.fetch_add(250, Ordering::SeqCst);
        assert_eq!(
            clock.now(),
            9_000_251,
            "it runs on by the raw clock's progress"
        );
        // The raw clock runs on and stays behind: the reading keeps its distance from it.
        now.fetch_add(1_000_000, Ordering::SeqCst);
        assert_eq!(clock.now(), 10_000_251);
    }

    /// A raw clock that steps back while running is held, then runs on from where it was.
    #[test]
    fn a_raw_clock_that_steps_back_never_makes_the_reading_step_back() {
        let (now, clock, _) = host(10_000_000);
        let first = clock.now();
        assert_eq!(first, 10_000_000);
        now.store(1_000_000, Ordering::SeqCst);
        assert_eq!(clock.now(), first, "held where it was");
        now.fetch_add(40, Ordering::SeqCst);
        assert_eq!(
            clock.now(),
            first + 40,
            "then it runs on by its own progress"
        );
        now.fetch_sub(5_000, Ordering::SeqCst);
        assert_eq!(clock.now(), first + 40);
    }

    /// The system clock's reading is monotonic by `Instant`: a floor far in the future is
    /// continued at real pace, and the reading never falls.
    #[test]
    fn the_system_clock_is_continued_by_a_monotonic_clock_past_a_floor_ahead_of_it() {
        let floor = system_us() + 3_600_000_000;
        let clock = Clock::new(None, floor);
        let a = clock.now();
        assert!(a > floor);
        std::thread::sleep(std::time::Duration::from_millis(20));
        let b = clock.now();
        assert!(b >= a + 20_000, "{b} is not 20 ms past {a}");
    }
}
