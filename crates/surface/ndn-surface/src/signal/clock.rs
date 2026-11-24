//! The clocks signals are dated and judged by (signals.md §3.3, §3.5, §13.8).
//!
//! `SignalOptions::clock` stays the source of raw time, the system's when none is given. The
//! layer reads it three ways:
//!
//! - **raw** ([`Clock::raw_now`]) judges whether what arrives is still live: `Expires`,
//!   `NotAfter`, and letting a run go. Nothing a sender or the device held can move it, so a
//!   receiver whose own dating is ahead still judges by real time. How far *ahead* of now
//!   a signal or a run may be dated (the 60 s and 24 h limits) is measured from the reading,
//!   which is never earlier than raw: a device whose raw clock is behind real time, and whose
//!   reading holds the time it last dated by, is not deaf to signals dated by real time.
//! - **the reading** ([`Clock::now`]) dates what this process sends. It starts at
//!   `max(raw, hint + 1)`, the hint being the time this device last dated by
//!   ([`Durable::hint`]), and runs on by the
//!   progress of time since: a monotonic clock when the raw clock is the system's (immune to
//!   the system clock stepping), the raw clock's own forward progress when a host gave one. So a
//!   clock that stepped back is held where it was while the process runs, and a restart does not
//!   date earlier than the last run did. The hint carries **no reserve**, so quick restarts
//!   cannot ratchet it ahead of the raw clock.
//! - **ticks** ([`Clock::ticks`]) time the rate buckets and the timers: never decreasing, never
//!   reset.
//!
//! The reading is held ahead of raw by no more than the run lifetime. A hint further ahead at
//! start (a clock set far ahead, dated by, then corrected), or a raw clock that falls further
//! behind the reading while running, is not kept: the reading goes to raw, and a warning says
//! so. Sequences are not dated by the reading, they come from the device's durable counter
//! (`Durable::sequences`), so the reading going to raw never lowers one.
//!
//! Held within the run lifetime, a forward step persists until real time catches up; a sender
//! whose clock stays behind real time still dates signals that are expired for receivers
//! (§13.8).

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use ndn_foundation_types::Name;
use ndn_heap::HeapError;
use ndn_sync::DataStore;

use super::{SignalClock, SignalError, system_us};

/// The layer's clock.
pub(super) struct Clock {
    raw: Option<SignalClock>,
    /// The run lifetime in µs: how far ahead of raw the reading may be held.
    lifetime_us: u64,
    state: Mutex<State>,
}

struct State {
    /// The last reading: raw, or held ahead of it.
    reading: u64,
    /// Monotonic µs for rate buckets and timers.
    ticks: u64,
    /// The system clock's progress source: when the clocks last advanced by it.
    at: Instant,
    /// A host clock's progress source: what it read last.
    last_raw: u64,
}

impl Clock {
    /// A clock over `raw` (the system's when `None`) for a device whose last dated time is
    /// `hint` and whose runs last `run_lifetime`. Its first reading is `max(raw, hint + 1)`,
    /// unless the hint is more than the run lifetime ahead of raw: then it is raw, and a
    /// warning says why.
    pub(super) fn new(raw: Option<SignalClock>, hint: u64, run_lifetime: Duration) -> Clock {
        let lifetime_us = u64::try_from(run_lifetime.as_micros()).unwrap_or(u64::MAX);
        let now = raw.as_ref().map_or_else(system_us, |c| c());
        let held = hint.saturating_add(1);
        let reading = if held <= now {
            now
        } else if held > now.saturating_add(lifetime_us) {
            let ahead = (hint - now) / 1_000_000;
            let life = lifetime_us / 1_000_000;
            tracing::warn!(
                target: "ndn_surface::signal",
                "the signal time hint is {ahead} s ahead of the clock, more than the run lifetime \
                 ({life} s): signals are dated by the clock as it reads now. If the clock was \
                 just corrected there is nothing to do; if it is wrong, set it right, because \
                 receivers drop signals dated far from their own time"
            );
            now
        } else {
            held
        };
        Clock {
            raw,
            lifetime_us,
            state: Mutex::new(State {
                reading,
                ticks: 0,
                at: Instant::now(),
                last_raw: now,
            }),
        }
    }

    /// The raw clock: what arrives is judged by it (§13.8).
    pub(super) fn raw_now(&self) -> u64 {
        self.raw.as_ref().map_or_else(system_us, |c| c())
    }

    /// The time this process dates what it sends by: at least raw, at least the reading before
    /// carried forward, and never more than the run lifetime ahead of raw.
    pub(super) fn now(&self) -> u64 {
        self.step().0
    }

    /// Monotonic µs, from an arbitrary start: for rate buckets and timers, which only compare
    /// readings of it.
    pub(super) fn ticks(&self) -> u64 {
        self.step().1
    }

    /// Both readings, advanced by the progress since the last.
    fn step(&self) -> (u64, u64) {
        let raw = self.raw_now();
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
        s.ticks = s.ticks.saturating_add(progress);
        let carried = s.reading.saturating_add(progress);
        s.reading = if carried > raw.saturating_add(self.lifetime_us) {
            let ahead = (carried - raw) / 1_000_000;
            let life = self.lifetime_us / 1_000_000;
            tracing::warn!(
                target: "ndn_surface::signal",
                "the signal reading was {ahead} s ahead of the clock, more than the run lifetime \
                 ({life} s) after the clock stepped back: signals are dated by the clock as it \
                 reads now. If the clock was just corrected there is nothing to do; if it is \
                 wrong, set it right, because receivers drop signals dated far from their own time"
            );
            raw
        } else {
            raw.max(carried)
        };
        (s.reading, s.ticks)
    }
}

/// Sequences made durable at a time (signals.md §3.3, §3.5): a send inside the block held needs
/// no write, and a crash loses at most one block of the 2^64 sequences.
pub(super) const SEQ_BLOCK: u64 = 1 << 20;

/// How far a time dated by must be from the hint held before the hint is written again
/// (signals.md §3.5): the hint is a hint, so a write about once a second is enough.
const TIME_NOTE_EVERY_US: u64 = 1_000_000;

/// Where the store keeps the sequence counter (`/localhost/ndn-surface/signal-clock`, 8 octets
/// big-endian): a number made durable above every sequence given, so a restart never gives one
/// below it. A prefix no device serves and the heap layer never scans.
fn counter_name() -> Name {
    "/localhost/ndn-surface/signal-clock"
        .parse()
        .expect("a valid name")
}

/// Where the store keeps the time hint (`/localhost/ndn-surface/signal-time`, 8 octets
/// big-endian, µs since the Unix epoch): a time signals were dated by, written lazily and never
/// waited for.
fn time_name() -> Name {
    "/localhost/ndn-surface/signal-time"
        .parse()
        .expect("a valid name")
}

/// What a process keeps of signals' clock in the store it was started with: the sequence counter
/// and the time hint.
pub(super) struct Durable {
    store: Arc<dyn DataStore>,
    held: Mutex<Held>,
}

struct Held {
    /// The counter made durable: every sequence given is below it.
    durable: u64,
    /// The highest counter written (a write whose barrier may not have returned).
    written: u64,
    /// The time hint, as last read or noted (µs since the Unix epoch).
    hint: u64,
}

impl Durable {
    /// What the last run left in `store`: the counter and the hint, 0 for each a process never
    /// wrote.
    pub(super) fn load(store: Arc<dyn DataStore>) -> Durable {
        let read = |name: Name| {
            store
                .get(&name)
                .and_then(|w| w.get(..8).and_then(|b| b.try_into().ok()))
                .map_or(0, u64::from_be_bytes)
        };
        let counter = read(counter_name());
        let hint = read(time_name());
        Durable {
            store,
            held: Mutex::new(Held {
                durable: counter,
                written: counter,
                hint,
            }),
        }
    }

    fn held(&self) -> std::sync::MutexGuard<'_, Held> {
        self.held.lock().expect("signal durable lock")
    }

    /// The sequences given are above this: the counter made durable, 0 where none was given
    /// (signals.md §3.3). A process starts its counter here, so a sequence is never given twice
    /// across a restart or a crash, whatever the clock did in between.
    pub(super) fn floor(&self) -> u64 {
        self.held().durable
    }

    /// The time last dated by, as the last run left it (µs since the Unix epoch; 0 where none was
    /// dated) or as noted since (signals.md §3.5). A hint, not a floor: written without a
    /// barrier, so after a crash it may be as old as the last barrier, and a clock that finds it
    /// far ahead of itself does not keep it.
    pub(super) fn hint(&self) -> u64 {
        self.held().hint
    }

    /// A signal was dated by `us` (µs since the Unix epoch). Held as the hint once it differs
    /// from the hint by a second or more, in either direction: a clock corrected after running
    /// ahead takes the hint back with it. Written to the store, never waited for.
    pub(super) fn note_time(&self, us: u64) {
        let mut held = self.held();
        if held.hint.abs_diff(us) < TIME_NOTE_EVERY_US {
            return;
        }
        held.hint = us;
        self.store
            .insert(time_name(), Bytes::copy_from_slice(&us.to_be_bytes()));
    }

    /// About to give sequences below `upto`: the counter once it is at least `upto` and durable.
    /// Below it already, answered at once with no write. Above it, the counter moves to `upto`
    /// plus [`SEQ_BLOCK`], the store's barrier ([`DataStore::sync`]) passes, and only then does
    /// this return, so a crash can never leave the counter at or below a sequence given. Asked
    /// again before the counter returned is neared.
    ///
    /// [`HeapError::Local`] when the store cannot make the write durable (check the disk the
    /// store is on): no sequence is to be given.
    pub(super) async fn sequences(&self, upto: u64) -> Result<u64, SignalError> {
        let write = {
            let mut held = self.held();
            if held.durable >= upto {
                return Ok(held.durable);
            }
            let target = upto.saturating_add(SEQ_BLOCK);
            if held.written < target {
                held.written = target;
                self.store.insert(
                    counter_name(),
                    Bytes::copy_from_slice(&target.to_be_bytes()),
                );
            }
            held.written
        };
        self.sync().await.map_err(|e| {
            SignalError::Heap(HeapError::Local {
                reason: format!("the store did not make the signal sequence counter durable ({e})"),
            })
        })?;
        let mut held = self.held();
        held.durable = held.durable.max(write);
        Ok(held.durable)
    }

    /// The store's barrier, on a blocking thread: a flush takes as long as the disk does. A
    /// store whose flush returns at once ([`DataStore::sync_is_immediate`]) is flushed inline.
    async fn sync(&self) -> std::io::Result<()> {
        if self.store.sync_is_immediate() {
            return self.store.sync();
        }
        let store = Arc::clone(&self.store);
        tokio::task::spawn_blocking(move || store.sync())
            .await
            .unwrap_or_else(|e| {
                Err(std::io::Error::other(format!(
                    "the flush did not finish ({e})"
                )))
            })
    }
}

#[cfg(test)]
mod durable_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    const LIFE: Duration = Duration::from_secs(3600);
    const HOUR_US: u64 = 3_600_000_000;

    /// A host clock at `start`, a clock over it for a device whose hint is `hint`, and the
    /// warnings logged while it was made.
    fn host(start: u64, hint: u64) -> (Arc<AtomicU64>, Clock, Vec<String>) {
        let now = Arc::new(AtomicU64::new(start));
        let read = Arc::clone(&now);
        let raw: SignalClock = Arc::new(move || read.load(Ordering::SeqCst));
        let (clock, warnings) = logged(|| Clock::new(Some(raw), hint, LIFE));
        (now, clock, warnings)
    }

    /// What `f` returned, and the warnings it logged on this thread.
    fn logged<R>(f: impl FnOnce() -> R) -> (R, Vec<String>) {
        struct Capture(Arc<Mutex<Vec<String>>>);
        struct Message(String);
        impl tracing::field::Visit for Message {
            fn record_debug(&mut self, f: &tracing::field::Field, v: &dyn std::fmt::Debug) {
                if f.name() == "message" {
                    self.0 = format!("{v:?}");
                }
            }
        }
        impl tracing::Subscriber for Capture {
            fn enabled(&self, m: &tracing::Metadata<'_>) -> bool {
                *m.level() <= tracing::Level::WARN
            }
            fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
                tracing::span::Id::from_u64(1)
            }
            fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
            fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
            fn event(&self, e: &tracing::Event<'_>) {
                let mut m = Message(String::new());
                e.record(&mut m);
                self.0.lock().unwrap().push(m.0);
            }
            fn enter(&self, _: &tracing::span::Id) {}
            fn exit(&self, _: &tracing::span::Id) {}
        }
        let log = Arc::new(Mutex::new(Vec::new()));
        let out = tracing::subscriber::with_default(Capture(Arc::clone(&log)), f);
        let warnings = log.lock().unwrap().clone();
        (out, warnings)
    }

    /// A raw clock above the hint is the reading, to the µs.
    #[test]
    fn a_raw_clock_above_the_hint_is_read_as_it_is() {
        let (now, clock, warnings) = host(5_000_000, 1_000);
        assert_eq!(clock.now(), 5_000_000);
        now.store(5_000_123, Ordering::SeqCst);
        assert_eq!(clock.now(), 5_000_123);
        assert!(warnings.is_empty());
    }

    /// A restart with the raw clock a little behind the hint starts above the hint and runs on
    /// at the raw clock's pace, not below it and not frozen.
    #[test]
    fn a_raw_clock_behind_the_hint_is_continued_from_the_hint() {
        let (now, clock, warnings) = host(1_000_000, 9_000_000);
        assert_eq!(
            clock.now(),
            9_000_001,
            "the first reading is one µs above the hint"
        );
        now.fetch_add(250, Ordering::SeqCst);
        assert_eq!(
            clock.now(),
            9_000_251,
            "it runs on by the raw clock's progress"
        );
        now.fetch_add(1_000_000, Ordering::SeqCst);
        assert_eq!(clock.now(), 10_000_251);
        assert!(
            warnings.is_empty(),
            "within the run lifetime nothing is said"
        );
    }

    /// The hint is kept up to the run lifetime ahead, and not a µs further: past it the reading
    /// is the raw clock and the warning says why.
    #[test]
    fn a_hint_more_than_the_run_lifetime_ahead_is_not_kept_and_is_logged() {
        let raw = 10 * HOUR_US;
        let (_, kept, warnings) = host(raw, raw + HOUR_US - 1);
        assert_eq!(
            kept.now(),
            raw + HOUR_US,
            "a reading a run lifetime ahead is kept"
        );
        assert!(warnings.is_empty());

        let (_, dropped, warnings) = host(raw, raw + HOUR_US);
        assert_eq!(dropped.now(), raw, "a µs past it the reading is raw");
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(
            warnings[0].contains("time hint") && warnings[0].contains("ahead of the clock"),
            "{warnings:?}"
        );
    }

    /// A raw clock that steps back while running is held, then runs on from where it was.
    #[test]
    fn a_raw_clock_that_steps_back_never_makes_the_reading_step_back() {
        let (now, clock, _) = host(10_000_000, 0);
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

    /// A raw clock that falls more than the run lifetime behind the reading while running is
    /// not held: the reading goes to raw and a warning says so, and the ticks never step back.
    #[test]
    fn a_raw_clock_far_behind_the_reading_while_running_takes_the_reading_with_it() {
        let (now, clock, _) = host(10 * HOUR_US, 0);
        assert_eq!(clock.now(), 10 * HOUR_US);
        now.store(12 * HOUR_US, Ordering::SeqCst);
        assert_eq!(clock.now(), 12 * HOUR_US, "a step forward is read as it is");
        let ticks = clock.ticks();
        now.store(10 * HOUR_US + 5, Ordering::SeqCst);
        let (read, warnings) = logged(|| clock.now());
        assert_eq!(
            read,
            10 * HOUR_US + 5,
            "the clock corrected 2 h back is read as it is"
        );
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].contains("ahead of the clock"), "{warnings:?}");
        assert!(clock.ticks() >= ticks, "ticks never step back");
        now.fetch_add(40, Ordering::SeqCst);
        assert_eq!(clock.now(), 10 * HOUR_US + 45);
    }

    /// The raw clock is read as it is, whatever the reading holds, for judging what arrives.
    #[test]
    fn what_arrives_is_judged_by_the_raw_clock_not_the_reading() {
        let (now, clock, _) = host(1_000_000, 601_000_000);
        assert_eq!(clock.now(), 601_000_001, "the reading is ten minutes ahead");
        assert_eq!(clock.raw_now(), 1_000_000, "the raw clock is not");
        now.store(2_000_000, Ordering::SeqCst);
        assert_eq!(clock.raw_now(), 2_000_000);
    }

    /// The ticks run on by the raw clock's forward progress and by nothing else.
    #[test]
    fn ticks_follow_progress_and_hold_through_a_step_back() {
        let (now, clock, _) = host(10_000_000, 0);
        let a = clock.ticks();
        now.fetch_add(300, Ordering::SeqCst);
        assert_eq!(clock.ticks(), a + 300);
        now.store(1, Ordering::SeqCst);
        assert_eq!(clock.ticks(), a + 300, "held through a step back");
    }

    /// The system clock's reading is monotonic by `Instant`: a hint ahead of it, within the run
    /// lifetime, is continued at real pace, and the reading never falls.
    #[test]
    fn the_system_clock_is_continued_by_a_monotonic_clock_past_a_hint_ahead_of_it() {
        let hint = system_us() + 1_800_000_000;
        let clock = Clock::new(None, hint, LIFE);
        let a = clock.now();
        assert!(a > hint);
        std::thread::sleep(Duration::from_millis(20));
        let b = clock.now();
        assert!(b >= a + 20_000, "{b} is not 20 ms past {a}");
    }
}
