//! The receiver's and sender's bounded state: the replay window of a run, rate
//! buckets, and the latest table of a scope.

use std::collections::HashMap;
use std::time::Duration;

use bytes::Bytes;
use ndn_foundation_types::Name;

/// Sequences a run's window remembers (§5).
pub(crate) const WINDOW: u64 = 1024;
/// (sender, address) pairs a scope's latest table holds (§5).
pub(crate) const LATEST_MAX: usize = 1024;

/// The sequences seen of one run: the highest, and which of the [`WINDOW`]
/// below it. A sequence seen, or older than the window, is a replay.
#[derive(Debug, Default)]
pub(crate) struct ReplayWindow {
    /// One above the highest sequence seen; 0 when none.
    top: u64,
    bits: [u64; (WINDOW / 64) as usize],
}

impl ReplayWindow {
    fn bit(seq: u64) -> (usize, u64) {
        let i = seq % WINDOW;
        ((i / 64) as usize, 1u64 << (i % 64))
    }

    /// Whether `seq` is new: above the highest seen, or in the window and unseen.
    pub(crate) fn fresh(&self, seq: u64) -> bool {
        if seq >= self.top {
            return true;
        }
        if self.top - seq > WINDOW {
            return false;
        }
        let (w, b) = Self::bit(seq);
        self.bits[w] & b == 0
    }

    /// Whether every sequence of `seqs` is new and none repeats in it.
    pub(crate) fn all_fresh(&self, seqs: impl Iterator<Item = u64> + Clone) -> bool {
        let mut prev: Option<u64> = None;
        seqs.clone().all(|s| {
            let ok = self.fresh(s) && prev.is_none_or(|p| s > p);
            prev = Some(s);
            ok
        })
    }

    /// Record `seq` as seen.
    pub(crate) fn mark(&mut self, seq: u64) {
        if seq >= self.top {
            let advance = seq + 1 - self.top;
            if advance >= WINDOW {
                self.bits = [0; (WINDOW / 64) as usize];
            } else {
                for s in self.top..=seq {
                    let (w, b) = Self::bit(s);
                    self.bits[w] &= !b;
                }
            }
            self.top = seq + 1;
        } else if self.top - seq > WINDOW {
            return;
        }
        let (w, b) = Self::bit(seq);
        self.bits[w] |= b;
    }
}

/// A token bucket: `rate` per second, at most `burst` at once.
#[derive(Debug)]
pub(crate) struct Bucket {
    rate: u64,
    burst: u64,
    /// Tokens, in millionths.
    micro: u64,
    at_us: u64,
}

impl Bucket {
    pub(crate) fn new(rate: u64, burst: u64, now_us: u64) -> Self {
        Bucket {
            rate,
            burst,
            micro: burst * 1_000_000,
            at_us: now_us,
        }
    }

    fn refill(&mut self, now_us: u64) {
        let elapsed = now_us.saturating_sub(self.at_us);
        self.at_us = self.at_us.max(now_us);
        self.micro = self
            .micro
            .saturating_add(elapsed.saturating_mul(self.rate))
            .min(self.burst * 1_000_000);
    }

    /// Take `n` tokens, or say how long until they are there.
    pub(crate) fn take(&mut self, n: u64, now_us: u64) -> Result<(), Duration> {
        self.refill(now_us);
        let need = n * 1_000_000;
        if self.micro >= need {
            self.micro -= need;
            return Ok(());
        }
        let short = need - self.micro;
        Err(Duration::from_micros(short.div_ceil(self.rate)))
    }
}

/// The newest sequence delivered per (sender, address) of one scope, at most
/// [`LATEST_MAX`] pairs; the least recently updated goes.
#[derive(Debug, Default)]
pub(crate) struct Latest {
    pairs: HashMap<(Name, Bytes), (u64, u64)>,
    tick: u64,
}

impl Latest {
    /// Take `seq` for `(sender, address)` if it is newer than the newest held:
    /// `false` means stale.
    pub(crate) fn advance(&mut self, sender: &Name, address: &Bytes, seq: u64) -> bool {
        self.tick += 1;
        let tick = self.tick;
        if let Some(held) = self.pairs.get_mut(&(sender.clone(), address.clone())) {
            if seq <= held.0 {
                return false;
            }
            *held = (seq, tick);
            return true;
        }
        if self.pairs.len() >= LATEST_MAX
            && let Some(oldest) = self
                .pairs
                .iter()
                .min_by_key(|(_, (_, t))| *t)
                .map(|(k, _)| k.clone())
        {
            self.pairs.remove(&oldest);
        }
        self.pairs
            .insert((sender.clone(), address.clone()), (seq, tick));
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_replay_window_refuses_a_seen_sequence_and_one_older_than_it() {
        let mut w = ReplayWindow::default();
        assert!(w.fresh(5000));
        w.mark(5000);
        assert!(!w.fresh(5000), "a sequence seen is a replay");
        assert!(w.fresh(4999), "an unseen one in the window is new");
        w.mark(4999);
        assert!(!w.fresh(4999));
        // The window: the WINDOW sequences below one above the highest seen.
        assert!(w.fresh(5001 - WINDOW), "the window's oldest");
        // (4998 - WINDOW shares its slot with 4998, never seen.)
        assert!(!w.fresh(4998 - WINDOW), "older than the window");
        w.mark(5000 + 3 * WINDOW);
        assert!(!w.fresh(5000 + 2 * WINDOW), "far below the new top");
        assert!(
            w.fresh(5001 + 2 * WINDOW + 1),
            "inside the window, never seen"
        );
        assert!(w.fresh(5000 + 3 * WINDOW - 1));
        assert!(!w.all_fresh([5000 + 3 * WINDOW + 1, 5000 + 3 * WINDOW].into_iter()));
        assert!(!w.all_fresh([9, 9].into_iter().map(|s| s + 5000 + 4 * WINDOW)));
        assert!(w.all_fresh((1..4).map(|s| s + 5000 + 3 * WINDOW)));
    }

    #[test]
    fn a_window_advanced_past_a_slot_forgets_its_old_mark() {
        let mut w = ReplayWindow::default();
        w.mark(10);
        w.mark(10 + WINDOW + 5);
        // 10 + WINDOW shares 10's slot, never seen, and is inside the window now.
        assert!(w.fresh(10 + WINDOW), "a forgotten mark refuses nothing");
        assert!(!w.fresh(10), "10 left the window");
        assert!(!w.fresh(10 + WINDOW + 5));
    }

    #[test]
    fn a_bucket_lets_its_burst_then_its_rate() {
        let mut b = Bucket::new(120, 30, 0);
        for _ in 0..30 {
            assert!(b.take(1, 0).is_ok());
        }
        let wait = b.take(1, 0).unwrap_err();
        assert_eq!(wait, Duration::from_micros(8334), "one token per 1/120 s");
        assert!(b.take(1, 8334).is_ok());
        assert!(b.take(1, 8334).is_err());
        assert!(b.take(30, 10_000_000).is_ok(), "never more than the burst");
        assert!(b.take(1, 10_000_000).is_err());
    }

    #[test]
    fn the_latest_table_keeps_the_newest_per_sender_and_address() {
        let mut l = Latest::default();
        let (a, b) = (
            "/alice/laptop/KEY/1".parse::<Name>().unwrap(),
            "/bob/phone/KEY/1".parse::<Name>().unwrap(),
        );
        let cursor = Bytes::from_static(b"cursor");
        assert!(l.advance(&a, &cursor, 10));
        assert!(!l.advance(&a, &cursor, 9), "older for the address: stale");
        assert!(!l.advance(&a, &cursor, 10), "the same: stale");
        assert!(l.advance(&b, &cursor, 1), "another sender's own order");
        assert!(
            l.advance(&a, &Bytes::from_static(b"presence"), 1),
            "another address"
        );
        assert!(l.advance(&a, &cursor, 11));
        for i in 0..LATEST_MAX as u64 {
            l.advance(&b, &Bytes::from(i.to_be_bytes().to_vec()), 1);
        }
        assert_eq!(l.pairs.len(), LATEST_MAX, "bounded");
        assert!(
            l.advance(&a, &cursor, 5),
            "the least recently updated pair went first"
        );
    }
}
