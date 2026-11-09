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
    /// 2^64 − 1, which the wire refuses (no sequence one above it), never is.
    pub(crate) fn fresh(&self, seq: u64) -> bool {
        if seq == u64::MAX {
            return false;
        }
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

    /// Record `seq` as seen; 2^64 − 1 (never fresh) is not recorded.
    pub(crate) fn mark(&mut self, seq: u64) {
        let Some(above) = seq.checked_add(1) else {
            return;
        };
        if seq >= self.top {
            if above - self.top >= WINDOW {
                self.bits = [0; (WINDOW / 64) as usize];
            } else {
                for s in self.top..=seq {
                    let (w, b) = Self::bit(s);
                    self.bits[w] &= !b;
                }
            }
            self.top = above;
        } else if self.top - seq > WINDOW {
            return;
        }
        let (w, b) = Self::bit(seq);
        self.bits[w] |= b;
    }
}

/// A token bucket: `rate` per second, at most `burst` at once. A take over the
/// burst (one send into more groups than the burst) is let from a full bucket
/// and leaves it in debt, so the average stays at `rate`.
#[derive(Debug)]
pub(crate) struct Bucket {
    rate: u64,
    burst: u64,
    /// Tokens, in millionths; below zero after a take over the burst.
    micro: i128,
    at_us: u64,
}

impl Bucket {
    /// A full bucket. A rate of 0 is taken as 1, so a wait is always finite.
    pub(crate) fn new(rate: u64, burst: u64, now_us: u64) -> Self {
        Bucket {
            rate: rate.max(1),
            burst,
            micro: Self::micro(burst),
            at_us: now_us,
        }
    }

    fn micro(n: u64) -> i128 {
        i128::from(n) * 1_000_000
    }

    fn refill(&mut self, now_us: u64) {
        let elapsed = now_us.saturating_sub(self.at_us);
        self.at_us = self.at_us.max(now_us);
        self.micro = self
            .micro
            .saturating_add(i128::from(elapsed).saturating_mul(i128::from(self.rate)))
            .min(Self::micro(self.burst));
    }

    /// Whether `n` tokens are there now (a full bucket for more than the burst),
    /// or how long until they are.
    pub(crate) fn ready(&mut self, n: u64, now_us: u64) -> Result<(), Duration> {
        self.refill(now_us);
        let need = Self::micro(n.min(self.burst));
        if self.micro >= need {
            return Ok(());
        }
        let short = u64::try_from(need - self.micro).unwrap_or(u64::MAX);
        Err(Duration::from_micros(short.div_ceil(self.rate)))
    }

    /// Spend `n` tokens [`ready`](Self::ready) said are there.
    pub(crate) fn spend(&mut self, n: u64) {
        self.micro = self.micro.saturating_sub(Self::micro(n));
    }

    /// Take `n` tokens, or say how long until they are there.
    pub(crate) fn take(&mut self, n: u64, now_us: u64) -> Result<(), Duration> {
        self.ready(n, now_us)?;
        self.spend(n);
        Ok(())
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
        self.tick = self.tick.saturating_add(1);
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

    /// L1: at the top of the sequence space the window neither panics nor wraps
    /// (a wrapped top would take every sequence as new again).
    #[test]
    fn the_window_at_the_last_sequence_neither_panics_nor_wraps() {
        let mut w = ReplayWindow::default();
        w.mark(u64::MAX - 1);
        assert!(!w.fresh(u64::MAX - 1), "the last sequence, seen");
        assert!(w.fresh(u64::MAX - 2), "below it, in the window, unseen");
        assert!(!w.fresh(0), "far below the window: the top did not wrap");
        // One past the last sequence the wire refuses; the window takes it as
        // nothing, not as new.
        w.mark(u64::MAX);
        assert!(!w.fresh(u64::MAX));
        assert!(!w.fresh(u64::MAX - 1));
        assert!(!w.fresh(0));
        let mut empty = ReplayWindow::default();
        empty.mark(u64::MAX);
        assert!(!empty.fresh(u64::MAX), "never new");
        assert!(empty.fresh(5), "and it marked nothing");
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

    /// One take over the burst (a packet into more groups than the push burst)
    /// is let only from a full bucket, and its debt is paid at the rate before
    /// anything more is let: the average stays at the rate.
    #[test]
    fn a_take_over_the_burst_is_let_from_a_full_bucket_and_paid_at_the_rate() {
        let mut b = Bucket::new(80, 160, 0);
        assert!(b.take(1, 0).is_ok());
        assert_eq!(
            b.take(400, 0),
            Err(Duration::from_micros(12_500)),
            "not from a bucket short of full"
        );
        assert!(b.take(400, 12_500).is_ok(), "from a full bucket");
        // 240 owed, and 1 more to take: (240 + 1) / 80 s.
        assert_eq!(b.take(1, 12_500), Err(Duration::from_micros(3_012_500)));
        assert!(b.take(1, 12_500 + 3_012_500).is_ok());
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
