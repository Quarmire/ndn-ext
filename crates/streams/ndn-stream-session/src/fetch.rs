//! Adaptive windowed fetcher: decides **which seqs to request and when**,
//! from RTT/timeout/nack signals — sans-IO and clock-free (the caller supplies
//! monotonic milliseconds and performs the actual Interests).
//!
//! The window grows additively on success and halves on loss; the retransmit
//! timeout is an EWMA-smoothed RTT times a multiplier; a seq that exhausts its
//! retry budget becomes a [`FetchAction::GiveUp`] — the caller then skips the
//! reorder cursor past it (or lets a FEC repair group recover it).
//!
//! Two operating shapes, one machine:
//! * **frontier-bound** — a known producer frontier caps requests (catch-up /
//!   history fetch);
//! * **predictive** — no frontier yet (live streaming): keep the window's
//!   worth of future seqs outstanding ahead of the delivery cursor, bounded by
//!   `lookahead` (the reserve-ahead pattern upstream's predictive subscriber
//!   uses).

use std::collections::BTreeMap;

/// Tuning for [`AdaptiveFetcher`].
#[derive(Clone, Debug)]
pub struct FetcherConfig {
    /// Starting window (max outstanding fetches).
    pub initial_window: usize,
    /// Ceiling for the window.
    pub max_window: usize,
    /// RTT seed before any sample, in ms.
    pub initial_rtt_ms: u64,
    /// EWMA weight of a new RTT sample, in percent (upstream uses α=0.25).
    pub rtt_alpha_percent: u8,
    /// Retransmit timeout = smoothed RTT × this.
    pub timeout_multiplier: u32,
    /// Retries per seq before giving up.
    pub max_retries: u32,
    /// How far past the delivery cursor to pre-request (predictive bound).
    pub lookahead: u64,
}

impl Default for FetcherConfig {
    fn default() -> Self {
        Self {
            initial_window: 4,
            max_window: 64,
            initial_rtt_ms: 200,
            rtt_alpha_percent: 25,
            timeout_multiplier: 4,
            max_retries: 3,
            lookahead: 256,
        }
    }
}

/// What the caller should do next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FetchAction {
    /// Express (or re-express) an Interest for this seq.
    Fetch {
        /// The seq to request.
        seq: u64,
        /// True if this is a retransmission.
        retry: bool,
    },
    /// The retry budget for this seq is exhausted; the fetcher has dropped it.
    /// Skip the reorder cursor past it or recover it via FEC.
    GiveUp {
        /// The abandoned seq.
        seq: u64,
    },
}

#[derive(Debug)]
struct Outstanding {
    sent_at_ms: u64,
    retries: u32,
}

/// Fetch-progress counters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FetchCounters {
    /// Interests the machine asked the caller to send (incl. retries).
    pub requested: u64,
    /// Retransmissions among those.
    pub retries: u64,
    /// Seqs satisfied by data.
    pub satisfied: u64,
    /// Seqs abandoned after the retry budget.
    pub gave_up: u64,
}

/// The adaptive fetch state machine.
#[derive(Debug)]
pub struct AdaptiveFetcher {
    cfg: FetcherConfig,
    srtt_ms: u64,
    window: usize,
    /// Next seq never yet requested.
    next_to_request: u64,
    /// Delivery cursor (from the reorder buffer) — bounds the lookahead.
    cursor: u64,
    /// Highest seq known to exist, if any (None ⇒ predictive).
    frontier: Option<u64>,
    outstanding: BTreeMap<u64, Outstanding>,
    counters: FetchCounters,
}

impl AdaptiveFetcher {
    /// A fetcher starting at `first_seq`.
    pub fn new(first_seq: u64, cfg: FetcherConfig) -> Self {
        Self {
            srtt_ms: cfg.initial_rtt_ms.max(1),
            window: cfg.initial_window.max(1),
            next_to_request: first_seq,
            cursor: first_seq,
            frontier: None,
            outstanding: BTreeMap::new(),
            cfg,
            counters: FetchCounters::default(),
        }
    }

    /// Current smoothed RTT estimate (ms).
    pub fn srtt_ms(&self) -> u64 {
        self.srtt_ms
    }

    /// Current window (max outstanding).
    pub fn window(&self) -> usize {
        self.window
    }

    /// Progress counters.
    pub fn counters(&self) -> FetchCounters {
        self.counters
    }

    /// Outstanding request count.
    pub fn outstanding_len(&self) -> usize {
        self.outstanding.len()
    }

    fn rto_ms(&self) -> u64 {
        self.srtt_ms
            .saturating_mul(u64::from(self.cfg.timeout_multiplier))
            .max(1)
    }

    /// Learn the producer's frontier (highest existing seq). Monotonic.
    pub fn on_frontier(&mut self, seq: u64) {
        self.frontier = Some(self.frontier.map_or(seq, |f| f.max(seq)));
    }

    /// Track the reorder buffer's delivery cursor (bounds the lookahead).
    pub fn on_cursor(&mut self, seq: u64) {
        self.cursor = self.cursor.max(seq);
        // Never re-request what the stream has moved past (skip_to case).
        self.next_to_request = self.next_to_request.max(seq);
        self.outstanding.retain(|&s, _| s >= seq);
    }

    /// Data for `seq` arrived. Feeds the RTT estimate (first-transmission
    /// samples only — Karn's rule) and grows the window additively.
    pub fn on_data(&mut self, now_ms: u64, seq: u64) {
        if let Some(out) = self.outstanding.remove(&seq) {
            self.counters.satisfied += 1;
            if out.retries == 0 {
                let sample = now_ms.saturating_sub(out.sent_at_ms).max(1);
                let a = u64::from(self.cfg.rtt_alpha_percent.min(100));
                self.srtt_ms = ((100 - a) * self.srtt_ms + a * sample) / 100;
                self.srtt_ms = self.srtt_ms.max(1);
            }
            self.window = (self.window + 1).min(self.cfg.max_window);
        }
    }

    /// `seq` was satisfied by another path (e.g. FEC recovery) — stop chasing
    /// it without taking an RTT sample or growing the window.
    pub fn mark_have(&mut self, seq: u64) {
        if self.outstanding.remove(&seq).is_some() {
            self.counters.satisfied += 1;
        }
    }

    /// An explicit negative signal (nack/timeout notification from the
    /// transport) for `seq`: halves the window; the seq re-fires from
    /// [`actions`](Self::actions) as an immediate retry (or gives up).
    pub fn on_nack(&mut self, seq: u64) {
        if let Some(out) = self.outstanding.get_mut(&seq) {
            out.sent_at_ms = 0; // due immediately at the next actions() pass
            self.window = (self.window / 2).max(1);
        }
    }

    /// Drive the machine: expire overdue requests (retry or give up) and fill
    /// the window. Call after every event and periodically (e.g. each tick of
    /// the caller's loop).
    pub fn actions(&mut self, now_ms: u64) -> Vec<FetchAction> {
        let mut out = Vec::new();
        let rto = self.rto_ms();

        // Overdue outstanding: retry within budget, else give up.
        let overdue: Vec<u64> = self
            .outstanding
            .iter()
            .filter(|(_, o)| now_ms.saturating_sub(o.sent_at_ms) >= rto)
            .map(|(&s, _)| s)
            .collect();
        for seq in overdue {
            let o = self.outstanding.get_mut(&seq).expect("collected above");
            if o.retries >= self.cfg.max_retries {
                self.outstanding.remove(&seq);
                self.counters.gave_up += 1;
                self.window = (self.window / 2).max(1);
                tracing::debug!(seq, "fetch retry budget exhausted — giving up");
                out.push(FetchAction::GiveUp { seq });
            } else {
                o.retries += 1;
                o.sent_at_ms = now_ms;
                self.counters.requested += 1;
                self.counters.retries += 1;
                self.window = (self.window / 2).max(1);
                out.push(FetchAction::Fetch { seq, retry: true });
            }
        }

        // Fill the window up to the frontier (or the predictive lookahead).
        let lookahead_limit = self.cursor.saturating_add(self.cfg.lookahead);
        let limit = match self.frontier {
            Some(f) => f.min(lookahead_limit),
            None => lookahead_limit,
        };
        while self.outstanding.len() < self.window && self.next_to_request <= limit {
            let seq = self.next_to_request;
            self.next_to_request += 1;
            self.outstanding.insert(
                seq,
                Outstanding {
                    sent_at_ms: now_ms,
                    retries: 0,
                },
            );
            self.counters.requested += 1;
            out.push(FetchAction::Fetch { seq, retry: false });
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fetcher() -> AdaptiveFetcher {
        AdaptiveFetcher::new(0, FetcherConfig::default())
    }

    fn seqs(actions: &[FetchAction]) -> Vec<u64> {
        actions
            .iter()
            .filter_map(|a| match a {
                FetchAction::Fetch { seq, .. } => Some(*seq),
                FetchAction::GiveUp { .. } => None,
            })
            .collect()
    }

    #[test]
    fn fills_the_window_up_to_the_frontier() {
        let mut f = fetcher();
        f.on_frontier(1);
        // Window is 4 but only seqs 0..=1 exist.
        assert_eq!(seqs(&f.actions(0)), vec![0, 1]);
        assert_eq!(f.actions(1), vec![], "nothing new to request");
    }

    #[test]
    fn predictive_mode_keeps_the_window_outstanding() {
        // No frontier: live/predictive — reserve-ahead the window's worth.
        let mut f = fetcher();
        assert_eq!(seqs(&f.actions(0)), vec![0, 1, 2, 3]);
        f.on_data(50, 0);
        f.on_cursor(1);
        // One slot freed + window grew: two new requests.
        assert_eq!(seqs(&f.actions(51)), vec![4, 5]);
    }

    #[test]
    fn window_grows_on_success_and_halves_on_loss() {
        let mut f = fetcher();
        f.actions(0);
        assert_eq!(f.window(), 4);
        f.on_data(10, 0);
        assert_eq!(f.window(), 5);
        f.on_nack(1);
        f.actions(11);
        assert_eq!(f.window(), 2, "halved by the nack retry");
    }

    #[test]
    fn rtt_ewma_updates_only_on_first_transmission_samples() {
        let mut f = fetcher();
        f.actions(0);
        f.on_data(100, 0); // sample = 100
        // srtt = 0.75*200 + 0.25*100 = 175
        assert_eq!(f.srtt_ms(), 175);
        // Time out seq 1 (rto = 175*4 = 700), then answer the retry — no sample.
        let acts = f.actions(701);
        assert!(acts.contains(&FetchAction::Fetch { seq: 1, retry: true }));
        let before = f.srtt_ms();
        f.on_data(5000, 1);
        assert_eq!(f.srtt_ms(), before, "Karn's rule: retried seq takes no sample");
    }

    #[test]
    fn retry_budget_exhausts_into_give_up() {
        let mut f = AdaptiveFetcher::new(
            0,
            FetcherConfig {
                initial_window: 1,
                max_retries: 2,
                ..Default::default()
            },
        );
        f.on_frontier(0);
        let mut gave_up = false;
        let mut t = 0;
        for _ in 0..8 {
            t += 10_000; // far past any rto
            for a in f.actions(t) {
                if a == (FetchAction::GiveUp { seq: 0 }) {
                    gave_up = true;
                }
            }
        }
        assert!(gave_up, "seq 0 must eventually be abandoned");
        assert_eq!(f.counters().gave_up, 1);
        assert_eq!(f.outstanding_len(), 0);
    }

    #[test]
    fn cursor_advance_cancels_overtaken_requests() {
        let mut f = fetcher();
        f.actions(0); // 0..=3 outstanding
        // The reorder buffer skipped to 3 (gap acknowledged elsewhere).
        f.on_cursor(3);
        assert_eq!(f.outstanding_len(), 1, "only seq 3 still relevant");
        // A very late GiveUp for 0..2 never fires; nothing re-requests them.
        assert!(seqs(&f.actions(1)).iter().all(|&s| s > 3));
    }

    #[test]
    fn mark_have_stops_chasing_without_rtt_pollution() {
        let mut f = fetcher();
        f.actions(0);
        let srtt = f.srtt_ms();
        f.mark_have(2); // FEC recovered it
        assert_eq!(f.srtt_ms(), srtt);
        assert_eq!(f.outstanding_len(), 3);
        assert_eq!(f.counters().satisfied, 1);
    }

    #[test]
    fn lookahead_bounds_predictive_reach() {
        let mut f = AdaptiveFetcher::new(
            0,
            FetcherConfig {
                initial_window: 16,
                lookahead: 4,
                ..Default::default()
            },
        );
        // Cursor at 0: predictive reach is 0..=4 even though the window is 16.
        assert_eq!(seqs(&f.actions(0)), vec![0, 1, 2, 3, 4]);
    }
}
