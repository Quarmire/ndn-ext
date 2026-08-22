//! Sans-IO **stream-session state engine** for NDN.
//!
//! The state a live named-data stream needs on each side, with no transport
//! attached:
//!
//! * [`reorder::ReorderBuffer`] — seq-keyed reordering: out-of-order arrivals
//!   deliver in order; duplicates and already-delivered items drop; gaps are
//!   tracked, bounded, and skippable. (The mechanism whose absence causes
//!   arrival-order pairing bugs — a late reply must never shift a stream.)
//! * [`fetch::AdaptiveFetcher`] — which seqs to request and when: RTT-EWMA
//!   window, timeout/nack backoff, retry budgets, frontier-bound catch-up and
//!   predictive (reserve-ahead) live operation.
//! * [`fec`] — K-of-N repair groups delegated to `ndn-coding`'s systematic MDS
//!   codec: any R losses per K-group recover from R parity items — strictly
//!   stronger than fixed XOR/two-parity schemes at equal overhead.
//! * [`SessionConsumer`] / [`SessionProducer`] — the composition, plus the
//!   **session-epoch** discipline: a stream identity is (name, session); a
//!   restarted producer publishes under a fresh session, consumers lock to the
//!   highest session seen and drop stale-session items instead of interleaving
//!   two lives of the stream.
//!
//! Mechanism parity with (not a port of) upstream NDNSF's stream substrate
//! (its specs 057/089/095: the C++ stream state engine the UAV work forced
//! into that framework's core) — rebuilt sans-IO for the ndn-rs stack, with
//! FEC delegated to [`ndn_coding`] instead of bespoke XOR parity. Everything
//! is clock-free (caller-supplied monotonic milliseconds) and deterministic.
//!
//! Binding to a transport (exact-name Interests, SVS, `serve_latest`) is the
//! caller's ~50 lines: publish/fetch by `(stream, session, seq)` names, feed
//! arrivals in, act on [`fetch::FetchAction`]s out.

#![deny(missing_docs)]

pub mod fec;
pub mod fetch;
pub mod reorder;

use bytes::Bytes;

use fec::{FecConfig, GroupDecoder, GroupEncoder, ParityItem};
use fetch::{AdaptiveFetcher, FetchAction, FetcherConfig};
use reorder::{InsertOutcome, ReorderBuffer};

/// Consumer tuning.
#[derive(Clone, Debug)]
pub struct ConsumerConfig {
    /// Fetcher tuning.
    pub fetcher: FetcherConfig,
    /// Max out-of-order span the reorder buffer holds.
    pub reorder_span: u64,
    /// FEC shape, if the stream carries parity.
    pub fec: Option<FecConfig>,
}

impl Default for ConsumerConfig {
    fn default() -> Self {
        Self {
            fetcher: FetcherConfig::default(),
            reorder_span: 1024,
            fec: None,
        }
    }
}

/// Something the consumer surfaced to the application.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StreamEvent {
    /// An in-order item.
    Item {
        /// Its seq.
        seq: u64,
        /// Its payload.
        payload: Bytes,
    },
    /// Seqs the stream gave up on (retry budget exhausted, no FEC recovery) —
    /// delivery continues after the hole, and the loss is explicit.
    Lost {
        /// The abandoned seqs.
        seqs: Vec<u64>,
    },
    /// The stream re-locked onto a newer session (producer restart); all
    /// state from the old session was discarded.
    SessionReset {
        /// The new session epoch.
        session: u64,
    },
}

/// The consumer side of one stream: session lock + reorder + adaptive fetch +
/// FEC recovery, composed.
pub struct SessionConsumer {
    cfg: ConsumerConfig,
    session: Option<u64>,
    reorder: ReorderBuffer,
    fetcher: AdaptiveFetcher,
    fec: Option<GroupDecoder>,
}

impl SessionConsumer {
    /// A consumer that will lock onto the first session it sees, delivering
    /// from that session's `first_seq`.
    pub fn new(first_seq: u64, cfg: ConsumerConfig) -> Self {
        Self {
            session: None,
            reorder: ReorderBuffer::new(first_seq, cfg.reorder_span),
            fetcher: AdaptiveFetcher::new(first_seq, cfg.fetcher.clone()),
            fec: cfg.fec.map(GroupDecoder::new),
            cfg,
        }
    }

    /// The locked session, once one item has been seen.
    pub fn session(&self) -> Option<u64> {
        self.session
    }

    /// The delivery cursor.
    pub fn next_seq(&self) -> u64 {
        self.reorder.next_seq()
    }

    /// Borrow the fetcher (RTT/window/counters observability).
    pub fn fetcher(&self) -> &AdaptiveFetcher {
        &self.fetcher
    }

    /// Session discipline shared by every arrival: `None` = accept (first
    /// session or current), `Some(events)` = handled as stale/reset.
    fn admit_session(&mut self, session: u64) -> Result<(), Vec<StreamEvent>> {
        match self.session {
            None => {
                self.session = Some(session);
                Ok(())
            }
            Some(current) if session == current => Ok(()),
            Some(current) if session < current => Err(Vec::new()), // stale — drop silently
            Some(_) => {
                // A newer session: the producer restarted. Drop everything and
                // re-lock — old-session state must never interleave.
                self.session = Some(session);
                self.reorder = ReorderBuffer::new(0, self.cfg.reorder_span);
                self.fetcher = AdaptiveFetcher::new(0, self.cfg.fetcher.clone());
                self.fec = self.cfg.fec.map(GroupDecoder::new);
                Err(vec![StreamEvent::SessionReset { session }])
            }
        }
    }

    /// Feed a received source item. Returns the events it unlocked (in-order
    /// deliveries, possibly after FEC recovery or a session reset).
    pub fn on_item(
        &mut self,
        now_ms: u64,
        session: u64,
        seq: u64,
        payload: Bytes,
    ) -> Vec<StreamEvent> {
        match self.admit_session(session) {
            Ok(()) => {}
            Err(events) => return events,
        }
        self.fetcher.on_data(now_ms, seq);
        let mut recovered = Vec::new();
        if let Some(fec) = &mut self.fec {
            recovered = fec.add_source(seq, payload.clone());
        }
        self.absorb(seq, payload, recovered)
    }

    /// Feed a received parity item.
    pub fn on_parity(&mut self, session: u64, item: ParityItem) -> Vec<StreamEvent> {
        match self.admit_session(session) {
            Ok(()) => {}
            Err(events) => return events,
        }
        let Some(fec) = &mut self.fec else {
            return Vec::new();
        };
        let recovered = fec.add_parity(item);
        self.deliver_recovered(recovered)
    }

    /// Learn the producer's frontier (e.g. from a latest-pointer fetch).
    pub fn on_frontier(&mut self, session: u64, seq: u64) -> Vec<StreamEvent> {
        match self.admit_session(session) {
            Ok(()) => {}
            Err(events) => return events,
        }
        self.fetcher.on_frontier(seq);
        Vec::new()
    }

    /// A negative signal for `seq` from the transport (nack / app timeout).
    pub fn on_nack(&mut self, seq: u64) {
        self.fetcher.on_nack(seq);
    }

    /// Drive the machine: returns transport actions to perform now. Any
    /// `GiveUp` is resolved internally (cursor skip, `Lost` event) — the
    /// caller only ever has to express the `Fetch`es. Call after every event
    /// and on a timer tick.
    pub fn actions(&mut self, now_ms: u64) -> (Vec<FetchAction>, Vec<StreamEvent>) {
        let mut fetches = Vec::new();
        let mut events = Vec::new();
        for action in self.fetcher.actions(now_ms) {
            match action {
                FetchAction::Fetch { .. } => fetches.push(action),
                FetchAction::GiveUp { seq } => {
                    // Skip the hole: deliver what the skip unblocks, report
                    // the loss explicitly.
                    let lost = self.reorder.skip_to(seq + 1);
                    if !lost.is_empty() {
                        events.push(StreamEvent::Lost { seqs: lost });
                    }
                    for (s, p) in self.reorder.pop_ready() {
                        events.push(StreamEvent::Item { seq: s, payload: p });
                    }
                    self.sync_cursor();
                }
            }
        }
        (fetches, events)
    }

    fn absorb(&mut self, seq: u64, payload: Bytes, recovered: Vec<(u64, Bytes)>) -> Vec<StreamEvent> {
        let mut events = Vec::new();
        match self.reorder.insert(seq, payload) {
            InsertOutcome::Accepted => {}
            InsertOutcome::Duplicate | InsertOutcome::Stale | InsertOutcome::TooFarAhead => {
                // Nothing delivered from this item; recovered items may still land.
            }
        }
        events.extend(self.deliver_recovered(recovered));
        for (s, p) in self.reorder.pop_ready() {
            events.push(StreamEvent::Item { seq: s, payload: p });
        }
        self.sync_cursor();
        events
    }

    fn deliver_recovered(&mut self, recovered: Vec<(u64, Bytes)>) -> Vec<StreamEvent> {
        let mut events = Vec::new();
        for (seq, payload) in recovered {
            self.fetcher.mark_have(seq);
            let _ = self.reorder.insert(seq, payload);
        }
        for (s, p) in self.reorder.pop_ready() {
            events.push(StreamEvent::Item { seq: s, payload: p });
        }
        self.sync_cursor();
        events
    }

    fn sync_cursor(&mut self) {
        let cursor = self.reorder.next_seq();
        self.fetcher.on_cursor(cursor);
        if let Some(fec) = &mut self.fec {
            fec.evict_below(cursor);
        }
    }
}

/// Producer tuning.
#[derive(Clone, Debug)]
pub struct ProducerConfig {
    /// How many recent items stay re-servable (retransmission window).
    pub retention: usize,
    /// FEC shape, if parity should be emitted.
    pub fec: Option<FecConfig>,
}

impl Default for ProducerConfig {
    fn default() -> Self {
        Self {
            retention: 1024,
            fec: None,
        }
    }
}

/// What a publish produced: the item's coordinates plus any parity now due.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Published {
    /// The item's assigned seq.
    pub seq: u64,
    /// Parity items completed by this publish (empty unless a group closed).
    pub parity: Vec<ParityItem>,
}

/// The producer side of one stream session: seq assignment, a bounded
/// retention buffer for re-serving, and per-group parity emission.
pub struct SessionProducer {
    session: u64,
    cfg: ProducerConfig,
    next_seq: u64,
    retained: std::collections::VecDeque<(u64, Bytes)>,
    fec: Option<GroupEncoder>,
}

impl SessionProducer {
    /// A producer for a **fresh** `session` epoch (pick a new value each
    /// producer life — a boot count or timestamp; consumers lock to the
    /// highest they see).
    pub fn new(session: u64, cfg: ProducerConfig) -> Self {
        Self {
            session,
            next_seq: 0,
            retained: std::collections::VecDeque::new(),
            fec: cfg.fec.map(|shape| GroupEncoder::new(0, shape)),
            cfg,
        }
    }

    /// This producer's session epoch.
    pub fn session(&self) -> u64 {
        self.session
    }

    /// The seq the next publish will take.
    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// Publish the next item: assigns its seq, retains it for re-serving, and
    /// returns any parity items its group completion produced.
    pub fn publish(&mut self, payload: Bytes) -> Published {
        let seq = self.next_seq;
        self.next_seq += 1;
        self.retained.push_back((seq, payload.clone()));
        while self.retained.len() > self.cfg.retention.max(1) {
            self.retained.pop_front();
        }
        let parity = match &mut self.fec {
            Some(enc) => enc.push(payload),
            None => Vec::new(),
        };
        Published { seq, parity }
    }

    /// Re-serve a retained item (a consumer's catch-up/retry fetch).
    pub fn retained(&self, seq: u64) -> Option<Bytes> {
        self.retained
            .iter()
            .find(|(s, _)| *s == seq)
            .map(|(_, p)| p.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b(s: &str) -> Bytes {
        Bytes::copy_from_slice(s.as_bytes())
    }

    fn items(events: &[StreamEvent]) -> Vec<u64> {
        events
            .iter()
            .filter_map(|e| match e {
                StreamEvent::Item { seq, .. } => Some(*seq),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn end_to_end_loss_recovered_by_fec_without_refetch() {
        // Producer with 1 parity per 3 items; item 1 is lost in transit; the
        // consumer recovers it from parity — no retransmission round-trip.
        let shape = FecConfig { k: 3, r: 1 };
        let mut producer = SessionProducer::new(
            1,
            ProducerConfig {
                fec: Some(shape),
                ..Default::default()
            },
        );
        let mut consumer = SessionConsumer::new(
            0,
            ConsumerConfig {
                fec: Some(shape),
                ..Default::default()
            },
        );

        let p0 = producer.publish(b("zero"));
        let p1 = producer.publish(b("one"));
        let p2 = producer.publish(b("two"));
        assert_eq!(p2.parity.len(), 1);

        let mut delivered = Vec::new();
        delivered.extend(consumer.on_item(10, 1, p0.seq, b("zero")));
        // p1 lost.
        let _ = p1;
        delivered.extend(consumer.on_item(20, 1, p2.seq, b("two")));
        assert_eq!(items(&delivered), vec![0], "2 waits on the hole at 1");
        delivered.extend(consumer.on_parity(1, p2.parity[0].clone()));
        assert_eq!(items(&delivered), vec![0, 1, 2], "FEC filled the hole");
        assert_eq!(
            consumer.next_seq(),
            3,
            "stream advanced past the recovered item"
        );
    }

    #[test]
    fn session_reset_drops_old_state_and_relocks() {
        let mut consumer = SessionConsumer::new(0, ConsumerConfig::default());
        consumer.on_item(0, 1, 0, b("a"));
        consumer.on_item(1, 1, 5, b("f")); // out-of-order, buffered
        // Producer restarts: session 2 appears.
        let events = consumer.on_item(2, 2, 0, b("A2"));
        assert_eq!(events, vec![StreamEvent::SessionReset { session: 2 }]);
        assert_eq!(consumer.session(), Some(2));
        // The new session's seq 0 delivers cleanly on the next feed.
        let events = consumer.on_item(3, 2, 0, b("A2"));
        assert_eq!(items(&events), vec![0]);
        // Old-session stragglers drop silently.
        assert!(consumer.on_item(4, 1, 6, b("stale")).is_empty());
    }

    #[test]
    fn give_up_skips_the_hole_and_reports_loss() {
        let mut consumer = SessionConsumer::new(
            0,
            ConsumerConfig {
                fetcher: FetcherConfig {
                    initial_window: 4,
                    max_retries: 0,
                    ..Default::default()
                },
                ..Default::default()
            },
        );
        // Request 0..=3; deliver 0, 2, 3; let 1 time out with no retries.
        let (fetches, _) = consumer.actions(0);
        assert_eq!(fetches.len(), 4);
        consumer.on_item(10, 1, 0, b("a"));
        consumer.on_item(11, 1, 2, b("c"));
        consumer.on_item(12, 1, 3, b("d"));
        let (_, events) = consumer.actions(1_000_000);
        assert!(
            events.contains(&StreamEvent::Lost { seqs: vec![1] }),
            "the loss is explicit: {events:?}"
        );
        assert_eq!(items(&events), vec![2, 3], "delivery continues past the hole");
    }

    #[test]
    fn producer_retention_serves_retries_and_stays_bounded() {
        let mut producer = SessionProducer::new(
            1,
            ProducerConfig {
                retention: 2,
                fec: None,
            },
        );
        producer.publish(b("a"));
        producer.publish(b("b"));
        producer.publish(b("c"));
        assert_eq!(producer.retained(0), None, "evicted at the cap");
        assert_eq!(producer.retained(2), Some(b("c")));
    }
}
