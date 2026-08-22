//! Seq-keyed reorder buffer: accept out-of-order stream items, emit them
//! in order, refuse duplicates and already-delivered ("stale") items, track
//! gaps, and stay bounded.
//!
//! This is the mechanism whose absence produces the classic arrival-order
//! pairing bug (a late reply shifts the stream and a hole becomes permanent):
//! items are keyed by their **sequence number**, never by arrival order.

use std::collections::BTreeMap;

use bytes::Bytes;

/// What happened to an inserted item.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InsertOutcome {
    /// Buffered (or immediately deliverable).
    Accepted,
    /// Already buffered at this seq — dropped.
    Duplicate,
    /// Below the delivery cursor — already delivered (or skipped) — dropped.
    Stale,
    /// Too far ahead of the delivery cursor (beyond the buffer's span cap) —
    /// refused so one runaway seq cannot pin unbounded state.
    TooFarAhead,
}

/// A bounded, seq-keyed reorder buffer.
///
/// `next` is the delivery cursor: the lowest seq not yet delivered. Items at
/// or above `next` (within `max_span`) buffer; [`pop_ready`](Self::pop_ready)
/// drains the contiguous run at `next`. A gap the caller has given up on is
/// skipped with [`skip_to`](Self::skip_to) (the adaptive fetcher decides when
/// — this buffer never drops data on its own).
#[derive(Debug)]
pub struct ReorderBuffer {
    next: u64,
    buffered: BTreeMap<u64, Bytes>,
    max_span: u64,
}

impl ReorderBuffer {
    /// A buffer delivering from `first_seq`, holding at most a `max_span`-wide
    /// window of out-of-order items (`seq < next + max_span`).
    pub fn new(first_seq: u64, max_span: u64) -> Self {
        Self {
            next: first_seq,
            buffered: BTreeMap::new(),
            max_span: max_span.max(1),
        }
    }

    /// The delivery cursor: the lowest seq not yet delivered/skipped.
    pub fn next_seq(&self) -> u64 {
        self.next
    }

    /// Number of buffered (undelivered, out-of-order) items.
    pub fn buffered_len(&self) -> usize {
        self.buffered.len()
    }

    /// Offer an item at `seq`.
    pub fn insert(&mut self, seq: u64, item: Bytes) -> InsertOutcome {
        if seq < self.next {
            return InsertOutcome::Stale;
        }
        if seq >= self.next.saturating_add(self.max_span) {
            return InsertOutcome::TooFarAhead;
        }
        if self.buffered.contains_key(&seq) {
            return InsertOutcome::Duplicate;
        }
        self.buffered.insert(seq, item);
        InsertOutcome::Accepted
    }

    /// Whether `seq` is already buffered or delivered.
    pub fn has(&self, seq: u64) -> bool {
        seq < self.next || self.buffered.contains_key(&seq)
    }

    /// Drain the contiguous in-order run at the cursor.
    pub fn pop_ready(&mut self) -> Vec<(u64, Bytes)> {
        let mut out = Vec::new();
        while let Some(item) = self.buffered.remove(&self.next) {
            out.push((self.next, item));
            self.next += 1;
        }
        out
    }

    /// The missing seqs (holes) between the cursor and the highest buffered
    /// item — what a fetcher should chase.
    pub fn missing(&self) -> Vec<u64> {
        let Some((&hi, _)) = self.buffered.iter().next_back() else {
            return Vec::new();
        };
        (self.next..hi)
            .filter(|s| !self.buffered.contains_key(s))
            .collect()
    }

    /// Give up on everything below `seq`: advance the cursor, dropping any
    /// buffered items below it. Returns the seqs skipped over that were never
    /// delivered (the acknowledged loss). No-op if `seq` is behind the cursor.
    pub fn skip_to(&mut self, seq: u64) -> Vec<u64> {
        if seq <= self.next {
            return Vec::new();
        }
        let lost: Vec<u64> = (self.next..seq)
            .filter(|s| !self.buffered.contains_key(s))
            .collect();
        self.buffered.retain(|&s, _| s >= seq);
        self.next = seq;
        lost
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b(s: &str) -> Bytes {
        Bytes::copy_from_slice(s.as_bytes())
    }

    #[test]
    fn out_of_order_arrival_delivers_in_order() {
        // The NS-6 shape: replies arrive 0, 2, 1 — delivery must be 0, 1, 2
        // with no permanent hole.
        let mut r = ReorderBuffer::new(0, 64);
        assert_eq!(r.insert(0, b("a")), InsertOutcome::Accepted);
        assert_eq!(r.insert(2, b("c")), InsertOutcome::Accepted);
        assert_eq!(
            r.pop_ready().iter().map(|(s, _)| *s).collect::<Vec<_>>(),
            vec![0],
            "2 must NOT deliver while 1 is missing"
        );
        assert_eq!(r.missing(), vec![1]);
        assert_eq!(r.insert(1, b("b")), InsertOutcome::Accepted);
        let ready = r.pop_ready();
        assert_eq!(
            ready.iter().map(|(s, _)| *s).collect::<Vec<_>>(),
            vec![1, 2]
        );
        assert_eq!(ready[0].1, b("b"));
    }

    #[test]
    fn duplicates_and_stale_are_refused() {
        let mut r = ReorderBuffer::new(0, 64);
        r.insert(0, b("a"));
        assert_eq!(r.insert(0, b("a2")), InsertOutcome::Duplicate);
        r.pop_ready();
        // Delivered seq re-offered (a late duplicate reply): stale, dropped.
        assert_eq!(r.insert(0, b("a3")), InsertOutcome::Stale);
    }

    #[test]
    fn span_cap_bounds_the_buffer() {
        let mut r = ReorderBuffer::new(0, 8);
        assert_eq!(r.insert(7, b("x")), InsertOutcome::Accepted);
        assert_eq!(r.insert(8, b("y")), InsertOutcome::TooFarAhead);
        assert_eq!(r.buffered_len(), 1);
    }

    #[test]
    fn skip_to_acknowledges_loss_and_unblocks() {
        let mut r = ReorderBuffer::new(0, 64);
        r.insert(0, b("a"));
        r.insert(3, b("d"));
        r.pop_ready();
        // Fetcher gave up on 1 and 2.
        assert_eq!(r.skip_to(3), vec![1, 2]);
        assert_eq!(
            r.pop_ready().iter().map(|(s, _)| *s).collect::<Vec<_>>(),
            vec![3]
        );
        // A very late 1 is now stale, not a corruption vector.
        assert_eq!(r.insert(1, b("b")), InsertOutcome::Stale);
    }

    #[test]
    fn skip_preserves_buffered_at_and_after_target() {
        let mut r = ReorderBuffer::new(0, 64);
        r.insert(2, b("c"));
        r.insert(5, b("f"));
        assert_eq!(r.skip_to(2), vec![0, 1]);
        assert_eq!(
            r.pop_ready().iter().map(|(s, _)| *s).collect::<Vec<_>>(),
            vec![2]
        );
        assert_eq!(r.missing(), vec![3, 4]);
    }
}
