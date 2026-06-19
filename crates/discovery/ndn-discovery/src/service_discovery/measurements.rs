//! Per-provider RTT and retransmit stats. Bounded LRU keyed by
//! `(announced_prefix, node_name)`; stale entries drop on read,
//! capacity overflow drops the least-recently-touched entry on insert.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use ndn_packet::Name;

const RING_SIZE: usize = 32;

pub struct ProviderMeasurement {
    pub node_name: Name,
    pub last_rtt: Option<Duration>,
    pub rtt_p50: Option<Duration>,
    pub retransmits: u32,
    pub timeouts: u32,
}

struct ProviderStats {
    rtts: VecDeque<Duration>,
    retransmits: u32,
    timeouts: u32,
    last_seen: Instant,
}

impl ProviderStats {
    fn new(now: Instant) -> Self {
        Self {
            rtts: VecDeque::with_capacity(RING_SIZE),
            retransmits: 0,
            timeouts: 0,
            last_seen: now,
        }
    }

    fn push_rtt(&mut self, rtt: Duration, now: Instant) {
        if self.rtts.len() == RING_SIZE {
            self.rtts.pop_front();
        }
        self.rtts.push_back(rtt);
        self.last_seen = now;
    }

    fn last_rtt(&self) -> Option<Duration> {
        self.rtts.back().copied()
    }

    fn p50(&self) -> Option<Duration> {
        if self.rtts.is_empty() {
            return None;
        }
        let mut sorted: Vec<Duration> = self.rtts.iter().copied().collect();
        sorted.sort_unstable();
        Some(sorted[sorted.len() / 2])
    }
}

type Key = (String, String);

pub(crate) struct MeasurementStore {
    capacity: usize,
    idle_ttl: Duration,
    entries: HashMap<Key, (Name, ProviderStats)>,
}

impl MeasurementStore {
    pub fn new(capacity: usize, idle_ttl: Duration) -> Self {
        Self {
            capacity,
            idle_ttl,
            entries: HashMap::new(),
        }
    }

    fn key(announced_prefix: &Name, node_name: &Name) -> Key {
        (announced_prefix.to_string(), node_name.to_string())
    }

    fn touch_or_insert(
        &mut self,
        announced_prefix: &Name,
        node_name: &Name,
        now: Instant,
    ) -> &mut ProviderStats {
        let k = Self::key(announced_prefix, node_name);
        if !self.entries.contains_key(&k) {
            if self.entries.len() >= self.capacity {
                self.evict_lru(now);
            }
            self.entries
                .insert(k.clone(), (node_name.clone(), ProviderStats::new(now)));
        }
        &mut self.entries.get_mut(&k).unwrap().1
    }

    fn evict_lru(&mut self, _now: Instant) {
        if self.entries.is_empty() {
            return;
        }
        let victim = self
            .entries
            .iter()
            .min_by_key(|(_, (_, s))| s.last_seen)
            .map(|(k, _)| k.clone());
        if let Some(k) = victim {
            self.entries.remove(&k);
        }
    }

    fn evict_stale(&mut self, now: Instant) {
        self.entries
            .retain(|_, (_, s)| now.duration_since(s.last_seen) < self.idle_ttl);
    }

    pub fn record_rtt(
        &mut self,
        announced_prefix: &Name,
        node_name: &Name,
        rtt: Duration,
        now: Instant,
    ) {
        self.touch_or_insert(announced_prefix, node_name, now)
            .push_rtt(rtt, now);
    }

    pub fn record_timeout(&mut self, announced_prefix: &Name, node_name: &Name, now: Instant) {
        let stats = self.touch_or_insert(announced_prefix, node_name, now);
        stats.timeouts = stats.timeouts.saturating_add(1);
        stats.last_seen = now;
    }

    /// Evicts stale entries first.
    pub fn measurements(
        &mut self,
        announced_prefix: &Name,
        now: Instant,
    ) -> Vec<ProviderMeasurement> {
        self.evict_stale(now);
        let prefix_key = announced_prefix.to_string();
        let mut out: Vec<ProviderMeasurement> = self
            .entries
            .iter()
            .filter(|((p, _), _)| p == &prefix_key)
            .map(|(_, (node_name, stats))| ProviderMeasurement {
                node_name: node_name.clone(),
                last_rtt: stats.last_rtt(),
                rtt_p50: stats.p50(),
                retransmits: stats.retransmits,
                timeouts: stats.timeouts,
            })
            .collect();
        out.sort_by_key(|a| a.node_name.to_string());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn n(s: &str) -> Name {
        Name::from_str(s).unwrap()
    }

    #[test]
    fn record_and_retrieve() {
        let now = Instant::now();
        let mut store = MeasurementStore::new(256, Duration::from_secs(600));
        let prefix = n("/ndn/svc/alpha");
        let node_a = n("/ndn/site/node-a");
        let node_b = n("/ndn/site/node-b");

        store.record_rtt(&prefix, &node_a, Duration::from_millis(10), now);
        store.record_rtt(&prefix, &node_a, Duration::from_millis(20), now);
        store.record_rtt(&prefix, &node_b, Duration::from_millis(50), now);

        let ms = store.measurements(&prefix, now);
        assert_eq!(ms.len(), 2);
        assert_eq!(ms[0].node_name, node_a);
        assert_eq!(ms[1].node_name, node_b);
        assert_eq!(ms[0].rtt_p50, Some(Duration::from_millis(20)));
        assert_eq!(ms[0].last_rtt, Some(Duration::from_millis(20)));
    }

    #[test]
    fn eviction_at_capacity() {
        let now = Instant::now();
        let capacity = 4;
        let mut store = MeasurementStore::new(capacity, Duration::from_secs(600));
        let prefix = n("/ndn/svc/beta");

        for i in 0..=capacity {
            let node = n(&format!("/ndn/node/{i}"));
            store.record_rtt(&prefix, &node, Duration::from_millis(i as u64 * 10), now);
        }

        let ms = store.measurements(&prefix, now);
        assert_eq!(ms.len(), capacity, "LRU victim should have been evicted");
    }

    #[test]
    fn stale_entries_evicted_on_read() {
        let now = Instant::now();
        let ttl = Duration::from_secs(1);
        let mut store = MeasurementStore::new(256, ttl);
        let prefix = n("/ndn/svc/gamma");
        let node = n("/ndn/site/node-x");

        store.record_rtt(&prefix, &node, Duration::from_millis(5), now);

        let future = now + ttl + Duration::from_millis(1);
        let ms = store.measurements(&prefix, future);
        assert!(ms.is_empty(), "stale entry should be evicted");
    }

    #[test]
    fn p50_over_window() {
        let now = Instant::now();
        let mut store = MeasurementStore::new(256, Duration::from_secs(600));
        let prefix = n("/ndn/svc/delta");
        let node = n("/ndn/site/node-y");

        for ms in 1u64..=5 {
            store.record_rtt(&prefix, &node, Duration::from_millis(ms), now);
        }

        let ms = store.measurements(&prefix, now);
        assert_eq!(ms[0].rtt_p50, Some(Duration::from_millis(3)));
    }
}
