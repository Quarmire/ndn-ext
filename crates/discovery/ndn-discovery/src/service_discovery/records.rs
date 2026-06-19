//! Local record storage, publication, lifecycle.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ndn_packet::Name;
use ndn_transport::FaceId;
use tracing::{debug, info};

use bytes::Bytes;

use crate::prefix_announce::ServiceRecord;

use super::ServiceDiscoveryProtocol;

pub(crate) struct RecordEntry {
    pub(super) record: ServiceRecord,
    pub(super) published_at_ms: u64,
    pub(super) expires_at: Option<Instant>,
    /// When set, the record is auto-withdrawn on `face-down`.
    pub(super) owner_face: Option<FaceId>,
}

pub(crate) struct ProducerRateLimit {
    pub(super) count: u32,
    pub(super) window_start: Instant,
}

impl ServiceDiscoveryProtocol {
    pub fn publish(&self, mut record: ServiceRecord) {
        let ts = current_timestamp_ms();
        record.version = ts;
        let mut records = self.local_records.lock().unwrap();
        let existing = records.iter().position(|e| {
            e.record.announced_prefix == record.announced_prefix
                && e.record.node_name == record.node_name
        });
        info!(
            prefix = %record.announced_prefix,
            node   = %record.node_name,
            freshness_ms = record.freshness_ms,
            "service record published",
        );
        let entry = RecordEntry {
            record,
            published_at_ms: ts,
            expires_at: None,
            owner_face: None,
        };
        if let Some(idx) = existing {
            records[idx] = entry;
        } else {
            records.push(entry);
        }
    }

    pub fn publish_with_ttl(&self, mut record: ServiceRecord, ttl_ms: u64) {
        let ts = current_timestamp_ms();
        record.version = ts;
        let expires_at = Instant::now() + Duration::from_millis(ttl_ms);
        let mut records = self.local_records.lock().unwrap();
        let existing = records.iter().position(|e| {
            e.record.announced_prefix == record.announced_prefix
                && e.record.node_name == record.node_name
        });
        info!(
            prefix       = %record.announced_prefix,
            node         = %record.node_name,
            freshness_ms = record.freshness_ms,
            ttl_ms,
            "service record published (TTL)",
        );
        let entry = RecordEntry {
            record,
            published_at_ms: ts,
            expires_at: Some(expires_at),
            owner_face: None,
        };
        if let Some(idx) = existing {
            records[idx] = entry;
        } else {
            records.push(entry);
        }
    }

    /// Publish a rendezvous record and stash its body bytes. The body
    /// is wrapped via [`ServiceDiscoveryConfig::encryption_hook`] and
    /// served when a `<root>/service-info/...` Interest arrives.
    pub fn publish_with_body(&self, mut record: ServiceRecord, body_bytes: Bytes) {
        let ts = current_timestamp_ms();
        record.version = ts;
        let wrapped = match self.config.encryption_hook.wrap(&body_bytes, &record) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(error=%e, "publish_with_body: encryption failed, body dropped");
                return;
            }
        };
        let hash_hex = prefix_hash_hex(&record.announced_prefix);
        let key = (hash_hex, record.node_name.to_string());
        self.insert_body(key, wrapped);
        let mut records = self.local_records.lock().unwrap();
        let existing = records.iter().position(|e| {
            e.record.announced_prefix == record.announced_prefix
                && e.record.node_name == record.node_name
        });
        info!(
            prefix = %record.announced_prefix,
            node   = %record.node_name,
            "service record published with body",
        );
        let entry = RecordEntry {
            record,
            published_at_ms: ts,
            expires_at: None,
            owner_face: None,
        };
        if let Some(idx) = existing {
            records[idx] = entry;
        } else {
            records.push(entry);
        }
    }

    pub fn publish_with_owner(&self, mut record: ServiceRecord, owner_face: FaceId) {
        let ts = current_timestamp_ms();
        record.version = ts;
        let mut records = self.local_records.lock().unwrap();
        let existing = records.iter().position(|e| {
            e.record.announced_prefix == record.announced_prefix
                && e.record.node_name == record.node_name
        });
        info!(
            prefix       = %record.announced_prefix,
            node         = %record.node_name,
            freshness_ms = record.freshness_ms,
            owner_face   = ?owner_face,
            "service record published (owned by face)",
        );
        let entry = RecordEntry {
            record,
            published_at_ms: ts,
            expires_at: None,
            owner_face: Some(owner_face),
        };
        if let Some(idx) = existing {
            records[idx] = entry;
        } else {
            records.push(entry);
        }
    }

    pub fn withdraw(&self, announced_prefix: &Name) {
        let mut records = self.local_records.lock().unwrap();
        let before = records.len();
        records.retain(|e| &e.record.announced_prefix != announced_prefix);
        if records.len() < before {
            info!(prefix = %announced_prefix, "service record withdrawn");
        } else {
            debug!(prefix = %announced_prefix, "service record withdraw: prefix not found (no-op)");
        }
    }

    pub fn local_records(&self) -> Vec<ServiceRecord> {
        self.local_records
            .lock()
            .unwrap()
            .iter()
            .map(|e| e.record.clone())
            .collect()
    }

    /// Local records take precedence over peers on collision.
    pub fn all_records(&self) -> Vec<ServiceRecord> {
        let local = self.local_records.lock().unwrap();
        let peers = self.peer_records.lock().unwrap();

        let mut out: Vec<ServiceRecord> = local.iter().map(|e| e.record.clone()).collect();
        for pr in peers.iter() {
            let already = out
                .iter()
                .any(|r| r.announced_prefix == pr.announced_prefix && r.node_name == pr.node_name);
            if !already {
                out.push(pr.clone());
            }
        }
        out
    }

    /// Rate-limit registrations per `identity` (audit #3). When a verifier
    /// is configured, `identity` is the *verified* signer — an attacker
    /// can't mint fresh buckets by varying an unauthenticated `node_name`.
    /// The map is bounded by `max_rate_limit_entries`: a full insert first
    /// prunes fully-expired windows, then evicts the oldest.
    pub(super) fn check_rate_limit(&self, identity: &Name, now: Instant) -> bool {
        let key = identity.to_string();
        let window = self.config.max_registrations_window;
        let limit = self.config.max_registrations_per_producer;
        let cap = self.config.max_rate_limit_entries.max(1);

        let mut limits = self.rate_limits.lock().unwrap();
        if !limits.contains_key(&key) && limits.len() >= cap {
            limits.retain(|_, e| now.duration_since(e.window_start) < window);
            if limits.len() >= cap
                && let Some(oldest) = limits
                    .iter()
                    .min_by_key(|(_, e)| e.window_start)
                    .map(|(k, _)| k.clone())
            {
                limits.remove(&oldest);
            }
        }
        let entry = limits.entry(key).or_insert_with(|| ProducerRateLimit {
            count: 0,
            window_start: now,
        });

        if now.duration_since(entry.window_start) >= window {
            entry.count = 1;
            entry.window_start = now;
            true
        } else if entry.count < limit {
            entry.count += 1;
            true
        } else {
            false
        }
    }

    /// Drop rate-limit entries whose window has fully elapsed (audit #3/#5).
    pub(super) fn prune_rate_limits(&self, now: Instant) {
        let window = self.config.max_registrations_window;
        self.rate_limits
            .lock()
            .unwrap()
            .retain(|_, e| now.duration_since(e.window_start) < window);
    }

    /// Drop body-fetch waiters older than `fetch_timeout` (audit #5):
    /// dropping the senders resolves their receivers to `Err`, the
    /// caller's timeout-fallback path, instead of leaking forever.
    pub(super) fn prune_pending_fetches(&self, now: Instant) {
        let timeout = self.config.fetch_timeout;
        self.pending_fetches
            .lock()
            .unwrap()
            .retain(|_, (send_at, _)| now.duration_since(*send_at) < timeout);
    }

    /// Insert a body blob, evicting an arbitrary entry when at capacity
    /// (audit #5). Local-publisher-bounded, but capped defensively.
    pub(super) fn insert_body(&self, key: (String, String), wrapped: Bytes) {
        let cap = self.config.max_body_entries.max(1);
        let mut store = self.body_store.lock().unwrap();
        if !store.contains_key(&key)
            && store.len() >= cap
            && let Some(victim) = store.keys().next().cloned()
        {
            store.remove(&victim);
        }
        store.insert(key, wrapped);
    }
}

pub(super) use crate::prefix_announce::prefix_hash_hex;

pub(super) fn current_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
