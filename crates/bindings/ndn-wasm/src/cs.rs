//! Content Store for the WASM simulation: LRU cache keyed by name string.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CsEntry {
    pub name: String,
    /// Human-readable content for display.
    pub content: String,
    pub content_bytes: usize,
    pub freshness_ms: u64,
    /// `Date.now()` at insertion.
    pub inserted_at: f64,
    pub sig_type: String,
}

pub type CsSnapshot = Vec<CsEntry>;

pub struct SimCs {
    entries: HashMap<String, CsEntry>,
    /// Oldest first; drives LRU eviction.
    insertion_order: Vec<String>,
    pub capacity: usize,
}

impl SimCs {
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: HashMap::new(),
            insertion_order: Vec::new(),
            capacity,
        }
    }

    pub fn lookup(
        &self,
        interest_name: &str,
        can_be_prefix: bool,
        must_be_fresh: bool,
        now_ms: f64,
    ) -> Option<&CsEntry> {
        if let Some(entry) = self.entries.get(interest_name)
            && (!must_be_fresh || is_fresh(entry, now_ms))
        {
            return Some(entry);
        }
        if can_be_prefix {
            for (name, entry) in &self.entries {
                if name.starts_with(interest_name) && (!must_be_fresh || is_fresh(entry, now_ms)) {
                    return Some(entry);
                }
            }
        }
        None
    }

    pub fn insert(
        &mut self,
        name: String,
        content: String,
        content_bytes: usize,
        freshness_ms: u64,
        now_ms: f64,
        sig_type: String,
    ) {
        if self.entries.contains_key(&name) {
            self.insertion_order.retain(|n| n != &name);
        }
        while !self.insertion_order.is_empty() && self.entries.len() >= self.capacity {
            let oldest = self.insertion_order.remove(0);
            self.entries.remove(&oldest);
        }
        let entry = CsEntry {
            name: name.clone(),
            content,
            content_bytes,
            freshness_ms,
            inserted_at: now_ms,
            sig_type,
        };
        self.entries.insert(name.clone(), entry);
        self.insertion_order.push(name);
    }

    pub fn remove(&mut self, name: &str) {
        self.entries.remove(name);
        self.insertion_order.retain(|n| n != name);
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Most-recently-inserted first, capped at 50 entries for display.
    pub fn snapshot(&self) -> CsSnapshot {
        let mut entries: Vec<CsEntry> = self
            .insertion_order
            .iter()
            .rev()
            .filter_map(|name| self.entries.get(name).cloned())
            .collect();
        entries.truncate(50);
        entries
    }
}

impl Default for SimCs {
    fn default() -> Self {
        Self::new(100)
    }
}

fn is_fresh(entry: &CsEntry, now_ms: f64) -> bool {
    // `freshness_ms == 0` is treated as never-stale in the simulator.
    if entry.freshness_ms == 0 {
        return true;
    }
    now_ms < entry.inserted_at + entry.freshness_ms as f64
}
