//! Pending Interest Table for the WASM simulation.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PitInRecord {
    pub face_id: u32,
    pub nonce: u32,
    /// `Date.now()` style.
    pub expires_at: f64,
}

/// Keyed by `(name, can_be_prefix, must_be_fresh)`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PitEntry {
    pub name: String,
    pub can_be_prefix: bool,
    pub must_be_fresh: bool,
    pub in_records: Vec<PitInRecord>,
    pub expires_at: f64,
}

impl PitEntry {
    pub fn new(
        name: String,
        can_be_prefix: bool,
        must_be_fresh: bool,
        face_id: u32,
        nonce: u32,
        now_ms: f64,
        lifetime_ms: f64,
    ) -> Self {
        let expires = now_ms + lifetime_ms;
        Self {
            name,
            can_be_prefix,
            must_be_fresh,
            in_records: vec![PitInRecord {
                face_id,
                nonce,
                expires_at: expires,
            }],
            expires_at: expires,
        }
    }

    /// Returns `true` if the in-record was appended; `false` on a duplicate
    /// nonce (loop detected).
    pub fn add_in_record(&mut self, face_id: u32, nonce: u32, expires_at: f64) -> bool {
        if self.in_records.iter().any(|r| r.nonce == nonce) {
            return false;
        }
        self.in_records.push(PitInRecord {
            face_id,
            nonce,
            expires_at,
        });
        true
    }

    pub fn in_faces(&self) -> Vec<u32> {
        self.in_records.iter().map(|r| r.face_id).collect()
    }
}

pub type PitSnapshot = Vec<PitEntry>;

pub struct SimPit {
    entries: HashMap<PitKey, PitEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct PitKey {
    name: String,
    can_be_prefix: bool,
    must_be_fresh: bool,
}

impl SimPit {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// First PIT name that the given Data satisfies, if any.
    pub fn match_data(&self, data_name: &str) -> Option<String> {
        for entry in self.entries.values() {
            if data_name == entry.name
                || (entry.can_be_prefix && data_name.starts_with(&entry.name))
            {
                return Some(entry.name.clone());
            }
        }
        None
    }

    /// Returns `(is_new_entry, did_aggregate)`.
    #[allow(clippy::too_many_arguments)]
    pub fn insert(
        &mut self,
        name: &str,
        can_be_prefix: bool,
        must_be_fresh: bool,
        face_id: u32,
        nonce: u32,
        now_ms: f64,
        lifetime_ms: f64,
    ) -> (bool, bool) {
        let key = PitKey {
            name: name.to_string(),
            can_be_prefix,
            must_be_fresh,
        };
        if let Some(entry) = self.entries.get_mut(&key) {
            let added = entry.add_in_record(face_id, nonce, now_ms + lifetime_ms);
            (false, added)
        } else {
            self.entries.insert(
                key,
                PitEntry::new(
                    name.to_string(),
                    can_be_prefix,
                    must_be_fresh,
                    face_id,
                    nonce,
                    now_ms,
                    lifetime_ms,
                ),
            );
            (true, false)
        }
    }

    /// Remove and return every entry the Data satisfies.
    pub fn remove_matching(&mut self, data_name: &str) -> Vec<PitEntry> {
        let mut matched_keys = Vec::new();
        for (key, entry) in &self.entries {
            if data_name == entry.name
                || (entry.can_be_prefix && data_name.starts_with(&entry.name))
            {
                matched_keys.push(key.clone());
            }
        }
        matched_keys
            .into_iter()
            .filter_map(|k| self.entries.remove(&k))
            .collect()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn evict_expired(&mut self, now_ms: f64) {
        self.entries.retain(|_, e| e.expires_at > now_ms);
    }

    pub fn snapshot(&self) -> PitSnapshot {
        let mut entries: Vec<PitEntry> = self.entries.values().cloned().collect();
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        entries
    }
}

impl Default for SimPit {
    fn default() -> Self {
        Self::new()
    }
}
