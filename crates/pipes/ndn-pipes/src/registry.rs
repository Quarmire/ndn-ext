//! The producer's live-pipe table, shared between the serve loop (which mutates
//! it) and the read-only PIPES introspection module (which [`list`]s it).
//!
//! [`list`]: PipeRegistry::list

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// One row of the PIPES `list` dataset: a live pipe and its remaining PUI.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PipeInfo {
    /// Lowercase-hex pipe id.
    pub id_hex: String,
    /// Milliseconds until the Promised Use Interval lapses.
    pub remaining_ms: u64,
}

struct Entry {
    deadline: Instant,
    pipe_key: Vec<u8>,
}

/// The live pipes a producer holds, keyed by pipe-id bytes, each with its PUI
/// deadline and pipe key. Cheaply cloneable (shared `Arc`): the serve loop
/// registers/renews/reclaims entries; the PIPES module reads [`list`].
///
/// [`list`]: PipeRegistry::list
#[derive(Clone, Default)]
pub struct PipeRegistry {
    inner: Arc<Mutex<HashMap<Vec<u8>, Entry>>>,
}

impl PipeRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register (or replace) a pipe with a fresh PUI deadline and its pipe key.
    pub(crate) fn insert(&self, id: Vec<u8>, deadline: Instant, pipe_key: Vec<u8>) {
        self.inner
            .lock()
            .unwrap()
            .insert(id, Entry { deadline, pipe_key });
    }

    /// Renew a live pipe's deadline (the CHECK keep-alive) and report it live;
    /// reap it if the deadline has already lapsed (lazy inactivity teardown).
    pub(crate) fn refresh_if_live(&self, id: &[u8], pui: Duration) -> bool {
        let mut m = self.inner.lock().unwrap();
        match m.get_mut(id) {
            Some(e) if Instant::now() <= e.deadline => {
                e.deadline = Instant::now() + pui;
                true
            }
            Some(_) => {
                m.remove(id);
                false
            }
            None => false,
        }
    }

    /// Authorize (and perform) a teardown: the supplied secret must equal the
    /// stored pipe key. An already-gone pipe is an idempotent success.
    pub(crate) fn teardown_authorized(&self, id: &[u8], secret: Option<&[u8]>) -> bool {
        let mut m = self.inner.lock().unwrap();
        match m.get(id) {
            Some(e) => {
                if secret == Some(e.pipe_key.as_slice()) {
                    m.remove(id);
                    true
                } else {
                    false // wrong pipe key — reject the teardown
                }
            }
            None => true, // already torn down: idempotent no-op
        }
    }

    /// Read-only snapshot of the live (unexpired) pipes, sorted by id — the
    /// `list` dataset. Expired-but-unreaped entries are filtered out, not shown.
    pub fn list(&self) -> Vec<PipeInfo> {
        let now = Instant::now();
        let mut rows: Vec<PipeInfo> = self
            .inner
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, e)| now <= e.deadline)
            .map(|(id, e)| PipeInfo {
                id_hex: to_hex(id),
                remaining_ms: e.deadline.saturating_duration_since(now).as_millis() as u64,
            })
            .collect();
        rows.sort_by(|a, b| a.id_hex.cmp(&b.id_hex));
        rows
    }
}

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_shows_live_pipes_sorted_and_hides_expired() {
        let reg = PipeRegistry::new();
        let now = Instant::now();
        reg.insert(vec![0xbb], now + Duration::from_secs(5), vec![1]);
        reg.insert(vec![0xaa], now + Duration::from_secs(5), vec![2]);
        reg.insert(vec![0xcc], now - Duration::from_secs(1), vec![3]); // expired

        let rows = reg.list();
        assert_eq!(rows.len(), 2, "expired pipe is not listed");
        assert_eq!(rows[0].id_hex, "aa", "sorted by id");
        assert_eq!(rows[1].id_hex, "bb");
        assert!(rows[0].remaining_ms > 0);
    }
}
