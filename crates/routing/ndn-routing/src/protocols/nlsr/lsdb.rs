//! Link-State Database — one LSA per `(origin_router, LsaType)` pair.
//! Drives age-out (`expire_due`), refresh of own LSAs, and `LsdbEvent`
//! notifications to RoutingTable and NamePrefixTable.
//!
//! C++ reference: `NLSR/src/lsdb.{hpp,cpp}`.
//!
//! Spec divergence from C++ NLSR: instead of scheduling one
//! `ndn::scheduler::EventId` per LSA (`NLSR/src/lsdb.cpp:416-421`,
//! `scheduleLsaExpiration`), we use a single 1 s global tick that
//! scans for expired entries — no per-entry cancellation bookkeeping.
//! The linear scan is negligible at NLSR scale.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use dashmap::mapref::entry::Entry;
use ndn_packet::Name;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::protocols::nlsr::lsa::{
    Lsa, LsaType, adjacency::AdjacencyLsa, adjacency::Adjacent, name::NameLsa, name::PrefixInfo,
};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct LsaKey {
    pub origin_router: Name,
    pub lsa_type: LsaType,
}

/// Mirrors `Lsdb::installLsa`'s return semantics
/// (`NLSR/src/lsdb.cpp:200-280`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstallResult {
    /// Newer seq_no; slot installed or replaced.
    Newer,
    /// seq_no < stored.
    Stale,
    /// seq_no == stored.
    Duplicate,
    /// Expiration already in the past at arrival.
    Invalid,
}

/// C++ equivalent: `LsdbUpdate` enum in `NLSR/src/lsdb.hpp:62`.
#[derive(Clone, Debug)]
pub enum LsdbUpdate {
    Installed,
    Updated,
    Removed,
}

/// Subscribers (RoutingTable, NamePrefixTable) receive this instead
/// of C++ `boost.signals2` callbacks.
#[derive(Clone, Debug)]
pub struct LsdbEvent {
    pub update: LsdbUpdate,
    pub lsa: Lsa,
    /// NameLsa only.
    pub prefixes_added: Vec<Name>,
    /// NameLsa only.
    pub prefixes_removed: Vec<Name>,
}

#[derive(Debug)]
pub struct ExpiredLsa {
    pub key: LsaKey,
    pub lsa: Lsa,
}

pub struct LsdbSnapshot {
    pub adjacency: Vec<Lsa>,
    pub name: Vec<Lsa>,
    pub coordinate: Vec<Lsa>,
}

impl std::fmt::Display for LsdbSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "LSDB: {} adj / {} name / {} coordinate",
            self.adjacency.len(),
            self.name.len(),
            self.coordinate.len()
        )?;
        for lsa in &self.adjacency {
            write!(f, "\n  adj  {} seq={}", lsa.origin_router(), lsa.seq_no())?;
        }
        for lsa in &self.name {
            write!(f, "\n  name {} seq={}", lsa.origin_router(), lsa.seq_no())?;
        }
        for lsa in &self.coordinate {
            write!(f, "\n  coor {} seq={}", lsa.origin_router(), lsa.seq_no())?;
        }
        Ok(())
    }
}

impl std::fmt::Debug for LsdbSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

struct LsaEntry {
    lsa: Lsa,
    /// tokio monotonic clock; pauseable in tests.
    expires_at: tokio::time::Instant,
    /// TTL at install time; used to compute the refresh threshold.
    lifetime: Duration,
}

/// Refresh when 20% of lifetime remains (= 80% elapsed).
const REFRESH_THRESHOLD_REMAINING: f64 = 0.20;

pub struct Lsdb {
    store: DashMap<LsaKey, LsaEntry>,
    pub own_router: Name,
    events: tokio::sync::broadcast::Sender<LsdbEvent>,
}

impl Lsdb {
    pub fn new(own_router: Name) -> Self {
        let (tx, _) = tokio::sync::broadcast::channel(64);
        Self {
            store: DashMap::new(),
            own_router,
            events: tx,
        }
    }

    pub fn event_stream(&self) -> tokio::sync::broadcast::Receiver<LsdbEvent> {
        self.events.subscribe()
    }

    pub fn len(&self) -> usize {
        self.store.len()
    }

    pub fn is_empty(&self) -> bool {
        self.store.is_empty()
    }

    /// `expiration_ms` is a wall-clock Unix timestamp; entries already
    /// in the past at arrival return `Invalid`. C++: `Lsdb::installLsa`
    /// (`NLSR/src/lsdb.cpp:200`).
    pub fn install(&self, lsa: Lsa) -> InstallResult {
        let now_sys_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        if lsa.expiration_ms() <= now_sys_ms {
            return InstallResult::Invalid;
        }

        let remaining_ms = lsa.expiration_ms() - now_sys_ms;
        let lifetime = Duration::from_millis(remaining_ms);
        let expires_at = tokio::time::Instant::now() + lifetime;

        let key = LsaKey {
            origin_router: lsa.origin_router().clone(),
            lsa_type: lsa.lsa_type(),
        };

        match self.store.entry(key) {
            Entry::Vacant(e) => {
                e.insert(LsaEntry {
                    lsa: lsa.clone(),
                    expires_at,
                    lifetime,
                });
                let _ = self.events.send(LsdbEvent {
                    update: LsdbUpdate::Installed,
                    lsa,
                    prefixes_added: vec![],
                    prefixes_removed: vec![],
                });
                InstallResult::Newer
            }
            Entry::Occupied(mut e) => {
                let stored_seq = e.get().lsa.seq_no();
                let new_seq = lsa.seq_no();
                if new_seq > stored_seq {
                    e.insert(LsaEntry {
                        lsa: lsa.clone(),
                        expires_at,
                        lifetime,
                    });
                    let _ = self.events.send(LsdbEvent {
                        update: LsdbUpdate::Updated,
                        lsa,
                        prefixes_added: vec![],
                        prefixes_removed: vec![],
                    });
                    InstallResult::Newer
                } else if new_seq == stored_seq {
                    InstallResult::Duplicate
                } else {
                    InstallResult::Stale
                }
            }
        }
    }

    /// Retrieve a clone of the LSA at `(originator, lsa_type)`, or `None`.
    pub fn lookup(&self, originator: &Name, lsa_type: LsaType) -> Option<Lsa> {
        let key = LsaKey {
            origin_router: originator.clone(),
            lsa_type,
        };
        self.store.get(&key).map(|e| e.value().lsa.clone())
    }

    /// Remove the LSA at `key`. Returns `true` if an entry was present.
    pub fn remove(&self, key: &LsaKey) -> bool {
        if let Some((_, entry)) = self.store.remove(key) {
            let _ = self.events.send(LsdbEvent {
                update: LsdbUpdate::Removed,
                lsa: entry.lsa,
                prefixes_added: vec![],
                prefixes_removed: vec![],
            });
            true
        } else {
            false
        }
    }

    pub fn iter_by_type(&self, lsa_type: LsaType) -> impl Iterator<Item = Lsa> + '_ {
        self.store
            .iter()
            .filter(move |e| e.key().lsa_type == lsa_type)
            .map(|e| e.value().lsa.clone())
    }

    /// Pure storage mutation; no I/O. Driven by [`start_age_out_task`].
    pub fn expire_due(&self, now: tokio::time::Instant) -> Vec<ExpiredLsa> {
        let expired_keys: Vec<LsaKey> = self
            .store
            .iter()
            .filter(|e| e.value().expires_at <= now)
            .map(|e| e.key().clone())
            .collect();

        expired_keys
            .into_iter()
            .filter_map(|k| {
                self.store.remove(&k).map(|(key, entry)| ExpiredLsa {
                    key,
                    lsa: entry.lsa,
                })
            })
            .collect()
    }

    /// Own LSAs within `REFRESH_THRESHOLD_REMAINING` of expiry. The
    /// Hello and Sync paths re-originate them before they age out at
    /// remote LSDBs. C++: `Lsdb::expireOrRefreshLsa` own-LSA branch
    /// (`NLSR/src/lsdb.cpp:424-457`).
    pub fn own_lsas_due_for_refresh(&self, now: tokio::time::Instant) -> Vec<Lsa> {
        self.store
            .iter()
            .filter(|e| {
                e.key().origin_router == self.own_router && {
                    let remaining = e.value().expires_at.saturating_duration_since(now);
                    let threshold = e.value().lifetime.mul_f64(REFRESH_THRESHOLD_REMAINING);
                    remaining <= threshold
                }
            })
            .map(|e| e.value().lsa.clone())
            .collect()
    }

    pub fn snapshot(&self) -> LsdbSnapshot {
        let mut adjacency = Vec::new();
        let mut name = Vec::new();
        let mut coordinate = Vec::new();
        for e in self.store.iter() {
            match e.key().lsa_type {
                LsaType::Adjacency => adjacency.push(e.value().lsa.clone()),
                LsaType::Name => name.push(e.value().lsa.clone()),
                LsaType::Coordinate => coordinate.push(e.value().lsa.clone()),
            }
        }
        LsdbSnapshot {
            adjacency,
            name,
            coordinate,
        }
    }

    /// 1 s tick: calls `expire_due` and broadcasts `LsdbEvent::Removed`
    /// for each expired entry. Exits when `cancel` fires.
    pub fn start_age_out_task(self: Arc<Self>, cancel: CancellationToken) -> JoinHandle<()> {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    _ = interval.tick() => {
                        let now = tokio::time::Instant::now();
                        for e in self.expire_due(now) {
                            let _ = self.events.send(LsdbEvent {
                                update: LsdbUpdate::Removed,
                                lsa: e.lsa,
                                prefixes_added: vec![],
                                prefixes_removed: vec![],
                            });
                        }
                    }
                }
            }
        })
    }

    /// C++: `Lsdb::isLsaNew` (`NLSR/src/lsdb.hpp:244-255`).
    pub fn is_lsa_new(&self, originator: &Name, lsa_type: LsaType, seq_no: u64) -> bool {
        match self.lookup(originator, lsa_type) {
            Some(existing) => seq_no > existing.seq_no(),
            None => true,
        }
    }

    /// C++: `Lsdb::buildAndInstallOwnNameLsa` (`NLSR/src/lsdb.cpp:90`).
    pub fn build_own_name_lsa(
        &self,
        prefixes: &[Name],
        seq_no: u64,
        lsa_refresh_ms: u64,
    ) -> InstallResult {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let lsa = Lsa::Name(NameLsa {
            origin_router: self.own_router.clone(),
            seq_no,
            expiration_ms: now_ms + lsa_refresh_ms,
            prefixes: prefixes
                .iter()
                .map(|n| PrefixInfo {
                    name: n.clone(),
                    cost: 0.0,
                })
                .collect(),
        });
        self.install(lsa)
    }

    /// C++: `Lsdb::buildAndInstallOwnAdjLsa` (`NLSR/src/lsdb.cpp:130`).
    pub fn build_own_adj_lsa(
        &self,
        adjacencies: Vec<Adjacent>,
        seq_no: u64,
        lsa_refresh_ms: u64,
    ) -> InstallResult {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let lsa = Lsa::Adjacency(AdjacencyLsa {
            origin_router: self.own_router.clone(),
            seq_no,
            expiration_ms: now_ms + lsa_refresh_ms,
            adjacencies,
        });
        self.install(lsa)
    }

    /// C++: `Lsdb::processUpdateFromSync` (`NLSR/src/lsdb.cpp:350`).
    pub fn process_sync_update(
        &self,
        origin_router: &Name,
        lsa_type: LsaType,
        seq_no: u64,
    ) -> bool {
        self.is_lsa_new(origin_router, lsa_type, seq_no)
    }
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use ndn_packet::{Name, NameComponent};

    use super::{InstallResult, Lsdb};
    use crate::protocols::nlsr::lsa::{Lsa, LsaType, adjacency::AdjacencyLsa, name::NameLsa};

    fn make_name(uri: &str) -> Name {
        Name::from_components(
            uri.trim_start_matches('/')
                .split('/')
                .filter(|c| !c.is_empty())
                .map(|c| NameComponent::generic(bytes::Bytes::copy_from_slice(c.as_bytes()))),
        )
    }

    fn unix_now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }

    fn adj_lsa(origin: &str, seq: u64, exp_ms: u64) -> Lsa {
        Lsa::Adjacency(AdjacencyLsa {
            origin_router: make_name(origin),
            seq_no: seq,
            expiration_ms: exp_ms,
            adjacencies: vec![],
        })
    }

    fn name_lsa(origin: &str, seq: u64, exp_ms: u64) -> Lsa {
        Lsa::Name(NameLsa {
            origin_router: make_name(origin),
            seq_no: seq,
            expiration_ms: exp_ms,
            prefixes: vec![],
        })
    }

    #[test]
    fn install_new_returns_newer() {
        let db = Lsdb::new(make_name("/self"));
        let result = db.install(adj_lsa("/router1", 1, unix_now_ms() + 120_000));
        assert_eq!(result, InstallResult::Newer);
    }

    #[test]
    fn install_stale_seq_returns_stale() {
        let db = Lsdb::new(make_name("/self"));
        db.install(adj_lsa("/router1", 10, unix_now_ms() + 120_000));
        let result = db.install(adj_lsa("/router1", 5, unix_now_ms() + 120_000));
        assert_eq!(result, InstallResult::Stale);
    }

    #[test]
    fn install_duplicate_seq_returns_duplicate() {
        let db = Lsdb::new(make_name("/self"));
        db.install(adj_lsa("/router1", 10, unix_now_ms() + 120_000));
        let result = db.install(adj_lsa("/router1", 10, unix_now_ms() + 120_000));
        assert_eq!(result, InstallResult::Duplicate);
    }

    #[test]
    fn install_higher_seq_returns_newer_and_updates() {
        let db = Lsdb::new(make_name("/self"));
        db.install(adj_lsa("/router1", 5, unix_now_ms() + 120_000));
        let result = db.install(adj_lsa("/router1", 10, unix_now_ms() + 120_000));
        assert_eq!(result, InstallResult::Newer);

        let stored = db
            .lookup(&make_name("/router1"), LsaType::Adjacency)
            .unwrap();
        assert_eq!(stored.seq_no(), 10);
    }

    #[test]
    fn install_already_expired_returns_invalid() {
        let db = Lsdb::new(make_name("/self"));
        // expiration_ms = 0 is before any realistic now
        let result = db.install(adj_lsa("/router1", 1, 0));
        assert_eq!(result, InstallResult::Invalid);
    }

    #[test]
    fn lookup_returns_none_for_missing() {
        let db = Lsdb::new(make_name("/self"));
        assert!(
            db.lookup(&make_name("/router1"), LsaType::Adjacency)
                .is_none()
        );
    }

    #[test]
    fn iter_by_type_filters_correctly() {
        let db = Lsdb::new(make_name("/self"));
        let now = unix_now_ms();
        db.install(adj_lsa("/r1", 1, now + 120_000));
        db.install(adj_lsa("/r2", 1, now + 120_000));
        db.install(name_lsa("/r1", 1, now + 120_000));

        let adj_entries: Vec<_> = db.iter_by_type(LsaType::Adjacency).collect();
        assert_eq!(adj_entries.len(), 2);

        let name_entries: Vec<_> = db.iter_by_type(LsaType::Name).collect();
        assert_eq!(name_entries.len(), 1);

        let coord_entries: Vec<_> = db.iter_by_type(LsaType::Coordinate).collect();
        assert_eq!(coord_entries.len(), 0);
    }

    #[test]
    fn snapshot_covers_all_types() {
        let db = Lsdb::new(make_name("/self"));
        let now = unix_now_ms();
        db.install(adj_lsa("/r1", 1, now + 120_000));
        db.install(name_lsa("/r1", 1, now + 120_000));

        let snap = db.snapshot();
        assert_eq!(snap.adjacency.len(), 1);
        assert_eq!(snap.name.len(), 1);
        assert_eq!(snap.coordinate.len(), 0);

        let display = format!("{snap}");
        assert!(display.contains("1 adj"));
        assert!(display.contains("1 name"));
    }

    #[tokio::test(start_paused = true)]
    async fn expire_due_removes_expired_entries() {
        let db = Lsdb::new(make_name("/self"));
        let exp_ms = unix_now_ms() + 60_000; // 60 s from now
        db.install(adj_lsa("/r1", 1, exp_ms));

        // Before deadline: nothing expired.
        let before = db.expire_due(tokio::time::Instant::now());
        assert!(before.is_empty());

        // Advance past the deadline.
        tokio::time::advance(std::time::Duration::from_secs(70)).await;

        let expired = db.expire_due(tokio::time::Instant::now());
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].lsa.seq_no(), 1);

        // Entry should be gone from the store.
        assert!(db.lookup(&make_name("/r1"), LsaType::Adjacency).is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn expire_due_keeps_live_entries() {
        let db = Lsdb::new(make_name("/self"));
        let exp_ms = unix_now_ms() + 120_000; // 120 s from now
        db.install(adj_lsa("/r1", 1, exp_ms));

        // Advance less than the lifetime.
        tokio::time::advance(std::time::Duration::from_secs(60)).await;

        let expired = db.expire_due(tokio::time::Instant::now());
        assert!(expired.is_empty());
        assert!(db.lookup(&make_name("/r1"), LsaType::Adjacency).is_some());
    }

    #[tokio::test(start_paused = true)]
    async fn own_lsas_due_for_refresh_at_threshold() {
        let own = make_name("/self");
        let db = Lsdb::new(own.clone());
        let exp_ms = unix_now_ms() + 120_000; // 120 s lifetime
        db.install(adj_lsa("/self", 1, exp_ms));

        // At 79% elapsed (21% remaining > 20% threshold): not yet due.
        tokio::time::advance(std::time::Duration::from_millis(94_800)).await; // 79%
        let due = db.own_lsas_due_for_refresh(tokio::time::Instant::now());
        assert!(due.is_empty(), "should not be due at 79% elapsed");

        // At 85% elapsed (15% remaining < 20% threshold): due.
        tokio::time::advance(std::time::Duration::from_millis(7_200)).await; // +6% = 85%
        let due = db.own_lsas_due_for_refresh(tokio::time::Instant::now());
        assert_eq!(due.len(), 1, "should be due at 85% elapsed");
        assert_eq!(due[0].origin_router(), &own);
    }
}
