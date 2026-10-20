//! Which routers' published Data a sync group member has applied, or has a
//! fetch queued for. Shared by Adv Sync ([`super::sync::DvSync`]) and Pfx
//! Sync ([`super::pfx_sync::DvPfxSync`]).
//!
//! A router is fetched while its newest known `(boot, seq)` is not applied,
//! with at most one fetch queued per router. A failed fetch leaves the state
//! unapplied, so the next Sync Interest naming that router queues it again,
//! rather than waiting for the router's next change.

use std::collections::{HashMap, HashSet};

use ndn_packet::Name;
use ndn_sync::{NeighborAdvance, SvsLocal};
use parking_lot::Mutex;

#[derive(Default)]
pub(crate) struct FetchTracker {
    state: Mutex<FetchState>,
}

#[derive(Default)]
struct FetchState {
    /// Per router, the `(boot, seq)` whose Data was applied.
    applied: HashMap<Name, (u64, u64)>,
    /// Routers with a fetch queued.
    queued: HashSet<Name>,
}

impl FetchState {
    /// Queue `router` at its newest known `(boot, seq)` unless that state is
    /// applied or a fetch is already queued.
    fn queue(&mut self, router: &Name, boot: u64, seq: u64) -> Option<NeighborAdvance> {
        (self.applied.get(router) != Some(&(boot, seq)) && self.queued.insert(router.clone())).then(
            || NeighborAdvance {
                name: router.clone(),
                boot,
                seq,
            },
        )
    }
}

impl FetchTracker {
    /// Queue a fetch of `router`'s newest state known to `svs`, unless it is
    /// applied or already queued. Returns the fetch to queue.
    pub(crate) fn queue(&self, svs: &SvsLocal, router: &Name) -> Option<NeighborAdvance> {
        let mut state = self.state.lock();
        let newest = svs.neighbor(router)?;
        state.queue(router, newest.boot, newest.seq)
    }

    /// [`Self::queue`] for every router `svs` knows.
    pub(crate) fn queue_all(&self, svs: &SvsLocal) -> Vec<NeighborAdvance> {
        let mut state = self.state.lock();
        svs.neighbors()
            .into_iter()
            .filter_map(|n| state.queue(&n.name, n.boot, n.seq))
            .collect()
    }

    /// Take `router`'s queued fetch: its newest state known to `svs`, unless
    /// that state is already applied.
    pub(crate) fn start(&self, svs: &SvsLocal, router: &Name) -> Option<NeighborAdvance> {
        let mut state = self.state.lock();
        state.queued.remove(router);
        let newest = svs.neighbor(router)?;
        (state.applied.get(router) != Some(&(newest.boot, newest.seq))).then(|| NeighborAdvance {
            name: router.clone(),
            boot: newest.boot,
            seq: newest.seq,
        })
    }

    /// Record that `adv`'s Data was fetched and applied.
    pub(crate) fn applied(&self, adv: &NeighborAdvance) {
        self.state
            .lock()
            .applied
            .insert(adv.name.clone(), (adv.boot, adv.seq));
    }

    /// Forget what was applied from `router`: its next Sync Interest queues
    /// a fetch even if its state did not change.
    pub(crate) fn forget(&self, router: &Name) {
        self.state.lock().applied.remove(router);
    }
}
