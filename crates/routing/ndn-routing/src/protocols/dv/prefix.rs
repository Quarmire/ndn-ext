//! ndn-dv global prefix table per SPEC.md §4 *Prefix Sync*.
//!
//! Global per-network mapping of prefix to exit routers that have
//! announced it, propagated via a canonical SVS group at
//! `/<network>/32=DV/32=PFS/32=svs`. Operations
//! (`PREFIX-OP-RESET` / `PREFIX-OP-ADD` / `PREFIX-OP-REMOVE`) are
//! processed in strict sequence order.
//!
//! Cross-referenced against `ndnd/dv/table/prefix_table.go`. Pure
//! data structure + algorithm; the FIB-join lives in [`super::fib`].

use std::collections::HashMap;
use std::sync::RwLock;

use ndn_packet::Name;

use crate::protocols::dv::tlv::{PrefixOpAdd, PrefixOpList, PrefixOpRemove};

/// Delta from [`PrefixTable::apply_op_list`] and local announce/withdraw.
/// `None` for `old_cost` = was not announced; `None` for `new_cost` =
/// withdrawn or reset.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrefixChange {
    pub router: Name,
    pub prefix: Name,
    pub old_cost: Option<u32>,
    pub new_cost: Option<u32>,
}

pub struct PrefixTable {
    self_router: Name,
    /// Kept separately so local announce/withdraw can produce outgoing
    /// `PrefixOpList` deltas without scanning the whole table. The
    /// self row in `remote` is kept in sync with this.
    local_prefixes: RwLock<HashMap<Name, u32>>,
    /// `router → (prefix → cost)`. Includes the self row when this
    /// router has made local announcements.
    remote: RwLock<HashMap<Name, HashMap<Name, u32>>>,
}

impl PrefixTable {
    pub fn new(self_router: Name) -> Self {
        Self {
            self_router,
            local_prefixes: RwLock::new(HashMap::new()),
            remote: RwLock::new(HashMap::new()),
        }
    }

    pub fn self_router(&self) -> &Name {
        &self.self_router
    }

    /// Per SPEC.md §4 the operations are processed strictly in
    /// order: optional `PREFIX-OP-RESET` first, then `PREFIX-OP-ADD`s,
    /// then `PREFIX-OP-REMOVE`s. `ops.exit_router` is not validated
    /// against the message-level sender identity here (the trust
    /// layer's job). Self-bouncing op lists are no-op'd:
    /// `local_prefixes` is authoritative for our own announcements.
    pub fn apply_op_list(&self, ops: &PrefixOpList) -> Vec<PrefixChange> {
        let router = ops.exit_router.clone();
        if router == self.self_router {
            return Vec::new();
        }

        let mut remote = self.remote.write().expect("PrefixTable::remote poisoned");
        let row = remote.entry(router.clone()).or_default();
        let mut changes = Vec::new();

        if ops.reset {
            for (prefix, old_cost) in row.drain() {
                changes.push(PrefixChange {
                    router: router.clone(),
                    prefix,
                    old_cost: Some(old_cost),
                    new_cost: None,
                });
            }
        }
        for add in &ops.adds {
            let old = row.insert(add.name.clone(), add.cost as u32);
            if old != Some(add.cost as u32) {
                changes.push(PrefixChange {
                    router: router.clone(),
                    prefix: add.name.clone(),
                    old_cost: old,
                    new_cost: Some(add.cost as u32),
                });
            }
        }
        for remove in &ops.removes {
            if let Some(old) = row.remove(&remove.name) {
                changes.push(PrefixChange {
                    router: router.clone(),
                    prefix: remove.name.clone(),
                    old_cost: Some(old),
                    new_cost: None,
                });
            }
        }
        if row.is_empty() {
            remote.remove(&router);
        }
        changes
    }

    /// Returns the `PrefixOpList` to publish on the Prefix Sync
    /// group, or `None` if the same cost was already announced.
    pub fn announce_local(&self, prefix: Name, cost: u32) -> Option<PrefixOpList> {
        let mut local = self
            .local_prefixes
            .write()
            .expect("PrefixTable::local_prefixes poisoned");
        if local.get(&prefix).copied() == Some(cost) {
            return None;
        }
        local.insert(prefix.clone(), cost);
        Some(PrefixOpList {
            exit_router: self.self_router.clone(),
            reset: false,
            adds: vec![PrefixOpAdd {
                name: prefix,
                cost: cost as u64,
            }],
            removes: Vec::new(),
        })
    }

    /// Returns the `PrefixOpList` to publish, or `None` if the prefix
    /// was not previously announced.
    pub fn withdraw_local(&self, prefix: &Name) -> Option<PrefixOpList> {
        let mut local = self
            .local_prefixes
            .write()
            .expect("PrefixTable::local_prefixes poisoned");
        local.remove(prefix)?;
        Some(PrefixOpList {
            exit_router: self.self_router.clone(),
            reset: false,
            adds: Vec::new(),
            removes: vec![PrefixOpRemove {
                name: prefix.clone(),
            }],
        })
    }

    /// Full snapshot: `Reset=true` followed by an `Add` for every
    /// currently-announced prefix. Used at startup (SPEC.md §4 step 2:
    /// "When a router starts, it sends a `PREFIX-OP-RESET`") and as a
    /// catch-up payload for new peers (ndnd's `Snap()`).
    pub fn snap(&self) -> PrefixOpList {
        let local = self
            .local_prefixes
            .read()
            .expect("PrefixTable::local_prefixes poisoned");
        let mut adds: Vec<PrefixOpAdd> = local
            .iter()
            .map(|(name, cost)| PrefixOpAdd {
                name: name.clone(),
                cost: *cost as u64,
            })
            .collect();
        adds.sort_by(|a, b| a.name.cmp(&b.name));
        PrefixOpList {
            exit_router: self.self_router.clone(),
            reset: true,
            adds,
            removes: Vec::new(),
        }
    }

    /// All routers (including self, if applicable) that have
    /// announced `prefix`, sorted lex by router name.
    pub fn routers_for_prefix(&self, prefix: &Name) -> Vec<(Name, u32)> {
        let mut out = Vec::new();
        let local = self
            .local_prefixes
            .read()
            .expect("PrefixTable::local_prefixes poisoned");
        if let Some(cost) = local.get(prefix) {
            out.push((self.self_router.clone(), *cost));
        }
        let remote = self.remote.read().expect("PrefixTable::remote poisoned");
        for (router, row) in remote.iter() {
            if let Some(cost) = row.get(prefix) {
                out.push((router.clone(), *cost));
            }
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    /// Every prefix announced by `router`, sorted lex.
    pub fn prefixes_for_router(&self, router: &Name) -> Vec<(Name, u32)> {
        let mut out: Vec<(Name, u32)> = if router == &self.self_router {
            let local = self
                .local_prefixes
                .read()
                .expect("PrefixTable::local_prefixes poisoned");
            local.iter().map(|(n, c)| (n.clone(), *c)).collect()
        } else {
            let remote = self.remote.read().expect("PrefixTable::remote poisoned");
            remote
                .get(router)
                .map(|row| row.iter().map(|(n, c)| (n.clone(), *c)).collect())
                .unwrap_or_default()
        };
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    /// All routers tracked in this table (self + every remote that
    /// has at least one announcement). Sorted lex.
    pub fn routers(&self) -> Vec<Name> {
        let mut out: Vec<Name> = Vec::new();
        {
            let local = self
                .local_prefixes
                .read()
                .expect("PrefixTable::local_prefixes poisoned");
            if !local.is_empty() {
                out.push(self.self_router.clone());
            }
        }
        {
            let remote = self.remote.read().expect("PrefixTable::remote poisoned");
            for router in remote.keys() {
                out.push(router.clone());
            }
        }
        out.sort();
        out.dedup();
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn name(s: &str) -> Name {
        Name::from_str(s).expect("valid name")
    }

    fn op_list(
        sender: &str,
        reset: bool,
        adds: Vec<(&str, u64)>,
        removes: Vec<&str>,
    ) -> PrefixOpList {
        PrefixOpList {
            exit_router: name(sender),
            reset,
            adds: adds
                .into_iter()
                .map(|(n, c)| PrefixOpAdd {
                    name: name(n),
                    cost: c,
                })
                .collect(),
            removes: removes
                .into_iter()
                .map(|n| PrefixOpRemove { name: name(n) })
                .collect(),
        }
    }

    #[test]
    fn add_inserts_new_prefix() {
        let pt = PrefixTable::new(name("/me"));
        let changes = pt.apply_op_list(&op_list("/peer", false, vec![("/p", 5)], vec![]));
        assert_eq!(changes.len(), 1);
        assert_eq!(
            changes[0],
            PrefixChange {
                router: name("/peer"),
                prefix: name("/p"),
                old_cost: None,
                new_cost: Some(5),
            },
        );
        assert_eq!(pt.routers_for_prefix(&name("/p")), vec![(name("/peer"), 5)],);
    }

    #[test]
    fn add_with_same_cost_is_noop() {
        let pt = PrefixTable::new(name("/me"));
        pt.apply_op_list(&op_list("/peer", false, vec![("/p", 5)], vec![]));
        let changes = pt.apply_op_list(&op_list("/peer", false, vec![("/p", 5)], vec![]));
        assert!(
            changes.is_empty(),
            "same-cost re-add must not emit a change"
        );
    }

    #[test]
    fn add_with_new_cost_updates() {
        let pt = PrefixTable::new(name("/me"));
        pt.apply_op_list(&op_list("/peer", false, vec![("/p", 5)], vec![]));
        let changes = pt.apply_op_list(&op_list("/peer", false, vec![("/p", 7)], vec![]));
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].old_cost, Some(5));
        assert_eq!(changes[0].new_cost, Some(7));
    }

    #[test]
    fn remove_drops_prefix() {
        let pt = PrefixTable::new(name("/me"));
        pt.apply_op_list(&op_list("/peer", false, vec![("/p", 5)], vec![]));
        let changes = pt.apply_op_list(&op_list("/peer", false, vec![], vec!["/p"]));
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].old_cost, Some(5));
        assert_eq!(changes[0].new_cost, None);
        assert!(pt.routers_for_prefix(&name("/p")).is_empty());
    }

    #[test]
    fn remove_of_missing_prefix_is_noop() {
        let pt = PrefixTable::new(name("/me"));
        let changes = pt.apply_op_list(&op_list("/peer", false, vec![], vec!["/missing"]));
        assert!(changes.is_empty());
    }

    #[test]
    fn reset_clears_all_sender_prefixes() {
        let pt = PrefixTable::new(name("/me"));
        pt.apply_op_list(&op_list(
            "/peer",
            false,
            vec![("/a", 1), ("/b", 2), ("/c", 3)],
            vec![],
        ));
        let changes = pt.apply_op_list(&op_list("/peer", true, vec![], vec![]));
        // All three prefixes go Some -> None.
        assert_eq!(changes.len(), 3);
        assert!(pt.prefixes_for_router(&name("/peer")).is_empty());
    }

    #[test]
    fn reset_then_adds_within_one_message() {
        // Per SPEC: Reset → Adds → Removes in strict order.
        let pt = PrefixTable::new(name("/me"));
        pt.apply_op_list(&op_list("/peer", false, vec![("/old", 1)], vec![]));
        let changes = pt.apply_op_list(&op_list(
            "/peer",
            true, // Reset first
            vec![("/new1", 1), ("/new2", 2)],
            vec![],
        ));
        // /old gets dropped by reset; /new1 and /new2 are added.
        assert_eq!(changes.len(), 3);
        assert_eq!(pt.prefixes_for_router(&name("/peer")).len(), 2);
        assert!(
            pt.prefixes_for_router(&name("/peer"))
                .iter()
                .any(|(p, _)| p == &name("/new1")),
        );
    }

    #[test]
    fn self_originated_op_list_is_ignored() {
        // A multicast loop could send us our own PrefixOpList back —
        // make sure it doesn't double-record our entries.
        let pt = PrefixTable::new(name("/me"));
        pt.announce_local(name("/a"), 1);
        let changes = pt.apply_op_list(&op_list("/me", false, vec![("/a", 99)], vec![]));
        assert!(changes.is_empty(), "self-bounce must not modify state");
        // Cost remains 1 (our local source of truth), not the 99 in the loop.
        assert_eq!(pt.routers_for_prefix(&name("/a")), vec![(name("/me"), 1)],);
    }

    #[test]
    fn announce_local_emits_add_op_list() {
        let pt = PrefixTable::new(name("/me"));
        let ops = pt.announce_local(name("/foo"), 3).expect("should publish");
        assert_eq!(ops.exit_router, name("/me"));
        assert!(!ops.reset);
        assert_eq!(ops.adds.len(), 1);
        assert_eq!(ops.adds[0].name, name("/foo"));
        assert_eq!(ops.adds[0].cost, 3);
        assert!(ops.removes.is_empty());
    }

    #[test]
    fn announce_local_same_cost_is_noop() {
        let pt = PrefixTable::new(name("/me"));
        pt.announce_local(name("/foo"), 3);
        assert!(pt.announce_local(name("/foo"), 3).is_none());
    }

    #[test]
    fn announce_local_then_change_cost_emits_add() {
        let pt = PrefixTable::new(name("/me"));
        pt.announce_local(name("/foo"), 3);
        let ops = pt
            .announce_local(name("/foo"), 5)
            .expect("cost change emits");
        assert_eq!(ops.adds.len(), 1);
        assert_eq!(ops.adds[0].cost, 5);
    }

    #[test]
    fn withdraw_local_emits_remove_op_list() {
        let pt = PrefixTable::new(name("/me"));
        pt.announce_local(name("/foo"), 3);
        let ops = pt.withdraw_local(&name("/foo")).expect("should publish");
        assert!(!ops.reset);
        assert!(ops.adds.is_empty());
        assert_eq!(ops.removes.len(), 1);
        assert_eq!(ops.removes[0].name, name("/foo"));
    }

    #[test]
    fn withdraw_local_missing_is_none() {
        let pt = PrefixTable::new(name("/me"));
        assert!(pt.withdraw_local(&name("/never_announced")).is_none());
    }

    #[test]
    fn snap_empty_router() {
        let pt = PrefixTable::new(name("/me"));
        let snap = pt.snap();
        assert!(snap.reset, "snap must always start with Reset");
        assert!(snap.adds.is_empty());
        assert!(snap.removes.is_empty());
    }

    #[test]
    fn snap_includes_all_local_prefixes_sorted() {
        let pt = PrefixTable::new(name("/me"));
        pt.announce_local(name("/zzz"), 9);
        pt.announce_local(name("/aaa"), 1);
        pt.announce_local(name("/mmm"), 5);
        let snap = pt.snap();
        assert!(snap.reset);
        assert_eq!(snap.adds.len(), 3);
        // Lex-sorted by name.
        assert_eq!(snap.adds[0].name, name("/aaa"));
        assert_eq!(snap.adds[0].cost, 1);
        assert_eq!(snap.adds[1].name, name("/mmm"));
        assert_eq!(snap.adds[2].name, name("/zzz"));
    }

    #[test]
    fn routers_for_prefix_aggregates_across_routers() {
        let pt = PrefixTable::new(name("/me"));
        pt.announce_local(name("/shared"), 2);
        pt.apply_op_list(&op_list("/a", false, vec![("/shared", 4)], vec![]));
        pt.apply_op_list(&op_list("/b", false, vec![("/shared", 3)], vec![]));
        let routers = pt.routers_for_prefix(&name("/shared"));
        // Lex order: /a, /b, /me.
        assert_eq!(
            routers,
            vec![(name("/a"), 4), (name("/b"), 3), (name("/me"), 2),],
        );
    }

    #[test]
    fn prefixes_for_router_returns_own_announcements() {
        let pt = PrefixTable::new(name("/me"));
        pt.announce_local(name("/p1"), 1);
        pt.announce_local(name("/p2"), 2);
        let prefixes = pt.prefixes_for_router(&name("/me"));
        assert_eq!(prefixes.len(), 2);
        assert_eq!(prefixes[0], (name("/p1"), 1));
        assert_eq!(prefixes[1], (name("/p2"), 2));
    }

    #[test]
    fn routers_lists_self_when_local_announcements_present() {
        let pt = PrefixTable::new(name("/me"));
        assert!(pt.routers().is_empty());
        pt.announce_local(name("/p"), 1);
        assert_eq!(pt.routers(), vec![name("/me")]);
        pt.apply_op_list(&op_list("/peer", false, vec![("/x", 1)], vec![]));
        let r = pt.routers();
        assert_eq!(r.len(), 2);
        assert!(r.contains(&name("/me")));
        assert!(r.contains(&name("/peer")));
    }

    #[test]
    fn two_router_announce_and_withdraw_round_trip() {
        // r1 announces /shop at cost 1; r2 receives via apply.
        let r1 = PrefixTable::new(name("/r1"));
        let r2 = PrefixTable::new(name("/r2"));

        let ops = r1.announce_local(name("/shop"), 1).unwrap();
        let changes = r2.apply_op_list(&ops);
        assert_eq!(changes.len(), 1);
        assert_eq!(
            r2.routers_for_prefix(&name("/shop")),
            vec![(name("/r1"), 1)],
        );

        // r1 withdraws; r2 receives the remove.
        let ops = r1.withdraw_local(&name("/shop")).unwrap();
        let changes = r2.apply_op_list(&ops);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].old_cost, Some(1));
        assert_eq!(changes[0].new_cost, None);
        assert!(r2.routers_for_prefix(&name("/shop")).is_empty());
    }

    #[test]
    fn router_restart_via_snap_catches_up() {
        // r1 announces three prefixes, then "restarts" (sends Snap).
        // A peer that missed all the intermediate adds catches up
        // from the snap.
        let r1 = PrefixTable::new(name("/r1"));
        r1.announce_local(name("/a"), 1);
        r1.announce_local(name("/b"), 2);
        r1.announce_local(name("/c"), 3);
        let snap = r1.snap();

        let peer = PrefixTable::new(name("/peer"));
        // Peer had some stale state from a previous boot.
        peer.apply_op_list(&op_list("/r1", false, vec![("/old", 99)], vec![]));
        // Snap-driven catch-up: Reset clears /old, three Adds install /a/b/c.
        let changes = peer.apply_op_list(&snap);
        assert_eq!(changes.len(), 4); // /old removed + /a/b/c added
        assert_eq!(peer.prefixes_for_router(&name("/r1")).len(), 3);
    }
}
