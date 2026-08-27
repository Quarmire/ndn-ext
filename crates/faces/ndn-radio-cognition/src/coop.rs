//! Cooperative-forwarding projection (task #45): how a node's relay filter *forms*
//! and how multi-hop Interest/Data propagate on an ad-hoc broadcast mesh with **no
//! routing server, no association, no host identity** — the other half of the
//! "removing MAC addresses breaks forwarding" objection (see
//! `ndn-face-monitor-wifi/docs/mac-addressing-doctrine.md` §4).
//!
//! ## The FIB-formation question, and the three models
//!
//! A relay must hear traffic it neither consumes nor produces. Its receive filter is
//! keyed on its *roles* — `consumer ∪ producer/cache ∪ FIB-prefixes ∪ pending-PIT` —
//! so a relay's filter is deliberately broader than a leaf's. The open question is
//! how the FIB / relay-prefix set forms with no infrastructure:
//!
//! - **(a) structured routing** — a protocol floods prefix announcements, every node
//!   builds `prefix → nexthop`. Efficient on a *stable* topology, but heavy
//!   (convergence, periodic churn under mobility) and a "nexthop" is degenerate on a
//!   broadcast medium where the ether *is* the only face.
//! - **(b) reactive / demand-driven** — no FIB. A node listens for Interests within a
//!   trust *scope*, rebroadcasts ones it can help with (CCLF-suppressed), and the PIT
//!   breadcrumb is the return path. Zero config, mobility-robust, broadcast-native;
//!   costs flooding, bounded by scope + CCLF + hop-limit.
//! - **(c) contribution-anchored** — a node advertises relay capability *by name*
//!   (`/can-serve/x`), peers form soft gradients toward it. The named-radio thesis
//!   applied to forwarding, and the power dial made explicit (decline = don't
//!   advertise). But it needs a bootstrap (to advertise a path you must first know one)
//!   — it is really an *optimisation layer over (b)*, and ties the anchoring/election
//!   work.
//!
//! These are a spectrum of *how much state you spend to avoid flooding*. This module
//! prototypes **(b)** as the baseline, because it always works (no convergence, no
//! bootstrap), it is what (a) and (c) refine, and it composes directly with the CCLF
//! suppression already in [`RadioPolicy`](crate::RadioPolicy) and the name-group
//! receive filter. The **scope** a node volunteers is the cooperation-vs-power dial:
//! empty = pure leaf that relays nothing; broad = backbone.
//!
//! What this module is: the reactive relay *state machine* — the ephemeral PIT
//! projection, CCLF timer-suppression (jittered rebroadcast + overhear-cancel), the
//! reverse-path, and scope bounding. What it is not: on-air multi-hop (needs ≥3
//! spatially-separated radios); the tests drive it over a modelled broadcast+adjacency
//! medium.

use std::collections::HashMap;

/// A routable prefix hash (coarse — what Interest reception filters on).
pub type Prefix = u32;
/// A full-name hash (fine — what pending-PIT Data reception filters on).
pub type Name = u64;

/// Which way a pending forward points.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dir {
    /// An Interest pending rebroadcast *toward the producer*.
    Interest,
    /// A Data pending forward *back toward the consumer* (created by a PIT match).
    Data,
}

/// The prefix a name falls under (top 32 bits). A real system hashes the routable
/// prefix component; here it is a fixed split so tests can compose names by hand.
pub fn prefix_of(name: Name) -> Prefix {
    (name >> 32) as u32
}

/// One ephemeral forwarding intent — the link-layer PIT projection. Soft state: its
/// loss costs a retransmit, never correctness.
#[derive(Clone, Copy, Debug)]
struct Pending {
    dir: Dir,
    /// CCLF rebroadcast time = arrival + this node's jitter. The best-placed node has
    /// the least jitter, fires first, and the rest overhear and cancel.
    fire_at: u64,
    /// An overheard duplicate cancelled our scheduled (re)broadcast.
    suppressed: bool,
    /// We have already put it on air (don't fire twice, and it is now a breadcrumb).
    done: bool,
}

/// A cooperative relay's projection of the forwarder onto the broadcast medium.
pub struct CoopRelay {
    /// Prefixes this node volunteers to relay for — its trust scope / the
    /// cooperation-vs-power dial. Interests outside it are heard and **ignored**.
    scope: Vec<Prefix>,
    /// The PIT projection, keyed by full name. An Interest entry becomes a Data entry
    /// on the return (the breadcrumb); entries expire (`purge`) so the filter self-cleans.
    pending: HashMap<Name, Pending>,
    /// Deterministic CCLF jitter for this node (a stand-in for link/position quality —
    /// lower = better-placed = wins the election). Real systems derive it from
    /// rank-deficit / RSSI (see `RadioPolicy`); here it is injected so tests are
    /// reproducible.
    jitter: u64,
    /// Entry lifetime.
    ttl: u64,
    /// Instrumentation: names this node actually put on air (for tests/metrics).
    pub emitted: Vec<(Name, Dir)>,
}

impl CoopRelay {
    pub fn new(scope: Vec<Prefix>, jitter: u64, ttl: u64) -> Self {
        Self {
            scope,
            pending: HashMap::new(),
            jitter,
            ttl,
            emitted: Vec::new(),
        }
    }

    /// The trust scope — the prefixes this node relays for. Setting it wider is
    /// volunteering more cooperation (and more receive/CPU cost); empty is a pure leaf.
    pub fn set_scope(&mut self, scope: Vec<Prefix>) {
        self.scope = scope;
    }

    fn in_scope(&self, name: Name) -> bool {
        self.scope.contains(&prefix_of(name))
    }

    /// Receive an Interest. Out-of-scope → ignored (the node hears it but does not
    /// relay — this is what bounds "listen to everything"). In-scope and new →
    /// schedule a CCLF-jittered rebroadcast and drop a PIT breadcrumb. In-scope and
    /// already pending → in-air aggregation: someone downstream already wants it, so
    /// we do not add a second timer (the medium performs the PIT aggregation).
    pub fn rx_interest(&mut self, name: Name, now: u64) {
        if !self.in_scope(name) {
            return;
        }
        if self.pending.contains_key(&name) {
            return; // aggregate: already pending
        }
        self.pending.insert(
            name,
            Pending {
                dir: Dir::Interest,
                fire_at: now + self.jitter,
                suppressed: false,
                done: false,
            },
        );
    }

    /// Receive a Data. A PIT match (we have a pending/forwarded Interest for it) turns
    /// the breadcrumb into a Data-return scheduled back toward the consumer,
    /// CCLF-suppressed like the Interest was. **Unsolicited Data — no matching PIT
    /// entry — is dropped** (the doctrine's DoS gate: you only carry Data you relayed
    /// an Interest for).
    pub fn rx_data(&mut self, name: Name, now: u64) {
        match self.pending.get(&name) {
            Some(_) => {
                self.pending.insert(
                    name,
                    Pending {
                        dir: Dir::Data,
                        fire_at: now + self.jitter,
                        suppressed: false,
                        done: false,
                    },
                );
            }
            None => { /* unsolicited: drop */ }
        }
    }

    /// Overhear another node put `(name, dir)` on air. If we had the same forward
    /// scheduled and not yet sent, cancel it — CCLF duplicate suppression. (An
    /// overheard Data matching a pending Interest also implicitly satisfies it.)
    pub fn overhear(&mut self, name: Name, dir: Dir) {
        if let Some(p) = self.pending.get_mut(&name)
            && !p.done
            && (p.dir == dir || dir == Dir::Data)
        {
            p.suppressed = true;
        }
    }

    /// Advance to `now`: emit every pending forward whose timer has fired and was not
    /// suppressed. Returns what goes on air (the caller/medium broadcasts it).
    pub fn tick(&mut self, now: u64) -> Vec<(Name, Dir)> {
        let mut out = Vec::new();
        for (&name, p) in self.pending.iter_mut() {
            if !p.done && !p.suppressed && p.fire_at <= now {
                p.done = true;
                out.push((name, p.dir));
                self.emitted.push((name, p.dir));
            }
        }
        out
    }

    /// Drop breadcrumbs older than the TTL (self-cleaning filter). `created` tracking
    /// is folded into `fire_at` for the prototype: an entry is stale `ttl` after it
    /// would have fired.
    pub fn purge(&mut self, now: u64) {
        let ttl = self.ttl;
        self.pending.retain(|_, p| now < p.fire_at + ttl);
    }

    /// Pending-entry count (the fine Data filter's width right now).
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// Drop the entire PIT projection — models soft-state loss (a crash, an eviction, a deliberate
    /// recompile). Per the §7 invariant of the MAC-addressing doctrine this must only cost
    /// *performance*: live demand (re-expressed Interests) rebuilds it, and no in-flight loss can
    /// corrupt state or mis-deliver. The `pit_projection_is_soft_state` test exercises exactly that.
    pub fn clear_projection(&mut self) {
        self.pending.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A modelled broadcast medium with adjacency: a frame from node `i` is heard by
    /// exactly `i`'s neighbours (spatial multi-hop, unlike the full-mesh loopback bus).
    /// Roles: a Consumer emits the Interest and records the Data; a Producer answers a
    /// matching Interest with Data; Relays run [`CoopRelay`].
    enum Role {
        Consumer {
            want: Name,
            got_data_at: Option<u64>,
        },
        Producer {
            prefix: Prefix,
        },
        Relay,
    }

    struct Node {
        relay: CoopRelay,
        role: Role,
        /// Data the producer role owes on air next tick (name).
        produce: Option<Name>,
    }

    struct Mesh {
        nodes: Vec<Node>,
        adj: Vec<Vec<usize>>, // adj[i] = who hears i
    }

    impl Mesh {
        fn run(&mut self, ticks: u64) {
            for t in 0..ticks {
                // 1. Collect this tick's emissions (relays' fired timers + producer Data + the
                //    consumer's t=0 Interest).
                let mut air: Vec<(usize, Name, Dir)> = Vec::new();
                for (i, n) in self.nodes.iter_mut().enumerate() {
                    for (name, dir) in n.relay.tick(t) {
                        air.push((i, name, dir));
                    }
                    if let Some(name) = n.produce.take() {
                        air.push((i, name, Dir::Data));
                        n.relay.emitted.push((name, Dir::Data));
                    }
                    if let Role::Consumer { want, got_data_at } = &n.role
                        && t == 0
                        && got_data_at.is_none()
                    {
                        air.push((i, *want, Dir::Interest));
                    }
                }
                // 2. Deliver each emission to the emitter's neighbours.
                for &(src, name, dir) in &air {
                    for &j in &self.adj[src] {
                        // Overhear-suppress first (a neighbour that had the same forward pending).
                        self.nodes[j].relay.overhear(name, dir);
                        match dir {
                            Dir::Interest => {
                                let answer = matches!(&self.nodes[j].role, Role::Producer { prefix } if *prefix == prefix_of(name));
                                if answer {
                                    // Producer answers next tick (origin Data).
                                    if self.nodes[j].produce.is_none() {
                                        self.nodes[j].produce = Some(name);
                                    }
                                } else {
                                    self.nodes[j].relay.rx_interest(name, t);
                                }
                            }
                            Dir::Data => {
                                if let Role::Consumer { want, got_data_at } =
                                    &mut self.nodes[j].role
                                    && *want == name
                                    && got_data_at.is_none()
                                {
                                    *got_data_at = Some(t);
                                } else {
                                    self.nodes[j].relay.rx_data(name, t);
                                }
                            }
                        }
                    }
                }
            }
        }

        fn consumer_got(&self, i: usize) -> Option<u64> {
            match &self.nodes[i].role {
                Role::Consumer { got_data_at, .. } => *got_data_at,
                _ => None,
            }
        }
    }

    const XY: Name = (1u64 << 32) | 7; // prefix /x = 1, suffix 7
    const SCOPE_X: Prefix = 1;

    fn relay(jitter: u64) -> CoopRelay {
        CoopRelay::new(vec![SCOPE_X], jitter, 1000)
    }

    /// Multi-hop: C — R1 — R2 — P (a line; C cannot hear P). The Interest must be
    /// relayed twice to reach P, and the Data must return along the PIT breadcrumbs.
    #[test]
    fn interest_reaches_producer_two_hops_and_data_returns() {
        let mut mesh = Mesh {
            nodes: vec![
                Node {
                    relay: relay(9),
                    role: Role::Consumer {
                        want: XY,
                        got_data_at: None,
                    },
                    produce: None,
                }, // 0 C
                Node {
                    relay: relay(1),
                    role: Role::Relay,
                    produce: None,
                }, // 1 R1
                Node {
                    relay: relay(1),
                    role: Role::Relay,
                    produce: None,
                }, // 2 R2
                Node {
                    relay: relay(9),
                    role: Role::Producer { prefix: SCOPE_X },
                    produce: None,
                }, // 3 P
            ],
            adj: vec![vec![1], vec![0, 2], vec![1, 3], vec![2]], // C<->R1<->R2<->P
        };
        mesh.run(30);
        let got = mesh.consumer_got(0);
        assert!(
            got.is_some(),
            "consumer must receive the Data via two relays"
        );
        // Both relays must have carried it in each direction (4 emissions total).
        assert!(mesh.nodes[1].relay.emitted.contains(&(XY, Dir::Interest)));
        assert!(mesh.nodes[2].relay.emitted.contains(&(XY, Dir::Interest)));
        assert!(mesh.nodes[1].relay.emitted.contains(&(XY, Dir::Data)));
        assert!(mesh.nodes[2].relay.emitted.contains(&(XY, Dir::Data)));
    }

    /// CCLF suppression: two candidate relays R1, R1' both hear C and R2. The one with
    /// the smaller jitter fires first; the other overhears and cancels — exactly one
    /// rebroadcasts the Interest, not both.
    #[test]
    fn redundant_relays_are_cclf_suppressed() {
        let mut mesh = Mesh {
            nodes: vec![
                Node {
                    relay: relay(9),
                    role: Role::Consumer {
                        want: XY,
                        got_data_at: None,
                    },
                    produce: None,
                }, // 0 C
                Node {
                    relay: relay(2),
                    role: Role::Relay,
                    produce: None,
                }, // 1 R1  (wins)
                Node {
                    relay: relay(5),
                    role: Role::Relay,
                    produce: None,
                }, // 2 R1' (suppressed)
                Node {
                    relay: relay(1),
                    role: Role::Relay,
                    produce: None,
                }, // 3 R2
                Node {
                    relay: relay(9),
                    role: Role::Producer { prefix: SCOPE_X },
                    produce: None,
                }, // 4 P
            ],
            // C heard by R1,R1'; R1 and R1' heard by C,R2 (and each other); R2 by R1,R1',P.
            adj: vec![
                vec![1, 2],
                vec![0, 2, 3],
                vec![0, 1, 3],
                vec![1, 2, 4],
                vec![3],
            ],
        };
        mesh.run(30);
        assert!(mesh.consumer_got(0).is_some(), "consumer still gets Data");
        let r1 = mesh.nodes[1].relay.emitted.contains(&(XY, Dir::Interest));
        let r1p = mesh.nodes[2].relay.emitted.contains(&(XY, Dir::Interest));
        assert!(
            r1 && !r1p,
            "exactly the better-placed relay forwards the Interest (CCLF)"
        );
    }

    /// Scope bounds cooperation: a node hears the Interest but its trust scope does not
    /// cover the prefix, so it never relays — the receive filter is roles, not ambient,
    /// and the width is a choice.
    #[test]
    fn out_of_scope_node_hears_but_does_not_relay() {
        let mut n = CoopRelay::new(vec![2 /* /z, not /x */], 1, 1000);
        n.rx_interest(XY, 0); // hears /x/y
        let fired = n.tick(5);
        assert!(
            fired.is_empty(),
            "out-of-scope Interest is heard but not relayed"
        );
        assert_eq!(
            n.pending_len(),
            0,
            "no forwarding state created for out-of-scope names"
        );
    }

    /// Unsolicited Data (no matching pending Interest) is dropped — the DoS gate, and
    /// the reason a flood of Data you did not ask for costs nothing past the filter.
    #[test]
    fn unsolicited_data_is_dropped() {
        let mut n = relay(1);
        n.rx_data(XY, 0); // no pending Interest for XY
        assert!(n.tick(5).is_empty());
        assert_eq!(n.pending_len(), 0);
    }

    /// **Doctrine §7 — the keystone invariant.** Everything below the network layer is soft state: a
    /// projection the forwarder can recompile at any time, whose loss costs *performance*, never
    /// *correctness*. Wipe the PIT projection mid-flight and show both halves of that claim: the
    /// in-flight Data round is lost (the performance cost) but nothing is mis-delivered, and a
    /// re-expressed Interest recompiles the breadcrumb so forwarding resumes (correctness preserved).
    #[test]
    fn pit_projection_is_soft_state_loss_costs_performance_not_correctness() {
        let mut r = relay(1);

        // Baseline: an Interest lays a breadcrumb, so the returning Data is forwarded.
        r.rx_interest(XY, 0);
        let _ = r.tick(5); // relay the Interest
        r.rx_data(XY, 6);
        assert!(
            r.tick(10).contains(&(XY, Dir::Data)),
            "with the breadcrumb, Data is forwarded"
        );

        // Soft-state LOSS: the whole projection is wiped (crash / eviction / recompile).
        r.clear_projection();
        assert_eq!(r.pending_len(), 0, "projection gone");

        // PERFORMANCE cost: Data arriving now has no breadcrumb → dropped as unsolicited. That round
        // is wasted — but it is NOT a correctness failure: nothing is forwarded wrongly.
        r.rx_data(XY, 20);
        assert!(
            r.tick(25).is_empty(),
            "post-loss Data is dropped (perf cost), never mis-forwarded"
        );

        // CORRECTNESS preserved: a re-expressed Interest recompiles the projection from live demand,
        // and forwarding resumes exactly as before the loss.
        r.rx_interest(XY, 30);
        let _ = r.tick(35);
        r.rx_data(XY, 36);
        assert!(
            r.tick(40).contains(&(XY, Dir::Data)),
            "the projection recompiled from re-expressed demand; Data flows again"
        );
    }

    /// **Doctrine §4 — the receive filter is *roles*, and its width is a soft-state choice.** The
    /// scope (name-group filter) is itself recomputable: drop a prefix and the node stops relaying
    /// for it (a deliberate narrowing / a lost filter entry — performance), re-add it and relaying
    /// resumes. No correctness depends on the filter persisting.
    #[test]
    fn scope_filter_is_soft_state_and_recompilable() {
        let mut r = relay(1); // scope = {/x}
        r.set_scope(vec![]); // lose the filter set (leaf node / eviction)
        r.rx_interest(XY, 0);
        assert!(
            r.tick(5).is_empty(),
            "with no scope, the Interest is heard but not relayed"
        );
        assert_eq!(r.pending_len(), 0, "no forwarding state without the role");

        r.set_scope(vec![SCOPE_X]); // recompile the filter from roles
        r.rx_interest(XY, 10);
        assert!(
            r.tick(15).contains(&(XY, Dir::Interest)),
            "filter recompiled; relaying resumes"
        );
    }
}
