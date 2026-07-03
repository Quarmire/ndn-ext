//! The sans-IO named-time runtime.
//!
//! [`Timekeeper`] is the state machine a host drives on a cadence: it collects
//! local-source readings and validated peer beacons, runs the `ndn-time`
//! discipline loop, and returns a [`TickOutcome`] telling the host what to
//! actuate — how to steer the clock, whether to write `NodeSignals.clock_ms`,
//! and whether to publish a fresh beacon. It performs no I/O itself, so it is
//! unit-testable with the mock/sim sources; the async SVS carriage and the
//! clock/`clock_ms` writes are the host's thin driver.
//!
//! The loop's key subtlety, handled here: the node's *own* clock is a trusted
//! input. Each local reading becomes a self-authenticated, distance-bounded
//! (it is local — no relay) sample, so a lone node with only its own GPS still
//! produces a fix and *tracks* it; peers merely refine it.

use ndn_time::provenance::PathId;
use ndn_time::{
    Authenticity, ClockCapability, Correction, Discipline, KeyId, Measured, MeasurementProvenance,
    PeerSample, TimePolicy, TimeState,
};
use ndn_time_sources::Reading;

/// The reserved peer slot for this node's own local-source readings — kept
/// distinct from any real peer id.
const SELF_PEER_ID: u64 = u64::MAX;

/// A beacon this node should publish under `/<scope>/time/<node>/<seq>`. The host
/// encodes it ([`crate::beacon_wire::encode`]), signs the Data, and publishes.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct OutboundBeacon {
    /// This node's id (the `<node>` name component).
    pub node_id: u64,
    /// The beacon sequence number.
    pub seq: u64,
    /// The corrected wall estimate to advertise, Unix ns.
    pub wall_ns: i64,
    /// The fix uncertainty to advertise (half-width), ns.
    pub uncertainty_ns: u64,
    /// This node's own clock capability.
    pub cap: ClockCapability,
}

/// What one [`Timekeeper::tick`] tells the host to do.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct TickOutcome {
    /// The combined fix (offset, uncertainty, skew, support, admitted).
    pub correction: Correction,
    /// How to steer the local clock (step/slew/track/withhold).
    pub discipline: Discipline,
    /// If `Some`, write this wall time (ms) to `NodeSignals.clock_ms`. `None`
    /// while withholding (fail-closed) — the caller leaves `clock_ms` unknown.
    pub clock_ms: Option<i64>,
    /// If `Some`, publish this beacon — emitted only when the fix tightened.
    pub beacon: Option<OutboundBeacon>,
}

/// The named-time runtime for one node.
pub struct Timekeeper {
    state: TimeState,
    policy: TimePolicy,
    node_id: u64,
    self_key: KeyId,
    local_cap: ClockCapability,
    seq: u64,
    has_prior_wall: bool,
    last_beaconed_uncertainty_ns: u64,
}

impl Timekeeper {
    /// A new runtime for `node_id`, whose own clock is `local_cap` and whose
    /// local readings are self-authenticated by `self_key`.
    pub fn new(
        node_id: u64,
        self_key: KeyId,
        local_cap: ClockCapability,
        policy: TimePolicy,
    ) -> Self {
        Self {
            state: TimeState::new(),
            policy,
            node_id,
            self_key,
            local_cap,
            seq: 0,
            has_prior_wall: false,
            last_beaconed_uncertainty_ns: u64::MAX,
        }
    }

    /// Provenance for this node's own local readings: local (so distance-bounded
    /// — no relay is possible on the node's own bus), replay-irrelevant, and
    /// authenticated by the node's own key.
    fn self_prov(&self) -> MeasurementProvenance {
        MeasurementProvenance {
            distance_bounded: true,
            replay_protected: true,
            authenticity: Authenticity::AuthenticatedDomainPeer(self.self_key),
            path: PathId(0),
        }
    }

    /// Feed a reading from a local time source (OS clock, GNSS, …). Stored as
    /// the node's own absolute wall belief, self-authenticated.
    pub fn ingest_local_reading(&mut self, reading: &Reading) {
        self.state.ingest(
            SELF_PEER_ID,
            PeerSample {
                wall: Measured {
                    value: reading.wall.center_ns,
                    sigma_ns: reading.wall.radius_ns,
                    prov: self.self_prov(),
                },
                captured_mono_ns: reading.captured_mono_ns,
                cap: reading.cap,
            },
        );
    }

    /// Feed a *validated* peer beacon (from [`crate::beacon_wire`] + the security
    /// layer). `peer_id` identifies the peer. Panics if `peer_id` is
    /// [`u64::MAX`] (reserved for local readings).
    pub fn ingest_beacon(&mut self, peer_id: u64, beacon: &ndn_time::TimeBeacon) {
        assert_ne!(
            peer_id, SELF_PEER_ID,
            "peer id u64::MAX is reserved for self"
        );
        self.state.ingest(peer_id, beacon.into_peer_sample());
    }

    /// Run one discipline pass. `now_mono_ns` is the monotonic clock (for aging
    /// and skew); `local_wall_ns` is the current wall reading being corrected.
    pub fn tick(&mut self, now_mono_ns: u64, local_wall_ns: i64) -> TickOutcome {
        let correction = self
            .policy
            .discipline(&mut self.state, local_wall_ns, now_mono_ns);
        let discipline = self
            .policy
            .act(&correction, &self.local_cap, self.has_prior_wall);

        // Actuation: the corrected wall (ms) to publish as clock_ms — withheld
        // while the fix is too uncertain; reported as-is while slewing.
        let clock_ms = match discipline {
            Discipline::Withhold { .. } => None,
            Discipline::Step { correction_ns } | Discipline::Track { correction_ns } => {
                Some(local_wall_ns.saturating_add(correction_ns) / 1_000_000)
            }
            Discipline::Slew { .. } => Some(local_wall_ns / 1_000_000),
        };

        // Re-beacon only when the fix tightened our advertised interval.
        let beacon = if self
            .policy
            .should_rebeacon(&correction, self.last_beaconed_uncertainty_ns)
        {
            self.seq += 1;
            self.last_beaconed_uncertainty_ns = correction.uncertainty_ns;
            Some(OutboundBeacon {
                node_id: self.node_id,
                seq: self.seq,
                wall_ns: local_wall_ns.saturating_add(correction.offset_ns),
                uncertainty_ns: correction.uncertainty_ns,
                cap: self.local_cap,
            })
        } else {
            None
        };

        if !matches!(discipline, Discipline::Withhold { .. }) {
            self.has_prior_wall = true;
        }
        TickOutcome {
            correction,
            discipline,
            clock_ms,
            beacon,
        }
    }

    /// The next beacon sequence number this node will use (for tests/telemetry).
    pub fn seq(&self) -> u64 {
        self.seq
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_time::TimeBeacon;
    use ndn_time::TimeInterval;
    use ndn_time_sources::Reading;

    fn reading(wall_ns: i64, unc: u64, cap: ClockCapability, mono: u64) -> Reading {
        Reading {
            wall: TimeInterval::new(wall_ns, unc),
            cap,
            captured_mono_ns: mono,
        }
    }

    #[test]
    fn lone_gnss_node_tracks_its_own_clock() {
        // A node whose only input is its own GPS: the self reading clears the
        // floor (local ⇒ distance-bounded, self-authenticated), and a GNSS clock
        // is a reference ⇒ Track (not steered).
        let mut tk = Timekeeper::new(
            1,
            KeyId(1),
            ClockCapability::gnss_disciplined(),
            TimePolicy::default(),
        );
        let local_wall = 1_700_000_000_000;
        // GPS reads +30 ns ahead of the local wall.
        tk.ingest_local_reading(&reading(
            local_wall + 30,
            30,
            ClockCapability::gnss_disciplined(),
            0,
        ));
        let out = tk.tick(0, local_wall);
        assert!(out.correction.admitted, "own trusted clock founds a fix");
        assert!(
            matches!(out.discipline, Discipline::Track { .. }),
            "a reference clock is tracked, got {:?}",
            out.discipline
        );
        assert!(out.clock_ms.is_some());
        assert!(out.beacon.is_some(), "first admitted fix beacons");
    }

    #[test]
    fn steerable_node_with_a_peer_steps_then_slews() {
        // An OS-clock node (disciplinable) with a tight authenticated peer beacon.
        let mut tk = Timekeeper::new(
            2,
            KeyId(2),
            ClockCapability::oscillator_tcxo(),
            TimePolicy::default(),
        );
        let local_wall = 1_700_000_000_000;
        // A peer 300 µs ahead (sub-threshold) with a tight GPS. Fresh each tick,
        // as the real loop re-ingests every round.
        let peer = |mono| TimeBeacon {
            wall: TimeInterval::new(local_wall + 300_000, 50_000),
            cap: ClockCapability::gnss_disciplined(),
            captured_mono_ns: mono,
            prov: MeasurementProvenance {
                distance_bounded: false,
                replay_protected: true,
                authenticity: Authenticity::AuthenticatedDomainPeer(KeyId(99)),
                path: PathId(7),
            },
        };
        // Bootstrap: first tick steps.
        tk.ingest_local_reading(&reading(
            local_wall,
            5_000_000,
            ClockCapability::oscillator_tcxo(),
            0,
        ));
        tk.ingest_beacon(99, &peer(0));
        let first = tk.tick(0, local_wall);
        assert!(first.correction.admitted);
        assert!(
            matches!(first.discipline, Discipline::Step { .. }),
            "bootstrap steps, got {:?}",
            first.discipline
        );
        // Second tick, fresh samples, prior wall: the sub-threshold offset slews.
        tk.ingest_local_reading(&reading(
            local_wall,
            5_000_000,
            ClockCapability::oscillator_tcxo(),
            1_000_000,
        ));
        tk.ingest_beacon(99, &peer(1_000_000));
        let second = tk.tick(1_000_000, local_wall);
        assert!(
            matches!(second.discipline, Discipline::Slew { .. }),
            "ongoing slews, got {:?}",
            second.discipline
        );
    }

    #[test]
    fn a_too_uncertain_node_withholds_and_does_not_beacon() {
        // Tight required uncertainty; a loose-only clock cannot meet it.
        let policy = TimePolicy {
            required_uncertainty_ns: 1_000, // 1 µs, unmeetable by a 100 ms clock
            ..TimePolicy::default()
        };
        let mut tk = Timekeeper::new(3, KeyId(3), ClockCapability::esp32_rc(), policy);
        let local_wall = 1_700_000_000_000;
        tk.ingest_local_reading(&reading(
            local_wall,
            100_000_000,
            ClockCapability::esp32_rc(),
            0,
        ));
        let out = tk.tick(0, local_wall);
        assert!(
            matches!(out.discipline, Discipline::Withhold { .. }),
            "too uncertain to act"
        );
        assert!(out.clock_ms.is_none(), "clock_ms withheld — fail-closed");
    }

    #[test]
    fn seq_advances_only_when_beaconing() {
        let mut tk = Timekeeper::new(
            4,
            KeyId(4),
            ClockCapability::gnss_disciplined(),
            TimePolicy::default(),
        );
        let local_wall = 1_700_000_000_000;
        tk.ingest_local_reading(&reading(
            local_wall,
            30,
            ClockCapability::gnss_disciplined(),
            0,
        ));
        let a = tk.tick(0, local_wall);
        assert!(a.beacon.is_some());
        assert_eq!(tk.seq(), 1);
        // Same (not-tighter) fix: no new beacon, seq unchanged.
        tk.ingest_local_reading(&reading(
            local_wall,
            30,
            ClockCapability::gnss_disciplined(),
            1_000,
        ));
        let b = tk.tick(1_000, local_wall);
        assert!(b.beacon.is_none(), "no tightening ⇒ no beacon");
        assert_eq!(tk.seq(), 1);
    }
}
