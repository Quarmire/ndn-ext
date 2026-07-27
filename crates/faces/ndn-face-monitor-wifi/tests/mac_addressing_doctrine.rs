//! Doctrine validation — asserts the falsifiable claims of `docs/mac-addressing-doctrine.md` against
//! the real link-layer primitives. Each test cites the doctrine section it vindicates.
//!
//! Claims proven deeper elsewhere (not duplicated here, cited for the map):
//!   • §8 hash internals — SipHash-2-4 reference vector + flat-46-bit vs split-24-bit collision
//!     behaviour: `ndn-frame-io/src/frame.rs` tests (`siphash24_reference_vector`, …).
//!   • §3/§4 cooperative forwarding + CCLF suppression + §3.2 PIT-gated DoS drop + §7 soft-state
//!     invariant: `ndn-radio-cognition/src/coop.rs` tests (`interest_reaches_producer_two_hops…`,
//!     `redundant_relays_are_cclf_suppressed`, `unsolicited_data_is_dropped`,
//!     `pit_projection_is_soft_state_loss_costs_performance_not_correctness`, …).
//!
//! The two §2 sub-claims that were once decided-but-unactuated are now ACTUATED and asserted here:
//! the ephemeral *rotating* source nonce (`EphemeralSource`, stamped in the TX path) and the
//! *nonce-keyed* per-neighbour RSSI map (`LinkSignalStore::set_source_link`, fed by the live RX path).

use ndn_face_monitor_wifi::{
    DEFAULT_SRC, EphemeralSource, GroupKey, LinkSignalStore, OPEN_GROUP_KEY, name_group,
    name_group_mac, prefix_key,
};
use ndn_signals_core::{LinkSignals, SignalStore, SignalView};

/// §0/§2 — the DESTINATION field carries a name-group hash: a locally-administered *multicast*
/// address ("the name is the group address"), derived from the name, never a host MAC.
#[test]
fn dst_is_a_name_group_multicast_not_a_host_mac() {
    let a = name_group_mac(&OPEN_GROUP_KEY, b"/sensor/temp");
    // Local multicast: I/G (group) bit set, U/L (locally administered) bit set.
    assert_eq!(a[0] & 0x01, 0x01, "I/G group bit set — a multicast (group) address");
    assert_eq!(a[0] & 0x02, 0x02, "U/L local bit set — locally administered, not a vendor host MAC");
    // The name determines the group: a different name → a different group address.
    let b = name_group_mac(&OPEN_GROUP_KEY, b"/sensor/humidity");
    assert_ne!(a, b, "the address is derived from the name (the name IS the group)");
}

/// §0/§2 — no host identity in the SOURCE field. What ships today is an inert, locally-administered
/// *individual* tag (`DEFAULT_SRC`), provably NOT a globally-unique host MAC: U/L=local means it is
/// explicitly not a manufacturer-assigned address, and nothing in the forwarder keys routing on it
/// (the `CoopRelay` keys purely on `Name` — see `ndn-radio-cognition/src/coop.rs`).
#[test]
fn src_is_an_inert_local_tag_not_a_globally_unique_host_mac() {
    assert_eq!(DEFAULT_SRC[0] & 0x02, 0x02, "locally administered (U/L) — not a vendor/host MAC");
    assert_eq!(DEFAULT_SRC[0] & 0x01, 0x00, "individual (not multicast) — it is a source address");
}

/// §8 — the name-hash is KEYED (SipHash-2-4): the same name under a different `GroupKey` lands in a
/// different group, so an outsider cannot compute (or target) a private group's pre-parse filter.
#[test]
fn keying_scopes_a_private_group_doctrine_s8() {
    let name = b"/fleet/telemetry";
    let open = name_group_mac(&OPEN_GROUP_KEY, name);
    let private = name_group_mac(&GroupKey(*b"a-shared-secret!"), name);
    assert_ne!(open, private, "a private GroupKey yields an unlinkable, outsider-unforgeable group");
}

/// §8 — split addressing: Interests filter coarsely on the routable PREFIX (one aggregatable entry),
/// Data finely on the full name. `name_group` packs H(prefix)‖H(full); `prefix_key` masks the low
/// bytes, so a relay matches a whole family with one entry while consumers discriminate full names.
#[test]
fn prefix_aggregation_matches_a_family_doctrine_s8() {
    let prefix = b"/x";
    let a = name_group(&OPEN_GROUP_KEY, prefix, b"/x/a", true);
    let b = name_group(&OPEN_GROUP_KEY, prefix, b"/x/b", true);
    assert_ne!(a, b, "full-name addresses within a prefix are distinct (the fine Data filter)");
    assert_eq!(prefix_key(a), prefix_key(b), "same routable prefix → one aggregatable filter entry");
}

// ---- §2 NOW ACTUATED (was decided-but-unactuated; commit made both real) ------------------------

/// §2 — the source field is now an EPHEMERAL, per-boot, ROTATING nonce (`EphemeralSource`), no longer
/// the fixed `DEFAULT_SRC` constant. It is locally-administered + individual (inert to real networks,
/// never a host MAC), stable within a rotation period (so a receiver can attribute a burst's RSSI to
/// one neighbour), and differs across periods and boots (bounded linkability, no persistent identity).
#[test]
fn source_nonce_rotates_per_boot() {
    let boot = EphemeralSource::new(0xA5A5_1234, 60_000); // 60 s rotation
    let n0 = boot.current(0);
    assert_eq!(n0[0] & 0x02, 0x02, "locally administered — not a globally-unique host MAC");
    assert_eq!(n0[0] & 0x01, 0x00, "individual — it is a source address");
    assert_eq!(n0, boot.current(59_999), "stable within one rotation period");
    assert_ne!(n0, boot.current(60_000), "rotates into the next period");
    assert_ne!(n0, EphemeralSource::new(0x0000_9999, 60_000).current(0), "differs across boots");
    assert_ne!(n0, DEFAULT_SRC, "no longer the fixed DEFAULT_SRC constant");
}

/// §2 — RSSI is now attributed PER NEIGHBOUR, keyed on the source nonce: `LinkSignalStore` keeps a
/// per-source map (`set_source_link`/`source_link`/`neighbours`) alongside the per-face one, so two
/// neighbours heard on one radio get distinct RSSI — the per-neighbour map the doctrine wants for
/// CCLF density / macro-diversity, in place of an ambient per-face scalar. The live RX path calls
/// `set_source_link(f.addr, ..)` for every captured frame (medium.rs).
#[test]
fn rssi_is_attributed_per_source_nonce() {
    let store = LinkSignalStore::new();
    let a = [0x02, 1, 1, 1, 1, 1];
    let b = [0x02, 2, 2, 2, 2, 2];
    store.set_source_link(a, LinkSignals { rssi_dbm: Some(-40), ..LinkSignals::default() });
    store.set_source_link(b, LinkSignals { rssi_dbm: Some(-80), ..LinkSignals::default() });
    assert_eq!(store.source_link(a).and_then(|s| s.rssi_dbm), Some(-40));
    assert_eq!(
        store.source_link(b).and_then(|s| s.rssi_dbm),
        Some(-80),
        "distinct neighbours → distinct RSSI (per-neighbour map, not an ambient scalar)"
    );
    assert!(store.source_link([0x02, 9, 9, 9, 9, 9]).is_none(), "unknown neighbour → no signal");
    assert_eq!(store.neighbours().len(), 2, "both neighbours visible in the per-source map");
}
