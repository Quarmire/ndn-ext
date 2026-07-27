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
//! Two §2 sub-claims are DECIDED BUT UNACTUATED — the doctrine asserts an ephemeral *rotating*
//! source nonce and *nonce-keyed* per-neighbour RSSI, but the code ships a fixed source constant and
//! keys RSSI on `FaceId`. They are pinned below as `#[ignore]`d tests so the doctrine↔code drift is
//! tracked, not silently papered over.

use ndn_face_monitor_wifi::{
    DEFAULT_SRC, GroupKey, OPEN_GROUP_KEY, name_group, name_group_mac, prefix_key,
};

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

// ---- §2 DECIDED-BUT-UNACTUATED: pinned so the doctrine↔code drift is tracked, not hidden --------

/// §2 — the source field is supposed to be an EPHEMERAL, per-boot, ROTATING nonce (it buys per-frame
/// RSSI attribution, DoS attribution, and producer scoping). Today it is `DEFAULT_SRC`, a
/// compile-time constant that never rotates. When the nonce generator lands (in `ndn-frame-io`),
/// remove `#[ignore]` and assert two frames from one boot share a nonce that differs across
/// boots/rotations, and that no forwarder state keys on it.
#[test]
#[ignore = "doctrine §2: ephemeral rotating source nonce is decided but unactuated (src = DEFAULT_SRC constant)"]
fn source_nonce_rotates_per_boot() {
    unimplemented!("no per-boot rotating nonce exists yet; see mac-addressing-doctrine.md §2");
}

/// §2 — RSSI should be attributed PER NEIGHBOUR, keyed on the source nonce (a per-neighbour map, not
/// the ambient scalar the doctrine wants to replace). Today `LinkSignalStore` keys on `FaceId` and
/// discards the captured source address. When re-keyed, remove `#[ignore]` and assert two
/// `CapturedFrame`s with distinct `addr2` store distinct RSSI under distinct keys.
#[test]
#[ignore = "doctrine §2: nonce-keyed per-neighbour RSSI is decided but unactuated (keyed on FaceId)"]
fn rssi_is_attributed_per_source_nonce() {
    unimplemented!("RSSI is keyed on FaceId, not the source nonce; see mac-addressing-doctrine.md §2");
}
