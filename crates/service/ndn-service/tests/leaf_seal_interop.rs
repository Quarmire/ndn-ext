//! Interop witness: the embedded leaf's `ScopeKey` (in `ndn-service-core`,
//! `no_std`) and the full node's `ContentKey` (in `ndn-security`) share a wire
//! envelope, so a sealed publication crosses the leaf↔gateway boundary unchanged.
//!
//! This is what "aligned the `ScopeKey` seal envelope with `ContentKey`" means
//! concretely: a leaf seals with a sequence-derived nonce and no RNG; a gateway
//! opens the *same bytes* with `ContentKey` (random-nonce code path), because the
//! nonce rides on the wire and both bind the publication name as AAD.

use ndn_packet::Name;
use ndn_security::confidentiality::{ContentKey, Sealed};
use ndn_service_core::publish::{Publisher, ScopeKey};
use ndn_service_core::Frame;

fn name(s: &str) -> Name {
    s.parse().unwrap()
}

#[test]
fn leaf_scopekey_seal_opens_under_contentkey() {
    let raw = [9u8; 32];
    let leaf = ScopeKey::from_bytes(raw);

    let n = name("/sensor/lab-3/secure").append_sequence_num(7);
    let aad = n.encode_to_tlv();

    // Leaf seals (seq 7 -> derived nonce, no RNG).
    let on_air = leaf.seal(7, &aad, b"telemetry frame 42");

    // The gateway parses the leaf bytes as ndn-security's `Sealed` and opens with
    // `ContentKey` — proving the envelope is byte-identical.
    let sealed = Sealed::from_bytes(&on_air).expect("leaf bytes parse as ContentKey Sealed");
    let gateway_key = ContentKey::from_bytes(raw);
    let plain = gateway_key
        .open(&sealed, &aad)
        .expect("ContentKey opens the leaf's seal");
    assert_eq!(plain, b"telemetry frame 42");
}

#[test]
fn contentkey_seal_opens_under_leaf_scopekey() {
    let raw = [3u8; 32];
    let gateway_key = ContentKey::from_bytes(raw);
    let leaf = ScopeKey::from_bytes(raw);

    let aad = name("/svc/topic").encode_to_tlv();

    // The gateway seals with a random nonce; the leaf opens it (reads the nonce off
    // the wire), so command/config flowing *to* the leaf works the same way.
    let sealed = gateway_key.seal(b"setpoint=21.5", &aad);
    let opened = leaf
        .open(&aad, &sealed.to_bytes())
        .expect("leaf ScopeKey opens a ContentKey seal");
    assert_eq!(opened, b"setpoint=21.5");
}

#[test]
fn end_to_end_publisher_to_contentkey() {
    // The full leaf path: a `Publisher` (which binds the name as AAD itself) emits a
    // sealed publication; a gateway reconstructs the AAD from the name and opens it.
    #[derive(Clone, PartialEq, Debug)]
    struct Reading(i32);
    impl Frame for Reading {
        fn encode(&self) -> bytes::Bytes {
            self.0.encode()
        }
        fn decode(b: &[u8]) -> Result<Self, ndn_service_core::ServiceError> {
            Ok(Reading(i32::decode(b)?))
        }
    }

    let raw = [42u8; 32];
    let mut sensor = Publisher::<Reading>::sealed(name("/sensor/x"), ScopeKey::from_bytes(raw));
    let pubn = sensor.build(&Reading(213));

    // Gateway side: AAD is the publication's own name; open with ContentKey, decode.
    let aad = pubn.name.encode_to_tlv();
    let sealed = Sealed::from_bytes(&pubn.payload).unwrap();
    let plain = ContentKey::from_bytes(raw).open(&sealed, &aad).unwrap();
    assert_eq!(Reading::decode(&plain).unwrap(), Reading(213));

    // Wrong AAD (a different name) must fail — the name binding is authenticated.
    let wrong_aad = name("/sensor/y").encode_to_tlv();
    assert!(ContentKey::from_bytes(raw).open(&sealed, &wrong_aad).is_err());
}
