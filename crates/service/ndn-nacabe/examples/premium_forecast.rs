//! NAC-ABE in miniature, in the weather domain used by the service-layer
//! examples: a **premium** forecast is sealed under an attribute, and only a
//! subscriber the authority issued a *satisfying* key to can read it.
//!
//! It shows the three NAC-ABE moves: the authority issues an attribute key sealed
//! to a subscriber; a publisher seals content under attributes via the content-key
//! (CK) indirection; a holder of a satisfying key opens it — others fail closed.
//!
//! Run: `cargo run -p ndn-nacabe --example premium_forecast`

use ndn_foundation_types::Hash;
use ndn_nacabe::{KpAuthority, open_kp, open_kp_dkey, seal_kp};
use ndn_packet::Name;
use ndn_sealed_box::Recipient;
use ndn_security::abe::{KpPolicyKey, PolicyExpr, lsw_setup};

fn n(s: &str) -> Name {
    s.parse().unwrap()
}

/// The authority issues `identity`'s key, sealed to a fresh X25519 recipient key,
/// and the subscriber opens it — the over-the-wire DKEY delivery in miniature.
fn issue_to(authority: &KpAuthority, identity: &Name) -> KpPolicyKey {
    let recipient = Recipient::generate().unwrap();
    let sealed = authority.issue_dkey(identity, &recipient.public).unwrap();
    open_kp_dkey(recipient, &sealed).unwrap()
}

fn main() {
    // The attribute authority holds the KP-ABE master keys.
    let (mp, ms) = lsw_setup().unwrap();
    let mut authority = KpAuthority::new(mp.clone(), ms);

    // Enroll two subscribers with key-policies — what attributes their key satisfies.
    authority.grant(n("/sub/alice"), PolicyExpr::parse("tier:premium OR tier:pro").unwrap());
    authority.grant(n("/sub/bob"), PolicyExpr::parse("tier:free").unwrap());

    // A publisher seals a premium forecast under the `tier:premium` attribute. CK
    // indirection: a fresh content key encrypts the text; the CK is ABE-wrapped.
    let kgc = (n("/wx/authority"), Hash::of(&mp.public_key_bytes), mp);
    let aad = b"/wx/premium/2026-06-19";
    let (ck, ct) = seal_kp(
        n("/wx/CK/1"),
        &["tier:premium".to_string()],
        &kgc,
        b"Premium: clear skies, high 31C, low 22C",
        aad,
    )
    .unwrap();
    println!("publisher sealed a premium forecast under attribute `tier:premium`");

    // Alice's key (tier:premium OR tier:pro) satisfies the policy and opens it.
    let alice = issue_to(&authority, &n("/sub/alice"));
    let plain = open_kp(&ck, &alice, &ct, aad).expect("alice's key satisfies the attribute");
    println!("alice (premium) reads: {}", String::from_utf8_lossy(&plain));

    // Bob's key (tier:free) does not satisfy `tier:premium` — fail closed.
    let bob = issue_to(&authority, &n("/sub/bob"));
    match open_kp(&ck, &bob, &ct, aad) {
        Ok(_) => println!("bob (free) read the premium forecast?!  (should not happen)"),
        Err(_) => println!("bob (free) is denied — the attribute policy is not satisfied"),
    }
}
