//! A link ends when the certificate that admitted it lapses (ndn-rs `ndn-link.md`
//! §8.7, round 12 L2): the check at the hello is not the last one. The words the
//! close carries are `table::tests`'.
//!
//! Real QUIC, real forwarders, a device whose certificate is valid for a few
//! seconds only.

mod common;

use std::time::Duration;

use common::{ANN, LONG, Person, Setup, dials, embedded, linked, until};

/// A device of the person links to Ann with a certificate valid for 8 seconds: once
/// it lapses, Ann closes the link, and a device with a certificate that holds stays
/// linked.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_link_whose_certificate_lapses_is_closed() {
    let alice = Person::new("/alice").await;
    let ann = embedded(&alice, ANN, Setup::inviter()).await;
    let short = Setup {
        cert_ms: 8_000,
        ..Setup::dialer()
    };
    let phone = embedded(&alice, "/alice/member/phone", short).await;
    let tablet = embedded(&alice, "/alice/member/tablet", Setup::dialer()).await;
    dials(&phone, &ann).await.expect("the phone links to ann");
    dials(&tablet, &ann).await.expect("the tablet links to ann");
    until("ann is linked to both", LONG, async || {
        linked(&ann, phone.key) && linked(&ann, tablet.key)
    })
    .await;

    until(
        "ann closed the link of the phone whose certificate lapsed",
        Duration::from_secs(30),
        async || !linked(&ann, phone.key),
    )
    .await;
    assert!(
        linked(&ann, tablet.key),
        "a link whose certificate holds was closed with it"
    );
}
