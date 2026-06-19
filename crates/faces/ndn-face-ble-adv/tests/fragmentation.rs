//! The load-bearing claim: a small `send_mtu` makes the paired `LpLinkService`
//! fragment an NDN packet across multiple advertisements, with no custom
//! chunking in the face. Driven through `Face::from_transport`, which gives the
//! Bluetooth kind an `LpLinkService`.

use std::sync::Arc;
use std::time::Duration;

use ndn_face_ble_adv::{AdvBackend, BleAdvFace, EXTENDED_ADV_MTU, LoopbackAdvBus};
use ndn_packet::encode::DataBuilder;
use ndn_transport::{Face, FaceId};

#[tokio::test]
async fn large_packet_fragments_into_multiple_adverts() {
    let bus = LoopbackAdvBus::new();

    // The sender, wrapped in a Face so the LpLinkService applies fragmentation
    // at the advertising MTU.
    let sender = BleAdvFace::new(FaceId(1), Arc::new(bus.endpoint(1, [0xA0; 6], -50)));
    let face = Face::from_transport(sender);

    // A passive observer endpoint to count advertisements on the medium.
    let observer = Arc::new(bus.endpoint(2, [0xB0; 6], -55));

    // A Data packet several times larger than one extended advertisement.
    let payload = vec![0x5Au8; 800];
    let data = DataBuilder::new("/ble/adv/big", &payload).sign_digest_sha256();
    assert!(
        data.len() > EXTENDED_ADV_MTU * 2,
        "test packet must be clearly multi-fragment"
    );

    face.send_bytes(data.clone()).await.expect("send");

    // Count the advertisements the observer hears within a short window.
    let mut adverts = 0usize;
    while tokio::time::timeout(Duration::from_millis(100), observer.next_scanned())
        .await
        .is_ok()
    {
        adverts += 1;
    }

    assert!(
        adverts > 1,
        "a {}-byte packet over a {EXTENDED_ADV_MTU}-byte advertising MTU must fragment \
         into multiple adverts; got {adverts}",
        data.len()
    );
}
