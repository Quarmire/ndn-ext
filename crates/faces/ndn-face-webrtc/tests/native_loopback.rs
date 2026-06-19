//! Native↔native witness for the WebRTC face.
//!
//! Two `WebRtcConnector`s in the same process establish a peer-to-peer
//! reliable-ordered datachannel and exchange one Interest/Data round
//! trip with no NDN forwarder in the path. This is the simplest
//! sanity check called for in
//! `.claude/prompts/wasm/phase5-webrtc-peer.md`.
//!
//! Why an in-process loopback? Two reasons:
//! - It exercises the full WebRTC stack (DTLS handshake, SCTP setup,
//!   datachannel send/recv) end-to-end.
//! - It validates the [`WebRtcConnector`]'s offer/answer/finalize
//!   surface without dragging in the HTTP relay (deferred to a
//!   later cut). Manual signaling round-trips bytes within the
//!   test harness.

use std::time::Duration;

use ndn_face_webrtc::{IceServers, RtcChannel, WebRtcConnector};

/// Phase 5 — `wasm_rtc_native_native`: two native peers in one
/// process exchange an Interest and matching Data over a WebRTC
/// reliable datachannel.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rtc_native_native_round_trip() {
    let _ = tracing_subscriber::fmt::try_init();

    // Both peers use the default ICE servers (Google STUN). Tests
    // run on loopback, so STUN is rarely consulted, but having it
    // configured matches the production code path.
    let alice = WebRtcConnector::new(IceServers::default()).expect("alice connector");
    let bob = WebRtcConnector::new(IceServers::default()).expect("bob connector");

    // 1. Alice creates an offer.
    let (offer, alice_pending) = alice.create_offer().await.expect("create offer");
    assert_eq!(offer.kind, "offer");
    assert!(offer.sdp.contains("v=0"), "SDP must start with v=0");

    // 2. Bob accepts the offer and produces an answer.
    let (answer, bob_pending) = bob.accept_offer(offer).await.expect("accept offer");
    assert_eq!(answer.kind, "answer");

    // 3. Alice and Bob finalise concurrently — Alice consumes the
    //    answer; Bob just waits for the datachannel-open event.
    //    The DTLS handshake is wrapped inside finalize_*; we cap
    //    it at a generous timeout so the test fails loud rather
    //    than hangs.
    let alice_face_fut = alice.finalize_with_answer(alice_pending, answer);
    let bob_face_fut = bob.finalize_pending(bob_pending);

    let (alice_face, bob_face) = tokio::time::timeout(Duration::from_secs(20), async {
        tokio::join!(alice_face_fut, bob_face_fut)
    })
    .await
    .expect("dtls/sctp handshake exceeded 20s");
    let alice_face = alice_face.expect("alice finalize");
    let bob_face = bob_face.expect("bob finalize");

    let alice = alice_face.channel();
    let bob = bob_face.channel();

    // 4. Round-trip: Alice sends an Interest-shaped payload, Bob
    //    receives it, Bob sends a Data-shaped payload back, Alice
    //    receives. The contents are opaque to the WebRTC layer —
    //    the channel is a byte pipe.
    let interest_wire = bytes::Bytes::from_static(b"\x05\x09\x07\x07\x08\x05hello");
    let data_wire = bytes::Bytes::from_static(b"\x06\x09\x07\x05\x08\x03ndn\x14\x00");

    alice.send(interest_wire.clone()).await.expect("alice send");
    let got = tokio::time::timeout(Duration::from_secs(5), bob.recv())
        .await
        .expect("bob recv timeout")
        .expect("bob recv");
    assert_eq!(got, interest_wire, "Bob received exactly Alice's bytes");

    bob.send(data_wire.clone()).await.expect("bob send");
    let got = tokio::time::timeout(Duration::from_secs(5), alice.recv())
        .await
        .expect("alice recv timeout")
        .expect("alice recv");
    assert_eq!(got, data_wire, "Alice received exactly Bob's bytes");
}
