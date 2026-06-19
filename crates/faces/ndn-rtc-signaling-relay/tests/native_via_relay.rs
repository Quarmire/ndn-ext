//! End-to-end witness: two native peers signal through the HTTP
//! relay and exchange Interest/Data over the resulting WebRTC
//! datachannel.
//!
//! This is the load-bearing checkpoint between phase 5's
//! "in-process loopback" witness and the playwright browser↔
//! native run: it proves the relay's wire shape works against
//! the native `WebRtcConnector`. Once the wasm path drives the
//! same wire, the playwright run is the only thing left.

use std::time::Duration;

use ndn_face_webrtc::{IceServers, RtcChannel, WebRtcConnector};
use ndn_rtc_signaling_relay::{RelayClient, RelayServer};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn native_native_via_http_relay() {
    let _ = tracing_subscriber::fmt::try_init();

    // 1. Boot the relay on a free port.
    let (bound, server_fut) = RelayServer::serve("127.0.0.1:0".parse().unwrap())
        .await
        .expect("relay bind");
    let _server_task = tokio::spawn(server_fut);
    let base = format!("http://{bound}");

    // Each rendezvous gets a fresh session id; collisions across
    // concurrent test runs would be a footgun otherwise.
    let session_id = format!("test-{}", std::process::id());
    let alice_client = RelayClient::new(base.clone(), session_id.clone());
    let bob_client = RelayClient::new(base, session_id);

    // 2. Build connectors on both sides (default Google STUN).
    let alice = WebRtcConnector::new(IceServers::default()).expect("alice connector");
    let bob = WebRtcConnector::new(IceServers::default()).expect("bob connector");

    // 3. Drive the offer/answer dance through the relay.
    //
    //   Alice                           Relay                          Bob
    //     │   POST /<id>/offer  ───────────►                              │
    //     │                                  ◄───── GET /<id>/offer       │
    //     │                                                                │
    //     │                                  ◄───── POST /<id>/answer     │
    //     │ GET /<id>/answer ──────────────►                              │
    //     │                                                                │
    //     │ ←──────────  DTLS / SCTP datachannel  ──────────────────────► │
    let alice_drive = async {
        let (offer, pending) = alice.create_offer().await.expect("create offer");
        alice_client.post_offer(&offer).await.expect("post offer");
        let answer = alice_client.get_answer().await.expect("get answer");
        alice
            .finalize_with_answer(pending, answer)
            .await
            .expect("alice finalize")
    };
    let bob_drive = async {
        let offer = bob_client.get_offer().await.expect("get offer");
        let (answer, pending) = bob.accept_offer(offer).await.expect("accept offer");
        bob_client.post_answer(&answer).await.expect("post answer");
        bob.finalize_pending(pending).await.expect("bob finalize")
    };

    let (alice_face, bob_face) = tokio::time::timeout(Duration::from_secs(30), async {
        tokio::join!(alice_drive, bob_drive)
    })
    .await
    .expect("dtls/sctp handshake exceeded 30s");

    let alice = alice_face.channel();
    let bob = bob_face.channel();

    // 4. Round-trip: Alice → Bob → Alice. Same as the in-process
    //    loopback witness; the new dimension is that signaling
    //    went via HTTP rather than direct function calls.
    let interest = bytes::Bytes::from_static(b"\x05\x09\x07\x07\x08\x05hello");
    let data = bytes::Bytes::from_static(b"\x06\x09\x07\x05\x08\x03ndn\x14\x00");

    alice.send(interest.clone()).await.expect("alice send");
    let got = tokio::time::timeout(Duration::from_secs(5), bob.recv())
        .await
        .expect("bob recv timeout")
        .expect("bob recv");
    assert_eq!(got, interest);

    bob.send(data.clone()).await.expect("bob send");
    let got = tokio::time::timeout(Duration::from_secs(5), alice.recv())
        .await
        .expect("alice recv timeout")
        .expect("alice recv");
    assert_eq!(got, data);
}
