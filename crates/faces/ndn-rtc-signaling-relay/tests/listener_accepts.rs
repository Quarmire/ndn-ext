//! Forwarder-side listener witness.
//!
//! Mirrors the `native_via_relay` shape but uses the
//! [`WebRtcListener`] API on the answerer side. This is the path
//! `ndn-fwd [listeners.webrtc]` will take: an operator points the
//! forwarder at a relay, and the listener accepts incoming
//! peers automatically.
//!
//! After the handshake we exercise the [`ndn_transport::Face`]
//! impl directly (not the [`RtcChannel`] surface) so the test
//! doubles as a contract pin: the engine is going to call
//! `Face::send` / `Face::recv` on this exact type.

use std::time::Duration;

use ndn_face_webrtc::{IceServers, RtcChannel, WebRtcConnector};
use ndn_rtc_signaling_relay::{RelayClient, RelayServer, WebRtcListener};
use ndn_transport::Transport;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn listener_accepts_via_relay() {
    let _ = tracing_subscriber::fmt::try_init();

    let (bound, server_fut) = RelayServer::serve("127.0.0.1:0".parse().unwrap())
        .await
        .expect("relay bind");
    let _server_task = tokio::spawn(server_fut);
    let base = format!("http://{bound}");

    let session = format!("listener-test-{}", std::process::id());

    // Caller side: drive the offerer flow against the relay
    // exactly the way the dioxus-demo's WebRtcConnector flow
    // would in a real deployment.
    let caller_base = base.clone();
    let caller_session = session.clone();
    let caller_drive = async move {
        let connector = WebRtcConnector::new(IceServers::default()).expect("connector");
        let client = RelayClient::new(caller_base, caller_session);
        let (offer, pending) = connector.create_offer().await.expect("create offer");
        client.post_offer(&offer).await.expect("post offer");
        let answer = client.get_answer().await.expect("get answer");
        connector
            .finalize_with_answer(pending, answer)
            .await
            .expect("finalize")
    };

    // Listener side: the abstraction `ndn-fwd` will use.
    let listener = WebRtcListener::new(base, IceServers::default());
    let listener_drive = async {
        listener
            .accept_one(&session, Duration::from_secs(30))
            .await
            .expect("listener accept")
    };

    let (caller_face, mut server_face) = tokio::time::timeout(Duration::from_secs(40), async {
        tokio::join!(caller_drive, listener_drive)
    })
    .await
    .expect("handshake exceeded 40s");

    // The listener returns a `WebRtcFace` whose id starts at 0 —
    // operators reassign it via `set_id` before plugging it into
    // the engine's face table.
    server_face.set_id(ndn_transport::FaceId(42));
    assert_eq!(server_face.id(), ndn_transport::FaceId(42));
    assert_eq!(server_face.kind(), ndn_transport::FaceKind::WebRtc);

    // Round-trip Interest/Data through the `ndn_transport::Face`
    // surface.
    let interest = bytes::Bytes::from_static(b"\x05\x09\x07\x07\x08\x05hello");
    let data = bytes::Bytes::from_static(b"\x06\x09\x07\x05\x08\x03ndn\x14\x00");

    caller_face
        .channel()
        .send(interest.clone())
        .await
        .map(|_| ())
        .expect("caller send");
    let got = tokio::time::timeout(Duration::from_secs(5), server_face.recv_bytes())
        .await
        .expect("server recv timeout")
        .expect("server recv");
    assert_eq!(got, interest);

    Transport::send_bytes(&server_face, data.clone())
        .await
        .expect("server send");
    let got = tokio::time::timeout(Duration::from_secs(5), caller_face.channel().recv())
        .await
        .expect("caller recv timeout")
        .expect("caller recv");
    assert_eq!(got, data);
}
