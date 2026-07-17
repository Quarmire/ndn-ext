//! End-to-end witness that the two *wrapped* halves interoperate: the
//! answerer via [`WebRtcListener::accept_one`] and the offerer via
//! [`WebRtcDialer::connect_one`], with no hand-rolled signaling dance on
//! either side. Proves the symmetric dialer wrapper is wire-compatible
//! with the listener wrapper by exchanging an Interest/Data over the
//! resulting datachannel.
//!
//! Sibling of `native_via_relay.rs`, which open-codes the offerer half.

use std::time::Duration;

use ndn_face_webrtc::{IceServers, RtcChannel};
use ndn_rtc_signaling_relay::{RelayServer, WebRtcDialer, WebRtcListener};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wrapped_dialer_and_listener_via_http_relay() {
    let _ = tracing_subscriber::fmt::try_init();

    // 1. Boot the relay on a free port.
    let (bound, server_fut) = RelayServer::serve("127.0.0.1:0".parse().unwrap())
        .await
        .expect("relay bind");
    let _server_task = tokio::spawn(server_fut);
    let base = format!("http://{bound}");

    // Fresh session id per run so concurrent runs don't collide.
    let session_id = format!("wrapped-{}", std::process::id());

    // 2. Both halves are driven purely through the wrappers — the dialer
    //    posts the offer and long-polls for the answer; the listener
    //    long-polls for the offer and posts the answer. No open-coded
    //    connector dance anywhere in this test.
    let dialer = WebRtcDialer::new(base.clone(), IceServers::default());
    let listener = WebRtcListener::new(base, IceServers::default());

    let dial_drive = dialer.connect_one(&session_id, Duration::from_secs(30));
    let accept_drive = listener.accept_one(&session_id, Duration::from_secs(30));

    let (dialer_face, listener_face) = tokio::time::timeout(Duration::from_secs(30), async {
        tokio::join!(dial_drive, accept_drive)
    })
    .await
    .expect("dtls/sctp handshake exceeded 30s");
    let dialer_face = dialer_face.expect("dialer connect_one");
    let listener_face = listener_face.expect("listener accept_one");

    let dial = dialer_face.channel();
    let accept = listener_face.channel();

    // 3. Round-trip: offerer → answerer → offerer, this time with both
    //    signaling halves wrapped.
    let interest = bytes::Bytes::from_static(b"\x05\x09\x07\x07\x08\x05hello");
    let data = bytes::Bytes::from_static(b"\x06\x09\x07\x05\x08\x03ndn\x14\x00");

    dial.send(interest.clone()).await.expect("dialer send");
    let got = tokio::time::timeout(Duration::from_secs(5), accept.recv())
        .await
        .expect("listener recv timeout")
        .expect("listener recv");
    assert_eq!(got, interest);

    accept.send(data.clone()).await.expect("listener send");
    let got = tokio::time::timeout(Duration::from_secs(5), dial.recv())
        .await
        .expect("dialer recv timeout")
        .expect("dialer recv");
    assert_eq!(got, data);
}
