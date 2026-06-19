//! QUIC face witnesses: loopback round-trip + connection migration.

use std::time::Duration;

use bytes::Bytes;
use ndn_transport::{FaceId, Transport};

use ndn_face_quic::{QuicConnector, QuicListener, QuicServerTls};
use ndn_transport::ClientTls;

fn make_tlv(tag: u8, value: &[u8]) -> Bytes {
    use ndn_tlv::TlvWriter;
    let mut w = TlvWriter::new();
    w.write_tlv(tag as u64, value);
    w.finish()
}

async fn pair() -> (QuicListener, QuicConnector, std::net::SocketAddr) {
    let listener = QuicListener::bind(
        "127.0.0.1:0".parse().unwrap(),
        QuicServerTls::SelfSigned {
            hostnames: vec!["localhost".into()],
        },
    )
    .await
    .expect("bind QUIC listener");
    let addr = listener.local_addr();
    let hash = listener.leaf_cert_sha256().expect("leaf hash");
    let connector =
        QuicConnector::new(ClientTls::CertHashes(vec![hash])).expect("client connector");
    (listener, connector, addr)
}

#[tokio::test]
async fn quic_loopback_round_trip() {
    let (listener, connector, addr) = pair().await;

    // The dialer opens the bi-stream; the listener's accept_bi resolves once
    // the dialer sends, so drive client-sends-first.
    let server_task = tokio::spawn(async move { listener.accept(FaceId(1)).await });
    let client = connector
        .connect(FaceId(0), addr, "localhost")
        .await
        .expect("dial");

    let interest = make_tlv(0x05, b"hello-quic");
    client
        .send_bytes(interest.clone())
        .await
        .expect("send interest");

    let server = server_task.await.unwrap().expect("accept");
    let got = tokio::time::timeout(Duration::from_secs(5), server.recv_bytes())
        .await
        .expect("recv timed out")
        .expect("recv interest");
    assert_eq!(got, interest);

    // Reverse direction (full duplex on the same stream).
    let data = make_tlv(0x06, b"world-quic");
    server.send_bytes(data.clone()).await.expect("send data");
    let got = tokio::time::timeout(Duration::from_secs(5), client.recv_bytes())
        .await
        .expect("recv timed out")
        .expect("recv data");
    assert_eq!(got, data);
}

/// A PEM-cert listener (the `QuicServerTls::Pem` path, as fed by ACME/operator
/// certs) round-trips with a dialer pinning its leaf hash.
#[tokio::test]
async fn quic_pem_listener_round_trip() {
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let listener = QuicListener::bind(
        "127.0.0.1:0".parse().unwrap(),
        QuicServerTls::Pem {
            cert_chain_pem: ck.cert.pem().into_bytes(),
            private_key_pem: ck.key_pair.serialize_pem().into_bytes(),
        },
    )
    .await
    .expect("bind PEM listener");
    let addr = listener.local_addr();
    let hash = listener.leaf_cert_sha256().expect("leaf hash from PEM");
    let connector = QuicConnector::new(ClientTls::CertHashes(vec![hash])).expect("connector");

    let server_task = tokio::spawn(async move { listener.accept(FaceId(1)).await });
    let client = connector
        .connect(FaceId(0), addr, "localhost")
        .await
        .expect("dial");
    client
        .send_bytes(make_tlv(0x05, b"pem-ok"))
        .await
        .expect("send");
    let server = server_task.await.unwrap().expect("accept");
    let got = tokio::time::timeout(Duration::from_secs(5), server.recv_bytes())
        .await
        .expect("recv timed out")
        .expect("recv");
    assert_eq!(got, make_tlv(0x05, b"pem-ok"));
}

/// The `WebPki` dial path must *reject* a self-signed peer (its cert chains to
/// no bundled root) — proving WebPKI verification is actually enforced, not
/// bypassed. A genuinely WebPKI-trusted (ACME) peer can't be exercised offline.
#[tokio::test]
async fn quic_webpki_rejects_self_signed() {
    let listener = QuicListener::bind(
        "127.0.0.1:0".parse().unwrap(),
        QuicServerTls::SelfSigned {
            hostnames: vec!["localhost".into()],
        },
    )
    .await
    .expect("bind");
    let addr = listener.local_addr();
    tokio::spawn(async move { listener.accept(FaceId(1)).await });

    let connector = QuicConnector::new(ClientTls::WebPki).expect("connector");
    let res = connector.connect(FaceId(0), addr, "localhost").await;
    assert!(
        res.is_err(),
        "WebPki dial must reject a self-signed peer (verification not enforced!)"
    );
}

/// The dialer's `QuicConnector` (its quinn `Endpoint`) can be dropped after
/// `connect` — the face's streams keep the connection (and the endpoint's I/O
/// driver) alive. This is what lets `faces/create quic://` return a face
/// without retaining the connector.
#[tokio::test]
async fn quic_face_survives_connector_drop() {
    let (listener, connector, addr) = pair().await;
    let server_task = tokio::spawn(async move { listener.accept(FaceId(1)).await });
    let client = connector
        .connect(FaceId(0), addr, "localhost")
        .await
        .expect("dial");
    drop(connector); // <-- endpoint handle dropped; face must survive

    client
        .send_bytes(make_tlv(0x05, b"after-drop"))
        .await
        .expect("send");
    let server = server_task.await.unwrap().expect("accept");
    let got = tokio::time::timeout(Duration::from_secs(5), server.recv_bytes())
        .await
        .expect("recv timed out (connector drop closed the connection)")
        .expect("recv");
    assert_eq!(got, make_tlv(0x05, b"after-drop"));
}

/// The headline: after a round-trip, rebind the client's UDP socket (its local
/// address changes) and confirm the *same* face keeps working — connection
/// migration. A UDP/TCP face would die here and need re-creation.
#[tokio::test]
async fn quic_connection_migration() {
    let (listener, connector, addr) = pair().await;

    let server_task = tokio::spawn(async move {
        let face = listener.accept(FaceId(1)).await.expect("accept");
        // Keep the listener alive for the duration by moving it into the task.
        (listener, face)
    });
    let client = connector
        .connect(FaceId(0), addr, "localhost")
        .await
        .expect("dial");

    // Round-trip #1.
    client
        .send_bytes(make_tlv(0x05, b"pre-migration"))
        .await
        .expect("send 1");
    let (_listener, server) = server_task.await.unwrap();
    let got = tokio::time::timeout(Duration::from_secs(5), server.recv_bytes())
        .await
        .expect("recv1 timed out")
        .expect("recv 1");
    assert_eq!(got, make_tlv(0x05, b"pre-migration"));

    // ── Migrate: rebind the client to a brand-new local UDP socket. ──
    let before = connector.local_addr().unwrap();
    let new_sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("new socket");
    connector.rebind(new_sock).expect("rebind");
    let after = connector.local_addr().unwrap();
    assert_ne!(
        before.port(),
        after.port(),
        "local address must have changed"
    );

    // Round-trip #2 on the SAME faces, post-migration.
    client
        .send_bytes(make_tlv(0x05, b"post-migration"))
        .await
        .expect("send 2 (face survived migration)");
    let got = tokio::time::timeout(Duration::from_secs(5), server.recv_bytes())
        .await
        .expect("recv2 timed out (migration broke the connection)")
        .expect("recv 2");
    assert_eq!(got, make_tlv(0x05, b"post-migration"));

    // And the reverse direction still works after migration.
    server
        .send_bytes(make_tlv(0x06, b"reply-post-migration"))
        .await
        .expect("send reply");
    let got = tokio::time::timeout(Duration::from_secs(5), client.recv_bytes())
        .await
        .expect("reply timed out")
        .expect("recv reply");
    assert_eq!(got, make_tlv(0x06, b"reply-post-migration"));
}
