//! Phase 3 native witness — drives `BrowserWebTransportFace` against the
//! Phase 2 `WebTransportListener` via `xwt-wtransport`. Same wire framing
//! as the browser path, just running in-process under Tokio so the audit
//! script can run without spinning up a real browser.

use std::sync::Arc;

use bytes::Bytes;
use ndn_runtime::TokioRuntime;
use ndn_transport::{FaceId, Transport};

use ndn_face_webtransport::{WebTransportListener, WtTlsConfig};
use ndn_face_webtransport_wasm::BrowserWebTransportFace;

fn make_tlv(tag: u8, value: &[u8]) -> Bytes {
    use ndn_tlv::TlvWriter;
    let mut w = TlvWriter::new();
    w.write_tlv(tag as u64, value);
    w.finish()
}

#[tokio::test]
async fn phase3_native_xwt_round_trip() {
    let listener = WebTransportListener::bind(
        "127.0.0.1:0".parse().unwrap(),
        WtTlsConfig::SelfSigned {
            hostnames: vec!["localhost".into()],
        },
    )
    .await
    .expect("bind WT listener");
    let server_addr = listener.local_addr();

    let server_task = tokio::spawn(async move { listener.accept(FaceId(1)).await });

    // Self-signed loopback: skip cert validation entirely. The browser path
    // would use `serverCertificateHashes` here; that's the dual covered by
    // the Playwright witness.
    let client_config = wtransport::ClientConfig::builder()
        .with_bind_default()
        .with_no_cert_validation()
        .build();

    let runtime: Arc<dyn ndn_runtime::Runtime> = Arc::new(TokioRuntime);
    let url = format!("https://{}/ndn", server_addr);
    let client_face = BrowserWebTransportFace::connect(FaceId(0), &url, client_config, runtime)
        .await
        .expect("client connect");

    let server_face = server_task.await.unwrap().expect("accept");

    let interest = make_tlv(0x05, b"hello");
    client_face
        .send_bytes(interest.clone())
        .await
        .expect("send interest");
    let received = server_face.recv_bytes().await.expect("recv interest");
    assert_eq!(received, ndn_packet::lp::encode_lp_packet(&interest));

    let data = make_tlv(0x06, b"world");
    server_face
        .send_bytes(data.clone())
        .await
        .expect("send data");
    let received = client_face.recv_bytes().await.expect("recv data");
    assert_eq!(received, ndn_packet::lp::encode_lp_packet(&data));

    // Oversized Data both directions must fragment over datagrams (NDNLPv2)
    // and reassemble, matching NDNts' H3Transport + LpService.
    let big = make_tlv(0x06, &vec![0x5A; 12_000]);
    let big_lp = ndn_packet::lp::encode_lp_packet(&big);

    server_face
        .send_bytes(big.clone())
        .await
        .expect("send big down");
    assert_eq!(reassemble(&client_face).await, big_lp);

    client_face
        .send_bytes(big.clone())
        .await
        .expect("send big up");
    assert_eq!(reassemble(&server_face).await, big_lp);
}

/// Drain datagrams from a face and reassemble one NDNLPv2-fragmented packet,
/// grouping by `sequence - frag_index` exactly as the engine decode stage does.
async fn reassemble<T: Transport>(face: &T) -> Bytes {
    use ndn_packet::fragment::ReassemblyBuffer;
    use ndn_packet::lp::extract_fragment;
    use std::time::Duration;

    let mut reasm = ReassemblyBuffer::new(Duration::from_secs(5));
    loop {
        let dgram = face.recv_bytes().await.expect("recv");
        let h = extract_fragment(&dgram).expect("expected fragmented datagram");
        let base_seq = h.sequence - h.frag_index;
        let payload = dgram.slice(h.frag_start..h.frag_end);
        if let Some(full) = reasm.process(0, base_seq, h.frag_index, h.frag_count, payload) {
            return full;
        }
    }
}
