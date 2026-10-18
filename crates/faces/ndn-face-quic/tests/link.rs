//! QUIC link invariants: the handshake proves each side's NDN key, a dial
//! that expects another key fails, a refusal reaches the other side with its
//! reason, NDN packets ride datagrams (fragmented when large), a scoped
//! (enrollment) link carries only its scope, attempts over the limits are
//! refused, and a link survives an address change.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ndn_face_quic::{
    Admission, Carries, CloseReason, HandshakeLimits, Link, LinkEndpoint, LinkError, LinkHello,
    LinkKey, LinkScope, LinkTransportConfig, LinkVerdict, RateLimit,
};
use ndn_packet::Name;
use ndn_packet::encode::{DataBuilder, InterestBuilder};
use ndn_security::{EcdsaP256Signer, Ed25519Signer};
use ndn_transport::{Face, FaceId, LpLinkService, Transport};

const T: Duration = Duration::from_secs(5);

fn ed_key(seed: u8) -> LinkKey {
    LinkKey::from_signer(Arc::new(Ed25519Signer::from_seed(
        &[seed; 32],
        format!("/ns/member/d{seed}/KEY/k").parse().unwrap(),
    )))
    .unwrap()
}

fn ec_key(seed: u8) -> LinkKey {
    LinkKey::from_signer(Arc::new(
        EcdsaP256Signer::from_seed(&[seed; 32], format!("/ns/node/r{seed}/KEY/k").parse().unwrap())
            .unwrap(),
    ))
    .unwrap()
}

fn endpoint(key: LinkKey, listen: bool) -> LinkEndpoint {
    endpoint_with(key, listen, LinkTransportConfig::default())
}

fn endpoint_with(key: LinkKey, listen: bool, config: LinkTransportConfig) -> LinkEndpoint {
    LinkEndpoint::bind("127.0.0.1:0".parse().unwrap(), Arc::new(key), &config, listen).unwrap()
}

fn addr(e: &LinkEndpoint) -> SocketAddr {
    e.local_addr().unwrap()
}

fn hello(tag: u8) -> LinkHello {
    LinkHello {
        certificates: vec![Bytes::from(vec![0x06, 0x01, tag])],
    }
}

/// Dial `listener` from `dialer` and admit on both sides.
async fn link(dialer: &LinkEndpoint, listener: &LinkEndpoint) -> (Link, Link) {
    let target = addr(listener);
    let accept = async {
        let mut hs = listener.accept().await.unwrap().handshake().await.unwrap();
        let theirs = hs.exchange_hello(&hello(2), T).await.unwrap();
        assert_eq!(theirs, hello(1));
        hs.admit(FaceId(2), T, Admission::default()).await.unwrap()
    };
    let dial = async {
        let mut hs = dialer.connect(target, None).await.unwrap();
        let theirs = hs.exchange_hello(&hello(1), T).await.unwrap();
        assert_eq!(theirs, hello(2));
        hs.admit(FaceId(1), T, Admission::default()).await.unwrap()
    };
    tokio::join!(dial, accept)
}

#[tokio::test]
async fn each_side_sees_the_other_sides_ndn_key() {
    for (a, b) in [(ed_key(1), ec_key(2)), (ec_key(3), ed_key(4))] {
        let (fa, fb) = (a.fingerprint(), b.fingerprint());
        let dialer = endpoint(a, false);
        let listener = endpoint(b, true);
        let target = addr(&listener);
        let (dialed, accepted) = tokio::join!(dialer.connect(target, Some(fb)), async {
            listener.accept().await.unwrap().handshake().await
        });
        assert_eq!(dialed.unwrap().peer_key().fingerprint(), fb);
        assert_eq!(accepted.unwrap().peer_key().fingerprint(), fa);
    }
}

#[tokio::test]
async fn a_dial_expecting_another_key_fails_in_the_handshake() {
    let dialer = endpoint(ed_key(1), false);
    let listener = endpoint(ed_key(2), true);
    let wrong = ed_key(3).fingerprint();
    let target = addr(&listener);
    let accept = tokio::spawn(async move {
        let incoming = listener.accept().await.unwrap();
        incoming.handshake().await.err()
    });
    match dialer.connect(target, Some(wrong)).await {
        Err(LinkError::UnexpectedKey { expected, presented }) => {
            assert_eq!(expected, wrong);
            assert_eq!(presented, ed_key(2).fingerprint());
        }
        Err(other) => panic!("expected UnexpectedKey, got {other}"),
        Ok(_) => panic!("a dial expecting another key succeeded"),
    }
    assert!(accept.await.unwrap().is_some(), "the listener saw a link come up");
}

#[tokio::test]
async fn a_refusal_reaches_the_other_side_with_its_reason() {
    let dialer = endpoint(ed_key(1), false);
    let listener = endpoint(ed_key(2), true);
    let target = addr(&listener);
    let refuse = async {
        let mut hs = listener.accept().await.unwrap().handshake().await.unwrap();
        hs.exchange_hello(&hello(2), T).await.unwrap();
        hs.refuse(CloseReason::Unrecognized, "not a device of a namespace I hold");
    };
    // The refusal may overtake the listener's hello: either way the dialer
    // learns the reason.
    let dial = async {
        let mut hs = dialer.connect(target, None).await.unwrap();
        match hs.exchange_hello(&hello(1), T).await {
            Err(e) => Some(e),
            Ok(_) => hs.admit(FaceId(1), T, Admission::default()).await.err(),
        }
    };
    let ((), refused) = tokio::join!(refuse, dial);
    match refused {
        Some(LinkError::Refused { reason, text }) => {
            assert_eq!(reason, Some(CloseReason::Unrecognized));
            assert_eq!(text, "not a device of a namespace I hold");
        }
        other => panic!("expected the refusal, got {other:?}"),
    }
}

#[tokio::test]
async fn a_peer_that_misses_the_message_deadline_is_closed_as_a_protocol_error() {
    let dialer = endpoint(ed_key(1), false);
    let listener = endpoint(ed_key(2), true);
    let target = addr(&listener);
    // The listener completes its handshake, then says nothing for longer
    // than the dialer waits for its hello.
    let slow = async {
        let mut hs = listener.accept().await.unwrap().handshake().await.unwrap();
        tokio::time::sleep(Duration::from_millis(600)).await;
        match hs.exchange_hello(&hello(2), T).await {
            Err(e) => e,
            Ok(_) => hs.admit(FaceId(2), T, Admission::default()).await.err().unwrap(),
        }
    };
    let dial = async {
        let mut hs = dialer.connect(target, None).await.unwrap();
        hs.exchange_hello(&hello(1), Duration::from_millis(200)).await.err().unwrap()
    };
    let (told, waited) = tokio::join!(slow, dial);
    assert!(matches!(waited, LinkError::Timeout), "{waited:?}");
    match told {
        LinkError::Refused { reason, text } => {
            assert_eq!(reason, Some(CloseReason::Protocol), "not a shutdown: {text}");
            assert!(text.contains("no link message"), "{text}");
            assert!(!told_is_transient(reason), "the slow side does not dial again at once");
        }
        other => panic!("expected the dialer's Protocol close, got {other:?}"),
    }
}

fn told_is_transient(reason: Option<CloseReason>) -> bool {
    LinkError::Refused {
        reason,
        text: String::new(),
    }
    .is_transient()
}

#[tokio::test]
async fn packets_ride_datagrams_both_ways_and_large_ones_are_fragmented() {
    let dialer = endpoint(ed_key(1), false);
    let listener = endpoint(ec_key(2), true);
    let (a, b) = link(&dialer, &listener).await;

    let small = Bytes::from_static(&[0x05, 0x03, 0x07, 0x01, 0x41]);
    a.face.send_bytes(small.clone()).await.unwrap();
    assert_eq!(tokio::time::timeout(T, b.face.recv_bytes()).await.unwrap().unwrap(), small);
    b.face.send_bytes(small.clone()).await.unwrap();
    assert_eq!(tokio::time::timeout(T, a.face.recv_bytes()).await.unwrap().unwrap(), small);

    // A 20 KB packet through the face's link service: one NDNLPv2 frame per
    // datagram, each within the link's datagram size, reassembled whole.
    let mut big = vec![0x06, 0xFD, 0x4E, 0x20];
    big.extend((0..20_000u32).map(|i| i as u8));
    let big = Bytes::from(big);
    let sender = Face::from_parts(
        Arc::new(a.face) as Arc<dyn ndn_transport::ErasedTransport>,
        Arc::new(LpLinkService::new()),
    );
    sender.send_bytes(big.clone()).await.unwrap();
    // The datagram size only grows as path MTU discovery finds room.
    let mtu = sender.transport.send_mtu().unwrap();

    let mut reassembly = ndn_packet::fragment::ReassemblyBuffer::new(T);
    let whole = loop {
        let frame = tokio::time::timeout(T, b.face.recv_bytes()).await.unwrap().unwrap();
        assert!(frame.len() <= mtu, "a {} B frame over the {mtu} B datagram size", frame.len());
        let lp = ndn_packet::lp::LpPacket::decode(frame).unwrap();
        assert!(lp.frag_count.unwrap_or(1) > 1, "the large packet was not fragmented");
        let (seq, index) = (lp.sequence.unwrap(), lp.frag_index.unwrap());
        if let Some(whole) = reassembly.process(
            0,
            seq - index,
            index,
            lp.frag_count.unwrap(),
            lp.fragment.unwrap(),
        ) {
            break whole;
        }
    };
    assert_eq!(whole, big);
}

/// The next frame `face` delivers.
async fn recv(face: &ndn_face_quic::LinkFace) -> Bytes {
    tokio::time::timeout(T, face.recv_bytes()).await.unwrap().unwrap()
}

/// The listener admits the dialer on an enrollment link: Interests under
/// `/home/CA` from the dialer, their answers back, nothing else.
#[tokio::test]
async fn an_enrollment_link_carries_only_its_scope_and_says_so() {
    let dialer = endpoint(ed_key(1), false);
    let listener = endpoint(ec_key(2), true);
    let target = addr(&listener);
    let ca: Name = "/home/CA".parse().unwrap();
    let accept = async {
        let mut hs = listener.accept().await.unwrap().handshake().await.unwrap();
        hs.exchange_hello(&hello(2), T).await.unwrap();
        let scope = LinkScope {
            receives: Carries::Interests,
            sends: Carries::Answers,
            names: Box::new(move |n: &Name| n.has_prefix(&ca)),
            rate: RateLimit { burst: 16, per_sec: 4 },
            explain: "enrollment only".into(),
        };
        let admission = Admission {
            verdict: LinkVerdict {
                enrollment_link: Some(vec!["/home".parse().unwrap()]),
            },
            scope: Some(scope),
        };
        hs.admit(FaceId(2), T, admission).await.unwrap()
    };
    let dial = async {
        let mut hs = dialer.connect(target, None).await.unwrap();
        hs.exchange_hello(&hello(1), T).await.unwrap();
        hs.admit(FaceId(1), T, Admission::default()).await.unwrap()
    };
    let (device, relay) = tokio::join!(dial, accept);
    assert_eq!(
        device.peer_verdict.enrollment_link,
        Some(vec!["/home".parse::<Name>().unwrap()]),
        "the device learns it is on an enrollment link"
    );
    assert!(relay.handle.scope_idle_for().is_some() && device.handle.scope_idle_for().is_none());
    let lp = |wire: Bytes| ndn_packet::lp::encode_lp_packet(&wire);

    // An Interest outside the scope never reaches the relay's forwarder and
    // is Nacked back to the device; one inside reaches it.
    let outside = InterestBuilder::new("/home/member/phone/album".parse::<Name>().unwrap()).build();
    let inside = InterestBuilder::new("/home/CA/NEW".parse::<Name>().unwrap()).build();
    device.face.send_bytes(lp(outside.clone())).await.unwrap();
    device.face.send_bytes(lp(inside.clone())).await.unwrap();
    let got = ndn_packet::lp::LpPacket::decode(recv(&relay.face).await).unwrap();
    assert_eq!(got.fragment.unwrap(), inside, "the first packet the relay sees is the one in scope");
    // The relay's face keeps reading (and Nacking) while the device waits.
    let nack = tokio::select! {
        nack = recv(&device.face) => nack,
        other = relay.face.recv_bytes() => panic!("the relay's forwarder got {other:?}"),
    };
    let nack = ndn_packet::lp::LpPacket::decode(nack).unwrap();
    assert!(nack.nack.is_some(), "the device got a Nack for the Interest outside the scope");
    assert_eq!(nack.fragment.unwrap(), outside);

    // The relay answers within the scope; it sends no Interest and no Data
    // outside it (each kept back is Nacked to the relay's own side).
    let interest_out = InterestBuilder::new("/home/CA/x".parse::<Name>().unwrap()).build();
    relay.face.send_bytes(lp(interest_out.clone())).await.unwrap();
    let own_nack = ndn_packet::lp::LpPacket::decode(recv(&relay.face).await).unwrap();
    assert_eq!(own_nack.fragment.unwrap(), interest_out);
    relay
        .face
        .send_bytes(lp(DataBuilder::new("/home/member/tab/note".parse::<Name>().unwrap(), b"x").build()))
        .await
        .unwrap();
    let answer = DataBuilder::new("/home/CA/NEW".parse::<Name>().unwrap(), b"ok").build();
    relay.face.send_bytes(lp(answer.clone())).await.unwrap();
    let got = ndn_packet::lp::LpPacket::decode(recv(&device.face).await).unwrap();
    assert_eq!(got.fragment.unwrap(), answer, "only the answer in scope reached the device");
}

#[tokio::test]
async fn attempts_over_the_per_source_limit_are_refused_before_their_handshake() {
    let config = LinkTransportConfig {
        limits: HandshakeLimits {
            max_in_flight_per_source: 1,
            ..HandshakeLimits::default()
        },
        ..LinkTransportConfig::default()
    };
    let listener = endpoint_with(ec_key(2), true, config);
    let target = addr(&listener);
    let first = endpoint(ed_key(1), false);
    let second = endpoint(ed_key(3), false);

    // The first attempt is accepted and held, not yet admitted.
    let (held, accepted) = tokio::join!(first.connect(target, None), async {
        listener.accept().await.unwrap().handshake().await.unwrap()
    });
    let _held = (held.unwrap(), accepted);

    let accepting = async {
        tokio::time::timeout(Duration::from_secs(2), listener.accept()).await.ok().flatten().is_some()
    };
    let (second_dial, accepted_second) = tokio::join!(second.connect(target, None), accepting);
    assert!(!accepted_second, "the second attempt from the same address was accepted");
    match second_dial {
        Err(LinkError::Refused { reason, .. }) => assert_eq!(reason, Some(CloseReason::Busy)),
        Err(other) => panic!("expected a refusal, got {other}"),
        Ok(_) => panic!("the second attempt from the same address got a handshake"),
    }
}

#[tokio::test]
async fn a_link_survives_its_dialers_address_change() {
    let dialer = endpoint(ed_key(1), false);
    let listener = endpoint(ed_key(2), true);
    let (a, b) = link(&dialer, &listener).await;
    let before = addr(&dialer);
    dialer
        .rebind(std::net::UdpSocket::bind("127.0.0.1:0").unwrap())
        .unwrap();
    assert_ne!(before, addr(&dialer));
    let pkt = Bytes::from_static(&[0x05, 0x03, 0x07, 0x01, 0x42]);
    a.face.send_bytes(pkt.clone()).await.unwrap();
    assert_eq!(tokio::time::timeout(T, b.face.recv_bytes()).await.unwrap().unwrap(), pkt);
    b.face.send_bytes(pkt.clone()).await.unwrap();
    assert_eq!(tokio::time::timeout(T, a.face.recv_bytes()).await.unwrap().unwrap(), pkt);
}

#[tokio::test]
async fn a_closed_link_tells_why() {
    let dialer = endpoint(ed_key(1), false);
    let listener = endpoint(ed_key(2), true);
    let (a, b) = link(&dialer, &listener).await;
    b.handle.close(CloseReason::Revoked, "your key is revoked");
    match tokio::time::timeout(T, a.handle.closed()).await.unwrap() {
        LinkError::Refused { reason, text } => {
            assert_eq!(reason, Some(CloseReason::Revoked));
            assert_eq!(text, "your key is revoked");
        }
        other => panic!("expected the close reason, got {other}"),
    }
    assert!(a.face.recv_bytes().await.is_err(), "the face outlived its link");
}
