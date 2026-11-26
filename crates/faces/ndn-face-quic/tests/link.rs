//! QUIC link invariants: the handshake proves each side's NDN key, a dial
//! that expects another key fails, a refusal reaches the other side with its
//! reason, NDN packets ride datagrams (fragmented when large) and are
//! counted (keep-alives are not), a scoped (enrollment) link carries only
//! its scope, attempts over the limits are refused, a link survives an
//! address change (its face then names the new addresses, the other side's
//! and its own), an endpoint links on a socket the host bound, the
//! messages after the verdict (Reachability, Presence) reach the other side,
//! the latest replacing the earlier, and both sides of a connection share
//! its membership binding value, which no other connection has.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use bytes::Bytes;
use ndn_face_quic::{
    Admission, Carries, ChannelPolicy, CloseReason, Departure, FairShare, HandshakeLimits,
    KeyFingerprint, LINK_SOCKET_BUFFER, Link, LinkEndpoint, LinkError, LinkHello, LinkKey,
    LinkScope, LinkTransportConfig, LinkVerdict, Narrowing, Presence, PresentDevice, QUEUE_CAP,
    QUEUE_FLOOR, RateLimit, Reachability, ScopeCounts,
};
use ndn_packet::Name;
use ndn_packet::encode::{DataBuilder, InterestBuilder};
use ndn_security::{EcdsaP256Signer, Ed25519Signer};
use ndn_transport::{Face, FaceId, LpLinkService, SideClass, SideRefused, Transport};

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
        EcdsaP256Signer::from_seed(
            &[seed; 32],
            format!("/ns/node/r{seed}/KEY/k").parse().unwrap(),
        )
        .unwrap(),
    ))
    .unwrap()
}

fn endpoint(key: LinkKey, listen: bool) -> LinkEndpoint {
    endpoint_with(key, listen, LinkTransportConfig::default())
}

fn endpoint_with(key: LinkKey, listen: bool, config: LinkTransportConfig) -> LinkEndpoint {
    LinkEndpoint::bind(
        "127.0.0.1:0".parse().unwrap(),
        Arc::new(key),
        &config,
        listen,
    )
    .unwrap()
}

fn addr(e: &LinkEndpoint) -> SocketAddr {
    e.local_addr().unwrap()
}

fn hello(tag: u8) -> LinkHello {
    LinkHello {
        certificates: vec![Bytes::from(vec![0x06, 0x01, tag])],
        ..LinkHello::default()
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

/// The value memberships are bound to is the same on both sides of one
/// connection and differs on another, between the same two keys: a
/// binding made for one connection does not hold on the other.
#[tokio::test]
async fn both_sides_share_a_connections_binding_value_and_no_other_connection_does() {
    let dialer = endpoint(ed_key(1), false);
    let listener = endpoint(ed_key(2), true);
    let target = addr(&listener);
    let mut values = Vec::new();
    for _ in 0..2 {
        let (dialed, accepted) = tokio::join!(dialer.connect(target, None), async {
            listener.accept().await.unwrap().handshake().await
        });
        let (dialed, accepted) = (dialed.unwrap(), accepted.unwrap());
        let value = dialed.channel_binding().unwrap();
        assert_eq!(accepted.channel_binding().unwrap(), value);
        values.push(value);
    }
    assert_ne!(values[0], values[1]);
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
        Err(LinkError::UnexpectedKey {
            expected,
            presented,
        }) => {
            assert_eq!(expected, wrong);
            assert_eq!(presented, ed_key(2).fingerprint());
        }
        Err(other) => panic!("expected UnexpectedKey, got {other}"),
        Ok(_) => panic!("a dial expecting another key succeeded"),
    }
    assert!(
        accept.await.unwrap().is_some(),
        "the listener saw a link come up"
    );
}

#[tokio::test]
async fn a_refusal_reaches_the_other_side_with_its_reason() {
    let dialer = endpoint(ed_key(1), false);
    let listener = endpoint(ed_key(2), true);
    let target = addr(&listener);
    let refuse = async {
        let mut hs = listener.accept().await.unwrap().handshake().await.unwrap();
        hs.exchange_hello(&hello(2), T).await.unwrap();
        hs.refuse(
            CloseReason::Unrecognized,
            "not a device of a namespace I hold",
        );
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
            Ok(_) => hs
                .admit(FaceId(2), T, Admission::default())
                .await
                .err()
                .unwrap(),
        }
    };
    let dial = async {
        let mut hs = dialer.connect(target, None).await.unwrap();
        hs.exchange_hello(&hello(1), Duration::from_millis(200))
            .await
            .err()
            .unwrap()
    };
    let (told, waited) = tokio::join!(slow, dial);
    assert!(matches!(waited, LinkError::Timeout), "{waited:?}");
    match told {
        LinkError::Refused { reason, text } => {
            assert_eq!(
                reason,
                Some(CloseReason::Protocol),
                "not a shutdown: {text}"
            );
            assert!(text.contains("no link message"), "{text}");
            assert!(
                !told_is_transient(reason),
                "the slow side does not dial again at once"
            );
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
    assert_eq!(
        tokio::time::timeout(T, b.face.recv_bytes())
            .await
            .unwrap()
            .unwrap(),
        small
    );
    b.face.send_bytes(small.clone()).await.unwrap();
    assert_eq!(
        tokio::time::timeout(T, a.face.recv_bytes())
            .await
            .unwrap()
            .unwrap(),
        small
    );

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
        let frame = tokio::time::timeout(T, b.face.recv_bytes())
            .await
            .unwrap()
            .unwrap();
        assert!(
            frame.len() <= mtu,
            "a {} B frame over the {mtu} B datagram size",
            frame.len()
        );
        let lp = ndn_packet::lp::LpPacket::decode(frame).unwrap();
        assert!(
            lp.frag_count.unwrap_or(1) > 1,
            "the large packet was not fragmented"
        );
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

/// A burst received between two idle-Ack ticks leaves hundreds of Acks owed.
/// They go out in datagrams the connection takes (its datagram size, which
/// the tick reads as it sends, not the face's fragmentation threshold of
/// 8800): all of them reach the peer. Sent in one packet sized for 8800,
/// the burst's Acks were over the path size and dropped, each a frame the
/// peer then resent.
#[tokio::test]
async fn the_acks_of_a_burst_reach_the_peer_in_datagrams_that_fit() {
    const BURST: usize = 600;
    let dialer = endpoint(ed_key(1), false);
    let listener = endpoint(ec_key(2), true);
    let (a, b) = link(&dialer, &listener).await;
    let service = Arc::new(LpLinkService::new());
    let face = Face::from_parts(
        Arc::new(a.face) as Arc<dyn ndn_transport::ErasedTransport>,
        Arc::clone(&service) as Arc<dyn ndn_transport::LinkService>,
    );

    for seq in 0..BURST as u64 {
        let frame =
            ndn_packet::lp::encode_lp_reliable(&[0x05, 0x03, 0xAA, 0xBB, 0xCC], seq, None, &[]);
        b.face.send_bytes(frame).await.unwrap();
    }
    for _ in 0..BURST {
        tokio::time::timeout(T, face.recv_bytes())
            .await
            .unwrap()
            .unwrap();
    }

    // The engine's tick: drain the owed Acks at the transport's limit of now,
    // each packet sent as it is.
    while let Some(ack) = service
        .reliability_feature()
        .take_acks(face.transport.send_mtu())
    {
        face.send_bytes(ack).await.unwrap();
    }

    let mut acked = 0;
    while acked < BURST {
        let frame = recv(&b.face).await;
        // The datagram size only grows as path MTU discovery finds room, so
        // its value now is at least what it was when the Acks were sized.
        let mtu = face.transport.send_mtu().unwrap();
        assert!(
            frame.len() <= mtu,
            "a {} B frame over the {mtu} B datagram size",
            frame.len()
        );
        acked += ndn_packet::lp::extract_acks(&frame).1.len();
    }
    assert_eq!(acked, BURST);
}

/// The next frame `face` delivers.
async fn recv(face: &ndn_face_quic::LinkFace) -> Bytes {
    tokio::time::timeout(T, face.recv_bytes())
        .await
        .unwrap()
        .unwrap()
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
            rate: RateLimit {
                burst: 16,
                per_sec: 4,
            },
            bandwidth: None,
            rated: Vec::new(),
            interests: None,
            answered: None,
            shared: None,
            explain: "enrollment only".into(),
            answers_in: None,
            interests_in: None,
            narrowing: None,
            counts: None,
        };
        let admission = Admission {
            verdict: LinkVerdict {
                enrollment_link: Some(vec!["/home".parse().unwrap()]),
            },
            scope: Some(scope),
            ..Admission::default()
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
    assert_eq!(
        got.fragment.unwrap(),
        inside,
        "the first packet the relay sees is the one in scope"
    );
    // The relay's face keeps reading (and Nacking) while the device waits.
    let nack = tokio::select! {
        nack = recv(&device.face) => nack,
        other = relay.face.recv_bytes() => panic!("the relay's forwarder got {other:?}"),
    };
    let nack = ndn_packet::lp::LpPacket::decode(nack).unwrap();
    assert!(
        nack.nack.is_some(),
        "the device got a Nack for the Interest outside the scope"
    );
    assert_eq!(nack.fragment.unwrap(), outside);

    // The relay answers within the scope; it sends no Interest and no Data
    // outside it (each kept back is Nacked to the relay's own side).
    let interest_out = InterestBuilder::new("/home/CA/x".parse::<Name>().unwrap()).build();
    relay
        .face
        .send_bytes(lp(interest_out.clone()))
        .await
        .unwrap();
    let own_nack = ndn_packet::lp::LpPacket::decode(recv(&relay.face).await).unwrap();
    assert_eq!(own_nack.fragment.unwrap(), interest_out);
    relay
        .face
        .send_bytes(lp(DataBuilder::new(
            "/home/member/tab/note".parse::<Name>().unwrap(),
            b"x",
        )
        .build()))
        .await
        .unwrap();
    let answer = DataBuilder::new("/home/CA/NEW".parse::<Name>().unwrap(), b"ok").build();
    relay.face.send_bytes(lp(answer.clone())).await.unwrap();
    let got = ndn_packet::lp::LpPacket::decode(recv(&device.face).await).unwrap();
    assert_eq!(
        got.fragment.unwrap(),
        answer,
        "only the answer in scope reached the device"
    );
}

/// Round 12, the ladder: a relay that has answered what its scope allows used to take the
/// next Interests in and drop their Data silently, each asker left to its timer (250 ms: the
/// 1 MiB put->watch p95). Every Interest of a windowed asker is answered now, by its Data or
/// by a Congestion Nack at once, and none waits for a timer.
#[tokio::test]
async fn an_asker_over_the_budget_of_answers_is_nacked_not_left_to_its_timer() {
    const ASKS: usize = 300;
    const WINDOW: usize = 2;
    let dialer = endpoint(ed_key(1), false);
    let listener = endpoint(ec_key(2), true);
    let target = addr(&listener);
    let name = |i: usize| -> Name { format!("/any/piece/{i}").parse().unwrap() };
    let answer = move |i: usize| DataBuilder::new(name(i), &[7u8; 900]).build();
    let lp = |wire: Bytes| ndn_packet::lp::encode_lp_packet(&wire);
    // A budget of 100 answers, refilled too slowly to matter here: the 300 asks spend it.
    let one = u32::try_from(lp(answer(0)).len()).unwrap();
    let accept = async {
        let mut hs = listener.accept().await.unwrap().handshake().await.unwrap();
        hs.exchange_hello(&hello(2), T).await.unwrap();
        let scope = LinkScope {
            receives: Carries::Everything,
            sends: Carries::Everything,
            names: Box::new(|_: &Name| true),
            rate: RateLimit {
                burst: 100_000,
                per_sec: 100_000,
            },
            bandwidth: None,
            rated: Vec::new(),
            interests: None,
            answered: Some(RateLimit {
                burst: 100 * one,
                per_sec: one,
            }),
            shared: None,
            explain: "answers are budgeted".into(),
            answers_in: None,
            interests_in: None,
            narrowing: None,
            counts: None,
        };
        let admission = Admission {
            verdict: LinkVerdict::default(),
            scope: Some(scope),
            ..Admission::default()
        };
        hs.admit(FaceId(2), T, admission).await.unwrap()
    };
    let dial = async {
        let mut hs = dialer.connect(target, None).await.unwrap();
        hs.exchange_hello(&hello(1), T).await.unwrap();
        hs.admit(FaceId(1), T, Admission::default()).await.unwrap()
    };
    let (device, relay) = tokio::join!(dial, accept);

    // The relay's forwarder answers every Interest its face delivers.
    let relay_face = Arc::new(relay);
    let serving = Arc::clone(&relay_face);
    let served = tokio::spawn(async move {
        loop {
            let Ok(Ok(wire)) = tokio::time::timeout(T, serving.face.recv_bytes()).await else {
                return;
            };
            let Ok(lp) = ndn_packet::lp::LpPacket::decode(wire) else {
                continue;
            };
            let Some(interest) = lp.fragment else {
                continue;
            };
            let Ok(interest) = ndn_packet::Interest::decode(interest) else {
                continue;
            };
            let i: usize = interest
                .name
                .to_string()
                .rsplit('/')
                .next()
                .unwrap()
                .parse()
                .unwrap();
            let _ = serving
                .face
                .send_bytes(ndn_packet::lp::encode_lp_packet(&answer(i)))
                .await;
        }
    });

    // The asker keeps WINDOW in flight, and waits for each reply.
    let (mut next, mut data, mut nacks, mut asked) = (0usize, 0usize, 0usize, 0usize);
    let express = |next: &mut usize, asked: &mut usize| {
        let wire = lp(InterestBuilder::new(name(*next)).build());
        *next += 1;
        *asked += 1;
        wire
    };
    for _ in 0..WINDOW {
        device
            .face
            .send_bytes(express(&mut next, &mut asked))
            .await
            .unwrap();
    }
    while data + nacks < ASKS {
        let Ok(Ok(wire)) =
            tokio::time::timeout(Duration::from_secs(2), device.face.recv_bytes()).await
        else {
            break;
        };
        let lp_in = ndn_packet::lp::LpPacket::decode(wire).unwrap();
        if lp_in.nack.is_some() {
            nacks += 1;
        } else {
            data += 1;
        }
        if asked < ASKS {
            device
                .face
                .send_bytes(express(&mut next, &mut asked))
                .await
                .unwrap();
        }
    }
    served.abort();
    assert_eq!(
        data + nacks,
        ASKS,
        "an Interest was answered by nothing: {data} Data and {nacks} Nacks for {asked} Interests, the rest left to their timer"
    );
    assert!(
        nacks > 0 && data >= 90,
        "the budget of 100 answers was spent and then told: {data} Data, {nacks} Nacks"
    );
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
        tokio::time::timeout(Duration::from_secs(2), listener.accept())
            .await
            .ok()
            .flatten()
            .is_some()
    };
    let (second_dial, accepted_second) = tokio::join!(second.connect(target, None), accepting);
    assert!(
        !accepted_second,
        "the second attempt from the same address was accepted"
    );
    match second_dial {
        Err(LinkError::Refused { reason, .. }) => assert_eq!(reason, Some(CloseReason::Busy)),
        Err(other) => panic!("expected a refusal, got {other}"),
        Ok(_) => panic!("the second attempt from the same address got a handshake"),
    }
}

/// Admitted links are capped: over `max_links` links up, an attempt is
/// refused before its handshake (an open serving policy's keys cannot hold
/// links without end); once one closes, a link is admitted again. Links
/// this side dials do not count.
#[tokio::test]
async fn attempts_over_the_admitted_link_cap_are_refused_until_one_closes() {
    let config = LinkTransportConfig {
        limits: HandshakeLimits {
            max_links: 1,
            ..HandshakeLimits::default()
        },
        ..LinkTransportConfig::default()
    };
    let listener = endpoint_with(ec_key(2), true, config);
    let target = addr(&listener);
    let first = endpoint(ed_key(1), false);
    let (a, b) = link(&first, &listener).await;

    // The listener dials out: that link does not count against its cap.
    let other = endpoint(ed_key(5), true);
    let _dialed = link(&listener, &other).await;

    let second = endpoint(ed_key(3), false);
    let accepting = async {
        tokio::time::timeout(Duration::from_secs(2), listener.accept())
            .await
            .ok()
            .flatten()
            .is_some()
    };
    let (second_dial, accepted_second) = tokio::join!(second.connect(target, None), accepting);
    assert!(!accepted_second, "an attempt over the cap was accepted");
    match second_dial {
        Err(LinkError::Refused { reason, .. }) => assert_eq!(reason, Some(CloseReason::Busy)),
        Err(other) => panic!("expected a refusal, got {other}"),
        Ok(_) => panic!("an attempt over the cap got a handshake"),
    }

    a.handle.close(CloseReason::Shutdown, "done");
    b.handle.closed().await;
    let third = endpoint(ed_key(4), false);
    let deadline = tokio::time::Instant::now() + T;
    loop {
        let (dialed, accepted) = tokio::join!(third.connect(target, None), async {
            let incoming = tokio::time::timeout(Duration::from_millis(500), listener.accept())
                .await
                .ok()
                .flatten()?;
            incoming.handshake().await.ok()
        });
        if let (Ok(_), Some(_)) = (dialed, accepted) {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "no link admitted after the only one closed"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
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
    assert_eq!(
        tokio::time::timeout(T, b.face.recv_bytes())
            .await
            .unwrap()
            .unwrap(),
        pkt
    );
    b.face.send_bytes(pkt.clone()).await.unwrap();
    assert_eq!(
        tokio::time::timeout(T, a.face.recv_bytes())
            .await
            .unwrap()
            .unwrap(),
        pkt
    );
}

#[tokio::test]
async fn a_migrated_links_face_names_the_new_address() {
    let dialer = endpoint(ed_key(1), false);
    let listener = endpoint(ed_key(2), true);
    let (a, b) = link(&dialer, &listener).await;
    let uri = |addr: SocketAddr| Some(format!("quic4://{addr}"));
    assert_eq!(b.face.remote_uri(), uri(addr(&dialer)));
    let before = addr(&dialer);
    dialer
        .rebind(std::net::UdpSocket::bind("127.0.0.1:0").unwrap())
        .unwrap();
    let after = addr(&dialer);
    assert_ne!(before, after);
    let pkt = Bytes::from_static(&[0x05, 0x03, 0x07, 0x01, 0x42]);
    a.face.send_bytes(pkt.clone()).await.unwrap();
    assert_eq!(
        tokio::time::timeout(T, b.face.recv_bytes())
            .await
            .unwrap()
            .unwrap(),
        pkt
    );
    until("the listener's face still names the old address", || {
        b.face.remote_uri() == uri(after)
    })
    .await;
    assert_eq!(b.face.remote_uri(), uri(b.handle.remote_address()));
}

#[tokio::test]
async fn a_rebound_links_face_names_its_new_local_address() {
    let dialer = endpoint(ed_key(1), false);
    let listener = endpoint(ed_key(2), true);
    let (a, b) = link(&dialer, &listener).await;
    let uri = |addr: SocketAddr| Some(format!("quic4://{addr}"));
    let before = addr(&dialer);
    assert_eq!(a.face.local_uri(), uri(before));
    assert_eq!(a.handle.local_address(), Some(before));
    assert_eq!(b.face.local_uri(), uri(addr(&listener)));
    dialer
        .rebind(std::net::UdpSocket::bind("127.0.0.1:0").unwrap())
        .unwrap();
    let after = addr(&dialer);
    assert_ne!(before, after);
    assert_eq!(a.face.local_uri(), uri(after));
    assert_eq!(a.handle.local_address(), Some(after));
    assert_eq!(b.face.local_uri(), uri(addr(&listener)));
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
    assert!(
        a.face.recv_bytes().await.is_err(),
        "the face outlived its link"
    );
}

/// What a hostile peer puts in a close reason: a forged log line, a terminal
/// escape, a bidi override, a zero-width character, and a page of words.
fn hostile_text() -> String {
    format!(
        "your key is revoked\n2026-01-01 INFO face.quic: trusted \x1b[2J\x1b[31m call \u{202E}now\u{200B}{}",
        " persuade".repeat(500)
    )
}

/// What a link hands up of the other device's close text has no control or
/// invisible character, is on one line and is bounded, whichever way the
/// other device closed.
fn assert_clean(text: &str) {
    assert!(
        !text
            .chars()
            .any(|c| c.is_control()
                || matches!(c, '\u{202E}' | '\u{200B}' | '\u{2066}'..='\u{2069}')),
        "the peer's control characters reached the caller: {text:?}"
    );
    assert!(
        text.chars().count() <= ndn_face_quic::PEER_TEXT_MAX,
        "the peer's text is not bounded: {} characters",
        text.chars().count()
    );
    assert!(
        text.starts_with("your key is revoked 2026-01-01 INFO"),
        "{text:?}"
    );
}

#[tokio::test]
async fn a_hostile_close_text_is_cleaned_before_it_is_handed_up() {
    let dialer = endpoint(ed_key(1), false);
    let listener = endpoint(ed_key(2), true);
    let (a, b) = link(&dialer, &listener).await;
    b.handle.close(CloseReason::Revoked, &hostile_text());
    match tokio::time::timeout(T, a.handle.closed()).await.unwrap() {
        LinkError::Refused { reason, text } => {
            assert_eq!(reason, Some(CloseReason::Revoked));
            assert_clean(&text);
            assert!(text.ends_with('…'), "{text:?}");
        }
        other => panic!("expected the close reason, got {other}"),
    }
}

#[tokio::test]
async fn a_hostile_refusal_text_is_cleaned_before_it_is_handed_up() {
    let dialer = endpoint(ed_key(1), false);
    let listener = endpoint(ed_key(2), true);
    let target = addr(&listener);
    let refuse = async {
        let mut hs = listener.accept().await.unwrap().handshake().await.unwrap();
        hs.exchange_hello(&hello(2), T).await.unwrap();
        hs.refuse(CloseReason::Revoked, &hostile_text());
    };
    let dial = async {
        let mut hs = dialer.connect(target, None).await.unwrap();
        match hs.exchange_hello(&hello(1), T).await {
            Err(e) => Some(e),
            Ok(_) => hs.admit(FaceId(1), T, Admission::default()).await.err(),
        }
    };
    let ((), refused) = tokio::join!(refuse, dial);
    match refused {
        Some(error @ LinkError::Refused { .. }) => {
            let LinkError::Refused { text, .. } = &error else {
                unreachable!()
            };
            assert_clean(text);
            assert_clean(
                error
                    .to_string()
                    .strip_prefix("the other device closed the link: ")
                    .expect("the sentence quotes the text"),
            );
        }
        other => panic!("expected the refusal, got {other:?}"),
    }
}

/// Wait until `handle` says the other side sees this one at `want`.
async fn observed(link: &Link, want: SocketAddr, within: Duration) {
    let start = std::time::Instant::now();
    while link.handle.observed_address() != Some(want) {
        assert!(
            start.elapsed() < within,
            "observed {:?}, expected {want}",
            link.handle.observed_address()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn each_side_tells_the_other_the_address_it_sees_and_again_when_it_changes() {
    let dialer = endpoint(ed_key(1), false);
    let listener = endpoint(ed_key(2), true);
    let (a, b) = link(&dialer, &listener).await;
    observed(&a, addr(&dialer), T).await;
    observed(&b, addr(&listener), T).await;
    // The dialer moves: the listener tells it its new address.
    dialer
        .rebind(std::net::UdpSocket::bind("127.0.0.1:0").unwrap())
        .unwrap();
    let pkt = Bytes::from_static(&[0x05, 0x03, 0x07, 0x01, 0x42]);
    a.face.send_bytes(pkt.clone()).await.unwrap();
    assert_eq!(
        tokio::time::timeout(T, b.face.recv_bytes())
            .await
            .unwrap()
            .unwrap(),
        pkt
    );
    observed(&a, addr(&dialer), Duration::from_secs(10)).await;
}

#[tokio::test]
async fn probes_reach_the_punch_that_watches_them_and_never_quic() {
    let a = endpoint(ed_key(1), true);
    let b = endpoint(ed_key(2), true);
    let session = [7u8; 8];
    let mut watch = b.watch_probes(session);
    let mut unwatched = b.watch_probes([8u8; 8]);
    a.send_probe(addr(&b), &session).await.unwrap();
    let from = tokio::time::timeout(T, watch.next()).await.unwrap();
    assert_eq!(from, Some(addr(&a)));
    assert!(
        tokio::time::timeout(Duration::from_millis(200), unwatched.next())
            .await
            .is_err(),
        "a probe of another session was delivered"
    );
    // The same sockets still carry links.
    let (x, y) = link(&a, &b).await;
    let pkt = Bytes::from_static(&[0x05, 0x03, 0x07, 0x01, 0x42]);
    x.face.send_bytes(pkt.clone()).await.unwrap();
    assert_eq!(
        tokio::time::timeout(T, y.face.recv_bytes())
            .await
            .unwrap()
            .unwrap(),
        pkt
    );
}

#[tokio::test]
async fn a_socket_that_does_not_listen_takes_only_the_direct_path_its_punch_expects() {
    let quick = LinkTransportConfig {
        handshake_timeout: Duration::from_millis(800),
        ..LinkTransportConfig::default()
    };
    let punched = Arc::new(endpoint_with(ed_key(2), false, quick.clone()));
    let peer = endpoint_with(ed_key(1), false, quick.clone());
    let stranger = endpoint_with(ed_key(3), false, quick);
    let target = addr(&punched);
    let key = ed_key(2).fingerprint();
    // Whatever the socket accepts is handshaken and reported.
    let (tx, mut accepted) = tokio::sync::mpsc::unbounded_channel();
    let acceptor = Arc::clone(&punched);
    tokio::spawn(async move {
        while let Some(incoming) = acceptor.accept().await {
            let tx = tx.clone();
            tokio::spawn(async move {
                if let Ok(hs) = incoming.handshake().await {
                    let _ = tx.send(hs.peer_key().fingerprint());
                }
            });
        }
    });
    // No punch: nothing answers, not even a refusal.
    assert!(matches!(
        peer.connect_direct(target, key).await,
        Err(LinkError::Connect(_))
    ));
    let window = punched.allow_inbound(&[addr(&peer)]);
    let dialed = peer.connect_direct(target, key).await.unwrap();
    assert_eq!(dialed.peer_key().fingerprint(), key);
    let from = tokio::time::timeout(T, accepted.recv()).await.unwrap();
    assert_eq!(from, Some(ed_key(1).fingerprint()));
    // Another address, while the window is open: nothing answers.
    assert!(matches!(
        stranger.connect_direct(target, key).await,
        Err(LinkError::Connect(_))
    ));
    drop(window);
    assert!(matches!(
        peer.connect_direct(target, key).await,
        Err(LinkError::Connect(_))
    ));
    assert!(
        accepted.try_recv().is_err(),
        "the socket took a connection no punch expected"
    );
}

#[tokio::test]
async fn an_endpoint_links_on_a_socket_the_host_bound() {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let bound = socket.local_addr().unwrap();
    let config = LinkTransportConfig::default();
    let listener = LinkEndpoint::from_socket(socket, Arc::new(ed_key(2)), &config, true).unwrap();
    assert_eq!(addr(&listener), bound);
    let dialer = endpoint(ed_key(1), false);
    let (a, b) = link(&dialer, &listener).await;
    let pkt = Bytes::from_static(&[0x05, 0x03, 0x07, 0x01, 0x43]);
    a.face.send_bytes(pkt.clone()).await.unwrap();
    assert_eq!(recv(&b.face).await, pkt);
}

/// The kernel's limit on a socket buffer a process may ask for (Linux only; `None` elsewhere).
fn buffer_limit(name: &str) -> Option<usize> {
    std::fs::read_to_string(format!("/proc/sys/net/core/{name}"))
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// A window of pieces arrives as hundreds of datagrams at once: 128 Data of 4,096 bytes
/// fragment to some 600 frames of 1,200 bytes. A socket left at the kernel's default buffer
/// (208 KiB, which holds about 90 such datagrams once the packet metadata is counted) drops
/// what its reader has not taken yet, and each datagram lost that way costs the asker a
/// re-expression timer of 250 ms (round 12: the 1 MiB put->watch p95 was that timer). The
/// endpoint asks the kernel for [`LINK_SOCKET_BUFFER`] of both buffers on every socket it
/// uses, one the host bound included, and so does a rebind.
#[tokio::test]
async fn a_link_socket_takes_the_buffers_a_burst_of_pieces_needs() {
    use socket2::SockRef;
    let (recv_limit, send_limit) = (buffer_limit("rmem_max"), buffer_limit("wmem_max"));
    let fresh = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let default = (
        SockRef::from(&fresh).recv_buffer_size().unwrap(),
        SockRef::from(&fresh).send_buffer_size().unwrap(),
    );
    // What the kernel gives for a request, as `getsockopt` reports it (Linux counts the
    // metadata too and reports twice what was granted).
    let expected = |limit: Option<usize>, default: usize| match limit {
        Some(limit) => default.max(2 * limit.min(LINK_SOCKET_BUFFER)),
        None => default,
    };
    let (want_recv, want_send) = (
        expected(recv_limit, default.0),
        expected(send_limit, default.1),
    );
    let sizes = |socket: &std::net::UdpSocket| {
        (
            SockRef::from(socket).recv_buffer_size().unwrap(),
            SockRef::from(socket).send_buffer_size().unwrap(),
        )
    };

    let bound = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let seen = bound.try_clone().unwrap();
    let config = LinkTransportConfig::default();
    let endpoint = LinkEndpoint::from_socket(bound, Arc::new(ed_key(2)), &config, true).unwrap();
    let (recv, send) = sizes(&seen);
    assert!(
        recv >= want_recv && send >= want_send,
        "the endpoint left its socket at {recv} bytes to receive and {send} to send; the kernel allows {want_recv} and {want_send} (default {default:?})"
    );

    let moved = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let seen = moved.try_clone().unwrap();
    endpoint.rebind(moved).unwrap();
    let (recv, send) = sizes(&seen);
    assert!(
        recv >= want_recv && send >= want_send,
        "the rebind left its socket at {recv} bytes to receive and {send} to send; the kernel allows {want_recv} and {want_send}"
    );
}

/// Wait until `f` holds, polling.
async fn until(what: &str, mut f: impl FnMut() -> bool) {
    let start = std::time::Instant::now();
    while !f() {
        assert!(start.elapsed() < T, "{what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn the_peers_latest_reachability_replaces_the_earlier() {
    let dialer = endpoint(ed_key(1), false);
    let listener = endpoint(ed_key(2), true);
    let (device, relay) = link(&dialer, &listener).await;
    assert_eq!(relay.handle.peer_reachability(), None);
    let first = Reachability {
        hold: true,
        wake_token: Some(Bytes::from_static(b"push-token-1")),
    };
    device.handle.send_reachability(&first);
    until("the relay heard the reachability", || {
        relay.handle.peer_reachability() == Some(first.clone())
    })
    .await;
    let newer = Reachability {
        hold: false,
        wake_token: None,
    };
    device.handle.send_reachability(&newer);
    until("the newer reachability replaced it", || {
        relay.handle.peer_reachability() == Some(newer.clone())
    })
    .await;
    assert_eq!(
        device.handle.peer_reachability(),
        None,
        "only the device told"
    );
}

#[tokio::test]
async fn presence_reaches_the_peer_and_replaces_per_namespace() {
    let dialer = endpoint(ed_key(1), false);
    let listener = endpoint(ed_key(2), true);
    let (device, relay) = link(&dialer, &listener).await;
    let present = |name: &str, key: u8| PresentDevice {
        device: name.parse().unwrap(),
        key: KeyFingerprint([key; 32]),
    };
    let presence = |ns: &str, devices: Vec<PresentDevice>| Presence {
        namespace: ns.parse().unwrap(),
        devices,
    };
    let home = presence("/home", vec![present("/home/member/phone", 1)]);
    let work = presence("/work", vec![present("/work/node/pc", 2)]);
    relay.handle.send_presence(&home);
    relay.handle.send_presence(&work);
    let seen = device.handle.presence();
    let wait = |want: Vec<Presence>| {
        let mut seen = seen.clone();
        async move {
            tokio::time::timeout(T, seen.wait_for(|p| *p == want))
                .await
                .unwrap()
                .unwrap();
        }
    };
    wait(vec![home.clone(), work.clone()]).await;
    // A newer list for /home replaces it; /work stays.
    let home2 = presence(
        "/home",
        vec![
            present("/home/member/phone", 1),
            present("/home/member/tab", 3),
        ],
    );
    relay.handle.send_presence(&home2);
    wait(vec![home2, work.clone()]).await;
    // An empty list: no device of /home is there any more.
    relay.handle.send_presence(&presence("/home", Vec::new()));
    wait(vec![work]).await;
    assert!(
        relay.handle.presence().borrow().is_empty(),
        "only the relay told"
    );
}

#[tokio::test]
async fn a_departure_reaches_the_peer_once_and_no_more_than_a_link_takes_are_told() {
    let dialer = endpoint(ed_key(1), false);
    let listener = endpoint(ed_key(2), true);
    let (person, inviter) = link(&dialer, &listener).await;
    let departure = |folder: &str, record: &str| Departure {
        folder: folder.parse().unwrap(),
        record: record.parse().unwrap(),
    };
    let a = departure("/a/32=data/one", "/a/d/32=log/one/seq=2");
    let b = departure("/a/32=data/two", "/a/d/32=log/two/seq=7");
    assert!(person.handle.departures().borrow().is_empty());
    inviter.handle.send_departure(&a);
    inviter.handle.send_departure(&b);
    // Told again: still one entry.
    inviter.handle.send_departure(&a);
    let mut heard = person.handle.departures();
    tokio::time::timeout(
        T,
        heard.wait_for(|all| all.contains(&a) && all.contains(&b)),
    )
    .await
    .unwrap()
    .unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        person.handle.departures().borrow().len(),
        2,
        "the same message twice is one entry"
    );
    assert!(
        inviter.handle.departures().borrow().is_empty(),
        "only the inviter told"
    );

    // More distinct folders than a link takes: the receiver closes the link
    // as a protocol error and says why.
    for i in 0..40 {
        inviter.handle.send_departure(&departure(
            &format!("/a/32=data/f{i}"),
            &format!("/a/d/32=log/f{i}/seq=1"),
        ));
    }
    let mut heard = person.handle.departures();
    tokio::time::timeout(
        T,
        heard.wait_for(|all| all.len() == ndn_face_quic::DEPARTURES_MAX),
    )
    .await
    .unwrap()
    .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        person.handle.departures().borrow().len(),
        ndn_face_quic::DEPARTURES_MAX,
        "a sender tells no more folders than the peer takes"
    );
    assert!(
        !inviter.handle.is_closed() && !person.handle.is_closed(),
        "telling too many is not a reason to close the link"
    );
}

#[tokio::test]
async fn datagrams_count_ndn_traffic_and_not_keep_alives() {
    let config = LinkTransportConfig {
        keep_alive: Duration::from_millis(100),
        idle_timeout: Duration::from_secs(5),
        ..LinkTransportConfig::default()
    };
    let dialer = endpoint_with(ed_key(1), false, config.clone());
    let listener = endpoint_with(ed_key(2), true, config);
    let (a, b) = link(&dialer, &listener).await;
    let (a0, b0) = (a.handle.datagrams(), b.handle.datagrams());
    // Several keep-alive intervals with no NDN traffic.
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert_eq!(
        (a.handle.datagrams(), b.handle.datagrams()),
        (a0, b0),
        "keep-alives are not counted"
    );
    let pkt = Bytes::from_static(&[0x05, 0x03, 0x07, 0x01, 0x44]);
    a.face.send_bytes(pkt.clone()).await.unwrap();
    assert_eq!(recv(&b.face).await, pkt);
    b.face.send_bytes(pkt.clone()).await.unwrap();
    assert_eq!(recv(&a.face).await, pkt);
    assert_eq!(a.handle.datagrams(), a0 + 2, "one sent, one received");
    assert_eq!(b.handle.datagrams(), b0 + 2, "one received, one sent");
}

// ---- The side path: channel frames beside NDN packets ------------------------------------

/// A channel frame: the marker, `tag` as four octets, then filler up to `len`.
fn frame(tag: u32, len: usize) -> Bytes {
    let mut v = vec![0u8; len.max(5)];
    v[1..5].copy_from_slice(&tag.to_be_bytes());
    for (i, b) in v.iter_mut().enumerate().skip(5) {
        *b = (i % 251) as u8 | 1;
    }
    Bytes::from(v)
}

fn carrying() -> Admission {
    Admission {
        channel: ChannelPolicy {
            carry: true,
            quota: None,
        },
        ..Admission::default()
    }
}

/// Dial and admit with the given hellos and admissions; the dialer's link first.
async fn link_with(
    dialer: &LinkEndpoint,
    listener: &LinkEndpoint,
    (hello_d, admission_d): (LinkHello, Admission),
    (hello_l, admission_l): (LinkHello, Admission),
) -> (Link, Link) {
    let target = addr(listener);
    let accept = async {
        let mut hs = listener.accept().await.unwrap().handshake().await.unwrap();
        hs.exchange_hello(&hello_l, T).await.unwrap();
        hs.admit(FaceId(2), T, admission_l).await.unwrap()
    };
    let dial = async {
        let mut hs = dialer.connect(target, None).await.unwrap();
        hs.exchange_hello(&hello_d, T).await.unwrap();
        hs.admit(FaceId(1), T, admission_d).await.unwrap()
    };
    tokio::join!(dial, accept)
}

/// A link both sides of which carry channel frames, with no quota.
async fn channel_link(dialer: &LinkEndpoint, listener: &LinkEndpoint) -> (Link, Link) {
    link_with(
        dialer,
        listener,
        (hello(1), carrying()),
        (hello(2), carrying()),
    )
    .await
}

/// What `face` delivers within `within`, until it delivers nothing for that long.
async fn drain_for(face: &ndn_face_quic::LinkFace, within: Duration) -> Vec<Bytes> {
    let mut got = Vec::new();
    while let Ok(Ok(wire)) = tokio::time::timeout(within, face.recv_bytes()).await {
        got.push(wire);
    }
    got
}

#[tokio::test]
async fn a_channel_datagram_reaches_recv_bytes_unchanged_and_is_not_nacked_over_quota() {
    let dialer = endpoint(ed_key(1), false);
    let listener = endpoint(ec_key(2), true);
    // The listener's link is scoped to one frame of NDN traffic, a scope that would drop
    // (and Nack) a channel frame it judged; its channel quota is 3,000 octets a second.
    let counts = Arc::new(ScopeCounts::default());
    let scope = LinkScope {
        receives: Carries::Everything,
        sends: Carries::Everything,
        names: Box::new(|_: &Name| true),
        rate: RateLimit {
            burst: 1,
            per_sec: 1,
        },
        bandwidth: None,
        rated: Vec::new(),
        interests: None,
        answered: None,
        shared: None,
        explain: "one frame".into(),
        answers_in: None,
        interests_in: None,
        narrowing: None,
        counts: Some(Arc::clone(&counts)),
    };
    let quota = Admission {
        scope: Some(scope),
        channel: ChannelPolicy {
            carry: true,
            quota: Some(FairShare::new(3000, 100, Duration::from_secs(1))),
        },
        ..Admission::default()
    };
    let (a, b) = link_with(
        &dialer,
        &listener,
        (hello(1), carrying()),
        (hello(2), quota),
    )
    .await;

    let sent: Vec<Bytes> = (0..6).map(|i| frame(i, 1000)).collect();
    for f in &sent {
        a.face
            .send_side(f.clone(), SideClass::Datagram)
            .await
            .unwrap();
    }
    let mut got = drain_for(&b.face, Duration::from_millis(400)).await;
    got.sort_by_key(|f| f[1..5].to_vec());
    assert_eq!(
        got,
        sent[..3],
        "the quota of 3,000 octets passed three frames of 1,000, each unchanged"
    );
    let stats = b.handle.side_stats();
    assert_eq!(stats.datagram_rx_frames, 3);
    assert_eq!(stats.datagram_rx_bytes, 3000);
    assert_eq!(stats.dropped_over_quota, 3);
    assert_eq!(a.handle.side_stats().datagram_tx_frames, 6);
    // The NDN scope never saw a channel frame: its rate (one frame) dropped none, and a
    // Nack answers Interests only, so nothing came back to the sender.
    assert_eq!(counts.over_rate(), 0);
    assert_eq!(counts.congestion_nacks(), 0);
    assert!(
        drain_for(&a.face, Duration::from_millis(300))
            .await
            .is_empty(),
        "a frame over quota is dropped without a Nack"
    );
    // NDN traffic over the same link is still judged by its own scope.
    let pkt = ndn_packet::lp::encode_lp_packet(
        &InterestBuilder::new("/any/thing".parse::<Name>().unwrap()).build(),
    );
    a.face.send_bytes(pkt.clone()).await.unwrap();
    assert_eq!(recv(&b.face).await, pkt);
    assert!(!a.handle.is_closed() && !b.handle.is_closed());
}

#[tokio::test]
async fn a_channel_stream_carries_frames_in_order_both_ways_on_the_links_connection() {
    const FRAMES: u32 = 120;
    let dialer = endpoint(ed_key(1), false);
    let listener = endpoint(ec_key(2), true);
    let (a, b) = channel_link(&dialer, &listener).await;
    let (a, b) = (Arc::new(a), Arc::new(b));
    // Frames from tiny to far over the datagram size and the stream's initial window.
    let size = |i: u32| [20usize, 700, 70_000, 400_000][(i % 4) as usize];
    let datagrams = (a.handle.datagrams(), b.handle.datagrams());

    let writer = |from: &Arc<Link>| {
        let from = Arc::clone(from);
        tokio::spawn(async move {
            for i in 0..FRAMES {
                from.face
                    .send_side(frame(i, size(i)), SideClass::Stream)
                    .await
                    .unwrap();
            }
        })
    };
    let (wa, wb) = (writer(&a), writer(&b));
    for to in [&a, &b] {
        for i in 0..FRAMES {
            let got = recv(&to.face).await;
            assert_eq!(
                got,
                frame(i, size(i)),
                "frame {i} is in its place, unchanged"
            );
        }
    }
    wa.await.unwrap();
    wb.await.unwrap();

    let total: u64 = (0..FRAMES).map(|i| size(i) as u64).sum();
    for link in [&a, &b] {
        let s = link.handle.side_stats();
        assert_eq!(
            (s.stream_tx_frames, s.stream_tx_bytes),
            (u64::from(FRAMES), total)
        );
        assert_eq!(
            (s.stream_rx_frames, s.stream_rx_bytes),
            (u64::from(FRAMES), total)
        );
        assert_eq!((s.datagram_tx_frames, s.datagram_rx_frames), (0, 0));
    }
    // The stream is not a datagram, and carried no NDN packet: the connection's datagram
    // counter did not move.
    assert_eq!((a.handle.datagrams(), b.handle.datagrams()), datagrams);

    // A channel datagram on the same link moves it: one connection carries both.
    a.face
        .send_side(frame(900, 300), SideClass::Datagram)
        .await
        .unwrap();
    assert_eq!(recv(&b.face).await, frame(900, 300));
    assert_eq!(a.handle.datagrams(), datagrams.0 + 1);
    assert_eq!(b.handle.datagrams(), datagrams.1 + 1);
    // NDN packets still ride datagrams beside the stream.
    let pkt = Bytes::from_static(&[0x05, 0x03, 0x07, 0x01, 0x42]);
    b.face.send_bytes(pkt.clone()).await.unwrap();
    assert_eq!(recv(&a.face).await, pkt);
    // Neither side dialed a second connection for the stream.
    let second = tokio::time::timeout(Duration::from_millis(300), listener.accept()).await;
    assert!(second.is_err(), "no second connection reached the listener");
    assert_eq!(a.handle.remote_address(), addr(&listener));
}

/// What `forward_side` hands the stream is written in order, in front of what `send_side`
/// writes after it, and a full queue refuses the frame instead of waiting.
#[tokio::test]
async fn forwarded_stream_frames_keep_their_order_and_a_full_queue_refuses() {
    let dialer = endpoint(ed_key(1), false);
    let listener = endpoint(ec_key(2), true);
    let (a, b) = channel_link(&dialer, &listener).await;
    for i in 0..50 {
        a.face
            .forward_side(frame(i, 2000), SideClass::Stream)
            .unwrap();
    }
    a.face
        .send_side(frame(50, 100), SideClass::Stream)
        .await
        .unwrap();
    for i in 0..51 {
        let got = recv(&b.face).await;
        assert_eq!(got, frame(i, if i == 50 { 100 } else { 2000 }));
    }
    // Frames of 1 MiB fill the 4 MiB queue while the writer has not run: the caller
    // is told Full, at once.
    let mut refused = None;
    for i in 0..64 {
        if let Err(e) = a
            .face
            .forward_side(frame(100 + i, 1024 * 1024), SideClass::Stream)
        {
            refused = Some(e);
            break;
        }
    }
    assert_eq!(refused, Some(SideRefused::Full));
    assert!(a.handle.side_stats().sink_full >= 1);
    // A frame over the stream's limit is refused with the limit.
    assert_eq!(
        a.face
            .forward_side(frame(7, 1024 * 1024 + 1), SideClass::Stream),
        Err(SideRefused::TooLarge {
            size: 1024 * 1024 + 1,
            max: 1024 * 1024
        })
    );
}

/// A sink face that cannot take a frame refuses it `Full` and moves nothing, and the receiver
/// sees exactly the gap: the frames the sink took arrive in order, none of the refused ones
/// ever do, and the frame sent once the sink had room arrives after a hole of the refused
/// tags (docs/specs/channel.md: relays are lossy under congestion, visibly: the next frame's
/// sequence shows the gap). Counted by the face as `sink_full`.
#[tokio::test]
async fn a_congested_sink_refuses_and_the_receiver_sees_exactly_the_gap() {
    let dialer = endpoint(ed_key(1), false);
    let listener = endpoint(ec_key(2), true);
    let (a, b) = channel_link(&dialer, &listener).await;
    // 1 MiB frames fill the 4 MiB queue while the writer has not run: some are taken, then
    // every one is refused at once.
    let (mut taken, mut refused) = (Vec::new(), Vec::new());
    for tag in 100..132u32 {
        match a
            .face
            .forward_side(frame(tag, 1024 * 1024), SideClass::Stream)
        {
            Ok(()) => taken.push(tag),
            Err(SideRefused::Full) => refused.push(tag),
            Err(other) => panic!("a sink either takes a frame or says Full, got {other}"),
        }
    }
    assert!(!taken.is_empty(), "an empty queue takes frames");
    assert!(
        !refused.is_empty(),
        "a 4 MiB queue is full after {} MiB",
        taken.len()
    );
    assert!(
        taken.iter().all(|t| *t < refused[0]),
        "the queue refuses once it is full, not before"
    );
    assert_eq!(a.handle.side_stats().sink_full, refused.len() as u64);
    // The receiver drains what the sink took, in order.
    for tag in &taken {
        assert_eq!(recv(&b.face).await, frame(*tag, 1024 * 1024));
    }
    // The sink has room again: the next frame is taken, and arrives after a hole that is
    // exactly the refused tags.
    let later = 200u32;
    let start = std::time::Instant::now();
    while a
        .face
        .forward_side(frame(later, 1024), SideClass::Stream)
        .is_err()
    {
        assert!(start.elapsed() < T, "the queue never had room again");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let got = recv(&b.face).await;
    assert_eq!(got, frame(later, 1024));
    let seen: Vec<u32> = taken.iter().copied().chain([later]).collect();
    assert!(
        refused.iter().all(|t| !seen.contains(t)),
        "no refused frame reached the receiver"
    );
    assert!(
        drain_for(&b.face, Duration::from_millis(300))
            .await
            .is_empty(),
        "and nothing else came"
    );
}

#[tokio::test]
async fn the_headroom_rule_bounds_what_a_channel_frame_waits_behind_ndn_datagrams() {
    const NDN: usize = 20_000;
    const CHANNEL: usize = 100;
    let dialer = endpoint(ed_key(1), false);
    let listener = endpoint(ec_key(2), true);
    let (a, b) = channel_link(&dialer, &listener).await;
    let a = Arc::new(a);
    // A link that has sent nothing yet has the floor: a modest rate gets what any link
    // slower than 1 Gbit/s gets.
    assert_eq!(a.face.side_limits().queue_max, QUEUE_FLOOR);
    // The peer reads nothing: the sender's buffer is all that holds the flood.
    let _b = b;

    let ndn = Bytes::from(vec![0x05u8; 1000]);
    let flood = {
        let a = Arc::clone(&a);
        tokio::spawn(async move {
            for _ in 0..NDN {
                // Waits for room: never drops an NDN datagram.
                a.face.send_bytes(ndn.clone()).await.unwrap();
            }
        })
    };
    // Wait for NDN datagrams to fill the send buffer past the headroom.
    let mut forwarded_full = false;
    let mut widest = QUEUE_FLOOR;
    let start = std::time::Instant::now();
    while !forwarded_full {
        assert!(
            start.elapsed() < T,
            "the NDN flood never queued {QUEUE_FLOOR} octets"
        );
        let limits = a.face.side_limits();
        if limits.queued > limits.queue_max {
            // The non-blocking path refuses and counts, and moves nothing.
            forwarded_full =
                a.face.forward_side(frame(0, 200), SideClass::Datagram) == Err(SideRefused::Full);
        }
        tokio::time::sleep(Duration::from_micros(200)).await;
    }
    assert!(a.handle.side_stats().sink_full >= 1);
    // Channel frames wait for headroom instead.
    for i in 0..CHANNEL {
        tokio::time::timeout(
            T,
            a.face.send_side(frame(i as u32, 200), SideClass::Datagram),
        )
        .await
        .expect("a channel frame got through the flood")
        .unwrap();
        // The headroom each frame was handed over under is at most the widest seen after it.
        let limits = a.face.side_limits();
        assert!((QUEUE_FLOOR..=QUEUE_CAP).contains(&limits.queue_max));
        widest = widest.max(limits.queue_max);
    }
    flood.await.unwrap();
    let stats = a.handle.side_stats();
    assert!(
        stats.queued_peak < widest as u64 && stats.queued_peak < QUEUE_CAP as u64,
        "a channel frame was handed over behind {} octets, over the {widest} headroom \
         ({QUEUE_FLOOR} to {QUEUE_CAP})",
        stats.queued_peak
    );
    // The channel datagrams the polling above did not refuse are counted with the rest.
    assert!(stats.datagram_tx_frames >= CHANNEL as u64);
    // Everything queued leaves: not one NDN datagram was dropped to make room.
    let start = std::time::Instant::now();
    while a.face.side_limits().queued > 0 {
        assert!(start.elapsed() < T, "the send buffer never drained");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(
        a.handle.datagrams(),
        NDN as u64 + stats.datagram_tx_frames,
        "every NDN and channel datagram left the send buffer"
    );
}

#[tokio::test]
async fn a_frame_over_the_path_size_is_repacked_once() {
    let dialer = endpoint(ed_key(1), false);
    let listener = endpoint(ec_key(2), true);
    let (a, b) = channel_link(&dialer, &listener).await;
    let max = a.face.side_frame_max();
    assert_eq!(
        Some(max),
        a.face.send_mtu(),
        "a datagram carries what the connection's datagram size says"
    );
    assert_eq!(max, a.handle.max_datagram_size().unwrap());
    // One octet over the limit: refused with the limit now, on both paths.
    let over = frame(1, max + 1);
    let refusal = SideRefused::TooLarge { size: max + 1, max };
    assert_eq!(
        a.face.send_side(over.clone(), SideClass::Datagram).await,
        Err(refusal.clone())
    );
    assert_eq!(
        a.face.forward_side(over.clone(), SideClass::Datagram),
        Err(refusal)
    );
    // Cut to the limit it reports, the frame is accepted and arrives whole.
    let cut = frame(1, a.face.side_frame_max());
    a.face
        .send_side(cut.clone(), SideClass::Datagram)
        .await
        .unwrap();
    assert_eq!(recv(&b.face).await, cut);
    // The stream takes the frame the datagram could not carry.
    a.face
        .send_side(over.clone(), SideClass::Stream)
        .await
        .unwrap();
    assert_eq!(recv(&b.face).await, over);
    assert_eq!(a.handle.side_stats().refused, 0);
}

/// Nothing but a channel frame goes on the side path: a frame that does not start with
/// the marker (an NDN packet) is refused for both carriers, so no NDN packet travels on a
/// stream or goes unjudged by the scope.
#[tokio::test]
async fn only_a_marked_frame_is_carried_on_the_side_path() {
    let dialer = endpoint(ed_key(1), false);
    let listener = endpoint(ec_key(2), true);
    let (a, b) = channel_link(&dialer, &listener).await;
    let ndn = Bytes::from_static(&[0x05, 0x03, 0x07, 0x01, 0x41]);
    for class in [SideClass::Datagram, SideClass::Stream] {
        assert_eq!(
            a.face.send_side(ndn.clone(), class).await,
            Err(SideRefused::Malformed)
        );
        assert_eq!(
            a.face.forward_side(ndn.clone(), class),
            Err(SideRefused::Malformed)
        );
        assert_eq!(
            a.face.send_side(Bytes::new(), class).await,
            Err(SideRefused::Malformed)
        );
    }
    assert!(
        drain_for(&b.face, Duration::from_millis(200))
            .await
            .is_empty()
    );
    assert_eq!(b.handle.side_stats().frames(), 0);
}

/// A link that does not carry (an unidentified or introduction link) sends nothing,
/// answers a frame it is sent by dropping and counting it, and stays up.
#[tokio::test]
async fn a_link_that_does_not_carry_refuses_channel_frames_and_stays_up() {
    let dialer = endpoint(ed_key(1), false);
    let listener = endpoint(ec_key(2), true);
    let (a, b) = link_with(
        &dialer,
        &listener,
        (hello(1), Admission::default()),
        (hello(2), carrying()),
    )
    .await;
    assert!(a.handle.side_peer_caps() && b.handle.side_peer_caps());
    for class in [SideClass::Datagram, SideClass::Stream] {
        assert_eq!(
            a.face.send_side(frame(1, 100), class).await,
            Err(SideRefused::NotCarried)
        );
        assert_eq!(
            a.face.forward_side(frame(1, 100), class),
            Err(SideRefused::NotCarried)
        );
    }
    assert_eq!(a.handle.side_stats().refused, 4);
    assert_eq!(a.handle.side_stats().frames(), 0);

    // The carrying side sends one anyway: the other drops and counts it, and tells the
    // sender nothing.
    b.face
        .send_side(frame(2, 100), SideClass::Datagram)
        .await
        .unwrap();
    let pkt = Bytes::from_static(&[0x05, 0x03, 0x07, 0x01, 0x43]);
    b.face.send_bytes(pkt.clone()).await.unwrap();
    assert_eq!(
        recv(&a.face).await,
        pkt,
        "the channel frame was dropped, the NDN packet after it delivered"
    );
    assert_eq!(a.handle.side_stats().refused, 5);
    assert_eq!(a.handle.side_stats().datagram_rx_frames, 0);
    assert!(!a.handle.is_closed() && !b.handle.is_closed());
}

/// A hello round trip over a real link carries `ChannelCaps`; a side whose hello claims
/// none makes `send_side` refuse on both sides.
#[tokio::test]
async fn a_peer_without_channel_caps_gets_no_side_frames() {
    let dialer = endpoint(ed_key(1), false);
    let listener = endpoint(ec_key(2), true);
    let plain = LinkHello {
        channel_caps: 0,
        ..hello(2)
    };
    let (a, b) = link_with(
        &dialer,
        &listener,
        (hello(1), carrying()),
        (plain, carrying()),
    )
    .await;
    assert!(
        !a.handle.side_peer_caps(),
        "the listener claimed no channels"
    );
    assert!(b.handle.side_peer_caps());
    for class in [SideClass::Datagram, SideClass::Stream] {
        assert_eq!(
            a.face.send_side(frame(1, 100), class).await,
            Err(SideRefused::PeerLacksChannels)
        );
        assert_eq!(
            b.face.send_side(frame(1, 100), class).await,
            Err(SideRefused::PeerLacksChannels),
            "a side that did not claim the capability sends none either"
        );
        assert_eq!(
            a.face.forward_side(frame(1, 100), class),
            Err(SideRefused::PeerLacksChannels)
        );
    }
    // NDN packets are unaffected.
    let pkt = Bytes::from_static(&[0x05, 0x03, 0x07, 0x01, 0x44]);
    a.face.send_bytes(pkt.clone()).await.unwrap();
    assert_eq!(recv(&b.face).await, pkt);
}

/// A link whose scope narrows in place (a grant's last entry ended: the departure link,
/// ndn-link §8.8) stops carrying channel frames both ways at the moment the scope narrows,
/// by the same judgement (`Narrowing::when`), and stays up: this side sends none (`NotCarried`),
/// drops and counts the datagrams the peer sends, stops reading the peer's stream and delivers
/// none of it.
#[tokio::test]
async fn a_link_whose_scope_narrows_stops_carrying_channel_frames_both_ways() {
    let dialer = endpoint(ed_key(1), false);
    let listener = endpoint(ec_key(2), true);
    let narrowed = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&narrowed);
    let scope = LinkScope {
        receives: Carries::Everything,
        sends: Carries::Everything,
        names: Box::new(|_: &Name| true),
        rate: RateLimit {
            burst: 1000,
            per_sec: 1000,
        },
        bandwidth: None,
        rated: Vec::new(),
        interests: None,
        answered: None,
        shared: None,
        explain: "a grant link".into(),
        answers_in: None,
        interests_in: None,
        narrowing: Some(Narrowing {
            when: Box::new(move || flag.load(Ordering::SeqCst)),
            receives: Carries::Interests,
            sends: Carries::Answers,
        }),
        counts: None,
    };
    let grant_link = Admission {
        scope: Some(scope),
        channel: ChannelPolicy {
            carry: true,
            quota: None,
        },
        ..Admission::default()
    };
    let (a, b) = link_with(
        &dialer,
        &listener,
        (hello(1), carrying()),
        (hello(2), grant_link),
    )
    .await;

    // While the grant stands, frames flow both ways on both carriers.
    for (from, to) in [(&a, &b), (&b, &a)] {
        for class in [SideClass::Datagram, SideClass::Stream] {
            from.face.send_side(frame(1, 200), class).await.unwrap();
            assert_eq!(recv(&to.face).await, frame(1, 200));
        }
    }
    let before = b.handle.side_stats();
    assert_eq!((before.datagram_rx_frames, before.stream_rx_frames), (1, 1));

    // The grant ends: the scope narrows.
    narrowed.store(true, Ordering::SeqCst);

    // This side sends none, by either call.
    for class in [SideClass::Datagram, SideClass::Stream] {
        assert_eq!(
            b.face.send_side(frame(2, 200), class).await,
            Err(SideRefused::NotCarried)
        );
        assert_eq!(
            b.face.forward_side(frame(2, 200), class),
            Err(SideRefused::NotCarried)
        );
    }

    // The peer's datagram is dropped and counted, the stream is stopped: its writer finds
    // the stream stopped within a bounded number of frames, and none is delivered.
    a.face
        .send_side(frame(3, 200), SideClass::Datagram)
        .await
        .unwrap();
    let mut stopped = false;
    for i in 0..500 {
        if a.face
            .send_side(frame(10 + i, 200), SideClass::Stream)
            .await
            .is_err()
        {
            stopped = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        stopped,
        "the narrowed side stopped reading the peer's channel stream"
    );
    for _ in 0..500 {
        if b.handle.side_stats().refused > before.refused {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let after = b.handle.side_stats();
    assert!(
        after.refused > before.refused,
        "the peer's datagram was dropped and counted"
    );
    assert_eq!(
        (after.datagram_rx_frames, after.stream_rx_frames),
        (1, 1),
        "no frame was delivered after the scope narrowed"
    );
    assert!(
        drain_for(&b.face, Duration::from_millis(300))
            .await
            .is_empty()
    );
    assert!(!a.handle.is_closed() && !b.handle.is_closed());
}
