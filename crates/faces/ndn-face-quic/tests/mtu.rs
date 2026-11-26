//! The datagram size of a link on loopback: a connection idle after the handshake finds a path
//! MTU above the 1,200 octets every QUIC path carries, up to the bound `path_mtu_max` sets
//! (9,000 by default); and a link on a bound that high still carries a burst, because one GSO
//! batch never exceeds the 65,507 octets of a UDP datagram.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use ndn_face_quic::{Admission, Link, LinkEndpoint, LinkHello, LinkKey, LinkTransportConfig};
use ndn_security::Ed25519Signer;
use ndn_transport::{FaceId, Transport};

const T: Duration = Duration::from_secs(10);

fn key(seed: u8) -> LinkKey {
    LinkKey::from_signer(Arc::new(Ed25519Signer::from_seed(
        &[seed; 32],
        format!("/ns/member/d{seed}/KEY/k").parse().unwrap(),
    )))
    .unwrap()
}

fn endpoint(seed: u8, listen: bool, config: &LinkTransportConfig) -> LinkEndpoint {
    LinkEndpoint::bind(
        "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
        Arc::new(key(seed)),
        config,
        listen,
    )
    .unwrap()
}

fn hello(tag: u8) -> LinkHello {
    LinkHello {
        certificates: vec![Bytes::from(vec![0x06, 0x01, tag])],
        ..LinkHello::default()
    }
}

async fn link(config: &LinkTransportConfig) -> (Link, Link, [LinkEndpoint; 2]) {
    let (dialer, listener) = (endpoint(1, false, config), endpoint(2, true, config));
    let target = listener.local_addr().unwrap();
    let accept = async {
        let mut hs = listener.accept().await.unwrap().handshake().await.unwrap();
        hs.exchange_hello(&hello(2), T).await.unwrap();
        hs.admit(FaceId(2), T, Admission::default()).await.unwrap()
    };
    let dial = async {
        let mut hs = dialer.connect(target, None).await.unwrap();
        hs.exchange_hello(&hello(1), T).await.unwrap();
        hs.admit(FaceId(1), T, Admission::default()).await.unwrap()
    };
    let (a, b) = tokio::join!(dial, accept);
    (a, b, [dialer, listener])
}

/// The datagram size the link reports once it is above `over`, or what it was at the deadline.
async fn size_over(link: &Link, over: usize) -> usize {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let size = link.handle.max_datagram_size().unwrap();
        if size > over || Instant::now() > deadline {
            return size;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// QUIC's floor: 1,200 octets of UDP payload carry 1,162 of datagram.
const FLOOR: usize = 1162;

/// What the old default bound of 1,452 octets of payload carried as a datagram (the payload
/// less the 38 octets of QUIC header, tag and frame overhead): the ceiling quinn's own default
/// stopped discovery at.
const OLD_CEILING: usize = 1452 - 38;

/// The datagram a payload of the default bound carries: 9,000 less the same 38.
const BOUND: usize = 9000 - 38;

/// Where the search has certainly climbed: its top tiers, far past the old ceiling.
const CLIMBED: usize = 8000;
const _: () = assert!(CLIMBED > OLD_CEILING && CLIMBED < BOUND);

/// The default bound is 9,000 octets of payload; an idle loopback link climbs past the old
/// 1,452 ceiling toward it, both ways, and never past it.
///
/// The size is not asserted exact. Discovery is quinn's binary search over 1,200..=9,000 that
/// stops when the next probe would move less than `minimum_change` (20) octets, then probes the
/// bound itself if that is still 20 or more away: payloads 5,100, 7,050, 8,025, 8,512, 8,756,
/// 8,878, 8,939, 8,969, 9,000. A probe that is lost lowers the search's upper bound and ends it
/// lower: a lost 9,000 ends it at 8,969 (8,931 of datagram, seen once under load), a lost
/// earlier probe sooner. So what holds on any machine is the band: above 8,000 (the search
/// reached its top tiers, far past the old ceiling) and at most the bound (the endpoint's
/// `max_udp_payload_size` caps what the peer probes).
#[tokio::test]
async fn an_idle_link_on_loopback_climbs_past_the_old_ceiling_toward_the_default_bound() {
    let (a, b, _eps) = link(&LinkTransportConfig::default()).await;
    for (side, link) in [("dialer", &a), ("listener", &b)] {
        let size = size_over(link, CLIMBED).await;
        assert!(
            size > CLIMBED,
            "the {side} settled on {size} of datagram: discovery did not climb toward the bound"
        );
        assert!(
            size <= BOUND,
            "the {side} settled on {size} of datagram, over the bound's {BOUND}"
        );
    }
}

/// What an Ethernet path ends at: a bound of 1,452 octets of payload (1,500 less the IPv6
/// and UDP headers), which the discovery of a link given that bound settles on, 1,414 of
/// datagram. A path whose own limit is lower than the default bound ends at its limit in the
/// same way, so the higher default costs an Ethernet path nothing but about a dozen probes.
#[tokio::test]
async fn a_bound_of_ethernets_size_settles_there() {
    let config = LinkTransportConfig {
        path_mtu_max: 1452,
        ..LinkTransportConfig::default()
    };
    let (a, b, _eps) = link(&config).await;
    assert_eq!(size_over(&a, 1400).await, 1414);
    assert_eq!(size_over(&b, 1400).await, 1414);
}

#[tokio::test]
async fn a_bound_below_the_minimum_is_the_minimum() {
    let config = LinkTransportConfig {
        path_mtu_max: 100,
        ..LinkTransportConfig::default()
    };
    let (a, _b, _eps) = link(&config).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(a.handle.max_datagram_size().unwrap(), FLOOR);
}

/// At a raised bound a burst of frames queued at once is sent as GSO batches; one over 65,507
/// octets fails with EMSGSIZE, which quinn-udp counts as sent, so a burst lost whole.
#[tokio::test]
async fn a_burst_at_a_raised_bound_arrives_whole() {
    let config = LinkTransportConfig {
        path_mtu_max: 9000,
        ..LinkTransportConfig::default()
    };
    let (a, b, _eps) = link(&config).await;
    // Discovery may still be climbing (the size is read as soon as it is past `CLIMBED`), so the
    // size after the burst is compared with this one, not with a settled value.
    let before = size_over(&a, CLIMBED).await;
    assert!(
        (CLIMBED + 1..=BOUND).contains(&before),
        "{before} of datagram: discovery did not climb toward the bound"
    );
    // The test task does not yield between sends until the connection's send buffer is full,
    // so the driver finds the whole burst queued.
    const FRAMES: usize = 800;
    let frame = Bytes::from(vec![0x06; 1000]);
    for _ in 0..FRAMES {
        a.face.send_bytes(frame.clone()).await.unwrap();
    }
    let mut got = 0;
    while got < FRAMES {
        match tokio::time::timeout(T, b.face.recv_bytes()).await {
            Ok(Ok(f)) => {
                assert_eq!(f, frame);
                got += 1;
            }
            other => panic!("{got} of {FRAMES} frames arrived, then {other:?}"),
        }
    }
    let after = size_over(&a, before - 1).await;
    assert!(
        (before..=BOUND).contains(&after),
        "the burst kept the size: {before} of datagram before it, {after} after"
    );
}
