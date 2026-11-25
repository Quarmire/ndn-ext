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

/// The default bound is 9,000 octets of payload, and an idle loopback link settles on it:
/// 8,962 of datagram, both ways.
#[tokio::test]
async fn an_idle_link_on_loopback_settles_on_the_default_bound() {
    let (a, b, _eps) = link(&LinkTransportConfig::default()).await;
    assert_eq!(size_over(&a, 8000).await, 8962);
    assert_eq!(size_over(&b, 8000).await, 8962);
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
    assert_eq!(size_over(&a, 8000).await, 8962);
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
    assert_eq!(size_over(&a, 8000).await, 8962, "the burst kept the size");
}
