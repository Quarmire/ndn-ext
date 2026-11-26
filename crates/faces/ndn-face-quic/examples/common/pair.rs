//! The link `side_ping` and `chan_ping` measure over: two `LinkEndpoint`s on loopback, each on its
//! own runtime, both sides `ChannelPolicy { carry: true }`, `LinkHello::default()` advertising
//! `ChannelCaps`.

use std::sync::Arc;
use std::time::Duration;

use ndn_face_quic::{
    Admission, ChannelPolicy, Link, LinkEndpoint, LinkHello, LinkKey, LinkTransportConfig,
};
use ndn_security::Ed25519Signer;
use ndn_transport::FaceId;

const T: Duration = Duration::from_secs(10);

pub fn key(seed: u8) -> LinkKey {
    LinkKey::from_signer(Arc::new(Ed25519Signer::from_seed(
        &[seed; 32],
        format!("/bench/member/d{seed}/KEY/k").parse().unwrap(),
    )))
    .unwrap()
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

pub struct Pair {
    /// The dialling side, the publisher.
    pub tx: Arc<Link>,
    /// The listening side, the subscriber.
    pub rx: Arc<Link>,
    pub _eps: [Arc<LinkEndpoint>; 2],
}

pub async fn connect(
    config: &LinkTransportConfig,
    rt_rx: &tokio::runtime::Handle,
    rt_tx: &tokio::runtime::Handle,
) -> Pair {
    let (rx, tx, eps) = connect_ids(config, rt_rx, rt_tx, FaceId(2), FaceId(1)).await;
    Pair {
        tx: Arc::new(tx),
        rx: Arc::new(rx),
        _eps: eps,
    }
}

/// The two ends of one link (`rx` listens, `tx` dials) with the face ids the caller gives: faces
/// that go into forwarders take their id from the forwarder's face table.
pub async fn connect_ids(
    config: &LinkTransportConfig,
    rt_rx: &tokio::runtime::Handle,
    rt_tx: &tokio::runtime::Handle,
    id_rx: FaceId,
    id_tx: FaceId,
) -> (Link, Link, [Arc<LinkEndpoint>; 2]) {
    let (c1, c2) = (config.clone(), config.clone());
    let listener = rt_rx
        .spawn(async move {
            Arc::new(
                LinkEndpoint::bind("127.0.0.1:0".parse().unwrap(), Arc::new(key(2)), &c1, true)
                    .unwrap(),
            )
        })
        .await
        .unwrap();
    let dialer = rt_tx
        .spawn(async move {
            Arc::new(
                LinkEndpoint::bind("127.0.0.1:0".parse().unwrap(), Arc::new(key(1)), &c2, false)
                    .unwrap(),
            )
        })
        .await
        .unwrap();
    let target = listener.local_addr().unwrap();
    let accept = {
        let listener = Arc::clone(&listener);
        rt_rx.spawn(async move {
            let mut hs = listener.accept().await.unwrap().handshake().await.unwrap();
            hs.exchange_hello(&LinkHello::default(), T).await.unwrap();
            hs.admit(id_rx, T, carrying()).await.unwrap()
        })
    };
    let dial = {
        let dialer = Arc::clone(&dialer);
        rt_tx.spawn(async move {
            let mut hs = dialer.connect(target, None).await.unwrap();
            hs.exchange_hello(&LinkHello::default(), T).await.unwrap();
            hs.admit(id_tx, T, carrying()).await.unwrap()
        })
    };
    let (rx, tx) = (accept.await.unwrap(), dial.await.unwrap());
    assert!(tx.handle.side_peer_caps() && rx.handle.side_peer_caps());
    (rx, tx, [listener, dialer])
}
