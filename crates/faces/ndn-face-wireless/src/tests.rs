//! In-process tests for the `WirelessFace` using a loopback bearer that does **real bearer-native
//! fragmentation** (splits a whole packet to its MTU and reassembles), so the face's job — bearer selection,
//! RX merge, cross-bearer dedup, and per-bearer MTU — is exercised without hardware.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bytes::Bytes;
use ndn_transport::{FaceError, FaceId, Transport};
use tokio::sync::{broadcast, Mutex as AsyncMutex};

use super::*;

/// One in-process broadcast medium (a bus). Bearers on the same bus hear each other.
#[derive(Clone)]
struct LoopbackBus {
    tx: broadcast::Sender<Frame>,
}
#[derive(Clone)]
struct Frame {
    src: u64,
    obj: u64,
    seq: u16,
    last: bool,
    data: Bytes,
}
impl LoopbackBus {
    fn new() -> Arc<Self> {
        Arc::new(Self { tx: broadcast::channel(4096).0 })
    }
}

static BEARER_IDS: AtomicU64 = AtomicU64::new(1);

/// A loopback bearer over a [`LoopbackBus`] with a configurable MTU/kind/reach — it fragments a whole packet
/// into `mtu`-sized chunks on send and reassembles per `(src, obj)` on recv (skipping its own echoes).
struct LoopbackBearer {
    id: u64,
    bus: Arc<LoopbackBus>,
    rx: AsyncMutex<broadcast::Receiver<Frame>>,
    mtu: usize,
    kind: BearerKind,
    range_rank: u8,
    next_obj: AtomicU64,
    reasm: Mutex<HashMap<(u64, u64), Vec<Bytes>>>,
}

impl LoopbackBearer {
    fn new(bus: &Arc<LoopbackBus>, mtu: usize, kind: BearerKind, range_rank: u8) -> Arc<Self> {
        Arc::new(Self {
            id: BEARER_IDS.fetch_add(1, Ordering::Relaxed),
            bus: Arc::clone(bus),
            rx: AsyncMutex::new(bus.tx.subscribe()),
            mtu,
            kind,
            range_rank,
            next_obj: AtomicU64::new(0),
            reasm: Mutex::new(HashMap::new()),
        })
    }
}

#[async_trait]
impl WirelessBearer for LoopbackBearer {
    fn kind(&self) -> BearerKind {
        self.kind
    }
    fn mtu(&self) -> usize {
        self.mtu
    }
    fn range_rank(&self) -> u8 {
        self.range_rank
    }

    async fn send(&self, wire: Bytes) -> Result<(), FaceError> {
        let obj = self.next_obj.fetch_add(1, Ordering::Relaxed);
        let chunks: Vec<Bytes> = if wire.is_empty() {
            vec![Bytes::new()]
        } else {
            wire.chunks(self.mtu).map(Bytes::copy_from_slice).collect()
        };
        let n = chunks.len();
        for (seq, data) in chunks.into_iter().enumerate() {
            let _ = self.bus.tx.send(Frame { src: self.id, obj, seq: seq as u16, last: seq + 1 == n, data });
        }
        Ok(())
    }

    async fn recv(&self) -> Result<Bytes, FaceError> {
        let mut rx = self.rx.lock().await;
        loop {
            let f = rx.recv().await.map_err(|_| FaceError::Closed)?;
            if f.src == self.id {
                continue; // skip our own echoes (loopback broadcasts to every subscriber, including us)
            }
            let mut r = self.reasm.lock().unwrap();
            let buf = r.entry((f.src, f.obj)).or_default();
            if buf.len() <= f.seq as usize {
                buf.resize(f.seq as usize + 1, Bytes::new());
            }
            buf[f.seq as usize] = f.data;
            if f.last {
                let parts = r.remove(&(f.src, f.obj)).unwrap();
                let mut whole = Vec::new();
                for p in parts {
                    whole.extend_from_slice(&p);
                }
                return Ok(Bytes::from(whole));
            }
        }
    }
}

fn ndn_wire(name: &[u8], content: &[u8]) -> Bytes {
    // A stand-in "network packet": distinctive bytes so dedup keys on the whole object.
    let mut v = Vec::new();
    v.extend_from_slice(name);
    v.push(0);
    v.extend_from_slice(content);
    Bytes::from(v)
}

/// Two nodes, each a WirelessFace over a Wi-Fi bus + a BLE bus. A broadcasts on ALL bearers (macrodiversity);
/// B must receive the object EXACTLY ONCE despite it arriving on both bearers (cross-bearer dedup).
#[tokio::test]
async fn broadcast_all_bearers_delivers_once_despite_two_paths() {
    let wifi = LoopbackBus::new();
    let ble = LoopbackBus::new();

    let a = WirelessFace::broadcast(
        FaceId(1),
        vec![
            LoopbackBearer::new(&wifi, 2000, BearerKind::Wifi, 1),
            LoopbackBearer::new(&ble, 200, BearerKind::Ble, 3),
        ],
    );
    let b = WirelessFace::broadcast(
        FaceId(2),
        vec![
            LoopbackBearer::new(&wifi, 2000, BearerKind::Wifi, 1),
            LoopbackBearer::new(&ble, 200, BearerKind::Ble, 3),
        ],
    );

    let obj = ndn_wire(b"/w/1", &vec![7u8; 500]); // 500 B: one Wi-Fi frame, but ~3 BLE fragments
    a.send_bytes(obj.clone()).await.unwrap();

    // First recv is the object; a second recv within a short window must NOT re-deliver it (deduped).
    let got = tokio::time::timeout(std::time::Duration::from_secs(1), b.recv_bytes()).await.unwrap().unwrap();
    assert_eq!(got, obj, "reassembled object matches (bearer-native fragmentation on BLE, whole on Wi-Fi)");

    let second = tokio::time::timeout(std::time::Duration::from_millis(200), b.recv_bytes()).await;
    assert!(second.is_err(), "the duplicate (same object via the other bearer) was deduped, not re-delivered");
}

/// The reach lever: a `ReachClassPolicy` sends Robust-class traffic on the highest-range bearer (BLE here) and
/// Throughput-class on the highest-MTU bearer (Wi-Fi). Prove each lands only on the intended bus.
#[tokio::test]
async fn reach_class_policy_selects_the_intended_bearer() {
    let wifi = LoopbackBus::new();
    let ble = LoopbackBus::new();

    // A witness on each bus (a lone bearer that only receives).
    let wifi_witness = LoopbackBearer::new(&wifi, 2000, BearerKind::Wifi, 1);
    let ble_witness = LoopbackBearer::new(&ble, 200, BearerKind::Ble, 3);

    // classify: first name byte 'R' ⇒ Robust, 'T' ⇒ Throughput.
    let policy = Arc::new(ReachClassPolicy {
        classify: |w: &[u8]| match w.first() {
            Some(b'R') => ReachClass::Robust,
            Some(b'T') => ReachClass::Throughput,
            _ => ReachClass::Redundant,
        },
    });
    let a = WirelessFace::new(
        FaceId(1),
        vec![
            LoopbackBearer::new(&wifi, 2000, BearerKind::Wifi, 1), // highest MTU
            LoopbackBearer::new(&ble, 200, BearerKind::Ble, 3),    // highest range_rank
        ],
        policy,
    );

    a.send_bytes(ndn_wire(b"R-far", b"x")).await.unwrap(); // Robust → BLE
    a.send_bytes(ndn_wire(b"T-fast", b"y")).await.unwrap(); // Throughput → Wi-Fi

    let ble_got =
        tokio::time::timeout(std::time::Duration::from_secs(1), ble_witness.recv()).await.unwrap().unwrap();
    assert_eq!(&ble_got[..1], b"R", "Robust class went out the long-reach (BLE) bearer");
    let wifi_got =
        tokio::time::timeout(std::time::Duration::from_secs(1), wifi_witness.recv()).await.unwrap().unwrap();
    assert_eq!(&wifi_got[..1], b"T", "Throughput class went out the high-MTU (Wi-Fi) bearer");

    // And the cross-check: the Robust object did NOT appear on Wi-Fi (a second wifi recv times out).
    let no_more_wifi = tokio::time::timeout(std::time::Duration::from_millis(200), wifi_witness.recv()).await;
    assert!(no_more_wifi.is_err(), "only the Throughput object rode Wi-Fi — selection, not broadcast");
}

/// No single face MTU — the face reports `None`; each bearer fragments to its own ceiling. A packet larger than
/// the BLE MTU but smaller than Wi-Fi's rides one Wi-Fi frame and several BLE fragments, and reassembles.
#[tokio::test]
async fn no_single_face_mtu_bearer_native_fragmentation() {
    let a = WirelessFace::broadcast(FaceId(1), vec![LoopbackBearer::new(&LoopbackBus::new(), 200, BearerKind::Ble, 3)]);
    assert_eq!(a.send_mtu(), None, "the wireless face exposes no single MTU upward");

    let ble = LoopbackBus::new();
    let tx = WirelessFace::broadcast(FaceId(1), vec![LoopbackBearer::new(&ble, 200, BearerKind::Ble, 3)]);
    let rx = WirelessFace::broadcast(FaceId(2), vec![LoopbackBearer::new(&ble, 200, BearerKind::Ble, 3)]);
    let big = ndn_wire(b"/big", &vec![9u8; 1000]); // 1000 B ≫ 200 B BLE MTU ⇒ ~5 fragments
    tx.send_bytes(big.clone()).await.unwrap();
    let got = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv_bytes()).await.unwrap().unwrap();
    assert_eq!(got, big, "the oversize packet reassembled from bearer-native BLE fragments");
}
