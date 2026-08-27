//! **Full NDN-over-BLE roundtrip** on two ESP32-C5 BLE backends: a consumer expresses an Interest, a
//! producer answers with a **large Data that fragments across BLE 5 extended advertisements** and is
//! reassembled + decoded on the consumer. Real NDN packets (verified with `ndn_packet::{Interest,Data}
//! ::decode`); fragmentation is the `BlePhy` NDNts per-sender path (no engine needed for the demo).
//!
//! ```sh
//! BLE_A=/dev/cu.usbmodem101 BLE_B=/dev/cu.usbmodem11101 \
//!   cargo run --example ble_roundtrip --features serial -p ndn-face-ble-adv
//! ```
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ndn_face_ble_adv::{BlePhy, Esp32BleBackend};
use ndn_packet::{Data, Interest};
use ndn_transport::{FaceId, Transport};

/// Minimal TLV encoder — `[type][len][value]`, with the 3-byte length form for ≥253.
fn tlv(ty: u8, val: &[u8]) -> Vec<u8> {
    let mut v = vec![ty];
    let n = val.len();
    if n < 253 {
        v.push(n as u8);
    } else {
        v.push(0xFD);
        v.push((n >> 8) as u8);
        v.push((n & 0xff) as u8);
    }
    v.extend_from_slice(val);
    v
}
fn name_tlv(comps: &[&[u8]]) -> Vec<u8> {
    tlv(
        0x07,
        &comps.iter().flat_map(|c| tlv(0x08, c)).collect::<Vec<u8>>(),
    )
}
fn interest_pkt(comps: &[&[u8]]) -> Bytes {
    let mut body = name_tlv(comps);
    body.extend(tlv(0x0a, &[0xDE, 0xAD, 0xBE, 0xEF])); // Nonce
    Bytes::from(tlv(0x05, &body))
}
fn data_pkt(comps: &[&[u8]], content: &[u8]) -> Bytes {
    let mut body = name_tlv(comps);
    body.extend(tlv(0x15, content)); // Content
    body.extend(tlv(0x16, &tlv(0x1b, &[0x00]))); // SignatureInfo{ SignatureType = DigestSha256 }
    body.extend(tlv(0x17, &[0u8; 32])); // SignatureValue (unverified — matches the bw16_ndn precedent)
    Bytes::from(tlv(0x06, &body))
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pa = std::env::var("BLE_A").unwrap_or_else(|_| "/dev/cu.usbmodem101".into());
    let pb = std::env::var("BLE_B").unwrap_or_else(|_| "/dev/cu.usbmodem11101".into());

    // Keep the concrete backends so we can drive the BLE↔Wi-Fi split knob (set_ble_share).
    let a_backend = Arc::new(Esp32BleBackend::open(&pa)?);
    let b_backend = Arc::new(Esp32BleBackend::open(&pb)?);
    tokio::time::sleep(Duration::from_millis(1500)).await; // NimBLE sync

    // A large Data whose wire form exceeds one extended advertisement → it MUST fragment.
    const NAME: &[&[u8]] = &[b"ndn", b"ble", b"big"];
    let content: Vec<u8> = (0..250u32).map(|i| (i % 251) as u8).collect();
    let data = data_pkt(NAME, &content);
    let interest = interest_pkt(NAME);
    println!(
        "Data wire size = {} B (frag MTU 200 → ~{} advertisements)",
        data.len(),
        data.len().div_ceil(200)
    );

    // The consumer raises its BLE share so it catches every fragment (the split is a lever, not a constant).
    b_backend.set_ble_share(0.9)?;
    tokio::time::sleep(Duration::from_millis(400)).await;

    // NDNts framing = per-sender fragmentation/reassembly inside the face. MTU 200 < the C5's 240B ext-adv cap.
    let producer = BlePhy::new(FaceId(1), a_backend.clone())
        .ndnts_framing()
        .with_mtu(200);
    let consumer = BlePhy::new(FaceId(2), b_backend.clone())
        .ndnts_framing()
        .with_mtu(200);

    // Producer: answer any Interest for our name with the large Data; also keep re-emitting it (broadcast is
    // lossy, so redundancy lets the consumer collect a full fragment set).
    let want = name_tlv(NAME);
    let prod = tokio::spawn(async move {
        let mut served = false;
        for _ in 0..120 {
            if !served {
                if let Ok(Ok((wire, _))) =
                    tokio::time::timeout(Duration::from_millis(60), producer.recv_bytes_with_addr())
                        .await
                {
                    if Interest::decode(wire.clone()).is_ok() {
                        if wire.windows(want.len()).any(|w| w == want.as_slice()) {
                            println!("producer: got Interest {} → serving Data", "/ndn/ble/big");
                            served = true;
                        }
                    }
                }
            }
            let _ = producer.send_bytes(data.clone()).await; // fragments across ext-adv (paced on-device)
            // ~4 fragments × ~110ms firmware pacing ≈ 500ms per full Data; re-send for broadcast redundancy.
            tokio::time::sleep(Duration::from_millis(550)).await;
        }
    });

    // Consumer: express the Interest a few times, then reassemble + decode + verify the Data.
    for _ in 0..4 {
        consumer.send_bytes(interest.clone()).await?;
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let mut ok = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while tokio::time::Instant::now() < deadline && !ok {
        if let Ok(Ok((wire, addr))) =
            tokio::time::timeout(Duration::from_millis(800), consumer.recv_bytes_with_addr()).await
        {
            if let Ok(d) = Data::decode(wire.clone()) {
                if d.content()
                    .map(|c| c.as_ref() == content.as_slice())
                    .unwrap_or(false)
                {
                    println!(
                        "consumer: REASSEMBLED + decoded Data /ndn/ble/big ({} B content) from {:02x?} ✔",
                        content.len(),
                        addr
                    );
                    ok = true;
                }
            }
        }
    }
    prod.abort();
    assert!(
        ok,
        "consumer did not reassemble the fragmented Data over BLE"
    );
    println!("✔ full NDN roundtrip over BLE: Interest → fragmented Data → reassembled, C5 ↔ C5");
    Ok(())
}
