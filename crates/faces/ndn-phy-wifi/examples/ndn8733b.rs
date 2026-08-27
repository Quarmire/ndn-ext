//! NDN over the RTL8733BU: wire the 8733b under a `WifiPhy` and send a real
//! NDN Data packet over the air, decoded on a second `WifiPhy` over the
//! RTL8812AU — the userspace 8733b driver carrying a genuine NDN packet end-to-end.
//!
//!   cargo run --features libusb-backend --example ndn8733b -- 1

#[cfg(feature = "libusb-backend")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(run())
}

/// Hand-encode a minimal NDN Data packet: Name + Content + a DigestSha256
/// SignatureInfo/Value — enough for `Data::decode` to round-trip.
#[cfg(feature = "libusb-backend")]
fn build_data(components: &[&[u8]], content: &[u8]) -> bytes::Bytes {
    let mut name = Vec::new();
    for c in components {
        name.push(0x08);
        name.push(c.len() as u8);
        name.extend_from_slice(c);
    }
    let mut body = Vec::new();
    body.push(0x07);
    body.push(name.len() as u8);
    body.extend_from_slice(&name);
    body.push(0x15);
    body.push(content.len() as u8);
    body.extend_from_slice(content);
    body.extend_from_slice(&[0x16, 0x03, 0x1b, 0x01, 0x00]); // SignatureInfo: DigestSha256
    body.push(0x17);
    body.push(0x20);
    body.extend_from_slice(&[0u8; 32]); // SignatureValue (dummy)
    let mut pkt = Vec::with_capacity(body.len() + 2);
    pkt.push(0x06);
    pkt.push(body.len() as u8);
    pkt.extend_from_slice(&body);
    bytes::Bytes::from(pkt)
}

#[cfg(feature = "libusb-backend")]
async fn run() -> Result<(), Box<dyn std::error::Error>> {
    use ndn_phy_wifi::{Rtl8733buBackend, Rtl8812auBackend, WifiPhy};
    use ndn_packet::Data;
    use ndn_transport::{FaceId, Transport};
    use std::sync::Arc;
    use std::time::Duration;

    let ch: u8 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);

    // Receiver: the RTL8812AU under a WifiPhy.
    let rx = Rtl8812auBackend::open()?;
    rx.bring_up_monitor(ch)?;
    let rx_face = WifiPhy::new(FaceId(2), Arc::new(rx));
    println!("(receiver: RTL8812AU on ch{ch})");

    // Sender: the RTL8733BU under a WifiPhy.
    let tx = Rtl8733buBackend::open()?;
    tx.bring_up_monitor(ch)?;
    let tx_face = WifiPhy::new(FaceId(1), Arc::new(tx));
    println!("(sender:   RTL8733BU on ch{ch})");

    let data = build_data(&[b"ndn", b"8733b"], b"hello-over-8733b-radio");
    println!(
        "8733b face → 8812au face on ch{ch}: sending NDN Data /ndn/8733b ({} B)…",
        data.len()
    );

    let sender = {
        let data = data.clone();
        tokio::spawn(async move {
            for _ in 0..400 {
                let _ = tx_face.send_bytes(data.clone()).await;
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
    };

    let mut got = false;
    for _ in 0..120 {
        if let Ok(Ok(wire)) =
            tokio::time::timeout(Duration::from_millis(400), rx_face.recv_bytes()).await
        {
            if let Ok(d) = Data::decode(wire) {
                let content = d.content().map(|c| String::from_utf8_lossy(c).into_owned());
                println!(
                    "  ✅ decoded NDN Data over the air: name={} content={:?}",
                    d.name, content
                );
                got = true;
                break;
            }
        }
    }
    sender.abort();
    println!(
        "{}",
        if got {
            "NDN-over-8733b: OK 🎉"
        } else {
            "no NDN Data decoded"
        }
    );
    Ok(())
}

#[cfg(not(feature = "libusb-backend"))]
fn main() {
    eprintln!("build with --features libusb-backend");
}
