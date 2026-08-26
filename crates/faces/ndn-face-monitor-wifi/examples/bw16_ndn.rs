//! NDN over the BW16: wire a BW16 (RTL8720DN, serial-bridged) under a
//! `MonitorWifiFace` and send a real NDN Data packet over the air, decoded on a
//! second `MonitorWifiFace` (over the RTL8812EU) — two independent radio backends,
//! the same face, a genuine NDN packet on 5 GHz.
//!
//!   cargo run --features serial-radio,libusb-backend --example bw16_ndn -- /dev/cu.usbserial-1110 149

#[cfg(all(feature = "serial-radio", feature = "libusb-backend"))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(run())
}

/// Hand-encode a minimal NDN Data packet: Name + Content + a DigestSha256
/// SignatureInfo/Value (dummy) — enough for `Data::decode` to round-trip.
#[cfg(all(feature = "serial-radio", feature = "libusb-backend"))]
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
    body.extend_from_slice(&name); // Name
    body.push(0x15);
    body.push(content.len() as u8);
    body.extend_from_slice(content); // Content
    body.extend_from_slice(&[0x16, 0x03, 0x1b, 0x01, 0x00]); // SignatureInfo: DigestSha256
    body.push(0x17);
    body.push(0x20);
    body.extend_from_slice(&[0u8; 32]); // SignatureValue (dummy)
    let mut pkt = Vec::with_capacity(body.len() + 2);
    pkt.push(0x06);
    pkt.push(body.len() as u8);
    pkt.extend_from_slice(&body); // Data
    bytes::Bytes::from(pkt)
}

#[cfg(all(feature = "serial-radio", feature = "libusb-backend"))]
async fn run() -> Result<(), Box<dyn std::error::Error>> {
    use ndn_face_monitor_wifi::{SerialRadioBackend, LibUsbRtl88xxBackend, MonitorWifiFace};
    use ndn_packet::Data;
    use ndn_transport::{FaceId, Transport};
    use std::sync::Arc;
    use std::time::Duration;

    let mut a = std::env::args().skip(1);
    let port = a.next().unwrap_or_else(|| "/dev/cu.usbserial-1110".into());
    let ch: u8 = a.next().and_then(|s| s.parse().ok()).unwrap_or(149);
    let rx_port = a.next(); // optional: a second BW16 serial port as the receiver

    // Sender: the BW16 under a MonitorWifiFace.
    let bw = SerialRadioBackend::open(&port)?;
    bw.set_channel(ch)?;
    let tx_face = MonitorWifiFace::new(FaceId(1), Arc::new(bw));

    // Receiver: a second BW16 if given, else the RTL8812EU (pumped for full-rate RX).
    let rx_face = match &rx_port {
        Some(p) => {
            let rb = SerialRadioBackend::open(p)?;
            rb.set_channel(ch)?;
            println!("(receiver: second BW16 {p})");
            MonitorWifiFace::new(FaceId(2), Arc::new(rb))
        }
        None => {
            let eu = Arc::new(LibUsbRtl88xxBackend::open_monitor(ch)?);
            let _pumps = eu.spawn_rx_pump(8);
            std::mem::forget(_pumps); // keep the RX pump threads alive
            println!("(receiver: RTL8812EU)");
            MonitorWifiFace::new(FaceId(2), eu)
        }
    };

    let data = build_data(&[b"ndn", b"serial-radio"], b"hello-over-bw16-radio");
    println!(
        "BW16 face → 8812EU face on ch{ch}: sending NDN Data /ndn/bw16 ({} B)…",
        data.len()
    );

    // Spam the Data packet from the BW16 face.
    let sender = {
        let data = data.clone();
        tokio::spawn(async move {
            for _ in 0..400 {
                let _ = tx_face.send_bytes(data.clone()).await;
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
    };

    // Receive on the 8812EU face, decode the NDN Data, verify.
    let mut got = false;
    for _ in 0..80 {
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
            "NDN-over-BW16: OK"
        } else {
            "no NDN Data decoded"
        }
    );
    Ok(())
}

#[cfg(not(all(feature = "serial-radio", feature = "libusb-backend")))]
fn main() {
    eprintln!("build with --features serial-radio,libusb-backend");
}
