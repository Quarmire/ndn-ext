//! Mutual Wi-Fi Aware (NAN) discovery with a real device over the RTL8812AU.
//!
//! Modes:
//!  - `node [service]` (default, service=`ndn`) — bring the 8812AU up (M1–M8),
//!    run the userspace `ndn-nan` engine, publish+subscribe the service, and
//!    print discovered peers. The S23 (ndn-anchor / ndn-ripple) should discover
//!    us and we it.
//!  - `sniff` — bring the radio up and dump every NAN beacon / Service Discovery
//!    Frame heard, decoding attributes. Use this to see exactly what a real
//!    device transmits (publish vs subscribe, which services, which attributes).
//!
//! Run on the OPi (blacklisted/clean dongle):
//!   sudo modprobe -r rtw88_8812au
//!   sudo NDN_RADIO_NO_RESET=1 LD_LIBRARY_PATH=$(nix path-info nixpkgs#libusb1)/lib \
//!       ./target/debug/examples/nan_s23 [sniff | node [service]]
#[cfg(feature = "libusb-backend")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use ndn_face_monitor_wifi::Rtl8812auBackend;

    let mode = std::env::args().nth(1).unwrap_or_else(|| "node".into());

    // ── Bring the radio up (M1–M8) ──
    let b = Rtl8812auBackend::open()?;
    println!("opened RTL8812AU pid={:#06x}", b.pid());
    b.power_on()?;
    b.mac_enable_dma()?;
    b.init_llt()?;
    let (ver, sub) = b.download_firmware()?;
    println!("✓ firmware {ver}.{sub} up");
    b.mac_config()?;
    b.mac_init_queues()?;
    b.bb_config()?;
    b.rf_config()?;
    b.set_channel(6)?;
    b.iq_calibrate()?;
    b.lc_calibrate()?;
    b.set_tx_power(0x3f)?;
    b.start_rx_dma()?; // release RX DMA last (calibration re-pauses it)
    println!("✓ RTL8812AU up on ch6, TX power max, RX live");

    if mode == "sniff" {
        return sniff(&b);
    }

    node(b, mode).await
}

/// Decode and print every NAN beacon / SDF heard.
#[cfg(feature = "libusb-backend")]
fn sniff(b: &ndn_face_monitor_wifi::Rtl8812auBackend) -> Result<(), Box<dyn std::error::Error>> {
    use ndn_nan_core::{NanBeacon, ServiceDiscoveryFrame};
    println!("[sniff] decoding NAN beacons + SDFs (Ctrl-C to stop) …");
    let (mut bn, mut sd) = (0u64, 0u64);
    loop {
        let Some(cf) = b.poll_frame()? else { continue };
        let buf = &cf.payload;
        if let Ok((beacon, attrs)) = NanBeacon::parse(buf) {
            bn += 1;
            println!(
                "\n── NAN BEACON #{bn}  src={}  cluster={}  ts={}  bi={}TU",
                mac(&beacon.header.addr2),
                mac(&beacon.header.addr3),
                beacon.timestamp,
                beacon.beacon_interval,
            );
            dump_attrs(attrs);
        } else if let Ok((sdf, attrs)) = ServiceDiscoveryFrame::parse(buf) {
            sd += 1;
            println!(
                "\n── NAN SDF #{sd}  src={}  dst={}",
                mac(&sdf.header.addr2),
                mac(&sdf.header.addr1),
            );
            dump_attrs(attrs);
        }
    }
}

/// Full userspace NAN node over the radio.
#[cfg(feature = "libusb-backend")]
async fn node(
    b: ndn_face_monitor_wifi::Rtl8812auBackend,
    service: String,
) -> Result<(), Box<dyn std::error::Error>> {
    use ndn_face_wifi_aware::{NanBackend, NanServiceName};
    use ndn_frame_io::FrameIo;
    use std::collections::HashSet;
    use std::sync::Arc;
    use std::time::Duration;

    let service = if service == "node" { "ndn".to_string() } else { service };
    // Low master preference + low NMI → merge INTO the S23's cluster.
    let nmi: [u8; 6] = [0x02, 0x4e, 0x41, 0x4e, 0x00, 0x31];
    let cfg = ndn_nan::Config::new(nmi, 6, 0);
    let radio: Arc<dyn FrameIo> = Arc::new(b);
    let driver = ndn_nan::spawn(radio, cfg, None);

    let svc = NanServiceName(service.clone());
    // Publish WITH a Presence-format service-info ("deviceId\nmodel\nip"), the
    // shape ndn-anchor emits and ndn-ripple parses to list a peer — an empty SSI
    // is silently dropped by the subscriber app.
    let presence = b"ndnrust0\nNDN-Rust-OPi5\n10.0.0.99".to_vec();
    driver.publish_with_info(&service, presence)?;
    driver.subscribe(&svc).await?;
    println!(
        "✓ NAN engine — publish+subscribe \"{service}\" as NMI {nmi:02x?}\n  watching for peers …"
    );

    let mut seen: HashSet<[u8; 6]> = HashSet::new();
    let mut ticks = 0u32;
    loop {
        for m in driver.drain_matches() {
            if seen.insert(m.peer) {
                println!("★ DISCOVERED peer NMI {:02x?} advertising \"{}\"", m.peer, m.service.0);
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
        ticks += 1;
        if ticks % 10 == 0 {
            println!("  … {}s, {} peer(s)", ticks / 2, seen.len());
        }
    }
}

#[cfg(feature = "libusb-backend")]
fn mac(m: &[u8; 6]) -> String {
    m.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":")
}

#[cfg(feature = "libusb-backend")]
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(feature = "libusb-backend")]
fn dump_attrs(attrs: &[u8]) {
    use ndn_nan_core::attr::{
        AttributeId, Attributes, Cluster, MasterIndication, ServiceControlType, ServiceDescriptor,
    };
    for a in Attributes::new(attrs).flatten() {
        match a.id {
            x if x == AttributeId::MasterIndication as u8 => {
                if let Ok(mi) = MasterIndication::decode(a.body) {
                    println!("   MasterIndication: pref={} rf={}", mi.master_preference, mi.random_factor);
                }
            }
            x if x == AttributeId::Cluster as u8 => {
                if let Ok(c) = Cluster::decode(a.body) {
                    println!("   Cluster: amr={:#018x} hop={} ambtt={}", c.anchor_master_rank, c.hop_count, c.ambtt);
                }
            }
            x if x == AttributeId::ServiceDescriptor as u8 => match ServiceDescriptor::decode(a.body) {
                Ok(sda) => {
                    let t = match sda.control.control_type {
                        ServiceControlType::Publish => "publish",
                        ServiceControlType::Subscribe => "subscribe",
                        ServiceControlType::FollowUp => "follow-up",
                    };
                    println!(
                        "   SDA: id={} inst={} req={} type={t} ssi={:?}",
                        hex(&sda.service_id),
                        sda.instance_id,
                        sda.requestor_instance_id,
                        String::from_utf8_lossy(&sda.service_info)
                    );
                }
                Err(_) => println!("   SDA(0x03) len={} [unmodelled fields]", a.body.len()),
            },
            id => println!(
                "   attr {:#04x} len={} {} body={}",
                id,
                a.body.len(),
                attr_name(id),
                hex(a.body)
            ),
        }
    }
}

#[cfg(feature = "libusb-backend")]
fn attr_name(id: u8) -> &'static str {
    match id {
        0x02 => "(ServiceIdList)",
        0x0E => "(SDEA)",
        0x0F => "(DeviceCapability)",
        0x10 => "(NDP)",
        0x12 => "(NanAvailability)",
        0x13 => "(NDC)",
        0x14 => "(NDL)",
        0x15 => "(NDLQos)",
        0x16 => "(Unaligned-Schedule)",
        0x18 => "(DeviceCapabilityExt)",
        _ => "",
    }
}

#[cfg(not(feature = "libusb-backend"))]
fn main() {
    eprintln!("build with --features libusb-backend");
}
