//! On-air Wi-Fi Aware (NAN) test tool for a Linux monitor-mode adapter.
//!
//! Two modes:
//!
//! - `sniff <iface>` — RX only. Capture 802.11 frames on a monitor interface and
//!   dump every **NAN** beacon / Service Discovery Frame it hears, decoding the
//!   attributes our `ndn-nan-core` parser understands. Use this to validate our
//!   codec against a real device (e.g. a Samsung S23 publishing/subscribing a
//!   Wi-Fi Aware service) and to learn which attributes that device includes.
//!
//! - `node <iface> <service>` — full node. Run a userspace NAN engine over the
//!   interface (publish + subscribe `<service>`), printing discovered peers and
//!   received follow-ups, and sending a follow-up every few seconds. Requires the
//!   interface to inject on the cluster's discovery channel (2.4 GHz ch 6), so
//!   point it at a 2.4 GHz-capable monitor radio.
//!
//! Set the interface to monitor mode on the NAN discovery channel first, e.g.:
//! ```text
//! sudo ip link set wlu1 down
//! sudo iw dev wlu1 set monitor otherbss fcsfail
//! sudo ip link set wlu1 up
//! sudo iw dev wlu1 set channel 6
//! ```
//! Then: `sudo ./nan_node sniff wlu1`  (NAN's social channel is 6 in 2.4 GHz;
//! also try 44 / 149 in 5 GHz).

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("nan_node is Linux-only (it uses AF_PACKET monitor-mode capture/injection).");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    linux::run().await
}

#[cfg(target_os = "linux")]
mod linux {
    use std::sync::Arc;
    use std::time::Duration;

    use ndn_face_wifi_aware::NanServiceName;
    use ndn_frame_io::{AfPacketBackend, FrameFormat, FrameIo};
    use ndn_nan_core::{
        NanBeacon, NanConfig, NanEngine, ServiceDiscoveryFrame,
        attr::{
            AttributeId, Attributes, Cluster, MasterIndication, ServiceControlType,
            ServiceDescriptor,
        },
    };

    pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
        let mut args = std::env::args().skip(1);
        let mode = args.next().unwrap_or_default();
        match mode.as_str() {
            "sniff" => {
                let iface = args.next().ok_or("usage: nan_node sniff <iface>")?;
                sniff(&iface).await
            }
            "node" => {
                let iface = args
                    .next()
                    .ok_or("usage: nan_node node <iface> <service>")?;
                let service = args
                    .next()
                    .ok_or("usage: nan_node node <iface> <service>")?;
                node(&iface, &service).await
            }
            "dump" => {
                let service = args.next().unwrap_or_else(|| "ndn".to_string());
                dump(&service);
                Ok(())
            }
            _ => {
                eprintln!("usage: nan_node <sniff|node|dump> <iface> [service]");
                std::process::exit(2);
            }
        }
    }

    /// Emit our generated beacon + SDF for `service` as a `text2pcap` hexdump (no
    /// radio). Pipe into `text2pcap -l 105 - out.pcap` then `tshark -r out.pcap
    /// -V` to dissect them with Wireshark's authoritative `wifi_nan` dissector —
    /// validating our encoders byte-for-byte against the same parser the S23's
    /// frames pass through.
    fn dump(service: &str) {
        let nmi = [0x02, b'N', b'A', b'N', 0x00, 0x01];
        let mut eng = NanEngine::new(NanConfig::new(nmi, 6, 0));
        eng.publish(service, b"ndn-test".to_vec());
        eng.subscribe(service, true);
        // The first poll (tu 0) is inside a Discovery Window, so it bursts a sync
        // beacon + the Service Discovery Frame for our functions.
        let step = eng.poll(0, &[]);
        for tx in &step.tx {
            text2pcap_frame(&tx.bytes);
        }
        eprintln!(
            "[dump] emitted {} frame(s) for service {service:?}",
            step.tx.len()
        );
    }

    /// Print one frame as a `text2pcap` offset hexdump (a blank-offset line per
    /// packet boundary).
    fn text2pcap_frame(bytes: &[u8]) {
        for (i, chunk) in bytes.chunks(16).enumerate() {
            let hex: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
            println!("{:06x} {}", i * 16, hex.join(" "));
        }
        println!(); // blank line separates packets for text2pcap
    }

    /// RX-only: capture and dump NAN frames.
    async fn sniff(iface: &str) -> Result<(), Box<dyn std::error::Error>> {
        let backend = AfPacketBackend::new(iface, FrameFormat::Raw80211)?;
        println!("[sniff] listening on {iface} for NAN beacons + Service Discovery Frames…");
        let mut beacons = 0u64;
        let mut sdfs = 0u64;
        loop {
            let cf = match backend.recv_frame().await {
                Ok(cf) => cf,
                Err(e) => {
                    eprintln!("[sniff] recv error: {e}");
                    continue;
                }
            };
            let buf = &cf.payload;
            if let Ok((beacon, attrs)) = NanBeacon::parse(buf) {
                beacons += 1;
                println!(
                    "\n── NAN BEACON #{beacons}  src={}  cluster={}  ts={}  bi={}TU  rssi={:?}",
                    mac(&beacon.header.addr2),
                    mac(&beacon.header.addr3),
                    beacon.timestamp,
                    beacon.beacon_interval,
                    cf.rssi_dbm
                );
                dump_attrs(attrs);
            } else if let Ok((sdf, attrs)) = ServiceDiscoveryFrame::parse(buf) {
                sdfs += 1;
                println!(
                    "\n── NAN SDF #{sdfs}  src={}  dst={}  rssi={:?}",
                    mac(&sdf.header.addr2),
                    mac(&sdf.header.addr1),
                    cf.rssi_dbm
                );
                dump_attrs(attrs);
            }
        }
    }

    /// Full userspace NAN node.
    async fn node(iface: &str, service: &str) -> Result<(), Box<dyn std::error::Error>> {
        use ndn_face_wifi_aware::NanBackend;

        let backend: Arc<dyn FrameIo> =
            Arc::new(AfPacketBackend::new(iface, FrameFormat::Raw80211)?);
        // A locally-administered NMI derived from the interface name's bytes.
        let nmi = [
            0x02,
            b'N',
            b'A',
            b'N',
            0x00,
            iface.bytes().last().unwrap_or(1),
        ];
        let driver = ndn_nan::spawn(backend, NanConfig::new(nmi, 6, 200), None);
        println!(
            "[node] NAN up on {iface}, nmi={}, service={service:?}",
            mac(&nmi)
        );

        let svc = NanServiceName(service.to_string());
        driver.publish(&svc).await?;
        driver.subscribe(&svc).await?;

        // Print discovered peers + received follow-ups; send a heartbeat follow-up
        // every 3 s.
        let d2 = driver.clone();
        tokio::spawn(async move {
            while let Ok(fu) = d2.next_followup().await {
                println!(
                    "[node] FOLLOW-UP from {}: {:?}  rssi={:?}",
                    fu.peer.map(|p| mac(&p)).unwrap_or_default(),
                    String::from_utf8_lossy(&fu.frame),
                    fu.rssi_dbm
                );
            }
        });

        let mut beat = 0u64;
        loop {
            tokio::time::sleep(Duration::from_secs(3)).await;
            for m in driver.drain_matches() {
                println!(
                    "[node] DISCOVERED peer {} for service {:?}",
                    mac(&m.peer),
                    m.service.0
                );
            }
            beat += 1;
            let msg = format!("hello-{beat}");
            let n = driver
                .broadcast(bytes::Bytes::from(msg.clone()))
                .await
                .is_ok();
            println!("[node] sent follow-up {msg:?} (queued={n})");
        }
    }

    /// Pretty-print the NAN attributes we recognize; show id+len for the rest.
    fn dump_attrs(attrs: &[u8]) {
        for a in Attributes::new(attrs).flatten() {
            match a.id {
                x if x == AttributeId::MasterIndication as u8 => {
                    if let Ok(mi) = MasterIndication::decode(a.body) {
                        println!(
                            "   MasterIndication: pref={} rf={}",
                            mi.master_preference, mi.random_factor
                        );
                    }
                }
                x if x == AttributeId::Cluster as u8 => {
                    if let Ok(c) = Cluster::decode(a.body) {
                        println!(
                            "   Cluster: amr={:#018x} hop={} ambtt={}",
                            c.anchor_master_rank, c.hop_count, c.ambtt
                        );
                    }
                }
                x if x == AttributeId::ServiceDescriptor as u8 => {
                    match ServiceDescriptor::decode(a.body) {
                        Ok(sda) => println!(
                            "   SDA: id={} inst={} req={} type={:?} ssi={:?}",
                            hex(&sda.service_id),
                            sda.instance_id,
                            sda.requestor_instance_id,
                            type_name(&sda),
                            String::from_utf8_lossy(&sda.service_info)
                        ),
                        Err(_) => println!(
                            "   SDA(0x03) len={} [has fields we don't model yet]",
                            a.body.len()
                        ),
                    }
                }
                id => println!("   attr {:#04x} len={} {}", id, a.body.len(), attr_name(id)),
            }
        }
    }

    fn type_name(sda: &ServiceDescriptor) -> &'static str {
        match sda.control.control_type {
            ServiceControlType::Publish => "publish",
            ServiceControlType::Subscribe => "subscribe",
            ServiceControlType::FollowUp => "follow-up",
        }
    }

    /// Names for attribute IDs we don't fully decode yet — so a capture tells us
    /// exactly what a real device includes (e.g. Device Capability / Availability).
    fn attr_name(id: u8) -> &'static str {
        match id {
            0x02 => "(ServiceIdList)",
            0x0E => "(SDEA)",
            0x0F => "(DeviceCapability)",
            0x10 => "(NDP)",
            0x12 => "(NanAvailability)",
            0x29 => "(NDPE)",
            0x2A => "(DeviceCapabilityExtension)",
            0xDD => "(VendorSpecific)",
            _ => "",
        }
    }

    fn mac(m: &[u8; 6]) -> String {
        m.iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":")
    }
    fn hex(b: &[u8]) -> String {
        b.iter().map(|b| format!("{b:02x}")).collect()
    }
}
