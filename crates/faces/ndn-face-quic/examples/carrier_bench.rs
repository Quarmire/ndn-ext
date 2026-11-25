//! The raw QUIC carrier under an ndn-link link, measured the way `versus.rs` rows B2 and B3
//! measure it (SHAPES-CHANNEL §1.1, §17): two quinn endpoints on loopback in one process, a
//! back-to-back publisher for a few seconds per size and a subscriber counting, then the 64 B
//! half round trip.
//!
//! No arguments: three repetitions of the default rows (QUIC datagram at 1 KiB, one
//! length-prefixed unidirectional stream at 1 KiB and 8 KiB, the 64 B datagram echo), then a
//! summary (median, min, max of each row). About 45 s. Pin from the command line, not here:
//! `taskset -c 10-13 cargo run --release -p ndn-face-quic --example carrier_bench`.
//!
//! Arguments are `key=value` words:
//!
//! | key | default | meaning |
//! |---|---|---|
//! | `only` | `dgram1k,stream1k,stream8k,lat` | rows to run; also `mtu` (idle after the handshake), `crypto` (ring's AEADs), `idle` |
//! | `repeat` | 3 | repetitions of the rows |
//! | `secs` | 3 | seconds measured per throughput row |
//! | `rt` | 2 | 2: sender and receiver on their own runtimes; 1: both on one |
//! | `workers` | 1 | worker threads per runtime |
//! | `mtu` | 0 | not 0: `MtuDiscoveryConfig::upper_bound` and the endpoint's `max_udp_payload_size` |
//! | `mtu_ep` | `mtu` | the endpoint's `max_udp_payload_size` alone |
//! | `mtu_up` | `mtu` | the discovery's `upper_bound` alone |
//! | `initial_mtu`, `min_mtu` | 0 | quinn's `initial_mtu` / `min_mtu` when not 0 |
//! | `mtud` | on | `off`: no MTU discovery |
//! | `gso` | on | `off`: `enable_segmentation_offload(false)` |
//! | `gro` | on | `off`: UDP_GRO switched off on the sockets after quinn set it |
//! | `sockbuf` | 0 | not 0: SO_RCVBUF and SO_SNDBUF of both sockets |
//! | `cc` | cubic | `cubic`, `bbr` or `newreno` |
//! | `iw` | 0 | not 0: the controller's initial window in bytes |
//! | `ack` | 0 | not 0: `AckFrequencyConfig::ack_eliciting_threshold` |
//! | `ack_delay_ms` | 25 | `AckFrequencyConfig::max_ack_delay` when `ack` is set |
//! | `send_window`, `recv_window`, `stream_window` | 0 | quinn's windows in bytes when not 0 |
//! | `dgsend`, `dgrecv` | 0 | the datagram buffers in bytes when not 0 |
//! | `profile` | | a file: the sampled CPU profile of every runtime thread, as TSV |
//! | `trace` | off | `on`: print the thread CPU of every row |
//! | `gso_bytes` | 0 | not 0: bound a GSO batch to this many bytes (segments of the largest size discovery may reach) |

use std::collections::BTreeMap;
use std::io::Write as _;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use quinn::congestion::{BbrConfig, ControllerFactory, CubicConfig, NewRenoConfig};
use quinn::{Connection, Endpoint, EndpointConfig, Runtime, TokioRuntime};
use tokio::io::{AsyncReadExt, BufReader};

mod common;
use common::{cpu_line, median, runtime, threads, trimmed};

#[derive(Clone, Debug)]
struct Args {
    only: Vec<String>,
    repeat: usize,
    secs: f64,
    rt: usize,
    workers: usize,
    mtu_ep: u16,
    mtu_up: u16,
    initial_mtu: u16,
    min_mtu: u16,
    mtud: bool,
    gso: bool,
    gro: bool,
    sockbuf: usize,
    cc: String,
    iw: u64,
    ack: u32,
    ack_delay_ms: u64,
    send_window: u64,
    recv_window: u64,
    stream_window: u64,
    dgsend: usize,
    dgrecv: usize,
    profile: Option<String>,
    trace: bool,
    gso_bytes: usize,
}

impl Args {
    fn parse() -> Self {
        let kv: BTreeMap<String, String> = std::env::args()
            .skip(1)
            .map(|a| {
                let (k, v) = a.split_once('=').unwrap_or_else(|| {
                    panic!("arguments are key=value words, got `{a}` (see the file's header)")
                });
                (k.to_owned(), v.to_owned())
            })
            .collect();
        let known = [
            "only",
            "repeat",
            "secs",
            "rt",
            "workers",
            "mtu",
            "mtu_ep",
            "mtu_up",
            "initial_mtu",
            "min_mtu",
            "mtud",
            "gso",
            "gro",
            "sockbuf",
            "cc",
            "iw",
            "ack",
            "ack_delay_ms",
            "send_window",
            "recv_window",
            "stream_window",
            "dgsend",
            "dgrecv",
            "profile",
            "trace",
            "gso_bytes",
        ];
        for k in kv.keys() {
            assert!(known.contains(&k.as_str()), "unknown argument `{k}`");
        }
        let num = |k: &str, d: u64| -> u64 {
            kv.get(k).map_or(d, |v| {
                v.parse().unwrap_or_else(|_| panic!("`{k}` is a number"))
            })
        };
        let flag = |k: &str, d: bool| -> bool {
            kv.get(k).map_or(d, |v| match v.as_str() {
                "on" | "1" | "true" => true,
                "off" | "0" | "false" => false,
                _ => panic!("`{k}` is on or off"),
            })
        };
        let mtu = num("mtu", 0) as u16;
        Self {
            only: kv
                .get("only")
                .map_or("dgram1k,stream1k,stream8k,lat", String::as_str)
                .split(',')
                .map(str::to_owned)
                .collect(),
            repeat: num("repeat", 3) as usize,
            secs: kv
                .get("secs")
                .map_or(3.0, |v| v.parse().expect("`secs` is a number")),
            rt: num("rt", 2) as usize,
            workers: num("workers", 1) as usize,
            mtu_ep: num("mtu_ep", u64::from(mtu)) as u16,
            mtu_up: num("mtu_up", u64::from(mtu)) as u16,
            initial_mtu: num("initial_mtu", 0) as u16,
            min_mtu: num("min_mtu", 0) as u16,
            mtud: flag("mtud", true),
            gso: flag("gso", true),
            gro: flag("gro", true),
            sockbuf: num("sockbuf", 0) as usize,
            cc: kv.get("cc").cloned().unwrap_or_else(|| "cubic".into()),
            iw: num("iw", 0),
            ack: num("ack", 0) as u32,
            ack_delay_ms: num("ack_delay_ms", 25),
            send_window: num("send_window", 0),
            recv_window: num("recv_window", 0),
            stream_window: num("stream_window", 0),
            dgsend: num("dgsend", 0) as usize,
            dgrecv: num("dgrecv", 0) as usize,
            profile: kv.get("profile").cloned(),
            trace: flag("trace", false),
            gso_bytes: num("gso_bytes", 0) as usize,
        }
    }
}

// ---- the QUIC pair --------------------------------------------------------------------------

const ALPN: &[u8] = b"carrier-bench";

fn transport(a: &Args) -> quinn::TransportConfig {
    let mut t = quinn::TransportConfig::default();
    // What ndn-link's endpoint sets (endpoint.rs `transport_config`), with one unidirectional
    // stream because the carrier's stream rows need it (stage 1 opens it after the verdict).
    t.max_concurrent_bidi_streams(quinn::VarInt::from_u32(1));
    t.max_concurrent_uni_streams(quinn::VarInt::from_u32(1));
    if a.mtud {
        let mut m = quinn::MtuDiscoveryConfig::default();
        if a.mtu_up != 0 {
            m.upper_bound(a.mtu_up);
        }
        t.mtu_discovery_config(Some(m));
    } else {
        t.mtu_discovery_config(None);
    }
    if a.initial_mtu != 0 {
        t.initial_mtu(a.initial_mtu);
    }
    if a.min_mtu != 0 {
        t.min_mtu(a.min_mtu);
    }
    t.enable_segmentation_offload(a.gso);
    let factory: Arc<dyn ControllerFactory + Send + Sync> = match a.cc.as_str() {
        "cubic" => {
            let mut c = CubicConfig::default();
            if a.iw != 0 {
                c.initial_window(a.iw);
            }
            Arc::new(c)
        }
        "bbr" => {
            let mut c = BbrConfig::default();
            if a.iw != 0 {
                c.initial_window(a.iw);
            }
            Arc::new(c)
        }
        "newreno" => {
            let mut c = NewRenoConfig::default();
            if a.iw != 0 {
                c.initial_window(a.iw);
            }
            Arc::new(c)
        }
        other => panic!("cc is cubic, bbr or newreno, not `{other}`"),
    };
    t.congestion_controller_factory(factory);
    if a.ack != 0 {
        let mut f = quinn::AckFrequencyConfig::default();
        f.ack_eliciting_threshold(quinn::VarInt::from_u32(a.ack));
        f.max_ack_delay(Some(Duration::from_millis(a.ack_delay_ms)));
        t.ack_frequency_config(Some(f));
    }
    if a.send_window != 0 {
        t.send_window(a.send_window);
    }
    if a.recv_window != 0 {
        t.receive_window(quinn::VarInt::from_u64(a.recv_window).unwrap());
    }
    if a.stream_window != 0 {
        t.stream_receive_window(quinn::VarInt::from_u64(a.stream_window).unwrap());
    }
    if a.dgsend != 0 {
        t.datagram_send_buffer_size(a.dgsend);
    }
    if a.dgrecv != 0 {
        t.datagram_receive_buffer_size(Some(a.dgrecv));
    }
    t
}

/// The socket quinn sees, with the segments of one GSO batch bounded.
#[derive(Debug)]
struct SegmentCap {
    inner: Arc<dyn quinn::AsyncUdpSocket>,
    max_segments: usize,
}

impl quinn::AsyncUdpSocket for SegmentCap {
    fn create_io_poller(self: Arc<Self>) -> std::pin::Pin<Box<dyn quinn::UdpPoller>> {
        Arc::clone(&self.inner).create_io_poller()
    }
    fn try_send(&self, transmit: &quinn::udp::Transmit) -> std::io::Result<()> {
        self.inner.try_send(transmit)
    }
    fn poll_recv(
        &self,
        cx: &mut std::task::Context,
        bufs: &mut [std::io::IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> std::task::Poll<std::io::Result<usize>> {
        self.inner.poll_recv(cx, bufs, meta)
    }
    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.inner.local_addr()
    }
    fn max_transmit_segments(&self) -> usize {
        self.inner.max_transmit_segments().min(self.max_segments)
    }
    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }
    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

struct Side {
    endpoint: Endpoint,
    /// What the socket reports to quinn: GSO segments, GRO segments, may_fragment.
    socket: String,
}

fn endpoint(a: &Args, server: Option<quinn::ServerConfig>) -> Side {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    if a.sockbuf != 0 {
        let s = socket2::SockRef::from(&socket);
        s.set_recv_buffer_size(a.sockbuf).unwrap();
        s.set_send_buffer_size(a.sockbuf).unwrap();
    }
    let fd = socket.as_raw_fd();
    let runtime: Arc<dyn Runtime> = Arc::new(TokioRuntime);
    let udp = runtime.wrap_udp_socket(socket).unwrap();
    let udp: Arc<dyn quinn::AsyncUdpSocket> = if a.gso_bytes == 0 {
        udp
    } else {
        // quinn 0.11 does not bound a GSO batch by the 65,507 bytes one UDP datagram may carry:
        // at a large segment size the sendmsg fails with EMSGSIZE, which quinn-udp counts as
        // success. The batch is bounded here by segments of the largest size discovery may reach.
        let largest = usize::from(a.mtu_up.max(a.initial_mtu).max(1452));
        Arc::new(SegmentCap {
            max_segments: (a.gso_bytes / largest).max(1),
            inner: udp,
        })
    };
    if !a.gro {
        sys::udp_gro_off(fd);
    }
    let report = format!(
        "max_transmit_segments={} max_receive_segments={} may_fragment={}",
        udp.max_transmit_segments(),
        udp.max_receive_segments(),
        udp.may_fragment()
    );
    let mut config = EndpointConfig::default();
    if a.mtu_ep != 0 {
        config.max_udp_payload_size(a.mtu_ep).unwrap();
    }
    let endpoint = Endpoint::new_with_abstract_socket(config, server, udp, runtime).unwrap();
    Side {
        endpoint,
        socket: report,
    }
}

struct Pair {
    /// The dialling side, the publisher.
    tx: Connection,
    /// The listening side, the subscriber.
    rx: Connection,
    _eps: [Endpoint; 2],
    sockets: [String; 2],
}

async fn connect(a: &Args, rt_rx: &tokio::runtime::Handle, rt_tx: &tokio::runtime::Handle) -> Pair {
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert = ck.cert.der().clone();
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der());
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key.into())
        .unwrap();
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let mut server = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap(),
    ));
    server.transport_config(Arc::new(transport(a)));

    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert).unwrap();
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let mut client = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap(),
    ));
    client.transport_config(Arc::new(transport(a)));

    let (a1, a2) = (a.clone(), a.clone());
    let listener = rt_rx
        .spawn(async move { endpoint(&a1, Some(server)) })
        .await
        .unwrap();
    let dialer = rt_tx
        .spawn(async move { endpoint(&a2, None) })
        .await
        .unwrap();
    let to: SocketAddr = listener.endpoint.local_addr().unwrap();
    let accept = {
        let ep = listener.endpoint.clone();
        rt_rx.spawn(async move { ep.accept().await.unwrap().await.unwrap() })
    };
    let dial = {
        let ep = dialer.endpoint.clone();
        let config = client;
        rt_tx.spawn(async move {
            ep.connect_with(config, to, "localhost")
                .unwrap()
                .await
                .unwrap()
        })
    };
    let (rx, tx) = (accept.await.unwrap(), dial.await.unwrap());
    Pair {
        tx,
        rx,
        sockets: [listener.socket, dialer.socket],
        _eps: [listener.endpoint, dialer.endpoint],
    }
}

// ---- the rows -------------------------------------------------------------------------------

#[derive(Clone, Debug, Default)]
struct Row {
    /// Messages per second counted by the subscriber, and per second sent.
    recv: f64,
    sent: f64,
    gbit: f64,
}

#[derive(Clone, Copy, Debug)]
struct Wire {
    tx_datagrams: u64,
    tx_ios: u64,
    rx_datagrams: u64,
    rx_ios: u64,
    /// The acknowledgements the receiver sent, the sender got.
    acks_sent_by_rx: u64,
    acks_got_by_tx: u64,
    lost: u64,
}

fn wire(p: &Pair) -> Wire {
    let (t, r) = (p.tx.stats(), p.rx.stats());
    Wire {
        tx_datagrams: t.udp_tx.datagrams,
        tx_ios: t.udp_tx.ios,
        rx_datagrams: r.udp_rx.datagrams,
        rx_ios: r.udp_rx.ios,
        acks_sent_by_rx: r.frame_tx.acks,
        acks_got_by_tx: t.frame_rx.acks,
        lost: t.path.lost_packets,
    }
}

fn payload(len: usize, framed: bool) -> Bytes {
    let mut v = Vec::with_capacity(len + 4);
    if framed {
        v.extend_from_slice(&(len as u32).to_be_bytes());
    }
    v.extend((0..len).map(|i| i as u8));
    Bytes::from(v)
}

struct Ctx {
    a: Args,
    rt_tx: Arc<tokio::runtime::Runtime>,
    rt_rx: Arc<tokio::runtime::Runtime>,
    pair: Pair,
}

impl Ctx {
    /// Run `publisher` on the sending runtime and `subscriber` on the receiving one for the
    /// window; the subscriber's counter is what is measured.
    fn throughput(
        &self,
        label: &str,
        size: usize,
        publisher: impl FnOnce(
            Connection,
            Arc<AtomicBool>,
            Arc<AtomicU64>,
        ) -> tokio::task::JoinHandle<()>,
        subscriber: impl FnOnce(Connection, Arc<AtomicU64>) -> tokio::task::JoinHandle<()>,
    ) -> Row {
        let (stop, sent, seen) = (
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicU64::new(0)),
            Arc::new(AtomicU64::new(0)),
        );
        let (r_task, t_task) = {
            let _g = self.rt_rx.enter();
            let r = subscriber(self.pair.rx.clone(), Arc::clone(&seen));
            drop(_g);
            let _g = self.rt_tx.enter();
            let t = publisher(self.pair.tx.clone(), Arc::clone(&stop), Arc::clone(&sent));
            (r, t)
        };
        std::thread::sleep(Duration::from_millis(500));
        let (c0, w0, s0, n0, t0) = (
            threads(),
            wire(&self.pair),
            sent.load(Ordering::Relaxed),
            seen.load(Ordering::Relaxed),
            Instant::now(),
        );
        std::thread::sleep(Duration::from_secs_f64(self.a.secs));
        let (c1, w1, s1, n1, wall) = (
            threads(),
            wire(&self.pair),
            sent.load(Ordering::Relaxed),
            seen.load(Ordering::Relaxed),
            t0.elapsed().as_secs_f64(),
        );
        stop.store(true, Ordering::Relaxed);
        t_task.abort();
        r_task.abort();
        let row = Row {
            recv: (n1 - n0) as f64 / wall,
            sent: (s1 - s0) as f64 / wall,
            gbit: (n1 - n0) as f64 * size as f64 * 8.0 / wall / 1e9,
        };
        println!(
            "row {label:<9} {size:>5} B  recv {:>9.0} msg/s  {:>5.2} Gbit/s   sent {:>9.0} msg/s",
            row.recv, row.gbit, row.sent
        );
        let d = |x: u64, y: u64| (y - x) as f64 / wall;
        println!(
            "    wire/s: tx {:.0} datagrams in {:.0} sendmsg ({:.1} per GSO), rx {:.0} datagrams in {:.0} recvmsg ({:.1} per GRO); \
             acks {:.0}/s sent by the receiver, {:.0}/s read by the sender; lost {}",
            d(w0.tx_datagrams, w1.tx_datagrams),
            d(w0.tx_ios, w1.tx_ios),
            (w1.tx_datagrams - w0.tx_datagrams) as f64 / (w1.tx_ios - w0.tx_ios).max(1) as f64,
            d(w0.rx_datagrams, w1.rx_datagrams),
            d(w0.rx_ios, w1.rx_ios),
            (w1.rx_datagrams - w0.rx_datagrams) as f64 / (w1.rx_ios - w0.rx_ios).max(1) as f64,
            d(w0.acks_sent_by_rx, w1.acks_sent_by_rx),
            d(w0.acks_got_by_tx, w1.acks_got_by_tx),
            w1.lost - w0.lost,
        );
        println!("    cpu: {}", cpu_line(&c0, &c1, wall));
        if self.a.trace {
            println!("    {:?}", self.pair.tx.stats().path);
        }
        std::thread::sleep(Duration::from_millis(300));
        row
    }

    fn dgram(&self, size: usize) -> Row {
        let msg = payload(size, false);
        self.throughput(
            "dgram",
            size,
            move |c, stop, sent| {
                tokio::spawn(async move {
                    while !stop.load(Ordering::Relaxed) {
                        if c.send_datagram_wait(msg.clone()).await.is_err() {
                            break;
                        }
                        sent.fetch_add(1, Ordering::Relaxed);
                    }
                })
            },
            |c, seen| {
                tokio::spawn(async move {
                    while c.read_datagram().await.is_ok() {
                        seen.fetch_add(1, Ordering::Relaxed);
                    }
                })
            },
        )
    }

    fn stream(&self, size: usize) -> Row {
        let msg = payload(size, true);
        self.throughput(
            "stream",
            size,
            move |c, stop, sent| {
                tokio::spawn(async move {
                    let mut tx = c.open_uni().await.unwrap();
                    while !stop.load(Ordering::Relaxed) {
                        if tx.write_all(&msg).await.is_err() {
                            break;
                        }
                        sent.fetch_add(1, Ordering::Relaxed);
                    }
                })
            },
            |c, seen| {
                tokio::spawn(async move {
                    let rx = c.accept_uni().await.unwrap();
                    let mut rx = BufReader::with_capacity(1 << 18, rx);
                    let mut buf = Vec::new();
                    while let Ok(len) = rx.read_u32().await {
                        buf.resize(len as usize, 0);
                        if rx.read_exact(&mut buf).await.is_err() {
                            break;
                        }
                        seen.fetch_add(1, Ordering::Relaxed);
                    }
                })
            },
        )
    }

    /// The 64 B half round trip: ping on a datagram, echo on a datagram. 1,000 warm-up round
    /// trips, then 10,000; the lowest and highest percent dropped, then p50 and p99 of the rest,
    /// in microseconds.
    fn latency(&self) -> (f64, f64, f64) {
        // The throughput rows leave a flood in the receive queues: drain it until it is quiet.
        for (c, rt) in [(&self.pair.rx, &self.rt_rx), (&self.pair.tx, &self.rt_tx)] {
            let c = c.clone();
            rt.block_on(async move {
                while tokio::time::timeout(Duration::from_millis(200), c.read_datagram())
                    .await
                    .is_ok()
                {}
            });
        }
        let echo = {
            let _g = self.rt_rx.enter();
            let c = self.pair.rx.clone();
            tokio::spawn(async move {
                while let Ok(d) = c.read_datagram().await {
                    if c.send_datagram(d).is_err() {
                        break;
                    }
                }
            })
        };
        let c = self.pair.tx.clone();
        let msg = payload(64, false);
        let mut samples = self.rt_tx.block_on(async move {
            let mut out = Vec::with_capacity(10_000);
            for i in 0..11_000 {
                let t = Instant::now();
                c.send_datagram(msg.clone()).unwrap();
                c.read_datagram().await.unwrap();
                if i >= 1_000 {
                    out.push(t.elapsed().as_secs_f64() * 1e6 / 2.0);
                }
            }
            out
        });
        echo.abort();
        let (p50, p99, mean) = trimmed(&mut samples);
        println!(
            "row lat64    p50 {p50:.1} us  p99 {p99:.1} us  mean {mean:.1} us (half round trip, 10,000 after 1,000, outer 1% dropped)"
        );
        std::thread::sleep(Duration::from_millis(300));
        (p50, p99, mean)
    }
}

fn path_report(p: &Pair) {
    for (who, c) in [("publisher", &p.tx), ("subscriber", &p.rx)] {
        let s = c.stats();
        println!(
            "path {who}: current_mtu {} max_datagram_size {:?} cwnd {} rtt {:?} lost {} probes sent {} lost {} black_holes {} \
             | udp_tx {} datagrams {} sendmsg, udp_rx {} datagrams {} recvmsg | frames tx ack {} ping {} datagram {} stream {}",
            s.path.current_mtu,
            c.max_datagram_size(),
            s.path.cwnd,
            s.path.rtt,
            s.path.lost_packets,
            s.path.sent_plpmtud_probes,
            s.path.lost_plpmtud_probes,
            s.path.black_holes_detected,
            s.udp_tx.datagrams,
            s.udp_tx.ios,
            s.udp_rx.datagrams,
            s.udp_rx.ios,
            s.frame_tx.acks,
            s.frame_tx.ping,
            s.frame_tx.datagram,
            s.frame_tx.stream,
        );
    }
}

// ---- ring's AEADs, for the crypto share ------------------------------------------------------

fn crypto() {
    use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
    println!("crypto: ring seal_in_place, one core, 1 s each");
    for (name, alg) in [
        ("AES-128-GCM", &aead::AES_128_GCM),
        ("AES-256-GCM", &aead::AES_256_GCM),
        ("ChaCha20-Poly1305", &aead::CHACHA20_POLY1305),
    ] {
        let key = LessSafeKey::new(UnboundKey::new(alg, &vec![7u8; alg.key_len()]).unwrap());
        for size in [1200usize, 1452, 8960] {
            let mut buf = vec![1u8; size];
            let (mut n, mut pn) = (0u64, 0u64);
            let t = Instant::now();
            while t.elapsed() < Duration::from_secs(1) {
                for _ in 0..64 {
                    let mut nonce = [0u8; 12];
                    nonce[4..].copy_from_slice(&pn.to_be_bytes());
                    pn += 1;
                    let tag = key
                        .seal_in_place_separate_tag(
                            Nonce::assume_unique_for_key(nonce),
                            Aad::from(&[0u8; 20][..]),
                            &mut buf,
                        )
                        .unwrap();
                    let _ = std::hint::black_box(tag);
                    n += 1;
                }
            }
            let secs = t.elapsed().as_secs_f64();
            println!(
                "  {name:<18} {size:>5} B: {:>6.0} ns/packet, {:.2} GB/s ({:.1} Gbit/s)",
                secs * 1e9 / n as f64,
                n as f64 * size as f64 / secs / 1e9,
                n as f64 * size as f64 * 8.0 / secs / 1e9
            );
        }
    }
    let hp = aead::quic::HeaderProtectionKey::new(&aead::quic::AES_128, &[7u8; 16]).unwrap();
    let (mut n, t) = (0u64, Instant::now());
    while t.elapsed() < Duration::from_secs(1) {
        for _ in 0..64 {
            std::hint::black_box(hp.new_mask(&[n as u8; 16]).unwrap());
            n += 1;
        }
    }
    println!(
        "  QUIC header protection (AES-128): {:.0} ns/packet",
        t.elapsed().as_secs_f64() * 1e9 / n as f64
    );
}

// ---- the sampling profile ---------------------------------------------------------------------

#[allow(unsafe_code)]
mod sys {
    //! Linux-only: switch UDP_GRO off, and sample on-CPU threads without `perf`. A per-thread
    //! CPU-time timer (`timer_create`, CPUCLOCK_SCHED of the tid) signals its own thread; the
    //! handler stores the interrupted instruction pointer. A thread that was inside a system
    //! call is interrupted on its way back to user space, so its sample lands on the libc
    //! wrapper of the call (`sendmsg`, `recvmsg`, ...): kernel time shows as that call.

    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    pub fn udp_gro_off(fd: i32) {
        let off: libc::c_int = 0;
        // SAFETY: `fd` is a live UDP socket owned by the caller; the value is a c_int.
        let r = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_UDP,
                libc::UDP_GRO,
                (&off as *const libc::c_int).cast(),
                size_of::<libc::c_int>() as u32,
            )
        };
        assert_eq!(
            r,
            0,
            "setsockopt(UDP_GRO, 0): {}",
            std::io::Error::last_os_error()
        );
    }

    const CAP: usize = 1 << 19;
    static IDX: AtomicUsize = AtomicUsize::new(0);
    static TID: [AtomicU64; CAP] = [const { AtomicU64::new(0) }; CAP];
    static RIP: [AtomicU64; CAP] = [const { AtomicU64::new(0) }; CAP];

    extern "C" fn on_prof(_sig: libc::c_int, _info: *mut libc::siginfo_t, ctx: *mut libc::c_void) {
        // SAFETY: the kernel passes a ucontext_t for a SA_SIGINFO handler; gettid takes no pointers.
        let (rip, tid) = unsafe {
            let uc = ctx as *const libc::ucontext_t;
            (
                (*uc).uc_mcontext.gregs[libc::REG_RIP as usize] as u64,
                libc::syscall(libc::SYS_gettid) as u64,
            )
        };
        let i = IDX.fetch_add(1, Ordering::Relaxed);
        if i < CAP {
            TID[i].store(tid, Ordering::Relaxed);
            RIP[i].store(rip, Ordering::Relaxed);
        }
    }

    /// Start a 1 kHz (nominal; the kernel checks CPU timers at its tick) CPU-time sampler on each tid.
    pub fn start(tids: &[u32]) {
        // SAFETY: plain libc calls with initialised structures; the handler only touches statics.
        unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = on_prof as extern "C" fn(_, _, _) as usize;
            sa.sa_flags = libc::SA_SIGINFO | libc::SA_RESTART;
            libc::sigemptyset(&mut sa.sa_mask);
            assert_eq!(libc::sigaction(libc::SIGPROF, &sa, std::ptr::null_mut()), 0);
            for &tid in tids {
                let clock: libc::clockid_t = ((!(tid as i32)) << 3) | 4 | 2;
                let mut ev: libc::sigevent = std::mem::zeroed();
                ev.sigev_notify = libc::SIGEV_THREAD_ID;
                ev.sigev_signo = libc::SIGPROF;
                ev.sigev_notify_thread_id = tid as i32;
                let mut timer: libc::timer_t = std::ptr::null_mut();
                if libc::timer_create(clock, &mut ev, &mut timer) != 0 {
                    eprintln!(
                        "timer_create for {tid}: {}",
                        std::io::Error::last_os_error()
                    );
                    continue;
                }
                let every = libc::timespec {
                    tv_sec: 0,
                    tv_nsec: 1_000_000,
                };
                let spec = libc::itimerspec {
                    it_interval: every,
                    it_value: every,
                };
                libc::timer_settime(timer, 0, &spec, std::ptr::null_mut());
            }
        }
    }

    /// The samples taken so far: (tid, instruction pointer).
    pub fn samples() -> Vec<(u32, u64)> {
        let n = IDX.load(Ordering::Relaxed).min(CAP);
        (0..n)
            .map(|i| {
                (
                    TID[i].load(Ordering::Relaxed) as u32,
                    RIP[i].load(Ordering::Relaxed),
                )
            })
            .collect()
    }
}

/// One TSV line per (thread name, module, offset): the count. `module` and `offset` come from
/// /proc/self/maps; resolve them with `nm`/`addr2line` against the module's file.
fn dump_profile(path: &str, names: &BTreeMap<u32, String>) {
    let maps: Vec<(u64, u64, u64, String)> = std::fs::read_to_string("/proc/self/maps")
        .unwrap()
        .lines()
        .filter_map(|l| {
            let mut f = l.split_whitespace();
            let (range, _perm, off, _dev, _ino) =
                (f.next()?, f.next()?, f.next()?, f.next()?, f.next()?);
            let file = f.next()?.to_owned();
            let (lo, hi) = range.split_once('-')?;
            Some((
                u64::from_str_radix(lo, 16).ok()?,
                u64::from_str_radix(hi, 16).ok()?,
                u64::from_str_radix(off, 16).ok()?,
                file,
            ))
        })
        .collect();
    let mut counts: BTreeMap<(String, String, u64), u64> = BTreeMap::new();
    for (tid, rip) in sys::samples() {
        let name = names
            .get(&tid)
            .cloned()
            .unwrap_or_else(|| format!("tid{tid}"));
        let (module, off) = maps
            .iter()
            .find(|(lo, hi, _, _)| (*lo..*hi).contains(&rip))
            .map_or(("?".to_owned(), rip), |(lo, _, off, file)| {
                (file.clone(), rip - lo + off)
            });
        *counts.entry((name, module, off)).or_default() += 1;
    }
    let mut f = std::fs::File::create(path).unwrap();
    for ((name, module, off), n) in counts {
        writeln!(f, "{name}\t{module}\t{off:#x}\t{n}").unwrap();
    }
    println!(
        "profile: {} samples written to {path}",
        sys::samples().len()
    );
}

// ---- main -------------------------------------------------------------------------------------

fn main() {
    let a = Args::parse();
    println!("args {a:?}");
    if a.only.iter().any(|o| o == "crypto") {
        crypto();
        if a.only.len() == 1 {
            return;
        }
    }
    let mut summary: BTreeMap<String, Vec<f64>> = BTreeMap::new();
    for rep in 0..a.repeat {
        let (rt_rx, rt_tx) = if a.rt == 1 {
            let r = runtime("both", a.workers);
            (Arc::clone(&r), r)
        } else {
            (runtime("recv", a.workers), runtime("send", a.workers))
        };
        let pair = rt_tx.block_on(connect(&a, rt_rx.handle(), rt_tx.handle()));
        println!(
            "--- repetition {} (sockets: listener {}, dialer {})",
            rep + 1,
            pair.sockets[0],
            pair.sockets[1]
        );
        let ctx = Ctx {
            a: a.clone(),
            rt_tx,
            rt_rx,
            pair,
        };
        if let Some(path) = a.profile.as_deref().filter(|_| rep == 0) {
            let names: BTreeMap<u32, String> =
                threads().into_iter().map(|(t, c)| (t, c.name)).collect();
            let tids: Vec<u32> = names
                .iter()
                .filter(|(_, n)| ["send", "recv", "both"].contains(&n.as_str()))
                .map(|(t, _)| *t)
                .collect();
            sys::start(&tids);
            let _ = path;
        }
        for only in &a.only {
            match only.as_str() {
                "dgram1k" => {
                    summary
                        .entry("dgram 1 KiB msg/s".into())
                        .or_default()
                        .push(ctx.dgram(1024).recv);
                }
                "stream1k" => {
                    summary
                        .entry("stream 1 KiB msg/s".into())
                        .or_default()
                        .push(ctx.stream(1024).recv);
                }
                "stream8k" => {
                    summary
                        .entry("stream 8 KiB msg/s".into())
                        .or_default()
                        .push(ctx.stream(8192).recv);
                }
                "lat" => {
                    let (p50, p99, _) = ctx.latency();
                    summary.entry("lat64 p50 us".into()).or_default().push(p50);
                    summary.entry("lat64 p99 us".into()).or_default().push(p99);
                }
                "mtu" | "idle" => {
                    std::thread::sleep(Duration::from_secs(2));
                }
                "crypto" => {}
                other => panic!("unknown row `{other}`"),
            }
        }
        path_report(&ctx.pair);
        if let Some(path) = a.profile.as_deref().filter(|_| rep == 0) {
            let names: BTreeMap<u32, String> =
                threads().into_iter().map(|(t, c)| (t, c.name)).collect();
            dump_profile(path, &names);
        }
    }
    println!("--- summary of {} repetitions: median [min, max]", a.repeat);
    for (k, mut v) in summary {
        let (m, lo, hi) = median(&mut v);
        println!("{k:<22} {m:>12.1} [{lo:.1}, {hi:.1}]");
    }
}
