//! The latency ladder: where the time goes from a TCP request/response to ndn-data's put->watch, one
//! cost per rung, as ndf's `examples/ladder.rs` measures it (round 12 reproduces it at this pin so it can be
//! run before and after a change). Numbers, no gate. Pinned runs are steadier:
//!
//! ```text
//! taskset -c 8-9 env LADDER_KID_CORES_A=10-11 LADDER_KID_CORES_B=12-13 LADDER_KID_CORES_SRV=14-15 \
//!     cargo run --release -p ndn-link --example ladder
//! ```
//!
//! Rungs (a 4096-byte piece is what the data layer asks; sizes 1 KiB, 16 KiB, 1 MiB):
//!
//! 1. TCP request/response on localhost, the server in another process.
//! 2. QUIC streams (quinn), the server in another process.
//! 3. NDN Interest->Data between two processes, each an embedded `ForwarderEngine`, over an
//!    `ndn-link` link set up by key (`PeerSpec`): a unsigned, b signed per request (ed25519), c signed and
//!    verified by the consumer, d = c with NDNLPv2 reliability (`PeerSpec::reliability`).
//! 4. The same on ONE forwarder with two app faces: a unsigned, b signed and verified.
//! 5. `ndn_data::Device` put on A -> B's `watch` yields, A and B two processes of this binary, each a
//!    person with a device on a forwarder of its own and a **fjall store on disk**, linked by
//!    `ndn-link`: A shares a folder and offers it, B joins by the short code. The clean runs have no recorder;
//!    the traced runs (`LADDER_TL`) install one in both children (the `ndn_data::timeline` events, see
//!    `ndn-data`'s `device.rs`) and give the 1 KiB timeline, B's fetches, the flush (fsync) of the commit rounds and
//!    `5p`, B's pull of the held version (its first fetch Interest out to its last Data in).
//! 6. Re-expressions: how many pieces of rung 3 were asked again after their timer (and how many asks
//!    failed outright), and in rung 5's traced runs how many of B's fetches were and how many drop
//!    notices the link gave.
//!
//! A size is asked as ndn-data asks it: pieces of `ndn_data::wire::CHUNK` (4096) bytes, `Config::window` (32)
//! in flight, each piece its own Interest, re-expressed after 250 ms, 500, 1000 within a 2 s lifetime
//! (`Config::lifetime`). `RTO_MIN` and `REEXPRESS_MAX` are private to ndn-data: mirrored here.
//!
//! Knobs (environment): `LADDER_RUNS` runs per size after the 10 warm-ups (200); `LADDER_ONLY`
//! the rungs to run (`1,2,3,4,5,6`); `LADDER_TL` traced put->watch runs per size (60; 0 skips them);
//! `LADDER_OUT` a file the report is also written to; `LADDER_DIR` where the stores live (`/tmp/ndn-ladder-data`, a
//! real disk, never a tmpfs: the flush barrier costs what the disk costs);
//! `LADDER_KID_CORES_A`, `_B` and `_SRV` the cores (a `taskset -c` list) of the data-layer children and of the
//! TCP, QUIC and producer servers (unset: they run on the cores the parent has).

#[allow(dead_code)]
#[path = "ladder/host.rs"]
mod host;
#[path = "ladder/newest.rs"]
mod newest;
#[path = "ladder/tape.rs"]
mod tape;

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use futures::StreamExt;
use ndn_app::{Consumer, EngineAppExt, Node};
use ndn_data::wire::CHUNK;
use ndn_engine::{EngineBuilder, EngineConfig};
use ndn_face_quic::{KeyFingerprint, LinkEndpoint, LinkKey, LinkKeySource, LinkTransportConfig};
use ndn_link::{
    ConfiguredEndpoints, EngineFaces, LinkSetup, LinkTrust, Links, PeerSpec, RelayService,
};
use ndn_packet::Name;
use ndn_packet::encode::{DataBuilder, InterestBuilder};
use ndn_security::verifier::{Ed25519Verifier, VerifyOutcome};
use ndn_security::{Certificate, Ed25519Signer, Keyring, SecurityProfile, SignWith};
use ndn_sync::DataStore;
use tape::now_ns;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, Lines};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio_util::sync::CancellationToken;

const SIZES: [(usize, &str); 3] = [(1 << 10, "1 KiB"), (16 << 10, "16 KiB"), (1 << 20, "1 MiB")];
const WARM: usize = 10;
/// The data layer's `RTO_MIN` and `REEXPRESS_MAX` (private there): an unanswered piece is asked again after 250 ms, 500, 1000.
const GAPS_MS: [u64; 3] = [250, 500, 1000];
static RUN: AtomicU64 = AtomicU64::new(0);
/// Pieces asked again after their timer; asks that failed (a Nack or the lifetime) and were asked again.
static REEXPRESSED: AtomicU64 = AtomicU64::new(0);
static NACKED: AtomicU64 = AtomicU64::new(0);
static FAILED: AtomicU64 = AtomicU64::new(0);

fn env<T: std::str::FromStr>(k: &str, d: T) -> T {
    std::env::var(k)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(d)
}
fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1e3
}
fn pct(v: &mut [Duration], p: f64) -> Duration {
    v.sort();
    v[((v.len() as f64 * p) as usize).min(v.len() - 1)]
}

/// p50 and p95 of `n` runs of `body` after the warm-up, each timed (`body` may await).
macro_rules! sample {
    ($n:expr, $body:expr) => {{
        let mut v = Vec::new();
        for i in 0..WARM + $n {
            let t = Instant::now();
            $body;
            if i >= WARM {
                v.push(t.elapsed());
            }
        }
        Some((pct(&mut v, 0.5), pct(&mut v, 0.95)))
    }};
}

/// The report: each line goes to stdout and to what `LADDER_OUT` gets at the end.
static REPORT: Mutex<String> = Mutex::new(String::new());
macro_rules! say {
    ($($a:tt)*) => {{
        let s = format!($($a)*);
        println!("{s}");
        let mut r = REPORT.lock().unwrap();
        r.push_str(&s);
        r.push('\n');
    }};
}

// ---- children ------------------------------------------------------------------------------------------------------
#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    match a.first().map(String::as_str) {
        Some("tcp") => tcp_server().await,
        Some("quic") => quic_server().await,
        Some("prod") => {
            let h = host(1, 2, None, a[1] == "1").await;
            let _guard = produce(&h.node).await;
            println!("ADDR {}", h.addr);
            std::future::pending::<()>().await
        }
        Some("a") => child_a(&a[1]).await,
        Some("b") => child_b(&a[1], &a[2]).await,
        _ => ladder().await,
    }
}

fn trace_if_asked() {
    if std::env::var("LADDER_TRACE").is_ok() {
        tracing::subscriber::set_global_default(tape::Tape).unwrap();
    }
}

/// Child A: Ann's folder, offered. `PUT <i> <size>`: put (clock and `i` first) at one path, say when it returned.
async fn child_a(dir: &str) {
    trace_if_asked();
    let ann = host::Host::open(Path::new(dir), 0x11).await;
    let folder = ann.share("ladder").await;
    println!("CODE {}", ann.offer(&folder).await);
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    while let Some(l) = lines.next_line().await.unwrap() {
        let w: Vec<&str> = l.split(' ').collect();
        match w[0] {
            "PUT" => {
                let (i, size): (u64, usize) = (w[1].parse().unwrap(), w[2].parse().unwrap());
                let (t0, mut bytes) = (now_ns(), vec![0u8; size]);
                bytes[..16].copy_from_slice(&t0.to_le_bytes());
                bytes[16..24].copy_from_slice(&i.to_le_bytes());
                ann.put(&folder, "bench", &bytes).await;
                println!("PUT {i} {t0} {}", now_ns());
            }
            _ => tape::command(w[0]),
        }
    }
}

/// Child B: Bob joins by the code and says, for each item the watch delivers, how long after the put started.
async fn child_b(dir: &str, code: &str) {
    trace_if_asked();
    let bob = host::Host::open(Path::new(dir), 0x22).await;
    let folder = bob.join(code).await;
    let mut items = Box::pin(bob.watch(&folder).await);
    println!("READY");
    tokio::spawn(async move {
        while let Some(bytes) = items.next().await {
            let (sent, i) = (
                u128::from_le_bytes(bytes[..16].try_into().unwrap()),
                u64::from_le_bytes(bytes[16..24].try_into().unwrap()),
            );
            println!("GOT {i} {}", now_ns().saturating_sub(sent));
        }
    });
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    while let Some(l) = lines.next_line().await.unwrap() {
        tape::command(&l);
    }
}

/// The next line the child said, which must start with `what`; the rest of it.
async fn line(out: &mut Lines<BufReader<ChildStdout>>, what: &str) -> String {
    let l = tokio::time::timeout(Duration::from_secs(60), out.next_line())
        .await
        .expect("the child answers in 60 s")
        .unwrap()
        .expect("the child is still there");
    l.strip_prefix(what)
        .unwrap_or_else(|| panic!("wanted {what}, the child said {l:?}"))
        .trim()
        .to_owned()
}

/// Child C: a TCP server answering each 8-byte request (a size) with that many bytes.
async fn tcp_server() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    println!("PORT {}", listener.local_addr().unwrap().port());
    let (mut s, _) = listener.accept().await.unwrap();
    let mut buf = vec![0u8; 1 << 20];
    let mut req = [0u8; 8];
    while s.read_exact(&mut req).await.is_ok() {
        s.write_all(&buf[..u64::from_le_bytes(req) as usize])
            .await
            .unwrap();
        buf[0] = 1;
    }
}

struct Kid {
    stdin: ChildStdin,
    out: Lines<BufReader<ChildStdout>>,
    _p: Child,
}

/// This binary again as `args`, its output piped; `traced` sets the recorder, `cores_env` names the variable that
/// holds the cores (a `taskset -c` list) it runs on, if any.
async fn kid(args: &[&str], traced: bool, cores_env: &str) -> Kid {
    let exe = std::env::current_exe().unwrap();
    let mut c = match std::env::var(cores_env) {
        Ok(cores) => {
            let mut c = Command::new("taskset");
            c.arg("-c").arg(cores).arg(exe);
            c
        }
        Err(_) => Command::new(exe),
    };
    c.args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .kill_on_drop(true);
    if traced {
        c.env("LADDER_TRACE", "1");
    }
    let mut p = c.spawn().unwrap();
    Kid {
        stdin: p.stdin.take().unwrap(),
        out: BufReader::new(p.stdout.take().unwrap()).lines(),
        _p: p,
    }
}

impl Kid {
    async fn ask(&mut self, cmd: &str, reply: &str) -> String {
        self.stdin
            .write_all(format!("{cmd}\n").as_bytes())
            .await
            .unwrap();
        line(&mut self.out, reply).await
    }
    async fn dump(&mut self) -> Vec<(u128, String, String)> {
        self.stdin.write_all(b"DUMP\n").await.unwrap();
        let mut v = Vec::new();
        while let Some(l) = self.out.next_line().await.unwrap() {
            if l == "END" {
                break;
            }
            if let Some(r) = l.strip_prefix("EV ") {
                let mut p = r.splitn(3, ' ');
                v.push((
                    p.next().unwrap().parse().unwrap(),
                    p.next().unwrap().to_owned(),
                    p.next().unwrap_or("").to_owned(),
                ));
            }
        }
        v
    }
}

// ---- rung 2: QUIC streams ---------------------------------------------------------------------------------------
/// A throwaway self-signed ed25519 certificate for `localhost` (CA:FALSE) and its PKCS#8 key, DER in hex (ndf's: the two ladders share them).
const CERT: &str = "3082014f30820101a00302010202141799c65fc473c3c894e70729a29ccefcfcc983ab300506032b6570300c310a300806035504030c016c3020170d3236313132313135313530305a180f32313236313032383135313530305a300c310a300806035504030c016c302a300506032b6570032100e1141fe474783e664c4a9e4a94955b4d73ba6d2cec21c18b1737bd3f3f357484a3733071301d0603551d0e04160414b8db32ee432671114239e8ed49553d066e03b5b2301f0603551d23041830168014b8db32ee432671114239e8ed49553d066e03b5b230140603551d11040d300b82096c6f63616c686f7374300c0603551d130101ff04023000300b0603551d0f040403020780300506032b65700341007c35f30860b6d8c77fb9e43dfc921fab1f8b191cfe53b2f22d2581a103d89a5ca892397d6157604140b36521cac893c43820bc9b0077b4508f75e902b870a603";
const KEY: &str = "302e020100300506032b6570042204206db92696bb9d22785530b2a2f3c1540a7599f2c6ec421f23995849edde94802a";
fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

async fn quic_server() {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![unhex(CERT).into()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(unhex(KEY)).into(),
        )
        .unwrap();
    tls.alpn_protocols = vec![b"ladder".to_vec()];
    let cfg = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap(),
    ));
    let ep = quinn::Endpoint::server(cfg, "127.0.0.1:0".parse().unwrap()).unwrap();
    println!("PORT {}", ep.local_addr().unwrap().port());
    let conn = ep.accept().await.unwrap().await.unwrap();
    let buf = vec![0u8; 1 << 20];
    while let Ok((mut tx, mut rx)) = conn.accept_bi().await {
        let mut req = [0u8; 8];
        rx.read_exact(&mut req).await.unwrap();
        tx.write_all(&buf[..u64::from_le_bytes(req) as usize])
            .await
            .unwrap();
        tx.finish().unwrap();
    }
}

async fn quic_client(port: &str) -> quinn::Connection {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = rustls::RootCertStore::empty();
    roots.add(unhex(CERT).into()).unwrap();
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"ladder".to_vec()];
    let mut ep = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    ep.set_default_client_config(quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap(),
    )));
    ep.connect(format!("127.0.0.1:{port}").parse().unwrap(), "localhost")
        .unwrap()
        .await
        .unwrap()
}

// ---- rungs 3 and 4: NDN Interest->Data ------------------------------------------------------------------------------
/// No namespace held, no certificate: the link is admitted by the expected key.
struct NoTrust(Arc<Keyring>);
impl LinkTrust for NoTrust {
    fn keyring(&self) -> &Arc<Keyring> {
        &self.0
    }
    fn own_chain(&self) -> Vec<Bytes> {
        Vec::new()
    }
    fn known_certificate(&self, _: &Name) -> Option<Certificate> {
        None
    }
    fn known_certificate_of_key(&self, _: &KeyFingerprint) -> Option<Certificate> {
        None
    }
}

fn link_key(seed: u8) -> LinkKey {
    LinkKey::from_signer(Arc::new(Ed25519Signer::from_seed(
        &[seed; 32],
        format!("/ladder/member/d{seed}/KEY/1").parse().unwrap(),
    )))
    .unwrap()
}

struct Host {
    node: Node,
    addr: String,
    engine: ndn_engine::ForwarderEngine,
    cancel: CancellationToken,
    _keep: (ndn_engine::ShutdownHandle, Arc<Links>),
}

/// An embedded forwarder as a host builds it, an app face, and a link to the device with key `peer`: dialled when `dial` has its address.
async fn host(me: u8, peer: u8, dial: Option<&str>, reliable: bool) -> Host {
    let (engine, shutdown) = EngineBuilder::new(EngineConfig {
        pipeline_threads: 1,
        ..EngineConfig::default()
    })
    .security_profile(SecurityProfile::Disabled)
    .build()
    .await
    .unwrap();
    let cancel = CancellationToken::new();
    let node = engine.app_node(cancel.child_token());
    let key: Arc<dyn LinkKeySource> = Arc::new(link_key(me));
    let transport = LinkTransportConfig::default();
    let socket = LinkEndpoint::bind(
        "127.0.0.1:0".parse().unwrap(),
        key.clone(),
        &transport,
        true,
    )
    .unwrap();
    let addr = socket.local_addr().unwrap().to_string();
    let spec = PeerSpec {
        label: "peer".into(),
        key: Some(link_key(peer).fingerprint()),
        endpoints: dial.map(str::to_owned).into_iter().collect(),
        routes: dial.map(|_| vec!["/ladder".parse().unwrap()]),
        reliability: reliable,
        ..PeerSpec::default()
    };
    let links = Links::start(
        LinkSetup {
            peers: vec![spec],
            key,
            trust: Arc::new(NoTrust(Arc::new(Keyring::new()))),
            faces: Arc::new(EngineFaces(engine.clone())),
            paths: Arc::new(ConfiguredEndpoints),
            candidates: Vec::new(),
            socket: Some(Arc::new(socket)),
            transport,
            relays: Default::default(),
            service: RelayService::default(),
            direct: Default::default(),
        },
        cancel.clone(),
    );
    Host {
        node,
        addr,
        engine,
        cancel,
        _keep: (shutdown, links),
    }
}

/// Answer `/ladder/<n|s>/<size>/<run>/<piece>` from memory with `min(4096, size - piece * 4096)` bytes: unsigned (`n`) or ed25519-signed per request.
async fn produce(node: &Node) -> ndn_app::ServeGuard {
    let signer = Arc::new(Ed25519Signer::from_seed(
        &[7; 32],
        "/ladder/KEY/1".parse().unwrap(),
    ));
    let zeros = Bytes::from(vec![0u8; CHUNK]);
    node.serve(
        "/ladder".parse::<Name>().unwrap(),
        move |interest, responder| {
            let (signer, zeros) = (signer.clone(), zeros.clone());
            async move {
                let c = interest.name.components();
                let num = |i: usize| {
                    std::str::from_utf8(&c[i].value)
                        .unwrap()
                        .parse::<usize>()
                        .unwrap()
                };
                let len = num(2).saturating_sub(num(4) * CHUNK).min(CHUNK);
                let b = DataBuilder::new((*interest.name).clone(), &zeros[..len]);
                let _ = responder
                    .respond_bytes(if c[1].value[0] == b'n' {
                        b.sign_none()
                    } else {
                        b.sign_with_sync(&*signer).unwrap()
                    })
                    .await;
            }
        },
    )
    .await
    .unwrap()
}

/// Ask for `size` bytes: its pieces, `window` in flight, each re-expressed after 250 ms, 500, 1000; `mode` n (unsigned), s (signed), v (signed and verified here).
/// A piece whose ask fails outright (a Nack, the lifetime) is counted and asked again, up to three times more, so one lost piece cannot end a long run.
async fn ask(node: &Node, mode: char, size: usize, window: usize) {
    let run = RUN.fetch_add(1, Relaxed);
    let pk =
        Ed25519Signer::from_seed(&[7; 32], "/ladder/KEY/1".parse().unwrap()).public_key_bytes();
    let got: usize = futures::stream::iter(0..size.div_ceil(CHUNK).max(1))
        .map(|piece| async move {
            let name: Name = format!(
                "/ladder/{}/{size}/{run}/{piece}",
                if mode == 'n' { 'n' } else { 's' }
            )
            .parse()
            .unwrap();
            let mut tries = 0;
            let (d, expressed) = loop {
                match Consumer::new(node.connection())
                    .fetch_reexpressing(
                        || InterestBuilder::new(name.clone()),
                        Duration::from_secs(2),
                        Duration::from_millis(250),
                        GAPS_MS.map(Duration::from_millis),
                    )
                    .await
                {
                    Ok(got) => break got,
                    Err(e) if tries < 3 => {
                        tries += 1;
                        FAILED.fetch_add(1, Relaxed);
                        if format!("{e:?}").contains("Nack") {
                            NACKED.fetch_add(1, Relaxed);
                        }
                    }
                    Err(e) => panic!("the piece {name} did not come in four asks: {e:?}"),
                }
            };
            REEXPRESSED.fetch_add(u64::from(expressed - 1), Relaxed);
            if mode == 'v' {
                assert_eq!(
                    Ed25519Verifier.verify_sync(d.signed_region(), d.sig_value(), &pk),
                    VerifyOutcome::Valid
                );
            }
            d.content().map_or(0, |c| c.len())
        })
        .buffer_unordered(window)
        .fold(0, |a, b| async move { a + b })
        .await;
    assert_eq!(got, size);
}

// ---- the ladder -------------------------------------------------------------------------------------------------
type Cell = Option<(Duration, Duration)>;
struct Rung {
    id: String,
    name: String,
    vs: Option<&'static str>,
    cells: [Cell; 3],
}

/// What rung 6 counts of a rung-3 variant, per size: runs (warm-up included), runs in which a piece was asked again after its timer, those pieces, asks that failed.
struct Reexpressed {
    id: &'static str,
    runs: [usize; 3],
    runs_with: [usize; 3],
    pieces: [u64; 3],
    failed: [u64; 3],
    nacked: [u64; 3],
}

fn loadavg() -> String {
    std::fs::read_to_string("/proc/loadavg")
        .map(|s| s.split(' ').take(3).collect::<Vec<_>>().join(" "))
        .unwrap_or_default()
}

async fn ladder() {
    let (n, only) = (
        env("LADDER_RUNS", 200usize),
        env("LADDER_ONLY", "1,2,3,4,5,6".to_owned()),
    );
    let on = |r: &str| only.split(',').any(|x| x == r);
    let window = ndn_data::Config::new().window;
    let (mut rungs, mut counts): (Vec<Rung>, Vec<Reexpressed>) = (Vec::new(), Vec::new());
    let started = loadavg();
    let data = PathBuf::from(env("LADDER_DIR", "/tmp/ndn-ladder-data".to_owned()))
        .join(format!("run-{}", std::process::id()));
    std::fs::create_dir_all(&data).unwrap();

    if on("1") {
        let mut tcp = kid(&["tcp"], false, "LADDER_KID_CORES_SRV").await;
        let mut sock = tokio::net::TcpStream::connect(format!(
            "127.0.0.1:{}",
            line(&mut tcp.out, "PORT").await
        ))
        .await
        .unwrap();
        sock.set_nodelay(true).unwrap();
        let mut cells = [None; 3];
        for (k, (size, _)) in SIZES.iter().enumerate() {
            let mut buf = vec![0u8; *size];
            cells[k] = sample!(n, {
                sock.write_all(&(*size as u64).to_le_bytes()).await.unwrap();
                sock.read_exact(&mut buf).await.unwrap();
            });
        }
        rungs.push(Rung {
            id: "1".into(),
            name: "TCP request/response, localhost".into(),
            vs: None,
            cells,
        });
    }
    if on("2") {
        let mut q = kid(&["quic"], false, "LADDER_KID_CORES_SRV").await;
        let conn = quic_client(&line(&mut q.out, "PORT").await).await;
        let mut cells = [None; 3];
        for (k, (size, _)) in SIZES.iter().enumerate() {
            let mut buf = vec![0u8; *size];
            cells[k] = sample!(n, {
                let (mut tx, mut rx) = conn.open_bi().await.unwrap();
                tx.write_all(&(*size as u64).to_le_bytes()).await.unwrap();
                tx.finish().unwrap();
                rx.read_exact(&mut buf).await.unwrap();
            });
        }
        rungs.push(Rung {
            id: "2".into(),
            name: "QUIC stream request/response, loopback (quinn)".into(),
            vs: Some("1"),
            cells,
        });
    }
    if on("3") {
        for rel in [false, true] {
            let mut p = kid(
                &["prod", if rel { "1" } else { "0" }],
                false,
                "LADDER_KID_CORES_SRV",
            )
            .await;
            let h = host(2, 1, Some(&line(&mut p.out, "ADDR").await), rel).await;
            while h
                .node
                .fetch("/ladder/n/64/0/0".parse::<Name>().unwrap())
                .await
                .is_err()
            {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            for (mode, id, vs, what) in [
                ('n', "3a", "2", "NDN Interest->Data over the link, unsigned"),
                ('s', "3b", "3a", "+ the producer signs ed25519 per request"),
                ('v', "3c", "3b", "+ the consumer verifies each Data"),
                ('v', "3d", "3c", "3c with NDNLPv2 reliability on the link"),
            ] {
                if rel != (id == "3d") {
                    continue;
                }
                let mut cells = [None; 3];
                let mut c = Reexpressed {
                    id,
                    runs: [0; 3],
                    runs_with: [0; 3],
                    pieces: [0; 3],
                    failed: [0; 3],
                    nacked: [0; 3],
                };
                for (k, (size, _)) in SIZES.iter().enumerate() {
                    let (f0, n0) = (FAILED.load(Relaxed), NACKED.load(Relaxed));
                    let r0 = REEXPRESSED.load(Relaxed);
                    cells[k] = sample!(n, {
                        let before = REEXPRESSED.load(Relaxed);
                        ask(&h.node, mode, *size, window).await;
                        c.runs_with[k] += usize::from(REEXPRESSED.load(Relaxed) > before);
                    });
                    c.runs[k] = n + WARM;
                    c.pieces[k] = REEXPRESSED.load(Relaxed) - r0;
                    c.failed[k] = FAILED.load(Relaxed) - f0;
                    c.nacked[k] = NACKED.load(Relaxed) - n0;
                }
                counts.push(c);
                rungs.push(Rung {
                    id: id.into(),
                    name: what.into(),
                    vs: Some(vs),
                    cells,
                });
            }
        }
    }
    if on("4") {
        let h = host(1, 2, None, false).await;
        let (cons, _guard) = (
            h.engine.app_node(h.cancel.child_token()),
            produce(&h.node).await,
        );
        for (mode, id, vs, what) in [
            ('n', "4a", "3a", "ONE forwarder, two app faces, unsigned"),
            ('v', "4b", "3c", "ONE forwarder, signed and verified"),
        ] {
            let mut cells = [None; 3];
            for (k, (size, _)) in SIZES.iter().enumerate() {
                cells[k] = sample!(n, ask(&cons, mode, *size, window).await);
            }
            rungs.push(Rung {
                id: id.into(),
                name: what.into(),
                vs: Some(vs),
                cells,
            });
        }
    }
    let mut timeline = String::new();
    let mut put_watch_counts = String::new();
    if on("5") {
        let tl = env("LADDER_TL", 60usize);
        for traced in [false, true] {
            if traced && tl == 0 {
                continue;
            }
            let (cells, pull, text, drops) = put_watch(&data, n, tl, traced).await;
            if traced {
                rungs.push(Rung { id: "5p".into(), name: "ndn-data pull of the held version (B: first fetch Interest out -> last Data in)".into(), vs: Some("3c"), cells: pull });
                timeline = text;
                put_watch_counts = drops;
            } else {
                rungs.push(Rung {
                    id: "5".into(),
                    name:
                        "ndn-data put on A -> B's watch yields, two processes (clean, no recorder)"
                            .into(),
                    vs: Some("5p"),
                    cells,
                });
            }
        }
    }
    let flush = if on("5") && env("LADDER_TL", 60usize) > 0 {
        flush_cost(&data)
    } else {
        String::new()
    };
    let finished = loadavg();
    let _ = std::fs::remove_dir_all(&data);

    // ---- the report ---------------------------------------------------------------------------------------------
    rungs.sort_by(|a, b| a.id.cmp(&b.id));
    say!("# ndn-link latency ladder\n");
    say!(
        "- runs per size {n} after {WARM} warm-ups; rungs {only}; traced put->watch runs per size {}",
        env("LADDER_TL", 60usize)
    );
    say!("- stores on: {}", filesystem(&data));
    say!(
        "- window {window} pieces of {CHUNK} bytes in flight; re-expression gaps {GAPS_MS:?} ms (the data layer's `RTO_MIN`/`REEXPRESS_MAX` are private: mirrored)"
    );
    say!("- load average (1 5 15 min) at start: {started}; at end: {finished}\n");
    say!("## Latency, p50 / p95 ms (delta = p50 minus its `vs` rung's)\n");
    say!("| rung | vs | {} |", SIZES.map(|s| s.1).join(" | "));
    say!("|---|---|{}", "---|".repeat(SIZES.len()));
    for r in &rungs {
        let cells: Vec<String> = r
            .cells
            .iter()
            .enumerate()
            .map(|(k, c)| {
                let base =
                    r.vs.and_then(|p| rungs.iter().find(|b| b.id == p))
                        .and_then(|b| b.cells[k]);
                match (c, base) {
                    (Some((a, b)), Some((p, _))) => {
                        format!("{:.3} / {:.3} ({:+.3})", ms(*a), ms(*b), ms(*a) - ms(p))
                    }
                    (Some((a, b)), None) => format!("{:.3} / {:.3}", ms(*a), ms(*b)),
                    _ => "-".into(),
                }
            })
            .collect();
        say!(
            "| {} {} | {} | {} |",
            r.id,
            r.name,
            r.vs.unwrap_or("-"),
            cells.join(" | ")
        );
    }
    if on("6") && (!counts.is_empty() || !put_watch_counts.is_empty()) {
        say!("\n## Rung 6: re-expressions\n");
        if !counts.is_empty() {
            say!(
                "Rung 3, by size (warm-up runs included): runs in which a piece was asked again after its timer / pieces asked again / asks that failed outright (Nack among them) and were asked again."
            );
            say!(
                "The link has no public counter of Interests it dropped or Nacked (`face.quic` keeps one and tells it in a rate-limited info notice), so the consumer's count is the measure here.\n"
            );
            say!("| rung | {} |", SIZES.map(|s| s.1).join(" | "));
            say!("|---|{}", "---|".repeat(SIZES.len()));
            for c in &counts {
                let cells: Vec<String> = (0..3)
                    .map(|k| {
                        format!(
                            "{} of {} runs / {} pieces / {} failed ({} Nack)",
                            c.runs_with[k], c.runs[k], c.pieces[k], c.failed[k], c.nacked[k]
                        )
                    })
                    .collect();
                say!("| {} | {} |", c.id, cells.join(" | "));
            }
        }
        if !put_watch_counts.is_empty() {
            say!("\nRung 5, traced runs:\n");
            say!("{put_watch_counts}");
        }
    }
    if !timeline.is_empty() {
        say!("\n## Rung 5 timeline (traced runs)\n");
        say!("{timeline}");
    }
    if !flush.is_empty() {
        say!("\n## What the durability barrier costs on this disk\n");
        say!("{flush}");
    }
    if let Ok(path) = std::env::var("LADDER_OUT") {
        std::fs::write(&path, &*REPORT.lock().unwrap()).unwrap();
    }
}

/// The filesystem `dir` is on: `df -PT` of it.
fn filesystem(dir: &Path) -> String {
    let probe = dir.parent().unwrap_or(dir);
    std::process::Command::new("df")
        .args(["-PT"])
        .arg(probe)
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| {
            s.lines().nth(1).map(|l| {
                l.split_whitespace()
                    .take(2)
                    .collect::<Vec<_>>()
                    .join(" type ")
            })
        })
        .map_or_else(
            || "unknown".into(),
            |f| format!("{} ({f})", probe.display()),
        )
}

// ---- rung 5: put->watch clean, then with its timeline --------------------------------------------------------------------
/// One put->watch: when it started, returned on A, was delivered on B, and the events both children recorded, by time: (time, A or B, "target message").
struct Step {
    i: usize,
    t0: u128,
    end: u128,
    got: u128,
    ev: Vec<(u128, char, String)>,
}

/// The times of the events of `who` whose text starts with the word `msg` (the message is first in the text).
fn times<'a>(r: &'a Step, who: char, msg: &'a str) -> impl Iterator<Item = u128> + 'a {
    r.ev.iter()
        .filter(move |e| {
            e.1 == who
                && e.2
                    .split_once("ndn_data::timeline ")
                    .is_some_and(|(_, t)| t.split(' ').next() == Some(msg))
        })
        .map(|e| e.0)
}
fn texts<'a>(r: &'a Step, who: char, msg: &'a str) -> impl Iterator<Item = (u128, &'a str)> + 'a {
    r.ev.iter()
        .filter(move |e| e.1 == who)
        .filter_map(move |e| {
            e.2.split_once("ndn_data::timeline ")
                .filter(|(_, t)| t.split(' ').next() == Some(msg))
                .map(|(_, t)| (e.0, t))
        })
}
fn field<'a>(m: &'a str, key: &str) -> Option<&'a str> {
    m.split(&format!("{key}="))
        .nth(1)
        .and_then(|r| r.split(' ').next())
}
/// What a data layer's fetch names, by the words in the name (`keyword=root`, ...): the writer's summary root, a node of its
/// summary tree (named by digest), a log entry, or a piece of a large payload (its manifest, its chunks).
fn kind(name: &str) -> &'static str {
    if name.ends_with("keyword=root") {
        "summary root"
    } else if name.contains("keyword=summary") {
        "summary node"
    } else if name.contains("keyword=manifest") {
        "manifest piece"
    } else if name.contains("keyword=log") && name.contains("/seg=") {
        "chunk"
    } else if name.contains("keyword=log") {
        "log entry"
    } else {
        "other"
    }
}

/// The end of a fetched name, past the person's long hashes: after the last `keyword=data/`, digests cut to 8 hex digits.
fn tail(name: &str) -> String {
    let t = name.rsplit("keyword=data/").next().unwrap_or(name);
    match t.split_once("sha256digest=") {
        Some((head, digest)) => format!("{head}sha256digest={}", &digest[..digest.len().min(8)]),
        None => t
            .rsplit_once("keyword=")
            .map_or(t.to_owned(), |(_, w)| w.to_owned()),
    }
}

/// The first of A's announcements and the last flush that ended before it: the round that made the put durable.
fn announce_at(r: &Step) -> Option<u128> {
    times(r, 'A', "announce").min()
}
fn flush_end_before_announce(r: &Step) -> Option<u128> {
    let a = announce_at(r)?;
    times(r, 'A', "flush_end").filter(|t| *t <= a).max()
}
/// B hears A's update: `sync_update` events name the device that moved (B hears itself too).
fn heard(r: &Step) -> Option<u128> {
    texts(r, 'B', "sync_update")
        .filter(|(_, t)| t.contains("member/d17"))
        .map(|(t, _)| t)
        .min()
}

async fn put_watch(
    data: &Path,
    n: usize,
    tl: usize,
    traced: bool,
) -> ([Cell; 3], [Cell; 3], String, String) {
    let steps: [(&str, fn(&Step) -> Option<u128>); 13] = [
        ("put returns on A", |r| Some(r.end)),
        ("A: store flush round 1 begins", |r| {
            times(r, 'A', "flush_begin").min()
        }),
        ("A: store flush round 1 ends", |r| {
            times(r, 'A', "flush_end").min()
        }),
        (
            "A: store flush round 2 begins (if the put needed a second)",
            |r| times(r, 'A', "flush_begin").nth(1),
        ),
        (
            "A: store flush ends (the round that announces)",
            flush_end_before_announce,
        ),
        ("A: announcement handed to sync", announce_at),
        ("B: sync update heard", heard),
        ("B: first fetch Interest out", |r| {
            times(r, 'B', "fetch_out").min()
        }),
        ("B: last Data in", |r| times(r, 'B', "fetch_in").max()),
        ("B: last signature verified", |r| {
            times(r, 'B', "verify_end").max()
        }),
        ("B: watch is sent the change (last)", |r| {
            times(r, 'B', "watch_send").max()
        }),
        ("B: watch yields (GOT)", |r| Some(r.got)),
        ("(B: first signature verification begins)", |r| {
            times(r, 'B', "verify_begin").min()
        }),
    ];
    let dir = data.join(if traced { "traced" } else { "clean" });
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::create_dir_all(dir.join("a")).unwrap();
    std::fs::create_dir_all(dir.join("b")).unwrap();
    let mut a = kid(
        &["a", dir.join("a").to_str().unwrap()],
        traced,
        "LADDER_KID_CORES_A",
    )
    .await;
    let code = line(&mut a.out, "CODE").await;
    let mut b = kid(
        &["b", dir.join("b").to_str().unwrap(), &code],
        traced,
        "LADDER_KID_CORES_B",
    )
    .await;
    line(&mut b.out, "READY").await;
    let (mut c5, mut c5p) = ([None; 3], [None; 3]);
    let (mut text, mut counts) = (String::new(), String::new());
    for (k, (size, label)) in SIZES.iter().enumerate() {
        let (mut got, mut pull, mut runs) = (Vec::new(), Vec::new(), Vec::new());
        eprintln!("rung 5 {} {label}", if traced { "traced" } else { "clean" });
        for i in 0..WARM + if traced { tl } else { n } {
            if traced {
                a.ask("CLEAR", "CLEAR").await;
                b.ask("CLEAR", "CLEAR").await;
            }
            let put: Vec<u128> = a
                .ask(&format!("PUT {i} {size}"), "PUT")
                .await
                .split(' ')
                .skip(1)
                .map(|x| x.parse().unwrap())
                .collect();
            // A watch that delivers more than once for a put (a later change of the same path) leaves
            // a stale GOT behind: take lines until this run's.
            let took: u128 = loop {
                let l = line(&mut b.out, "GOT").await;
                let mut w = l.split(' ');
                if w.next().unwrap().parse::<usize>().unwrap() == i {
                    break w.next().unwrap().parse().unwrap();
                }
            };
            if i < WARM {
                continue;
            }
            got.push(Duration::from_nanos(took as u64));
            if traced {
                let mut ev: Vec<(u128, char, String)> =
                    [('A', a.dump().await), ('B', b.dump().await)]
                        .into_iter()
                        .flat_map(|(w, v)| {
                            v.into_iter()
                                .map(move |(t, tg, m)| (t, w, format!("{tg} {m}")))
                        })
                        .collect();
                ev.sort_by_key(|e| e.0);
                let r = Step {
                    i,
                    t0: put[0],
                    end: put[1],
                    got: put[0] + took,
                    ev,
                };
                if let (Some(f), Some(s)) = (
                    times(&r, 'B', "fetch_out").min(),
                    times(&r, 'B', "fetch_in").max(),
                ) {
                    pull.push(Duration::from_nanos(s.saturating_sub(f) as u64));
                }
                runs.push(r);
            }
        }
        c5[k] = Some((pct(&mut got, 0.5), pct(&mut got, 0.95)));
        if !traced {
            continue;
        }
        c5p[k] = (!pull.is_empty()).then(|| (pct(&mut pull, 0.5), pct(&mut pull, 0.95)));
        let (t, c) = report_timeline(label, &runs, &steps);
        text.push_str(&t);
        text.push('\n');
        counts.push_str(&c);
    }
    drop((a, b));
    (c5, c5p, text, counts)
}

/// The timeline table of one size, its fetch accounting, and the counts of rung 6 (as two strings).
fn report_timeline(
    label: &str,
    runs: &[Step],
    steps: &[(&str, fn(&Step) -> Option<u128>)],
) -> (String, String) {
    use std::fmt::Write;
    let (mut t, mut c) = (String::new(), String::new());
    let _ = writeln!(
        t,
        "### {label}: {} runs, ms after the put began\n",
        runs.len()
    );
    let _ = writeln!(
        t,
        "| step | p50 | p95 | step (p50 delta) | runs with it |\n|---|---|---|---|---|"
    );
    let mut before = 0.0;
    for (what, f) in steps {
        let mut v: Vec<Duration> = runs
            .iter()
            .filter_map(|r| f(r).map(|x| Duration::from_nanos(x.saturating_sub(r.t0) as u64)))
            .collect();
        if v.is_empty() {
            let _ = writeln!(t, "| {what} | - | - | - | 0 of {} |", runs.len());
            continue;
        }
        let (p50, p95) = (ms(pct(&mut v, 0.5)), ms(pct(&mut v, 0.95)));
        if what.starts_with('(') {
            let _ = writeln!(
                t,
                "| {what} | {p50:.3} | {p95:.3} | - | {} of {} |",
                v.len(),
                runs.len()
            );
        } else {
            let _ = writeln!(
                t,
                "| {what} | {p50:.3} | {p95:.3} | {:+.3} | {} of {} |",
                p50 - before,
                v.len(),
                runs.len()
            );
            before = p50;
        }
    }

    // The fetches of B: how many one new version takes, each timed (its Interest out to its Data in, by name).
    let mut per_run = Vec::new();
    let (mut all, mut again, mut misses) = (Vec::new(), 0usize, 0usize);
    let mut kinds: std::collections::BTreeMap<&str, usize> = Default::default();
    let mut verify = Vec::new();
    for r in runs {
        let outs: Vec<(u128, &str)> = texts(r, 'B', "fetch_out").collect();
        per_run.push(outs.len());
        let mut pending: std::collections::HashMap<&str, Vec<u128>> = Default::default();
        for (t, m) in &outs {
            let name = field(m, "name").unwrap_or("");
            *kinds.entry(kind(name)).or_default() += 1;
            pending.entry(name).or_default().push(*t);
        }
        for (t, m) in texts(r, 'B', "fetch_in") {
            if field(m, "expressed")
                .and_then(|e| e.parse::<u32>().ok())
                .unwrap_or(1)
                > 1
            {
                again += 1;
            }
            if let Some(o) = pending
                .get_mut(field(m, "name").unwrap_or(""))
                .and_then(|v| (!v.is_empty()).then(|| v.remove(0)))
            {
                all.push(Duration::from_nanos(t.saturating_sub(o) as u64));
            }
        }
        misses += texts(r, 'B', "fetch_miss").count();
        if let (Some(f), Some(l)) = (
            times(r, 'B', "verify_begin").min(),
            times(r, 'B', "verify_end").max(),
        ) {
            verify.push((
                Duration::from_nanos(l.saturating_sub(f) as u64),
                times(r, 'B', "verify_end").count(),
            ));
        }
    }
    per_run.sort();
    let _ = writeln!(
        t,
        "\nB's fetches for one new {label} version: p50 {} per put (min {}, max {}); by kind over all {} runs: {kinds:?}",
        per_run[per_run.len() / 2],
        per_run[0],
        per_run[per_run.len() - 1],
        runs.len()
    );
    if !all.is_empty() {
        let _ = writeln!(
            t,
            "\nEach fetch Interest out -> Data in: p50 {:.3} ms, p95 {:.3} ms, max {:.3} ms ({} fetches, {again} answered after a re-expression, {misses} missed).",
            ms(pct(&mut all, 0.5)),
            ms(pct(&mut all, 0.95)),
            ms(pct(&mut all, 1.0)),
            all.len()
        );
    }
    if !verify.is_empty() {
        let mut span: Vec<Duration> = verify.iter().map(|v| v.0).collect();
        let mut count: Vec<usize> = verify.iter().map(|v| v.1).collect();
        count.sort();
        let _ = writeln!(
            t,
            "B's verifications per put: p50 {}; first begin -> last end p50 {:.3} ms (they overlap, so this is a span, not a sum).",
            count[count.len() / 2],
            ms(pct(&mut span, 0.5))
        );
    }
    // A's flush rounds: the committer is one task, so each `flush_begin` pairs with the next `flush_end`.
    let (mut rounds, mut per_put) = (Vec::new(), Vec::new());
    for r in runs {
        let (begins, ends): (Vec<u128>, Vec<u128>) = (
            times(r, 'A', "flush_begin").collect(),
            times(r, 'A', "flush_end").collect(),
        );
        per_put.push(begins.len());
        rounds.extend(
            begins
                .iter()
                .zip(&ends)
                .map(|(b, e)| Duration::from_nanos(e.saturating_sub(*b) as u64)),
        );
    }
    if !rounds.is_empty() {
        per_put.sort();
        let _ = writeln!(
            t,
            "A's store flush (fsync) inside put->watch: p50 {:.3} ms, p95 {:.3} ms, max {:.3} ms over {} rounds, {} rounds per put (p50).",
            ms(pct(&mut rounds, 0.5)),
            ms(pct(&mut rounds, 0.95)),
            ms(pct(&mut rounds, 1.0)),
            rounds.len(),
            per_put[per_put.len() / 2]
        );
    }
    // One run's own sequence: the median run by its watch time.
    let mut by_got: Vec<&Step> = runs.iter().collect();
    by_got.sort_by_key(|r| r.got - r.t0);
    if let Some(r) = by_got.get(by_got.len() / 2) {
        let _ = writeln!(
            t,
            "\nThe median run (#{}, {:.3} ms), B's fetches in order, ms after the put began:\n",
            r.i,
            (r.got - r.t0) as f64 / 1e6
        );
        let _ = writeln!(
            t,
            "| at | what | name (tail) | answered after (ms) | Interests expressed |\n|---|---|---|---|---|"
        );
        let ins: Vec<(u128, &str)> = texts(r, 'B', "fetch_in").collect();
        let outs: Vec<(u128, &str)> = texts(r, 'B', "fetch_out").collect();
        // The sequence of a 1 MiB version is 280 chunk pieces: the first 14 and the last 3 are shown.
        let shown = |k: usize| outs.len() <= 24 || k < 14 || k + 3 >= outs.len();
        for (k, (at, m)) in outs.iter().enumerate() {
            if !shown(k) {
                if k == 14 {
                    let _ = writeln!(t, "| ... | {} more fetches | | | |", outs.len() - 17);
                }
                continue;
            }
            let name = field(m, "name").unwrap_or("");
            let inn = ins
                .iter()
                .find(|(t, x)| t >= at && field(x, "name") == Some(name));
            let _ = writeln!(
                t,
                "| {:.3} | {} | `{}` | {} | {} |",
                at.saturating_sub(r.t0) as f64 / 1e6,
                kind(name),
                tail(name),
                inn.map_or("-".into(), |(t, _)| format!(
                    "{:.3}",
                    t.saturating_sub(*at) as f64 / 1e6
                )),
                inn.and_then(|(_, x)| field(x, "expressed")).unwrap_or("-")
            );
        }
    }

    // Rung 6 for the put->watch: B's fetches asked again, and the link's drop notices (`face.quic`, rate limited).
    let drops: Vec<&str> = runs
        .iter()
        .flat_map(|r| {
            r.ev.iter()
                .filter(|e| e.2.starts_with("face.quic ") && e.2.contains("dropped"))
                .map(|e| e.2.as_str())
        })
        .collect();
    let cumulative = drops
        .iter()
        .filter_map(|d| field(d, "dropped").and_then(|x| x.parse::<u64>().ok()))
        .max()
        .unwrap_or(0);
    let slow = runs.iter().filter(|r| r.got - r.t0 > 150_000_000).count();
    let _ = writeln!(
        c,
        "- {label}: B's fetches answered after a re-expression {again} of {} ({misses} missed); `face.quic` drop notices {} (rate-limited; the link's own counter at its last notice {cumulative}); runs over 150 ms {slow} of {}",
        all.len(),
        drops.len(),
        runs.len()
    );
    (t, c)
}

/// What the durability barrier costs on this disk, measured on its own, in `data`: an fsync of a 4 KiB file, and the data layer's
/// store barrier (`DataStore::sync` of the fjall store the `Device` uses) after one 1 KiB insert, 200 each; then the flush rounds the
/// traced runs saw are in their timelines (`flush_begin` -> `flush_end`).
fn flush_cost(data: &Path) -> String {
    use std::io::{Seek, Write};
    let dir = data.join("flush");
    std::fs::create_dir_all(&dir).unwrap();
    let time = |mut f: Box<dyn FnMut()>| {
        let mut v: Vec<Duration> = (0..210)
            .map(|_| {
                let t = Instant::now();
                f();
                t.elapsed()
            })
            .skip(10)
            .collect();
        (
            ms(pct(&mut v, 0.5)),
            ms(pct(&mut v, 0.95)),
            ms(pct(&mut v, 1.0)),
        )
    };
    let mut file = std::fs::File::create(dir.join("file")).unwrap();
    let block = vec![7u8; 4096];
    let all = time(Box::new(move || {
        file.rewind().unwrap();
        file.write_all(&block).unwrap();
        file.sync_all().unwrap();
    }));
    let mut file = std::fs::File::create(dir.join("file-data")).unwrap();
    let block = vec![7u8; 4096];
    let dat = time(Box::new(move || {
        file.rewind().unwrap();
        file.write_all(&block).unwrap();
        file.sync_data().unwrap();
    }));
    let store = ndn_sync::store::BackendStore::open_fjall(dir.join("store")).unwrap();
    let wire = Bytes::from(vec![9u8; 1024]);
    let mut i = 0u64;
    let barrier = time(Box::new(move || {
        i += 1;
        store.insert(format!("/ladder/flush/{i}").parse().unwrap(), wire.clone());
        store.sync().unwrap();
    }));
    format!(
        "| barrier | p50 ms | p95 ms | max ms |\n|---|---|---|---|\n| fsync (`sync_all`) of a 4 KiB write | {:.3} | {:.3} | {:.3} |\n| `sync_data` of a 4 KiB write | {:.3} | {:.3} | {:.3} |\n| the data layer's store: `insert` of 1 KiB then `DataStore::sync` (fjall) | {:.3} | {:.3} | {:.3} |\n\nThe flush rounds of the data layer inside put->watch (`flush_begin` -> `flush_end`) are the timeline's step 'A: store flush begins' to 'ends'.\n",
        all.0, all.1, all.2, dat.0, dat.1, dat.2, barrier.0, barrier.1, barrier.2
    )
}
