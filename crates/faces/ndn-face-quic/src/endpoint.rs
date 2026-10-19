//! One UDP socket for this device's QUIC links: it dials, and (when the
//! device listens) accepts, with this device's NDN key as its TLS identity.
//! The same socket sends and receives the probes of direct-path punches,
//! and a socket that does not listen accepts the direct paths of a punch
//! from the punched device's candidate addresses only, while that punch
//! runs.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use rustls::crypto::CryptoProvider;
use sha2::{Digest, Sha256};

use crate::key::{KeyFingerprint, LinkKey, LinkKeySource};
use crate::link::{Direction, Handshaken, LinkError};
use crate::message::{CloseReason, PathSession};
use crate::probe::{ProbeSocket, ProbeTap, ProbeWatch};
use crate::verify::{DialerKeyVerifier, KeyResolver, ListenerKeyVerifier, Presented};

/// ALPN of the link protocol. A listener speaking anything else (an older
/// stream-framed `ndn` QUIC face, an HTTP/3 server) fails the handshake.
pub const ALPN_LINK: &[u8] = b"ndn-link/1";

/// The TLS server name a dial sends. Nothing checks it: the listener is
/// identified by its key, not a host name, and SNI is not sent.
const SERVER_NAME: &str = "ndn-link";

/// Transport settings of every link of an endpoint.
#[derive(Clone, Debug)]
pub struct LinkTransportConfig {
    /// How often an idle link sends a keep-alive, so NAT and firewall
    /// bindings on the path stay open (most expire UDP state after 30 s or
    /// more).
    pub keep_alive: Duration,
    /// How long a link may hear nothing before it counts as lost.
    pub idle_timeout: Duration,
    /// How long a dial waits for the handshake. An address where nothing
    /// listens answers nothing (QUIC ignores ICMP), so without it a dial
    /// would wait out the idle timeout.
    pub handshake_timeout: Duration,
    /// Keep-alive of a direct path this device dials. Shorter than
    /// `keep_alive`: a direct path crosses NATs that keep a mapping only
    /// while packets flow, and its loss is noticed sooner, so traffic falls
    /// back to the relay sooner.
    pub direct_keep_alive: Duration,
    /// Idle timeout a dialled direct path offers; a connection takes the
    /// smaller of both sides' offers, so it applies to both sides.
    pub direct_idle_timeout: Duration,
    /// Bounds on handshakes not yet admitted.
    pub limits: HandshakeLimits,
}

impl Default for LinkTransportConfig {
    fn default() -> Self {
        Self {
            keep_alive: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(30),
            handshake_timeout: Duration::from_secs(5),
            direct_keep_alive: Duration::from_secs(2),
            direct_idle_timeout: Duration::from_secs(8),
            limits: HandshakeLimits::default(),
        }
    }
}

/// Safe bounds of a link's keep-alive: under the floor, keep-alives cost
/// battery and data for nothing; over the ceiling, NAT bindings expire.
const KEEP_ALIVE_MIN: Duration = Duration::from_secs(2);
const KEEP_ALIVE_MAX: Duration = Duration::from_secs(60);
/// The idle timeout outlasts this many keep-alives, so a lost one or two
/// do not count the link as lost.
const IDLE_KEEP_ALIVES: u32 = 3;
const IDLE_TIMEOUT_MAX: Duration = Duration::from_secs(600);

impl LinkTransportConfig {
    /// The default settings with this keep-alive and idle timeout, if they
    /// are within safe bounds: a keep-alive of 2–60 s, an idle timeout of at
    /// least 3 keep-alives and at most 600 s. A longer keep-alive saves
    /// battery and data on a phone; a shorter one keeps a link through NATs
    /// that forget sooner. The refusal says which bound and why.
    pub fn bounded(keep_alive: Duration, idle_timeout: Duration) -> Result<Self, String> {
        let secs = |d: Duration| d.as_secs_f64();
        if keep_alive < KEEP_ALIVE_MIN {
            return Err(format!(
                "a keep-alive every {} s is under the {} s floor: each keep-alive wakes the radio \
                 and costs battery and data, and no NAT needs them that often; use {}–{} s",
                secs(keep_alive),
                KEEP_ALIVE_MIN.as_secs(),
                KEEP_ALIVE_MIN.as_secs(),
                KEEP_ALIVE_MAX.as_secs()
            ));
        }
        if keep_alive > KEEP_ALIVE_MAX {
            return Err(format!(
                "a keep-alive every {} s is over the {} s ceiling: most NATs drop a UDP binding \
                 after 30 s or more without traffic, some sooner, and a link whose binding is gone \
                 receives nothing until it is dialled again; use {}–{} s (a longer keep-alive \
                 saves battery and data where the NATs on the path allow it)",
                secs(keep_alive),
                KEEP_ALIVE_MAX.as_secs(),
                KEEP_ALIVE_MIN.as_secs(),
                KEEP_ALIVE_MAX.as_secs()
            ));
        }
        let floor = keep_alive * IDLE_KEEP_ALIVES;
        if idle_timeout < floor {
            return Err(format!(
                "an idle timeout of {} s is under {IDLE_KEEP_ALIVES} keep-alives ({} s): a lost \
                 keep-alive or two would count a working link as lost; raise it to at least {} s \
                 or shorten the keep-alive",
                secs(idle_timeout),
                secs(floor),
                secs(floor)
            ));
        }
        if idle_timeout > IDLE_TIMEOUT_MAX {
            return Err(format!(
                "an idle timeout of {} s is over the {} s ceiling: a link whose path broke would \
                 count as up that long, and traffic sent over it would be lost meanwhile; use at \
                 most {} s",
                secs(idle_timeout),
                IDLE_TIMEOUT_MAX.as_secs(),
                IDLE_TIMEOUT_MAX.as_secs()
            ));
        }
        Ok(Self {
            keep_alive,
            idle_timeout,
            ..Self::default()
        })
    }
}

/// Bounds on inbound connections that have not been admitted as links: an
/// unauthenticated attempt costs a handshake, so their number is capped in
/// total and per source address, and a source refused again and again is
/// refused outright for a while.
#[derive(Clone, Debug)]
pub struct HandshakeLimits {
    /// Inbound connections in their handshake or admission at once.
    pub max_in_flight: usize,
    /// Of those, from one source address.
    pub max_in_flight_per_source: usize,
    /// Refusals of one source address within `refusal_window` before it is
    /// refused outright…
    pub refusals_before_cooldown: u32,
    /// …for this long.
    pub cooldown: Duration,
    /// Refusals older than this are forgotten: the count starts again at
    /// the first refusal after the window of the previous first one ends.
    pub refusal_window: Duration,
}

impl Default for HandshakeLimits {
    fn default() -> Self {
        Self {
            max_in_flight: 64,
            max_in_flight_per_source: 4,
            refusals_before_cooldown: 8,
            cooldown: Duration::from_secs(60),
            refusal_window: Duration::from_secs(60),
        }
    }
}

#[derive(Default)]
struct Source {
    in_flight: usize,
    refusals: u32,
    /// When the first of `refusals` was counted.
    window_start: Option<Instant>,
    cooldown_until: Option<Instant>,
}

pub(crate) struct Gate {
    limits: HandshakeLimits,
    in_flight: AtomicUsize,
    sources: Mutex<HashMap<IpAddr, Source>>,
}

/// One inbound connection's place under the [`HandshakeLimits`], held until
/// the link is admitted or refused.
pub(crate) struct Permit {
    gate: Arc<Gate>,
    source: IpAddr,
}

impl Permit {
    /// The link was refused: count it against the source.
    pub(crate) fn refused(&self) {
        self.gate.refused(self.source, Instant::now());
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        self.gate.in_flight.fetch_sub(1, Ordering::SeqCst);
        let mut sources = self
            .gate
            .sources
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(source) = sources.get_mut(&self.source) {
            source.in_flight = source.in_flight.saturating_sub(1);
            if source.in_flight == 0 && source.refusals == 0 && source.cooldown_until.is_none() {
                sources.remove(&self.source);
            }
        }
    }
}

impl Gate {
    fn new(limits: HandshakeLimits) -> Arc<Self> {
        Arc::new(Self {
            limits,
            in_flight: AtomicUsize::new(0),
            sources: Mutex::new(HashMap::new()),
        })
    }

    /// Count a refusal of `ip` at `now`; at `refusals_before_cooldown` within
    /// `refusal_window`, refuse that source outright for `cooldown`.
    fn refused(&self, ip: IpAddr, now: Instant) {
        let limits = &self.limits;
        let mut sources = self.sources.lock().unwrap_or_else(PoisonError::into_inner);
        let source = sources.entry(ip).or_default();
        if source
            .window_start
            .is_none_or(|start| now.saturating_duration_since(start) >= limits.refusal_window)
        {
            source.refusals = 0;
            source.window_start = Some(now);
        }
        source.refusals += 1;
        if source.refusals >= limits.refusals_before_cooldown {
            source.refusals = 0;
            source.window_start = None;
            source.cooldown_until = Some(now + limits.cooldown);
            tracing::warn!(
                target: "face.quic",
                source = %ip,
                cooldown_secs = limits.cooldown.as_secs(),
                "refusing link attempts from this address for a while: too many were refused"
            );
        }
    }

    fn admit(self: &Arc<Self>, ip: IpAddr) -> Result<Permit, &'static str> {
        let now = Instant::now();
        let mut sources = self.sources.lock().unwrap_or_else(PoisonError::into_inner);
        if sources.len() > 4096 {
            sources.retain(|_, s| s.in_flight > 0 || s.cooldown_until.is_some_and(|t| t > now));
        }
        let source = sources.entry(ip).or_default();
        if let Some(until) = source.cooldown_until {
            if until > now {
                return Err("too many of its link attempts were refused recently");
            }
            source.cooldown_until = None;
        }
        if source.in_flight >= self.limits.max_in_flight_per_source {
            return Err("too many of its link attempts are in progress");
        }
        if self.in_flight.load(Ordering::SeqCst) >= self.limits.max_in_flight {
            return Err("this device has too many link attempts in progress");
        }
        source.in_flight += 1;
        self.in_flight.fetch_add(1, Ordering::SeqCst);
        Ok(Permit {
            gate: Arc::clone(self),
            source: ip,
        })
    }

    fn busy(&self) -> bool {
        self.in_flight.load(Ordering::SeqCst) * 2 >= self.limits.max_in_flight
    }
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Which addresses a socket that does not listen accepts direct paths from,
/// while punches run: each address with the number of punches expecting it.
#[derive(Default)]
struct Expected {
    from: HashMap<SocketAddr, usize>,
    windows: usize,
}

/// A link endpoint: one UDP socket that dials links and, when bound as a
/// listener, accepts them.
pub struct LinkEndpoint {
    endpoint: quinn::Endpoint,
    socket: Mutex<Arc<ProbeSocket>>,
    probes: Arc<ProbeTap>,
    key: Arc<dyn LinkKeySource>,
    transport: Arc<quinn::TransportConfig>,
    direct_transport: Arc<quinn::TransportConfig>,
    handshake_timeout: Duration,
    gate: Arc<Gate>,
    listening: bool,
    /// The server side of a direct path: a socket that does not listen
    /// accepts with it only while an [`InboundWindow`] is open.
    direct_server: quinn::ServerConfig,
    expected: Arc<Mutex<Expected>>,
}

impl LinkEndpoint {
    /// Bind `addr`: [`from_socket`](Self::from_socket) with a socket bound
    /// there.
    pub fn bind(
        addr: SocketAddr,
        key: Arc<dyn LinkKeySource>,
        config: &LinkTransportConfig,
        listen: bool,
    ) -> Result<Self, LinkError> {
        Self::from_socket(std::net::UdpSocket::bind(addr)?, key, config, listen)
    }

    /// Use `socket`, bound by the caller — to a network interface or a
    /// network (a phone's Wi-Fi or cellular network), say. With `listen`,
    /// inbound links are accepted ([`accept`](Self::accept)); without, the
    /// socket dials, and accepts only the direct paths of the punches it
    /// runs ([`allow_inbound`](Self::allow_inbound)). The socket is made
    /// non-blocking.
    pub fn from_socket(
        socket: std::net::UdpSocket,
        key: Arc<dyn LinkKeySource>,
        config: &LinkTransportConfig,
        listen: bool,
    ) -> Result<Self, LinkError> {
        // Fail at bind, with the reason, when this device has no usable key.
        let current = key
            .current()
            .map_err(|e| LinkError::NoLinkKey(e.to_string()))?;
        let transport = Arc::new(transport_config(config.keep_alive, config.idle_timeout));
        let direct_transport = Arc::new(transport_config(
            config.direct_keep_alive,
            config.direct_idle_timeout,
        ));
        let server = listen
            .then(|| server_config(Arc::clone(&key), Arc::clone(&transport)))
            .transpose()?;
        let direct_server = server_config(Arc::clone(&key), Arc::clone(&direct_transport))?;
        let runtime: Arc<dyn quinn::Runtime> = Arc::new(quinn::TokioRuntime);
        let probes = Arc::new(ProbeTap::default());
        // quinn's socket state sets the socket non-blocking.
        let socket = Arc::new(ProbeSocket::new(
            runtime.wrap_udp_socket(socket)?,
            Arc::clone(&probes),
        ));
        let endpoint = quinn::Endpoint::new_with_abstract_socket(
            endpoint_config(&current),
            server,
            Arc::clone(&socket) as Arc<dyn quinn::AsyncUdpSocket>,
            runtime,
        )?;
        Ok(Self {
            endpoint,
            socket: Mutex::new(socket),
            probes,
            key,
            transport,
            direct_transport,
            handshake_timeout: config.handshake_timeout,
            gate: Gate::new(config.limits.clone()),
            listening: listen,
            direct_server,
            expected: Arc::new(Mutex::new(Expected::default())),
        })
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.endpoint.local_addr()
    }

    pub fn is_listening(&self) -> bool {
        self.listening
    }

    /// Dial `addr`. With `expected`, the handshake fails unless the listener
    /// presents exactly that key.
    pub async fn connect(
        &self,
        addr: SocketAddr,
        expected: Option<KeyFingerprint>,
    ) -> Result<Handshaken, LinkError> {
        self.connect_with(addr, expected, Arc::clone(&self.transport))
            .await
    }

    /// Dial a direct path to `addr`, a candidate address of the device with
    /// key `expected`, whose punch opened the way: the handshake fails
    /// unless that device answers, and the path keeps itself alive with
    /// the direct-path keep-alive and idle timeout.
    pub async fn connect_direct(
        &self,
        addr: SocketAddr,
        expected: KeyFingerprint,
    ) -> Result<Handshaken, LinkError> {
        self.connect_with(addr, Some(expected), Arc::clone(&self.direct_transport))
            .await
    }

    async fn connect_with(
        &self,
        addr: SocketAddr,
        expected: Option<KeyFingerprint>,
        transport: Arc<quinn::TransportConfig>,
    ) -> Result<Handshaken, LinkError> {
        let presented = Arc::new(Presented::default());
        // The key this connection presents, fixed for its handshake: the
        // memberships its hello shows are bound to it.
        let key = self
            .key
            .current()
            .map_err(|e| LinkError::NoLinkKey(e.to_string()))?;
        let config = self.client_config(expected, Arc::clone(&presented), transport, &key)?;
        let connecting = self
            .endpoint
            .connect_with(config, addr, SERVER_NAME)
            .map_err(|e| LinkError::Connect(e.to_string()))?;
        let Ok(handshake) = tokio::time::timeout(self.handshake_timeout, connecting).await else {
            return Err(LinkError::Connect(format!(
                "no answer from {addr} within {} s (is the device running and reachable?)",
                self.handshake_timeout.as_secs()
            )));
        };
        let connection = match handshake {
            Ok(c) => c,
            Err(e) => {
                return Err(match (expected, presented.get()) {
                    (Some(expected), Some(key)) if key.fingerprint() != expected => {
                        LinkError::UnexpectedKey {
                            expected,
                            presented: key.fingerprint(),
                        }
                    }
                    _ => LinkError::from_connection(e),
                });
            }
        };
        Handshaken::new(
            connection,
            Direction::Dialed,
            None,
            self.endpoint.clone(),
            key,
        )
    }

    /// Send the probe of a punch's `session` to `to` from this socket.
    /// Delivery is best effort, like any UDP datagram's.
    pub async fn send_probe(&self, to: SocketAddr, session: &PathSession) -> std::io::Result<()> {
        let socket = Arc::clone(&self.socket.lock().unwrap_or_else(PoisonError::into_inner));
        socket.send_probe(to, session).await
    }

    /// The probes of `session` this socket receives, until the watch is
    /// dropped. Probes of sessions nobody watches are dropped.
    pub fn watch_probes(&self, session: PathSession) -> ProbeWatch {
        self.probes.watch(session)
    }

    /// Accept the direct paths of a punch from `from` (the punched device's
    /// candidate addresses) while the returned window is open. A socket
    /// that listens accepts every link anyway; one that does not answers
    /// nothing else, not even a refusal.
    pub fn allow_inbound(&self, from: &[SocketAddr]) -> InboundWindow {
        let from: Vec<SocketAddr> = from.iter().map(|a| canonical(*a)).collect();
        let mut expected = self.expected.lock().unwrap_or_else(PoisonError::into_inner);
        for addr in &from {
            *expected.from.entry(*addr).or_default() += 1;
        }
        expected.windows += 1;
        if !self.listening && expected.windows == 1 {
            self.endpoint
                .set_server_config(Some(self.direct_server.clone()));
        }
        InboundWindow {
            endpoint: self.endpoint.clone(),
            expected: Arc::clone(&self.expected),
            listening: self.listening,
            from,
        }
    }

    /// Whether a socket that does not listen takes a connection from
    /// `remote` now: a punch expects it.
    fn expects(&self, remote: SocketAddr) -> bool {
        self.expected
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .from
            .contains_key(&canonical(remote))
    }

    /// The next inbound link that completed its handshake. Attempts over the
    /// [`HandshakeLimits`] are refused before their handshake; a handshake
    /// that fails is logged and skipped. `None` once the endpoint is closed.
    pub async fn accept(&self) -> Option<Incoming> {
        loop {
            let incoming = self.endpoint.accept().await?;
            let remote = incoming.remote_address();
            let punched = self.expects(remote);
            if !self.listening && !punched {
                // Not listening: as if nothing were here.
                incoming.ignore();
                continue;
            }
            // Under load, make a source prove its address (a Retry round
            // trip) before it costs a handshake.
            if self.gate.busy() && !incoming.remote_address_validated() && incoming.may_retry() {
                if let Err(e) = incoming.retry() {
                    tracing::debug!(target: "face.quic", source = %remote, error = %e, "retry failed");
                }
                continue;
            }
            match self.gate.admit(remote.ip()) {
                Ok(permit) => {
                    // The key this connection presents, fixed for its
                    // handshake: the memberships its hello shows are bound
                    // to it. A punch expects it: the connection is kept
                    // alive as a direct path.
                    let transport = if punched {
                        &self.direct_transport
                    } else {
                        &self.transport
                    };
                    let fixed = self
                        .key
                        .current()
                        .map_err(|e| LinkError::NoLinkKey(e.to_string()))
                        .and_then(|key| {
                            Ok((
                                server_config(Arc::new(key.clone()), Arc::clone(transport))?,
                                key,
                            ))
                        });
                    match fixed {
                        Ok((server, key)) => {
                            return Some(Incoming {
                                incoming,
                                permit,
                                endpoint: self.endpoint.clone(),
                                server: Arc::new(server),
                                key,
                            });
                        }
                        Err(e) => {
                            tracing::warn!(target: "face.quic", source = %remote, error = %e, "cannot take a link");
                            incoming.refuse();
                        }
                    }
                }
                Err(why) => {
                    tracing::info!(
                        target: "face.quic",
                        source = %remote,
                        reason = why,
                        "refused a link attempt before its handshake"
                    );
                    incoming.refuse();
                }
            }
        }
    }

    /// Move the endpoint to another socket (an address change of this
    /// device): its links migrate with it.
    pub fn rebind(&self, socket: std::net::UdpSocket) -> std::io::Result<()> {
        let wrapped = Arc::new(ProbeSocket::new(
            quinn::Runtime::wrap_udp_socket(&quinn::TokioRuntime, socket)?,
            Arc::clone(&self.probes),
        ));
        self.endpoint
            .rebind_abstract(Arc::clone(&wrapped) as Arc<dyn quinn::AsyncUdpSocket>)?;
        *self.socket.lock().unwrap_or_else(PoisonError::into_inner) = wrapped;
        Ok(())
    }

    /// Close every link with `reason` and wait (up to `grace`) until the
    /// peers were told.
    pub async fn close(&self, reason: CloseReason, text: &str, grace: Duration) {
        self.endpoint
            .close(quinn::VarInt::from_u32(reason.code()), text.as_bytes());
        let _ = tokio::time::timeout(grace, self.endpoint.wait_idle()).await;
    }

    fn client_config(
        &self,
        expected: Option<KeyFingerprint>,
        presented: Arc<Presented>,
        transport: Arc<quinn::TransportConfig>,
        key: &LinkKey,
    ) -> Result<quinn::ClientConfig, LinkError> {
        let provider = provider();
        let mut tls = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| LinkError::Tls(e.to_string()))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(ListenerKeyVerifier {
                expected,
                presented,
                provider,
            }))
            .with_client_cert_resolver(Arc::new(KeyResolver(Arc::new(key.clone()))));
        tls.alpn_protocols = vec![ALPN_LINK.to_vec()];
        tls.enable_sni = false;
        // Every link proves its key with a full handshake.
        tls.resumption = rustls::client::Resumption::disabled();
        let quic = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
            .map_err(|e| LinkError::Tls(e.to_string()))?;
        let mut config = quinn::ClientConfig::new(Arc::new(quic));
        config.transport_config(transport);
        Ok(config)
    }
}

/// An address as sockets compare it: an IPv4-mapped IPv6 address as IPv4.
fn canonical(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(addr.ip().to_canonical(), addr.port())
}

/// A punch's permission for its direct paths to come in
/// ([`LinkEndpoint::allow_inbound`]); closed when dropped.
pub struct InboundWindow {
    endpoint: quinn::Endpoint,
    expected: Arc<Mutex<Expected>>,
    listening: bool,
    from: Vec<SocketAddr>,
}

impl Drop for InboundWindow {
    fn drop(&mut self) {
        let mut expected = self.expected.lock().unwrap_or_else(PoisonError::into_inner);
        for addr in &self.from {
            if let Some(n) = expected.from.get_mut(addr) {
                *n -= 1;
                if *n == 0 {
                    expected.from.remove(addr);
                }
            }
        }
        expected.windows -= 1;
        if !self.listening && expected.windows == 0 {
            self.endpoint.set_server_config(None);
        }
    }
}

/// An inbound connection, before its handshake, under the endpoint's
/// [`HandshakeLimits`].
pub struct Incoming {
    incoming: quinn::Incoming,
    permit: Permit,
    endpoint: quinn::Endpoint,
    server: Arc<quinn::ServerConfig>,
    /// The key this connection presents.
    key: LinkKey,
}

impl Incoming {
    pub fn remote_address(&self) -> SocketAddr {
        self.incoming.remote_address()
    }

    /// Complete the handshake.
    pub async fn handshake(self) -> Result<Handshaken, LinkError> {
        let accepted = self.incoming.accept_with(self.server);
        let connecting = accepted.map_err(LinkError::from_connection)?;
        match connecting.await {
            Ok(connection) => Handshaken::new(
                connection,
                Direction::Accepted,
                Some(self.permit),
                self.endpoint,
                self.key,
            ),
            Err(e) => {
                self.permit.refused();
                Err(LinkError::from_connection(e))
            }
        }
    }
}

fn transport_config(keep_alive: Duration, idle_timeout: Duration) -> quinn::TransportConfig {
    let mut t = quinn::TransportConfig::default();
    t.keep_alive_interval(Some(keep_alive));
    t.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(idle_timeout)
            .unwrap_or(quinn::VarInt::from_u32(30_000).into()),
    ));
    // NDN packets ride datagrams; the one bidirectional stream is the link's
    // control stream, and no peer needs more.
    t.max_concurrent_bidi_streams(quinn::VarInt::from_u32(1));
    t.max_concurrent_uni_streams(quinn::VarInt::from_u32(0));
    t.datagram_receive_buffer_size(Some(4 * 1024 * 1024));
    t.datagram_send_buffer_size(4 * 1024 * 1024);
    t
}

fn server_config(
    key: Arc<dyn LinkKeySource>,
    transport: Arc<quinn::TransportConfig>,
) -> Result<quinn::ServerConfig, LinkError> {
    let provider = provider();
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| LinkError::Tls(e.to_string()))?
        .with_client_cert_verifier(Arc::new(DialerKeyVerifier { provider }))
        .with_cert_resolver(Arc::new(KeyResolver(key)));
    tls.alpn_protocols = vec![ALPN_LINK.to_vec()];
    // No resumption and no 0-RTT: every link proves its key with a full
    // handshake.
    tls.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    tls.send_tls13_tickets = 0;
    tls.max_early_data_size = 0;
    let quic = quinn::crypto::rustls::QuicServerConfig::try_from(tls)
        .map_err(|e| LinkError::Tls(e.to_string()))?;
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(quic));
    config.transport_config(transport);
    Ok(config)
}

/// The stateless-reset key, derived from this device's key so it is the
/// same after a restart: a peer still holding a link from before a crash is
/// told at its next packet that the link is gone (a QUIC stateless reset),
/// and dials again at once instead of waiting out the idle timeout. Both
/// device key types sign deterministically (Ed25519; P-256 per RFC 6979);
/// the label starts with a byte no NDN packet or TLS signature input starts
/// with.
fn endpoint_config(key: &crate::key::LinkKey) -> quinn::EndpointConfig {
    let label = b"ndn-link stateless reset key v1";
    match key.sign_label(label) {
        Some(signature) => {
            let seed = Sha256::new()
                .chain_update(label)
                .chain_update(&signature)
                .finalize();
            quinn::EndpointConfig::new(Arc::new(ring::hmac::Key::new(
                ring::hmac::HMAC_SHA256,
                &seed,
            )))
        }
        None => quinn::EndpointConfig::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cooling(gate: &Gate, ip: IpAddr) -> bool {
        let sources = gate.sources.lock().unwrap_or_else(PoisonError::into_inner);
        sources.get(&ip).is_some_and(|s| s.cooldown_until.is_some())
    }

    #[test]
    fn refusals_spread_beyond_the_window_never_cool_a_source_down() {
        let gate = Gate::new(HandshakeLimits::default());
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let t0 = Instant::now();
        // 7 refusals, then the window passes: the count starts over.
        for _ in 0..7 {
            gate.refused(ip, t0);
        }
        let later = t0 + gate.limits.refusal_window;
        for _ in 0..7 {
            gate.refused(ip, later);
        }
        assert!(
            !cooling(&gate, ip),
            "refusals older than the window are forgotten"
        );
        gate.refused(ip, later + Duration::from_secs(1));
        assert!(
            cooling(&gate, ip),
            "8 refusals within the window cool the source down"
        );
    }

    #[test]
    fn transport_settings_stay_within_nat_safe_bounds() {
        let s = Duration::from_secs;
        assert!(LinkTransportConfig::bounded(s(10), s(30)).is_ok());
        assert!(LinkTransportConfig::bounded(s(2), s(6)).is_ok());
        assert!(LinkTransportConfig::bounded(s(60), s(600)).is_ok());
        for (keep_alive, idle) in [
            (Duration::from_millis(1500), s(30)),
            (s(61), s(600)),
            (s(10), s(29)),
            (s(10), s(601)),
        ] {
            assert!(
                LinkTransportConfig::bounded(keep_alive, idle).is_err(),
                "{keep_alive:?}, {idle:?}"
            );
        }
    }
}
