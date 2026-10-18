//! One UDP socket for this device's QUIC links: it dials, and (when the
//! device listens) accepts, with this device's NDN key as its TLS identity.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use rustls::crypto::CryptoProvider;
use sha2::{Digest, Sha256};

use crate::key::{KeyFingerprint, LinkKeySource};
use crate::link::{Direction, Handshaken, LinkError};
use crate::message::CloseReason;
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
    /// Bounds on handshakes not yet admitted.
    pub limits: HandshakeLimits,
}

impl Default for LinkTransportConfig {
    fn default() -> Self {
        Self {
            keep_alive: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(30),
            handshake_timeout: Duration::from_secs(5),
            limits: HandshakeLimits::default(),
        }
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
    /// Refusals of one source address before it is refused outright…
    pub refusals_before_cooldown: u32,
    /// …for this long.
    pub cooldown: Duration,
}

impl Default for HandshakeLimits {
    fn default() -> Self {
        Self {
            max_in_flight: 64,
            max_in_flight_per_source: 4,
            refusals_before_cooldown: 8,
            cooldown: Duration::from_secs(60),
        }
    }
}

#[derive(Default)]
struct Source {
    in_flight: usize,
    refusals: u32,
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
        let mut sources = self.gate.sources.lock().unwrap_or_else(PoisonError::into_inner);
        let source = sources.entry(self.source).or_default();
        source.refusals += 1;
        if source.refusals >= self.gate.limits.refusals_before_cooldown {
            source.refusals = 0;
            source.cooldown_until = Some(Instant::now() + self.gate.limits.cooldown);
            tracing::warn!(
                target: "face.quic",
                source = %self.source,
                cooldown_secs = self.gate.limits.cooldown.as_secs(),
                "refusing link attempts from this address for a while: too many were refused"
            );
        }
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        self.gate.in_flight.fetch_sub(1, Ordering::SeqCst);
        let mut sources = self.gate.sources.lock().unwrap_or_else(PoisonError::into_inner);
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

/// A link endpoint: one UDP socket that dials links and, when bound as a
/// listener, accepts them.
pub struct LinkEndpoint {
    endpoint: quinn::Endpoint,
    key: Arc<dyn LinkKeySource>,
    transport: Arc<quinn::TransportConfig>,
    handshake_timeout: Duration,
    gate: Arc<Gate>,
    listening: bool,
}

impl LinkEndpoint {
    /// Bind `addr`. With `listen`, inbound links are accepted
    /// ([`accept`](Self::accept)); without, the socket only dials.
    pub fn bind(
        addr: SocketAddr,
        key: Arc<dyn LinkKeySource>,
        config: &LinkTransportConfig,
        listen: bool,
    ) -> Result<Self, LinkError> {
        // Fail at bind, with the reason, when this device has no usable key.
        let current = key.current().map_err(|e| LinkError::NoLinkKey(e.to_string()))?;
        let transport = Arc::new(transport_config(config));
        let server_config = listen
            .then(|| server_config(Arc::clone(&key), Arc::clone(&transport)))
            .transpose()?;
        let socket = std::net::UdpSocket::bind(addr)?;
        let endpoint = quinn::Endpoint::new(
            endpoint_config(&current),
            server_config,
            socket,
            Arc::new(quinn::TokioRuntime),
        )?;
        Ok(Self {
            endpoint,
            key,
            transport,
            handshake_timeout: config.handshake_timeout,
            gate: Gate::new(config.limits.clone()),
            listening: listen,
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
        let presented = Arc::new(Presented::default());
        let config = self.client_config(expected, Arc::clone(&presented))?;
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
        Handshaken::new(connection, Direction::Dialed, None, self.endpoint.local_addr().ok())
    }

    /// The next inbound link that completed its handshake. Attempts over the
    /// [`HandshakeLimits`] are refused before their handshake; a handshake
    /// that fails is logged and skipped. `None` once the endpoint is closed.
    pub async fn accept(&self) -> Option<Incoming> {
        loop {
            let incoming = self.endpoint.accept().await?;
            let remote = incoming.remote_address();
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
                    return Some(Incoming {
                        incoming,
                        permit,
                        local: self.endpoint.local_addr().ok(),
                    });
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
        self.endpoint.rebind(socket)
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
            .with_client_cert_resolver(Arc::new(KeyResolver(Arc::clone(&self.key))));
        tls.alpn_protocols = vec![ALPN_LINK.to_vec()];
        tls.enable_sni = false;
        // Every link proves its key with a full handshake.
        tls.resumption = rustls::client::Resumption::disabled();
        let quic = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
            .map_err(|e| LinkError::Tls(e.to_string()))?;
        let mut config = quinn::ClientConfig::new(Arc::new(quic));
        config.transport_config(Arc::clone(&self.transport));
        Ok(config)
    }
}

/// An inbound connection, before its handshake, under the endpoint's
/// [`HandshakeLimits`].
pub struct Incoming {
    incoming: quinn::Incoming,
    permit: Permit,
    local: Option<SocketAddr>,
}

impl Incoming {
    pub fn remote_address(&self) -> SocketAddr {
        self.incoming.remote_address()
    }

    /// Complete the handshake.
    pub async fn handshake(self) -> Result<Handshaken, LinkError> {
        let connecting = self
            .incoming
            .accept()
            .map_err(|e| LinkError::from_connection(e))?;
        match connecting.await {
            Ok(connection) => {
                Handshaken::new(connection, Direction::Accepted, Some(self.permit), self.local)
            }
            Err(e) => {
                self.permit.refused();
                Err(LinkError::from_connection(e))
            }
        }
    }
}

fn transport_config(config: &LinkTransportConfig) -> quinn::TransportConfig {
    let mut t = quinn::TransportConfig::default();
    t.keep_alive_interval(Some(config.keep_alive));
    t.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(config.idle_timeout).unwrap_or(quinn::VarInt::from_u32(30_000).into()),
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
