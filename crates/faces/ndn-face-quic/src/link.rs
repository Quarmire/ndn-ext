//! A link after its handshake: the hello exchange, the admission verdicts,
//! and the face it becomes.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use bytes::Bytes;
use ndn_packet::Name;
use quinn::{ConnectionError, SendDatagramError};
use tracing::trace;

use ndn_transport::{FaceError, FaceId, FaceKind, Transport, ip_face_uri};

use crate::endpoint::Permit;
use crate::key::{KeyFingerprint, LinkKey, PeerKey};
use crate::membership::{ChannelBinding, MEMBERSHIP_EXPORTER_LABEL};
use crate::message::{
    CloseReason, LINK_HELLO, LINK_VERDICT, LinkHello, LinkVerdict, MAX_MESSAGE, OBSERVED_ADDRESS, PRESENCE,
    Presence, REACHABILITY, Reachability, WAKE_TOKEN_MAX, decode_udp_address, encode_observed_address, skippable,
    split_tlv,
};
use crate::scope::{Judged, LinkScope, ScopeState, nack_for};

/// A datagram payload every QUIC path carries: QUIC packets of 1200 bytes
/// (RFC 9000 §14) less packet and frame overhead. Used only if the
/// connection cannot report its current datagram size.
pub const DATAGRAM_FLOOR: usize = 1100;

/// Which side opened the link.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    Dialed,
    Accepted,
}

/// Why a link did not come up, or ended.
#[derive(Debug, thiserror::Error)]
pub enum LinkError {
    #[error("this device has no usable link key: {0}")]
    NoLinkKey(String),
    #[error("tls: {0}")]
    Tls(String),
    #[error("{0}")]
    Connect(String),
    #[error("the device there presents key {presented}, not the expected fingerprint {expected}")]
    UnexpectedKey {
        expected: KeyFingerprint,
        presented: KeyFingerprint,
    },
    /// The other device refused or closed the link, with a reason.
    #[error("the other device closed the link: {text}")]
    Refused {
        reason: Option<CloseReason>,
        text: String,
    },
    /// This device refused or closed the link, with a reason (already told
    /// to the other device).
    #[error("this device closed the link: {text}")]
    RefusedHere { reason: CloseReason, text: String },
    #[error("the link messages were malformed: {0}")]
    Protocol(String),
    #[error("the other device sent no link message in time")]
    Timeout,
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

impl LinkError {
    pub(crate) fn from_connection(e: ConnectionError) -> Self {
        match e {
            ConnectionError::ApplicationClosed(close) => {
                let reason = CloseReason::from_code(close.error_code.into_inner());
                let text = String::from_utf8_lossy(&close.reason).into_owned();
                Self::Refused { reason, text }
            }
            ConnectionError::ConnectionClosed(close)
                if close.error_code == quinn::TransportErrorCode::CONNECTION_REFUSED =>
            {
                Self::Refused {
                    reason: Some(CloseReason::Busy),
                    text: "the device there refuses link attempts from this address for now \
                           (too many at once, or too many refused)"
                        .into(),
                }
            }
            ConnectionError::TimedOut => Self::Connect(
                "the other device stopped answering (it went away, or the path to it broke)"
                    .into(),
            ),
            ConnectionError::LocallyClosed => Self::Connect("this device closed the link".into()),
            other => Self::Connect(other.to_string()),
        }
    }

    /// Whether dialling again later, with nothing changed, may succeed.
    pub fn is_transient(&self) -> bool {
        match self {
            Self::Refused { reason, .. } => reason.is_none_or(|r| r.is_transient()),
            Self::RefusedHere { reason, .. } => reason.is_transient(),
            Self::UnexpectedKey { .. } | Self::NoLinkKey(_) | Self::Tls(_) => false,
            _ => true,
        }
    }
}

/// A connection whose TLS handshake proved the peer holds [`peer_key`]
/// (Self::peer_key), not yet admitted as a link.
pub struct Handshaken {
    connection: quinn::Connection,
    peer: PeerKey,
    direction: Direction,
    permit: Option<Permit>,
    /// The endpoint the connection runs on: its socket's address is this
    /// side's, and changes when the endpoint is rebound.
    endpoint: quinn::Endpoint,
    control: Option<(quinn::SendStream, quinn::RecvStream)>,
    /// The key this side presented in the handshake.
    local: LinkKey,
}

impl Handshaken {
    pub(crate) fn new(
        connection: quinn::Connection,
        direction: Direction,
        permit: Option<Permit>,
        endpoint: quinn::Endpoint,
        local: LinkKey,
    ) -> Result<Self, LinkError> {
        let peer = connection
            .peer_identity()
            .and_then(|id| id.downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>().ok())
            .and_then(|certs| certs.first().map(|c| PeerKey::from_spki(c.as_ref())))
            .ok_or_else(|| LinkError::Protocol("the handshake carried no peer key".into()))?
            .map_err(|e| LinkError::Protocol(e.to_string()))?;
        Ok(Self {
            connection,
            peer,
            direction,
            permit,
            endpoint,
            control: None,
            local,
        })
    }

    pub fn peer_key(&self) -> &PeerKey {
        &self.peer
    }

    /// The key this side presented in the handshake: the link key the
    /// memberships of this side's hello are bound to (a key the device
    /// switched to since applies to its next connection).
    pub fn local_key(&self) -> &LinkKey {
        &self.local
    }

    pub fn direction(&self) -> Direction {
        self.direction
    }

    pub fn remote_address(&self) -> SocketAddr {
        self.connection.remote_address()
    }

    /// The address of this side's socket now: after a rebind (this device
    /// moved), the new one.
    pub fn local_address(&self) -> Option<SocketAddr> {
        self.endpoint.local_addr().ok()
    }

    /// The value this connection's [`Membership`](crate::Membership)
    /// bindings are bound to: 32 bytes of the TLS exporter (RFC 8446 §7.5)
    /// with label [`MEMBERSHIP_EXPORTER_LABEL`](crate::MEMBERSHIP_EXPORTER_LABEL)
    /// and an empty context. Both sides of this connection compute the
    /// same value, and no other connection has it.
    pub fn channel_binding(&self) -> Result<ChannelBinding, LinkError> {
        let mut out = [0u8; 32];
        self.connection
            .export_keying_material(&mut out, MEMBERSHIP_EXPORTER_LABEL, &[])
            .map_err(|_| LinkError::Tls("the TLS exporter of the link is not available".into()))?;
        Ok(out)
    }

    /// Send `ours` and receive the peer's hello, within `deadline`. The
    /// dialer speaks first.
    pub async fn exchange_hello(
        &mut self,
        ours: &LinkHello,
        deadline: Duration,
    ) -> Result<LinkHello, LinkError> {
        let wire = ours.encode();
        let exchange = async {
            let (mut send, mut recv) = match self.direction {
                Direction::Dialed => {
                    let (mut send, recv) =
                        self.connection.open_bi().await.map_err(LinkError::from_connection)?;
                    write(&mut send, &self.connection, &wire).await?;
                    (send, recv)
                }
                Direction::Accepted => {
                    self.connection.accept_bi().await.map_err(LinkError::from_connection)?
                }
            };
            let theirs = read_message(&mut recv, &self.connection, LINK_HELLO).await?;
            if self.direction == Direction::Accepted {
                write(&mut send, &self.connection, &wire).await?;
            }
            let hello = LinkHello::decode(&theirs).map_err(LinkError::Protocol)?;
            Ok::<_, LinkError>((hello, send, recv))
        };
        let (hello, send, recv) = match tokio::time::timeout(deadline, exchange).await {
            Ok(Ok(exchanged)) => exchanged,
            Ok(Err(e)) => return Err(self.fail(e, deadline)),
            Err(_) => return Err(self.fail(LinkError::Timeout, deadline)),
        };
        self.control = Some((send, recv));
        Ok(hello)
    }

    /// Admit the link: tell the peer (`admission.verdict`), and wait (up to
    /// `deadline`) for it to admit the link too. The face is `id`; NDN
    /// packets flow from here on, within `admission.scope` when set.
    pub async fn admit(
        mut self,
        id: FaceId,
        deadline: Duration,
        admission: Admission,
    ) -> Result<Link, LinkError> {
        if self.connection.max_datagram_size().is_none() {
            let text = "the other device does not support QUIC datagrams, which links carry \
                        NDN packets in";
            return Err(self.fail(LinkError::Protocol(text.into()), deadline));
        }
        let (mut send, mut recv) = self
            .control
            .take()
            .ok_or_else(|| LinkError::Protocol("no hello was exchanged".into()))?;
        let connection = self.connection.clone();
        let ours = admission.verdict.encode();
        let verdicts = async {
            write(&mut send, &connection, &ours).await?;
            let theirs = read_message(&mut recv, &connection, LINK_VERDICT).await?;
            LinkVerdict::decode(&theirs).map_err(LinkError::Protocol)
        };
        let peer_verdict = match tokio::time::timeout(deadline, verdicts).await {
            Ok(Ok(verdict)) => verdict,
            Ok(Err(e)) => return Err(self.fail(e, deadline)),
            Err(_) => return Err(self.fail(LinkError::Timeout, deadline)),
        };
        drop(self.permit.take());
        let remote = self.connection.remote_address();
        trace!(target: "face.quic", face = %id, peer = %remote, scoped = admission.scope.is_some(), "link admitted");
        let scope = admission.scope.map(|s| Arc::new(ScopeState::new(s)));
        let local_answers = scope.as_ref().map(|_| {
            let (tx, rx) = tokio::sync::mpsc::channel(LOCAL_ANSWERS);
            (tx, tokio::sync::Mutex::new(rx))
        });
        let (observed_tx, observed) = tokio::sync::watch::channel(None);
        let (reachability_tx, reachability) = tokio::sync::watch::channel(None);
        let (presence_tx, presence) = tokio::sync::watch::channel(Vec::new());
        let outbox = Arc::new(Outbox::default());
        let heard = Heard {
            observed: observed_tx,
            reachability: reachability_tx,
            presence: presence_tx,
        };
        tokio::spawn(observe(self.connection.clone(), send, recv, Arc::clone(&outbox), heard));
        Ok(Link {
            face: LinkFace {
                id,
                connection: self.connection.clone(),
                endpoint: self.endpoint.clone(),
                scope: scope.clone(),
                local_answers,
            },
            handle: LinkHandle {
                connection: self.connection,
                endpoint: self.endpoint,
                scope,
                observed,
                outbox,
                reachability,
                presence,
            },
            peer_verdict,
        })
    }

    /// Refuse the link: close it with `reason` and a sentence for the person
    /// reading the other device's log.
    pub fn refuse(self, reason: CloseReason, text: &str) {
        if let Some(permit) = &self.permit {
            permit.refused();
        }
        self.connection
            .close(quinn::VarInt::from_u32(reason.code()), text.as_bytes());
    }

    /// The hello or verdict exchange failed on this side: a malformed
    /// message, another protocol version, or no message within `deadline`.
    /// Close with [`CloseReason::Protocol`] and the reason, so the peer
    /// neither takes it for a shutdown nor dials again at once, and count it
    /// against the source like any refusal. Other errors (the peer closed,
    /// the connection broke) pass unchanged.
    fn fail(&self, error: LinkError, deadline: Duration) -> LinkError {
        let text = match &error {
            LinkError::Protocol(text) => text.clone(),
            LinkError::Timeout => format!(
                "your device sent no link message within {} s of the last one",
                deadline.as_secs()
            ),
            _ => return error,
        };
        if let Some(permit) = &self.permit {
            permit.refused();
        }
        self.connection
            .close(quinn::VarInt::from_u32(CloseReason::Protocol.code()), text.as_bytes());
        match error {
            LinkError::Protocol(text) => LinkError::RefusedHere {
                reason: CloseReason::Protocol,
                text,
            },
            other => other,
        }
    }
}

/// Write a link message. A connection the peer closed reports the peer's
/// reason.
async fn write(send: &mut quinn::SendStream, connection: &quinn::Connection, wire: &[u8]) -> Result<(), LinkError> {
    send.write_all(wire).await.map_err(|e| match connection.close_reason() {
        Some(reason) => LinkError::from_connection(reason),
        None => LinkError::Connect(e.to_string()),
    })
}

/// Read one link message of TLV-TYPE `expected` and return its value. A
/// connection the peer closed reports the peer's reason.
async fn read_message(
    recv: &mut quinn::RecvStream,
    connection: &quinn::Connection,
    expected: u64,
) -> Result<Bytes, LinkError> {
    match read_tlv(recv, connection).await? {
        Some((t, value)) if t == expected => Ok(value),
        Some((t, _)) => Err(LinkError::Protocol(format!(
            "expected link message {expected:#x}, got {t:#x}"
        ))),
        None => Err(match connection.close_reason() {
            Some(reason) => LinkError::from_connection(reason),
            None => LinkError::Protocol(format!(
                "the control stream ended where link message {expected:#x} belongs"
            )),
        }),
    }
}

/// Read one link message: its TLV-TYPE and value. `None` when the stream
/// ended (FIN) before it.
async fn read_tlv(
    recv: &mut quinn::RecvStream,
    connection: &quinn::Connection,
) -> Result<Option<(u64, Bytes)>, LinkError> {
    let closed = |e: String| match connection.close_reason() {
        Some(reason) => LinkError::from_connection(reason),
        None => LinkError::Protocol(e),
    };
    // A TLV header is at most 1 + 9 + 1 + 9 bytes; read it a byte at a time
    // until it parses, then the value.
    let mut buf: Vec<u8> = Vec::with_capacity(512);
    loop {
        let mut byte = [0u8; 1];
        if buf.is_empty() {
            match recv.read(&mut byte).await.map_err(|e| closed(e.to_string()))? {
                None => return Ok(None),
                Some(0) => continue,
                Some(_) => {}
            }
        } else {
            recv.read_exact(&mut byte).await.map_err(|e| closed(e.to_string()))?;
        }
        buf.push(byte[0]);
        if let Some((t, start, len)) = header(&buf) {
            if len > MAX_MESSAGE {
                return Err(LinkError::Protocol(format!(
                    "a link message of {len} bytes is over the {MAX_MESSAGE}-byte limit"
                )));
            }
            buf.resize(start + len, 0);
            recv.read_exact(&mut buf[start..])
                .await
                .map_err(|e| closed(e.to_string()))?;
            let (_, start, end) = split_tlv(&buf).map_err(LinkError::Protocol)?;
            return Ok(Some((t, Bytes::copy_from_slice(&buf[start..end]))));
        }
        if buf.len() > 20 {
            return Err(LinkError::Protocol("unreadable link message header".into()));
        }
    }
}

/// How often a side checks whether the address it sees the peer at
/// changed (the peer's NAT remapped, or the peer moved), to tell it.
const OBSERVE_INTERVAL: Duration = Duration::from_secs(5);

/// Most namespaces a peer's presence covers at once: a relay tells a device
/// of the namespaces they share, which are few.
const PRESENCE_NAMESPACES_MAX: usize = 256;

/// Messages this side has yet to write on the control stream. The latest of
/// each kind replaces one not yet written (per namespace for presence), so
/// a peer slow to read costs no memory.
#[derive(Default)]
struct Outbox {
    pending: Mutex<Pending>,
    ready: tokio::sync::Notify,
}

#[derive(Default)]
struct Pending {
    reachability: Option<Bytes>,
    presence: Vec<(Name, Bytes)>,
}

impl Outbox {
    fn put_reachability(&self, wire: Bytes) {
        self.pending.lock().unwrap_or_else(PoisonError::into_inner).reachability = Some(wire);
        self.ready.notify_one();
    }

    fn put_presence(&self, namespace: &Name, wire: Bytes) {
        let mut pending = self.pending.lock().unwrap_or_else(PoisonError::into_inner);
        match pending.presence.iter_mut().find(|(ns, _)| ns == namespace) {
            Some((_, queued)) => *queued = wire,
            None => pending.presence.push((namespace.clone(), wire)),
        }
        drop(pending);
        self.ready.notify_one();
    }

    fn take(&self) -> Vec<Bytes> {
        let mut pending = self.pending.lock().unwrap_or_else(PoisonError::into_inner);
        let reachability = pending.reachability.take();
        reachability
            .into_iter()
            .chain(pending.presence.drain(..).map(|(_, wire)| wire))
            .collect()
    }
}

/// Where the messages the peer sends after the verdict go.
struct Heard {
    observed: tokio::sync::watch::Sender<Option<SocketAddr>>,
    reachability: tokio::sync::watch::Sender<Option<Reachability>>,
    presence: tokio::sync::watch::Sender<Vec<Presence>>,
}

impl Heard {
    /// Take one message the peer sent after the verdict; `Err` is why the
    /// link closes as a protocol error.
    fn take(&self, t: u64, value: &[u8]) -> Result<(), String> {
        match t {
            OBSERVED_ADDRESS => {
                let addr = decode_udp_address(value).map_err(|e| format!("malformed ObservedAddress link message: {e}"))?;
                self.observed.send_replace(Some(addr));
            }
            REACHABILITY => {
                let r = Reachability::decode(value).map_err(|e| format!("malformed Reachability link message: {e}"))?;
                self.reachability.send_replace(Some(r));
            }
            PRESENCE => {
                let p = Presence::decode(value).map_err(|e| format!("malformed Presence link message: {e}"))?;
                let mut over = false;
                self.presence.send_if_modified(|all| {
                    let at = all.iter().position(|q| q.namespace == p.namespace);
                    match (at, p.devices.is_empty()) {
                        (Some(i), true) => {
                            all.remove(i);
                        }
                        (Some(i), false) => all[i] = p,
                        (None, true) => return false,
                        (None, false) if all.len() >= PRESENCE_NAMESPACES_MAX => {
                            over = true;
                            return false;
                        }
                        (None, false) => all.push(p),
                    }
                    true
                });
                if over {
                    return Err(format!(
                        "presence for more than {PRESENCE_NAMESPACES_MAX} namespaces at once: a relay \
                         tells a device of the namespaces they share"
                    ));
                }
            }
            t if skippable(t) => {}
            t => return Err(format!("unknown critical link message {t:#x} after the verdict")),
        }
        Ok(())
    }
}

/// After the verdicts, for the life of the link: tell the peer the address
/// its packets come from (`ObservedAddress`, at once and whenever it
/// changes) and write what this side queued (`Reachability`, `Presence`);
/// take the peer's messages into `heard`. A peer that ends its control
/// stream or does not read it (it predates these messages) ends that half
/// only.
async fn observe(
    connection: quinn::Connection,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    outbox: Arc<Outbox>,
    heard: Heard,
) {
    let tell = async {
        let mut told = None;
        loop {
            let now = connection.remote_address();
            let now = SocketAddr::new(now.ip().to_canonical(), now.port());
            if told != Some(now) {
                if send.write_all(&encode_observed_address(now)).await.is_err() {
                    return;
                }
                told = Some(now);
            }
            for wire in outbox.take() {
                if send.write_all(&wire).await.is_err() {
                    return;
                }
            }
            tokio::select! {
                () = tokio::time::sleep(OBSERVE_INTERVAL) => {}
                () = outbox.ready.notified() => {}
            }
        }
    };
    let hear = async {
        loop {
            match read_tlv(&mut recv, &connection).await {
                Ok(Some((t, value))) => {
                    if let Err(text) = heard.take(t, &value) {
                        connection.close(quinn::VarInt::from_u32(CloseReason::Protocol.code()), text.as_bytes());
                        return;
                    }
                }
                Ok(None) | Err(_) => return,
            }
        }
    };
    tokio::select! {
        _ = connection.closed() => {}
        _ = async { tokio::join!(tell, hear) } => {}
    }
}

/// Type, value offset and value length of a complete TLV header in `buf`.
fn header(buf: &[u8]) -> Option<(u64, usize, usize)> {
    let (t, tn) = ndn_tlv::read_varu64(buf).ok()?;
    let (l, ln) = ndn_tlv::read_varu64(buf.get(tn..)?).ok()?;
    Some((t, tn + ln, usize::try_from(l).ok()?))
}

/// How a side admits a link: what it tells the peer, and what the link
/// carries on its side.
#[derive(Default)]
pub struct Admission {
    /// The verdict sent to the peer.
    pub verdict: LinkVerdict,
    /// `Some`: the link carries only this ([`LinkScope`]); `None`: a full
    /// link.
    pub scope: Option<LinkScope>,
}

/// Answers a scoped face makes for this side (Nacks for the Interests it
/// keeps from the peer), queued for its receive side.
const LOCAL_ANSWERS: usize = 16;

/// An admitted link: its face, a handle to close it, and what the other
/// side's verdict said.
pub struct Link {
    pub face: LinkFace,
    pub handle: LinkHandle,
    pub peer_verdict: LinkVerdict,
}

/// Closes a link, tells when it ended, and carries the messages of the
/// link's control stream after the verdict.
#[derive(Clone)]
pub struct LinkHandle {
    connection: quinn::Connection,
    endpoint: quinn::Endpoint,
    scope: Option<Arc<ScopeState>>,
    observed: tokio::sync::watch::Receiver<Option<SocketAddr>>,
    outbox: Arc<Outbox>,
    reachability: tokio::sync::watch::Receiver<Option<Reachability>>,
    presence: tokio::sync::watch::Receiver<Vec<Presence>>,
}

impl LinkHandle {
    pub fn close(&self, reason: CloseReason, text: &str) {
        self.connection
            .close(quinn::VarInt::from_u32(reason.code()), text.as_bytes());
    }

    /// Resolves when the link has ended, with why.
    pub async fn closed(&self) -> LinkError {
        LinkError::from_connection(self.connection.closed().await)
    }

    /// Whether the link ended (or this side closed it), though its end may
    /// not have been handled yet.
    pub fn is_closed(&self) -> bool {
        self.connection.close_reason().is_some()
    }

    pub fn remote_address(&self) -> SocketAddr {
        self.connection.remote_address()
    }

    /// The address of this side's socket now: after a rebind (this device
    /// moved), the new one.
    pub fn local_address(&self) -> Option<SocketAddr> {
        self.endpoint.local_addr().ok()
    }

    /// The address the other device sees this one's packets come from, as
    /// it last said (`ObservedAddress`): this device's address beyond the
    /// NATs between them. `None` until it says.
    pub fn observed_address(&self) -> Option<SocketAddr> {
        *self.observed.borrow()
    }

    /// The link's current round-trip time estimate.
    pub fn rtt(&self) -> Duration {
        self.connection.rtt()
    }

    /// The largest NDNLPv2 frame the link carries now.
    pub fn max_datagram_size(&self) -> Option<usize> {
        self.connection.max_datagram_size()
    }

    /// For a scoped link, how long its scope has passed no packet; `None`
    /// for a full link.
    pub fn scope_idle_for(&self) -> Option<Duration> {
        self.scope.as_ref().map(|s| s.idle_for())
    }

    /// Tell the peer (a relay) how this device is reached while its link is
    /// down ([`Reachability`]); it replaces what was told before. A wake
    /// token over [`WAKE_TOKEN_MAX`] bytes, or empty, is not sent (the peer
    /// would close the link over it): the warning says so.
    pub fn send_reachability(&self, r: &Reachability) {
        if let Some(token) = &r.wake_token
            && !(1..=WAKE_TOKEN_MAX).contains(&token.len())
        {
            tracing::warn!(
                target: "face.quic",
                peer = %self.connection.remote_address(),
                "not sending a wake token of {} bytes: a wake token is 1 to {WAKE_TOKEN_MAX} bytes; \
                 register a shorter one (the relay keeps the reachability it was told before)",
                token.len()
            );
            return;
        }
        self.outbox.put_reachability(r.encode());
    }

    /// What the peer last said of how it is reached while its link is down;
    /// `None` until it says.
    pub fn peer_reachability(&self) -> Option<Reachability> {
        self.reachability.borrow().clone()
    }

    /// Tell the peer which devices of `p.namespace` are linked here now
    /// ([`Presence`]); it replaces what was told before for that namespace.
    /// A list over the 64 KiB a link message takes is not sent (the peer
    /// would close the link over it): the warning says so.
    pub fn send_presence(&self, p: &Presence) {
        let wire = p.encode();
        if wire.len() > MAX_MESSAGE {
            tracing::warn!(
                target: "face.quic",
                peer = %self.connection.remote_address(),
                "not sending the presence of {} devices of {}: it takes {} bytes, over the {MAX_MESSAGE}-byte \
                 limit of a link message; list fewer (the peer keeps the presence it was told before)",
                p.devices.len(),
                p.namespace,
                wire.len()
            );
            return;
        }
        self.outbox.put_presence(&p.namespace, wire);
    }

    /// The peer's latest presence, one entry per namespace with a device
    /// present (an empty list from the peer removes the namespace's entry).
    pub fn presence(&self) -> tokio::sync::watch::Receiver<Vec<Presence>> {
        self.presence.clone()
    }

    /// NDN datagrams the link has sent and received so far (QUIC DATAGRAM
    /// frames; keep-alives and control messages are not counted): whether
    /// the link carried traffic since an earlier reading.
    pub fn datagrams(&self) -> u64 {
        let stats = self.connection.stats();
        stats.frame_tx.datagram + stats.frame_rx.datagram
    }
}

/// The face of a link: each NDNLPv2 frame is one QUIC datagram. The face's
/// link service frames and fragments packets to [`send_mtu`]
/// (Transport::send_mtu), the connection's current datagram size, which
/// grows as path MTU discovery finds room. A scoped link's face drops what
/// its [`LinkScope`] does not carry, both ways.
pub struct LinkFace {
    id: FaceId,
    connection: quinn::Connection,
    /// The endpoint the connection runs on, for this side's address.
    endpoint: quinn::Endpoint,
    scope: Option<Arc<ScopeState>>,
    local_answers: Option<(
        tokio::sync::mpsc::Sender<Bytes>,
        tokio::sync::Mutex<tokio::sync::mpsc::Receiver<Bytes>>,
    )>,
}

impl LinkFace {
    async fn send_datagram(&self, wire: Bytes) -> Result<(), FaceError> {
        let len = wire.len();
        match self.connection.send_datagram_wait(wire).await {
            Ok(()) => Ok(()),
            // The path's datagram size shrank between framing and sending:
            // this frame is lost, as on any datagram link, and recovered the
            // NDN way.
            Err(SendDatagramError::TooLarge) => {
                trace!(target: "face.quic", face = %self.id, len, "datagram over the path size, dropped");
                Ok(())
            }
            Err(SendDatagramError::ConnectionLost(_)) => Err(FaceError::Closed),
            Err(e) => Err(FaceError::Io(std::io::Error::other(e))),
        }
    }

    async fn read_datagram(&self) -> Result<Bytes, FaceError> {
        self.connection
            .read_datagram()
            .await
            .map_err(|_| FaceError::Closed)
    }
}

impl Transport for LinkFace {
    fn id(&self) -> FaceId {
        self.id
    }

    fn kind(&self) -> FaceKind {
        FaceKind::Quic
    }

    /// The connection's current address: after a migration (the peer's
    /// address changed, or this side rebound) it is the new one.
    fn remote_uri(&self) -> Option<String> {
        Some(ip_face_uri("quic", self.connection.remote_address()))
    }

    /// This side's socket address now: after a rebind (this device moved)
    /// it is the new one.
    fn local_uri(&self) -> Option<String> {
        self.endpoint.local_addr().ok().map(|addr| ip_face_uri("quic", addr))
    }

    fn send_mtu(&self) -> Option<usize> {
        Some(self.connection.max_datagram_size().unwrap_or(DATAGRAM_FLOOR))
    }

    async fn send_bytes(&self, wire: Bytes) -> Result<(), FaceError> {
        if let Some(scope) = &self.scope {
            match scope.sending(&wire) {
                Judged::Pass => {}
                Judged::Drop(interest) => {
                    // An Interest kept from the peer is Nacked to this side.
                    if let (Some(interest), Some((answers, _))) = (interest, &self.local_answers) {
                        let _ = answers.try_send(nack_for(&interest));
                    }
                    return Ok(());
                }
            }
        }
        self.send_datagram(wire).await
    }

    async fn recv_bytes(&self) -> Result<Bytes, FaceError> {
        let (Some(scope), Some((_, answers))) = (&self.scope, &self.local_answers) else {
            return self.read_datagram().await;
        };
        let mut answers = answers.lock().await;
        loop {
            let wire = tokio::select! {
                wire = self.read_datagram() => wire?,
                Some(answer) = answers.recv() => return Ok(answer),
            };
            match scope.received(&wire) {
                Judged::Pass => return Ok(wire),
                // An Interest the peer may not send here is Nacked to it.
                Judged::Drop(Some(interest)) => {
                    let _ = self.connection.send_datagram(nack_for(&interest));
                }
                Judged::Drop(None) => {}
            }
        }
    }
}
