//! A link after its handshake: the hello exchange, the admission verdicts,
//! and the face it becomes.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::Poll;
use std::time::Duration;

use bytes::Bytes;
use ndn_packet::Name;
use quinn::{ConnectionError, SendDatagramError};
use tracing::trace;

use ndn_transport::{
    FaceError, FaceId, FaceKind, SIDE_MARKER, SideClass, SideRefused, Transport, ip_face_uri,
};

use crate::endpoint::Permit;
use crate::key::{KeyFingerprint, LinkKey, PeerKey};
use crate::membership::{ChannelBinding, MEMBERSHIP_EXPORTER_LABEL};
use crate::message::{
    CloseReason, DEPARTURE, DEPARTURES_MAX, Departure, LINK_HELLO, LINK_VERDICT, LinkHello,
    LinkVerdict, MAX_MESSAGE, OBSERVED_ADDRESS, PRESENCE, Presence, REACHABILITY, Reachability,
    WAKE_TOKEN_MAX, decode_udp_address, encode_observed_address, skippable, split_tlv,
};
use crate::scope::{Judged, LinkScope, ScopeState, nack_for};
use crate::side::{ChannelPolicy, SideCarrier, SideLimits, SideStats, has_channel_caps};

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
                // The other device chose these words: whatever it put in them,
                // what is handed up is one bounded line of printable text.
                let text = crate::text::sanitize_peer_text(&String::from_utf8_lossy(&close.reason));
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
                "the other device stopped answering (it went away, or the path to it broke)".into(),
            ),
            ConnectionError::LocallyClosed => Self::Connect("this device closed the link".into()),
            // A transport close of the other device quotes its reason phrase.
            other => Self::Connect(crate::text::sanitize_peer_text(&other.to_string())),
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

/// A connection whose TLS handshake proved the peer holds
/// [`peer_key`](Self::peer_key), not yet admitted as a link.
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
    /// The peer's hello carried `ChannelCaps` bit 0 (set by `exchange_hello`).
    peer_caps: bool,
    /// This side's hello did.
    our_caps: bool,
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
            .and_then(|id| {
                id.downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
                    .ok()
            })
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
            peer_caps: false,
            our_caps: false,
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
                    let (mut send, recv) = self
                        .connection
                        .open_bi()
                        .await
                        .map_err(LinkError::from_connection)?;
                    write(&mut send, &self.connection, &wire).await?;
                    (send, recv)
                }
                Direction::Accepted => self
                    .connection
                    .accept_bi()
                    .await
                    .map_err(LinkError::from_connection)?,
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
        self.peer_caps = has_channel_caps(hello.channel_caps);
        self.our_caps = has_channel_caps(ours.channel_caps);
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
        if let Some(permit) = self.permit.take() {
            permit.admitted(self.connection.clone());
        }
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
        let (departures_tx, departures) = tokio::sync::watch::channel(Vec::new());
        let outbox = Arc::new(Outbox::default());
        let heard = Heard {
            observed: observed_tx,
            reachability: reachability_tx,
            presence: presence_tx,
            departures: departures_tx,
        };
        let local_close = Arc::new(std::sync::OnceLock::new());
        let side = SideCarrier::new(
            self.connection.clone(),
            self.peer_caps,
            self.our_caps,
            admission.channel,
            scope.clone(),
            Arc::clone(&local_close),
        );
        side.spawn(id);
        tokio::spawn(observe(
            self.connection.clone(),
            send,
            recv,
            Arc::clone(&outbox),
            heard,
        ));
        Ok(Link {
            face: LinkFace {
                id,
                connection: self.connection.clone(),
                endpoint: self.endpoint.clone(),
                scope: scope.clone(),
                local_answers,
                side: Arc::clone(&side),
            },
            handle: LinkHandle {
                connection: self.connection,
                endpoint: self.endpoint,
                scope,
                observed,
                outbox,
                reachability,
                presence,
                departures,
                local_close,
                side,
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
        self.connection.close(
            quinn::VarInt::from_u32(CloseReason::Protocol.code()),
            text.as_bytes(),
        );
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
async fn write(
    send: &mut quinn::SendStream,
    connection: &quinn::Connection,
    wire: &[u8],
) -> Result<(), LinkError> {
    send.write_all(wire)
        .await
        .map_err(|e| match connection.close_reason() {
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
            match recv
                .read(&mut byte)
                .await
                .map_err(|e| closed(e.to_string()))?
            {
                None => return Ok(None),
                Some(0) => continue,
                Some(_) => {}
            }
        } else {
            recv.read_exact(&mut byte)
                .await
                .map_err(|e| closed(e.to_string()))?;
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
    departures: Vec<(Name, Bytes)>,
    /// The folders this side told the peer of, ever, on this link.
    told: Vec<Name>,
}

impl Outbox {
    fn put_reachability(&self, wire: Bytes) {
        self.pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .reachability = Some(wire);
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

    /// Queue a `Departure` for `folder`; `false` when this link already told
    /// [`DEPARTURES_MAX`] other folders (the peer takes no more).
    fn put_departure(&self, folder: &Name, wire: Bytes) -> bool {
        let mut pending = self.pending.lock().unwrap_or_else(PoisonError::into_inner);
        if !pending.told.contains(folder) {
            if pending.told.len() >= DEPARTURES_MAX {
                return false;
            }
            pending.told.push(folder.clone());
        }
        match pending.departures.iter_mut().find(|(f, _)| f == folder) {
            Some((_, queued)) => *queued = wire,
            None => pending.departures.push((folder.clone(), wire)),
        }
        drop(pending);
        self.ready.notify_one();
        true
    }

    fn take(&self) -> Vec<Bytes> {
        let pending = &mut *self.pending.lock().unwrap_or_else(PoisonError::into_inner);
        let reachability = pending.reachability.take();
        reachability
            .into_iter()
            .chain(pending.presence.drain(..).map(|(_, wire)| wire))
            .chain(pending.departures.drain(..).map(|(_, wire)| wire))
            .collect()
    }
}

/// Where the messages the peer sends after the verdict go.
struct Heard {
    observed: tokio::sync::watch::Sender<Option<SocketAddr>>,
    reachability: tokio::sync::watch::Sender<Option<Reachability>>,
    presence: tokio::sync::watch::Sender<Vec<Presence>>,
    departures: tokio::sync::watch::Sender<Vec<Departure>>,
}

impl Heard {
    /// Take one message the peer sent after the verdict; `Err` is why the
    /// link closes as a protocol error.
    fn take(&self, t: u64, value: &[u8]) -> Result<(), String> {
        match t {
            OBSERVED_ADDRESS => {
                let addr = decode_udp_address(value)
                    .map_err(|e| format!("malformed ObservedAddress link message: {e}"))?;
                self.observed.send_replace(Some(addr));
            }
            REACHABILITY => {
                let r = Reachability::decode(value)
                    .map_err(|e| format!("malformed Reachability link message: {e}"))?;
                self.reachability.send_replace(Some(r));
            }
            PRESENCE => {
                let p = Presence::decode(value)
                    .map_err(|e| format!("malformed Presence link message: {e}"))?;
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
            DEPARTURE => {
                let d = Departure::decode(value)
                    .map_err(|e| format!("malformed Departure link message: {e}"))?;
                let mut over = false;
                self.departures.send_if_modified(|all| {
                    match all.iter().position(|q| q.folder == d.folder) {
                        Some(i) if all[i] == d => return false,
                        Some(i) => all[i] = d,
                        None if all.len() >= DEPARTURES_MAX => {
                            over = true;
                            return false;
                        }
                        None => all.push(d),
                    }
                    true
                });
                if over {
                    return Err(format!(
                        "a Departure message for more than {DEPARTURES_MAX} folders at once: a \
                         link tells a person of the few folders it let them go of"
                    ));
                }
            }
            t if skippable(t) => {}
            t => {
                return Err(format!(
                    "unknown critical link message {t:#x} after the verdict"
                ));
            }
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
                        connection.close(
                            quinn::VarInt::from_u32(CloseReason::Protocol.code()),
                            text.as_bytes(),
                        );
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
    /// Whether the link carries channel frames, and under which quota. The
    /// default carries none.
    pub channel: ChannelPolicy,
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
    departures: tokio::sync::watch::Receiver<Vec<Departure>>,
    /// What this side said when it closed the link (the first close wins, as
    /// in QUIC): the connection itself keeps no text of a close made here.
    local_close: Arc<std::sync::OnceLock<(CloseReason, String)>>,
    side: Arc<SideCarrier>,
}

impl LinkHandle {
    pub fn close(&self, reason: CloseReason, text: &str) {
        let _ = self.local_close.set((reason, text.to_string()));
        self.connection
            .close(quinn::VarInt::from_u32(reason.code()), text.as_bytes());
    }

    /// Resolves when the link has ended, with why. A link this side closed
    /// ends with the reason and the words it closed with.
    pub async fn closed(&self) -> LinkError {
        match self.connection.closed().await {
            ConnectionError::LocallyClosed => match self.local_close.get() {
                Some((reason, text)) => LinkError::RefusedHere {
                    reason: *reason,
                    text: text.clone(),
                },
                None => LinkError::Connect("this device closed the link".into()),
            },
            other => LinkError::from_connection(other),
        }
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

    /// The local address this link's packets arrive at (the destination
    /// address the peer sent to): for a link accepted on a socket bound to
    /// every address, the one address of this device the peer reached it at.
    /// The socket's own address when that is a specific one and the system
    /// gives no destination address; `None` when this is neither (a socket
    /// on every address on a system that tells no destination), where which
    /// address a link was accepted at is not known.
    pub fn accepted_ip(&self) -> Option<IpAddr> {
        self.connection
            .local_ip()
            .or_else(|| {
                self.endpoint
                    .local_addr()
                    .ok()
                    .map(|a| a.ip())
                    .filter(|ip| !ip.is_unspecified())
            })
            .map(|ip| ip.to_canonical())
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

    /// Tell the peer it was let go of `d.folder`, naming the members record
    /// to fetch ([`Departure`]); it replaces what was told before for that
    /// folder. A link tells at most [`DEPARTURES_MAX`] folders (the peer
    /// closes a link that hears more): the others are not sent, and the
    /// warning says so.
    pub fn send_departure(&self, d: &Departure) {
        let wire = d.encode();
        if wire.len() > MAX_MESSAGE {
            tracing::warn!(
                target: "face.quic",
                peer = %self.connection.remote_address(),
                "not sending the departure of {}: it takes {} bytes, over the {MAX_MESSAGE}-byte \
                 limit of a link message",
                d.folder,
                wire.len()
            );
            return;
        }
        if !self.outbox.put_departure(&d.folder, wire) {
            tracing::warn!(
                target: "face.quic",
                peer = %self.connection.remote_address(),
                "not telling the peer it was let go of {}: this link already told it of \
                 {DEPARTURES_MAX} folders, which is as many as a link takes",
                d.folder
            );
        }
    }

    /// What the peer last told this side of its departures, one entry per
    /// folder (the latest for a folder replaces the earlier).
    pub fn departures(&self) -> tokio::sync::watch::Receiver<Vec<Departure>> {
        self.departures.clone()
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

    /// What the link's side path carried and dropped so far: channel frames
    /// and octets each way by carrier, and what was refused or dropped.
    /// Counters only: no address, no key.
    pub fn side_stats(&self) -> SideStats {
        self.side.stats()
    }

    /// Change how long a write to this link's channel stream may make no progress before the
    /// link is closed ([`STREAM_STALL`](crate::STREAM_STALL), 30 s, by default): a peer that
    /// has granted no flow-control credit for this long is not reading the stream it was
    /// granted. The link is closed with [`CloseReason::Protocol`] and words that say so, and
    /// the senders waiting on it are told. At least a millisecond.
    pub fn set_stream_stall(&self, stall: Duration) {
        self.side.set_stream_stall(stall);
    }

    /// The QUIC connection's own counters (packets, datagrams and frames each way, and the
    /// path's congestion window, losses and congestion events): read-only, for diagnosing a
    /// link's throughput. No address, no key.
    pub fn quic_stats(&self) -> quinn::ConnectionStats {
        self.connection.stats()
    }

    /// Whether the peer's hello advertised `ChannelCaps` (bit 0, channel
    /// frames). A link carries channel frames only when both sides'
    /// hellos did and this side's [`ChannelPolicy`] carries.
    pub fn side_peer_caps(&self) -> bool {
        self.side.peer_caps()
    }
}

/// The face of a link: each NDNLPv2 frame is one QUIC datagram. The face's
/// link service frames and fragments packets to
/// [`send_mtu`](ndn_transport::Transport::send_mtu), the connection's
/// current datagram size, which grows as path MTU discovery finds room. A
/// scoped link's face drops what its [`LinkScope`] does not carry, both
/// ways.
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
    side: Arc<SideCarrier>,
}

impl LinkFace {
    async fn send_datagram(&self, wire: Bytes) -> Result<(), FaceError> {
        let len = wire.len();
        match self.connection.send_datagram_wait(wire).await {
            Ok(()) => Ok(()),
            // Every frame is sized to `send_mtu` as it is when sent, and a
            // repair that no longer fits is cut again to it (ndn-transport's
            // reliability), so reaching here takes the path's datagram size
            // falling between that sizing and this call. The frame is lost,
            // as on any datagram link, and recovered the NDN way; a run that
            // logs this repeatedly has a sender sizing for a stale limit.
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

    /// What a writer of channel frames needs to know before it hands one
    /// over: the octets queued in the connection's datagram send buffer now
    /// (the input of the headroom rule), and the frame limits.
    pub fn side_limits(&self) -> SideLimits {
        self.side.limits()
    }

    /// What one datagram read is: a channel frame goes to the side path's
    /// quota (it never reaches the NDN scope, and a drop sends no Nack); any
    /// other frame is judged by the link's scope, if it has one. `None`: the
    /// frame was dropped.
    fn judge_datagram(&self, wire: Bytes) -> Option<Bytes> {
        if wire.first() == Some(&SIDE_MARKER) {
            return self.side.received_datagram(&wire).then_some(wire);
        }
        let Some(scope) = &self.scope else {
            return Some(wire);
        };
        match scope.received(&wire) {
            Judged::Pass => Some(wire),
            // An Interest the peer may not send here, or sends over a
            // rate, is Nacked to it.
            Judged::Drop(Some((reason, interest))) => {
                let _ = self.connection.send_datagram(nack_for(reason, &interest));
                None
            }
            Judged::Drop(None) => None,
        }
    }

    /// `recv_bytes` of a link that also listens for the Nacks its scope answers itself with.
    /// (The channel stream's frames are not read here: they have a lane of their own,
    /// [`recv_side_stream`](Transport::recv_side_stream), so that waiting for room at a sink can
    /// never hold back what this reads.)
    async fn recv_bytes_from_all(&self) -> Result<Bytes, FaceError> {
        let mut answers = match &self.local_answers {
            Some((_, answers)) => Some(answers.lock().await),
            None => None,
        };
        loop {
            let datagram = self.read_datagram();
            tokio::pin!(datagram);
            // A datagram already queued is taken without registering on the
            // other sources, which costs more than the read itself on a link
            // that is saturated; one call in eight listens to them all, so
            // none is starved.
            if self.side.datagram_first() {
                let polled = std::future::poll_fn(|cx| Poll::Ready(datagram.as_mut().poll(cx)));
                if let Poll::Ready(wire) = polled.await {
                    if let Some(wire) = self.judge_datagram(wire?) {
                        return Ok(wire);
                    }
                    continue;
                }
            }
            tokio::select! {
                wire = &mut datagram => {
                    if let Some(wire) = self.judge_datagram(wire?) {
                        return Ok(wire);
                    }
                }
                answer = async {
                    match answers.as_mut() {
                        Some(answers) => answers.recv().await,
                        None => std::future::pending().await,
                    }
                } => {
                    if let Some(answer) = answer {
                        return Ok(answer);
                    }
                }
            }
        }
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
        self.endpoint
            .local_addr()
            .ok()
            .map(|addr| ip_face_uri("quic", addr))
    }

    fn send_mtu(&self) -> Option<usize> {
        Some(
            self.connection
                .max_datagram_size()
                .unwrap_or(DATAGRAM_FLOOR),
        )
    }

    async fn send_bytes(&self, wire: Bytes) -> Result<(), FaceError> {
        if let Some(scope) = &self.scope {
            match scope.sending(&wire) {
                Judged::Pass => {}
                Judged::Drop(nack) => {
                    // An Interest kept from the peer is Nacked to this side.
                    if let (Some((reason, interest)), Some((answers, _))) =
                        (nack, &self.local_answers)
                    {
                        let _ = answers.try_send(nack_for(reason, &interest));
                    }
                    return Ok(());
                }
            }
        }
        self.send_datagram(wire).await
    }

    async fn recv_bytes(&self) -> Result<Bytes, FaceError> {
        if self.local_answers.is_some() {
            return self.recv_bytes_from_all().await;
        }
        loop {
            let wire = self.read_datagram().await?;
            if let Some(wire) = self.judge_datagram(wire) {
                return Ok(wire);
            }
        }
    }

    /// The side path's own limits: a datagram carries what the connection
    /// does now, and the stream's frames are bounded apart.
    fn side_frame_max(&self) -> usize {
        self.side.frame_max()
    }

    async fn send_side(&self, frame: Bytes, class: SideClass) -> Result<(), SideRefused> {
        self.side.send(frame, class).await
    }

    fn forward_side(&self, frame: Bytes, class: SideClass) -> Result<(), SideRefused> {
        self.side.forward(frame, class)
    }

    fn side_room(&self, class: SideClass) -> bool {
        self.side.room(class)
    }

    fn side_room_for(&self, frame: &[u8], class: SideClass) -> bool {
        self.side.room_for(frame.len(), class)
    }

    /// The channel stream's frames come through [`recv_side_stream`](Self::recv_side_stream),
    /// not `recv_bytes`, on a link that can carry them.
    fn side_stream_lane(&self) -> bool {
        self.side.stream_lane()
    }

    /// The next frame of the peer's channel stream, in order. Not taking one is the back
    /// pressure: the stream's reader task stops at its inbox bound, stops reading the
    /// connection's stream, and flow control slows the peer, whose write then
    /// closes the link after [`STREAM_STALL`](crate::STREAM_STALL) without progress.
    async fn recv_side_stream(&self) -> Result<Bytes, FaceError> {
        self.side.next_stream_frame().await.ok_or(FaceError::Closed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn heard() -> (Heard, tokio::sync::watch::Receiver<Vec<Departure>>) {
        let (departures, rx) = tokio::sync::watch::channel(Vec::new());
        let heard = Heard {
            observed: tokio::sync::watch::channel(None).0,
            reachability: tokio::sync::watch::channel(None).0,
            presence: tokio::sync::watch::channel(Vec::new()).0,
            departures,
        };
        (heard, rx)
    }

    fn departure(i: usize, seq: usize) -> Departure {
        Departure {
            folder: format!("/a/32=data/f{i}").parse().unwrap(),
            record: format!("/a/d/32=log/f{i}/seq={seq}").parse().unwrap(),
        }
    }

    /// A malformed Departure, or one for more folders than a link takes,
    /// closes the link as a protocol error; the latest for a folder replaces
    /// the earlier.
    #[test]
    fn a_peer_that_tells_too_many_folders_or_garbage_is_a_protocol_error() {
        let (heard, rx) = heard();
        for i in 0..DEPARTURES_MAX {
            let wire = departure(i, 1).encode();
            heard.take(DEPARTURE, &wire[4..]).unwrap();
        }
        // The same folder again with a newer record replaces its entry.
        heard
            .take(DEPARTURE, &departure(3, 9).encode()[4..])
            .unwrap();
        assert_eq!(rx.borrow().len(), DEPARTURES_MAX);
        assert!(rx.borrow().contains(&departure(3, 9)));
        assert!(!rx.borrow().contains(&departure(3, 1)));
        let over = heard
            .take(DEPARTURE, &departure(DEPARTURES_MAX, 1).encode()[4..])
            .unwrap_err();
        assert!(over.contains("Departure"), "{over}");
        let garbage = heard.take(DEPARTURE, &[0x07, 0x00]).unwrap_err();
        assert!(garbage.contains("Departure"), "{garbage}");
    }

    // ---- The side stream, as a raw quinn peer sees it ----

    use crate::endpoint::{LinkEndpoint, LinkTransportConfig};
    use crate::side::STREAM_FRAME_MAX;
    use ndn_security::Ed25519Signer;

    const T: Duration = Duration::from_secs(5);
    /// Long enough for a stream that was going to open to have opened, on loopback.
    const NEVER: Duration = Duration::from_millis(400);

    fn endpoint(seed: u8, listen: bool) -> LinkEndpoint {
        let key = LinkKey::from_signer(Arc::new(Ed25519Signer::from_seed(
            &[seed; 32],
            format!("/ns/member/d{seed}/KEY/k").parse().unwrap(),
        )))
        .unwrap();
        LinkEndpoint::bind(
            "127.0.0.1:0".parse().unwrap(),
            Arc::new(key),
            &LinkTransportConfig::default(),
            listen,
        )
        .unwrap()
    }

    fn hello(caps: u8) -> LinkHello {
        LinkHello {
            channel_caps: caps,
            ..LinkHello::default()
        }
    }

    fn carrying() -> Admission {
        Admission {
            channel: ChannelPolicy {
                carry: true,
                quota: None,
            },
            ..Admission::default()
        }
    }

    /// Dial and finish both TLS handshakes; no link message was sent yet.
    async fn handshaken(
        dialer: &LinkEndpoint,
        listener: &LinkEndpoint,
    ) -> (Handshaken, Handshaken) {
        let target = listener.local_addr().unwrap();
        let (d, l) = tokio::join!(dialer.connect(target, None), async {
            listener.accept().await.unwrap().handshake().await
        });
        (d.unwrap(), l.unwrap())
    }

    async fn hellos(d: &mut Handshaken, l: &mut Handshaken, (hd, hl): (LinkHello, LinkHello)) {
        let (a, b) = tokio::join!(d.exchange_hello(&hd, T), l.exchange_hello(&hl, T));
        a.unwrap();
        b.unwrap();
    }

    async fn admitted(
        d: Handshaken,
        l: Handshaken,
        (ad, al): (Admission, Admission),
    ) -> (Link, Link) {
        let (a, b) = tokio::join!(d.admit(FaceId(1), T, ad), l.admit(FaceId(2), T, al));
        (a.unwrap(), b.unwrap())
    }

    /// Whether the peer of `raw` grants it a unidirectional stream within `within`.
    async fn stream_opens(raw: &quinn::Connection, within: Duration) -> bool {
        tokio::time::timeout(within, raw.open_uni()).await.is_ok()
    }

    #[tokio::test]
    async fn no_channel_stream_opens_before_the_verdict_and_none_without_caps() {
        let (dialer, listener) = (endpoint(1, false), endpoint(2, true));

        // Before the hellos and before the verdict, a raw quinn peer that opens a
        // unidirectional stream is refused: the link's transport grants none.
        let (mut d, mut l) = handshaken(&dialer, &listener).await;
        let raw = d.connection.clone();
        assert!(
            !stream_opens(&raw, NEVER).await,
            "a stream opened before the hellos"
        );
        hellos(&mut d, &mut l, (hello(1), hello(1))).await;
        assert!(
            !stream_opens(&raw, NEVER).await,
            "a stream opened before the verdict"
        );
        // Both carry: after the verdict the peer has granted exactly one.
        let (a, b) = admitted(d, l, (carrying(), carrying())).await;
        let first = tokio::time::timeout(T, raw.open_uni())
            .await
            .expect("the verdict grants the stream")
            .unwrap();
        assert!(
            !stream_opens(&raw, NEVER).await,
            "a second stream opened: the grant is one"
        );
        drop(first);
        assert!(a.handle.side_peer_caps() && b.handle.side_peer_caps());

        // A peer whose hello has no ChannelCaps: no grant, and `send_side` refuses.
        let (mut d, mut l) = handshaken(&dialer, &listener).await;
        let raw = d.connection.clone();
        hellos(&mut d, &mut l, (hello(1), hello(0))).await;
        let (a, b) = admitted(d, l, (carrying(), carrying())).await;
        assert!(!a.handle.side_peer_caps() && b.handle.side_peer_caps());
        assert!(
            !stream_opens(&raw, NEVER).await,
            "a peer without caps was granted a stream"
        );
        let marked = Bytes::from_static(&[0, 1, 2]);
        for class in [SideClass::Datagram, SideClass::Stream] {
            assert_eq!(
                a.face.send_side(marked.clone(), class).await,
                Err(SideRefused::PeerLacksChannels)
            );
            assert_eq!(
                b.face.send_side(marked.clone(), class).await,
                Err(SideRefused::PeerLacksChannels)
            );
        }

        // A link whose admission does not carry (an unidentified or introduction
        // link) grants no stream either, though both hellos had the capability.
        let (mut d, mut l) = handshaken(&dialer, &listener).await;
        let raw = d.connection.clone();
        hellos(&mut d, &mut l, (hello(1), hello(1))).await;
        let (a, b) = admitted(d, l, (carrying(), Admission::default())).await;
        assert!(
            !stream_opens(&raw, NEVER).await,
            "a link that does not carry granted a stream"
        );
        assert_eq!(
            b.face.send_side(marked.clone(), SideClass::Stream).await,
            Err(SideRefused::NotCarried)
        );
        assert_eq!(b.handle.side_stats().refused, 1);
        drop(a);
    }

    /// What a peer sends on the channel stream that is not a channel frame is dropped and
    /// counted and the stream is stopped, the link stays up; a frame over what the side
    /// grants closes the link as a protocol error.
    #[tokio::test]
    async fn a_malformed_channel_record_stops_the_stream_and_an_oversize_one_closes_the_link() {
        let (dialer, listener) = (endpoint(1, false), endpoint(2, true));
        for (record, closes) in [
            // No marker.
            (vec![0, 0, 0, 3, 0x07, 1, 2], false),
            // A record of no octets.
            (vec![0, 0, 0, 0], false),
            // One octet over the 1 MiB a side grants.
            (((STREAM_FRAME_MAX + 1) as u32).to_be_bytes().to_vec(), true),
        ] {
            let (mut d, mut l) = handshaken(&dialer, &listener).await;
            let raw = d.connection.clone();
            hellos(&mut d, &mut l, (hello(1), hello(1))).await;
            let (a, b) = admitted(d, l, (carrying(), carrying())).await;
            let mut stream = tokio::time::timeout(T, raw.open_uni())
                .await
                .unwrap()
                .unwrap();
            stream.write_all(&record).await.unwrap();
            let start = std::time::Instant::now();
            while b.handle.side_stats().dropped_malformed == 0 {
                assert!(start.elapsed() < T, "the record {record:?} was not counted");
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            if closes {
                match tokio::time::timeout(T, b.handle.closed()).await.unwrap() {
                    LinkError::RefusedHere { reason, text } => {
                        assert_eq!(reason, CloseReason::Protocol);
                        assert!(text.contains("channel frame"), "{text}");
                    }
                    other => panic!("expected the Protocol close, got {other:?}"),
                }
                match tokio::time::timeout(T, a.handle.closed()).await.unwrap() {
                    LinkError::Refused { reason, .. } => {
                        assert_eq!(reason, Some(CloseReason::Protocol));
                    }
                    other => panic!("expected the peer's Protocol close, got {other:?}"),
                }
            } else {
                tokio::time::sleep(Duration::from_millis(200)).await;
                assert!(
                    !a.handle.is_closed() && !b.handle.is_closed(),
                    "the link stays up"
                );
                assert_eq!(b.handle.side_stats().stream_rx_frames, 0);
                // NDN packets still cross it.
                let pkt = Bytes::from_static(&[0x05, 0x03, 0x07, 0x01, 0x41]);
                a.face.send_bytes(pkt.clone()).await.unwrap();
                assert_eq!(
                    tokio::time::timeout(T, b.face.recv_bytes())
                        .await
                        .unwrap()
                        .unwrap(),
                    pkt
                );
            }
        }
    }

    /// A peer that starts a channel record (the length prefix, or the prefix and some of the
    /// octets) and then sends nothing holds the stream's reader, the permit for the length it
    /// named and the buffer it asked for for as long as the link stays up (security review F4 of
    /// the stream lane). A record the peer does not finish within the link's stall bound ends the
    /// stream, counted `dropped_malformed`: the link stays up, and so do its NDN packets.
    #[tokio::test]
    async fn a_channel_record_the_peer_leaves_half_written_ends_its_stream() {
        let (dialer, listener) = (endpoint(1, false), endpoint(2, true));
        for (what, written) in [
            ("half a length prefix", vec![0, 0]),
            ("a length prefix and no octets", vec![0, 0, 0, 10]),
            (
                "a length prefix and some octets",
                vec![0, 0, 0, 10, SIDE_MARKER, 1],
            ),
        ] {
            let (mut d, mut l) = handshaken(&dialer, &listener).await;
            let raw = d.connection.clone();
            hellos(&mut d, &mut l, (hello(1), hello(1))).await;
            let (a, b) = admitted(d, l, (carrying(), carrying())).await;
            b.handle.set_stream_stall(Duration::from_millis(300));
            let mut stream = tokio::time::timeout(T, raw.open_uni())
                .await
                .unwrap()
                .unwrap();
            stream.write_all(&written).await.unwrap();
            let start = std::time::Instant::now();
            while b.handle.side_stats().dropped_malformed == 0 {
                assert!(
                    start.elapsed() < T,
                    "{what}, then silence: the stream was not ended"
                );
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            assert!(
                !a.handle.is_closed() && !b.handle.is_closed(),
                "the link stays up"
            );
            let pkt = Bytes::from_static(&[0x05, 0x03, 0x07, 0x01, 0x41]);
            a.face.send_bytes(pkt.clone()).await.unwrap();
            assert_eq!(
                tokio::time::timeout(T, b.face.recv_bytes())
                    .await
                    .unwrap()
                    .unwrap(),
                pkt
            );
        }
    }

    /// The peer's channel stream is the one it was granted: when it finishes, or is reset,
    /// quinn must not hand the peer the credit for a second (the carrier reads one stream
    /// and never accepts another, so a second would only let the peer buffer a flow-control
    /// window of bytes nobody reads).
    #[tokio::test]
    async fn a_finished_or_reset_channel_stream_is_not_replaced_by_a_second() {
        let (dialer, listener) = (endpoint(1, false), endpoint(2, true));
        for finish in [true, false] {
            let (mut d, mut l) = handshaken(&dialer, &listener).await;
            let raw = d.connection.clone();
            hellos(&mut d, &mut l, (hello(1), hello(1))).await;
            let (a, b) = admitted(d, l, (carrying(), carrying())).await;
            let mut stream = tokio::time::timeout(T, raw.open_uni())
                .await
                .unwrap()
                .unwrap();
            stream
                .write_all(&[0, 0, 0, 3, SIDE_MARKER, 1, 2])
                .await
                .unwrap();
            assert_eq!(
                tokio::time::timeout(T, b.face.recv_side_stream())
                    .await
                    .unwrap()
                    .unwrap(),
                Bytes::from_static(&[SIDE_MARKER, 1, 2])
            );
            if finish {
                stream.finish().unwrap();
            } else {
                stream.reset(quinn::VarInt::from_u32(7)).unwrap();
            }
            assert!(
                !stream_opens(&raw, NEVER).await,
                "a second channel stream opened after the first {}",
                if finish { "finished" } else { "was reset" }
            );
            assert!(!a.handle.is_closed() && !b.handle.is_closed());
        }
    }

    /// A peer that advertised the capability but grants no stream (its policy does not
    /// carry) must not hold this side's stream lane for good: `send_side(Stream)` gives up
    /// with a refusal that says why, once, and the lane then refuses at once. Datagrams are
    /// unaffected.
    #[tokio::test]
    async fn a_peer_that_never_grants_its_stream_does_not_stall_the_stream_lane() {
        let (dialer, listener) = (endpoint(1, false), endpoint(2, true));
        let (mut d, mut l) = handshaken(&dialer, &listener).await;
        hellos(&mut d, &mut l, (hello(1), hello(1))).await;
        let (a, b) = admitted(d, l, (carrying(), Admission::default())).await;
        let marked = Bytes::from_static(&[SIDE_MARKER, 1, 2]);
        let first = tokio::time::timeout(
            Duration::from_secs(60),
            a.face.send_side(marked.clone(), SideClass::Stream),
        )
        .await
        .expect("send_side(Stream) returned instead of waiting for a grant that never comes");
        let Err(SideRefused::Io(why)) = first else {
            panic!("expected a refusal that says the peer granted no stream, got {first:?}");
        };
        assert!(why.contains("grant"), "{why}");
        // The lane is closed: the next send refuses at once, not after another wait.
        let second = tokio::time::timeout(
            Duration::from_secs(1),
            a.face.send_side(marked.clone(), SideClass::Stream),
        )
        .await
        .expect("a second send_side(Stream) refuses at once");
        assert!(matches!(second, Err(SideRefused::Io(_))), "{second:?}");
        // What was queued for the stream goes the same way: nothing waits behind it.
        a.face
            .send_side(marked.clone(), SideClass::Datagram)
            .await
            .unwrap();
        assert!(!a.handle.is_closed() && !b.handle.is_closed());
    }

    /// `quic_stats` reads the connection's own counters: a datagram a link sends is counted by
    /// the sender as a QUIC datagram frame and a UDP datagram, and by the receiver as received.
    #[tokio::test]
    async fn quic_stats_count_the_datagrams_a_link_carried() {
        let (dialer, listener) = (endpoint(1, false), endpoint(2, true));
        let (mut d, mut l) = handshaken(&dialer, &listener).await;
        hellos(&mut d, &mut l, (hello(1), hello(1))).await;
        let (a, b) = admitted(d, l, (carrying(), carrying())).await;
        let (sent, received) = (a.handle.quic_stats(), b.handle.quic_stats());
        let wire = Bytes::from_static(b"\x64\x03\x01\x02\x03");
        a.face.send_bytes(wire.clone()).await.unwrap();
        assert_eq!(b.face.recv_bytes().await.unwrap(), wire);
        let (sent_after, received_after) = (a.handle.quic_stats(), b.handle.quic_stats());
        assert_eq!(
            sent_after.frame_tx.datagram - sent.frame_tx.datagram,
            1,
            "the sender counted one datagram frame"
        );
        assert!(sent_after.udp_tx.datagrams > sent.udp_tx.datagrams);
        assert_eq!(
            received_after.frame_rx.datagram - received.frame_rx.datagram,
            1,
            "the receiver counted it"
        );
        assert!(received_after.udp_rx.datagrams > received.udp_rx.datagrams);
        assert!(sent_after.path.cwnd > 0);
    }

    /// A link that comes up with datagrams already queued on its connection still reads the
    /// octets queued, to the octet: what the connection's buffer holds beyond what it holds
    /// empty. The carrier takes no baseline from the buffer at link-up (it read one there, and
    /// a buffer that held N octets then read N too few for the life of the link, which admits
    /// that many NDN octets ahead of a channel frame). The datagrams are queued and the
    /// carrier built with no await between, so the connection's driver, on this
    /// single-threaded runtime, cannot send any of them first.
    #[tokio::test]
    async fn a_carrier_built_over_a_full_send_buffer_reads_what_is_queued() {
        let (dialer, listener) = (endpoint(1, false), endpoint(2, true));
        let (d, _l) = handshaken(&dialer, &listener).await;
        let connection = d.connection.clone();
        let empty = connection.datagram_send_buffer_space();
        for _ in 0..10 {
            connection
                .send_datagram(Bytes::from(vec![0x05u8; 1000]))
                .unwrap();
        }
        let held = empty - connection.datagram_send_buffer_space();
        assert!(
            held >= 10_000,
            "ten datagrams of 1000 octets are queued: {held}"
        );
        let side = SideCarrier::new(
            connection,
            true,
            true,
            ChannelPolicy {
                carry: true,
                quota: None,
            },
            None,
            Arc::new(std::sync::OnceLock::new()),
        );
        assert_eq!(
            side.limits().queued,
            held,
            "the carrier reads every octet the buffer holds, not those queued after it was built"
        );
    }

    /// What the queued-octets read rests on, of the QUIC library and of this crate's transport
    /// configuration: a connection's empty datagram send buffer reports its configured size
    /// less 32 octets of space, and each datagram queued takes its payload and 32 more off it.
    /// A library that counts otherwise (quinn-proto 0.11.16 took payload only and kept none in
    /// reserve) makes the read wrong, and fails here first.
    #[tokio::test]
    async fn the_send_buffer_counts_as_the_queued_octets_read_assumes() {
        let (dialer, listener) = (endpoint(1, false), endpoint(2, true));
        let (d, _l) = handshaken(&dialer, &listener).await;
        let connection = d.connection.clone();
        let empty = connection.datagram_send_buffer_space();
        assert_eq!(
            crate::side::DATAGRAM_SEND_BUFFER - empty,
            crate::side::DATAGRAM_RECORD,
            "an empty send buffer is configured at DATAGRAM_SEND_BUFFER and reports one record taken"
        );
        connection
            .send_datagram(Bytes::from(vec![0x05u8; 1000]))
            .unwrap();
        assert_eq!(
            empty - connection.datagram_send_buffer_space(),
            1000 + crate::side::DATAGRAM_RECORD,
            "a queued datagram takes its payload and one record"
        );
    }
}
