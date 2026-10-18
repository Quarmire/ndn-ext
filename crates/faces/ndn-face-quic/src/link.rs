//! A link after its handshake: the hello exchange, the admission verdicts,
//! and the face it becomes.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use quinn::{ConnectionError, SendDatagramError};
use tracing::trace;

use ndn_transport::{FaceError, FaceId, FaceKind, Transport, ip_face_uri};

use crate::endpoint::Permit;
use crate::key::{KeyFingerprint, PeerKey};
use crate::message::{
    CloseReason, LINK_HELLO, LINK_VERDICT, LinkHello, LinkVerdict, MAX_MESSAGE, split_tlv,
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
    local: Option<SocketAddr>,
    control: Option<(quinn::SendStream, quinn::RecvStream)>,
}

impl Handshaken {
    pub(crate) fn new(
        connection: quinn::Connection,
        direction: Direction,
        permit: Option<Permit>,
        local: Option<SocketAddr>,
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
            local,
            control: None,
        })
    }

    pub fn peer_key(&self) -> &PeerKey {
        &self.peer
    }

    pub fn direction(&self) -> Direction {
        self.direction
    }

    pub fn remote_address(&self) -> SocketAddr {
        self.connection.remote_address()
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
            let _ = send.finish();
            LinkVerdict::decode(&theirs).map_err(LinkError::Protocol)
        };
        let peer_verdict = match tokio::time::timeout(deadline, verdicts).await {
            Ok(Ok(verdict)) => verdict,
            Ok(Err(e)) => return Err(self.fail(e, deadline)),
            Err(_) => return Err(self.fail(LinkError::Timeout, deadline)),
        };
        drop(self.permit.take());
        let local = self.local.map(|addr| ip_face_uri("quic", addr));
        let remote = self.connection.remote_address();
        trace!(target: "face.quic", face = %id, peer = %remote, scoped = admission.scope.is_some(), "link admitted");
        let scope = admission.scope.map(|s| Arc::new(ScopeState::new(s)));
        let local_answers = scope.as_ref().map(|_| {
            let (tx, rx) = tokio::sync::mpsc::channel(LOCAL_ANSWERS);
            (tx, tokio::sync::Mutex::new(rx))
        });
        Ok(Link {
            face: LinkFace {
                id,
                connection: self.connection.clone(),
                remote_uri: ip_face_uri("quic", remote),
                local_uri: local,
                scope: scope.clone(),
                local_answers,
            },
            handle: LinkHandle {
                connection: self.connection,
                scope,
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
    let closed = |e: String| match connection.close_reason() {
        Some(reason) => LinkError::from_connection(reason),
        None => LinkError::Protocol(e),
    };
    // A TLV header is at most 1 + 9 + 1 + 9 bytes; read it a byte at a time
    // until it parses, then the value.
    let mut buf: Vec<u8> = Vec::with_capacity(512);
    loop {
        let mut byte = [0u8; 1];
        recv.read_exact(&mut byte).await.map_err(|e| closed(e.to_string()))?;
        buf.push(byte[0]);
        if let Some((t, start, len)) = header(&buf) {
            if t != expected {
                return Err(LinkError::Protocol(format!(
                    "expected link message {expected:#x}, got {t:#x}"
                )));
            }
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
            return Ok(Bytes::copy_from_slice(&buf[start..end]));
        }
        if buf.len() > 20 {
            return Err(LinkError::Protocol("unreadable link message header".into()));
        }
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

/// Closes a link and tells when it ended.
#[derive(Clone)]
pub struct LinkHandle {
    connection: quinn::Connection,
    scope: Option<Arc<ScopeState>>,
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

    pub fn remote_address(&self) -> SocketAddr {
        self.connection.remote_address()
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
}

/// The face of a link: each NDNLPv2 frame is one QUIC datagram. The face's
/// link service frames and fragments packets to [`send_mtu`]
/// (Transport::send_mtu), the connection's current datagram size, which
/// grows as path MTU discovery finds room. A scoped link's face drops what
/// its [`LinkScope`] does not carry, both ways.
pub struct LinkFace {
    id: FaceId,
    connection: quinn::Connection,
    remote_uri: String,
    local_uri: Option<String>,
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

    fn remote_uri(&self) -> Option<String> {
        Some(self.remote_uri.clone())
    }

    fn local_uri(&self) -> Option<String> {
        self.local_uri.clone()
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
