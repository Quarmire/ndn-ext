//! Probes: small UDP datagrams a device sends from its link socket to the
//! candidate addresses of a device it punches a direct path to. A probe
//! leaving through a NAT makes it keep a mapping for that pair of
//! addresses, so the QUIC handshake that follows on the same socket gets
//! through. Probes ride the link socket itself (the mapping a NAT keeps is
//! per source address and port); the socket hands every probe it receives
//! to the punch that waits for it and none to QUIC.
//!
//! Wire: 24 bytes, `00` ‖ ASCII `ndn-link probe` ‖ `01` ‖ the punch's
//! 8-byte session. No QUIC packet to a link socket is a probe: a long-header
//! packet starts with a byte whose top bit is set, and a short-header packet
//! to this endpoint's 8-byte connection IDs is at least 29 bytes (header
//! protection samples 16 bytes after a packet number of up to 4).

use std::collections::HashMap;
use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll, ready};

use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use tokio::sync::mpsc;

use crate::message::PathSession;

/// Length of a probe datagram.
pub const PROBE_LEN: usize = 24;
const PROBE_PREFIX: &[u8; 16] = b"\0ndn-link probe\x01";
/// Probes a punch takes from the socket before it reads them.
const PROBE_QUEUE: usize = 64;

/// The probe datagram of `session`.
pub fn encode_probe(session: &PathSession) -> [u8; PROBE_LEN] {
    let mut probe = [0u8; PROBE_LEN];
    probe[..16].copy_from_slice(PROBE_PREFIX);
    probe[16..].copy_from_slice(session);
    probe
}

/// The session a probe datagram names; `None` for anything else.
pub fn decode_probe(datagram: &[u8]) -> Option<PathSession> {
    if datagram.len() != PROBE_LEN || !datagram.starts_with(PROBE_PREFIX) {
        return None;
    }
    PathSession::try_from(&datagram[16..]).ok()
}

/// The punches waiting for probes on one socket, by session. Probes of a
/// session nobody waits for are dropped, so a stranger's probes cost no
/// state.
#[derive(Default)]
pub(crate) struct ProbeTap {
    watching: Mutex<HashMap<PathSession, mpsc::Sender<SocketAddr>>>,
}

impl ProbeTap {
    pub(crate) fn watch(self: &Arc<Self>, session: PathSession) -> ProbeWatch {
        let (tx, rx) = mpsc::channel(PROBE_QUEUE);
        self.watching
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(session, tx);
        ProbeWatch {
            tap: Arc::clone(self),
            session,
            rx,
        }
    }

    fn received(&self, session: PathSession, from: SocketAddr) {
        let watching = self.watching.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(tx) = watching.get(&session) {
            let _ = tx.try_send(from);
        }
    }
}

/// The probes of one punch's session that reach this socket, by source
/// address. Dropping it stops the watch.
pub struct ProbeWatch {
    tap: Arc<ProbeTap>,
    session: PathSession,
    rx: mpsc::Receiver<SocketAddr>,
}

impl ProbeWatch {
    /// The source address of the next probe of this session.
    pub async fn next(&mut self) -> Option<SocketAddr> {
        self.rx.recv().await
    }
}

impl Drop for ProbeWatch {
    fn drop(&mut self) {
        self.tap
            .watching
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&self.session);
    }
}

/// The link socket as QUIC sees it: every datagram but probes.
pub(crate) struct ProbeSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    tap: Arc<ProbeTap>,
}

impl fmt::Debug for ProbeSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProbeSocket").field("inner", &self.inner).finish()
    }
}

impl ProbeSocket {
    pub(crate) fn new(inner: Arc<dyn AsyncUdpSocket>, tap: Arc<ProbeTap>) -> Self {
        Self { inner, tap }
    }

    /// Send the probe of `session` to `to`, once the socket is writable.
    pub(crate) async fn send_probe(&self, to: SocketAddr, session: &PathSession) -> io::Result<()> {
        let probe = encode_probe(session);
        let destination = match (self.inner.local_addr()?.ip(), to.ip()) {
            (IpAddr::V6(_), IpAddr::V4(v4)) => SocketAddr::new(IpAddr::V6(v4.to_ipv6_mapped()), to.port()),
            _ => to,
        };
        let transmit = Transmit {
            destination,
            ecn: None,
            contents: &probe,
            segment_size: None,
            src_ip: None,
        };
        let mut poller = Arc::clone(&self.inner).create_io_poller();
        loop {
            match self.inner.try_send(&transmit) {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    std::future::poll_fn(|cx| poller.as_mut().poll_writable(cx)).await?;
                }
                sent => return sent,
            }
        }
    }
}

impl AsyncUdpSocket for ProbeSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Arc::clone(&self.inner).create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        self.inner.try_send(transmit)
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let n = ready!(self.inner.poll_recv(cx, bufs, meta))?;
        for (m, buf) in meta.iter_mut().zip(bufs.iter()).take(n) {
            // Datagrams of one RecvMeta come from one source and, but for
            // the last, are `stride` long; probes are taken only when every
            // one of them is a probe.
            if m.stride != PROBE_LEN || m.len == 0 {
                continue;
            }
            let segments: Vec<&[u8]> = buf[..m.len].chunks(PROBE_LEN).collect();
            let sessions: Vec<PathSession> = segments.iter().filter_map(|s| decode_probe(s)).collect();
            if sessions.len() != segments.len() {
                continue;
            }
            let from = SocketAddr::new(m.addr.ip().to_canonical(), m.addr.port());
            for session in sessions {
                self.tap.received(session, from);
            }
            // QUIC skips a datagram of no bytes.
            m.len = 0;
        }
        Poll::Ready(Ok(n))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner.max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_probe_names_its_session_and_nothing_else_is_a_probe() {
        let session = [9, 8, 7, 6, 5, 4, 3, 2];
        let probe = encode_probe(&session);
        assert_eq!(
            probe,
            [
                0x00, b'n', b'd', b'n', b'-', b'l', b'i', b'n', b'k', b' ', b'p', b'r', b'o', b'b', b'e', 0x01, 9, 8,
                7, 6, 5, 4, 3, 2
            ]
        );
        assert_eq!(decode_probe(&probe), Some(session));
        assert_eq!(decode_probe(&probe[..23]), None);
        let mut other = probe;
        other[15] = 0x02;
        assert_eq!(decode_probe(&other), None);
        // A QUIC long-header packet starts with its top bit set.
        other[0] = 0xC0;
        assert_eq!(decode_probe(&other), None);
    }
}
