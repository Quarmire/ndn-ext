//! The ring carrier: a one-writer, many-reader broadcast ring as a [`Transport`], for channel
//! frames between processes of one host (docs/specs/channel.md, the carrier a face must provide).
//!
//! A [`RingFace`] is one end of a [`BroadcastWriter`]/[`BroadcastReader`] ring
//! ([`spsc`](crate::spsc)): the sender's process **offers** the ring ([`RingFace::offer`]) and a
//! receiver's process **attaches** to it ([`RingFace::attach`]); the host adds each face to its
//! forwarder, whose side table routes the frames (the writer is a sink, a reader a route's source).
//!
//! * **The writer is send-only.** [`send_side`](Transport::send_side) and
//!   [`forward_side`](Transport::forward_side) publish one frame into the ring and never wait: the
//!   ring is lossy, a reader that falls more than [`RING_SLOTS`] frames behind is lapped and counts
//!   it ([`RingStats::lapped`]), the writer is never paced. Only the datagram class exists (a
//!   lossy ring has no reliable stream): a stream-class frame is refused
//!   [`NotCarried`](SideRefused::NotCarried), which the forwarder counts as `class_unsupported`.
//!   NDN packets never travel on a ring: `send_bytes` is refused.
//! * **A reader is receive-only, and cannot forge.** It maps the ring's data region read-only: the
//!   region is a sealed memfd (`F_SEAL_FUTURE_WRITE`, `F_SEAL_SHRINK`, `F_SEAL_GROW`), so no
//!   writable mapping, `write(2)` or `ftruncate` of it succeeds through *any* descriptor of it
//!   (a `/proc/self/fd/N` reopen with `O_RDWR` included) — this holds against a reader of the
//!   **same uid** too. A reader owns only a registry page of its own (it can neither write the
//!   other readers' wake flags nor reach the header a later attach reads, and no reader can
//!   shrink a region under the writer), and its face carries nothing out
//!   ([`side_frame_max`](Transport::side_frame_max) is 0). A frame is what the writer's process
//!   wrote, so a local reader needs no per-frame signature to know where a frame came from.
//!   *Not Linux:* there is no `memfd` sealing; the data fd is an `O_RDONLY` open of a `0o600`
//!   object, which keeps readers of other uids from writing the ring, and a same-uid process that
//!   can reopen the object read-write is not stopped.
//! * **Exact-size frames.** A frame is published with its own length and read with it: no padding,
//!   no `Name`/`Data` dressing.
//! * **End of stream.** The writer's drop publishes a one-octet frame (`0x00`, [`EOS`]); a channel
//!   frame has at least [`CHANNEL_FRAME_MIN`] (36) octets, so the two are told apart by length
//!   alone. A reader that reads it ends: [`recv_bytes`](Transport::recv_bytes) answers
//!   [`FaceError::Closed`] and [`RingFace::ended_cleanly`] says the writer ended, rather than
//!   died (the ring's wake pipe closing without it). Any other frame that is not a channel frame
//!   (not marked, or shorter than 36 octets) is dropped and counted ([`RingStats::malformed`]):
//!   it never reaches the forwarder's NDN pipeline.
//! * **Who may attach.** The ring is found by the control socket `/tmp/.ndn-shm-ctl-<hash>.sock`
//!   named by [`rendezvous_token`] of the ring's name, and the handoff of its fds is gated by
//!   [`capability_token`], which binds a 32-octet secret (it travels inside the channel's sealed
//!   session record, so only its audience holds it) to the name. A client that does not hold the
//!   secret fails the mutual authentication and learns nothing, and a producer that does not
//!   hold it fails the client's check.
//!
//! The handoff protocol, the ring and its mutual authentication are `spsc.rs`'s, unchanged. The
//! rendezvous, capability and exclusive-bind helpers (`rendezvous_token`, `capability_token`,
//! `bind_exclusive`, `sealed_geometry`, the attach retry) are this file's, labelled
//! `ndn-channel\0…`.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use ndn_foundation_types::Name;
use ndn_transport::{FaceError, FaceId, FaceKind, SIDE_MARKER, SideClass, SideRefused, Transport};

use crate::ShmError;
use crate::spsc::{
    BroadcastReader, BroadcastWriter, ShmToken, connect_broadcast_handoff, control_socket_path,
    serve_broadcast_handoff,
};

/// Slots in a ring: a reader that falls this many frames behind is lapped.
pub const RING_SLOTS: u32 = 256;

/// Readers one ring serves at a time. A reader that leaves (its end of the wakeup pipe closes)
/// frees its place, so a ring serves any number of readers over its life; when all places are held
/// by live readers an attach is [`Declined`](RingError::Declined) with that reason.
pub const RING_READERS: u32 = 32;

/// Octets a slot has beyond the longest frame (the ring's own bookkeeping per slot is separate).
pub const RING_SLOT_HEADROOM: usize = 256;

/// The longest frame a ring can be offered for: 256 slots of it stay within the ring's mapping
/// bound.
pub const RING_FRAME_MAX: usize = 1 << 20;

/// The one-octet frame the writer publishes when it ends cleanly.
pub const EOS: u8 = 0x00;

/// The fewest octets a channel frame has (docs/specs/channel.md, the frame): a frame this short
/// or shorter than this is not one, and a one-octet frame is [`EOS`].
pub const CHANNEL_FRAME_MIN: usize = 36;

/// Attach attempts: a reader that finds the control socket bound but not yet accepting (the
/// writer's process is starting) tries this many times, [`ATTACH_PAUSE`] apart.
pub const ATTACH_TRIES: u32 = 100;

/// The pause between attach attempts.
pub const ATTACH_PAUSE: Duration = Duration::from_millis(20);

/// The secret a ring's attach is gated by: 32 octets from a CSPRNG, one per ring.
pub type RingSecret = [u8; 32];

const RENDEZVOUS_LABEL: &[u8] = b"ndn-channel\x00rendezvous\x00";
const CAPABILITY_LABEL: &[u8] = b"ndn-channel\x00capability\x00";

/// Why a ring was not offered or attached, and what to do.
#[derive(Debug, thiserror::Error)]
pub enum RingError {
    /// No control socket of the ring's name is served on this host.
    #[error(
        "no ring of this name is served on this host (no live listener at {0}): the sender is on \
         another host or has ended; use the link carriers"
    )]
    NotHere(PathBuf),
    /// Another live process serves the name.
    #[error(
        "a live process already serves this ring name ({0}): a ring is offered once per channel; \
         the channel id is random, so this is a second offer of the same channel"
    )]
    AlreadyServed(PathBuf),
    /// The two ends do not share the secret.
    #[error(
        "the ring's owner and this process do not share the ring's secret (mutual authentication \
         failed): attach with the secret from the channel's session record; a different process \
         may have taken the ring's name"
    )]
    Refused,
    /// The ring's owner had no place for this reader, or could not set one up: it said why.
    #[error("the ring's owner declined the attach: {0}")]
    Declined(String),
    /// The ring was found but gave no ring: its control socket did not answer within
    /// [`HANDSHAKE_TIMEOUT`](crate::spsc::HANDSHAKE_TIMEOUT), or would not hand its fds over
    /// within [`ATTACH_TRIES`] tries.
    #[error(
        "the ring accepted no attach in {ms} ms ({last}): the sender's process is not serving \
         it; try again, or use the link carriers"
    )]
    NotServing {
        /// Milliseconds spent trying.
        ms: u128,
        /// The last error.
        last: String,
    },
    /// The frame limit asked of a ring is unusable.
    #[error(
        "a ring takes frames of {min} to {max} octets and {asked} was asked: use the carrier's \
         frame limit"
    )]
    FrameMax {
        /// The frame limit asked.
        asked: usize,
        /// The least.
        min: usize,
        /// The most.
        max: usize,
    },
    /// The ring's shared memory.
    #[error("shm: {0}")]
    Shm(#[from] ShmError),
    /// The control socket.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// What a ring face counted.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RingStats {
    /// Frames the writer published (writer), or the ring's own count of them (reader).
    pub published: u64,
    /// Frames the reader handed to the forwarder.
    pub received: u64,
    /// Frames the reader lost because the writer lapped it.
    pub lapped: u64,
    /// Frames the reader dropped because they were not channel frames.
    pub malformed: u64,
    /// Frames the writer refused because they asked for the stream class.
    pub class_refused: u64,
}

/// The token a ring is **found** by: the control socket's path derives from it. Anyone who knows
/// the ring's name can find (not attach to) the ring.
pub fn rendezvous_token(ring: &Name) -> ShmToken {
    sha256_parts(&[RENDEZVOUS_LABEL, &ring.encode_to_tlv()])
}

/// The token a ring's attach is **gated** by: bound to the ring's name (a secret cannot be lifted
/// to another ring) and domain-separated from [`rendezvous_token`].
pub fn capability_token(ring: &Name, secret: &[u8]) -> ShmToken {
    sha256_parts(&[CAPABILITY_LABEL, &ring.encode_to_tlv(), secret])
}

fn sha256_parts(parts: &[&[u8]]) -> ShmToken {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    let mut t = [0u8; 32];
    t.copy_from_slice(&h.finalize());
    t
}

/// Where a ring named `ring` is served on this host.
pub fn control_path(ring: &Name) -> PathBuf {
    control_socket_path(&rendezvous_token(ring))
}

/// Whether a ring named `ring` is served on this host now: its control socket exists (a stale
/// one, left by a crashed writer, exists too and refuses the attach).
pub fn served_here(ring: &Name) -> bool {
    control_path(ring).exists()
}

/// The ring's geometry for frames of at most `frame_max` octets: [`RING_SLOTS`] slots of
/// `frame_max` + [`RING_SLOT_HEADROOM`] octets. Returns `(capacity, slot_size)`.
pub fn sealed_geometry(frame_max: usize) -> (u32, u32) {
    (RING_SLOTS, (frame_max + RING_SLOT_HEADROOM) as u32)
}

/// Bind a writer's control socket **exclusively**: refuse to hijack a live owner. If the path is
/// in use it is probed: a live listener is an error (the name is served), a stale socket (no
/// listener, a crashed writer's) is reclaimed. The probe is bounded (one second): a listener
/// whose backlog is full is live. The listener does not count the probe's connect-and-close as an
/// unauthorized attempt.
pub fn bind_exclusive(path: &Path) -> Result<tokio::net::UnixListener, RingError> {
    match tokio::net::UnixListener::bind(path) {
        Ok(l) => Ok(l),
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
            let probe = crate::spsc::connect_bounded(path, std::time::Instant::now() + PROBE_WAIT);
            match probe {
                Ok(_) => return Err(RingError::AlreadyServed(path.to_path_buf())),
                Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                    return Err(RingError::AlreadyServed(path.to_path_buf()));
                }
                Err(_) => {}
            }
            let _ = std::fs::remove_file(path);
            tokio::net::UnixListener::bind(path).map_err(RingError::Io)
        }
        Err(e) => Err(RingError::Io(e)),
    }
}

/// How long [`bind_exclusive`] waits for a socket already at the path to accept its probe.
const PROBE_WAIT: Duration = Duration::from_secs(1);

enum End {
    Writer {
        ring: Arc<BroadcastWriter>,
        frame_max: usize,
        serve: tokio::task::JoinHandle<()>,
        path: PathBuf,
    },
    Reader {
        reader: BroadcastReader,
    },
}

/// One end of a channel ring as a face. See the [module](self).
pub struct RingFace {
    id: FaceId,
    end: End,
    /// Published (writer) or handed over (reader).
    counted: AtomicU64,
    malformed: AtomicU64,
    class_refused: AtomicU64,
    ended: AtomicBool,
    clean: AtomicBool,
}

impl RingFace {
    /// Offer a ring named `ring` for frames of at most `frame_max` octets, gated by `secret`: bind
    /// its control socket exclusively and serve the handoff to every reader that proves the secret
    /// (up to [`RING_READERS`]). Must run within a Tokio runtime. The returned face is the writer.
    pub async fn offer(
        id: FaceId,
        ring: &Name,
        secret: &RingSecret,
        frame_max: usize,
    ) -> Result<Self, RingError> {
        if !(CHANNEL_FRAME_MIN..=RING_FRAME_MAX).contains(&frame_max) {
            return Err(RingError::FrameMax {
                asked: frame_max,
                min: CHANNEL_FRAME_MIN,
                max: RING_FRAME_MAX,
            });
        }
        let (capacity, slot_size) = sealed_geometry(frame_max);
        let writer = Arc::new(BroadcastWriter::create(capacity, slot_size, RING_READERS)?);
        let path = control_path(ring);
        let listener = bind_exclusive(&path)?;
        let capability = capability_token(ring, secret);
        let serving = Arc::clone(&writer);
        let serve = tokio::spawn(async move {
            let _ = serve_broadcast_handoff(listener, capability, serving).await;
        });
        Ok(Self::new(
            id,
            End::Writer {
                ring: writer,
                frame_max,
                serve,
                path,
            },
        ))
    }

    /// Attach to the ring named `ring` served on this host, proving `secret`. A reader sees the
    /// frames published after it attached, not the ones before (the ring is lossy and keeps no
    /// backlog for a reader to catch up from). Must run within a Tokio runtime.
    ///
    /// [`NotHere`](RingError::NotHere) at once when no control socket of that name exists: a
    /// receiver attaches iff the ring is served on this host. A bound socket that is not yet
    /// accepting is retried [`ATTACH_TRIES`] times, [`ATTACH_PAUSE`] apart, off the runtime's
    /// threads; a failed authentication ([`Refused`](RingError::Refused)) is final at once, and so
    /// is an owner that answers nothing within [`HANDSHAKE_TIMEOUT`](crate::spsc::HANDSHAKE_TIMEOUT)
    /// ([`NotServing`](RingError::NotServing), which says so) — an attach never waits for ever on a
    /// silent socket — and an owner with no place for the reader
    /// ([`Declined`](RingError::Declined), with its reason).
    pub async fn attach(id: FaceId, ring: &Name, secret: &[u8]) -> Result<Self, RingError> {
        let path = control_path(ring);
        if !path.exists() {
            return Err(RingError::NotHere(path));
        }
        let capability = capability_token(ring, secret);
        let started = std::time::Instant::now();
        let mut tried = 0u32;
        let (data, reg, wake, idx) = loop {
            let p = path.clone();
            let attempt =
                tokio::task::spawn_blocking(move || connect_broadcast_handoff(&p, &capability))
                    .await
                    .map_err(|e| RingError::Io(std::io::Error::other(format!("join: {e}"))))?;
            match attempt {
                Ok(parts) => break parts,
                Err(ShmError::Io(e)) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                    return Err(RingError::Refused);
                }
                Err(ShmError::Refused(why)) => return Err(RingError::Declined(why)),
                Err(ShmError::Io(e)) if e.kind() == std::io::ErrorKind::TimedOut => {
                    return Err(RingError::NotServing {
                        ms: started.elapsed().as_millis(),
                        last: e.to_string(),
                    });
                }
                Err(_) if tried + 1 < ATTACH_TRIES => {
                    tried += 1;
                    tokio::time::sleep(ATTACH_PAUSE).await;
                }
                Err(ShmError::Io(e))
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
                    ) =>
                {
                    return Err(RingError::NotHere(path));
                }
                Err(e) => {
                    return Err(RingError::NotServing {
                        ms: started.elapsed().as_millis(),
                        last: e.to_string(),
                    });
                }
            }
        };
        let reader = BroadcastReader::from_fds(data, reg, wake, idx)?;
        Ok(Self::new(id, End::Reader { reader }))
    }

    fn new(id: FaceId, end: End) -> Self {
        Self {
            id,
            end,
            counted: AtomicU64::new(0),
            malformed: AtomicU64::new(0),
            class_refused: AtomicU64::new(0),
            ended: AtomicBool::new(false),
            clean: AtomicBool::new(false),
        }
    }

    /// What this end counted.
    pub fn stats(&self) -> RingStats {
        let (published, received, lapped) = match &self.end {
            End::Writer { ring, .. } => (ring.published(), 0, 0),
            End::Reader { reader } => (
                reader.published(),
                self.counted.load(Ordering::Relaxed),
                reader.dropped(),
            ),
        };
        RingStats {
            published,
            received,
            lapped,
            malformed: self.malformed.load(Ordering::Relaxed),
            class_refused: self.class_refused.load(Ordering::Relaxed),
        }
    }

    /// Whether this is the writer's end.
    pub fn is_writer(&self) -> bool {
        matches!(self.end, End::Writer { .. })
    }

    /// The readers the writer has handed the ring to (0 on a reader).
    pub fn readers(&self) -> usize {
        match &self.end {
            End::Writer { ring, .. } => ring.consumer_count(),
            End::Reader { .. } => 0,
        }
    }

    /// Whether a reader has seen the ring end, and whether the writer ended it by its
    /// end-of-stream frame (`Some(true)`) or died without one (`Some(false)`); `None` while the
    /// ring lives.
    pub fn ended_cleanly(&self) -> Option<bool> {
        self.ended
            .load(Ordering::Acquire)
            .then(|| self.clean.load(Ordering::Relaxed))
    }

    /// The writer's publish: every refusal the side path has, and the ring's own.
    fn publish(&self, frame: &Bytes, class: SideClass) -> Result<(), SideRefused> {
        let End::Writer {
            ring, frame_max, ..
        } = &self.end
        else {
            return Err(SideRefused::NotCarried);
        };
        if class == SideClass::Stream {
            self.class_refused.fetch_add(1, Ordering::Relaxed);
            return Err(SideRefused::NotCarried);
        }
        // A short frame would be read as the end of the stream (one octet) or dropped as
        // malformed (under 36): refuse it here, where the sender can be told.
        if frame.first() != Some(&SIDE_MARKER) || frame.len() < CHANNEL_FRAME_MIN {
            return Err(SideRefused::Malformed);
        }
        if frame.len() > *frame_max {
            return Err(SideRefused::TooLarge {
                size: frame.len(),
                max: *frame_max,
            });
        }
        ring.publish(frame);
        Ok(())
    }
}

/// What a frame read from a ring is.
#[derive(Debug, PartialEq, Eq)]
enum Read {
    /// The writer ended.
    Eos,
    /// A channel frame.
    Channel,
    /// Neither.
    Malformed,
}

/// Tell the writer's end-of-stream frame from a channel frame by length alone.
fn classify(frame: &[u8]) -> Read {
    if frame.len() == 1 && frame[0] == EOS {
        Read::Eos
    } else if frame.first() == Some(&SIDE_MARKER) && frame.len() >= CHANNEL_FRAME_MIN {
        Read::Channel
    } else {
        Read::Malformed
    }
}

impl Drop for RingFace {
    fn drop(&mut self) {
        if let End::Writer {
            ring, serve, path, ..
        } = &self.end
        {
            // A clean end tells the readers apart from a crash; then the listener goes.
            ring.publish(&[EOS]);
            serve.abort();
            let _ = std::fs::remove_file(path);
        }
    }
}

impl Transport for RingFace {
    fn id(&self) -> FaceId {
        self.id
    }

    fn kind(&self) -> FaceKind {
        FaceKind::Shm
    }

    /// The longest channel frame the writer publishes (the ring's slot less its headroom); 0 on a
    /// reader, which carries nothing out.
    fn side_frame_max(&self) -> usize {
        match &self.end {
            End::Writer { frame_max, .. } => *frame_max,
            End::Reader { .. } => 0,
        }
    }

    /// A lossy broadcast ring has no ordered, reliable stream: the datagram class only, and
    /// only on a writer (a reader carries nothing out).
    fn side_carries(&self, class: SideClass) -> bool {
        class == SideClass::Datagram && self.side_frame_max() != 0
    }

    /// Publish one frame into the ring. Datagram class only; see [`forward_side`](Self::forward_side).
    async fn send_side(&self, frame: Bytes, class: SideClass) -> Result<(), SideRefused> {
        self.publish(&frame, class)
    }

    /// Publish one frame into the ring, which never waits and is never full: a reader that does
    /// not keep up is lapped and counts it. A stream-class frame is refused
    /// [`NotCarried`](SideRefused::NotCarried) (a lossy ring has no reliable stream), a frame
    /// that is not a channel frame [`Malformed`](SideRefused::Malformed), one over the ring's
    /// frame limit [`TooLarge`](SideRefused::TooLarge), and a reader's end refuses every frame
    /// `NotCarried`.
    fn forward_side(&self, frame: Bytes, class: SideClass) -> Result<(), SideRefused> {
        self.publish(&frame, class)
    }

    /// The next channel frame of the ring, on a reader; never on a writer. The writer's
    /// end-of-stream frame ends the face ([`FaceError::Closed`]), and a frame that is not a channel
    /// frame is dropped and counted, never returned: nothing a ring carries reaches the forwarder as
    /// an NDN packet.
    async fn recv_bytes(&self) -> Result<Bytes, FaceError> {
        let End::Reader { reader } = &self.end else {
            return std::future::pending().await;
        };
        loop {
            if self.ended.load(Ordering::Acquire) {
                return Err(FaceError::Closed);
            }
            let Some(frame) = reader.recv().await else {
                // The wake pipe closed with no end-of-stream frame: the writer died.
                self.ended.store(true, Ordering::Release);
                return Err(FaceError::Closed);
            };
            match classify(&frame) {
                Read::Channel => {
                    self.counted.fetch_add(1, Ordering::Relaxed);
                    return Ok(Bytes::from(frame));
                }
                Read::Eos => {
                    self.clean.store(true, Ordering::Relaxed);
                    self.ended.store(true, Ordering::Release);
                    return Err(FaceError::Closed);
                }
                Read::Malformed => {
                    self.malformed.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }

    /// NDN packets never travel on a ring.
    async fn send_bytes(&self, _wire: Bytes) -> Result<(), FaceError> {
        Err(FaceError::Io(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "a channel ring carries channel frames only: send an NDN packet on a link or the local face",
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    fn ring_name(tag: &str) -> Name {
        format!(
            "/ring-test/{}/{tag}/32=chan/32=ring/00ff",
            std::process::id()
        )
        .parse()
        .unwrap()
    }

    /// A channel frame of `len` octets whose second octet and tail say which frame it is.
    fn frame(len: usize, n: u8) -> Bytes {
        let mut v = vec![n; len];
        v[0] = SIDE_MARKER;
        Bytes::from(v)
    }

    const SECRET: RingSecret = [0x5a; 32];

    async fn recv(face: &RingFace) -> Result<Bytes, FaceError> {
        tokio::time::timeout(Duration::from_secs(3), face.recv_bytes())
            .await
            .expect("a frame within 3 s")
    }

    /// Whether the face has a frame waiting now (it does not wait for one).
    async fn nothing_waiting(face: &RingFace) -> bool {
        tokio::time::timeout(Duration::from_millis(150), face.recv_bytes())
            .await
            .is_err()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn every_reader_receives_what_the_writer_publishes_byte_identical_and_in_order() {
        let name = ring_name("every");
        let writer = RingFace::offer(FaceId(1), &name, &SECRET, 1400)
            .await
            .unwrap();
        assert!(writer.is_writer());
        assert_eq!(writer.side_frame_max(), 1400);
        let a = RingFace::attach(FaceId(2), &name, &SECRET).await.unwrap();
        let b = RingFace::attach(FaceId(3), &name, &SECRET).await.unwrap();
        assert_eq!(writer.readers(), 2);

        // Exact sizes: the shortest channel frame, a middling one, the longest the ring takes.
        let sent = [frame(CHANNEL_FRAME_MIN, 1), frame(777, 2), frame(1400, 3)];
        for f in &sent {
            writer
                .send_side(f.clone(), SideClass::Datagram)
                .await
                .unwrap();
        }
        for reader in [&a, &b] {
            for f in &sent {
                assert_eq!(&recv(reader).await.unwrap(), f);
            }
            assert_eq!(reader.stats().received, 3);
            assert_eq!(reader.stats().lapped, 0);
        }
        assert_eq!(writer.stats().published, 3);
        // `forward_side`, the forwarder's call, publishes the same.
        writer
            .forward_side(frame(100, 9), SideClass::Datagram)
            .unwrap();
        assert_eq!(recv(&a).await.unwrap(), frame(100, 9));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_reader_cannot_write_the_ring_by_face_or_by_mapping() {
        let name = ring_name("ro");
        let writer = RingFace::offer(FaceId(1), &name, &SECRET, 200)
            .await
            .unwrap();
        let reader = RingFace::attach(FaceId(2), &name, &SECRET).await.unwrap();

        // By face: a reader carries nothing out, in either class or by either call.
        assert_eq!(reader.side_frame_max(), 0);
        for class in [SideClass::Datagram, SideClass::Stream] {
            assert_eq!(
                reader.send_side(frame(100, 1), class).await,
                Err(SideRefused::NotCarried)
            );
            assert_eq!(
                reader.forward_side(frame(100, 1), class),
                Err(SideRefused::NotCarried)
            );
        }
        assert!(reader.send_bytes(frame(100, 1)).await.is_err());
        assert_eq!(
            writer.stats().published,
            0,
            "nothing the reader tried reached the ring"
        );

        // By mapping: the fd the ring hands a reader cannot be mapped writable, so a process
        // that holds the secret and the fd still cannot forge a frame another reader sees.
        let path = control_path(&name);
        let cap = capability_token(&name, &SECRET);
        let (data, _reg, _wake, _idx) =
            tokio::task::spawn_blocking(move || connect_broadcast_handoff(&path, &cap))
                .await
                .unwrap()
                .unwrap();
        let rw = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                data.as_raw_fd(),
                0,
            )
        };
        assert_eq!(
            rw,
            libc::MAP_FAILED,
            "a writable mapping of the data region is refused"
        );
        // A sealed memfd refuses with EPERM (Linux); an O_RDONLY fd of a shm object with EACCES.
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(if cfg!(target_os = "linux") {
                libc::EPERM
            } else {
                libc::EACCES
            })
        );
        let ro = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ,
                libc::MAP_SHARED,
                data.as_raw_fd(),
                0,
            )
        };
        assert_ne!(
            ro,
            libc::MAP_FAILED,
            "a read-only mapping is what a reader gets"
        );
        unsafe { libc::munmap(ro, 4096) };
        // And the writer's frames are still what the reader reads.
        writer
            .send_side(frame(60, 4), SideClass::Datagram)
            .await
            .unwrap();
        assert_eq!(recv(&reader).await.unwrap(), frame(60, 4));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_attach_refuses_a_wrong_secret_at_once_and_the_ring_still_serves_the_right_one() {
        let name = ring_name("cap");
        let writer = RingFace::offer(FaceId(1), &name, &SECRET, 200)
            .await
            .unwrap();
        let started = std::time::Instant::now();
        // A wrong secret, then the secret of another ring of the same name's digest, then none.
        for wrong in [&[0x11u8; 32][..], &SECRET[..31], &[]] {
            match RingFace::attach(FaceId(9), &name, wrong).await {
                Err(RingError::Refused) => {}
                Err(e) => panic!("a wrong capability must be Refused, got: {e}"),
                Ok(_) => panic!("a wrong capability was handed the ring"),
            }
        }
        assert!(
            started.elapsed() < ATTACH_PAUSE * 20,
            "a refusal is final, not retried for {ATTACH_TRIES} tries: {:?}",
            started.elapsed()
        );
        assert_eq!(
            writer.readers(),
            0,
            "no reader was registered for a refused attach"
        );
        // The ring still serves the holder of the secret (three refusals did not end it).
        let reader = RingFace::attach(FaceId(2), &name, &SECRET).await.unwrap();
        writer
            .send_side(frame(50, 7), SideClass::Datagram)
            .await
            .unwrap();
        assert_eq!(recv(&reader).await.unwrap(), frame(50, 7));
        // The secret is bound to the name: it opens no other ring.
        let other = ring_name("cap-other");
        let _other_writer = RingFace::offer(FaceId(3), &other, &[0x99; 32], 200)
            .await
            .unwrap();
        assert!(matches!(
            RingFace::attach(FaceId(4), &other, &SECRET).await,
            Err(RingError::Refused)
        ));
    }

    #[test]
    fn the_two_tokens_of_a_ring_are_distinct_and_labelled_for_the_channel() {
        let n = ring_name("tokens");
        assert_ne!(rendezvous_token(&n), capability_token(&n, &[]));
        assert_ne!(capability_token(&n, b"a"), capability_token(&n, b"b"));
        assert_ne!(
            capability_token(&n, b"a"),
            capability_token(&ring_name("tokens2"), b"a"),
            "a secret cannot be lifted to another ring"
        );
        // The labels are the channel's: a rendezvous and a capability of one name never collide.
        assert_eq!(
            rendezvous_token(&n),
            sha256_parts(&[b"ndn-channel\x00rendezvous\x00", &n.encode_to_tlv()])
        );
        assert_ne!(
            rendezvous_token(&n),
            sha256_parts(&[b"ndn-channel\x00capability\x00", &n.encode_to_tlv()])
        );
        assert_eq!(
            capability_token(&n, b"s"),
            sha256_parts(&[b"ndn-channel\x00capability\x00", &n.encode_to_tlv(), b"s"])
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_name_no_one_serves_is_not_here_at_once() {
        let name = ring_name("nobody");
        assert!(!served_here(&name));
        let started = std::time::Instant::now();
        assert!(matches!(
            RingFace::attach(FaceId(1), &name, &SECRET).await,
            Err(RingError::NotHere(_))
        ));
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "no retries for an absent socket"
        );
        // A crashed writer's stale socket is no ring either: the attach says so after its
        // tries, and an offer of the name reclaims the path.
        let path = control_path(&name);
        drop(std::os::unix::net::UnixListener::bind(&path).unwrap());
        assert!(path.exists());
        assert!(matches!(
            RingFace::attach(FaceId(1), &name, &SECRET).await,
            Err(RingError::NotHere(_))
        ));
        let writer = RingFace::offer(FaceId(2), &name, &SECRET, 100)
            .await
            .unwrap();
        assert!(served_here(&name));
        drop(writer);
        assert!(
            !served_here(&name),
            "a writer that ends takes its socket with it"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_name_is_offered_once_and_a_live_ring_is_not_hijacked() {
        let name = ring_name("twice");
        let first = RingFace::offer(FaceId(1), &name, &SECRET, 100)
            .await
            .unwrap();
        match RingFace::offer(FaceId(2), &name, &SECRET, 100).await {
            Err(RingError::AlreadyServed(_)) => {}
            Err(e) => panic!("a second offer of a live name must be AlreadyServed, got: {e}"),
            Ok(_) => panic!("a live ring's name was taken over"),
        }
        // The first is untouched.
        let reader = RingFace::attach(FaceId(3), &name, &SECRET).await.unwrap();
        first
            .send_side(frame(40, 1), SideClass::Datagram)
            .await
            .unwrap();
        assert_eq!(recv(&reader).await.unwrap(), frame(40, 1));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_reader_that_attaches_late_misses_the_earlier_frames_and_the_ring_says_so() {
        let name = ring_name("late");
        let writer = RingFace::offer(FaceId(1), &name, &SECRET, 100)
            .await
            .unwrap();
        for n in 1..=5u8 {
            writer
                .send_side(frame(50, n), SideClass::Datagram)
                .await
                .unwrap();
        }
        let late = RingFace::attach(FaceId(2), &name, &SECRET).await.unwrap();
        assert!(
            nothing_waiting(&late).await,
            "the frames before the attach are gone for it"
        );
        writer
            .send_side(frame(50, 6), SideClass::Datagram)
            .await
            .unwrap();
        assert_eq!(recv(&late).await.unwrap(), frame(50, 6));
        let stats = late.stats();
        assert_eq!(stats.received, 1);
        assert_eq!(
            stats.published, 6,
            "the ring's count says six were published: a reader that has one knows it missed five"
        );
        assert_eq!(stats.lapped, 0, "they were never its to lose: not lapping");

        // A reader that attached in time but does not keep up is lapped, and counts what it lost.
        let slow = RingFace::attach(FaceId(3), &name, &SECRET).await.unwrap();
        let extra = RING_SLOTS as u64 + 44;
        for i in 0..extra {
            let mut f = frame(50, 0).to_vec();
            f[1..9].copy_from_slice(&i.to_be_bytes());
            writer
                .send_side(Bytes::from(f), SideClass::Datagram)
                .await
                .unwrap();
        }
        let first = recv(&slow).await.unwrap();
        assert_eq!(
            u64::from_be_bytes(first[1..9].try_into().unwrap()),
            44,
            "the oldest frames went first"
        );
        assert_eq!(slow.stats().lapped, 44, "the loss is counted, not silent");
        // The writer was never paced: it published all of them with a reader that read none.
        assert_eq!(writer.stats().published, 6 + extra);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_end_of_stream_frame_is_told_from_a_channel_frame_by_length() {
        let name = ring_name("eos");
        let writer = RingFace::offer(FaceId(1), &name, &SECRET, 100)
            .await
            .unwrap();
        let reader = RingFace::attach(FaceId(2), &name, &SECRET).await.unwrap();

        // The writer cannot publish an end-of-stream frame, or one too short to be a channel
        // frame, by the side path.
        for short in [1, 2, CHANNEL_FRAME_MIN - 1] {
            assert_eq!(
                writer.send_side(frame(short, 3), SideClass::Datagram).await,
                Err(SideRefused::Malformed),
                "{short} octets"
            );
        }
        assert_eq!(
            writer
                .send_side(Bytes::from_static(&[EOS]), SideClass::Datagram)
                .await,
            Err(SideRefused::Malformed)
        );
        assert_eq!(writer.stats().published, 0);

        // What is on the ring raw: a 35-octet marked frame, an unmarked frame of channel length
        // (an NDN Data's first octet), then the shortest channel frame, then a longest one.
        // Only the last two are channel frames; the first two are dropped and counted.
        let End::Writer { ring, .. } = &writer.end else {
            unreachable!()
        };
        ring.publish(&frame(CHANNEL_FRAME_MIN - 1, 1));
        let mut ndn = vec![0x06; 80];
        ndn[1] = 0x4e;
        ring.publish(&ndn);
        ring.publish(&frame(CHANNEL_FRAME_MIN, 2));
        ring.publish(&frame(100, 3));
        assert_eq!(recv(&reader).await.unwrap(), frame(CHANNEL_FRAME_MIN, 2));
        assert_eq!(recv(&reader).await.unwrap(), frame(100, 3));
        assert_eq!(reader.stats().malformed, 2);
        assert_eq!(reader.stats().received, 2);
        assert_eq!(reader.ended_cleanly(), None);

        // The writer ends: the reader sees the end-of-stream frame and says it was clean.
        drop(writer);
        assert!(matches!(recv(&reader).await, Err(FaceError::Closed)));
        assert_eq!(reader.ended_cleanly(), Some(true));
        assert!(
            matches!(recv(&reader).await, Err(FaceError::Closed)),
            "and stays ended"
        );
    }

    /// What each shared-memory face carries, as the forwarder and a sender that asks see it: the
    /// ordered, reliable ring of two processes (`SpscFace`) carries both classes, the lossy
    /// broadcast ring's writer the datagram class only, and its reader nothing.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_shared_memory_faces_report_which_side_classes_they_carry() {
        let (spsc, _fds) = crate::spsc::SpscFace::create_anon_with(FaceId(90), 16, 256).unwrap();
        assert!(spsc.side_carries(SideClass::Datagram) && spsc.side_carries(SideClass::Stream));
        let name = ring_name("carries");
        let writer = RingFace::offer(FaceId(1), &name, &SECRET, 300)
            .await
            .unwrap();
        let reader = RingFace::attach(FaceId(2), &name, &SECRET).await.unwrap();
        assert!(writer.side_carries(SideClass::Datagram));
        assert!(
            !writer.side_carries(SideClass::Stream),
            "a lossy ring has no stream"
        );
        assert!(
            !reader.side_carries(SideClass::Datagram) && !reader.side_carries(SideClass::Stream)
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_writer_refuses_what_the_side_path_refuses_and_is_never_full() {
        let name = ring_name("writer");
        let writer = RingFace::offer(FaceId(1), &name, &SECRET, 300)
            .await
            .unwrap();
        let reader = RingFace::attach(FaceId(2), &name, &SECRET).await.unwrap();

        // An NDN packet is not a side frame; one over the ring's frame limit is `TooLarge`.
        let ndn = Bytes::from(vec![0x06; 100]);
        assert_eq!(
            writer.send_side(ndn.clone(), SideClass::Datagram).await,
            Err(SideRefused::Malformed)
        );
        assert_eq!(
            writer.forward_side(ndn, SideClass::Datagram),
            Err(SideRefused::Malformed)
        );
        let too_large = SideRefused::TooLarge {
            size: 301,
            max: 300,
        };
        assert_eq!(
            writer.send_side(frame(301, 1), SideClass::Datagram).await,
            Err(too_large.clone())
        );
        assert_eq!(
            writer.forward_side(frame(301, 1), SideClass::Datagram),
            Err(too_large)
        );
        assert_eq!(
            writer.forward_side(frame(300, 1), SideClass::Datagram),
            Ok(())
        );
        assert_eq!(recv(&reader).await.unwrap(), frame(300, 1));

        // The face says so as a fact of its medium: a writer carries the datagram class only, a
        // reader (which carries nothing out) none.
        assert!(writer.side_carries(SideClass::Datagram));
        assert!(
            !writer.side_carries(SideClass::Stream),
            "a lossy ring has no stream"
        );
        assert!(!reader.side_carries(SideClass::Datagram));

        // Only the datagram class exists on a lossy ring: the stream class is refused, counted
        // by the face, and the forwarder counts it `class_unsupported` (NotCarried).
        assert_eq!(
            writer.forward_side(frame(100, 1), SideClass::Stream),
            Err(SideRefused::NotCarried)
        );
        assert_eq!(
            writer.send_side(frame(100, 1), SideClass::Stream).await,
            Err(SideRefused::NotCarried)
        );
        assert_eq!(writer.stats().class_refused, 2);

        // NDN packets do not travel on a ring, and a writer receives nothing.
        assert!(writer.send_bytes(frame(100, 1)).await.is_err());
        assert!(
            tokio::time::timeout(Duration::from_millis(100), writer.recv_bytes())
                .await
                .is_err()
        );

        // A reader that reads nothing never fills it: the writer takes 10 rings' worth.
        for i in 0..(RING_SLOTS as usize * 10) {
            assert_eq!(
                writer.forward_side(frame(50, (i % 250) as u8), SideClass::Datagram),
                Ok(()),
                "frame {i}"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_ring_for_an_unusable_frame_limit_is_refused_with_the_range() {
        for asked in [0, CHANNEL_FRAME_MIN - 1, RING_FRAME_MAX + 1] {
            match RingFace::offer(FaceId(1), &ring_name("limit"), &SECRET, asked).await {
                Err(RingError::FrameMax { asked: a, min, max }) => {
                    assert_eq!((a, min, max), (asked, CHANNEL_FRAME_MIN, RING_FRAME_MAX));
                }
                Err(e) => panic!("expected FrameMax for {asked}, got: {e}"),
                Ok(_) => panic!("a ring for {asked} octets was offered"),
            }
        }
        assert_eq!(
            sealed_geometry(1400),
            (RING_SLOTS, (1400 + RING_SLOT_HEADROOM) as u32)
        );
        assert!(
            !served_here(&ring_name("limit")),
            "a refused offer leaves no socket"
        );
    }
}
