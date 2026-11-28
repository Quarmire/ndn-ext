//! The side path of a link: channel frames beside NDN packets, on the link's
//! own QUIC connection.
//!
//! A *channel frame* is not an NDN packet: its first octet is
//! [`SIDE_MARKER`] (`0x00`, which no NDN packet starts with). Two carriers
//! share the connection and its one congestion controller:
//!
//! - **Datagram.** The frame is one QUIC DATAGRAM frame, read by the face's
//!   one datagram reader ([`LinkFace`](crate::LinkFace)'s `recv_bytes`) like
//!   any other and returned to its caller unchanged. A frame leaves only
//!   while fewer than the *headroom* bytes wait in the connection's datagram
//!   send buffer (about a millisecond of the connection's send rate, between
//!   [`QUEUE_FLOOR`] and [`QUEUE_CAP`]; the *headroom rule*), so it waits
//!   behind about that much NDN traffic and never makes quinn drop an older
//!   NDN datagram to find room.
//! - **Stream.** One unidirectional stream per direction carries
//!   `u32 big-endian length | frame` records, opened on the first stream-class
//!   send. The link's transport configuration grants a peer no unidirectional
//!   stream at the handshake; after the verdict, when both hellos carried
//!   `ChannelCaps` and this side's [`ChannelPolicy`] carries, this side grants
//!   exactly one, and a task reads the peer's records into the face's inbound
//!   queue. NDN packets never travel on a stream: a side frame is refused
//!   unless it starts with the marker.
//!
//! Nothing here costs a link a byte before the verdict: a face exists only
//! after it. A link that does not carry (a policy of this side's, decided from
//! the admitted link) sends nothing, grants nothing, and drops and counts what
//! the peer sends, without closing the link. Carrying is judged live, not once at
//! admission: a link whose scope narrows in place ([`Narrowing`](crate::Narrowing): a
//! grant's last entry ended, the departure link) stops carrying at the moment its
//! scope narrows, by the same judgement, in both directions: it sends none, drops
//! and counts the datagrams the peer sends, and stops reading the peer's stream
//! (which is not taken up again; datagrams follow the judgement). The link stays up.

use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::task::Poll;
use std::time::{Duration, Instant};

use bytes::{Buf, Bytes, BytesMut};
use quinn::{SendDatagramError, VarInt};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use tracing::{debug, trace};

use ndn_transport::{FaceId, SIDE_MARKER, SideClass, SideRefused};

use crate::link::DATAGRAM_FLOOR;
use crate::message::{CHANNEL_CAPS_V1, CloseReason};
use crate::scope::{FairMember, FairShare, Flow, ScopeState};

/// The least headroom, in octets of datagrams that may wait in the connection's
/// send buffer when a channel datagram is handed to it: a millisecond at
/// 1 Gbit/s, and what any slower connection gets. It is two GSO batches of the
/// link socket (64 KiB each): at 64 KiB one batch drained the whole headroom, the
/// driver found the queue empty between batches, and a saturating 1 KiB
/// publisher measured 0.92 of raw datagrams (0.97 at 128 KiB).
pub const QUEUE_FLOOR: usize = 128 * 1024;

/// The most headroom: well under the connection's 1 MiB send buffer, so room
/// for an NDN datagram is always left and none is dropped for a channel frame.
pub const QUEUE_CAP: usize = 512 * 1024;

/// How much of the connection's send rate the headroom allows to queue: what a
/// channel datagram waits behind NDN traffic is about this long.
const HEADROOM_TIME: Duration = Duration::from_millis(1);

/// Shortest window the send rate is measured over (and so how often it is read).
const RATE_WINDOW_MIN: Duration = Duration::from_millis(1);

/// A window this long replaces the smoothed rate; a shorter one moves it by its
/// share of this.
const RATE_WINDOW_FULL: Duration = Duration::from_millis(20);

/// Datagrams sent between two looks at the clock for the rate.
const RATE_EVERY: u64 = 16;

/// The headroom for a connection sending `rate` octets a second: the octets it
/// sends in [`HEADROOM_TIME`], within [`QUEUE_FLOOR`] and [`QUEUE_CAP`].
pub(crate) fn headroom_for(rate: f64) -> usize {
    let wanted = rate * HEADROOM_TIME.as_secs_f64();
    if wanted.is_nan() {
        return QUEUE_FLOOR;
    }
    (wanted.clamp(0.0, QUEUE_CAP as f64) as usize).clamp(QUEUE_FLOOR, QUEUE_CAP)
}

/// The smoothed rate after a window of `dt` in which `inst` octets a second
/// were sent.
pub(crate) fn smoothed_rate(rate: f64, inst: f64, dt: Duration) -> f64 {
    let share = (dt.as_secs_f64() / RATE_WINDOW_FULL.as_secs_f64()).min(1.0);
    rate + share * (inst - rate)
}

/// The size of the datagram send buffer of every link's connection: the one place it is
/// stated. The link's transport configuration sets it (`endpoint::transport_config`, so a
/// connection's buffer is this size whichever way it was made), and what the headroom is
/// measured against is derived from it, as `queued` is this less
/// `datagram_send_buffer_space()` less [`DATAGRAM_RECORD`]. (It is quinn's own default too; a
/// test pins that.)
pub const DATAGRAM_SEND_BUFFER: usize = 1024 * 1024;

/// What quinn-proto counts for the record of a datagram, `size_of::<Datagram>()`, in a
/// connection's datagram send buffer. Vendored `quinn-proto-0.11.19/src/connection/datagrams.rs`:
/// `DatagramBuffer::memory_used` is the queued payload plus this for each queued datagram, and
/// `Datagrams::send_buffer_space` is the configured size less `memory_used` and less this once
/// more, kept in reserve. So an empty buffer reports `DATAGRAM_SEND_BUFFER - DATAGRAM_RECORD`
/// of space, and `memory_used = DATAGRAM_SEND_BUFFER - space - DATAGRAM_RECORD` whatever is
/// queued. (0.11.16 counted payload only and kept none in reserve, so this is 0 there; the
/// crate requires a quinn-proto release of the 0.11.19 accounting, and the test
/// `the_send_buffer_counts_as_the_queued_octets_read_assumes` fails first if a release counts
/// otherwise.)
pub(crate) const DATAGRAM_RECORD: usize = 32;

/// The longest channel frame on the stream (a record's payload). A peer that
/// sends a longer one has sent more than this side grants: the link is closed
/// as a protocol error.
pub const STREAM_FRAME_MAX: usize = ndn_transport::side_header::STREAM_FRAME_GRANT;

/// Octets of stream frames [`forward_side`](ndn_transport::Transport::forward_side)
/// may have queued in front of the stream writer, records' prefixes included.
pub const STREAM_QUEUE_MAX: usize = 4 * 1024 * 1024;

/// Octets of received stream frames waiting for the face's reader: past it the
/// side-stream task stops reading, and QUIC flow control slows the peer.
const INBOX_BYTES: usize = 4 * 1024 * 1024;

/// Octets one write of the stream writer task takes from its queue (frames are
/// not split, so a write may pass this by one frame).
const WRITE_BATCH: usize = 256 * 1024;

/// Frames up to this many octets are written as one copied record; larger ones
/// as a prefix chunk and the frame itself.
const SMALL_RECORD: usize = 16 * 1024;

/// Octets one read of the peer's stream takes at most.
const READ_CHUNK: usize = 256 * 1024;

/// How often a blocked datagram send looks at the send buffer again, once it
/// has given up yielding (tokio's timers are 1 ms granular: sleeping alone
/// would cap a saturating sender at [`QUEUE_MAX`] a millisecond).
const HEADROOM_RECHECK: Duration = Duration::from_millis(1);

/// How many times a blocked datagram send yields to the runtime (which runs the
/// connection's driver, draining the send buffer) and looks again before it
/// sleeps: a driver sending at line rate frees room within microseconds, and a
/// peer that stopped costs a blocked sender about 0.3 ms of one core per frame
/// it waits to send, not a spin without end.
const HEADROOM_YIELDS: u32 = 256;

/// How long this side waits for the peer to grant its channel stream before it gives up
/// the stream for good. The peer grants it right after the verdict, when both hellos
/// carried `ChannelCaps` and its policy carries; a peer whose policy does not carry (the
/// hello does not say) never does, and an open that waited for ever would hold the stream
/// lane (and, through `forward_side`'s writer, its queue) for the life of the link. A
/// resource bound: whether a stream is granted is the peer's frame, not this clock's, and
/// a late grant is a peer that is not following the protocol.
const STREAM_GRANT_WAIT: Duration = Duration::from_secs(10);

/// The longest a write to the channel stream may make no progress before the link is closed:
/// the peer has granted no flow-control credit for this long, so it is not reading the stream
/// it was granted. A link that sends `Keep`s and never reads would otherwise hold every
/// sender waiting for room on it (the engine refreshes a sink on every `Keep`, read or not)
/// for the life of the link. It is a bound on the peer's progress, not a judgement on its
/// data: any octet the peer takes restarts it, so a slow link that moves is never closed.
/// [`LinkHandle::set_stream_stall`](crate::LinkHandle::set_stream_stall) changes it for one
/// link.
pub const STREAM_STALL: Duration = Duration::from_secs(30);

/// Why this side stopped a channel stream.
const STREAM_MALFORMED: VarInt = VarInt::from_u32(1);

/// The channel policy of an admitted link, decided by the side admitting it
/// (ndn-link.md §17A): whether the link carries channel frames at all, and
/// under which fair share.
#[derive(Clone, Default)]
pub struct ChannelPolicy {
    /// Whether this side carries channel frames on the link. `false` (the
    /// default): it sends none, grants the peer no stream, and drops and
    /// counts the marked frames the peer sends, without closing the link.
    /// `true`: it carries them while the link's scope is not narrowed (a
    /// scope that narrows in place ends the carriage with it).
    pub carry: bool,
    /// `Some`: the bytes the link carries each way are held to a fair share
    /// of this pool, with the namespace's other links on it
    /// ([`FairShare`]). `None`: no quota; the link's congestion control
    /// decides.
    pub quota: Option<FairShare>,
}

/// What the side path of one link carried and dropped, since it came up.
/// Counters only: no address, no key, no name.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SideStats {
    /// Channel datagrams sent, and their octets.
    pub datagram_tx_frames: u64,
    pub datagram_tx_bytes: u64,
    /// Channel datagrams received and delivered, and their octets.
    pub datagram_rx_frames: u64,
    pub datagram_rx_bytes: u64,
    /// Channel frames written to the stream, and their octets (without the
    /// record prefix).
    pub stream_tx_frames: u64,
    pub stream_tx_bytes: u64,
    /// Channel frames read from the stream, and their octets.
    pub stream_rx_frames: u64,
    pub stream_rx_bytes: u64,
    /// Stream frames written in the same write as an earlier one: the stream
    /// writer takes what has queued while it wrote.
    pub coalesced: u64,
    /// Frames dropped for the link's quota: received datagrams, and frames
    /// `forward_side` refused as [`Full`](SideRefused::Full) for it.
    pub dropped_over_quota: u64,
    /// Marked frames the peer sent that are malformed (a stream record of no
    /// octets, over the limit, or not starting with the marker).
    pub dropped_malformed: u64,
    /// Stream writes that found no flow-control credit and waited.
    pub stream_blocked: u64,
    /// Frames `forward_side` refused because the send buffer or the stream
    /// queue had no room.
    pub sink_full: u64,
    /// Frames refused because this link does not carry channel frames, or the
    /// peer lacks the capability: those sent, and those received and dropped.
    pub refused: u64,
    /// The most octets that waited in the connection's datagram send buffer
    /// when a channel datagram was handed to it.
    pub queued_peak: u64,
}

impl SideStats {
    /// Frames sent and received, both carriers.
    pub fn frames(&self) -> u64 {
        self.datagram_tx_frames
            + self.datagram_rx_frames
            + self.stream_tx_frames
            + self.stream_rx_frames
    }

    /// Octets sent and received, both carriers: the link's channel activity.
    pub fn bytes(&self) -> u64 {
        self.datagram_tx_bytes
            + self.datagram_rx_bytes
            + self.stream_tx_bytes
            + self.stream_rx_bytes
    }
}

impl std::ops::AddAssign for SideStats {
    /// The counters of two paths of one link, together: each is summed, and
    /// `queued_peak` is the larger.
    fn add_assign(&mut self, other: Self) {
        self.datagram_tx_frames += other.datagram_tx_frames;
        self.datagram_tx_bytes += other.datagram_tx_bytes;
        self.datagram_rx_frames += other.datagram_rx_frames;
        self.datagram_rx_bytes += other.datagram_rx_bytes;
        self.stream_tx_frames += other.stream_tx_frames;
        self.stream_tx_bytes += other.stream_tx_bytes;
        self.stream_rx_frames += other.stream_rx_frames;
        self.stream_rx_bytes += other.stream_rx_bytes;
        self.coalesced += other.coalesced;
        self.dropped_over_quota += other.dropped_over_quota;
        self.dropped_malformed += other.dropped_malformed;
        self.stream_blocked += other.stream_blocked;
        self.sink_full += other.sink_full;
        self.refused += other.refused;
        self.queued_peak = self.queued_peak.max(other.queued_peak);
    }
}

/// What a writer of channel frames needs to know before it hands one over.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SideLimits {
    /// Octets waiting in the connection's datagram send buffer now.
    pub queued: usize,
    /// A channel datagram leaves only while `queued` is under this: the
    /// headroom now, between [`QUEUE_FLOOR`] and [`QUEUE_CAP`].
    pub queue_max: usize,
    /// The longest datagram the connection carries now.
    pub frame_max: usize,
    /// The longest frame the stream carries ([`STREAM_FRAME_MAX`]).
    pub stream_frame_max: usize,
}

#[derive(Default)]
struct Counters {
    datagram_tx_frames: AtomicU64,
    datagram_tx_bytes: AtomicU64,
    datagram_rx_frames: AtomicU64,
    datagram_rx_bytes: AtomicU64,
    stream_tx_frames: AtomicU64,
    stream_tx_bytes: AtomicU64,
    stream_rx_frames: AtomicU64,
    stream_rx_bytes: AtomicU64,
    coalesced: AtomicU64,
    dropped_over_quota: AtomicU64,
    dropped_malformed: AtomicU64,
    stream_blocked: AtomicU64,
    sink_full: AtomicU64,
    refused: AtomicU64,
    queued_peak: AtomicU64,
}

fn bump(counter: &AtomicU64) {
    counter.fetch_add(1, Ordering::Relaxed);
}

fn add(counter: &AtomicU64, n: usize) {
    counter.fetch_add(n as u64, Ordering::Relaxed);
}

impl Counters {
    fn snapshot(&self) -> SideStats {
        let get = |c: &AtomicU64| c.load(Ordering::Relaxed);
        SideStats {
            datagram_tx_frames: get(&self.datagram_tx_frames),
            datagram_tx_bytes: get(&self.datagram_tx_bytes),
            datagram_rx_frames: get(&self.datagram_rx_frames),
            datagram_rx_bytes: get(&self.datagram_rx_bytes),
            stream_tx_frames: get(&self.stream_tx_frames),
            stream_tx_bytes: get(&self.stream_tx_bytes),
            stream_rx_frames: get(&self.stream_rx_frames),
            stream_rx_bytes: get(&self.stream_rx_bytes),
            coalesced: get(&self.coalesced),
            dropped_over_quota: get(&self.dropped_over_quota),
            dropped_malformed: get(&self.dropped_malformed),
            stream_blocked: get(&self.stream_blocked),
            sink_full: get(&self.sink_full),
            refused: get(&self.refused),
            queued_peak: get(&self.queued_peak),
        }
    }
}

/// This side's stream towards the peer.
enum StreamTx {
    /// Not opened: the first stream-class send opens it.
    Idle,
    Open(quinn::SendStream),
    /// The peer stopped it, or a write failed: this link has no stream any
    /// more (the datagram carrier and the link are unaffected).
    Ended,
}

/// Stream frames `forward_side` queued, in order, and their octets.
#[derive(Default)]
struct Queue {
    frames: std::collections::VecDeque<Bytes>,
    octets: usize,
}

/// The connection's send rate as last measured: when, the octets it had sent
/// then (`udp_tx.bytes`), and the smoothed rate in octets a second.
struct RateSample {
    at: Instant,
    bytes: u64,
    rate: f64,
}

/// A received stream frame, holding its share of [`INBOX_BYTES`] until the
/// reader takes it.
type Inbound = (Bytes, OwnedSemaphorePermit);

/// The side path of one link, shared by its [`LinkFace`](crate::LinkFace) and
/// [`LinkHandle`](crate::LinkHandle).
pub(crate) struct SideCarrier {
    connection: quinn::Connection,
    /// The peer's hello carried `ChannelCaps` bit 0.
    peer_caps: bool,
    /// This side's hello did.
    our_caps: bool,
    /// This side's policy carries channel frames on this link.
    carry: bool,
    /// The link's scope: while it is narrowed (a grant ended) the link carries nothing.
    scope: Option<Arc<ScopeState>>,
    quota: Option<FairMember>,
    counters: Counters,
    stream_tx: tokio::sync::Mutex<StreamTx>,
    queue: Mutex<Queue>,
    /// The octets in `queue`, as of its last change: lets a send skip the
    /// queue's lock when `forward_side` queued nothing.
    queued_octets: AtomicUsize,
    wake: tokio::sync::Notify,
    /// [`STREAM_STALL`] for this link, in milliseconds.
    stall_ms: AtomicU64,
    /// Calls to the face's reader, to let it look at every source now and then.
    turn: AtomicU32,
    /// The headroom now, from the send rate last measured.
    headroom: AtomicUsize,
    rate: Mutex<RateSample>,
    stream_rx: tokio::sync::Mutex<mpsc::Receiver<Inbound>>,
    /// Where the stream reader puts frames; taken by [`Self::spawn`].
    inbox: Mutex<Option<mpsc::Sender<Inbound>>>,
    inbox_budget: Arc<Semaphore>,
    /// What this side said when it closed the link, shared with the handle.
    local_close: Arc<OnceLock<(CloseReason, String)>>,
}

impl SideCarrier {
    pub(crate) fn new(
        connection: quinn::Connection,
        peer_caps: bool,
        our_caps: bool,
        policy: ChannelPolicy,
        scope: Option<Arc<ScopeState>>,
        local_close: Arc<OnceLock<(CloseReason, String)>>,
    ) -> Arc<Self> {
        let (tx, rx) = mpsc::channel(1024);
        let sent_bytes = connection.stats().udp_tx.bytes;
        Arc::new(Self {
            connection,
            peer_caps,
            our_caps,
            carry: policy.carry,
            scope,
            quota: policy.quota.as_ref().map(FairShare::join),
            counters: Counters::default(),
            stream_tx: tokio::sync::Mutex::new(StreamTx::Idle),
            queue: Mutex::new(Queue::default()),
            queued_octets: AtomicUsize::new(0),
            wake: tokio::sync::Notify::new(),
            stall_ms: AtomicU64::new(STREAM_STALL.as_millis() as u64),
            turn: AtomicU32::new(0),
            headroom: AtomicUsize::new(QUEUE_FLOOR),
            rate: Mutex::new(RateSample {
                at: Instant::now(),
                bytes: sent_bytes,
                rate: 0.0,
            }),
            stream_rx: tokio::sync::Mutex::new(rx),
            inbox: Mutex::new(Some(tx)),
            inbox_budget: Arc::new(Semaphore::new(INBOX_BYTES)),
            local_close,
        })
    }

    /// Whether this side carries channel frames on the link now: its policy carries and the
    /// link's scope is not narrowed. Judged at every use, by the scope's own
    /// [`Narrowing::when`](crate::Narrowing), so a grant that ends stops the carriage at once.
    fn carrying(&self) -> bool {
        self.carry && !self.scope.as_ref().is_some_and(|scope| scope.narrowed())
    }

    /// Both hellos carried the capability and this side carries now: channel
    /// frames flow, and the stream is granted.
    pub(crate) fn enabled(&self) -> bool {
        self.peer_caps && self.our_caps && self.carrying()
    }

    pub(crate) fn peer_caps(&self) -> bool {
        self.peer_caps
    }

    pub(crate) fn stats(&self) -> SideStats {
        self.counters.snapshot()
    }

    /// Change [`STREAM_STALL`] for this link (at least a millisecond).
    pub(crate) fn set_stream_stall(&self, stall: Duration) {
        let ms = u64::try_from(stall.as_millis()).unwrap_or(u64::MAX).max(1);
        self.stall_ms.store(ms, Ordering::Relaxed);
    }

    /// After the verdict: grant the peer its one stream and start the tasks
    /// that read it and write what `forward_side` queued. Does nothing for a
    /// link that does not carry.
    pub(crate) fn spawn(self: &Arc<Self>, face: FaceId) {
        if !self.enabled() {
            return;
        }
        let inbox = self
            .inbox
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        let Some(inbox) = inbox else { return };
        self.connection
            .set_max_concurrent_uni_streams(VarInt::from_u32(1));
        tokio::spawn(side_stream(Arc::clone(self), face, inbox));
        tokio::spawn(side_writer(Arc::clone(self)));
    }

    pub(crate) fn limits(&self) -> SideLimits {
        SideLimits {
            queued: self.queued(),
            queue_max: self.headroom(),
            frame_max: self.frame_max(),
            stream_frame_max: STREAM_FRAME_MAX,
        }
    }

    /// Whether the link has ended (the peer closed it, this side did, or it was lost): it takes
    /// no frame of either class, which `forward` refuses [`Closed`](SideRefused::Closed).
    fn is_closed(&self) -> bool {
        self.connection.close_reason().is_some()
    }

    /// Whether [`forward`](Self::forward) would take a frame of `class` now and not refuse it
    /// [`Full`](SideRefused::Full): the datagram class while fewer octets wait in the send
    /// buffer than the headroom, the stream class while its queue is under its bound; and a
    /// link that has ended, which refuses `Closed` and not `Full`, so there is nothing to wait
    /// for. The read `forward` makes first, without the frame; room is not reserved.
    pub(crate) fn room(&self, class: SideClass) -> bool {
        self.is_closed()
            || match class {
                SideClass::Datagram => self.queued() < self.headroom(),
                SideClass::Stream => {
                    self.queue
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .octets
                        < STREAM_QUEUE_MAX
                }
            }
    }

    /// [`room`](Self::room) for a frame of `len` octets: what `forward` would answer for it
    /// without taking it. The datagram class as `room` says and, where the link has a quota,
    /// the quota's bucket holds enough for it ([`FairMember::would_admit`](crate::scope::FairMember::would_admit),
    /// which spends nothing); the stream class while the queue holds this frame under its bound
    /// (`room` only asks that the queue is under it) and the quota holds enough. A sender told
    /// `Full` by the first hop keeps the frame and offers it again when this says room: a frame
    /// this read said room for and `forward` refused would be lost there, counted `sink_full`
    /// or `dropped_over_quota`.
    pub(crate) fn room_for(&self, len: usize, class: SideClass) -> bool {
        if self.is_closed() {
            return true;
        }
        let fits = match class {
            SideClass::Datagram => self.queued() < self.headroom(),
            SideClass::Stream => {
                self.queue
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .octets
                    + len
                    + 4
                    <= STREAM_QUEUE_MAX
            }
        };
        fits && self
            .quota
            .as_ref()
            .is_none_or(|quota| quota.would_admit(Flow::Tx, len))
    }

    /// Octets waiting in the connection's datagram send buffer, by the connection's own count
    /// (payload and [`DATAGRAM_RECORD`] for each queued datagram): the size the transport
    /// configuration gives the buffer less the space it reports and less the one record it
    /// keeps in reserve. Derived from the configuration and the library's constant on every
    /// read, and from nothing the buffer held at any earlier moment, so that what was queued
    /// when the link came up cannot skew it.
    fn queued(&self) -> usize {
        DATAGRAM_SEND_BUFFER
            .saturating_sub(self.connection.datagram_send_buffer_space())
            .saturating_sub(DATAGRAM_RECORD)
    }

    /// The connection's current datagram size.
    pub(crate) fn frame_max(&self) -> usize {
        self.connection
            .max_datagram_size()
            .unwrap_or(DATAGRAM_FLOOR)
    }

    /// The refusals every send has, before any octet moves.
    /// `size_now`: also compare the frame with the datagram size now (one read
    /// of the connection's state). A blocking datagram send leaves that to
    /// QUIC, which refuses an over-size datagram at once and says so; the
    /// non-blocking path asks first so that a full buffer never hides it.
    fn check(&self, frame: &Bytes, class: SideClass, size_now: bool) -> Result<(), SideRefused> {
        if frame.first() != Some(&SIDE_MARKER) {
            bump(&self.counters.refused);
            return Err(SideRefused::Malformed);
        }
        if !self.carrying() {
            bump(&self.counters.refused);
            return Err(SideRefused::NotCarried);
        }
        if !(self.peer_caps && self.our_caps) {
            bump(&self.counters.refused);
            return Err(SideRefused::PeerLacksChannels);
        }
        let max = match class {
            SideClass::Datagram if !size_now => usize::MAX,
            SideClass::Datagram => self.frame_max(),
            SideClass::Stream => STREAM_FRAME_MAX,
        };
        if frame.len() > max {
            return Err(SideRefused::TooLarge {
                size: frame.len(),
                max,
            });
        }
        Ok(())
    }

    fn closed() -> SideRefused {
        SideRefused::Closed
    }

    /// Take `len` octets of quota for a send, waiting for them.
    async fn admit_tx(&self, len: usize) -> Result<(), SideRefused> {
        let Some(quota) = &self.quota else {
            return Ok(());
        };
        while let Err(wait) = quota.admit(Flow::Tx, len) {
            if self.connection.close_reason().is_some() {
                return Err(Self::closed());
            }
            tokio::time::sleep(wait.max(HEADROOM_RECHECK)).await;
        }
        Ok(())
    }

    /// Take `len` octets of quota for `forward_side`, which never waits.
    fn try_admit_tx(&self, len: usize) -> Result<(), SideRefused> {
        match &self.quota {
            Some(quota) if quota.admit(Flow::Tx, len).is_err() => {
                bump(&self.counters.dropped_over_quota);
                Err(SideRefused::Full)
            }
            _ => Ok(()),
        }
    }

    /// The octets that may wait in the send buffer when a channel datagram is
    /// handed to it now.
    fn headroom(&self) -> usize {
        self.headroom.load(Ordering::Relaxed)
    }

    /// Measure the connection's send rate over the time since the last look
    /// (at least [`RATE_WINDOW_MIN`]; a look that finds less waits for the next)
    /// and set the headroom from it.
    fn refresh_headroom(&self) {
        let Ok(mut sample) = self.rate.try_lock() else {
            return;
        };
        let now = Instant::now();
        let dt = now.saturating_duration_since(sample.at);
        if dt < RATE_WINDOW_MIN {
            return;
        }
        let bytes = self.connection.stats().udp_tx.bytes;
        let inst = bytes.saturating_sub(sample.bytes) as f64 / dt.as_secs_f64();
        sample.rate = smoothed_rate(sample.rate, inst, dt);
        sample.at = now;
        sample.bytes = bytes;
        self.headroom
            .store(headroom_for(sample.rate), Ordering::Relaxed);
    }

    fn sent_datagram(&self, len: usize, queued: usize) {
        let sent = self
            .counters
            .datagram_tx_frames
            .fetch_add(1, Ordering::Relaxed);
        if sent.is_multiple_of(RATE_EVERY) {
            self.refresh_headroom();
        }
        add(&self.counters.datagram_tx_bytes, len);
        // A read first: the peak rarely moves, and a read does not take the
        // counters' cache line from the reader of `side_stats`.
        if queued as u64 > self.counters.queued_peak.load(Ordering::Relaxed) {
            self.counters
                .queued_peak
                .fetch_max(queued as u64, Ordering::Relaxed);
        }
    }

    /// Send one channel frame, waiting for what it takes: quota, headroom,
    /// and, on the stream, flow control and the stream's opening (which waits
    /// for the peer to grant its stream).
    pub(crate) async fn send(&self, frame: Bytes, class: SideClass) -> Result<(), SideRefused> {
        self.check(&frame, class, false)?;
        if self.quota.is_some() {
            self.admit_tx(frame.len()).await?;
        }
        match class {
            SideClass::Datagram => self.send_datagram(frame).await,
            SideClass::Stream => self.send_stream(frame).await,
        }
    }

    async fn send_datagram(&self, frame: Bytes) -> Result<(), SideRefused> {
        let len = frame.len();
        let mut yields = 0;
        let queued = loop {
            let queued = self.queued();
            if queued < self.headroom() {
                break queued;
            }
            if yields < HEADROOM_YIELDS {
                yields += 1;
                tokio::task::yield_now().await;
                continue;
            }
            self.refresh_headroom();
            if self.connection.close_reason().is_some() {
                return Err(Self::closed());
            }
            tokio::time::sleep(HEADROOM_RECHECK).await;
        };
        // `_wait` never drops an older datagram for this one: if the buffer
        // filled since the check, it waits.
        match self.connection.send_datagram_wait(frame).await {
            Ok(()) => {
                self.sent_datagram(len, queued);
                Ok(())
            }
            Err(e) => Err(self.datagram_refused(e, len)),
        }
    }

    fn datagram_refused(&self, error: SendDatagramError, len: usize) -> SideRefused {
        match error {
            SendDatagramError::TooLarge => SideRefused::TooLarge {
                size: len,
                max: self.frame_max(),
            },
            SendDatagramError::ConnectionLost(_) => Self::closed(),
            other => SideRefused::Io(other.to_string()),
        }
    }

    async fn send_stream(&self, frame: Bytes) -> Result<(), SideRefused> {
        let mut stream = self.stream_tx.lock().await;
        // What `forward_side` queued before goes first.
        if self.queued_octets.load(Ordering::Acquire) > 0 {
            self.write_queued(&mut stream).await?;
        }
        self.write_one(&mut stream, frame).await
    }

    /// Whether the face's reader should try the datagram queue alone this
    /// time: seven calls in eight.
    pub(crate) fn datagram_first(&self) -> bool {
        // One reader calls this; a lost increment under two only shifts which
        // call looks at every source.
        let turn = self.turn.load(Ordering::Relaxed).wrapping_add(1);
        self.turn.store(turn, Ordering::Relaxed);
        turn & 7 != 0
    }

    /// The non-blocking twin of [`send`](Self::send): a frame that has no room
    /// now is refused [`Full`](SideRefused::Full), never waited for.
    pub(crate) fn forward(&self, frame: Bytes, class: SideClass) -> Result<(), SideRefused> {
        self.check(&frame, class, true)?;
        let len = frame.len();
        match class {
            SideClass::Datagram => {
                let queued = self.queued();
                if queued >= self.headroom() {
                    bump(&self.counters.sink_full);
                    return Err(SideRefused::Full);
                }
                self.try_admit_tx(len)?;
                // Under the headroom (at most `QUEUE_CAP`) of the buffer's 1 MiB is in use, so room
                // for this frame is there and no older datagram is dropped.
                match self.connection.send_datagram(frame) {
                    Ok(()) => {
                        self.sent_datagram(len, queued);
                        Ok(())
                    }
                    Err(e) => Err(self.datagram_refused(e, len)),
                }
            }
            SideClass::Stream => {
                if self.is_closed() {
                    return Err(Self::closed());
                }
                let mut queue = self.queue.lock().unwrap_or_else(PoisonError::into_inner);
                if queue.octets + len + 4 > STREAM_QUEUE_MAX {
                    bump(&self.counters.sink_full);
                    return Err(SideRefused::Full);
                }
                self.try_admit_tx(len)?;
                queue.octets += len + 4;
                self.queued_octets.store(queue.octets, Ordering::Release);
                queue.frames.push_back(frame);
                drop(queue);
                self.wake.notify_one();
                Ok(())
            }
        }
    }

    /// Write every frame `forward_side` queued, in order, under the stream
    /// lock. A stream that ended drops them.
    async fn write_queued(&self, stream: &mut StreamTx) -> Result<(), SideRefused> {
        loop {
            // A scope that narrowed since these were queued: they are not sent.
            if !self.carrying() {
                let mut queue = self.queue.lock().unwrap_or_else(PoisonError::into_inner);
                queue.frames.clear();
                queue.octets = 0;
                self.queued_octets.store(0, Ordering::Release);
                bump(&self.counters.refused);
                return Err(SideRefused::NotCarried);
            }
            let batch = {
                let mut queue = self.queue.lock().unwrap_or_else(PoisonError::into_inner);
                let mut batch = Vec::new();
                let mut octets = 0;
                while let Some(frame) = queue.frames.front() {
                    if !batch.is_empty() && octets + frame.len() > WRITE_BATCH {
                        break;
                    }
                    octets += frame.len() + 4;
                    queue.octets -= frame.len() + 4;
                    batch.extend(queue.frames.pop_front());
                }
                self.queued_octets.store(queue.octets, Ordering::Release);
                batch
            };
            if batch.is_empty() {
                return Ok(());
            }
            if let Err(e) = self.write_frames(stream, batch).await {
                // The stream is gone: what was queued for it goes with it.
                let mut queue = self.queue.lock().unwrap_or_else(PoisonError::into_inner);
                queue.frames.clear();
                queue.octets = 0;
                self.queued_octets.store(0, Ordering::Release);
                return Err(e);
            }
        }
    }

    /// Write `frames` as records in one write, opening the stream first if no
    /// frame has gone yet.
    async fn write_frames(
        &self,
        stream: &mut StreamTx,
        frames: Vec<Bytes>,
    ) -> Result<(), SideRefused> {
        let (count, octets) = (frames.len(), frames.iter().map(Bytes::len).sum::<usize>());
        let mut chunks = Vec::with_capacity(2 * count);
        for frame in frames {
            // At most STREAM_FRAME_MAX, checked before it was queued.
            chunks.push(Bytes::copy_from_slice(&(frame.len() as u32).to_be_bytes()));
            chunks.push(frame);
        }
        self.write_chunks(stream, &mut chunks, count, octets).await
    }

    /// Write one frame as a record. A small one is copied behind its prefix
    /// into one buffer, which costs one allocation and no list of chunks; a
    /// large one goes as a prefix chunk and itself, uncopied.
    async fn write_one(&self, stream: &mut StreamTx, frame: Bytes) -> Result<(), SideRefused> {
        let len = frame.len();
        // At most STREAM_FRAME_MAX, checked before this send.
        let prefix = (len as u32).to_be_bytes();
        if len <= SMALL_RECORD {
            let mut record = BytesMut::with_capacity(4 + len);
            record.extend_from_slice(&prefix);
            record.extend_from_slice(&frame);
            self.write_chunks(stream, &mut [record.freeze()], 1, len)
                .await
        } else {
            let mut chunks = [Bytes::copy_from_slice(&prefix), frame];
            self.write_chunks(stream, &mut chunks, 1, len).await
        }
    }

    /// Write `chunks` (the records of `count` frames of `octets` octets in
    /// all) in one write, opening the stream first if no frame has gone yet.
    async fn write_chunks(
        &self,
        stream: &mut StreamTx,
        chunks: &mut [Bytes],
        count: usize,
        octets: usize,
    ) -> Result<(), SideRefused> {
        if let StreamTx::Idle = stream {
            let opened =
                match tokio::time::timeout(STREAM_GRANT_WAIT, self.connection.open_uni()).await {
                    Ok(Ok(opened)) => opened,
                    Ok(Err(_)) => return Err(Self::closed()),
                    Err(_) => {
                        *stream = StreamTx::Ended;
                        return Err(SideRefused::Io(format!(
                            "the peer of this link granted no channel stream in {} s (it does not \
                         carry channel frames, or is not following the protocol): this link has \
                         no channel stream; datagrams are unaffected",
                            STREAM_GRANT_WAIT.as_secs()
                        )));
                    }
                };
            *stream = StreamTx::Open(opened);
        }
        // The stream is `Ended` while a write is in flight: a send that is
        // dropped half way leaves half a record, and no record may follow it.
        let StreamTx::Open(mut send) = std::mem::replace(stream, StreamTx::Ended) else {
            return Err(SideRefused::Io(
                "the channel stream of this link ended".into(),
            ));
        };
        let written = {
            let stall = self.stream_stall();
            let mut bufs: &mut [Bytes] = chunks;
            let mut blocked = false;
            loop {
                if bufs.is_empty() {
                    break Ok(());
                }
                // One look at what the stream takes: a write that finds credit completes at
                // once, and one that finds none waits for the peer, for at most `stall`. The
                // wait is for any progress (`write_chunks` completes when the stream takes an
                // octet), so a peer that reads slowly keeps the stream and one that does not
                // read at all is found out, whatever else it sends.
                let done = {
                    let mut step = std::pin::pin!(send.write_chunks(&mut *bufs));
                    match std::future::poll_fn(|cx| Poll::Ready(step.as_mut().poll(cx))).await {
                        Poll::Ready(done) => done,
                        Poll::Pending => {
                            if !blocked {
                                blocked = true;
                                bump(&self.counters.stream_blocked);
                            }
                            match tokio::time::timeout(stall, step).await {
                                Ok(done) => done,
                                Err(_) => return Err(self.close_stalled(stall)),
                            }
                        }
                    }
                };
                match done {
                    Ok(written) => bufs = &mut bufs[written.chunks..],
                    Err(e) => break Err(e),
                }
            }
        };
        match written {
            Ok(()) => {
                *stream = StreamTx::Open(send);
                add(&self.counters.stream_tx_frames, count);
                add(&self.counters.stream_tx_bytes, octets);
                add(&self.counters.coalesced, count - 1);
                Ok(())
            }
            Err(e) => Err(match e {
                quinn::WriteError::ConnectionLost(_) => Self::closed(),
                other => SideRefused::Io(other.to_string()),
            }),
        }
    }

    /// How long a write to the stream may make no progress now: [`STREAM_STALL`] unless
    /// [`set_stream_stall`](Self::set_stream_stall) changed it.
    fn stream_stall(&self) -> Duration {
        Duration::from_millis(self.stall_ms.load(Ordering::Relaxed))
    }

    /// The peer took no octet of the channel stream for `stall`: it is not reading the stream
    /// it was granted, whatever else it sends (a sink is kept live by its `Keep`s, read or not).
    /// Close the link, with words the peer can read that say why and what to do, so that the
    /// senders waiting on this link are told and the forwarder drops its sinks; the send in
    /// flight is told the same.
    fn close_stalled(&self, stall: Duration) -> SideRefused {
        let text = format!(
            "your device did not read the channel stream for {stall:?} while this device had \
             channel frames to send it, so this link is closed; read the channel stream (or \
             leave the channels you follow) and link again"
        );
        self.close_protocol(&text);
        SideRefused::Io(text)
    }

    /// A marked datagram arrived: whether it is delivered. One that this link
    /// does not carry, or that the peer had no capability to send, is dropped
    /// and counted `refused`; one over the quota is dropped and counted. The
    /// peer is told nothing: a Nack answers an Interest, and this is none.
    pub(crate) fn received_datagram(&self, wire: &Bytes) -> bool {
        if !self.enabled() {
            bump(&self.counters.refused);
            return false;
        }
        if let Some(quota) = &self.quota
            && quota.admit(Flow::Rx, wire.len()).is_err()
        {
            bump(&self.counters.dropped_over_quota);
            return false;
        }
        bump(&self.counters.datagram_rx_frames);
        add(&self.counters.datagram_rx_bytes, wire.len());
        true
    }

    /// The next frame the stream delivered; `None` once the stream reader has ended (the
    /// link still reads datagrams). Pending while the link has no stream reader.
    pub(crate) async fn next_stream_frame(&self) -> Option<Bytes> {
        let mut rx = self.stream_rx.lock().await;
        rx.recv().await.map(|(frame, _permit)| frame)
    }

    /// Whether the stream's frames reach the face through its own lane
    /// ([`next_stream_frame`](Self::next_stream_frame)): both hellos carried the capability and
    /// this side's policy carries. Fixed for the life of the link.
    pub(crate) fn stream_lane(&self) -> bool {
        self.peer_caps && self.our_caps && self.carry
    }

    fn close_protocol(&self, text: &str) {
        let reason = CloseReason::Protocol;
        let _ = self.local_close.set((reason, text.to_string()));
        self.connection
            .close(VarInt::from_u32(reason.code()), text.as_bytes());
    }
}

/// Write what `forward_side` queued, for the life of the link.
async fn side_writer(side: Arc<SideCarrier>) {
    loop {
        tokio::select! {
            () = side.wake.notified() => {}
            _ = side.connection.closed() => return,
        }
        let mut stream = side.stream_tx.lock().await;
        if let Err(e) = side.write_queued(&mut stream).await {
            trace!(target: "face.quic", error = %e, "side stream writer stopped writing");
        }
    }
}

/// Accept the peer's one stream and read its records into the face's inbound
/// queue, for the life of the link. A record over the limit closes the link
/// (the peer sent more than this side granted); a malformed one stops the
/// stream and leaves the link up.
async fn side_stream(side: Arc<SideCarrier>, face: FaceId, inbox: mpsc::Sender<Inbound>) {
    let accepted = tokio::select! {
        accepted = side.connection.accept_uni() => accepted,
        _ = side.connection.closed() => return,
    };
    let Ok(mut recv) = accepted else { return };
    // The one stream this side grants is taken: grant no other. quinn hands the peer the
    // credit for another stream when the first finishes or is reset, and nothing here would
    // ever accept it (the peer could buffer a flow-control window of bytes nobody reads).
    side.connection
        .set_max_concurrent_uni_streams(VarInt::from_u32(0));
    let mut buf = BytesMut::new();
    loop {
        if !side.carrying() {
            bump(&side.counters.refused);
            stop_stream(face, &mut recv, "the link no longer carries channel frames");
            return;
        }
        // Every record that is whole in `buf`.
        while buf.len() >= 4 {
            let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
            if len > STREAM_FRAME_MAX {
                bump(&side.counters.dropped_malformed);
                side.close_protocol(&format!(
                    "your device sent a channel frame of {len} bytes on the channel stream, over the \
                     {STREAM_FRAME_MAX} bytes this device grants"
                ));
                return;
            }
            if len == 0 {
                bump(&side.counters.dropped_malformed);
                stop_stream(face, &mut recv, "a channel record of no octets");
                return;
            }
            if buf.len() < 4 + len {
                break;
            }
            let permit = tokio::select! {
                permit = Arc::clone(&side.inbox_budget).acquire_many_owned(len as u32) => match permit {
                    Ok(permit) => permit,
                    Err(_) => return,
                },
                _ = side.connection.closed() => return,
            };
            // A copy of its own: a frame the reader has not taken yet pins its
            // own octets and not the buffer they were read into.
            let frame = Bytes::copy_from_slice(&buf[4..4 + len]);
            buf.advance(4 + len);
            if frame[0] != SIDE_MARKER {
                bump(&side.counters.dropped_malformed);
                stop_stream(
                    face,
                    &mut recv,
                    "a channel record that does not start with the marker",
                );
                return;
            }
            // A stream cannot drop a frame without breaking the channel's order:
            // over the quota the reader waits, and flow control slows the peer.
            if let Some(quota) = &side.quota {
                while let Err(wait) = quota.admit(Flow::Rx, len) {
                    tokio::select! {
                        () = tokio::time::sleep(wait.max(HEADROOM_RECHECK)) => {}
                        _ = side.connection.closed() => return,
                    }
                }
            }
            // The wait may have been long: judge again before the frame is delivered.
            if !side.carrying() {
                bump(&side.counters.refused);
                stop_stream(face, &mut recv, "the link no longer carries channel frames");
                return;
            }
            bump(&side.counters.stream_rx_frames);
            add(&side.counters.stream_rx_bytes, len);
            if inbox.send((frame, permit)).await.is_err() {
                return;
            }
        }
        // More octets: one read takes what the stream has, many records at a time.
        match recv.read_chunk(READ_CHUNK, true).await {
            Ok(Some(chunk)) => buf.extend_from_slice(&chunk.bytes),
            // The peer finished its stream: between two records, or inside one.
            Ok(None) => {
                if !buf.is_empty() {
                    bump(&side.counters.dropped_malformed);
                }
                return;
            }
            // Reset, stopped, or the connection is gone.
            Err(_) => return,
        }
    }
}

/// Stop the peer's channel stream (a malformed record, or a link that no longer carries): the
/// link stays up. No other stream is granted: the credit went with the stream's acceptance.
fn stop_stream(face: FaceId, recv: &mut quinn::RecvStream, why: &str) {
    debug!(target: "face.quic", face = %face, "stopping the channel stream: {why}");
    let _ = recv.stop(STREAM_MALFORMED);
}

/// Whether a hello's capabilities include channel frames.
pub(crate) fn has_channel_caps(caps: u8) -> bool {
    caps & CHANNEL_CAPS_V1 != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_headroom_is_a_millisecond_of_the_send_rate_between_the_floor_and_the_cap() {
        let gbit = 1e9 / 8.0;
        // 1 Gbit/s and slower, and no rate yet: exactly the floor.
        for rate in [0.0, 1e3, 1e6, gbit / 10.0, gbit, f64::NAN, -5.0] {
            assert_eq!(headroom_for(rate), QUEUE_FLOOR, "rate {rate}");
        }
        // A millisecond of 2.5 and 4 Gbit/s: 312.5 KB and 500 KB.
        assert_eq!(headroom_for(2.5 * gbit), (2.5 * gbit / 1000.0) as usize);
        assert_eq!(headroom_for(4.0 * gbit), (4.0 * gbit / 1000.0) as usize);
        // Faster than the cap: the cap, which leaves room in the 1 MiB buffer.
        for rate in [4.5 * gbit, 10.0 * gbit, 100.0 * gbit, f64::INFINITY] {
            assert_eq!(headroom_for(rate), QUEUE_CAP, "rate {rate}");
        }
        const { assert!(QUEUE_CAP < DATAGRAM_SEND_BUFFER) };
        // Never under the floor, never over the cap, and not falling as the rate rises.
        let mut last = 0;
        for step in 0..400 {
            let h = headroom_for(step as f64 * 5e7);
            assert!((QUEUE_FLOOR..=QUEUE_CAP).contains(&h) && h >= last);
            last = h;
        }
    }

    #[test]
    fn the_rate_follows_the_windows_it_is_measured_over() {
        let ms = Duration::from_millis;
        // A window of the full length replaces the rate; a short one moves it by its share.
        assert_eq!(smoothed_rate(100.0, 900.0, RATE_WINDOW_FULL), 900.0);
        assert_eq!(smoothed_rate(100.0, 900.0, ms(500)), 900.0);
        let half = smoothed_rate(0.0, 1000.0, RATE_WINDOW_FULL / 2);
        assert!((half - 500.0).abs() < 1e-9, "{half}");
        let short = smoothed_rate(0.0, 1e9, RATE_WINDOW_MIN);
        assert!(short > 0.0 && short < 1e9 / 10.0, "{short}");
        // A burst of one short window does not lift the headroom to the cap
        // from a link that was idle.
        assert!(headroom_for(short) < QUEUE_CAP);
    }
}
