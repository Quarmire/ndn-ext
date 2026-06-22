//! **Named, zero-copy surfaces over the SHM face** — the ergonomic G11 layer.
//!
//! [`NamedPublisher`] / [`NamedSubscriber`] close the gap between the fast SHM
//! primitives (`ndn-face-shm`) and *"craft interoperating named data + surfaces
//! between processes"*: a producer publishes a stream of frames under an **NDN
//! name**; a local consumer attaches by the **same name** and reads each frame
//! **zero-copy**. No fds, tokens, control sockets, or ring/slot sizing leak into
//! the API. Frames are real signed NDN Data on the wire (so the consumer gets the
//! frame's *name*, not just bytes), and the rendezvous is derived from the name.
//!
//! ```no_run
//! # use ndn_surface::{NamedPublisher, NamedSubscriber};
//! # async fn demo() -> Result<(), ndn_surface::SurfaceError> {
//! let mut pubr = NamedPublisher::open("/app/surface").await?;
//! pubr.publish(b"frame-0").await?;                 // publishes /app/surface/v=0
//!
//! let mut sub = NamedSubscriber::connect("/app/surface").await?;
//! sub.next_frame(|f| println!("{} = {} bytes", f.name, f.content.len())).await;
//! # Ok(()) }
//! ```
//!
//! ## Named-data transparency
//!
//! [`NamedSubscriber`] reads frames **by name** regardless of where the producer
//! lives. The *same* `next_frame()` call resolves two ways:
//!
//! - **Local** — a [`NamedPublisher`] is serving on this host → frames stream over
//!   the SHM ring and content is **borrowed in place** (zero-copy).
//! - **Remote** — no local producer → frames are fetched **over the forwarder**
//!   by Interest/Data (`<surface>/v=<seq>`), content owned from the network.
//!
//! [`NamedSubscriber::connect_via`] picks: it probes the name's local rendezvous
//! and, finding none, falls back to a forwarder fetch through a caller-supplied
//! [`Consumer`]. The consumer code is identical either way — *fetch by name; get
//! zero-copy if it's local, the network if it isn't.*
//!
//! ## Access control
//!
//! An ungated surface ([`NamedPublisher::open`]) is discoverable *and* attachable
//! by anyone who knows the name. A **gated** surface (`open_gated` paired with
//! [`NamedSubscriber::connect_gated`]) keeps the name-derived rendezvous (so it is
//! still findable) but gates the fd-handshake on a caller secret — the secret never
//! appears on the wire or in the socket path and is bound to the name.
//!
//! Scope: the large-frame `SharedBuffer` path and 1:N fan-out remain seams for the
//! next phase.

use std::path::PathBuf;

use bytes::Bytes;
use ndn_app::Consumer;
use ndn_face_shm::{
    ShmFace, ShmHandle, ShmToken, connect_fd_handoff, control_socket_path, serve_fd_handoff,
};
use ndn_foundation_types::Name;
use ndn_packet::encode::DataBuilder;
use ndn_packet::tlv_type;
use ndn_transport::FaceId;

/// Default maximum frame size (ring slot) — 1 MiB. Override with
/// [`NamedPublisher::open_with_max_frame`].
const DEFAULT_MAX_FRAME: usize = 1 << 20;

#[derive(Debug, thiserror::Error)]
pub enum SurfaceError {
    #[error("shm: {0}")]
    Shm(#[from] ndn_face_shm::ShmError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("face: {0}")]
    Face(String),
    #[error("malformed frame on the wire")]
    Malformed,
}

/// **Rendezvous** token — derives the control-socket *path* from the name so both
/// sides find the same socket. This is *discovery*: anyone who knows the name can
/// locate (and, on an ungated surface, attach to) the surface. Distinct domain
/// separation from the capability token so a path value can never double as a gate.
fn rendezvous_token(name: &Name) -> ShmToken {
    sha256_parts(&[b"ndn-surface\x00rendezvous\x00", &name.encode_to_tlv()])
}

/// **Capability** token — the secret presented at the fd-handshake that gates
/// *who* may attach. Bound to the name (so a secret can't be lifted to another
/// surface at the same path) and domain-separated from the rendezvous token. An
/// ungated surface uses [`rendezvous_token`] as its capability (knowing the name
/// is sufficient); a gated surface uses this, keyed on a caller secret.
fn capability_token(name: &Name, secret: &[u8]) -> ShmToken {
    sha256_parts(&[b"ndn-surface\x00capability\x00", &name.encode_to_tlv(), secret])
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

/// Publishes a stream of named frames that a local consumer can attach to by
/// name and read zero-copy. SPSC: one subscriber per surface (a fan-out variant
/// is future work).
pub struct NamedPublisher {
    face: ShmFace,
    name: Name,
    seq: u64,
    path: PathBuf,
    serve: tokio::task::JoinHandle<()>,
}

impl NamedPublisher {
    /// Open an **ungated** surface named `name` (default 1 MiB max frame): anyone
    /// who knows the name may attach. For access control use
    /// [`open_gated`](Self::open_gated).
    pub async fn open(name: impl Into<Name>) -> Result<Self, SurfaceError> {
        let name = name.into();
        let cap = rendezvous_token(&name);
        Self::open_inner(name, DEFAULT_MAX_FRAME, cap).await
    }

    /// Open an ungated surface whose frames are up to `max_frame` bytes.
    pub async fn open_with_max_frame(
        name: impl Into<Name>,
        max_frame: usize,
    ) -> Result<Self, SurfaceError> {
        let name = name.into();
        let cap = rendezvous_token(&name);
        Self::open_inner(name, max_frame, cap).await
    }

    /// Open a **capability-gated** surface: the control socket is still found by
    /// name (discovery), but the fd-handshake is gated on `secret` — only a
    /// subscriber that presents the same secret via
    /// [`NamedSubscriber::connect_gated`] (or `connect_via_gated`) may attach. The
    /// secret never appears on the wire or in the socket path; it is bound to the
    /// name so it can't be replayed against another surface.
    pub async fn open_gated(
        name: impl Into<Name>,
        secret: &[u8],
    ) -> Result<Self, SurfaceError> {
        let name = name.into();
        let cap = capability_token(&name, secret);
        Self::open_inner(name, DEFAULT_MAX_FRAME, cap).await
    }

    async fn open_inner(
        name: Name,
        max_frame: usize,
        capability: ShmToken,
    ) -> Result<Self, SurfaceError> {
        // FaceId is irrelevant for a standalone surface — the facade picks one.
        let (face, fds) = ShmFace::create_anon_for_mtu(FaceId(0), max_frame)?;
        let path = control_socket_path(&rendezvous_token(&name));
        let _ = std::fs::remove_file(&path);
        let listener = tokio::net::UnixListener::bind(&path)?;
        let serve = tokio::spawn(async move {
            let _ = serve_fd_handoff(listener, capability, fds).await;
        });
        Ok(Self {
            face,
            name,
            seq: 0,
            path,
            serve,
        })
    }

    /// Publish the next frame: a signed NDN Data named `<surface>/v=<seq>` whose
    /// content is `content`, encoded **directly into the shared ring slot** (no
    /// socket transfer). Returns the frame's full name.
    pub async fn publish(&mut self, content: &[u8]) -> Result<Name, SurfaceError> {
        let frame_name = self.name.clone().append_version(self.seq);
        let b = DataBuilder::new(frame_name.clone(), content);
        let len = b.encoded_len_digest_sha256();
        self.face
            .send_with(len, |slot| {
                b.encode_digest_sha256_into(slot);
            })
            .await
            .map_err(|e| SurfaceError::Face(e.to_string()))?;
        self.seq += 1;
        Ok(frame_name)
    }

    /// The surface's name.
    pub fn name(&self) -> &Name {
        &self.name
    }
}

impl Drop for NamedPublisher {
    fn drop(&mut self) {
        self.serve.abort();
        let _ = std::fs::remove_file(&self.path);
    }
}

/// A frame delivered to a [`NamedSubscriber`] consumer: its NDN name plus a
/// **zero-copy borrowed view** of its content (valid only inside the
/// `next_frame` closure — copy out if you must retain it).
pub struct FrameRef<'a> {
    pub name: Name,
    pub content: &'a [u8],
}

/// Where a [`NamedSubscriber`]'s frames come from — chosen by name, hidden from
/// the consumer. Local is zero-copy over SHM; Remote pulls each frame by name
/// over the forwarder.
enum Source {
    /// A local publisher is serving — frames stream over the SHM ring.
    Local(ShmHandle),
    /// No local producer — fetch `<surface>/v=<seq>` over the forwarder.
    Remote { consumer: Consumer, seq: u64 },
}

/// Attaches to a named surface and reads its frames by name — zero-copy when the
/// producer is local, over the forwarder when it is remote, same call either way.
pub struct NamedSubscriber {
    source: Source,
    surface: Name,
}

impl NamedSubscriber {
    /// Attach to an **ungated local** surface named `name`, establishing the
    /// zero-copy SHM channel (retrying briefly until the publisher is serving).
    /// Errors if no local publisher appears — use [`connect_via`](Self::connect_via)
    /// for the location-transparent path, or [`connect_gated`](Self::connect_gated)
    /// for a capability-gated surface.
    pub async fn connect(name: impl Into<Name>) -> Result<Self, SurfaceError> {
        let surface = name.into();
        let cap = rendezvous_token(&surface);
        Self::connect_local_inner(surface, cap, 100).await
    }

    /// Attach to a **capability-gated local** surface, presenting `secret` at the
    /// handshake. Must match the publisher's [`open_gated`](NamedPublisher::open_gated)
    /// secret or the handshake is refused.
    pub async fn connect_gated(
        name: impl Into<Name>,
        secret: &[u8],
    ) -> Result<Self, SurfaceError> {
        let surface = name.into();
        let cap = capability_token(&surface, secret);
        Self::connect_local_inner(surface, cap, 100).await
    }

    async fn connect_local_inner(
        surface: Name,
        capability: ShmToken,
        attempts: u32,
    ) -> Result<Self, SurfaceError> {
        let path = control_socket_path(&rendezvous_token(&surface));
        let handle = local_connect(&path, capability, attempts).await?;
        Ok(Self {
            source: Source::Local(handle),
            surface,
        })
    }

    /// Attach to the surface named `name`, **wherever the producer is**: probe the
    /// name's local rendezvous and, if a publisher is serving here, take the
    /// zero-copy SHM path; otherwise fall back to fetching frames by name over the
    /// forwarder behind `consumer`. The returned subscriber is read identically in
    /// both cases — *that* is the transparency.
    pub async fn connect_via(
        name: impl Into<Name>,
        consumer: Consumer,
    ) -> Result<Self, SurfaceError> {
        let surface = name.into();
        let cap = rendezvous_token(&surface);
        Self::connect_via_inner(surface, cap, consumer).await
    }

    /// Like [`connect_via`](Self::connect_via), but presents `secret` at the local
    /// handshake (for a [`open_gated`](NamedPublisher::open_gated) producer on this
    /// host). The remote fallback is unaffected — remote authenticity is carried by
    /// NDN signing on the fetched Data, a separate concern from local attach gating.
    pub async fn connect_via_gated(
        name: impl Into<Name>,
        secret: &[u8],
        consumer: Consumer,
    ) -> Result<Self, SurfaceError> {
        let surface = name.into();
        let cap = capability_token(&surface, secret);
        Self::connect_via_inner(surface, cap, consumer).await
    }

    async fn connect_via_inner(
        surface: Name,
        capability: ShmToken,
        consumer: Consumer,
    ) -> Result<Self, SurfaceError> {
        let path = control_socket_path(&rendezvous_token(&surface));
        // A local publisher creates the control socket in `open`; its absence is
        // the cheap, race-free signal that the producer is not on this host.
        if path.exists() {
            // Short probe: tolerate the publisher-still-starting handshake race,
            // but don't stall a genuinely-remote attach on a stale socket.
            if let Ok(handle) = local_connect(&path, capability, 10).await {
                return Ok(Self {
                    source: Source::Local(handle),
                    surface,
                });
            }
        }
        Ok(Self {
            source: Source::Remote { consumer, seq: 0 },
            surface,
        })
    }

    /// Await the next frame and hand it to `f` as a [`FrameRef`] — its NDN name and
    /// its content. Local: content is **borrowed in place** (zero-copy). Remote:
    /// content is owned network bytes (still borrowed for the closure's duration).
    /// `None` when the surface closes (or a frame can't be fetched/parsed).
    pub async fn next_frame<R>(&mut self, f: impl FnOnce(FrameRef<'_>) -> R) -> Option<R> {
        match &mut self.source {
            Source::Local(handle) => handle
                .recv_with(|wire| match parse_frame(wire) {
                    Ok((name, content)) => Some(f(FrameRef { name, content })),
                    Err(_) => None,
                })
                .await
                .flatten(),
            Source::Remote { consumer, seq } => {
                let frame_name = self.surface.clone().append_version(*seq);
                let data = consumer.fetch(frame_name).await.ok()?;
                *seq += 1;
                let content = data.content().map(|b| b.as_ref()).unwrap_or(&[]);
                Some(f(FrameRef {
                    name: (*data.name).clone(),
                    content,
                }))
            }
        }
    }

    /// The surface prefix this subscriber is attached to.
    pub fn surface(&self) -> &Name {
        &self.surface
    }

    /// True if this subscriber resolved to the local zero-copy path.
    pub fn is_local(&self) -> bool {
        matches!(self.source, Source::Local(_))
    }
}

/// Establish the local zero-copy channel, retrying the (blocking) handshake up to
/// `attempts` times to absorb the publisher-still-starting race.
async fn local_connect(
    path: &std::path::Path,
    token: ShmToken,
    attempts: u32,
) -> Result<ShmHandle, SurfaceError> {
    let mut tried = 0u32;
    loop {
        let p = path.to_path_buf();
        let r = tokio::task::spawn_blocking(move || connect_fd_handoff(&p, &token))
            .await
            .map_err(|e| SurfaceError::Face(format!("join: {e}")))?;
        match r {
            Ok(h) => return Ok(h),
            Err(_) if tried + 1 < attempts => {
                tried += 1;
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            Err(e) => return Err(e.into()),
        }
    }
}

/// Borrowed parse of a Data wire: extract the Name (small, owned) and the Content
/// value (borrowed in place — the large part stays in the shared slot, no copy).
fn parse_frame(wire: &[u8]) -> Result<(Name, &[u8]), SurfaceError> {
    use ndn_tlv::read_varu64;
    let read = |buf: &[u8], pos: &mut usize| -> Result<u64, SurfaceError> {
        let (v, n) = read_varu64(&buf[*pos..]).map_err(|_| SurfaceError::Malformed)?;
        *pos += n;
        Ok(v)
    };

    let mut pos = 0usize;
    if read(wire, &mut pos)? != tlv_type::DATA {
        return Err(SurfaceError::Malformed);
    }
    let _inner_len = read(wire, &mut pos)?; // bound is the wire len; we walk to end

    let mut name: Option<Name> = None;
    let mut content: Option<&[u8]> = None;
    while pos < wire.len() {
        let typ = read(wire, &mut pos)?;
        let len = read(wire, &mut pos)? as usize;
        let start = pos;
        let end = start.checked_add(len).filter(|e| *e <= wire.len()).ok_or(SurfaceError::Malformed)?;
        match typ {
            t if t == tlv_type::NAME => {
                name = Some(
                    Name::decode(Bytes::copy_from_slice(&wire[start..end]))
                        .map_err(|_| SurfaceError::Malformed)?,
                );
            }
            t if t == tlv_type::CONTENT => {
                content = Some(&wire[start..end]);
            }
            _ => {}
        }
        pos = end;
    }
    Ok((name.ok_or(SurfaceError::Malformed)?, content.unwrap_or(&[])))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_app::{EngineBuilder, Producer};
    use ndn_engine::EngineConfig;
    use ndn_face_local::InProcFace;
    use ndn_security::KeyChain;
    use ndn_transport::FaceId;

    /// #4 (named-data transparency, local half): publish frames by name; a
    /// subscriber attaches by the SAME name and reads each frame zero-copy, with
    /// the frame's NDN name recovered from the wire. Through the public facade
    /// only — no fds/tokens/sockets touched by the test.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn named_surface_local_zero_copy_round_trip() {
        let surface = "/app/surface";
        let mut pubr = NamedPublisher::open(surface).await.unwrap();
        let mut sub = NamedSubscriber::connect(surface).await.unwrap();

        for i in 0..5u64 {
            let frame = vec![(i as u8).wrapping_add(1); 2000];
            let published = pubr.publish(&frame).await.unwrap();

            let (name, body) = sub
                .next_frame(|f| (f.name.clone(), f.content.to_vec()))
                .await
                .expect("frame");

            // By name: the wire-recovered name equals the published name (= /app/surface/v=i).
            assert_eq!(name, published, "frame {i} name round-trips on the wire");
            assert_eq!(name.to_string(), format!("/app/surface/v={i}"));
            // Zero-copy content (the test copies only to assert).
            assert_eq!(body, frame, "frame {i} content");
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn empty_content_frame() {
        let mut pubr = NamedPublisher::open("/s/empty").await.unwrap();
        let mut sub = NamedSubscriber::connect("/s/empty").await.unwrap();
        let published = pubr.publish(b"").await.unwrap();
        let name = sub.next_frame(|f| f.name.clone()).await.expect("frame");
        assert_eq!(name, published);
    }

    /// #4 (named-data transparency, REMOTE half): a producer lives across the
    /// forwarder (no local SHM publisher). `connect_via` finds no local rendezvous
    /// and transparently fetches frames by name over the engine — the *same*
    /// `next_frame()` consumer code as the local path, just not zero-copy.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn named_surface_remote_fetch_by_name() {
        // Two-face in-proc engine routing the surface prefix to the producer.
        let surface_str = "/remote/surface";
        let surface: Name = surface_str.parse().unwrap();
        let (consumer_face, consumer_handle) = InProcFace::new(FaceId(1), 256);
        let (producer_face, producer_handle) = InProcFace::new(FaceId(2), 256);
        let (engine, _shutdown) = EngineBuilder::new(EngineConfig::default())
            .face(consumer_face)
            .face(producer_face)
            .build()
            .await
            .expect("engine build");
        engine.fib().add_nexthop(&surface, FaceId(2), 0);

        // Remote producer: signs frames under the surface name, answers each
        // `<surface>/v=<seq>` Interest with that frame's content.
        let kc = KeyChain::ephemeral(surface_str).expect("keychain");
        let signer = kc.signer().expect("signer");
        let producer =
            Producer::from_handle(producer_handle, surface.clone()).with_signer(signer);
        let serve = tokio::spawn(async move {
            producer
                .serve(|interest, responder| async move {
                    // content keyed off the requested version so the test can check it
                    let n = interest.name.to_string();
                    let v = n.rsplit("v=").next().and_then(|s| s.parse::<u64>().ok());
                    if let Some(v) = v {
                        let frame = vec![(v as u8).wrapping_add(1); 2000];
                        let _ = responder.respond((*interest.name).clone(), frame).await;
                    }
                })
                .await
        });

        // No NamedPublisher::open for this name → the local rendezvous is absent,
        // so connect_via must take the remote path.
        let consumer = Consumer::from_handle(consumer_handle);
        let mut sub = NamedSubscriber::connect_via(surface.clone(), consumer)
            .await
            .unwrap();
        assert!(!sub.is_local(), "should have resolved to the remote path");

        for i in 0..5u64 {
            let expected = vec![(i as u8).wrapping_add(1); 2000];
            let (name, body) = sub
                .next_frame(|f| (f.name.clone(), f.content.to_vec()))
                .await
                .expect("remote frame");
            // Same by-name guarantee as local: the frame's name is /remote/surface/v=i.
            assert_eq!(name.to_string(), format!("/remote/surface/v={i}"));
            assert_eq!(body, expected, "remote frame {i} content");
        }
        serve.abort();
    }

    // ---- phase-2: capability auth ----------------------------------------

    /// A gated surface admits the holder of the right secret and reads frames
    /// normally — the secret never touches the wire or the (name-derived) path.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn capability_gated_round_trip() {
        let name = "/gated/ok";
        let secret = b"correct horse battery staple";
        let mut pubr = NamedPublisher::open_gated(name, secret).await.unwrap();
        let mut sub = NamedSubscriber::connect_gated(name, secret).await.unwrap();
        pubr.publish(b"for your eyes only").await.unwrap();
        let body = sub.next_frame(|f| f.content.to_vec()).await.expect("frame");
        assert_eq!(body, b"for your eyes only");
    }

    /// The gate actually gates: a connector presenting the wrong secret — or the
    /// public (name-only) token — is refused the fd-handoff. Driven at the handshake
    /// level (single attempt each) so the negatives don't burn the publisher's
    /// reject budget; both rejections land on a throwaway surface.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn capability_wrong_secret_and_public_token_rejected() {
        let surface: Name = "/gated/reject".parse().unwrap();
        let _pubr = NamedPublisher::open_gated("/gated/reject", b"right-secret")
            .await
            .unwrap();
        let path = control_socket_path(&rendezvous_token(&surface));

        // (a) wrong secret → rejected
        let wrong = capability_token(&surface, b"wrong-secret");
        let p1 = path.clone();
        let r1 = tokio::task::spawn_blocking(move || connect_fd_handoff(&p1, &wrong))
            .await
            .unwrap();
        assert!(r1.is_err(), "wrong secret must be refused the handoff");

        // (b) public/name-only token (would attach an ungated surface) → rejected
        let public = rendezvous_token(&surface);
        let p2 = path.clone();
        let r2 = tokio::task::spawn_blocking(move || connect_fd_handoff(&p2, &public))
            .await
            .unwrap();
        assert!(
            r2.is_err(),
            "knowing the name must NOT be enough on a gated surface"
        );

        // ...and the legitimate secret still attaches (budget not exhausted: 2<16).
        let good = NamedSubscriber::connect_gated("/gated/reject", b"right-secret")
            .await
            .unwrap();
        assert!(good.is_local(), "legitimate secret still attaches");
    }

    /// Rendezvous (path) and capability (gate) are domain-separated: even for an
    /// ungated surface the two derived tokens differ, so a path value can never
    /// double as a gate.
    #[test]
    fn rendezvous_and_capability_are_domain_separated() {
        let n: Name = "/x/y".parse().unwrap();
        assert_ne!(rendezvous_token(&n), capability_token(&n, b""));
        // distinct secrets ⇒ distinct capabilities; same secret different name ⇒ distinct
        assert_ne!(capability_token(&n, b"a"), capability_token(&n, b"b"));
        let m: Name = "/x/z".parse().unwrap();
        assert_ne!(capability_token(&n, b"a"), capability_token(&m, b"a"));
    }

    // ---- #5 failure / chaos / soak ---------------------------------------
    // The findings are the deliverable: what the surface does when things go
    // wrong, and whether any of it leaks or hangs.

    use std::time::Duration;
    use tokio::time::timeout;

    /// Spin a signed remote surface behind an in-proc engine; returns a Consumer
    /// reaching it plus the serve task + engine guard (keep alive for the test).
    async fn spawn_remote_surface(
        surface: &Name,
    ) -> (Consumer, tokio::task::JoinHandle<()>, impl Sized) {
        let (cf, ch) = InProcFace::new(FaceId(1), 256);
        let (pf, ph) = InProcFace::new(FaceId(2), 256);
        let (engine, shutdown) = EngineBuilder::new(EngineConfig::default())
            .face(cf)
            .face(pf)
            .build()
            .await
            .expect("engine build");
        engine.fib().add_nexthop(surface, FaceId(2), 0);
        let kc = KeyChain::ephemeral(surface.to_string()).expect("keychain");
        let signer = kc.signer().expect("signer");
        let producer = Producer::from_handle(ph, surface.clone()).with_signer(signer);
        let serve = tokio::spawn(async move {
            let _ = producer
                .serve(|interest, responder| async move {
                    let n = interest.name.to_string();
                    if let Some(v) = n.rsplit("v=").next().and_then(|s| s.parse::<u64>().ok()) {
                        let frame = vec![(v as u8).wrapping_add(1); 2000];
                        let _ = responder.respond((*interest.name).clone(), frame).await;
                    }
                })
                .await;
        });
        (Consumer::from_handle(ch), serve, (engine, shutdown))
    }

    /// CHAOS: publisher vanishes mid-stream. The consumer must (a) still drain the
    /// frames already buffered in the ring, then (b) see a clean **end-of-stream**
    /// (`None`) — not hang. (Pins the dogfood's FRICTION #11 as actually handled:
    /// the SHM wakeup-pipe EOF surfaces as `None`.)
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn publisher_drop_ends_stream_cleanly() {
        let mut pubr = NamedPublisher::open("/chaos/drop").await.unwrap();
        let mut sub = NamedSubscriber::connect("/chaos/drop").await.unwrap();
        for i in 0..3u64 {
            pubr.publish(&[i as u8; 100]).await.unwrap();
        }
        // Producer gone: aborts serve, removes socket, drops the ShmFace → the
        // consumer's wakeup pipe write end closes.
        drop(pubr);

        // (a) buffered frames survive the producer's exit (shared pages outlive it).
        for i in 0..3u64 {
            let body = timeout(Duration::from_secs(2), sub.next_frame(|f| f.content.to_vec()))
                .await
                .expect("must not hang on buffered frame")
                .expect("buffered frame still readable");
            assert_eq!(body, vec![i as u8; 100], "buffered frame {i}");
        }
        // (b) then clean end-of-stream, within a bound (proves no infinite park).
        let end = timeout(Duration::from_secs(2), sub.next_frame(|f| f.content.to_vec())).await;
        assert!(
            matches!(end, Ok(None)),
            "publisher gone ⇒ end-of-stream None, got {end:?}"
        );
    }

    /// CHAOS: a crashed publisher left a stale control socket. `connect_via` must
    /// not get stuck on the dead local path — it probes, the handshake fails, and
    /// it transparently falls back to the remote forwarder fetch.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stale_socket_falls_back_to_remote() {
        let surface: Name = "/chaos/stale".parse().unwrap();
        // Simulate the crash residue: bind then drop a listener — the socket file
        // remains (Unix doesn't unlink on close) but connects are refused.
        let path = control_socket_path(&rendezvous_token(&surface));
        let _ = std::fs::remove_file(&path);
        drop(tokio::net::UnixListener::bind(&path).expect("bind stale socket"));
        assert!(path.exists(), "stale socket should be present for the probe");

        let (consumer, serve, _engine) = spawn_remote_surface(&surface).await;
        let mut sub = NamedSubscriber::connect_via(surface.clone(), consumer)
            .await
            .unwrap();
        assert!(
            !sub.is_local(),
            "stale local socket must not be taken — should fall back to remote"
        );
        let name = sub.next_frame(|f| f.name.clone()).await.expect("remote frame");
        assert_eq!(name.to_string(), "/chaos/stale/v=0");
        serve.abort();
        let _ = std::fs::remove_file(&path);
    }

    /// CHAOS: a slow consumer with a tiny ring (1 MiB slots ⇒ ~2 frames buffered).
    /// The producer must block on a full ring (backpressure) rather than drop or
    /// corrupt — every frame arrives, in order, intact.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn slow_consumer_backpressure_no_loss() {
        const N: u64 = 64;
        let mut pubr = NamedPublisher::open("/chaos/backpressure").await.unwrap();
        let mut sub = NamedSubscriber::connect("/chaos/backpressure").await.unwrap();

        // Producer races ahead; send_with parks when the ring is full.
        let prod = tokio::spawn(async move {
            for i in 0..N {
                pubr.publish(&[(i & 0xff) as u8; 1000]).await.unwrap();
            }
            pubr // keep alive until the consumer is done
        });

        for i in 0..N {
            let body = timeout(Duration::from_secs(5), sub.next_frame(|f| f.content.to_vec()))
                .await
                .expect("no stall under backpressure")
                .expect("frame");
            assert_eq!(
                body,
                vec![(i & 0xff) as u8; 1000],
                "frame {i} order/integrity under backpressure"
            );
            tokio::time::sleep(Duration::from_millis(1)).await; // be slow on purpose
        }
        let _pubr = prod.await.unwrap();
    }

    /// SOAK: many open→publish→read→drop cycles. Asserts each cycle's control
    /// socket is cleaned up on publisher drop, and the process fd count does not
    /// grow per cycle (a leak would add ~fds-per-face × cycles).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn soak_no_socket_or_fd_leak() {
        // macOS/Linux: /dev/fd lists this process's open fds.
        let fd_count = || std::fs::read_dir("/dev/fd").map(|d| d.count()).unwrap_or(0);
        const CYCLES: u64 = 40;
        const FRAMES: u64 = 10;

        // Warm up one cycle so first-touch allocations don't count as "growth".
        let baseline_after_warmup;
        {
            let mut p = NamedPublisher::open("/soak/warmup").await.unwrap();
            let mut s = NamedSubscriber::connect("/soak/warmup").await.unwrap();
            p.publish(b"x").await.unwrap();
            s.next_frame(|_| ()).await.unwrap();
            drop(p);
            drop(s);
            baseline_after_warmup = fd_count();
        }

        for cycle in 0..CYCLES {
            let name = format!("/soak/{cycle}");
            let mut pubr = NamedPublisher::open(name.as_str()).await.unwrap();
            let mut sub = NamedSubscriber::connect(name.as_str()).await.unwrap();
            for i in 0..FRAMES {
                pubr.publish(&[i as u8; 500]).await.unwrap();
                let body = sub.next_frame(|f| f.content.to_vec()).await.expect("frame");
                assert_eq!(body, vec![i as u8; 500]);
            }
            let path = control_socket_path(&rendezvous_token(&name.parse::<Name>().unwrap()));
            drop(pubr);
            drop(sub);
            assert!(!path.exists(), "cycle {cycle}: control socket left behind");
        }

        let after = fd_count();
        assert!(
            after <= baseline_after_warmup + 8,
            "fd leak across {CYCLES} cycles: warmup={baseline_after_warmup} after={after}"
        );
    }

    // ---- #3 generality ---------------------------------------------------
    // The API is shaped for "a stream of versioned frames". Probe a different
    // surface shape to see what that bakes in. See g11-generality-2026-06-21.md
    // for the full catalogue (request/reply, fan-in, last-value all need new API).

    /// GENERALITY: does the stream model carry a *finite ordered object* (a bulk
    /// file)? Yes — chunk into frames; use publisher-drop (→ None, proven in #5) as
    /// the EOF marker; the consumer reads-until-None and reassembles, byte-identical.
    /// FRICTION (the deliverable): the consumer never learns the content length or
    /// chunk count up front (no preallocation, no progress %), and a clean end is
    /// indistinguishable from a crash — "read until None" is the *entire* object
    /// protocol, with no completion/integrity marker. The missing primitive is
    /// object framing (length + last-segment/FinalBlockId), which RDR already has at
    /// the app layer but the surface facade does not expose.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bulk_object_via_frames_drop_as_eof() {
        const CHUNK: usize = 60_000;
        let original: Vec<u8> = (0..1_000_000u32).map(|i| (i % 251) as u8).collect();

        let name = "/bulk/file";
        let mut pubr = NamedPublisher::open_with_max_frame(name, 64 * 1024)
            .await
            .unwrap();
        let mut sub = NamedSubscriber::connect(name).await.unwrap();

        let data = original.clone();
        let prod = tokio::spawn(async move {
            for chunk in data.chunks(CHUNK) {
                pubr.publish(chunk).await.unwrap();
            }
            drop(pubr); // EOF = drop — the only completion signal the API offers.
        });

        // The consumer does NOT know the length or chunk count.
        let reassembled = timeout(Duration::from_secs(10), async move {
            let mut r = Vec::new();
            while let Some(chunk) = sub.next_frame(|f| f.content.to_vec()).await {
                r.extend_from_slice(&chunk);
            }
            r
        })
        .await
        .expect("bulk transfer must terminate (drop ⇒ None)");
        prod.await.unwrap();

        assert_eq!(reassembled.len(), original.len(), "bulk length");
        assert_eq!(reassembled, original, "bulk object reassembles byte-identical");
    }
}
