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
//! let sub = NamedSubscriber::connect("/app/surface").await?;
//! sub.next_frame(|f| println!("{} = {} bytes", f.name, f.content.len())).await;
//! # Ok(()) }
//! ```
//!
//! Scope (G11 increment-4 facade, first cut): the **local** zero-copy path,
//! framed NDN Data over the ring (consumer content is borrowed in place). The
//! remote-transparent fallback (`connect` → forwarder fetch when the producer is
//! not on this host) and the large-frame `SharedBuffer` path are seams for the
//! next phase; the API is shaped so they slot in behind the same calls.

use std::path::PathBuf;

use bytes::Bytes;
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

/// The local rendezvous for a surface is derived from its name (so both sides
/// compute the same control socket). This is *discovery*, not auth — a published
/// surface is meant to be found by name; restricting *who* may read is a separate
/// capability layer (a real secret token over the name-resolution path) and is
/// not yet wired here.
fn surface_token(name: &Name) -> ShmToken {
    use sha2::{Digest, Sha256};
    let mut t = [0u8; 32];
    t.copy_from_slice(&Sha256::digest(name.encode_to_tlv()));
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
    /// Open a surface named `name` for publishing (default 1 MiB max frame).
    pub async fn open(name: impl Into<Name>) -> Result<Self, SurfaceError> {
        Self::open_with_max_frame(name, DEFAULT_MAX_FRAME).await
    }

    /// Open a surface whose frames are up to `max_frame` bytes.
    pub async fn open_with_max_frame(
        name: impl Into<Name>,
        max_frame: usize,
    ) -> Result<Self, SurfaceError> {
        let name = name.into();
        let token = surface_token(&name);
        // FaceId is irrelevant for a standalone surface — the facade picks one.
        let (face, fds) = ShmFace::create_anon_for_mtu(FaceId(0), max_frame)?;
        let path = control_socket_path(&token);
        let _ = std::fs::remove_file(&path);
        let listener = tokio::net::UnixListener::bind(&path)?;
        let serve = tokio::spawn(async move {
            let _ = serve_fd_handoff(listener, token, fds).await;
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

/// Attaches to a named surface and reads its frames; gets local zero-copy when
/// the producer is on this host.
pub struct NamedSubscriber {
    handle: ShmHandle,
    surface: Name,
}

impl NamedSubscriber {
    /// Attach to the surface named `name`. Locally this establishes the
    /// zero-copy SHM channel (retrying briefly until the publisher is serving).
    pub async fn connect(name: impl Into<Name>) -> Result<Self, SurfaceError> {
        let surface = name.into();
        let token = surface_token(&surface);
        let path = control_socket_path(&token);
        let handle = {
            let mut attempt = 0u32;
            loop {
                let p = path.clone();
                let r = tokio::task::spawn_blocking(move || connect_fd_handoff(&p, &token))
                    .await
                    .map_err(|e| SurfaceError::Face(format!("join: {e}")))?;
                match r {
                    Ok(h) => break h,
                    Err(_) if attempt < 100 => {
                        attempt += 1;
                        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                    }
                    Err(e) => return Err(e.into()),
                }
            }
        };
        Ok(Self { handle, surface })
    }

    /// Await the next frame and hand it to `f` as a borrowed [`FrameRef`] — its
    /// NDN name and a zero-copy view of its content. `None` when the surface
    /// closes (or a malformed frame is seen).
    pub async fn next_frame<R>(&self, f: impl FnOnce(FrameRef<'_>) -> R) -> Option<R> {
        self.handle
            .recv_with(|wire| match parse_frame(wire) {
                Ok((name, content)) => Some(f(FrameRef { name, content })),
                Err(_) => None,
            })
            .await
            .flatten()
    }

    /// The surface prefix this subscriber is attached to.
    pub fn surface(&self) -> &Name {
        &self.surface
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

    /// #4 (named-data transparency, local half): publish frames by name; a
    /// subscriber attaches by the SAME name and reads each frame zero-copy, with
    /// the frame's NDN name recovered from the wire. Through the public facade
    /// only — no fds/tokens/sockets touched by the test.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn named_surface_local_zero_copy_round_trip() {
        let surface = "/app/surface";
        let mut pubr = NamedPublisher::open(surface).await.unwrap();
        let sub = NamedSubscriber::connect(surface).await.unwrap();

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
        let sub = NamedSubscriber::connect("/s/empty").await.unwrap();
        let published = pubr.publish(b"").await.unwrap();
        let name = sub.next_frame(|f| f.name.clone()).await.expect("frame");
        assert_eq!(name, published);
    }
}
