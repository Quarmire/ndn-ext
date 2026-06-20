//! The embedded-facing **leaf producer** — the lightest surface for a constrained
//! device (an ESP32-class sensor) to put *typed, named, optionally confidential*
//! data on the air, using only the `no_std` message layer of this crate.
//!
//! # Why this lives here
//!
//! The full service layer ([`ndn-service`], [`ndn-ndnsf`]) and its `Topic<T>` feed
//! assume an async runtime, an SVS sync group, and `std` — the right shape for a
//! *capable* node, the wrong shape for a sensor. The service-layer role split (see
//! `docs/specs/service-layer.md`) already puts the heavy machinery — ABE, policy
//! authorities, SVS coordination — on the gateway, leaving the leaf the cheap part:
//! **frame a value, name it, seal it with a symmetric key, emit it.** That cheap
//! part needs nothing but [`Frame`](crate::Frame) + [`Name`], both `no_std`, so it
//! lives in this foundation crate rather than a separate one: a leaf depends on
//! `ndn-service-core` with `default-features = false` and nothing else.
//!
//! - **Typed.** A value implements [`Frame`](crate::Frame) (hand-written, or
//!   `#[derive(Frame)]` from `ndn-service-macro` — proc-macros run on the host, so
//!   the derive is available to `no_std` leaves too). The gateway decodes with the
//!   *same* `Frame`, so leaf and node speak one message format.
//! - **Confidential, cheaply.** With the `seal` feature a [`ScopeKey`] seals each
//!   publication with ChaCha20-Poly1305 — the same AEAD the rest of the stack uses
//!   (via `ndn-crypto-core`), an embedded-appropriate cipher (no pairings, no RNG
//!   on the hot path). The leaf *holds* a symmetric scope key; the gateway
//!   *distributes* it (ABE-by-role / sealed-box). That asymmetry is the point.
//!
//! `ndn-publish` builds a [`Publication`] (a name + payload bytes) and hands it to
//! a [`PublicationSink`] — the one trait the platform implements, over whatever
//! link it has (ESP-NOW broadcast, a raw 802.11 monitor-mode frame, a UART, or a
//! UDP socket on a more capable node). A capable node downstream ingests these
//! named publications into the full `Topic<T>` / SVS world; the leaf need not know.
//!
//! ```
//! use ndn_service_core::publish::{Publisher, Publication, PublicationSink};
//! use ndn_service_core::Frame;
//!
//! // A sink that just collects publications (a real one would transmit).
//! #[derive(Default)]
//! struct Collect(Vec<Publication>);
//! impl PublicationSink for Collect {
//!     type Error = core::convert::Infallible;
//!     fn deliver(&mut self, p: &Publication) -> Result<(), Self::Error> {
//!         self.0.push(p.clone());
//!         Ok(())
//!     }
//! }
//!
//! let mut sensor = Publisher::<u32>::new("/sensor/temp".parse().unwrap());
//! let mut sink = Collect::default();
//! sensor.publish(&21, &mut sink).unwrap();      // -> /sensor/temp/seq=0
//! sensor.publish(&22, &mut sink).unwrap();      // -> /sensor/temp/seq=1
//! assert_eq!(sink.0.len(), 2);
//! assert_eq!(u32::decode(&sink.0[1].payload).unwrap(), 22);
//! ```
//!
//! [`ndn-service`]: https://docs.rs/ndn-service
//! [`ndn-ndnsf`]: https://docs.rs/ndn-ndnsf

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use core::marker::PhantomData;

use ndn_packet::Name;

use crate::Frame;

/// A named, ready-to-transmit publication: the NDN name (`<topic>/seq=N`) and its
/// payload bytes (the encoded [`Frame`](crate::Frame), or — with the `seal`
/// feature — the sealed frame). A [`PublicationSink`] is what actually puts it on
/// the air; building it is allocation-light and runtime-free.
#[derive(Clone, Debug)]
pub struct Publication {
    /// The publication's NDN name.
    pub name: Name,
    /// The payload bytes carried under that name.
    pub payload: Vec<u8>,
}

/// The platform's transmit seam — the one trait a constrained target implements,
/// over whatever link it has: an ESP-NOW broadcast, a raw 802.11 monitor-mode
/// frame, a UART, or a UDP socket on a more capable node. The producer builds the
/// [`Publication`]; the sink emits it.
///
/// Keeping all I/O behind this trait is what lets the producer be `no_std` and own
/// no executor — the leaf hands the sink a finished publication and is done. A real
/// sink typically wraps the payload in a signed NDN Data object before transmission
/// (or relies on a downstream gateway to do so); that wrapping is the platform's
/// concern, not the producer's.
pub trait PublicationSink {
    /// The platform's transmit error.
    type Error;

    /// Emit `publication` on the link.
    fn deliver(&mut self, publication: &Publication) -> Result<(), Self::Error>;
}

/// A typed, append-only **feed producer** for a constrained leaf.
///
/// Frames each value with its [`Frame`](crate::Frame), names it `<topic>/seq=N`
/// (the NDN sequence-number naming convention), and hands the [`Publication`] to a
/// [`PublicationSink`]. Holds only the topic name, the next sequence number, and
/// (with `seal`) an optional scope key — no buffers, no runtime.
pub struct Publisher<T> {
    topic: Name,
    seq: u64,
    #[cfg(feature = "seal")]
    key: Option<ScopeKey>,
    _marker: PhantomData<fn() -> T>,
}

impl<T: Frame> Publisher<T> {
    /// A publisher of `T` onto `topic`; publications are named `<topic>/seq=N`,
    /// starting at `seq=0`.
    pub fn new(topic: Name) -> Self {
        Self {
            topic,
            seq: 0,
            #[cfg(feature = "seal")]
            key: None,
            _marker: PhantomData,
        }
    }

    /// A confidential publisher: each publication is sealed under `key` before it
    /// reaches the sink (see [`ScopeKey`] for the nonce/sequence caveat).
    #[cfg(feature = "seal")]
    pub fn sealed(topic: Name, key: ScopeKey) -> Self {
        Self {
            topic,
            seq: 0,
            key: Some(key),
            _marker: PhantomData,
        }
    }

    /// Resume the sequence at `seq` (e.g. restored from persistent storage on
    /// boot). With `seal` this matters: the sequence is the AEAD nonce, so it MUST
    /// be monotonic across reboots when a key is reused — persist it, or rekey.
    pub fn starting_at(mut self, seq: u64) -> Self {
        self.seq = seq;
        self
    }

    /// The sequence number the next publication will carry.
    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// Build the next publication — frame `value`, name it `<topic>/seq=N`, seal it
    /// if keyed — **without advancing**. For callers that drive transmission
    /// themselves (and then call [`advance`](Self::advance)).
    pub fn build(&self, value: &T) -> Publication {
        let frame = value.encode();
        let name = self.topic.clone().append_sequence_num(self.seq);
        #[cfg(feature = "seal")]
        let payload = match &self.key {
            Some(k) => k.seal(self.seq, &frame),
            None => frame.to_vec(),
        };
        #[cfg(not(feature = "seal"))]
        let payload = frame.to_vec();
        Publication { name, payload }
    }

    /// Advance the sequence (pairs with [`build`](Self::build) for callers that
    /// transmit publications themselves).
    pub fn advance(&mut self) {
        self.seq += 1;
    }

    /// Frame `value`, name it, deliver it via `sink`, and advance the sequence.
    /// Returns the published name on success.
    pub fn publish<S: PublicationSink>(
        &mut self,
        value: &T,
        sink: &mut S,
    ) -> Result<Name, S::Error> {
        let publication = self.build(value);
        let name = publication.name.clone();
        sink.deliver(&publication)?;
        self.seq += 1;
        Ok(name)
    }
}

/// A symmetric **scope key** for confidential publishing — ChaCha20-Poly1305, the
/// same AEAD primitive the rest of the stack uses (via `ndn-crypto-core`, so a leaf
/// seal and a native `ContentKey` open share their cipher core).
///
/// The role asymmetry that makes this embedded-appropriate: the *gateway* runs the
/// heavy key distribution (ABE-by-role, sealed-box) and hands a leaf only the
/// finished 32-byte scope key; the *leaf* holds that key and seals with it. No
/// pairings, no asymmetric crypto, no key exchange on the device.
///
/// ## Nonce / sequence caveat
///
/// The AEAD nonce is derived from the publication's sequence number, so **no RNG is
/// needed on the leaf** — but the sequence MUST be unique per message under one
/// key. An append-only feed satisfies this naturally *within a boot*; across
/// reboots, either persist the sequence (and resume with
/// [`Publisher::starting_at`]) or take a fresh key, or a nonce repeats and
/// ChaCha20-Poly1305's guarantees collapse.
///
/// ## Faithfulness
///
/// The cipher core is shared with the stack; the *envelope* here is minimal
/// (`ciphertext || 16-byte tag`, empty AAD). Aligning the envelope byte-for-byte
/// with `ndn-security`'s `ContentKey` — and binding the publication name as AAD —
/// is a tracked hardening step (see the spec, `docs/specs/service-layer.md` §13).
#[cfg(feature = "seal")]
#[derive(Clone)]
pub struct ScopeKey {
    key: [u8; 32],
}

#[cfg(feature = "seal")]
impl ScopeKey {
    /// Wrap the raw 32-byte key bytes a gateway delivered to this leaf.
    pub fn from_bytes(key: [u8; 32]) -> Self {
        Self { key }
    }

    /// Seal `plaintext` for sequence `seq`. Output is `ciphertext || 16-byte tag`.
    /// See the type docs for the sequence/nonce requirement.
    pub fn seal(&self, seq: u64, plaintext: &[u8]) -> Vec<u8> {
        let mut buf = plaintext.to_vec();
        let nonce = nonce_for(seq);
        let tag = ndn_crypto_core::seal_in_place(&self.key, &nonce, &[], &mut buf)
            .expect("scope key is 32 bytes");
        buf.extend_from_slice(&tag);
        buf
    }

    /// Open a [`seal`](Self::seal)ed payload for sequence `seq`. Returns `None` if
    /// authentication fails (wrong key, wrong sequence, or tampering).
    pub fn open(&self, seq: u64, sealed: &[u8]) -> Option<Vec<u8>> {
        if sealed.len() < 16 {
            return None;
        }
        let (body, tag) = sealed.split_at(sealed.len() - 16);
        let mut buf = body.to_vec();
        let mut t = [0u8; 16];
        t.copy_from_slice(tag);
        let nonce = nonce_for(seq);
        if ndn_crypto_core::open_in_place(&self.key, &nonce, &[], &mut buf, &t) {
            Some(buf)
        } else {
            None
        }
    }
}

/// Derive a 12-byte AEAD nonce from a sequence number (big-endian in the low 8
/// bytes). Unique per sequence ⇒ unique per message under one key.
#[cfg(feature = "seal")]
fn nonce_for(seq: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&seq.to_be_bytes());
    nonce
}
