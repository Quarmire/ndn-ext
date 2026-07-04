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
//! part needs nothing but [`Frame`] + [`Name`], both `no_std`, so it
//! lives in this foundation crate rather than a separate one: a leaf depends on
//! `ndn-service-core` with `default-features = false` and nothing else.
//!
//! - **Typed.** A value implements [`Frame`] (hand-written, or
//!   `#[derive(Frame)]` from `ndn-service-macro` — proc-macros run on the host, so
//!   the derive is available to `no_std` leaves too). The gateway decodes with the
//!   *same* `Frame`, so leaf and node speak one message format.
//! - **Confidential, cheaply.** With the `seal` feature a `ScopeKey` seals each
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
/// payload bytes (the encoded [`Frame`], or — with the `seal`
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
/// Frames each value with its [`Frame`], names it `<topic>/seq=N`
/// (the NDN sequence-number naming convention), and hands the [`Publication`] to a
/// [`PublicationSink`]. Holds only the topic name, the next sequence number, and
/// (with `seal`) an optional seal context (scope key + publisher id) — no buffers,
/// no runtime.
pub struct Publisher<T> {
    topic: Name,
    seq: u64,
    #[cfg(feature = "seal")]
    seal: Option<SealCtx>,
    _marker: PhantomData<fn() -> T>,
}

/// A confidential publisher's seal state: the scope key plus this publisher's
/// unique id (the AEAD nonce prefix, so two leaves sharing a scope key never
/// collide nonces).
#[cfg(feature = "seal")]
struct SealCtx {
    key: ScopeKey,
    publisher_id: [u8; 4],
}

impl<T: Frame> Publisher<T> {
    /// A publisher of `T` onto `topic`; publications are named `<topic>/seq=N`,
    /// starting at `seq=0`.
    pub fn new(topic: Name) -> Self {
        Self {
            topic,
            seq: 0,
            #[cfg(feature = "seal")]
            seal: None,
            _marker: PhantomData,
        }
    }

    /// A confidential publisher: each publication is sealed under `key` before it
    /// reaches the sink.
    ///
    /// `publisher_id` MUST be **unique among every leaf that shares this scope
    /// key** (the gateway assigns it at provisioning, e.g. a small per-device
    /// index). It forms the high 4 bytes of the AEAD nonce; the sequence forms the
    /// low 8. Distinct ids guarantee distinct nonces across the fleet, and a
    /// monotonic sequence guarantees distinct nonces within one leaf — together the
    /// nonce-uniqueness ChaCha20-Poly1305 requires. See [`ScopeKey`] for the
    /// across-reboot sequence requirement.
    #[cfg(feature = "seal")]
    pub fn sealed(topic: Name, key: ScopeKey, publisher_id: u32) -> Self {
        Self {
            topic,
            seq: 0,
            seal: Some(SealCtx {
                key,
                publisher_id: publisher_id.to_be_bytes(),
            }),
            _marker: PhantomData,
        }
    }

    /// Resume the sequence at `seq` (restored from persistent storage on boot).
    ///
    /// With `seal` this is **load-bearing, not advisory**: the sequence is the low
    /// 8 bytes of the AEAD nonce, so it MUST be strictly monotonic across reboots
    /// under a reused key. A leaf without reliable non-volatile storage MUST take a
    /// fresh scope key (or a fresh `publisher_id`) each boot instead — otherwise a
    /// reboot replays nonces and ChaCha20-Poly1305's guarantees collapse.
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
        // When sealing, bind the publication name as AAD (the same discipline
        // `ContentKey` callers follow), so name and ciphertext are tamper-evident
        // together and a native open agrees on the bound bytes. The nonce is
        // `publisher_id ‖ seq` — unique across leaves (distinct id) and across this
        // leaf's messages (monotonic seq).
        #[cfg(feature = "seal")]
        let payload = match &self.seal {
            Some(ctx) => {
                let mut nonce = [0u8; 12];
                nonce[..4].copy_from_slice(&ctx.publisher_id);
                nonce[4..].copy_from_slice(&self.seq.to_be_bytes());
                ctx.key.seal(nonce, &name.encode_to_tlv(), &frame)
            }
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
/// ## Nonce discipline (the caller's responsibility)
///
/// [`seal`](Self::seal) takes the 12-byte nonce explicitly — like `ContentKey`,
/// `ScopeKey` is the cipher primitive and does **not** choose nonces. [`Publisher`]
/// builds the nonce as `publisher_id ‖ seq` (no RNG on the leaf): a per-leaf id
/// (unique across leaves sharing the key) over a monotonic sequence (unique within
/// a leaf). The sequence MUST stay monotonic across reboots under a reused key — or
/// rekey on boot — exactly the ChaCha20-Poly1305 nonce-uniqueness requirement. A
/// caller using `ScopeKey` directly owns this discipline.
///
/// ## Wire envelope (aligned with `ndn-security`'s `ContentKey`)
///
/// A sealed payload is `nonce ‖ tag ‖ ciphertext` — byte-for-byte the layout of
/// `ndn-security`'s [`Sealed::to_bytes`], so a gateway opens a leaf's publication
/// directly with `Sealed::from_bytes(payload)` + `ContentKey::open` (the two share
/// the ChaCha20-Poly1305 cipher core via `ndn-crypto-core`). The nonce is **carried
/// on the wire**, so the reader is agnostic to how it was chosen: [`open`](Self::open)
/// reads the nonce from the payload and therefore opens both leaf-sealed
/// (`publisher_id ‖ seq` nonce) and `ContentKey`-sealed (random nonce) payloads.
///
/// The AAD is the publication's name ([`Name::encode_to_tlv`](ndn_packet::Name)),
/// which [`Publisher`] binds automatically — the same name-binding discipline
/// `ContentKey` callers follow, so a leaf seal and a native open agree on it.
///
/// The raw key is zeroized on drop ([`zeroize::ZeroizeOnDrop`]).
///
/// [`Sealed::to_bytes`]: https://docs.rs/ndn-security
#[cfg(feature = "seal")]
#[derive(Clone, zeroize::ZeroizeOnDrop)]
pub struct ScopeKey {
    key: [u8; 32],
}

/// AEAD nonce length — matches `ndn-security`'s `NONCE_LEN`.
#[cfg(feature = "seal")]
const NONCE_LEN: usize = 12;
/// AEAD tag length — matches `ndn-security`'s `TAG_LEN`.
#[cfg(feature = "seal")]
const TAG_LEN: usize = 16;

#[cfg(feature = "seal")]
impl ScopeKey {
    /// Wrap the raw 32-byte key bytes a gateway delivered to this leaf.
    pub fn from_bytes(key: [u8; 32]) -> Self {
        Self { key }
    }

    /// Seal `plaintext` under the explicit 12-byte `nonce`, binding `aad`. Output is
    /// the `ContentKey` wire layout — `nonce ‖ tag ‖ ciphertext` — openable by
    /// `ndn-security`'s `ContentKey::open` after `Sealed::from_bytes`.
    ///
    /// The caller MUST ensure `nonce` is unique per message under this key (see the
    /// type docs); reusing a nonce breaks ChaCha20-Poly1305 catastrophically.
    pub fn seal(&self, nonce: [u8; NONCE_LEN], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let mut buf = plaintext.to_vec();
        let tag = ndn_crypto_core::seal_in_place(&self.key, &nonce, aad, &mut buf)
            .expect("scope key is 32 bytes");
        let mut out = Vec::with_capacity(NONCE_LEN + TAG_LEN + buf.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&tag);
        out.extend_from_slice(&buf);
        out
    }

    /// Open a payload in the `nonce ‖ tag ‖ ciphertext` layout, verifying `aad`.
    /// Reads the nonce from the wire, so it opens both leaf-sealed and
    /// `ContentKey`-sealed payloads. `None` if authentication fails (wrong key,
    /// wrong AAD, or tampering).
    pub fn open(&self, aad: &[u8], sealed: &[u8]) -> Option<Vec<u8>> {
        if sealed.len() < NONCE_LEN + TAG_LEN {
            return None;
        }
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&sealed[..NONCE_LEN]);
        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&sealed[NONCE_LEN..NONCE_LEN + TAG_LEN]);
        let mut buf = sealed[NONCE_LEN + TAG_LEN..].to_vec();
        if ndn_crypto_core::open_in_place(&self.key, &nonce, aad, &mut buf, &tag) {
            Some(buf)
        } else {
            None
        }
    }
}
