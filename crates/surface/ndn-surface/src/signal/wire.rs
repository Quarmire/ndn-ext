//! The signal wire (TLV-TYPEs 0x0580–0x05AF, ndn-rs `docs/specs/signals.md`).
//!
//! A **packet** is a `SignalBody` (unsealed scope) or a `SignalSealed` (sealed
//! scope), at most [`PACKET_MAX`] octets. It rides as the ApplicationParameters of
//! a push Interest `<group>/32=signal/<ParametersSha256Digest>` and, unchanged, as
//! a frame of a run's local ring. Every TLV-TYPE here is even: a decoder skips an
//! unknown even element and refuses an unknown odd one.
//!
//! This module needs no device: a capture tool decodes what a relay carries with
//! [`decode_packet`] and [`decode_run_header_body`].

use std::fmt;

use bytes::Bytes;
use ndn_foundation_types::{Name, NameComponent};
use ndn_packet::Interest;
use ndn_packet::tlv_type;
use ndn_tlv::TlvReader;
use ndn_tlv::writer::tlv_size;
use sha2::{Digest, Sha256};

/// `SignalBody`: Name (scope), RunId, \[RunHeader\], Signal* (0–32; at least one
/// unless RunHeader rides), RunSignature.
pub const SIGNAL_BODY: u64 = 0x0580;
/// `SignalSealed`: KeyId, SealNonce, Ciphertext.
pub const SIGNAL_SEALED: u64 = 0x0582;
/// `KeyId`: 8 octets, the signal key's id.
pub const KEY_ID: u64 = 0x0584;
/// `SealNonce`: 24 random octets.
pub const SEAL_NONCE: u64 = 0x0586;
/// `Ciphertext`: XChaCha20-Poly1305 of the `SignalBody` TLV, tag appended.
pub const CIPHERTEXT: u64 = 0x0588;
/// `RunId`: 16 octets, SHA-256(run public key)[0..16].
pub const RUN_ID: u64 = 0x058A;
/// `RunHeader`: the run header's whole Data wire.
pub const RUN_HEADER: u64 = 0x058C;
/// `Signal`: SignalSeq, Address, Expires, Payload.
pub const SIGNAL: u64 = 0x058E;
/// `SignalSeq`: NonNegativeInteger.
pub const SIGNAL_SEQ: u64 = 0x0590;
/// `Address`: 0–64 octets.
pub const ADDRESS: u64 = 0x0592;
/// `Expires`: NonNegativeInteger, ms since the Unix epoch.
pub const EXPIRES: u64 = 0x0594;
/// `Payload`: 0–768 octets.
pub const PAYLOAD: u64 = 0x0596;
/// `RunSignature`: 64 octets, Ed25519 by the run key.
pub const RUN_SIGNATURE: u64 = 0x0598;
/// `RunHeaderBody`: RunKey, RunStart, RunNotAfter, \[LocalRing\] (the header's Content).
pub const RUN_HEADER_BODY: u64 = 0x059A;
/// `RunKey`: 32 octets, Ed25519 public key.
pub const RUN_KEY: u64 = 0x059C;
/// `RunStart`: NonNegativeInteger, the run's first sequence.
pub const RUN_START: u64 = 0x059E;
/// `RunNotAfter`: NonNegativeInteger, ms since the Unix epoch.
pub const RUN_NOT_AFTER: u64 = 0x05A0;
/// `LocalRing`: 32 octets, the run's ring secret.
pub const LOCAL_RING: u64 = 0x05A2;

/// Domain separation of the run signature and of the seal's associated data.
pub const CONTEXT: &[u8] = b"ndn-signal/1";
/// The most octets a packet's whole encoding may take.
pub const PACKET_MAX: usize = 1024;
/// The most octets of an address.
pub const ADDRESS_MAX: usize = 64;
/// The most octets of a payload.
pub const PAYLOAD_MAX: usize = 768;
/// The most signals in one packet.
pub const SIGNALS_MAX: usize = 32;
/// Octets of a key id.
pub const KEY_ID_LEN: usize = 8;
/// Octets of a seal nonce.
pub const NONCE_LEN: usize = 24;
/// Octets of the Poly1305 tag appended to a ciphertext.
pub const TAG_LEN: usize = 16;
/// Octets of a run signature.
pub const SIGNATURE_LEN: usize = 64;

/// The keyword component a push name carries after its group: `32=signal`.
pub const SIGNAL_KEYWORD: &[u8] = b"signal";
/// The keyword of a namespace's sync group, `<ns>/32=sync`.
pub const SYNC_KEYWORD: &[u8] = b"sync";
/// InterestLifetime of a push Interest.
pub const PUSH_LIFETIME_MS: u64 = 1000;
/// HopLimit of a push Interest.
pub const PUSH_HOP_LIMIT: u8 = 8;

/// A run's id: the first 16 octets of SHA-256 of its public key, so no one can
/// claim another run's id.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub struct RunId(pub [u8; 16]);

impl RunId {
    /// The id of the run whose Ed25519 public key is `key`.
    pub fn of_key(key: &[u8; 32]) -> RunId {
        let digest = Sha256::digest(key);
        let mut id = [0u8; 16];
        id.copy_from_slice(&digest[..16]);
        RunId(id)
    }
}

impl fmt::Display for RunId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

/// Why octets are no signal packet. Each says which element and how.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum WireError {
    /// An element doesn't parse as TLV (truncated, a length past its end, a
    /// non-minimal number).
    #[error("{inside} does not parse as TLV ({why})")]
    Tlv {
        /// The element being read.
        inside: &'static str,
        /// The TLV reader's reason.
        why: String,
    },
    /// An unknown odd (critical) element: a later revision a reader must
    /// understand. Update the program.
    #[error(
        "{inside} carries the unknown critical element {typ:#x}; a program that knows it reads it"
    )]
    Critical {
        /// The container.
        inside: &'static str,
        /// The element's TLV-TYPE.
        typ: u64,
    },
    /// A required element is missing.
    #[error("{inside} lacks its {what}")]
    Missing {
        /// The container.
        inside: &'static str,
        /// The element missing.
        what: &'static str,
    },
    /// A known element in the wrong place (out of order, repeated, or after the
    /// run signature).
    #[error("{inside} carries {what} out of place")]
    Order {
        /// The container.
        inside: &'static str,
        /// The element out of place.
        what: &'static str,
    },
    /// A fixed-size element of another size.
    #[error("{what} is {len} octets, not {want}")]
    Length {
        /// The element.
        what: &'static str,
        /// Its octets.
        len: usize,
        /// The octets it takes.
        want: usize,
    },
    /// Over a limit of the wire (§5).
    #[error("{what} is {size}, over its limit of {max}")]
    Limit {
        /// What is over.
        what: &'static str,
        /// Its size.
        size: usize,
        /// The limit.
        max: usize,
    },
    /// Neither a `SignalBody` nor a `SignalSealed`, or octets after it.
    #[error("not a signal packet: {why}")]
    NotPacket {
        /// What was found instead.
        why: String,
    },
}

/// A decoded packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Packet {
    /// An unsealed `SignalBody`.
    Body(Body),
    /// A `SignalSealed`: its plaintext is a `SignalBody` TLV.
    Sealed(Sealed),
}

/// A `SignalSealed`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sealed {
    /// The signal key's id.
    pub key_id: [u8; KEY_ID_LEN],
    /// The random nonce.
    pub nonce: [u8; NONCE_LEN],
    /// The ciphertext, tag appended.
    pub ciphertext: Bytes,
}

/// A `SignalBody`. Its slices share the packet's allocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Body {
    /// The scope (folder or collection).
    pub scope: Name,
    /// The run.
    pub run: RunId,
    /// The run header's Data wire, when it rides.
    pub header: Option<Bytes>,
    /// The signals, in order (none in a header-only packet).
    pub signals: Vec<WireSignal>,
    /// The run signature.
    pub signature: [u8; SIGNATURE_LEN],
    /// The value octets the run signature covers (after [`CONTEXT`]).
    pub signed: Bytes,
}

/// One `Signal`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WireSignal {
    /// Its sequence.
    pub seq: u64,
    /// The app's address.
    pub address: Bytes,
    /// ms since the Unix epoch, by the sender's clock.
    pub expires: u64,
    /// The app's payload.
    pub payload: Bytes,
}

/// A `RunHeaderBody`: the Content of a run header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunHeaderBody {
    /// The run's Ed25519 public key.
    pub key: [u8; 32],
    /// The run's first sequence (the sender's clock in µs when it opened).
    pub start: u64,
    /// ms since the Unix epoch after which the run's packets are expired.
    pub not_after: u64,
    /// The secret of the run's local ring, when it opened one.
    pub ring: Option<[u8; 32]>,
}

fn tlv(inside: &'static str) -> impl Fn(ndn_tlv::TlvError) -> WireError {
    move |e| WireError::Tlv {
        inside,
        why: format!("{e:?}"),
    }
}

/// The elements of one container: each known one, unknown even ones skipped,
/// unknown odd ones refused.
struct Elements {
    reader: TlvReader,
    inside: &'static str,
}

impl Elements {
    fn new(value: Bytes, inside: &'static str) -> Self {
        Elements {
            reader: TlvReader::new(value),
            inside,
        }
    }

    /// The next known element: its offset in the value, type and value.
    fn next(&mut self, known: &[u64]) -> Result<Option<(usize, u64, Bytes)>, WireError> {
        loop {
            if self.reader.is_empty() {
                return Ok(None);
            }
            let at = self.reader.position();
            let (typ, value) = self.reader.read_tlv().map_err(tlv(self.inside))?;
            if known.contains(&typ) {
                return Ok(Some((at, typ, value)));
            }
            if typ & 1 == 1 {
                return Err(WireError::Critical {
                    inside: self.inside,
                    typ,
                });
            }
        }
    }
}

fn fixed<const N: usize>(what: &'static str, v: &[u8]) -> Result<[u8; N], WireError> {
    v.try_into().map_err(|_| WireError::Length {
        what,
        len: v.len(),
        want: N,
    })
}

fn nni(what: &'static str, v: &[u8]) -> Result<u64, WireError> {
    match v.len() {
        1 | 2 | 4 | 8 => Ok(v.iter().fold(0u64, |acc, b| (acc << 8) | u64::from(*b))),
        len => Err(WireError::Length { what, len, want: 8 }),
    }
}

/// Decode a packet: the ApplicationParameters of a push Interest, or a ring frame.
pub fn decode_packet(packet: Bytes) -> Result<Packet, WireError> {
    if packet.len() > PACKET_MAX {
        return Err(WireError::Limit {
            what: "packet",
            size: packet.len(),
            max: PACKET_MAX,
        });
    }
    let mut r = TlvReader::new(packet);
    let (typ, value) = r.read_tlv().map_err(tlv("packet"))?;
    if !r.is_empty() {
        return Err(WireError::NotPacket {
            why: format!("{} octets follow its element", r.remaining()),
        });
    }
    match typ {
        SIGNAL_BODY => decode_body_value(value).map(Packet::Body),
        SIGNAL_SEALED => decode_sealed_value(value).map(Packet::Sealed),
        other => Err(WireError::NotPacket {
            why: format!("its element is {other:#x}"),
        }),
    }
}

/// Decode a `SignalBody` TLV: the plaintext of a sealed packet.
pub fn decode_body(body: Bytes) -> Result<Body, WireError> {
    let mut r = TlvReader::new(body);
    let (typ, value) = r.read_tlv().map_err(tlv("SignalBody"))?;
    if typ != SIGNAL_BODY || !r.is_empty() {
        return Err(WireError::NotPacket {
            why: "a sealed packet's plaintext is not one SignalBody".into(),
        });
    }
    decode_body_value(value)
}

fn decode_sealed_value(value: Bytes) -> Result<Sealed, WireError> {
    const IN: &str = "SignalSealed";
    let mut els = Elements::new(value, IN);
    let mut key_id = None;
    let mut nonce = None;
    let mut ciphertext = None;
    while let Some((_, typ, v)) = els.next(&[KEY_ID, SEAL_NONCE, CIPHERTEXT])? {
        match typ {
            KEY_ID if key_id.is_none() && nonce.is_none() && ciphertext.is_none() => {
                key_id = Some(fixed::<KEY_ID_LEN>("KeyId", &v)?);
            }
            SEAL_NONCE if key_id.is_some() && nonce.is_none() && ciphertext.is_none() => {
                nonce = Some(fixed::<NONCE_LEN>("SealNonce", &v)?);
            }
            CIPHERTEXT if nonce.is_some() && ciphertext.is_none() => {
                if v.len() < TAG_LEN {
                    return Err(WireError::Length {
                        what: "Ciphertext",
                        len: v.len(),
                        want: TAG_LEN,
                    });
                }
                ciphertext = Some(v);
            }
            KEY_ID => {
                return Err(WireError::Order {
                    inside: IN,
                    what: "KeyId",
                });
            }
            SEAL_NONCE => {
                return Err(WireError::Order {
                    inside: IN,
                    what: "SealNonce",
                });
            }
            _ => {
                return Err(WireError::Order {
                    inside: IN,
                    what: "Ciphertext",
                });
            }
        }
    }
    Ok(Sealed {
        key_id: key_id.ok_or(WireError::Missing {
            inside: IN,
            what: "KeyId",
        })?,
        nonce: nonce.ok_or(WireError::Missing {
            inside: IN,
            what: "SealNonce",
        })?,
        ciphertext: ciphertext.ok_or(WireError::Missing {
            inside: IN,
            what: "Ciphertext",
        })?,
    })
}

fn decode_body_value(value: Bytes) -> Result<Body, WireError> {
    const IN: &str = "SignalBody";
    #[derive(PartialEq, PartialOrd)]
    enum At {
        Scope,
        Run,
        Header,
        Signals,
        Signed,
    }
    let all = value.clone();
    let mut els = Elements::new(value, IN);
    let mut at = At::Scope;
    let mut scope = None;
    let mut run = None;
    let mut header = None;
    let mut signals = Vec::new();
    let mut signature = None;
    let mut signed = Bytes::new();
    let known = [tlv_type::NAME, RUN_ID, RUN_HEADER, SIGNAL, RUN_SIGNATURE];
    while let Some((offset, typ, v)) = els.next(&known)? {
        match typ {
            tlv_type::NAME if at == At::Scope => {
                scope = Some(Name::decode(v).map_err(|e| WireError::Tlv {
                    inside: "the scope Name",
                    why: format!("{e:?}"),
                })?);
                at = At::Run;
            }
            RUN_ID if at == At::Run => {
                run = Some(RunId(fixed::<16>("RunId", &v)?));
                at = At::Header;
            }
            RUN_HEADER if at == At::Header => {
                header = Some(v);
                at = At::Signals;
            }
            SIGNAL if at == At::Header || at == At::Signals => {
                if signals.len() == SIGNALS_MAX {
                    return Err(WireError::Limit {
                        what: "signals in a packet",
                        size: SIGNALS_MAX + 1,
                        max: SIGNALS_MAX,
                    });
                }
                signals.push(decode_signal(v)?);
                at = At::Signals;
            }
            RUN_SIGNATURE if at == At::Header || at == At::Signals => {
                signature = Some(fixed::<SIGNATURE_LEN>("RunSignature", &v)?);
                signed = all.slice(..offset);
                at = At::Signed;
            }
            _ => {
                return Err(WireError::Order {
                    inside: IN,
                    what: match typ {
                        tlv_type::NAME => "the scope Name",
                        RUN_ID => "RunId",
                        RUN_HEADER => "RunHeader",
                        SIGNAL => "a Signal",
                        _ => "RunSignature",
                    },
                });
            }
        }
    }
    let scope = scope.ok_or(WireError::Missing {
        inside: IN,
        what: "scope Name",
    })?;
    let run = run.ok_or(WireError::Missing {
        inside: IN,
        what: "RunId",
    })?;
    let signature = signature.ok_or(WireError::Missing {
        inside: IN,
        what: "RunSignature",
    })?;
    if signals.is_empty() && header.is_none() {
        return Err(WireError::Missing {
            inside: IN,
            what: "Signal (a packet without its run header carries at least one)",
        });
    }
    // Nothing may follow the run signature: it would ride unsigned.
    if signed.len() + tlv_size(RUN_SIGNATURE, SIGNATURE_LEN) != all.len() {
        return Err(WireError::Order {
            inside: IN,
            what: "an element after RunSignature",
        });
    }
    Ok(Body {
        scope,
        run,
        header,
        signals,
        signature,
        signed,
    })
}

fn decode_signal(value: Bytes) -> Result<WireSignal, WireError> {
    const IN: &str = "Signal";
    let mut els = Elements::new(value, IN);
    let order = [SIGNAL_SEQ, ADDRESS, EXPIRES, PAYLOAD];
    let mut got: [Option<Bytes>; 4] = [None, None, None, None];
    let mut next = 0usize;
    while let Some((_, typ, v)) = els.next(&order)? {
        let i = order.iter().position(|t| *t == typ).unwrap_or(usize::MAX);
        if i != next {
            return Err(WireError::Order {
                inside: IN,
                what: ["SignalSeq", "Address", "Expires", "Payload"][i.min(3)],
            });
        }
        got[i] = Some(v);
        next += 1;
    }
    let [seq, address, expires, payload] = got;
    let seq = nni(
        "SignalSeq",
        &seq.ok_or(WireError::Missing {
            inside: IN,
            what: "SignalSeq",
        })?,
    )?;
    let address = address.ok_or(WireError::Missing {
        inside: IN,
        what: "Address",
    })?;
    let expires = nni(
        "Expires",
        &expires.ok_or(WireError::Missing {
            inside: IN,
            what: "Expires",
        })?,
    )?;
    let payload = payload.ok_or(WireError::Missing {
        inside: IN,
        what: "Payload",
    })?;
    if address.len() > ADDRESS_MAX {
        return Err(WireError::Limit {
            what: "an address",
            size: address.len(),
            max: ADDRESS_MAX,
        });
    }
    if payload.len() > PAYLOAD_MAX {
        return Err(WireError::Limit {
            what: "a payload",
            size: payload.len(),
            max: PAYLOAD_MAX,
        });
    }
    Ok(WireSignal {
        seq,
        address,
        expires,
        payload,
    })
}

/// Decode a run header's Content.
pub fn decode_run_header_body(content: &[u8]) -> Result<RunHeaderBody, WireError> {
    const IN: &str = "RunHeaderBody";
    let mut r = TlvReader::new(Bytes::copy_from_slice(content));
    let (typ, value) = r.read_tlv().map_err(tlv(IN))?;
    if typ != RUN_HEADER_BODY || !r.is_empty() {
        return Err(WireError::NotPacket {
            why: "a run header's content is not one RunHeaderBody".into(),
        });
    }
    let order = [RUN_KEY, RUN_START, RUN_NOT_AFTER, LOCAL_RING];
    let mut els = Elements::new(value, IN);
    let mut got: [Option<Bytes>; 4] = [None, None, None, None];
    let mut next = 0usize;
    while let Some((_, typ, v)) = els.next(&order)? {
        let i = order.iter().position(|t| *t == typ).unwrap_or(usize::MAX);
        if i != next {
            return Err(WireError::Order {
                inside: IN,
                what: ["RunKey", "RunStart", "RunNotAfter", "LocalRing"][i.min(3)],
            });
        }
        got[i] = Some(v);
        next = i + 1;
    }
    let [key, start, not_after, ring] = got;
    Ok(RunHeaderBody {
        key: fixed::<32>(
            "RunKey",
            &key.ok_or(WireError::Missing {
                inside: IN,
                what: "RunKey",
            })?,
        )?,
        start: nni(
            "RunStart",
            &start.ok_or(WireError::Missing {
                inside: IN,
                what: "RunStart",
            })?,
        )?,
        not_after: nni(
            "RunNotAfter",
            &not_after.ok_or(WireError::Missing {
                inside: IN,
                what: "RunNotAfter",
            })?,
        )?,
        ring: ring.map(|r| fixed::<32>("LocalRing", &r)).transpose()?,
    })
}

// ---- encoding ---------------------------------------------------------------------------------

fn put_varu64(out: &mut Vec<u8>, v: u64) {
    let mut tmp = [0u8; 9];
    let n = ndn_tlv::write_varu64(&mut tmp, v);
    out.extend_from_slice(&tmp[..n]);
}

fn put_header(out: &mut Vec<u8>, typ: u64, len: usize) {
    put_varu64(out, typ);
    put_varu64(out, len as u64);
}

fn put_tlv(out: &mut Vec<u8>, typ: u64, value: &[u8]) {
    put_header(out, typ, value.len());
    out.extend_from_slice(value);
}

fn nni_bytes(v: u64) -> ([u8; 8], usize) {
    let b = v.to_be_bytes();
    let n = if v <= 0xFF {
        1
    } else if v <= 0xFFFF {
        2
    } else if v <= 0xFFFF_FFFF {
        4
    } else {
        8
    };
    (b, n)
}

fn nni_size(typ: u64, v: u64) -> usize {
    tlv_size(typ, nni_bytes(v).1)
}

fn put_nni(out: &mut Vec<u8>, typ: u64, v: u64) {
    let (b, n) = nni_bytes(v);
    put_tlv(out, typ, &b[8 - n..]);
}

/// The encoded size of a `Name` TLV.
pub(crate) fn name_size(name: &Name) -> usize {
    tlv_size(tlv_type::NAME, name_value_size(name))
}

fn name_value_size(name: &Name) -> usize {
    name.components()
        .iter()
        .map(|c| tlv_size(c.typ, c.value.len()))
        .sum()
}

fn put_name(out: &mut Vec<u8>, name: &Name) {
    put_header(out, tlv_type::NAME, name_value_size(name));
    for c in name.components() {
        put_tlv(out, c.typ, &c.value);
    }
}

/// One signal to encode: (seq, address, expires, payload).
pub(crate) type Outgoing<'a> = (u64, &'a [u8], u64, &'a [u8]);

fn signal_value_size(s: &Outgoing<'_>) -> usize {
    nni_size(SIGNAL_SEQ, s.0)
        + tlv_size(ADDRESS, s.1.len())
        + nni_size(EXPIRES, s.2)
        + tlv_size(PAYLOAD, s.3.len())
}

/// The encoded size of a `SignalBody` TLV carrying `header` and `signals`.
pub(crate) fn body_size(
    scope_tlv: usize,
    header: Option<usize>,
    signals: &[Outgoing<'_>],
) -> usize {
    tlv_size(SIGNAL_BODY, body_value_size(scope_tlv, header, signals))
}

fn body_value_size(scope_tlv: usize, header: Option<usize>, signals: &[Outgoing<'_>]) -> usize {
    scope_tlv
        + tlv_size(RUN_ID, 16)
        + header.map_or(0, |h| tlv_size(RUN_HEADER, h))
        + signals
            .iter()
            .map(|s| tlv_size(SIGNAL, signal_value_size(s)))
            .sum::<usize>()
        + tlv_size(RUN_SIGNATURE, SIGNATURE_LEN)
}

/// The encoded size of a `SignalSealed` TLV sealing a body of `body` octets.
pub(crate) fn sealed_size(body: usize) -> usize {
    tlv_size(SIGNAL_SEALED, sealed_value_size(body))
}

fn sealed_value_size(body: usize) -> usize {
    tlv_size(KEY_ID, KEY_ID_LEN)
        + tlv_size(SEAL_NONCE, NONCE_LEN)
        + tlv_size(CIPHERTEXT, body + TAG_LEN)
}

/// Encode a `SignalBody` into `out` (cleared first), signed by `sign` over
/// [`CONTEXT`] ‖ the value octets before `RunSignature`.
pub(crate) fn encode_body(
    out: &mut Vec<u8>,
    scope: &Name,
    run: &RunId,
    header: Option<&[u8]>,
    signals: &[Outgoing<'_>],
    sign: impl FnOnce(&[u8]) -> [u8; SIGNATURE_LEN],
) {
    out.clear();
    let value = body_value_size(name_size(scope), header.map(<[u8]>::len), signals);
    out.reserve(tlv_size(SIGNAL_BODY, value));
    put_header(out, SIGNAL_BODY, value);
    let start = out.len();
    put_name(out, scope);
    put_tlv(out, RUN_ID, &run.0);
    if let Some(h) = header {
        put_tlv(out, RUN_HEADER, h);
    }
    for s in signals {
        put_header(out, SIGNAL, signal_value_size(s));
        put_nni(out, SIGNAL_SEQ, s.0);
        put_tlv(out, ADDRESS, s.1);
        put_nni(out, EXPIRES, s.2);
        put_tlv(out, PAYLOAD, s.3);
    }
    let signature = sign(&out[start..]);
    put_tlv(out, RUN_SIGNATURE, &signature);
}

/// Encode a `SignalSealed` around `body`, leaving the plaintext where the
/// ciphertext goes: `seal` encrypts that region in place and returns the tag.
pub(crate) fn encode_sealed(
    key_id: &[u8; KEY_ID_LEN],
    nonce: &[u8; NONCE_LEN],
    body: &[u8],
    seal: impl FnOnce(&mut [u8]) -> [u8; TAG_LEN],
) -> Vec<u8> {
    let value = sealed_value_size(body.len());
    let mut out = Vec::with_capacity(tlv_size(SIGNAL_SEALED, value));
    put_header(&mut out, SIGNAL_SEALED, value);
    put_tlv(&mut out, KEY_ID, key_id);
    put_tlv(&mut out, SEAL_NONCE, nonce);
    put_header(&mut out, CIPHERTEXT, body.len() + TAG_LEN);
    let at = out.len();
    out.extend_from_slice(body);
    let tag = seal(&mut out[at..]);
    out.extend_from_slice(&tag);
    out
}

/// Encode a run header's Content.
pub(crate) fn encode_run_header_body(body: &RunHeaderBody) -> Vec<u8> {
    let value = tlv_size(RUN_KEY, 32)
        + nni_size(RUN_START, body.start)
        + nni_size(RUN_NOT_AFTER, body.not_after)
        + body.ring.map_or(0, |_| tlv_size(LOCAL_RING, 32));
    let mut out = Vec::with_capacity(tlv_size(RUN_HEADER_BODY, value));
    put_header(&mut out, RUN_HEADER_BODY, value);
    put_tlv(&mut out, RUN_KEY, &body.key);
    put_nni(&mut out, RUN_START, body.start);
    put_nni(&mut out, RUN_NOT_AFTER, body.not_after);
    if let Some(ring) = &body.ring {
        put_tlv(&mut out, LOCAL_RING, ring);
    }
    out
}

// ---- the push Interest ------------------------------------------------------------------------

/// `<ns>/32=sync`: a namespace's sync group.
pub fn sync_group(namespace: &Name) -> Name {
    namespace
        .clone()
        .append_component(NameComponent::keyword(Bytes::from_static(SYNC_KEYWORD)))
}

fn signal_keyword() -> NameComponent {
    NameComponent::keyword(Bytes::from_static(SIGNAL_KEYWORD))
}

fn params_digest(packet: &[u8]) -> [u8; 32] {
    let mut header = Vec::with_capacity(8);
    put_header(&mut header, tlv_type::APP_PARAMETERS, packet.len());
    let mut h = Sha256::new();
    h.update(&header);
    h.update(packet);
    h.finalize().into()
}

/// The push name of `packet` in `group`: `<group>/32=signal/<ParametersSha256Digest>`.
pub fn push_name(group: &Name, packet: &[u8]) -> Name {
    group
        .clone()
        .append_component(signal_keyword())
        .append_component(NameComponent::new(
            tlv_type::PARAMETERS_SHA256,
            Bytes::copy_from_slice(&params_digest(packet)),
        ))
}

/// The push Interest of `packet` into `group`: its name [`push_name`], Nonce,
/// InterestLifetime 1 s, HopLimit 8, `packet` as its ApplicationParameters;
/// unsigned, no CanBePrefix, no MustBeFresh.
pub fn push_interest(group: &Name, packet: &[u8]) -> Bytes {
    let digest = params_digest(packet);
    let keyword = signal_keyword();
    let name_value = name_value_size(group)
        + tlv_size(keyword.typ, keyword.value.len())
        + tlv_size(tlv_type::PARAMETERS_SHA256, 32);
    let (lifetime, lifetime_len) = nni_bytes(PUSH_LIFETIME_MS);
    let value = tlv_size(tlv_type::NAME, name_value)
        + tlv_size(tlv_type::NONCE, 4)
        + tlv_size(tlv_type::INTEREST_LIFETIME, lifetime_len)
        + tlv_size(tlv_type::HOP_LIMIT, 1)
        + tlv_size(tlv_type::APP_PARAMETERS, packet.len());
    let mut out = Vec::with_capacity(tlv_size(tlv_type::INTEREST, value));
    put_header(&mut out, tlv_type::INTEREST, value);
    put_header(&mut out, tlv_type::NAME, name_value);
    for c in group.components() {
        put_tlv(&mut out, c.typ, &c.value);
    }
    put_tlv(&mut out, keyword.typ, &keyword.value);
    put_tlv(&mut out, tlv_type::PARAMETERS_SHA256, &digest);
    // Each packet's name is unique (its digest), so a nonce drawn from it is
    // unique per Interest and the same for every copy of it.
    put_tlv(&mut out, tlv_type::NONCE, &digest[..4]);
    put_tlv(
        &mut out,
        tlv_type::INTEREST_LIFETIME,
        &lifetime[8 - lifetime_len..],
    );
    put_tlv(&mut out, tlv_type::HOP_LIMIT, &[PUSH_HOP_LIMIT]);
    put_tlv(&mut out, tlv_type::APP_PARAMETERS, packet);
    Bytes::from(out)
}

/// The packet a push Interest carries: `Some` when `interest` is named
/// `<group>/32=signal/<digest>`, carries ApplicationParameters, and `digest` is
/// SHA-256 of its parameters portion. Anything else (an SVS sync Interest, a
/// fetch) is no push.
pub fn push_packet(interest: &Interest) -> Option<Bytes> {
    let comps = interest.name.components();
    let [.., sync, signal, digest] = comps else {
        return None;
    };
    if digest.typ != tlv_type::PARAMETERS_SHA256
        || signal.typ != tlv_type::KEYWORD
        || signal.value.as_ref() != SIGNAL_KEYWORD
        || sync.typ != tlv_type::KEYWORD
        || sync.value.as_ref() != SYNC_KEYWORD
    {
        return None;
    }
    let params = interest.app_parameters()?.clone();
    let portion = interest.parameters_portion()?;
    if Sha256::digest(&portion).as_slice() != digest.value.as_ref() {
        return None;
    }
    Some(params)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(s: &str) -> Name {
        s.parse().unwrap()
    }

    fn body(header: Option<&[u8]>, signals: &[Outgoing<'_>]) -> Vec<u8> {
        let mut out = Vec::new();
        encode_body(
            &mut out,
            &n("/alice/32=data/board"),
            &RunId([7; 16]),
            header,
            signals,
            |_| [9; SIGNATURE_LEN],
        );
        out
    }

    #[test]
    fn a_body_round_trips_and_its_size_is_known_before_encoding() {
        let signals: [Outgoing<'_>; 2] = [
            (
                1_700_000_000_000_000,
                b"cursor",
                1_700_000_002_000,
                b"x=1,y=2",
            ),
            (1_700_000_000_000_001, b"", 0, &[0u8; PAYLOAD_MAX]),
        ];
        let wire = body(Some(b"header"), &signals);
        assert_eq!(
            wire.len(),
            body_size(name_size(&n("/alice/32=data/board")), Some(6), &signals)
        );
        let Packet::Body(b) = decode_packet(Bytes::from(wire.clone())).unwrap() else {
            panic!("an unsealed packet decodes as a body");
        };
        assert_eq!(b.scope, n("/alice/32=data/board"));
        assert_eq!(b.run, RunId([7; 16]));
        assert_eq!(b.header.as_deref(), Some(&b"header"[..]));
        assert_eq!(b.signals.len(), 2);
        assert_eq!(b.signals[0].seq, 1_700_000_000_000_000);
        assert_eq!(b.signals[0].address.as_ref(), b"cursor");
        assert_eq!(b.signals[0].payload.as_ref(), b"x=1,y=2");
        assert_eq!(b.signals[0].expires, 1_700_000_002_000);
        assert_eq!(b.signals[1].payload.len(), PAYLOAD_MAX);
        assert_eq!(b.signature, [9; SIGNATURE_LEN]);
        // What the signature covers: the value up to RunSignature.
        let value_start = wire.len() - b.signed.len() - tlv_size(RUN_SIGNATURE, SIGNATURE_LEN);
        assert_eq!(
            &wire[value_start..value_start + b.signed.len()],
            b.signed.as_ref()
        );
        assert_eq!(decode_body(Bytes::from(wire)).unwrap(), b);
    }

    #[test]
    fn a_sealed_packet_round_trips() {
        let wire = encode_sealed(&[1; 8], &[2; 24], b"plaintext", |region| {
            region.reverse();
            [3; TAG_LEN]
        });
        assert_eq!(wire.len(), sealed_size(9));
        let Packet::Sealed(s) = decode_packet(Bytes::from(wire)).unwrap() else {
            panic!("a sealed packet decodes as sealed");
        };
        assert_eq!(s.key_id, [1; 8]);
        assert_eq!(s.nonce, [2; 24]);
        assert_eq!(&s.ciphertext[..9], b"txetnialp");
        assert_eq!(&s.ciphertext[9..], &[3; TAG_LEN]);
    }

    #[test]
    fn a_run_header_body_round_trips_with_and_without_its_ring() {
        for ring in [None, Some([5u8; 32])] {
            let h = RunHeaderBody {
                key: [4; 32],
                start: 1_700_000_000_123_456,
                not_after: 1_700_003_600_000,
                ring,
            };
            assert_eq!(
                decode_run_header_body(&encode_run_header_body(&h)).unwrap(),
                h
            );
        }
    }

    /// `body` with an element of type `typ` spliced in after the RunId.
    fn with_element(typ: u64) -> Bytes {
        let signals: [Outgoing<'_>; 1] = [(1, b"a", 2, b"p")];
        let wire = body(None, &signals);
        let mut r = TlvReader::new(Bytes::from(wire));
        let (_, value) = r.read_tlv().unwrap();
        let after_run = name_size(&n("/alice/32=data/board")) + tlv_size(RUN_ID, 16);
        let mut v = value[..after_run].to_vec();
        put_tlv(&mut v, typ, b"later");
        v.extend_from_slice(&value[after_run..]);
        let mut out = Vec::new();
        put_tlv(&mut out, SIGNAL_BODY, &v);
        Bytes::from(out)
    }

    #[test]
    fn an_unknown_even_element_is_skipped_and_an_unknown_odd_one_refused() {
        let Packet::Body(b) = decode_packet(with_element(0x05AE)).unwrap() else {
            panic!("a body");
        };
        assert_eq!(
            b.signals.len(),
            1,
            "the unknown even element is passed over"
        );
        assert_eq!(
            decode_packet(with_element(0x05AF)),
            Err(WireError::Critical {
                inside: "SignalBody",
                typ: 0x05AF
            }),
            "an unknown odd element is refused"
        );
    }

    #[test]
    fn nothing_may_follow_the_run_signature() {
        let signals: [Outgoing<'_>; 1] = [(1, b"a", 2, b"p")];
        let wire = body(None, &signals);
        let mut r = TlvReader::new(Bytes::from(wire));
        let (_, value) = r.read_tlv().unwrap();
        let mut v = value.to_vec();
        put_tlv(&mut v, 0x05AE, b"unsigned");
        let mut out = Vec::new();
        put_tlv(&mut out, SIGNAL_BODY, &v);
        assert!(matches!(
            decode_packet(Bytes::from(out)),
            Err(WireError::Order { .. })
        ));
    }

    #[test]
    fn over_its_limits_a_packet_is_refused() {
        let long = [0u8; ADDRESS_MAX + 1];
        let signals: [Outgoing<'_>; 1] = [(1, &long, 2, b"p")];
        assert!(matches!(
            decode_packet(Bytes::from(body(None, &signals))),
            Err(WireError::Limit {
                what: "an address",
                ..
            })
        ));
        let many: Vec<Outgoing<'_>> = (0..=SIGNALS_MAX as u64)
            .map(|i| (i, &b""[..], 0, &b""[..]))
            .collect();
        assert!(matches!(
            decode_packet(Bytes::from(body(None, &many))),
            Err(WireError::Limit {
                what: "signals in a packet",
                ..
            })
        ));
        assert!(matches!(
            decode_packet(Bytes::from(vec![0u8; PACKET_MAX + 1])),
            Err(WireError::Limit { what: "packet", .. })
        ));
        assert!(
            matches!(
                decode_packet(Bytes::from(body(None, &[]))),
                Err(WireError::Missing { .. })
            ),
            "without its header a packet carries a signal"
        );
        assert!(
            decode_packet(Bytes::from(body(Some(b"h"), &[]))).is_ok(),
            "a header-only packet"
        );
    }

    #[test]
    fn a_push_interest_carries_its_packet_under_its_digest() {
        let group = sync_group(&n("/alice"));
        let packet = body(None, &[(1, b"a", 2, b"p")]);
        let wire = push_interest(&group, &packet);
        let interest = Interest::decode(wire).unwrap();
        assert_eq!(*interest.name, push_name(&group, &packet));
        assert_eq!(interest.lifetime(), Some(std::time::Duration::from_secs(1)));
        assert_eq!(interest.hop_limit(), Some(PUSH_HOP_LIMIT));
        assert!(!interest.selectors().can_be_prefix && !interest.selectors().must_be_fresh);
        assert_eq!(push_packet(&interest).as_deref(), Some(&packet[..]));
        // Parameters altered on the way no longer match the name's digest.
        let mut altered = push_interest(&group, &packet).to_vec();
        *altered.last_mut().unwrap() ^= 1;
        let altered = Interest::decode(Bytes::from(altered)).unwrap();
        assert_eq!(push_packet(&altered), None);
        // A sync Interest of the same group is no push.
        let svs = ndn_packet::encode::InterestBuilder::new(group.clone().append("v=2"))
            .app_parameters(packet.clone())
            .build();
        assert_eq!(push_packet(&Interest::decode(svs).unwrap()), None);
    }
}
