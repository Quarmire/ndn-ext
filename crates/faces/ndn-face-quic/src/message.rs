//! Link messages, on the link's control stream (its first bidirectional
//! stream), and the reasons a link is closed with.
//!
//! After the handshake each side sends a [`LinkHello`] carrying its NDN
//! certificate and the issuer certificates it keeps; each side decides from
//! the other's hello whether to admit the link, and says so with a
//! [`LinkVerdict`] or by closing the connection with a [`CloseReason`]. A
//! link carries NDN packets only once both sides admitted it.
//!
//! Wire: TLV-TYPEs in the application range.
//! `LinkHello = 0x0450 { LinkVersion 0x0451 (1 byte), Data* }` — the first
//! Data is the sender's certificate, the rest its issuers (nearest first);
//! `LinkVerdict = 0x0452 { EnrollmentLink 0x0454 { Name* }? }` — admitted;
//! with `EnrollmentLink`, admitted as an enrollment link that carries only
//! the enrollment of the receiver in the namespaces named.

use bytes::Bytes;
use ndn_packet::Name;
use ndn_tlv::{TlvWriter, read_varu64};

pub(crate) const LINK_HELLO: u64 = 0x0450;
const LINK_VERSION: u64 = 0x0451;
pub(crate) const LINK_VERDICT: u64 = 0x0452;
const ENROLLMENT_LINK: u64 = 0x0454;
const DATA: u64 = 0x06;
const NAME: u64 = 0x07;

/// The link protocol version this crate speaks.
pub const LINK_PROTOCOL_VERSION: u8 = 1;

/// Upper bound on one link message: a certificate chain is a few KiB.
pub(crate) const MAX_MESSAGE: usize = 64 * 1024;

/// The first link message: the sender's certificate and its issuers.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LinkHello {
    /// Certificate Data wires: the sender's own certificate first, then the
    /// issuer certificates it keeps, nearest first. Empty when the sender
    /// has no certificate (a device not enrolled anywhere, linked by its
    /// expected fingerprint alone).
    pub certificates: Vec<Bytes>,
}

impl LinkHello {
    pub(crate) fn encode(&self) -> Bytes {
        let mut w = TlvWriter::new();
        w.write_nested(LINK_HELLO, |w| {
            w.write_tlv(LINK_VERSION, &[LINK_PROTOCOL_VERSION]);
            for cert in &self.certificates {
                w.write_raw(cert);
            }
        });
        w.finish()
    }

    /// Decode the value of a `LinkHello` TLV.
    pub(crate) fn decode(value: &[u8]) -> Result<Self, String> {
        let mut certificates = Vec::new();
        let mut version = None;
        let mut cur = value;
        while !cur.is_empty() {
            let (t, start, end) = split_tlv(cur)?;
            match t {
                LINK_VERSION => match &cur[start..end] {
                    [v] => version = Some(*v),
                    other => {
                        return Err(format!(
                            "a link protocol version of {} bytes in the link hello (it is one byte)",
                            other.len()
                        ));
                    }
                },
                DATA => certificates.push(Bytes::copy_from_slice(&cur[..end])),
                t if skippable(t) => {}
                t => return Err(format!("unknown critical field {t:#x} in the link hello")),
            }
            cur = &cur[end..];
        }
        match version {
            Some(LINK_PROTOCOL_VERSION) => Ok(Self { certificates }),
            Some(v) => Err(format!(
                "the peer speaks link protocol version {v}; this device speaks version \
                 {LINK_PROTOCOL_VERSION}: update the older of the two"
            )),
            None => Err("the link hello carries no protocol version".into()),
        }
    }
}

/// The second link message: the sender admitted the link.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LinkVerdict {
    /// `Some`: the sender admitted the link only as an enrollment link,
    /// which carries the receiver's enrollment in these namespaces (their
    /// CA, trust context and certificates) and nothing else, until the
    /// receiver links again holding a certificate. Never empty: an empty
    /// list is a malformed verdict. `None`: a full link.
    pub enrollment_link: Option<Vec<Name>>,
}

impl LinkVerdict {
    pub(crate) fn encode(&self) -> Bytes {
        let mut w = TlvWriter::new();
        w.write_nested(LINK_VERDICT, |w| {
            if let Some(namespaces) = &self.enrollment_link {
                w.write_nested(ENROLLMENT_LINK, |w| {
                    for ns in namespaces {
                        w.write_raw(&ns.encode_to_tlv());
                    }
                });
            }
        });
        w.finish()
    }

    /// Decode the value of a `LinkVerdict` TLV.
    pub(crate) fn decode(value: &[u8]) -> Result<Self, String> {
        let mut verdict = Self::default();
        let mut cur = value;
        while !cur.is_empty() {
            let (t, start, end) = split_tlv(cur)?;
            match t {
                ENROLLMENT_LINK => {
                    let mut namespaces = Vec::new();
                    let mut names = &cur[start..end];
                    while !names.is_empty() {
                        let (nt, nstart, nend) = split_tlv(names)?;
                        if nt != NAME {
                            return Err(format!("{nt:#x} where a namespace name belongs in the link verdict"));
                        }
                        namespaces.push(
                            Name::decode(Bytes::copy_from_slice(&names[nstart..nend]))
                                .map_err(|e| format!("a namespace in the link verdict: {e}"))?,
                        );
                        names = &names[nend..];
                    }
                    if namespaces.is_empty() {
                        return Err("an enrollment link for no namespace in the link verdict".into());
                    }
                    verdict.enrollment_link = Some(namespaces);
                }
                t if skippable(t) => {}
                t => return Err(format!("unknown critical field {t:#x} in the link verdict")),
            }
            cur = &cur[end..];
        }
        Ok(verdict)
    }
}

/// Whether an unrecognized TLV-TYPE in a link message may be skipped: an
/// even type above 31. Types 0–31 are always critical, as in NDN packets.
fn skippable(t: u64) -> bool {
    t > 31 && t & 1 == 0
}

/// One TLV at the head of `buf`: its type, and where its value starts and the
/// TLV ends.
pub(crate) fn split_tlv(buf: &[u8]) -> Result<(u64, usize, usize), String> {
    let (t, tn) = read_varu64(buf).map_err(|_| "truncated TLV type".to_string())?;
    let (l, ln) = read_varu64(&buf[tn..]).map_err(|_| "truncated TLV length".to_string())?;
    let start = tn + ln;
    let end = start
        .checked_add(usize::try_from(l).map_err(|_| "TLV too long".to_string())?)
        .filter(|&end| end <= buf.len())
        .ok_or_else(|| "truncated TLV value".to_string())?;
    Ok((t, start, end))
}

/// Why a link was closed, as a QUIC application close code; the close also
/// carries a sentence for the person reading the other side's log.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CloseReason {
    /// The device is shutting down (its daemon stops).
    Shutdown,
    /// A newer link to the same device took this one's place.
    Replaced,
    /// An enrollment link carried nothing for longer than its idle
    /// lifetime.
    Idle,
    /// The device enrolled: it links again holding its certificate, as an
    /// enrolled device, in place of its enrollment link.
    Enrolled,
    /// The key has no valid certificate in a namespace this device holds,
    /// and no `[[peer]]` entry expects its fingerprint.
    Unrecognized,
    /// The certificate sent is for another key than the one the handshake
    /// proved.
    CertificateForAnotherKey,
    /// The key (or a certificate on its chain) is revoked by a held version
    /// of the namespace's trust context.
    Revoked,
    /// The namespace's link policy does not let the peer's role link here.
    RoleNotAllowed,
    /// The peer is a valid device, but not the device a `[[peer]]` entry
    /// expects at that endpoint.
    NotTheExpectedDevice,
    /// The link messages were malformed or the peer misbehaved.
    Protocol,
    /// Too many link attempts at once from that address, or in total; or
    /// too many enrollment links.
    Busy,
    /// This device has no usable link key.
    NoLinkKey,
}

impl CloseReason {
    pub fn code(self) -> u32 {
        match self {
            Self::Shutdown => 0x00,
            Self::Replaced => 0x01,
            Self::Idle => 0x02,
            Self::Enrolled => 0x03,
            Self::Unrecognized => 0x10,
            Self::CertificateForAnotherKey => 0x11,
            Self::Revoked => 0x12,
            Self::RoleNotAllowed => 0x13,
            Self::NotTheExpectedDevice => 0x14,
            Self::Protocol => 0x15,
            Self::Busy => 0x16,
            Self::NoLinkKey => 0x17,
        }
    }

    pub fn from_code(code: u64) -> Option<Self> {
        Some(match code {
            0x00 => Self::Shutdown,
            0x01 => Self::Replaced,
            0x02 => Self::Idle,
            0x03 => Self::Enrolled,
            0x10 => Self::Unrecognized,
            0x11 => Self::CertificateForAnotherKey,
            0x12 => Self::Revoked,
            0x13 => Self::RoleNotAllowed,
            0x14 => Self::NotTheExpectedDevice,
            0x15 => Self::Protocol,
            0x16 => Self::Busy,
            0x17 => Self::NoLinkKey,
            _ => return None,
        })
    }

    /// Whether the link should be dialled again later without a change on
    /// either side: a shutdown, a busy listener, an idle enrollment link or
    /// an enrollment completed pass; a refusal of the key does not (until
    /// the trust data or the config changes).
    pub fn is_transient(self) -> bool {
        matches!(
            self,
            Self::Shutdown | Self::Replaced | Self::Idle | Self::Enrolled | Self::Busy
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_hello_round_trips() {
        let hello = LinkHello {
            certificates: vec![Bytes::from_static(&[0x06, 0x01, 0xAA]), Bytes::from_static(&[0x06, 0x00])],
        };
        let wire = hello.encode();
        let (t, start, end) = split_tlv(&wire).unwrap();
        assert_eq!(t, LINK_HELLO);
        assert_eq!(LinkHello::decode(&wire[start..end]).unwrap(), hello);
    }

    #[test]
    fn a_verdict_round_trips_with_and_without_an_enrollment_link() {
        for verdict in [
            LinkVerdict::default(),
            LinkVerdict {
                enrollment_link: Some(vec!["/home".parse().unwrap(), "/work/lab".parse().unwrap()]),
            },
        ] {
            let wire = verdict.encode();
            let (t, start, end) = split_tlv(&wire).unwrap();
            assert_eq!(t, LINK_VERDICT);
            assert_eq!(LinkVerdict::decode(&wire[start..end]).unwrap(), verdict);
        }
    }

    #[test]
    fn malformed_link_messages_are_refused() {
        // LinkVersion of two bytes, even if the first is 1.
        assert!(LinkHello::decode(&[0xFD, 0x04, 0x51, 0x02, 0x01, 0x00]).is_err());
        // Unknown even types 0–31 are critical, as in NDN packets; above 31
        // they are skipped.
        assert!(LinkHello::decode(&[0xFD, 0x04, 0x51, 0x01, 0x01, 0x0A, 0x00]).is_err());
        assert!(LinkHello::decode(&[0xFD, 0x04, 0x51, 0x01, 0x01, 0xFD, 0x04, 0x56, 0x00]).is_ok());
        assert!(LinkVerdict::decode(&[0x08, 0x00]).is_err());
        // An enrollment link for no namespace means nothing.
        assert!(LinkVerdict::decode(&[0xFD, 0x04, 0x54, 0x00]).is_err());
    }

    #[test]
    fn close_codes_round_trip() {
        for r in [
            CloseReason::Shutdown,
            CloseReason::Replaced,
            CloseReason::Idle,
            CloseReason::Enrolled,
            CloseReason::Unrecognized,
            CloseReason::CertificateForAnotherKey,
            CloseReason::Revoked,
            CloseReason::RoleNotAllowed,
            CloseReason::NotTheExpectedDevice,
            CloseReason::Protocol,
            CloseReason::Busy,
            CloseReason::NoLinkKey,
        ] {
            assert_eq!(CloseReason::from_code(u64::from(r.code())), Some(r));
        }
    }
}
