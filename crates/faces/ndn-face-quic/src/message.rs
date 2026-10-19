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
//! `LinkHello = 0x0450 { LinkVersion 0x0451 (1 byte), Data*, Membership
//! 0x045C*, DirectPath 0x045A (8 bytes)? }` — the first Data is the
//! sender's certificate for its link key, the rest its issuers (nearest
//! first); each [`Membership`] is a namespace the sender is a member of
//! with another key, bound to this connection; `DirectPath` marks a
//! connection made for a direct path of the link (the punch's session);
//! `LinkVerdict = 0x0452 { EnrollmentLink 0x0454 { Name* }? }` — admitted;
//! with `EnrollmentLink`, admitted as an enrollment link that carries only
//! the enrollment of the receiver in the namespaces named;
//! `ObservedAddress = 0x0458 (UDP address)` — after the verdict, the source
//! address the sender sees the receiver's packets come from (sent at once,
//! and again whenever it changes);
//! `Reachability = 0x0440 { HoldInterests 0x0442 (empty)?, WakeToken 0x0444
//! (1..=1024 bytes)? }` — after the verdict, device to relay: whether the
//! relay should hold Interests for the device while it is asleep, and the
//! opaque token the relay's wake notifier gets to wake it; the latest
//! replaces the earlier ones;
//! `Presence = 0x0446 { Name, PresentDevice 0x0448 { Name, KeyDigest 0x044A
//! (32 bytes) }* }` — after the verdict, relay to device: the devices of
//! namespace `Name` linked to the relay now (device name and key
//! fingerprint, no address), the full list; the latest for a namespace
//! replaces the earlier ones, and an empty list says none is.
//!
//! Every message after the verdict has an even TLV-TYPE above 31, so a
//! receiver that predates it skips it. A malformed one closes the link with
//! [`CloseReason::Protocol`].

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use bytes::Bytes;
use ndn_packet::Name;
use ndn_tlv::{TlvWriter, read_varu64};

use crate::key::KeyFingerprint;
use crate::membership::{MEMBERSHIP, Membership};

pub(crate) const LINK_HELLO: u64 = 0x0450;
const LINK_VERSION: u64 = 0x0451;
pub(crate) const LINK_VERDICT: u64 = 0x0452;
const ENROLLMENT_LINK: u64 = 0x0454;
pub(crate) const OBSERVED_ADDRESS: u64 = 0x0458;
const DIRECT_PATH: u64 = 0x045A;
pub(crate) const REACHABILITY: u64 = 0x0440;
const HOLD_INTERESTS: u64 = 0x0442;
const WAKE_TOKEN: u64 = 0x0444;
pub(crate) const PRESENCE: u64 = 0x0446;
const PRESENT_DEVICE: u64 = 0x0448;
const KEY_DIGEST: u64 = 0x044A;
pub(crate) const DATA: u64 = 0x06;
const NAME: u64 = 0x07;

/// The session of a direct-path attempt (its punch), which the dialer of a
/// direct path names in its [`LinkHello`].
pub type PathSession = [u8; 8];

/// The link protocol version this crate speaks.
pub const LINK_PROTOCOL_VERSION: u8 = 1;

/// Upper bound on one link message: a certificate chain is a few KiB.
pub(crate) const MAX_MESSAGE: usize = 64 * 1024;

/// The first link message: the sender's certificate and its issuers, and
/// its memberships of other namespaces.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LinkHello {
    /// Certificate Data wires: the sender's own certificate first, then the
    /// issuer certificates it keeps, nearest first. Empty when the sender
    /// has no certificate (a device not enrolled anywhere, linked by its
    /// expected fingerprint alone).
    pub certificates: Vec<Bytes>,
    /// The namespaces the sender is a member of with a key other than its
    /// link key, each bound to this connection. A receiver uses at most
    /// [`MEMBERSHIPS_MAX`](crate::MEMBERSHIPS_MAX) of them.
    pub memberships: Vec<Membership>,
    /// `Some`: this connection is a direct path made by the punch of this
    /// session (the dialer names it; the listener repeats it when it takes
    /// the connection as that direct path).
    pub direct_path: Option<PathSession>,
}

impl LinkHello {
    pub(crate) fn encode(&self) -> Bytes {
        let mut w = TlvWriter::new();
        w.write_nested(LINK_HELLO, |w| {
            w.write_tlv(LINK_VERSION, &[LINK_PROTOCOL_VERSION]);
            for cert in &self.certificates {
                w.write_raw(cert);
            }
            for membership in &self.memberships {
                membership.write(w);
            }
            if let Some(session) = &self.direct_path {
                w.write_tlv(DIRECT_PATH, session);
            }
        });
        w.finish()
    }

    /// Decode the value of a `LinkHello` TLV.
    pub(crate) fn decode(value: &[u8]) -> Result<Self, String> {
        let mut certificates = Vec::new();
        let mut memberships = Vec::new();
        let mut direct_path = None;
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
                MEMBERSHIP => memberships.push(
                    Membership::decode(&cur[start..end])
                        .map_err(|e| format!("{e} in the link hello"))?,
                ),
                DIRECT_PATH => {
                    direct_path = Some(PathSession::try_from(&cur[start..end]).map_err(|_| {
                        format!(
                            "a direct-path session of {} bytes in the link hello (it is 8 bytes)",
                            end - start
                        )
                    })?);
                }
                t if skippable(t) => {}
                t => return Err(format!("unknown critical field {t:#x} in the link hello")),
            }
            cur = &cur[end..];
        }
        match version {
            Some(LINK_PROTOCOL_VERSION) => Ok(Self {
                certificates,
                memberships,
                direct_path,
            }),
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
                            return Err(format!(
                                "{nt:#x} where a namespace name belongs in the link verdict"
                            ));
                        }
                        namespaces.push(
                            Name::decode(Bytes::copy_from_slice(&names[nstart..nend]))
                                .map_err(|e| format!("a namespace in the link verdict: {e}"))?,
                        );
                        names = &names[nend..];
                    }
                    if namespaces.is_empty() {
                        return Err(
                            "an enrollment link for no namespace in the link verdict".into()
                        );
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

/// An `ObservedAddress` message: the address this side sees the receiver's
/// packets come from.
pub(crate) fn encode_observed_address(addr: SocketAddr) -> Bytes {
    let mut w = TlvWriter::new();
    w.write_tlv(OBSERVED_ADDRESS, &encode_udp_address(addr));
    w.finish()
}

/// Most bytes a wake token takes: a platform push token (APNs, FCM, a
/// UnifiedPush endpoint URL) fits with room to spare.
pub const WAKE_TOKEN_MAX: usize = 1024;

/// How the sender is reached while it does not keep its link up: a device
/// tells a relay. The latest a relay received replaces the earlier ones.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Reachability {
    /// Hold Interests for this device while it is asleep (its link closed
    /// with [`CloseReason::Asleep`]), within the relay's bounds, and deliver
    /// them when it links again.
    pub hold: bool,
    /// An opaque token (1 to [`WAKE_TOKEN_MAX`] bytes) the relay hands to
    /// its wake notifier when Interests arrive for this device while it is
    /// asleep — a platform push token, for instance. `None`: do not wake
    /// this device.
    pub wake_token: Option<Bytes>,
}

impl Reachability {
    pub(crate) fn encode(&self) -> Bytes {
        let mut w = TlvWriter::new();
        w.write_nested(REACHABILITY, |w| {
            if self.hold {
                w.write_tlv(HOLD_INTERESTS, &[]);
            }
            if let Some(token) = &self.wake_token {
                w.write_tlv(WAKE_TOKEN, token);
            }
        });
        w.finish()
    }

    /// Decode the value of a `Reachability` TLV.
    pub(crate) fn decode(value: &[u8]) -> Result<Self, String> {
        let mut reachability = Self::default();
        let mut cur = value;
        while !cur.is_empty() {
            let (t, start, end) = split_tlv(cur)?;
            let field = &cur[start..end];
            match t {
                HOLD_INTERESTS if field.is_empty() => reachability.hold = true,
                HOLD_INTERESTS => {
                    return Err(format!(
                        "a HoldInterests of {} bytes in the Reachability message (it is empty)",
                        field.len()
                    ));
                }
                WAKE_TOKEN if (1..=WAKE_TOKEN_MAX).contains(&field.len()) => {
                    reachability.wake_token = Some(Bytes::copy_from_slice(field));
                }
                WAKE_TOKEN => {
                    return Err(format!(
                        "a wake token of {} bytes in the Reachability message (it is 1 to \
                         {WAKE_TOKEN_MAX} bytes)",
                        field.len()
                    ));
                }
                t if skippable(t) => {}
                t => {
                    return Err(format!(
                        "unknown critical field {t:#x} in the Reachability message"
                    ));
                }
            }
            cur = &cur[end..];
        }
        Ok(reachability)
    }
}

/// Which devices of a namespace are linked to the sender (a relay) now.
/// Carries no address: a device that may make a direct path with one of
/// them asks for its candidates the usual way.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Presence {
    pub namespace: Name,
    /// The full list; empty: no device of the namespace is linked there.
    pub devices: Vec<PresentDevice>,
}

/// A device a [`Presence`] lists.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PresentDevice {
    /// The device's name, normally `/<namespace>/<role>/<device>`.
    pub device: Name,
    /// The fingerprint of the key it linked with.
    pub key: KeyFingerprint,
}

impl Presence {
    pub(crate) fn encode(&self) -> Bytes {
        let mut w = TlvWriter::new();
        w.write_nested(PRESENCE, |w| {
            w.write_raw(&self.namespace.encode_to_tlv());
            for d in &self.devices {
                w.write_nested(PRESENT_DEVICE, |w| {
                    w.write_raw(&d.device.encode_to_tlv());
                    w.write_tlv(KEY_DIGEST, &d.key.0);
                });
            }
        });
        w.finish()
    }

    /// Decode the value of a `Presence` TLV.
    pub(crate) fn decode(value: &[u8]) -> Result<Self, String> {
        let mut namespace = None;
        let mut devices = Vec::new();
        let mut cur = value;
        while !cur.is_empty() {
            let (t, start, end) = split_tlv(cur)?;
            match t {
                NAME => {
                    namespace = Some(decode_name(
                        &cur[start..end],
                        "the namespace of the Presence message",
                    )?)
                }
                PRESENT_DEVICE => devices.push(decode_present_device(&cur[start..end])?),
                t if skippable(t) => {}
                t => {
                    return Err(format!(
                        "unknown critical field {t:#x} in the Presence message"
                    ));
                }
            }
            cur = &cur[end..];
        }
        let namespace = namespace.ok_or("a Presence message names no namespace")?;
        Ok(Self { namespace, devices })
    }
}

fn decode_present_device(value: &[u8]) -> Result<PresentDevice, String> {
    let mut device = None;
    let mut key = None;
    let mut cur = value;
    while !cur.is_empty() {
        let (t, start, end) = split_tlv(cur)?;
        let field = &cur[start..end];
        match t {
            NAME => device = Some(decode_name(field, "a device in the Presence message")?),
            KEY_DIGEST => {
                key = Some(KeyFingerprint(<[u8; 32]>::try_from(field).map_err(
                    |_| {
                        format!(
                            "a key digest of {} bytes in the Presence message (it is 32)",
                            field.len()
                        )
                    },
                )?));
            }
            t if skippable(t) => {}
            t => return Err(format!("unknown critical field {t:#x} in a PresentDevice")),
        }
        cur = &cur[end..];
    }
    match (device, key) {
        (Some(device), Some(key)) => Ok(PresentDevice { device, key }),
        _ => Err("a PresentDevice without its device name or key digest".into()),
    }
}

fn decode_name(value: &[u8], what: &str) -> Result<Name, String> {
    Name::decode(Bytes::copy_from_slice(value)).map_err(|e| format!("{what}: {e}"))
}

/// A UDP address as link messages and direct-path candidates carry it: the
/// IPv4 (4 bytes) or IPv6 (16 bytes) address, then the port (2 bytes), in
/// network byte order. An IPv4-mapped IPv6 address is written as IPv4.
pub fn encode_udp_address(addr: SocketAddr) -> Vec<u8> {
    let mut out = match addr.ip().to_canonical() {
        IpAddr::V4(ip) => ip.octets().to_vec(),
        IpAddr::V6(ip) => ip.octets().to_vec(),
    };
    out.extend_from_slice(&addr.port().to_be_bytes());
    out
}

/// Decode a UDP address ([`encode_udp_address`]): 6 or 18 bytes.
pub fn decode_udp_address(value: &[u8]) -> Result<SocketAddr, String> {
    let port = |p: &[u8]| u16::from_be_bytes([p[0], p[1]]);
    match value.len() {
        6 => Ok(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(value[0], value[1], value[2], value[3])),
            port(&value[4..]),
        )),
        18 => {
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&value[..16]);
            Ok(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(ip)),
                port(&value[16..]),
            ))
        }
        n => Err(format!("a UDP address of {n} bytes (it is 6 or 18)")),
    }
}

/// Whether an unrecognized TLV-TYPE in a link message may be skipped: an
/// even type above 31. Types 0–31 are always critical, as in NDN packets.
pub(crate) fn skippable(t: u64) -> bool {
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
    /// The device enrolled, or its memberships changed otherwise: it links
    /// again presenting the certificates it holds now (in place of its
    /// enrollment link, or of a link whose hello no longer says all it is).
    Enrolled,
    /// A connection names a direct-path session ([`LinkHello::direct_path`])
    /// this device is not punching (it ended, or never began): the other
    /// device's next punch makes a new one.
    PathExpired,
    /// The device closed its link to sleep: its on-demand link carried
    /// nothing for its idle time, its host went inactive (an app in the
    /// background), or its link mode was turned off. It links again when it
    /// has something to send or is woken; a relay it asked to
    /// ([`Reachability`]) holds Interests for it and wakes it meanwhile.
    Asleep,
    /// The device no longer uses this relay: a relay it prefers is back, or
    /// this relay was removed from its configuration or disconnected by its
    /// user. Not a fault of either side.
    Released,
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
    /// Direct paths between the two devices are turned off: by the link
    /// policy of the namespace (its trust context), or by this device's
    /// peer entry for the other. Refuses a direct-path punch.
    DirectPathsOff,
    /// This relay's serving policy does not serve the device's namespace or
    /// key (it serves its own namespaces, listed ones, or any within quotas,
    /// as its operator chose): use another relay, or ask this relay's
    /// operator to serve the namespace.
    NotServed,
    /// A [`Membership`] in the hello is not bound to this link: its binding
    /// does not verify under that certificate's key for the sender's link
    /// key on this connection — the sender does not hold the certificate's
    /// key (a forged membership), or the binding was made for another
    /// connection (a replayed one).
    MembershipNotBound,
}

impl CloseReason {
    pub fn code(self) -> u32 {
        match self {
            Self::Shutdown => 0x00,
            Self::Replaced => 0x01,
            Self::Idle => 0x02,
            Self::Enrolled => 0x03,
            Self::PathExpired => 0x04,
            Self::Asleep => 0x05,
            Self::Released => 0x06,
            Self::Unrecognized => 0x10,
            Self::CertificateForAnotherKey => 0x11,
            Self::Revoked => 0x12,
            Self::RoleNotAllowed => 0x13,
            Self::NotTheExpectedDevice => 0x14,
            Self::Protocol => 0x15,
            Self::Busy => 0x16,
            Self::NoLinkKey => 0x17,
            Self::DirectPathsOff => 0x18,
            Self::NotServed => 0x19,
            Self::MembershipNotBound => 0x1A,
        }
    }

    pub fn from_code(code: u64) -> Option<Self> {
        Some(match code {
            0x00 => Self::Shutdown,
            0x01 => Self::Replaced,
            0x02 => Self::Idle,
            0x03 => Self::Enrolled,
            0x04 => Self::PathExpired,
            0x05 => Self::Asleep,
            0x06 => Self::Released,
            0x10 => Self::Unrecognized,
            0x11 => Self::CertificateForAnotherKey,
            0x12 => Self::Revoked,
            0x13 => Self::RoleNotAllowed,
            0x14 => Self::NotTheExpectedDevice,
            0x15 => Self::Protocol,
            0x16 => Self::Busy,
            0x17 => Self::NoLinkKey,
            0x18 => Self::DirectPathsOff,
            0x19 => Self::NotServed,
            0x1A => Self::MembershipNotBound,
            _ => return None,
        })
    }

    /// Whether the link should be dialled again later without a change on
    /// either side: a shutdown, a busy listener, an idle enrollment link,
    /// an enrollment completed, an expired direct-path session, a device
    /// gone asleep or a relay released pass; a refusal of the key or of its
    /// namespace does not (until the trust data or the config changes).
    pub fn is_transient(self) -> bool {
        matches!(
            self,
            Self::Shutdown
                | Self::Replaced
                | Self::Idle
                | Self::Enrolled
                | Self::PathExpired
                | Self::Asleep
                | Self::Released
                | Self::Busy
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_hello_round_trips() {
        for hello in [
            LinkHello {
                certificates: vec![
                    Bytes::from_static(&[0x06, 0x01, 0xAA]),
                    Bytes::from_static(&[0x06, 0x00]),
                ],
                ..LinkHello::default()
            },
            LinkHello {
                direct_path: Some([1, 2, 3, 4, 5, 6, 7, 8]),
                ..LinkHello::default()
            },
            LinkHello {
                certificates: vec![Bytes::from_static(&[0x06, 0x01, 0xAA])],
                memberships: vec![Membership {
                    certificates: vec![
                        Bytes::from_static(&[0x06, 0x01, 0xBB]),
                        Bytes::from_static(&[0x06, 0x00]),
                    ],
                    binding: Bytes::from_static(&[1, 2, 3]),
                }],
                direct_path: Some([8; 8]),
            },
        ] {
            let wire = hello.encode();
            let (t, start, end) = split_tlv(&wire).unwrap();
            assert_eq!(t, LINK_HELLO);
            assert_eq!(LinkHello::decode(&wire[start..end]).unwrap(), hello);
        }
    }

    #[test]
    fn udp_addresses_and_observed_address_messages_round_trip() {
        for addr in ["192.0.2.7:6363", "[2001:db8::1]:443"] {
            let addr: SocketAddr = addr.parse().unwrap();
            assert_eq!(decode_udp_address(&encode_udp_address(addr)).unwrap(), addr);
        }
        // An IPv4-mapped IPv6 address is carried as IPv4.
        let mapped: SocketAddr = "[::ffff:192.0.2.7]:6363".parse().unwrap();
        assert_eq!(encode_udp_address(mapped), [192, 0, 2, 7, 0x18, 0xDB]);
        assert!(decode_udp_address(&[1, 2, 3, 4, 5]).is_err());
        let wire = encode_observed_address("192.0.2.7:6363".parse().unwrap());
        assert_eq!(
            wire.as_ref(),
            [0xFD, 0x04, 0x58, 0x06, 192, 0, 2, 7, 0x18, 0xDB]
        );
    }

    #[test]
    fn a_direct_path_session_is_eight_bytes() {
        let hello = |len: u8| {
            let mut v = vec![0xFD, 0x04, 0x51, 0x01, 0x01, 0xFD, 0x04, 0x5A, len];
            v.extend(std::iter::repeat_n(0xAB, usize::from(len)));
            LinkHello::decode(&v)
        };
        assert_eq!(hello(8).unwrap().direct_path, Some([0xAB; 8]));
        assert!(hello(7).is_err());
        assert!(hello(9).is_err());
        // The vector of ndn-link.md: no certificate, session 01..08.
        let wire = LinkHello {
            direct_path: Some([1, 2, 3, 4, 5, 6, 7, 8]),
            ..LinkHello::default()
        }
        .encode();
        assert_eq!(
            wire.as_ref(),
            [
                0xFD, 0x04, 0x50, 0x11, 0xFD, 0x04, 0x51, 0x01, 0x01, 0xFD, 0x04, 0x5A, 0x08, 1, 2,
                3, 4, 5, 6, 7, 8
            ]
        );
    }

    #[test]
    fn a_membership_needs_a_certificate_and_a_binding() {
        let hello = |membership: &[u8]| {
            let mut v = vec![
                0xFD,
                0x04,
                0x51,
                0x01,
                0x01,
                0xFD,
                0x04,
                0x5C,
                membership.len() as u8,
            ];
            v.extend_from_slice(membership);
            LinkHello::decode(&v)
        };
        let ok = hello(&[0x06, 0x00, 0xFD, 0x04, 0x5E, 0x01, 0xAA]).unwrap();
        assert_eq!(ok.memberships[0].binding.as_ref(), [0xAA]);
        assert!(hello(&[0xFD, 0x04, 0x5E, 0x01, 0xAA]).is_err());
        assert!(hello(&[0x06, 0x00]).is_err());
        assert!(hello(&[0x06, 0x00, 0xFD, 0x04, 0x5E, 0x00]).is_err());
        assert!(
            hello(&[
                0x06, 0x00, 0xFD, 0x04, 0x5E, 0x01, 0xAA, 0xFD, 0x04, 0x5F, 0x00
            ])
            .is_err()
        );
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
            CloseReason::PathExpired,
            CloseReason::Asleep,
            CloseReason::Released,
            CloseReason::Unrecognized,
            CloseReason::CertificateForAnotherKey,
            CloseReason::Revoked,
            CloseReason::RoleNotAllowed,
            CloseReason::NotTheExpectedDevice,
            CloseReason::Protocol,
            CloseReason::Busy,
            CloseReason::NoLinkKey,
            CloseReason::DirectPathsOff,
            CloseReason::NotServed,
            CloseReason::MembershipNotBound,
        ] {
            assert_eq!(CloseReason::from_code(u64::from(r.code())), Some(r));
        }
        // The codes of ndn-link.md, and which pass with time.
        for (r, code, transient) in [
            (CloseReason::Asleep, 0x05, true),
            (CloseReason::Released, 0x06, true),
            (CloseReason::NotServed, 0x19, false),
            (CloseReason::MembershipNotBound, 0x1A, false),
        ] {
            assert_eq!((r.code(), r.is_transient()), (code, transient), "{r:?}");
        }
    }

    #[test]
    fn reachability_matches_the_spec_vectors_and_round_trips() {
        let full = Reachability {
            hold: true,
            wake_token: Some(Bytes::from_static(b"tok")),
        };
        let wire = full.encode();
        assert_eq!(
            wire.as_ref(),
            [
                0xFD, 0x04, 0x40, 0x0B, 0xFD, 0x04, 0x42, 0x00, 0xFD, 0x04, 0x44, 0x03, b't', b'o',
                b'k'
            ]
        );
        assert_eq!(Reachability::decode(&wire[4..]).unwrap(), full);
        // Neither: no holding, no waking.
        assert_eq!(
            Reachability::default().encode().as_ref(),
            [0xFD, 0x04, 0x40, 0x00]
        );
        assert_eq!(Reachability::decode(&[]).unwrap(), Reachability::default());
        // HoldInterests is empty; a wake token is 1..=1024 bytes.
        assert!(Reachability::decode(&[0xFD, 0x04, 0x42, 0x01, 0x01]).is_err());
        assert!(Reachability::decode(&[0xFD, 0x04, 0x44, 0x00]).is_err());
        let mut long = vec![0xFD, 0x04, 0x44, 0xFD, 0x04, 0x01];
        long.extend([0u8; 1025]);
        assert!(Reachability::decode(&long).is_err());
        long.truncate(long.len() - 1);
        long[5] = 0x00;
        assert_eq!(
            Reachability::decode(&long)
                .unwrap()
                .wake_token
                .unwrap()
                .len(),
            WAKE_TOKEN_MAX
        );
    }

    #[test]
    fn presence_matches_the_spec_vector_and_round_trips() {
        let presence = Presence {
            namespace: "/home".parse().unwrap(),
            devices: vec![PresentDevice {
                device: "/home/d".parse().unwrap(),
                key: KeyFingerprint([0xAB; 32]),
            }],
        };
        let mut expected = vec![
            0xFD, 0x04, 0x46, 0x3B, 0x07, 0x06, 0x08, 0x04, b'h', b'o', b'm', b'e',
        ];
        expected.extend([0xFD, 0x04, 0x48, 0x2F]);
        expected.extend([
            0x07, 0x09, 0x08, 0x04, b'h', b'o', b'm', b'e', 0x08, 0x01, b'd',
        ]);
        expected.extend([0xFD, 0x04, 0x4A, 0x20]);
        expected.extend([0xAB; 32]);
        let wire = presence.encode();
        assert_eq!(wire.as_ref(), expected);
        assert_eq!(Presence::decode(&wire[4..]).unwrap(), presence);
        let none = Presence {
            namespace: "/home".parse().unwrap(),
            devices: Vec::new(),
        };
        assert_eq!(Presence::decode(&none.encode()[4..]).unwrap(), none);
        // A namespace is required; a key digest is 32 bytes.
        assert!(Presence::decode(&[]).is_err());
        let short_key = [
            0x07, 0x00, 0xFD, 0x04, 0x48, 0x07, 0x07, 0x00, 0xFD, 0x04, 0x4A, 0x01, 0xAB,
        ];
        assert!(Presence::decode(&short_key).is_err());
        let no_key = [0x07, 0x00, 0xFD, 0x04, 0x48, 0x02, 0x07, 0x00];
        assert!(Presence::decode(&no_key).is_err());
    }
}
