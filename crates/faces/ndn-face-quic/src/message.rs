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
//! 0x045C*, DirectPath 0x045A (8 bytes)?, Follows 0x0456 { Name+ }?,
//! ChannelCaps 0x044E (1 byte) }` — the
//! first Data is the sender's certificate for its link key, the rest its
//! issuers (nearest first); each [`Membership`] is a namespace the sender is a
//! member of with another key, bound to this connection; `DirectPath` marks a
//! connection made for a direct path of the link (the punch's session);
//! `Follows` names the space groups the sender follows
//! (`<owner>/32=sync/<space>`, each a whole group name, never a namespace or
//! an owner's whole group), told to a peer it uses as a relay so that the
//! relay routes exactly those groups to it (at most [`FOLLOWS_MAX`] names,
//! each of at most [`FOLLOW_DEPTH_MAX`] components, see
//! [`check_followed_group`]); `ChannelCaps` is a bit set of what the sender
//! can carry besides NDN packets (bit 0: channel frames, version 1, see
//! [`CHANNEL_CAPS_V1`]), always sent; a sender that predates it sends none,
//! which a receiver reads as no capability, and a side sends no channel frame
//! to a peer that did not advertise it;
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
//! `Departure = 0x044C { Name(folder), Name(record) }` — after the verdict,
//! inviter to the person it let go of `folder`: the log entry name of the
//! members record that leaves the person out, a hint of which name to fetch
//! (it carries no authority; the record is judged by its signatures). The
//! latest for a folder replaces the earlier ones.
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
const FOLLOWS: u64 = 0x0456;
pub(crate) const REACHABILITY: u64 = 0x0440;
const HOLD_INTERESTS: u64 = 0x0442;
const WAKE_TOKEN: u64 = 0x0444;
pub(crate) const PRESENCE: u64 = 0x0446;
const PRESENT_DEVICE: u64 = 0x0448;
const KEY_DIGEST: u64 = 0x044A;
pub(crate) const DEPARTURE: u64 = 0x044C;
/// The hello's `ChannelCaps`: one octet, a bit set.
pub(crate) const CHANNEL_CAPS: u64 = 0x044E;

/// Bit 0 of `ChannelCaps`: the sender carries channel frames (first octet
/// `0x00`, ndn-link.md §9) as QUIC datagrams and on one unidirectional stream
/// per direction, version 1.
pub const CHANNEL_CAPS_V1: u8 = 0x01;

/// Most space groups a hello's `Follows` names; a receiver ignores the rest
/// (and a sender names no more). A device follows spaces, not namespaces, so
/// the count is of spaces: 32 is a few dozen spaces over a handful of
/// people, and bounds the routes one link makes on a relay.
pub const FOLLOWS_MAX: usize = 32;
/// Most components of a followed group's name: a longer name is malformed in
/// a hello. A group is `<owner>/32=sync/<space>`: an owner namespace of at
/// most 8 components (the bound a followed namespace had), the keyword, and
/// at most [`FOLLOW_SPACE_MAX`] components of the space's own name.
pub const FOLLOW_DEPTH_MAX: usize = 13;
/// Most components after `32=sync` in a followed group: the space's name
/// under its owner (one to four, as the data layer names a space).
pub const FOLLOW_SPACE_MAX: usize = 4;
/// Most distinct `Departure` messages a link takes from its peer, and queues
/// toward it: a person is let go of a few folders at once, not hundreds.
pub const DEPARTURES_MAX: usize = 16;
pub(crate) const DATA: u64 = 0x06;
const NAME: u64 = 0x07;

/// The session of a direct-path attempt (its punch), which the dialer of a
/// direct path names in its [`LinkHello`].
pub type PathSession = [u8; 8];

/// The link protocol version this crate speaks.
pub const LINK_PROTOCOL_VERSION: u8 = 1;

/// Upper bound on one link message: a certificate chain is a few KiB.
pub(crate) const MAX_MESSAGE: usize = 64 * 1024;

/// The first link message: the sender's certificate and its issuers, its
/// memberships of other namespaces, and what else it can carry.
#[derive(Clone, Debug, PartialEq, Eq)]
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
    /// The space groups the sender follows (`<owner>/32=sync/<space>`, as
    /// [`check_followed_group`] defines them), told to a peer it uses as a
    /// relay (empty otherwise): the relay routes exactly these groups over
    /// this link, not the owner's others. A claim buys those routes and
    /// nothing else. At most [`FOLLOWS_MAX`] of them, each of at most
    /// [`FOLLOW_DEPTH_MAX`] components; a receiver uses the first
    /// [`FOLLOWS_MAX`] and takes a name that is no such group for a
    /// malformed hello.
    pub follows: Vec<Name>,
    /// `Some`: this connection is a direct path made by the punch of this
    /// session (the dialer names it; the listener repeats it when it takes
    /// the connection as that direct path).
    pub direct_path: Option<PathSession>,
    /// `ChannelCaps`: a bit set of what the sender carries besides NDN
    /// packets ([`CHANNEL_CAPS_V1`]). The default hello claims what this
    /// implementation speaks; a decoded hello has no bit for a sender that
    /// predates the field. Only a link whose two hellos both have the bit
    /// carries channel frames.
    pub channel_caps: u8,
}

impl Default for LinkHello {
    fn default() -> Self {
        Self {
            certificates: Vec::new(),
            memberships: Vec::new(),
            follows: Vec::new(),
            direct_path: None,
            channel_caps: CHANNEL_CAPS_V1,
        }
    }
}

/// Whether `name` is a space group a device can follow, as the data layer
/// names one: `<owner>/32=sync/<s1>[/…/<s4>]` — a non-empty owner namespace
/// of plain components (no keyword, no digest), the keyword `32=sync`, then
/// one to [`FOLLOW_SPACE_MAX`] generic components, and at most
/// [`FOLLOW_DEPTH_MAX`] components in all. A namespace and the owner's whole
/// group (`<owner>/32=sync`, the prefix of every space of the owner) are
/// not one: a claim names the spaces it follows, never more.
///
/// `Err` says what the name lacks.
pub fn check_followed_group(name: &Name) -> Result<(), String> {
    use ndn_packet::tlv_type::{IMPLICIT_SHA256, KEYWORD, NAME_COMPONENT, PARAMETERS_SHA256};
    let comps = name.components();
    let Some(at) = comps
        .iter()
        .position(|c| c.typ == KEYWORD && c.value.as_ref() == b"sync")
    else {
        return Err(format!(
            "{name} is no space group: it has no 32=sync component (a followed group is \
             <owner>/32=sync/<space>)"
        ));
    };
    if at == 0 {
        return Err(format!("{name} has no owner namespace before 32=sync"));
    }
    if comps[..at]
        .iter()
        .any(|c| matches!(c.typ, KEYWORD | IMPLICIT_SHA256 | PARAMETERS_SHA256))
    {
        return Err(format!(
            "{name} has a keyword or digest component in its owner namespace"
        ));
    }
    let space = &comps[at + 1..];
    if space.is_empty() {
        return Err(format!(
            "{name} is the whole group of its owner, the prefix of every space: name the \
             space's own group, <owner>/32=sync/<space>"
        ));
    }
    if space.len() > FOLLOW_SPACE_MAX || space.iter().any(|c| c.typ != NAME_COMPONENT) {
        return Err(format!(
            "{name}: after 32=sync a group has 1 to {FOLLOW_SPACE_MAX} generic components (the \
             space's name)"
        ));
    }
    if comps.len() > FOLLOW_DEPTH_MAX {
        return Err(format!(
            "{name} has {} components (a followed group has at most {FOLLOW_DEPTH_MAX})",
            comps.len()
        ));
    }
    Ok(())
}

impl LinkHello {
    /// What a hello says: at most [`FOLLOWS_MAX`] of `follows`, the ones that
    /// are followable groups ([`check_followed_group`]; a sender never makes
    /// its own hello malformed).
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
            let follows: Vec<&Name> = self
                .follows
                .iter()
                .filter(|g| check_followed_group(g).is_ok())
                .take(FOLLOWS_MAX)
                .collect();
            if !follows.is_empty() {
                w.write_nested(FOLLOWS, |w| {
                    for ns in follows {
                        w.write_raw(&ns.encode_to_tlv());
                    }
                });
            }
            if let Some(session) = &self.direct_path {
                w.write_tlv(DIRECT_PATH, session);
            }
            w.write_tlv(CHANNEL_CAPS, &[self.channel_caps]);
        });
        w.finish()
    }

    /// Decode the value of a `LinkHello` TLV.
    pub(crate) fn decode(value: &[u8]) -> Result<Self, String> {
        let mut certificates = Vec::new();
        let mut memberships = Vec::new();
        let mut follows: Vec<Name> = Vec::new();
        let mut direct_path = None;
        let mut channel_caps = 0;
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
                FOLLOWS => {
                    let mut names = &cur[start..end];
                    if names.is_empty() {
                        return Err("a Follows naming no space group in the link hello".into());
                    }
                    while !names.is_empty() {
                        let (nt, nstart, nend) = split_tlv(names)?;
                        if nt != NAME {
                            return Err(format!(
                                "{nt:#x} where a followed group's name belongs in the link hello"
                            ));
                        }
                        let group = Name::decode(Bytes::copy_from_slice(&names[nstart..nend]))
                            .map_err(|e| format!("a followed group in the link hello: {e}"))?;
                        check_followed_group(&group)
                            .map_err(|e| format!("a followed group in the link hello: {e}"))?;
                        if follows.len() < FOLLOWS_MAX {
                            follows.push(group);
                        }
                        names = &names[nend..];
                    }
                }
                DIRECT_PATH => {
                    direct_path = Some(PathSession::try_from(&cur[start..end]).map_err(|_| {
                        format!(
                            "a direct-path session of {} bytes in the link hello (it is 8 bytes)",
                            end - start
                        )
                    })?);
                }
                CHANNEL_CAPS => match &cur[start..end] {
                    [caps] => channel_caps = *caps,
                    other => {
                        return Err(format!(
                            "channel capabilities of {} bytes in the link hello (they are one byte)",
                            other.len()
                        ));
                    }
                },
                t if skippable(t) => {}
                t => return Err(format!("unknown critical field {t:#x} in the link hello")),
            }
            cur = &cur[end..];
        }
        match version {
            Some(LINK_PROTOCOL_VERSION) => Ok(Self {
                certificates,
                memberships,
                follows,
                direct_path,
                channel_caps,
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

/// A `Departure` message: the inviter tells a person it let go which members
/// record to fetch. A hint of *which name to ask for*, with no authority of
/// its own: the record fetched is judged by its signatures, not by this.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Departure {
    /// The folder the person was let go of.
    pub folder: Name,
    /// The log entry name of the members record that leaves the person out.
    pub record: Name,
}

impl Departure {
    pub(crate) fn encode(&self) -> Bytes {
        let mut w = TlvWriter::new();
        w.write_nested(DEPARTURE, |w| {
            w.write_raw(&self.folder.encode_to_tlv());
            w.write_raw(&self.record.encode_to_tlv());
        });
        w.finish()
    }

    /// Decode the value of a `Departure` TLV: exactly two names, the folder
    /// then the record.
    pub(crate) fn decode(value: &[u8]) -> Result<Self, String> {
        let mut folder = None;
        let mut record = None;
        let mut cur = value;
        while !cur.is_empty() {
            let (t, start, end) = split_tlv(cur)?;
            match t {
                NAME if folder.is_none() => {
                    folder = Some(decode_name(
                        &cur[start..end],
                        "the folder of the Departure message",
                    )?);
                }
                NAME if record.is_none() => {
                    record = Some(decode_name(
                        &cur[start..end],
                        "the record of the Departure message",
                    )?);
                }
                NAME => return Err("a third name in the Departure message".into()),
                t if skippable(t) => {}
                t => {
                    return Err(format!(
                        "unknown critical field {t:#x} in the Departure message"
                    ));
                }
            }
            cur = &cur[end..];
        }
        match (folder, record) {
            (Some(folder), Some(record)) => Ok(Self { folder, record }),
            _ => Err("a Departure message needs a folder and a record name".into()),
        }
    }
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
                follows: vec![
                    "/a/32=sync/x".parse().unwrap(),
                    "/b/c/32=sync/y/z".parse().unwrap(),
                ],
                channel_caps: 0,
            },
            LinkHello {
                follows: vec!["/a/32=sync/x".parse().unwrap()],
                ..LinkHello::default()
            },
        ] {
            let wire = hello.encode();
            let (t, start, end) = split_tlv(&wire).unwrap();
            assert_eq!(t, LINK_HELLO);
            assert_eq!(LinkHello::decode(&wire[start..end]).unwrap(), hello);
        }
    }

    /// The wire of a hello whose `Follows` field holds `names` (each as given:
    /// the bytes of a Name TLV).
    fn hello_following(names: &[Vec<u8>]) -> Vec<u8> {
        let inner: Vec<u8> = names.concat();
        let mut v = vec![0xFD, 0x04, 0x51, 0x01, 0x01, 0xFD, 0x04, 0x56];
        if inner.len() < 253 {
            v.push(inner.len() as u8);
        } else {
            v.push(0xFD);
            v.extend((inner.len() as u16).to_be_bytes());
        }
        v.extend(inner);
        v
    }

    fn name_tlv(text: &str) -> Vec<u8> {
        text.parse::<Name>().unwrap().encode_to_tlv().to_vec()
    }

    #[test]
    fn a_hello_follows_is_even_names_and_an_older_receiver_skips_it() {
        let wire = LinkHello {
            follows: vec![
                "/a/32=sync/x".parse().unwrap(),
                "/b/c/32=sync/y/z".parse().unwrap(),
            ],
            ..LinkHello::default()
        }
        .encode();
        // The vector of ndn-link.md §19.21: Follows 0x0456 { /a/32=sync/x,
        // /b/c/32=sync/y/z } after the version, then ChannelCaps 0x044E 01.
        assert_eq!(
            wire.as_ref(),
            [
                0xFD, 0x04, 0x50, 0x30, 0xFD, 0x04, 0x51, 0x01, 0x01, 0xFD, 0x04, 0x56, 0x22, 0x07,
                0x0C, 0x08, 0x01, 0x61, 0x20, 0x04, 0x73, 0x79, 0x6E, 0x63, 0x08, 0x01, 0x78, 0x07,
                0x12, 0x08, 0x01, 0x62, 0x08, 0x01, 0x63, 0x20, 0x04, 0x73, 0x79, 0x6E, 0x63, 0x08,
                0x01, 0x79, 0x08, 0x01, 0x7A, 0xFD, 0x04, 0x4E, 0x01, 0x01
            ]
        );
        // 0x0456 is even and above 31: a receiver that does not know it skips it.
        assert!(skippable(0x0456));
        // An unknown even field beside it is skipped; an odd one is a
        // malformed hello.
        let mut v = hello_following(&[name_tlv("/a/32=sync/x")]);
        v.extend([0xFD, 0x04, 0x70, 0x01, 0xAA]);
        assert_eq!(
            LinkHello::decode(&v).unwrap().follows,
            ["/a/32=sync/x".parse::<Name>().unwrap()]
        );
        v.extend([0xFD, 0x04, 0x71, 0x00]);
        assert!(LinkHello::decode(&v).is_err());
    }

    #[test]
    fn a_hello_follows_is_bounded() {
        let group = |i: usize| format!("/n{i}/32=sync/s");
        let many: Vec<Vec<u8>> = (0..FOLLOWS_MAX + 3).map(|i| name_tlv(&group(i))).collect();
        // Over the limit: the first FOLLOWS_MAX are used, the rest ignored.
        let big = hello_following(&many);
        let decoded = LinkHello::decode(&big).unwrap();
        assert_eq!(decoded.follows.len(), FOLLOWS_MAX);
        assert_eq!(decoded.follows[0], group(0).parse::<Name>().unwrap());
        assert_eq!(
            decoded.follows[FOLLOWS_MAX - 1],
            group(FOLLOWS_MAX - 1).parse::<Name>().unwrap()
        );
        // The sender names no more than FOLLOWS_MAX either.
        let told = LinkHello {
            follows: (0..FOLLOWS_MAX + 3)
                .map(|i| group(i).parse().unwrap())
                .collect(),
            ..LinkHello::default()
        }
        .encode();
        let (_, start, end) = split_tlv(&told).unwrap();
        assert_eq!(
            LinkHello::decode(&told[start..end]).unwrap().follows.len(),
            FOLLOWS_MAX
        );
    }

    /// A hello's `Follows` names space groups, `<owner>/32=sync/<1 to 4
    /// components>`, and nothing else: a namespace, the owner's whole group
    /// (`<owner>/32=sync`, the prefix of every space of the owner) and any
    /// other name is a malformed hello, so no claim can route more than the
    /// spaces it names.
    #[test]
    fn a_hello_follows_names_exact_groups_and_refuses_what_is_not_one() {
        let ok = |text: &str| LinkHello::decode(&hello_following(&[name_tlv(text)])).is_ok();
        assert!(ok("/a/32=sync/x"));
        assert!(ok("/a/b/c/32=sync/w/x/y/z"));
        // A namespace, and the group of the owner's every space.
        assert!(!ok("/a"), "a namespace is no group");
        assert!(!ok("/a/32=sync"), "the owner's whole group is no space's");
        // The owner is not empty; a space's name is one to four components.
        assert!(!ok("/32=sync/x"));
        assert!(!ok("/a/32=sync/v/w/x/y/z"));
        // Only the group's own keyword: no other keyword in the owner or after it.
        assert!(!ok("/a/32=data/x"));
        assert!(!ok("/a/32=data/32=sync/x"));
        assert!(!ok("/a/32=sync/32=sync"));
        assert!(!ok("/a/32=sync/x/32=sync/y"));
        assert!(!ok("/a/32=sync/x/v=3"));
        // The deepest group is FOLLOW_DEPTH_MAX components; one more is malformed.
        let deepest = |owner: usize| format!("{}/32=sync/w/x/y/z", "/o".repeat(owner));
        assert!(ok(&deepest(FOLLOW_DEPTH_MAX - 5)));
        assert!(!ok(&deepest(FOLLOW_DEPTH_MAX - 4)));
        // The root is no group; neither is an empty or a foreign list.
        assert!(LinkHello::decode(&hello_following(&[vec![0x07, 0x00]])).is_err());
        assert!(LinkHello::decode(&hello_following(&[])).is_err());
        assert!(LinkHello::decode(&hello_following(&[vec![0x08, 0x01, 0x61]])).is_err());
        assert!(LinkHello::decode(&hello_following(&[vec![0x07, 0x05, 0x08]])).is_err());
        // A sender never makes its own hello malformed: it leaves such names out.
        let wire = LinkHello {
            follows: vec![
                "/a".parse().unwrap(),
                "/a/32=sync".parse().unwrap(),
                "/a/32=sync/x".parse().unwrap(),
            ],
            ..LinkHello::default()
        }
        .encode();
        let (_, start, end) = split_tlv(&wire).unwrap();
        assert_eq!(
            LinkHello::decode(&wire[start..end]).unwrap().follows,
            ["/a/32=sync/x".parse::<Name>().unwrap()]
        );
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
                0xFD, 0x04, 0x50, 0x16, 0xFD, 0x04, 0x51, 0x01, 0x01, 0xFD, 0x04, 0x5A, 0x08, 1, 2,
                3, 4, 5, 6, 7, 8, 0xFD, 0x04, 0x4E, 0x01, 0x01
            ]
        );
    }

    /// `ChannelCaps` (0x044E) is one octet, always encoded, and read as an even
    /// field: a hello from a sender that predates it decodes with no capability,
    /// and one whose field is not one octet is malformed.
    #[test]
    fn a_hello_carries_channel_caps_and_an_older_hello_has_none() {
        let wire = LinkHello::default().encode();
        assert_eq!(
            wire.as_ref(),
            [
                0xFD, 0x04, 0x50, 0x0A, 0xFD, 0x04, 0x51, 0x01, 0x01, 0xFD, 0x04, 0x4E, 0x01, 0x01
            ]
        );
        assert!(skippable(CHANNEL_CAPS));
        let (_, start, end) = split_tlv(&wire).unwrap();
        assert_eq!(
            LinkHello::decode(&wire[start..end]).unwrap().channel_caps,
            CHANNEL_CAPS_V1
        );
        // Always encoded, even when it claims nothing.
        let none = LinkHello {
            channel_caps: 0,
            ..LinkHello::default()
        }
        .encode();
        assert_eq!(&none[none.len() - 5..], [0xFD, 0x04, 0x4E, 0x01, 0x00]);
        // A sender that predates the field sends none: no capability.
        let older = [0xFD, 0x04, 0x51, 0x01, 0x01];
        assert_eq!(LinkHello::decode(&older).unwrap().channel_caps, 0);
        // Bits beyond the ones this side knows are kept, not an error.
        let future = [0xFD, 0x04, 0x51, 0x01, 0x01, 0xFD, 0x04, 0x4E, 0x01, 0x03];
        assert_eq!(LinkHello::decode(&future).unwrap().channel_caps, 0x03);
        // Not one octet: malformed.
        for bad in [
            &[0xFD, 0x04, 0x51, 0x01, 0x01, 0xFD, 0x04, 0x4E, 0x00][..],
            &[
                0xFD, 0x04, 0x51, 0x01, 0x01, 0xFD, 0x04, 0x4E, 0x02, 0x01, 0x01,
            ][..],
        ] {
            assert!(LinkHello::decode(bad).is_err());
        }
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
        assert!(LinkHello::decode(&[0xFD, 0x04, 0x51, 0x01, 0x01, 0xFD, 0x04, 0x70, 0x00]).is_ok());
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

    #[test]
    fn departure_matches_the_spec_vector_round_trips_and_is_read_strictly() {
        let departure = Departure {
            folder: "/a/32=data/n".parse().unwrap(),
            record: "/a/d/32=log/n/seq=3".parse().unwrap(),
        };
        let wire = departure.encode();
        // The vector of the spec (ndn-link.md §19.20), 37 bytes.
        let hex: String = wire.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "fd044c21070c08016120046461746108016e071108016108016420036c6f6708016e3a0103"
        );
        // 0x044C { Name(folder), Name(record) }
        assert_eq!(&wire[..3], [0xFD, 0x04, 0x4C]);
        let folder = departure.folder.encode_to_tlv();
        let record = departure.record.encode_to_tlv();
        assert_eq!(usize::from(wire[3]), folder.len() + record.len());
        assert_eq!(&wire[4..4 + folder.len()], folder.as_ref());
        assert_eq!(&wire[4 + folder.len()..], record.as_ref());
        assert_eq!(Departure::decode(&wire[4..]).unwrap(), departure);
        // Both names are required, and no third one.
        assert!(Departure::decode(&[]).is_err());
        assert!(Departure::decode(&folder).is_err());
        let mut three = wire[4..].to_vec();
        three.extend_from_slice(&record);
        assert!(Departure::decode(&three).is_err());
        // An unknown even field above 31 is skipped, an odd one is critical.
        let mut skipped = wire[4..].to_vec();
        skipped.extend([0xFD, 0x04, 0x4E, 0x00]);
        assert_eq!(Departure::decode(&skipped).unwrap(), departure);
        let mut critical = wire[4..].to_vec();
        critical.extend([0xFD, 0x04, 0x4F, 0x00]);
        assert!(Departure::decode(&critical).is_err());
        // A name that is not a Name.
        assert!(Departure::decode(&[0x07, 0x01, 0xFF, 0x07, 0x00]).is_err());
    }
}
