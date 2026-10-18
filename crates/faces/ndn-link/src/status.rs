//! What a host shows about this device's links: each device it links with,
//! the paths that reach it, and whether a direct path is up, being tried,
//! or why not.

use std::net::SocketAddr;
use std::time::Duration;

use ndn_face_quic::KeyFingerprint;
use ndn_packet::Name;
use ndn_transport::FaceId;

/// This device's links, as [`Links::report`](crate::Links::report) gives
/// them.
#[derive(Clone, Debug, Default)]
pub struct LinkReport {
    /// The fingerprint of the key this device links with now (what other
    /// devices name in `[[peer]] key`).
    pub key: Option<KeyFingerprint>,
    /// Probe datagrams this device sent for direct-path punches, in total.
    pub probes_sent: u64,
    /// Punch requests this device refused, in total.
    pub punches_refused: u64,
    pub links: Vec<LinkStatus>,
}

/// One device this device links with (or is configured to, or punched
/// with).
#[derive(Clone, Debug)]
pub struct LinkStatus {
    /// How messages name it: its peer entry's label, else its device name,
    /// else its key.
    pub label: String,
    /// Its key, once known.
    pub key: Option<KeyFingerprint>,
    /// Its device name, once known (from its certificate, or its peer
    /// entry).
    pub device: Option<Name>,
    /// The ways it is reached now; empty when it is not.
    pub paths: Vec<PathStatus>,
    /// Its direct path: up, being tried, or why not.
    pub direct: DirectStatus,
}

/// What reaches a device.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PathKind {
    /// A QUIC link dialled to a configured endpoint, or accepted.
    Link,
    /// A QUIC link a hole punch made.
    Direct,
    /// Routes over the link to the relay the device is reached through.
    Relay,
}

impl PathKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Link => "link",
            Self::Direct => "direct",
            Self::Relay => "relay",
        }
    }
}

/// One path to a device.
#[derive(Clone, Debug)]
pub struct PathStatus {
    pub kind: PathKind,
    /// The face carrying it (for a relay path, the relay's link face).
    pub face: FaceId,
    /// The address the QUIC connection reaches (for a relay path, the
    /// relay's).
    pub remote: Option<SocketAddr>,
    /// The connection's round-trip time estimate.
    pub rtt: Option<Duration>,
    /// How long it has been up.
    pub age: Duration,
    /// For a relay path: the relay's label.
    pub via: Option<String>,
}

/// The state of a device's direct path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DirectState {
    /// No direct path is wanted: the device is not reached through a relay,
    /// or it is linked already.
    None,
    /// Direct paths are turned off (the link policy, or the peer entry);
    /// the text says which.
    Off,
    /// A punch runs now.
    Trying,
    /// A direct path is up.
    Up,
    /// The last punch did not make a direct path; the text says why. It is
    /// tried again later.
    NotPossible,
    /// The last punch was refused (by the other device, or by this one);
    /// the text says why.
    Refused,
}

impl DirectState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Off => "off",
            Self::Trying => "trying",
            Self::Up => "up",
            Self::NotPossible => "not-possible",
            Self::Refused => "refused",
        }
    }
}

/// A device's direct-path state, why, and when it is tried next.
#[derive(Clone, Debug)]
pub struct DirectStatus {
    pub state: DirectState,
    /// For a person: why, and what to do if anything.
    pub text: String,
    /// When the next punch is due, for `NotPossible` and `Refused`.
    pub retry_in: Option<Duration>,
}

impl Default for DirectStatus {
    fn default() -> Self {
        Self {
            state: DirectState::None,
            text: String::new(),
            retry_in: None,
        }
    }
}
