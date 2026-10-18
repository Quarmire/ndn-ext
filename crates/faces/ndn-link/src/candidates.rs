//! Where a device may be reached directly: its candidate addresses, which
//! it signs into a punch, and the order the dialling side tries the other's.

use std::net::{IpAddr, SocketAddr};

/// How a device knows a candidate address of its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CandidateKind {
    /// An address of one of its interfaces, on the link socket's port.
    Host,
    /// The address a linked device sees it at (`ObservedAddress`): its
    /// address beyond the NATs on that path (server-reflexive).
    Reflexive,
    /// An address configured to reach the link socket (a port forward).
    Advertised,
    /// An address a port-mapping protocol (PCP, NAT-PMP, UPnP) mapped to
    /// the link socket.
    Mapped,
}

impl CandidateKind {
    /// The kind's code in a punch message.
    pub fn code(self) -> u8 {
        match self {
            Self::Host => 0,
            Self::Reflexive => 1,
            Self::Advertised => 2,
            Self::Mapped => 3,
        }
    }

    pub fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            0 => Self::Host,
            1 => Self::Reflexive,
            2 => Self::Advertised,
            3 => Self::Mapped,
            _ => return None,
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::Reflexive => "reflexive",
            Self::Advertised => "advertised",
            Self::Mapped => "mapped",
        }
    }
}

/// A candidate address of a device.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Candidate {
    pub kind: CandidateKind,
    pub addr: SocketAddr,
}

/// A source of this device's candidate addresses, beyond the reflexive
/// ones its links report: its interfaces ([`HostCandidates`]), configured
/// addresses ([`AdvertisedCandidates`]), or a port-mapping protocol
/// ([`CandidateKind::Mapped`]).
pub trait CandidateSource: Send + Sync + 'static {
    /// The candidates for the link socket bound at `local`.
    fn candidates(&self, local: SocketAddr) -> Vec<Candidate>;
}

/// The addresses of this device's interfaces on the link socket's port: the
/// socket's own address when it is bound to one, else every interface
/// address of its family (an IPv6 socket on `::` takes IPv4 too). Loopback
/// and link-local addresses only when `include_local` (devices on one
/// machine).
#[derive(Clone, Copy, Debug, Default)]
pub struct HostCandidates {
    pub include_local: bool,
}

impl CandidateSource for HostCandidates {
    fn candidates(&self, local: SocketAddr) -> Vec<Candidate> {
        let ips: Vec<IpAddr> = if local.ip().is_unspecified() {
            interfaces()
                .into_iter()
                .map(|i| i.addr)
                .filter(|ip| local.is_ipv6() || ip.is_ipv4())
                .collect()
        } else {
            vec![local.ip()]
        };
        let mut out: Vec<Candidate> = Vec::new();
        for ip in ips {
            if !self.include_local && is_local(ip) {
                continue;
            }
            let candidate = Candidate {
                kind: CandidateKind::Host,
                addr: SocketAddr::new(ip, local.port()),
            };
            if !out.contains(&candidate) {
                out.push(candidate);
            }
        }
        out
    }
}

/// Addresses configured to reach the link socket from elsewhere (port
/// forwards on the NAT in front of it).
#[derive(Clone, Debug, Default)]
pub struct AdvertisedCandidates(pub Vec<SocketAddr>);

impl CandidateSource for AdvertisedCandidates {
    fn candidates(&self, local: SocketAddr) -> Vec<Candidate> {
        self.0
            .iter()
            .filter(|a| local.is_ipv6() || a.is_ipv4())
            .map(|&addr| Candidate {
                kind: CandidateKind::Advertised,
                addr,
            })
            .collect()
    }
}

/// Loopback, link-local or unspecified: reaches only this machine or link.
fn is_local(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_link_local() || v4.is_unspecified(),
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unicast_link_local() || v6.is_unspecified(),
    }
}

/// An address of one of this device's interfaces, with its prefix length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Interface {
    pub(crate) addr: IpAddr,
    pub(crate) prefix: u8,
}

/// This device's interface addresses.
#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple", target_os = "freebsd"))]
pub(crate) fn interfaces() -> Vec<Interface> {
    let Ok(addrs) = nix::ifaddrs::getifaddrs() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for a in addrs {
        let (Some(addr), Some(mask)) = (a.address, a.netmask) else {
            continue;
        };
        if let (Some(ip), Some(m)) = (addr.as_sockaddr_in(), mask.as_sockaddr_in()) {
            out.push(Interface {
                addr: IpAddr::V4(ip.ip()),
                prefix: u32::from(m.ip()).count_ones() as u8,
            });
        } else if let (Some(ip), Some(m)) = (addr.as_sockaddr_in6(), mask.as_sockaddr_in6()) {
            out.push(Interface {
                addr: IpAddr::V6(ip.ip()),
                prefix: u128::from(m.ip()).count_ones() as u8,
            });
        }
    }
    out
}

/// No interface enumeration on this platform: a socket bound to a
/// specific address still offers it.
#[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple", target_os = "freebsd")))]
pub(crate) fn interfaces() -> Vec<Interface> {
    Vec::new()
}

/// Whether `ip` lies in the subnet of one of `ours`.
fn on_our_subnet(ours: &[Interface], ip: IpAddr) -> bool {
    let ip = ip.to_canonical();
    ours.iter().any(|i| match (i.addr.to_canonical(), ip) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            let mask = u32::MAX.checked_shl(32 - u32::from(i.prefix.min(32))).unwrap_or(0);
            u32::from(a) & mask == u32::from(b) & mask
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            let mask = u128::MAX.checked_shl(128 - u32::from(i.prefix.min(128))).unwrap_or(0);
            u128::from(a) & mask == u128::from(b) & mask
        }
        _ => false,
    })
}

/// The other device's candidates this device's socket at `local` can reach,
/// in the order its dials try them: IPv6 host addresses, IPv4 host
/// addresses on one of this device's subnets, then the reflexive, advertised
/// and mapped ones. Other host addresses (another network's private
/// addresses) are probed but not dialled. Duplicates once.
pub(crate) fn dial_order(theirs: &[Candidate], local: SocketAddr, ours: &[Interface]) -> Vec<SocketAddr> {
    let rank = |c: &Candidate| -> Option<u8> {
        if !reachable_from(local, c.addr) {
            return None;
        }
        match (c.kind, c.addr.ip().to_canonical()) {
            (CandidateKind::Host, IpAddr::V6(_)) => Some(0),
            (CandidateKind::Host, ip) if on_our_subnet(ours, ip) => Some(1),
            (CandidateKind::Host, _) => None,
            (CandidateKind::Reflexive, _) => Some(2),
            (CandidateKind::Advertised | CandidateKind::Mapped, _) => Some(3),
        }
    };
    let mut ranked: Vec<(u8, SocketAddr)> = theirs.iter().filter_map(|c| rank(c).map(|r| (r, c.addr))).collect();
    ranked.sort_by_key(|(r, _)| *r);
    let mut out: Vec<SocketAddr> = Vec::new();
    for (_, addr) in ranked {
        if !out.contains(&addr) {
            out.push(addr);
        }
    }
    out
}

/// The other device's candidates this device probes from its socket at
/// `local`: every one of an address family the socket reaches.
pub(crate) fn probe_targets(theirs: &[Candidate], local: SocketAddr) -> Vec<SocketAddr> {
    let mut out: Vec<SocketAddr> = Vec::new();
    for c in theirs {
        if reachable_from(local, c.addr) && !out.contains(&c.addr) {
            out.push(c.addr);
        }
    }
    out
}

/// Whether a socket bound at `local` can send to `addr`: same family, or
/// IPv4 from an IPv6 socket on `::` (dual stack).
fn reachable_from(local: SocketAddr, addr: SocketAddr) -> bool {
    let addr = addr.ip().to_canonical();
    match local.ip() {
        IpAddr::V4(_) => addr.is_ipv4(),
        IpAddr::V6(v6) => addr.is_ipv6() || v6.is_unspecified(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(kind: CandidateKind, addr: &str) -> Candidate {
        Candidate {
            kind,
            addr: addr.parse().unwrap(),
        }
    }

    #[test]
    fn dials_go_to_ipv6_hosts_then_hosts_on_our_subnet_then_reflexive_addresses() {
        use CandidateKind::*;
        let ours = [Interface {
            addr: "192.168.1.2".parse().unwrap(),
            prefix: 24,
        }];
        let theirs = [
            c(Reflexive, "203.0.113.9:40000"),
            c(Host, "192.168.7.5:6367"),
            c(Host, "192.168.1.9:6367"),
            c(Advertised, "198.51.100.1:6367"),
            c(Host, "[2001:db8::5]:6367"),
        ];
        let v4: SocketAddr = "0.0.0.0:6367".parse().unwrap();
        assert_eq!(
            dial_order(&theirs, v4, &ours),
            ["192.168.1.9:6367", "203.0.113.9:40000", "198.51.100.1:6367"]
                .map(|a| a.parse::<SocketAddr>().unwrap())
        );
        // Every candidate of a reachable family is probed, other networks'
        // private addresses included.
        assert_eq!(probe_targets(&theirs, v4).len(), 4);
        let dual: SocketAddr = "[::]:6367".parse().unwrap();
        assert_eq!(dial_order(&theirs, dual, &ours)[0], "[2001:db8::5]:6367".parse().unwrap());
    }

    #[test]
    fn host_candidates_skip_loopback_unless_asked_and_keep_the_bound_address() {
        let bound: SocketAddr = "127.0.0.1:7000".parse().unwrap();
        assert!(HostCandidates::default().candidates(bound).is_empty());
        assert_eq!(
            HostCandidates { include_local: true }.candidates(bound),
            [c(CandidateKind::Host, "127.0.0.1:7000")]
        );
        let public: SocketAddr = "192.0.2.4:7000".parse().unwrap();
        assert_eq!(
            HostCandidates::default().candidates(public),
            [c(CandidateKind::Host, "192.0.2.4:7000")]
        );
    }
}
